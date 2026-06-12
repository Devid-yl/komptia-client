"""
Service de synchronisation du schéma BDD.

Synchronise automatiquement ou manuellement le schéma de la base source
vers les données d'entraînement (DDL) depuis la base de données directement.
"""

import asyncio
import hashlib
import json
import logging
import re
import os
import time
from datetime import datetime

# fcntl est Unix-only (Linux + macOS = environnements de prod Komptia).
# Sur Windows, l'import échoue et le file lock est désactivé silencieusement —
# l'asyncio.Lock garde son rôle in-process. Acceptable car Komptia n'est pas
# déployé sur Windows en prod.
try:
    import fcntl as _fcntl

    _FCNTL_AVAILABLE = True
except ImportError:
    _fcntl = None
    _FCNTL_AVAILABLE = False
from collections import defaultdict
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.core import clock
from app.core.database import get_session
from app.core.exceptions import DatabaseError, QueryError, SageConnectionError
from app.constants_ai import (
    get_schema_sync_max_rows_tables,
    get_schema_sync_max_rows_views,
)
from app.models.ai_performance import SchemaSync
from app.services.ai.training_store import get_training_store
from app.services.ai.schema_loader import SchemaLoader

logger = logging.getLogger(__name__)


# CTE des index de chunks pour la récupération chunkée des définitions
# (vues ET fonctions). Cause : pyodbc tronque silencieusement les colonnes
# ``nvarchar(max)`` (OBJECT_DEFINITION / sys.sql_modules.definition) à
# ~4000 bytes. On chunke donc côté SQL via SUBSTRING (2000 chars = 4000
# bytes UTF-16, sous le cap), puis on reconstitue côté Python.
#
# Limite : 64 chunks × 2000 chars = 128 KB max par définition. COUPLAGE :
# ces 2 valeurs doivent rester synchronisées avec
# app.constants_ai.SCHEMA_SYNC_VIEW_CHUNK_COUNT/_SIZE et avec
# ``sqlite_sage_connector._intercept_metadata_query`` (règles
# SYS.SQL_MODULES). Si vous changez ici, changez les autres sites aussi.
_DEF_CHUNKS_CTE = """
    WITH chunks AS (
        SELECT n FROM (VALUES
            (1),(2),(3),(4),(5),(6),(7),(8),(9),(10),
            (11),(12),(13),(14),(15),(16),(17),(18),(19),(20),
            (21),(22),(23),(24),(25),(26),(27),(28),(29),(30),
            (31),(32),(33),(34),(35),(36),(37),(38),(39),(40),
            (41),(42),(43),(44),(45),(46),(47),(48),(49),(50),
            (51),(52),(53),(54),(55),(56),(57),(58),(59),(60),
            (61),(62),(63),(64)
        ) AS v(n)
    )
"""

# Récupération chunkée par object_id (préférée) : l'``object_id`` vient du
# catalogue (sys.views / sys.objects) listé juste avant — PAS de
# re-résolution ``OBJECT_ID('schema.nom')`` qui peut renvoyer NULL côté
# compte à permissions restreintes (prod) et sauter l'objet en silence.
_DEF_CHUNK_QUERY_BY_OBJECT_ID = (
    _DEF_CHUNKS_CTE
    + """
    SELECT
        c.n AS chunk_idx,
        SUBSTRING(m.definition, (c.n - 1) * 2000 + 1, 2000) AS chunk_data,
        LEN(m.definition) AS total_len
    FROM chunks c
    CROSS JOIN sys.sql_modules m
    WHERE m.object_id = ?
      AND (c.n - 1) * 2000 < LEN(m.definition)
    ORDER BY c.n
"""
)

# Fallback legacy par nom qualifié — utilisé seulement si le catalogue n'a
# pas fourni d'object_id (connecteur custom / colonne absente).
_DEF_CHUNK_QUERY_BY_NAME = (
    _DEF_CHUNKS_CTE
    + """
    SELECT
        c.n AS chunk_idx,
        SUBSTRING(m.definition, (c.n - 1) * 2000 + 1, 2000) AS chunk_data,
        LEN(m.definition) AS total_len
    FROM chunks c
    CROSS JOIN sys.sql_modules m
    WHERE m.object_id = OBJECT_ID(?)
      AND (c.n - 1) * 2000 < LEN(m.definition)
    ORDER BY c.n
"""
)

# Cap de warnings individuels « définition introuvable » par sync — au-delà,
# un seul warning agrégé (évite 400+ lignes de log sur un compte prod sans
# permission VIEW DEFINITION, tout en gardant le signal actionnable).
_DEF_SKIP_WARN_CAP = 5


async def _fetch_definition_chunked(connector, object_id, qualified_name) -> Tuple[str, int]:
    """Récupère la définition complète d'une vue/fonction par chunks.

    Préfère ``object_id`` (robuste aux permissions restreintes) et ne
    retombe sur ``OBJECT_ID(nom)`` que si le catalogue n'a pas fourni
    d'object_id. Retourne ``(definition, total_len)`` — ``definition``
    vide signifie « introuvable » (objet invisible, permission VIEW
    DEFINITION manquante, ou définition réellement vide).
    """
    if object_id is not None:
        result = await connector.execute(
            _DEF_CHUNK_QUERY_BY_OBJECT_ID, (object_id,), bypass_admin_cap=True
        )
    else:
        result = await connector.execute(
            _DEF_CHUNK_QUERY_BY_NAME, (qualified_name,), bypass_admin_cap=True
        )
    rows = result.to_dicts()
    if not rows:
        return "", 0
    rows_sorted = sorted(rows, key=lambda r: r.get("chunk_idx") or 0)
    definition = "".join((r.get("chunk_data") or "") for r in rows_sorted)
    total_len = rows_sorted[-1].get("total_len") or 0
    if total_len and len(definition) < total_len:
        logger.warning(
            "Définition de %s dépasse la capacité de chunking (%d/%d chars "
            "récupérés). Élargir _DEF_CHUNKS_CTE dans schema_sync.py si besoin.",
            qualified_name,
            len(definition),
            total_len,
        )
    return definition, total_len


# Pourcentages de progression — séparés en constantes pour rendre explicite
# la séquence et éviter les collisions silencieuses lors de refactors. La
# règle est : view_mining < embeddings < done. Si on insère une étape, on
# ajuste ces constantes (et les overlays clients récupèrent juste un percent
# différent — pas de breakage).
_PROGRESS_PERCENT_VIEW_MINING = 94
_PROGRESS_PERCENT_EMBEDDINGS = 96
_PROGRESS_PERCENT_DONE = 100

# Fréquence cible des progress events pendant une boucle longue : viser
# environ 20 events sur la durée totale de la phase (compromis entre
# overhead bus et fluidité visuelle de la barre). Pour une BDD avec 30
# vues, ça donne 1 event tous les 2 vues ; pour 500 vues, 1 tous les 25.
# Évite le piège du modulo fixe (`% 50`) qui ne tirerait qu'un seul event
# sur une petite BDD → fenêtre silencieuse non corrigée.
_VIEW_MINING_TARGET_EVENT_COUNT = 20


def _filter_suggestions_by_user_denied(
    suggestions: List[Dict[str, str]],
    denied_filter: tuple,
) -> List[Dict[str, str]]:
    """**#141** — Filtre une liste de suggestions ``{prompt,label}`` en
    droppant celles dont l'un des deux champs contient un nom denied
    (table ou colonne) du caller.

    Args:
        suggestions: liste de dicts ``{"prompt": str, "label": str}``.
        denied_filter: ``(denied_tables, denied_columns_flat)`` retourné
            par :meth:`SchemaSyncService._load_user_suggestion_filter`.

    Returns:
        Liste filtrée (ordre préservé). Une suggestion qui mentionne un
        nom denied dans ``prompt`` OU ``label`` (any-match) est droppée
        entièrement — pas de scrub via placeholder ``[…]`` car une
        suggestion du type ``"Combien dans […] ?"`` est inutile pour
        l'user (UX dégradée). Mieux vaut moins de suggestions que des
        suggestions cassées.

    **Stratégie word boundary** : utilise
    :func:`contains_protected_name` qui respecte ``\\bNAME\\b``
    case-insensitive — pas de faux positifs sur ``F_X`` matchant
    ``MY_F_XYZ`` (fix Phase 2.5.bis.bis review #2).
    """
    from app.services.data_access.error_messages import contains_protected_name

    denied_tables, denied_cols = denied_filter
    kept = []
    for sug in suggestions:
        prompt = sug.get("prompt", "") or ""
        label = sug.get("label", "") or ""
        if contains_protected_name(prompt, denied_tables, denied_cols):
            continue
        if contains_protected_name(label, denied_tables, denied_cols):
            continue
        kept.append(sug)
    return kept


class _SyncCompleteness:
    """Accumulateur des sections de sync schéma qui ÉCHOUENT silencieusement.

    D1-F7 (#76) — Plusieurs sections de ``_sync_from_sage_impl``
    (views / functions / synonyms / fk / inferred / cardinality / view_mining)
    avalent leur exception et continuent (non-bloquant, par design). Mais sans
    traçage, la sync renvoie ``success:True`` alors que la connaissance schéma
    d'Iris est PARTIELLE — ex : si la requête FK échoue, Iris ignore les
    jointures mais le sync affiche « ✅ terminé » → l'agent génère du SQL avec
    des jointures fausses/manquantes (DONNÉES FAUSSES SILENCIEUSES, axe 5/21).

    Cet accumulateur enregistre chaque section échouée et expose un indicateur
    de complétude propagé dans le résultat ET l'audit ``SchemaSync.changes_detail``
    pour que l'admin sache que la sync est incomplète (et puisse la relancer).
    On NE bascule PAS ``success`` à False : les tables/colonnes ont bien été
    synchronisées (le cœur), seules des couches d'enrichissement manquent —
    flipper ``success`` casserait la logique incrémentale des callers.
    """

    def __init__(self) -> None:
        self.failed: List[Dict[str, str]] = []

    def mark(self, section: str, err: BaseException) -> None:
        """Enregistre l'échec d'une section + log WARNING visible (axe 5)."""
        self.failed.append({"section": section, "reason": type(err).__name__})
        logger.warning(
            "Sync schéma : section '%s' échouée (%s) — connaissance Iris "
            "PARTIELLE pour cette catégorie (sync marquée incomplète).",
            section,
            type(err).__name__,
        )

    @property
    def is_complete(self) -> bool:
        return not self.failed

    def as_result_fields(self) -> Dict[str, Any]:
        """Champs à fusionner dans le résultat de sync + ``changes_detail``."""
        return {"complete": self.is_complete, "incomplete_sections": list(self.failed)}


class SchemaSyncService:
    """
    Service de synchronisation du schéma.

    - Lit le schéma depuis Sage (via INFORMATION_SCHEMA) ou schema_context.yaml
    - Génère les DDL pour le training store
    - Détecte les changements entre syncs
    """

    # B8 — File lock pour protection multi-process. asyncio.Lock seul ne
    # protège que les coroutines DU MÊME process. 2 instances de l'app (ou
    # un cron + l'app) pourraient lancer 2 syncs concurrentes → corruption
    # potentielle de value_mapping (DELETE+INSERT entrelacés). fcntl.flock
    # est libéré automatiquement par le kernel à la mort du process — pas
    # de stale lock après crash.
    _LOCK_FILE_NAME = ".schema_sync.lock"

    @classmethod
    def _lock_file_path(cls) -> Path:
        """Chemin du fichier de lock. Vit dans data/ (créé au premier sync)."""
        from app.config import get_config

        return Path(get_config().database.path).parent / cls._LOCK_FILE_NAME

    def __init__(self):
        self.training_store = get_training_store()
        self._sync_lock = asyncio.Lock()
        # B8 — file descriptor du flock actif. None = pas de lock détenu.
        self._file_lock_fd: Optional[int] = None
        # B11 — État de progression partagé pour `/api/ai/schema/sync/status`.
        # Mis à jour par le wrapper `_progress` dans `_sync_from_sage_impl`.
        # `None` = aucune sync active. Lecture sync sans lock car asyncio
        # est single-threaded — pas de race read/write.
        self._current_progress: Optional[Dict[str, Any]] = None
        # B11 — Référence au cancel_event de la sync active. Permet à
        # `DELETE /api/ai/schema/sync` de cancel sans avoir à passer
        # l'event au handler. None si pas de sync en cours.
        self._active_cancel_event: Optional[asyncio.Event] = None
        # B11 — Timestamp du dernier sync complété (succès OU échec) — pour
        # implémenter le cooldown anti-spam-clic admin. None si jamais sync.
        self._last_completed_at: Optional[datetime] = None

    def get_current_progress(self) -> Optional[Dict[str, Any]]:
        """Retourne l'état de progression de la sync en cours, ou None.

        Format complet (admin) — utilisé par `GET /api/ai/schema/sync` :
        ``{"step": str, "percent": int, "message": str, "started_at": iso8601,
        "elapsed_seconds": float, "table_in_progress": str | None}``.

        Pour l'overlay user-facing utiliser :meth:`get_overlay_progress` qui
        applique le filtrage admin/user (single source of truth pour le
        contrat de séparation des champs entre les 2 endpoints).
        """
        return dict(self._current_progress) if self._current_progress else None

    def get_overlay_progress(self) -> Optional[Dict[str, Any]]:
        """Variante filtrée pour l'overlay sync visible par tous les users
        authentifiés. Source unique du contrat admin/user (axe 14).

        Critère de filtrage :

        * **Inclus** (utiles à l'overlay) : ``step``, ``percent``,
          ``message``, ``elapsed_seconds``. Les noms de tables que le
          ``message`` peut contenir (ex. ``Enrichissement table 5/388
          (FACTURES)...``) NE SONT PAS confidentiels — la doctrine de
          confidentialité multi-niveaux Komptia (cf. ``CLAUDE.md``)
          classe le schéma/structure en Niveau 1 (envoi libre au LLM).
        * **Exclus** (bruit pour les users non-admin) : ``started_at``
          (timestamp absolu, le ``elapsed_seconds`` suffit côté UI),
          ``table_in_progress`` (extraction redondante avec ``message``,
          utile uniquement au handler admin pour debug structuré).

        Retourne ``None`` si aucune sync n'est en cours — caller doit
        afficher l'état "inactive".
        """
        if not self._current_progress:
            return None
        src = self._current_progress
        return {
            "step": src.get("step", ""),
            "percent": src.get("percent", 0),
            "message": src.get("message", ""),
            "elapsed_seconds": src.get("elapsed_seconds", 0),
        }

    def cancel_active_sync(self) -> bool:
        """Demande l'annulation de la sync en cours. Retourne True si demande
        envoyée, False si pas de sync active.

        L'annulation est asynchrone : le sync vérifie `cancel_event` à chaque
        étape et retourne au prochain check (granularité ~quelques secondes).
        """
        if self._active_cancel_event is not None:
            self._active_cancel_event.set()
            return True
        return False

    def get_last_completed_at(self) -> Optional[datetime]:
        """Timestamp UTC de la dernière sync terminée. Pour cooldown handler."""
        return self._last_completed_at

    def _acquire_file_lock(self) -> bool:
        """B8 — Tente d'acquérir le flock exclusif non-bloquant.

        Retourne True si acquis, False si un autre process le détient déjà.
        Sur Windows (pas de fcntl), retourne True silencieusement — la
        protection se réduit à l'asyncio.Lock in-process.
        """
        if not _FCNTL_AVAILABLE:
            return True
        path = self._lock_file_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT, 0o600)
        except OSError:
            logger.warning(
                "Impossible d'ouvrir %s — file lock désactivé pour ce sync.",
                path,
                exc_info=True,
            )
            return True
        try:
            _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return False
        except OSError:
            os.close(fd)
            logger.warning(
                "flock(%s) erreur — fallback sans file lock.",
                path,
                exc_info=True,
            )
            return True
        # Écrire le PID + timestamp pour debug ; pas critique si fail.
        try:
            os.ftruncate(fd, 0)
            os.write(
                fd,
                f"pid={os.getpid()} ts={clock.now().isoformat()}\n".encode(),
            )
        except OSError:
            pass
        self._file_lock_fd = fd
        return True

    def _release_file_lock(self) -> None:
        """B8 — Libère le flock + ferme le fd. Idempotent."""
        if self._file_lock_fd is None:
            return
        if _FCNTL_AVAILABLE:
            try:
                _fcntl.flock(self._file_lock_fd, _fcntl.LOCK_UN)
            except OSError:
                logger.debug("flock(LOCK_UN) erreur (fd peut-être déjà fermé)", exc_info=True)
        try:
            os.close(self._file_lock_fd)
        except OSError:
            pass
        self._file_lock_fd = None

    async def sync_from_yaml(
        self,
        yaml_path: Optional[Path] = None,
        user_id: Optional[int] = None,
        sync_type: str = "manual",
    ) -> Dict[str, Any]:
        """
        Synchronise le training store depuis schema_context.yaml.

        Convertit chaque table en DDL CREATE TABLE et en documentation.
        Protégé par un lock pour empêcher les syncs concurrentes.

        Args:
            yaml_path: Chemin vers le YAML (défaut: data/schema_context.yaml)
            user_id: ID utilisateur qui lance la sync
            sync_type: Type de sync (manual, auto, scheduled)

        Returns:
            Résumé de la synchronisation

        Raises:
            RuntimeError: Si une synchronisation est déjà en cours
        """
        # NOTE: locked() + async with is safe in asyncio (single-threaded, no preemption
        # between the check and the acquire since there's no await between them)
        if self._sync_lock.locked():
            raise RuntimeError("Une synchronisation est déjà en cours. Veuillez patienter.")

        # B8 — file lock multi-process : protège contre 2 instances de l'app
        # ou un script standalone (recovery_sync_sqlite, cron) qui sync en
        # parallèle. Acquis EN DEHORS de l'asyncio.Lock pour pouvoir reporter
        # l'erreur sans tenir le lock asyncio.
        if not self._acquire_file_lock():
            raise RuntimeError(
                "Une synchronisation est déjà en cours dans un autre process. "
                "Veuillez patienter."
            )
        try:
            async with self._sync_lock:
                return await self._sync_from_yaml_impl(yaml_path, user_id, sync_type)
        finally:
            self._release_file_lock()

    async def _sync_from_yaml_impl(
        self,
        yaml_path: Optional[Path] = None,
        user_id: Optional[int] = None,
        sync_type: str = "manual",
    ) -> Dict[str, Any]:
        """Implémentation interne de sync_from_yaml (protégée par lock)."""
        start_time = time.time()

        try:
            # Charger le schéma
            loader = SchemaLoader(schema_path=yaml_path)
            schema = loader.load()
            tables = schema.get("tables", {})
            metadata = schema.get("metadata", {})

            changes = {
                "tables_added": 0,
                "ddl_added": 0,
                "doc_added": 0,
                "tables_updated": 0,
            }

            total_columns = 0

            # 1. Générer et stocker DDL pour chaque table
            for table_name, table_info in tables.items():
                ddl = self._generate_ddl(table_name, table_info)
                await self.training_store.add_ddl(
                    ddl=ddl,
                    table_name=table_name,
                    source=sync_type,
                    user_id=user_id,
                )
                changes["ddl_added"] += 1
                total_columns += len(table_info.get("columns", []))

            # 2. Stocker la documentation métier
            # Notes globales
            notes = metadata.get("notes", [])
            if notes:
                from app.config import get_config

                db_label = get_config().sage.label
                doc_text = f"Règles métier {db_label}:\n" + "\n".join(f"- {n}" for n in notes)
                await self.training_store.add_documentation(
                    doc=doc_text,
                    category="règles_sage",
                    tags=["sage", "comptabilité", "règles"],
                    source=sync_type,
                    user_id=user_id,
                )
                changes["doc_added"] += 1

            # Documentation par table (descriptions + colonnes spéciales)
            for table_name, table_info in tables.items():
                # Description de la table
                desc = table_info.get("description", "")
                if desc:
                    col_docs = []
                    for col in table_info.get("columns", []):
                        if col.get("description"):
                            col_docs.append(
                                f"- {col['name']} ({col['type']}): {col['description']}"
                            )

                    doc = f"Table {table_name}: {desc}\nColonnes:\n" + "\n".join(col_docs)
                    await self.training_store.add_documentation(
                        doc=doc,
                        category=f"table_{table_name.lower()}",
                        tags=[table_name.lower(), "schema"],
                        source=sync_type,
                        user_id=user_id,
                    )
                    changes["doc_added"] += 1

                # Relations (clés étrangères)
                fks = table_info.get("foreign_keys", [])
                if fks:
                    fk_doc = f"Relations de {table_name}:\n"
                    for fk in fks:
                        fk_doc += f"- {fk['column']} référence {fk['references']}\n"
                    await self.training_store.add_documentation(
                        doc=fk_doc,
                        category=f"relations_{table_name.lower()}",
                        tags=[table_name.lower(), "relations", "jointures"],
                        source=sync_type,
                        user_id=user_id,
                    )
                    changes["doc_added"] += 1

            # 3. Stocker les requêtes courantes comme exemples
            common_queries = metadata.get("common_queries", [])
            for query in common_queries:
                await self.training_store.add_question_sql(
                    question=query["description"],
                    sql=query["sql"].strip(),
                    tags=["exemple", "schema"],
                    quality_score=1.0,
                    source=sync_type,
                    user_id=user_id,
                )

            duration = time.time() - start_time

            # 4. Logger la sync
            async with get_session() as session:
                sync_record = SchemaSync(
                    sync_type=sync_type,
                    success=True,
                    tables_added=changes["ddl_added"],
                    total_tables=len(tables),
                    total_columns=total_columns,
                    duration_seconds=duration,
                    triggered_by=user_id,
                    changes_detail=changes,
                )
                session.add(sync_record)
                await session.commit()

            logger.info(
                "✅ Schema sync terminé en %.2fs: %d DDL, %d docs, %d exemples",
                duration,
                changes["ddl_added"],
                changes["doc_added"],
                len(common_queries),
            )

            # Indexer les embeddings vectoriels (delta uniquement)
            try:
                reindex_counts = await self.training_store.reindex_embeddings()
                if sum(reindex_counts.values()) > 0:
                    logger.info("Embeddings reindexés après YAML sync: %s", reindex_counts)
            except Exception as e:
                logger.debug("Reindex embeddings après sync: %s", e)

            return {
                "success": True,
                "duration": duration,
                "tables_count": len(tables),
                "columns_count": total_columns,
                **changes,
            }

        except (SQLAlchemyError, ConnectionError, OSError, DatabaseError) as e:
            duration = time.time() - start_time

            # Logger l'échec
            async with get_session() as session:
                sync_record = SchemaSync(
                    sync_type=sync_type,
                    success=False,
                    error_message=f"Erreur sync ({type(e).__name__})",
                    duration_seconds=duration,
                    triggered_by=user_id,
                )
                session.add(sync_record)
                await session.commit()

            logger.error("Schema sync échoué: %s", e, exc_info=True)
            return {
                "success": False,
                "error": f"Erreur synchronisation schéma ({type(e).__name__})",
                "duration": duration,
            }

    async def sync_from_sage(
        self,
        user_id: Optional[int] = None,
        progress_callback: Optional[Any] = None,
        cancel_event: Optional[asyncio.Event] = None,
        force_full: bool = False,
    ) -> Dict[str, Any]:
        """
        Synchronise directement depuis la base Sage via INFORMATION_SCHEMA.

        Args:
            user_id: ID de l'utilisateur déclencheur
            progress_callback: async callable(step: str, percent: int, message: str)
            cancel_event: asyncio.Event — si set, le sync s'arrête à la prochaine étape
            force_full: Si True, re-enrichir toutes les tables même si le DDL n'a pas changé

        Raises:
            RuntimeError: Si une synchronisation est déjà en cours
        """
        if self._sync_lock.locked():
            raise RuntimeError("Une synchronisation est déjà en cours. Veuillez patienter.")

        # B8 — file lock multi-process (cf. sync_from_yaml). Protège contre
        # un sync concurrent depuis un autre process (autre instance app,
        # script standalone recovery_sync_sqlite, cron).
        if not self._acquire_file_lock():
            raise RuntimeError(
                "Une synchronisation est déjà en cours dans un autre process. "
                "Veuillez patienter."
            )
        try:
            async with self._sync_lock:
                return await self._sync_from_sage_impl(
                    user_id, progress_callback, cancel_event, force_full
                )
        finally:
            self._release_file_lock()

    async def _sync_from_sage_impl(
        self,
        user_id: Optional[int] = None,
        progress_callback: Optional[Any] = None,
        cancel_event: Optional[asyncio.Event] = None,
        force_full: bool = False,
    ) -> Dict[str, Any]:
        """Implémentation interne de sync_from_sage (protégée par lock).

        B11 : `try/finally` extérieur garantit le nettoyage de
        `_current_progress` et `_active_cancel_event` quoiqu'il arrive
        (succès, exception, cancel). Sinon le status endpoint retournerait
        un état périmé après crash.
        """
        start_time = time.time()

        # Initialisé AVANT le try : le statut version est inclus dans le
        # SchemaSync record que la sync soit succès ou échec. Sans init
        # pré-try, le failure path bas (ligne ~1922) tomberait sur un
        # NameError si la sync crashait avant `_detect_and_store_server_version`.
        # Cf. Bug n°7 (2026-05-26) : détection silencieuse qui rend les
        # garde-fous compat-level downstream aveugles.
        version_status: Dict[str, Any] = {
            "ok": False,
            "phase": "not_started",
            "label": None,
            "raw_version": None,
            "compatibility_level": None,
            "committed": False,
            "error": None,
        }

        try:
            from app.services.database.sage_connector import get_sage_connector, PYODBC_AVAILABLE

            if not PYODBC_AVAILABLE:
                return {
                    "success": False,
                    "error": "pyodbc non disponible. Utilisez la sync depuis YAML.",
                }

            connector = get_sage_connector()

            # B11 — Initialiser l'état partagé pour `GET /api/ai/schema/sync/status`.
            # `started_at` UTC, mis à jour à chaque _progress, nettoyé en fin de sync.
            sync_started_at = clock.now()
            self._current_progress = {
                "step": "start",
                "percent": 0,
                "message": "Initialisation...",
                "started_at": sync_started_at.isoformat(),
                "elapsed_seconds": 0.0,
                "table_in_progress": None,
            }
            # B11 — Exposer le cancel_event si présent, sinon créer un local.
            # Permet à `DELETE /api/ai/schema/sync` de cancel via service.
            if cancel_event is None:
                cancel_event = asyncio.Event()
            self._active_cancel_event = cancel_event

            async def _progress(step: str, percent: int, message: str):
                """Report progress if callback is set + update shared state."""
                # B11 — Update shared state pour le status endpoint.
                # Detection de table_in_progress par parsing du message
                # ("Enrichissement table X/Y (TABLE_NAME)..."). Best-effort,
                # ne lève pas si le pattern ne match pas.
                table_in_progress = None
                m = re.search(r"\(([A-Za-z_][A-Za-z0-9_]*)\)\.\.\.$", message)
                if m:
                    table_in_progress = m.group(1)
                self._current_progress = {
                    "step": step,
                    "percent": percent,
                    "message": message,
                    "started_at": sync_started_at.isoformat(),
                    "elapsed_seconds": (clock.now() - sync_started_at).total_seconds(),
                    "table_in_progress": table_in_progress,
                }
                if progress_callback:
                    try:
                        await progress_callback(step, percent, message)
                    except Exception:
                        pass  # Ne pas casser le sync si le callback échoue
                # Broadcast global event bus → tous les users authentifiés
                # voient l'overlay sync schéma. Best-effort.
                try:
                    from app.services.event_bus import get_event_bus

                    await get_event_bus().publish(
                        "schema_sync.progress",
                        {"step": step, "percent": percent, "message": message},
                    )
                except Exception:
                    pass

            def _cancelled() -> bool:
                """Check if sync was cancelled."""
                return cancel_event is not None and cancel_event.is_set()

            # Broadcast started event sur le bus global (overlay frontend).
            try:
                from app.services.event_bus import get_event_bus

                await get_event_bus().publish("schema_sync.started", {})
            except Exception:
                pass
            await _progress("start", 0, "Connexion à SQL Server...")

            # Détection de la version + compat_level SQL Server.
            # Helper extrait pour testabilité (cf. tests/unit/
            # test_schema_sync_version_detection.py). Le statut détaillé
            # est propagé dans `changes_detail.version_detection` du
            # SchemaSync record → visible côté admin via
            # /admin/database → historique. Échec = WARNING + exc_info
            # (PAS logger.debug invisible). Cf. Bug n°7 (2026-05-26).
            version_status = await self._detect_and_store_server_version(connector)

            # Feature #7 task #7d (2026-05-26) — Si la détection version a
            # détecté un downgrade avec capabilities cassées, on déclenche
            # la pipeline rewrite LLM des paires Q/SQL stockées impactées.
            # La pipeline est SÉQUENTIELLE (1 LLM call par paire), peut
            # prendre plusieurs minutes pour beaucoup de paires — le sync
            # est volontairement prolongé pour attendre la fin (la doctrine
            # user dit explicitement "il faudra prolonger le sync pour
            # laisser le temps au llm de faire la mise à jour des requêtes
            # sql"). Le rewrite_pipeline_result est attaché à version_status
            # pour être visible dans changes_detail côté admin.
            rewrite_pipeline_result = None
            try:
                if version_status.get("capability_delta") and version_status[
                    "capability_delta"
                ].get("broken_capabilities"):
                    from app.services.ai.sql_rewrite_pipeline import (
                        rewrite_affected_pairs,
                    )

                    rewrite_pipeline_result = await rewrite_affected_pairs(
                        version_status["capability_delta"],
                        progress_callback=_progress,
                        cancel_event=cancel_event,
                        user_id=user_id,
                    )
                    # Sérialise le dataclass en dict pour le JSON
                    # changes_detail.
                    version_status["rewrite_pipeline"] = {
                        "triggered": rewrite_pipeline_result.triggered,
                        "total_affected": rewrite_pipeline_result.total_affected,
                        "succeeded": rewrite_pipeline_result.succeeded,
                        "needs_human_review": rewrite_pipeline_result.needs_human_review,
                        "failed": rewrite_pipeline_result.failed,
                        "skipped_already_rewritten": (
                            rewrite_pipeline_result.skipped_already_rewritten
                        ),
                        "cancelled": rewrite_pipeline_result.cancelled,
                        "duration_seconds": rewrite_pipeline_result.duration_seconds,
                    }
            except Exception as rewrite_err:  # noqa: BLE001
                # Defense in depth : si la pipeline rewrite crash, on
                # log mais on n'avorte PAS le sync (le schéma a déjà été
                # sync, c'est juste les paires Q/SQL qui ne sont pas
                # réécrites — récupérable au sync suivant).
                logger.warning(
                    "Feature #7 — pipeline rewrite a crashé (non-bloquant "
                    "pour la sync schéma) : %s",
                    rewrite_err,
                    exc_info=True,
                )
                version_status["rewrite_pipeline"] = {
                    "triggered": True,
                    "error": f"{type(rewrite_err).__name__}: {rewrite_err}",
                }

            if _cancelled():
                return {"success": False, "error": "Synchronisation annulée."}
            await _progress("tables", 5, "Lecture des tables...")

            # Schéma source — paramétrable via SAGE_DB_SCHEMA (default "dbo").
            # Évite hardcoded TABLE_SCHEMA = 'dbo' (cf. règle GÉNÉRICITÉ de
            # CLAUDE.md : Komptia est agnostique au logiciel source SQL Server).
            #
            # F-string + validation regex stricte : on ne peut pas utiliser
            # `?` ici car le path SQLite (sqlite_sage_connector) intercepte
            # ces queries en remplaçant complètement par sqlite_master sans
            # placeholder. Validation defense-in-depth contre SQL injection
            # même si la source est admin-controlled (env var).
            from app.config import get_config as _get_config

            _raw_schema = _get_config().sage.source_schema or "dbo"
            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", _raw_schema):
                logger.error(
                    "SAGE_DB_SCHEMA invalide (%r) — caractères non-identifier "
                    "détectés. Fallback à 'dbo'.",
                    _raw_schema,
                )
                _raw_schema = "dbo"
            source_schema = _raw_schema

            # Lire INFORMATION_SCHEMA
            tables_query = f"""
                SELECT TABLE_SCHEMA, TABLE_NAME
                FROM INFORMATION_SCHEMA.TABLES
                WHERE TABLE_TYPE = 'BASE TABLE'
                AND TABLE_SCHEMA = '{source_schema}'
                ORDER BY TABLE_NAME
            """

            tables_result = await connector.execute(
                tables_query,
                max_rows=get_schema_sync_max_rows_views(),
                bypass_admin_cap=True,
            )
            tables_list = tables_result.to_dicts()

            changes = {"ddl_added": 0, "doc_added": 0}
            # D1-F7 (#76) — traçage des sections qui échouent silencieusement
            # (functions/synonyms/fk/cardinality/view_mining). Sans lui, la sync
            # renvoie success:True alors que la connaissance schéma d'Iris est
            # partielle (cf. _SyncCompleteness).
            _completeness = _SyncCompleteness()
            total_columns = 0

            # Batch query: fetch all columns in one query
            all_columns_query = f"""
                SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH,
                       IS_NULLABLE, COLUMN_DEFAULT
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = '{source_schema}'
                ORDER BY TABLE_NAME, ORDINAL_POSITION
            """
            # max_rows élevé : Sage Coala = ~800 tables × ~15 colonnes en moyenne
            # = ~12000 lignes. Cap à get_schema_sync_max_rows_tables() (50k par
            # défaut, configurable via constants_ai).
            all_columns_result = await connector.execute(
                all_columns_query,
                max_rows=get_schema_sync_max_rows_tables(),
                bypass_admin_cap=True,
            )
            all_columns = all_columns_result.to_dicts()
            # Review #3 : si la query INFORMATION_SCHEMA.COLUMNS a tronqué
            # (BDD très large > 50k colonnes), `columns_by_table` est partiel.
            # On le marque pour désactiver le B2 cleanup orphans (sinon risque
            # de DELETE des valeurs de colonnes valides absentes du résultat
            # tronqué).
            all_columns_truncated = bool(getattr(all_columns_result, "truncated", False))
            if all_columns_truncated:
                logger.warning(
                    "INFORMATION_SCHEMA.COLUMNS tronqué à %d lignes — la BDD "
                    "source semble plus large que SCHEMA_SYNC_MAX_ROWS_TABLES. "
                    "B2 orphans cleanup sera désactivé pour éviter des "
                    "suppressions erronées. Augmenter le cap via "
                    "ai_config.schema_sync_max_rows_tables si pertinent.",
                    len(all_columns),
                )

            # Group columns by table name
            columns_by_table = defaultdict(list)
            for col in all_columns:
                columns_by_table[col["TABLE_NAME"]].append(col)

            # Charger les DDL existants pour détecter les changements (sync incrémental)
            existing_ddl: dict[str, str] = {}
            if not force_full:
                # Phase α.4.C : sync schéma = opération SYSTEM, on bypass le filtrage.
                from app.services.data_access.enforcer import SYSTEM_USER

                all_ddl = await self.training_store.get_all_ddl_contents(user=SYSTEM_USER)
                existing_ddl = {d["table_name"]: d["content"] for d in all_ddl if d["table_name"]}

            changed_tables: set[str] = set()

            for row in tables_list:
                table_name = row["TABLE_NAME"]
                columns = columns_by_table.get(table_name, [])

                # Générer DDL (normalisé pour comparaison stable)
                ddl = self._generate_ddl_from_info_schema(table_name, columns).strip()

                # Comparer avec le DDL existant — si identique, skip le upsert
                old_ddl = existing_ddl.get(table_name, "").strip()
                if old_ddl and old_ddl == ddl:
                    total_columns += len(columns)
                    continue  # Table inchangée — pas besoin de re-sauvegarder ni re-enrichir

                changed_tables.add(table_name)
                await self.training_store.add_ddl(
                    ddl=ddl,
                    table_name=table_name,
                    source="auto_sync",
                    user_id=user_id,
                )
                changes["ddl_added"] += 1
                total_columns += len(columns)

            logger.info(
                "DDL: %d tables changées sur %d (force_full=%s)",
                len(changed_tables),
                len(tables_list),
                force_full,
            )

            if _cancelled():
                return {"success": False, "error": "Synchronisation annulée."}
            await _progress("cleanup", 12, "Nettoyage des tables obsolètes...")

            # ========================================
            # 1b. Nettoyer les tables obsolètes
            # ========================================
            # Tables qui existent dans le training store mais plus sur Sage
            sage_table_names = {row["TABLE_NAME"].upper() for row in tables_list}
            # Phase α.4.C : sync schéma = SYSTEM.
            from app.services.data_access.enforcer import SYSTEM_USER

            stored_table_names = await self.training_store.get_all_table_names(user=SYSTEM_USER)
            stale_count = 0
            for stored_name in stored_table_names:
                # Ignorer les vues (format schema_viewXxx standard SQL Server) — nettoyées séparément
                if stored_name.upper().startswith("DBO_"):
                    continue
                if stored_name.upper() not in sage_table_names:
                    await self.training_store.deactivate_by_table(stored_name)
                    stale_count += 1
                    logger.info("Table obsolète désactivée: %s", stored_name)

            if stale_count:
                logger.info("🧹 %s tables obsolètes désactivées", stale_count)
            changes["stale_removed"] = stale_count

            if _cancelled():
                return {"success": False, "error": "Synchronisation annulée."}
            await _progress("views", 15, "Synchronisation des vues SQL...")

            # ========================================
            # 2. Synchroniser les VUES SQL
            # ========================================
            # Fiabilisation 2026-06-09 (incident prod « 0 vue syncée en
            # silence ») :
            # - le catalogue fournit ``v.object_id`` réutilisé tel quel pour
            #   lire sys.sql_modules (la re-résolution ``OBJECT_ID(nom)``
            #   renvoyait NULL sur le compte prod restreint → 0 chunk → vue
            #   sautée SANS trace) ;
            # - chaque vue sans définition récupérable est COMPTÉE et loguée ;
            # - la section est suivie par ``_SyncCompleteness`` comme les
            #   autres (functions/synonyms/fk/...) : échec du catalogue, perte
            #   de connexion mi-boucle, ou 0/N définitions récupérées →
            #   ``complete:False`` + section ``views`` dans
            #   ``incomplete_sections`` (l'admin voit que la connaissance
            #   d'Iris est partielle au lieu d'un faux « ✅ terminé »).
            views_query = """
                SELECT
                s.name as schema_name,
                v.name as view_name,
                v.object_id as object_id,
                CAST(ep.value AS NVARCHAR(MAX)) as description
                FROM sys.views v
                INNER JOIN sys.schemas s ON v.schema_id = s.schema_id
                LEFT JOIN sys.extended_properties ep
                ON ep.major_id = v.object_id
                AND ep.minor_id = 0
                AND ep.name = 'MS_Description'
                WHERE s.name NOT IN ('sys', 'INFORMATION_SCHEMA')
                ORDER BY s.name, v.name
            """

            views_list: List[Dict[str, Any]] = []
            try:
                views_result = await connector.execute(
                    views_query,
                    max_rows=get_schema_sync_max_rows_views(),
                    bypass_admin_cap=True,
                )
                views_list = views_result.to_dicts()
            except (SQLAlchemyError, ConnectionError, DatabaseError) as views_err:
                # Catalogue illisible (permissions sys.views, connexion…) —
                # non-bloquant pour le cœur tables/colonnes, mais tracé.
                _completeness.mark("views", views_err)

            _views_section_failed = any(
                f["section"] == "views" for f in _completeness.failed
            )
            if not views_list and not _views_section_failed:
                # 0 vue listée PAR UN CATALOGUE QUI A RÉPONDU : soit la source
                # n'a réellement aucune vue, soit le compte ne les voit pas
                # (VIEW DEFINITION / metadata visibility). Indiscernable côté
                # code → log INFO actionnable pour le diagnostic prod, sans
                # fausse alerte. (Si le catalogue a LEVÉ, la cause réelle est
                # déjà marquée — ce diagnostic serait trompeur, revue adv.
                # 2026-06-10.)
                logger.info(
                    "Sync vues : 0 vue visible dans sys.views — si la base "
                    "source en contient, vérifier les permissions du compte "
                    "SQL (VIEW DEFINITION / metadata visibility)."
                )

            views_synced = 0
            views_def_missing = 0
            # Accumulate full view DDLs for later mining (détecteurs 1, 2, 4)
            view_ddls_for_mining: List[Dict[str, str]] = []
            for view_row in views_list:
                # Distingue « définition jamais stockée » d'un échec APRÈS
                # add_view réussi (ex. add_documentation de la description) :
                # dans ce 2ᵉ cas la vue est bien synchronisée — la compter
                # aussi dans views_def_missing fausserait la comptabilité
                # (synced + missing > listed, revue adv. 2026-06-10).
                _view_synced_this_iter = False
                try:
                    schema_name = view_row["schema_name"]
                    view_name = view_row["view_name"]
                    description = view_row.get("description", "")

                    full_view_name = f"{schema_name}.{view_name}"

                    definition, _total_len = await _fetch_definition_chunked(
                        connector,
                        view_row.get("object_id"),
                        full_view_name,
                    )

                    if not definition:
                        # AVANT 2026-06-09 ce cas était un pass silencieux :
                        # en prod, AUCUNE vue n'était syncée et la sync
                        # affichait quand même « ✅ terminé ».
                        views_def_missing += 1
                        if views_def_missing <= _DEF_SKIP_WARN_CAP:
                            logger.warning(
                                "Sync vues : définition introuvable pour %s "
                                "(object_id=%s) — vue SAUTÉE. Cause probable : "
                                "permission VIEW DEFINITION manquante pour le "
                                "compte SQL.",
                                full_view_name,
                                view_row.get("object_id"),
                            )
                        continue

                    # Extraire le SELECT (enlever CREATE VIEW ... AS)
                    definition = definition.strip()
                    parts = re.split(r"\bAS\b", definition, maxsplit=1, flags=re.IGNORECASE)
                    if len(parts) >= 2:
                        select_part = parts[1].strip()
                    else:
                        select_part = definition

                    ddl = f"-- Vue: {full_view_name}\nCREATE VIEW {full_view_name} AS\n{select_part}"

                    # Phase 1.6 (#43) — extraire dépendances via sqlglot
                    # pour peupler depends_on. Fail-safe : [] si parsing
                    # échoue → Phase 2.1 traitera la vue comme "deps
                    # inconnues" (fail-closed strict).
                    try:
                        from app.services.data_access.dependency_parser import (
                            extract_dependencies_from_sql,
                        )

                        view_deps = extract_dependencies_from_sql(ddl)
                    except Exception as parse_err:
                        logger.warning(
                            "Sync vues: extract_dependencies échoué " "pour %s: %s",
                            full_view_name,
                            parse_err,
                        )
                        view_deps = []

                    # Phase 1.6 (#43) — utiliser add_view (au lieu de
                    # add_ddl legacy). Le data_type est maintenant VIEW
                    # distinct de DDL, ce qui permet au closure transitif
                    # de calculer correctement les dépendances.
                    # Rétro-compat lecture : ``get_related_ddl`` et
                    # ``get_ddl_by_table_names`` ont été étendus pour
                    # inclure data_type IN (DDL, VIEW) côté lecture.
                    await self.training_store.add_view(
                        definition=ddl,
                        view_name=full_view_name.replace(".", "_"),
                        source="auto_sync_view",
                        user_id=user_id,
                        depends_on=view_deps or None,
                    )
                    changes["ddl_added"] += 1
                    views_synced += 1
                    _view_synced_this_iter = True
                    # Conserver pour le mining (détecteurs 1, 2, 4)
                    view_ddls_for_mining.append(
                        {
                            "name": view_name,
                            "full_name": full_view_name,
                            "ddl": ddl,
                        }
                    )

                    # Extraire les JOIN patterns depuis le SQL de la vue
                    # Les vues montrent les jointures VALIDÉES par le DBA.
                    # On les stocke comme join_pattern: docs pour que le
                    # RAG les trouve quand le LLM cherche comment joindre.
                    try:
                        join_patterns = self._extract_join_patterns(view_name, select_part)
                        for jp in join_patterns:
                            await self.training_store.add_documentation(
                                doc=jp["doc"],
                                category=jp["category"],
                                tags=["auto_sync", "join_pattern", "view_derived"],
                                source="schema_sync_view_join",
                                user_id=user_id,
                            )
                        if join_patterns:
                            changes["doc_added"] += len(join_patterns)
                    except Exception as jp_err:
                        logger.debug(
                            "Join pattern extraction failed for %s: %s", view_name, jp_err
                        )

                    # Ajouter la description si disponible
                    if description:
                        doc_content = f"Vue {full_view_name}: {description}"
                        await self.training_store.add_documentation(
                            doc=doc_content,
                            category=f"vue_{schema_name}",
                            tags=["vue", schema_name],
                            source="view_description",
                            user_id=user_id,
                        )
                        changes["doc_added"] += 1

                except SageConnectionError as conn_err:
                    # Connexion source perdue mi-boucle : inutile de marteler
                    # les vues restantes (timeouts en série). Section marquée
                    # incomplète ; la sync continue (le cœur tables/colonnes
                    # est déjà fait).
                    _completeness.mark("views", conn_err)
                    logger.warning(
                        "Sync vues interrompue par perte de connexion source "
                        "après %d/%d vues.",
                        views_synced,
                        len(views_list),
                    )
                    break
                except (SQLAlchemyError, ConnectionError, DatabaseError) as e:
                    # Échec isolé sur UNE vue : compté + logué (plafonné, même
                    # cap que le chemin « définition vide » — revue adv.
                    # 2026-06-10), la boucle continue. AVANT 2026-06-09 ce
                    # catch ignorait les exceptions applicatives (QueryError…)
                    # levées par les connecteurs → filet INERTE : l'exception
                    # sortait de la boucle et tuait la sync entière sans trace.
                    if not _view_synced_this_iter:
                        views_def_missing += 1
                    if views_def_missing <= _DEF_SKIP_WARN_CAP or _view_synced_this_iter:
                        logger.warning(
                            "Impossible de synchroniser la vue %s: %s%s",
                            view_row.get("view_name", "unknown"),
                            type(e).__name__,
                            (
                                " (définition stockée, enrichissement doc échoué)"
                                if _view_synced_this_iter
                                else ""
                            ),
                        )
                    continue

            if views_def_missing > _DEF_SKIP_WARN_CAP:
                logger.warning(
                    "Sync vues : %d définitions de vues introuvables ou en "
                    "échec au total (les %d premières sont détaillées "
                    "ci-dessus).",
                    views_def_missing,
                    _DEF_SKIP_WARN_CAP,
                )
            if views_def_missing > 0:
                # Connaissance PARTIELLE = section incomplète, dès la 1ʳᵉ vue
                # manquante — pas seulement le cas 0/N (revue adv. 2026-06-10 :
                # un compte avec VIEW DEFINITION sur un seul schéma donnait
                # 12/400 syncées et complete:True, variante directe de
                # l'incident prod). ``mark`` est idempotent sémantiquement :
                # on n'ajoute pas de doublon si un échec amont a déjà marqué.
                if not any(f["section"] == "views" for f in _completeness.failed):
                    _completeness.mark(
                        "views",
                        QueryError(
                            f"{views_def_missing}/{len(views_list)} définitions "
                            "de vues non récupérées"
                        ),
                    )
            # Comptes exposés dans le résultat + l'audit changes_detail :
            # l'admin peut comparer listées vs syncées au lieu de déduire.
            changes["views_listed"] = len(views_list)
            changes["views_def_missing"] = views_def_missing

            if _cancelled():
                return {"success": False, "error": "Synchronisation annulée."}
            await _progress("functions", 17, "Synchronisation des fonctions SQL...")

            # ========================================
            # 2.bis Synchroniser les FONCTIONS SQL (Phase 1.2 — #14)
            # ========================================
            # Pour le closure transitif du mode invisible : on doit savoir
            # quelles fonctions existent et de quelles tables elles dépendent
            # (les dépendances seront extraites en Phase 1.5 via sqlglot).
            # Types SQL Server :
            #   FN — Scalar function
            #   TF — Table-valued function (multistatement)
            #   IF — Inline table-valued function
            # On ignore les fonctions système (sys / INFORMATION_SCHEMA).
            functions_synced = 0
            try:
                functions_query = """
                    SELECT
                        s.name as schema_name,
                        o.name as function_name,
                        o.object_id as object_id,
                        o.type as function_type
                    FROM sys.objects o
                    INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
                    WHERE o.type IN ('FN', 'TF', 'IF')
                    AND s.name NOT IN ('sys', 'INFORMATION_SCHEMA')
                    ORDER BY s.name, o.name
                """
                functions_result = await connector.execute(
                    functions_query,
                    max_rows=get_schema_sync_max_rows_views(),
                    bypass_admin_cap=True,
                )
                functions_list = functions_result.to_dicts()

                for fn_row in functions_list:
                    try:
                        schema_name = fn_row["schema_name"]
                        function_name = fn_row["function_name"]
                        full_fn_name = f"{schema_name}.{function_name}"

                        # Récupérer la définition via le même chunking que
                        # les vues (cap pyodbc 4KB sur nvarchar(max)) — helper
                        # partagé, object_id du catalogue préféré (la
                        # re-résolution OBJECT_ID(nom) peut renvoyer NULL sur
                        # compte restreint → fonction sautée en silence).
                        definition, _total_len = await _fetch_definition_chunked(
                            connector,
                            fn_row.get("object_id"),
                            full_fn_name,
                        )
                        if not definition:
                            continue

                        if definition:
                            definition = definition.strip()
                            # Phase 1.5 (#17) — parser les dépendances via
                            # sqlglot pour peupler ``depends_on``. Fail-safe :
                            # si le parsing échoue, ``deps`` = [], et le
                            # closure transitif Phase 2.1 traitera l'objet
                            # comme « dépendances inconnues » → fail-closed.
                            try:
                                from app.services.data_access.dependency_parser import (
                                    extract_dependencies_from_sql,
                                )

                                deps = extract_dependencies_from_sql(definition)
                            except Exception as parse_err:
                                logger.warning(
                                    "Sync fonctions: extract_dependencies " "échoué pour %s: %s",
                                    full_fn_name,
                                    parse_err,
                                )
                                deps = []

                            # Stocker via le store. ``add_function`` upserte
                            # par function_name si déjà présente.
                            await self.training_store.add_function(
                                definition=definition,
                                function_name=full_fn_name.replace(".", "_"),
                                source="auto_sync_function",
                                user_id=user_id,
                                depends_on=deps or None,  # None si liste vide
                            )
                            functions_synced += 1

                    except (SQLAlchemyError, ConnectionError, QueryError) as fn_err:
                        # QueryError inclus (2026-06-09) : les connecteurs
                        # lèvent les exceptions applicatives, pas SQLAlchemy —
                        # sans lui ce filet per-item était inerte. Une
                        # SageConnectionError (connexion perdue) remonte au
                        # catch de section ci-dessous → mark("functions").
                        logger.warning(
                            "Impossible de synchroniser la fonction %s: %s",
                            fn_row.get("function_name", "unknown"),
                            type(fn_err).__name__,
                        )
                        continue

                changes["functions_added"] = functions_synced
                logger.info("Sync fonctions: %d ajoutées/mises à jour", functions_synced)

            except (SQLAlchemyError, ConnectionError, DatabaseError) as fn_outer_err:
                # Échec du SELECT global (BDD legacy sans fonctions, ou
                # permissions manquantes sur sys.objects). Non-bloquant, mais
                # tracé comme section incomplète (#76) — Iris ignorera ces
                # fonctions et leurs dépendances.
                _completeness.mark("functions", fn_outer_err)

            if _cancelled():
                return {"success": False, "error": "Synchronisation annulée."}
            await _progress("synonyms", 18, "Synchronisation des synonymes SQL...")

            # ========================================
            # 2.ter Synchroniser les SYNONYMES SQL (Phase 1.3 — #15)
            # ========================================
            # Un synonyme est un alias SQL Server qui redirige vers une
            # autre table/vue/fonction. Pour le closure transitif : si
            # la cible est interdite, le synonyme doit l'être aussi.
            # sys.synonyms expose la cible directement via base_object_name —
            # pas de parsing nécessaire.
            synonyms_synced = 0
            try:
                synonyms_query = """
                    SELECT
                        s.name AS schema_name,
                        sy.name AS synonym_name,
                        sy.base_object_name AS target
                    FROM sys.synonyms sy
                    INNER JOIN sys.schemas s ON sy.schema_id = s.schema_id
                    WHERE s.name NOT IN ('sys', 'INFORMATION_SCHEMA')
                    ORDER BY s.name, sy.name
                """
                synonyms_result = await connector.execute(
                    synonyms_query,
                    max_rows=get_schema_sync_max_rows_views(),
                    bypass_admin_cap=True,
                )
                synonyms_list = synonyms_result.to_dicts()

                for syn_row in synonyms_list:
                    try:
                        schema_name = syn_row["schema_name"]
                        synonym_name = syn_row["synonym_name"]
                        target = syn_row.get("target") or ""
                        full_syn_name = f"{schema_name}.{synonym_name}".replace(".", "_")

                        if not target:
                            # base_object_name vide = synonyme cassé / corrompu.
                            # On le log mais on skip — pas la peine d'indexer
                            # un alias vers rien.
                            logger.warning(
                                "Synonyme %s.%s sans cible (skip)",
                                schema_name,
                                synonym_name,
                            )
                            continue

                        await self.training_store.add_synonym(
                            synonym_name=full_syn_name,
                            target=target,
                            source="auto_sync_synonym",
                            user_id=user_id,
                        )
                        synonyms_synced += 1

                    except (SQLAlchemyError, ConnectionError, QueryError) as syn_err:
                        logger.warning(
                            "Impossible de synchroniser le synonyme %s: %s",
                            syn_row.get("synonym_name", "unknown"),
                            type(syn_err).__name__,
                        )
                        continue

                changes["synonyms_added"] = synonyms_synced
                logger.info("Sync synonymes: %d ajoutés/mis à jour", synonyms_synced)

            except (SQLAlchemyError, ConnectionError, DatabaseError) as syn_outer_err:
                # Même gestion que pour les fonctions : non-bloquant + tracé
                # incomplet (#76). Iris ne résoudra pas ces synonymes.
                _completeness.mark("synonyms", syn_outer_err)

            if _cancelled():
                return {"success": False, "error": "Synchronisation annulée."}
            await _progress("fk", 20, "Synchronisation des clés étrangères...")

            # ========================================
            # 3. Synchroniser les RELATIONS (FK) — 100% programmatique
            # ========================================
            # Une seule requête batch pour TOUTES les FK de la BDD.
            # Stockées immédiatement → Iris connaît les jointures dès le premier message.
            fk_count = 0
            try:
                fk_batch_query = """
                    SELECT
                        KCU1.TABLE_NAME AS child_table,
                        KCU1.COLUMN_NAME AS child_column,
                        KCU2.TABLE_NAME AS parent_table,
                        KCU2.COLUMN_NAME AS parent_column,
                        RC.CONSTRAINT_NAME
                    FROM INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS RC
                    JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE KCU1
                        ON RC.CONSTRAINT_NAME = KCU1.CONSTRAINT_NAME
                    JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE KCU2
                        ON RC.UNIQUE_CONSTRAINT_NAME = KCU2.CONSTRAINT_NAME
                        AND KCU1.ORDINAL_POSITION = KCU2.ORDINAL_POSITION
                    ORDER BY KCU1.TABLE_NAME, KCU1.ORDINAL_POSITION
                """
                fk_result = await connector.execute(
                    fk_batch_query,
                    max_rows=get_schema_sync_max_rows_tables(),
                    bypass_admin_cap=True,
                )
                fk_rows = fk_result.to_dicts()

                # Grouper par contrainte (une FK multi-colonnes = 1 relation)
                fk_by_constraint: dict[str, dict] = {}
                for fk_row in fk_rows:
                    cname = fk_row["CONSTRAINT_NAME"]
                    if cname not in fk_by_constraint:
                        fk_by_constraint[cname] = {
                            "child_table": fk_row["child_table"],
                            "parent_table": fk_row["parent_table"],
                            "columns": [],
                            "constraint": cname,
                        }
                    fk_by_constraint[cname]["columns"].append(
                        (fk_row["child_column"], fk_row["parent_column"])
                    )

                # Stocker chaque FK comme documentation relation (sortante ET entrante):
                for fk_info in fk_by_constraint.values():
                    col_parts = [f"{child} → {parent}" for child, parent in fk_info["columns"]]
                    # FK sortante : child_table possède la FK
                    doc_outgoing = (
                        f"FK sortante: {fk_info['child_table']}"
                        f"({', '.join(col_parts)}) "
                        f"REFERENCES {fk_info['parent_table']}. "
                        f"Constraint: {fk_info['constraint']}."
                    )
                    await self.training_store.add_documentation(
                        doc=doc_outgoing,
                        category=f"relation:{fk_info['parent_table']}→{fk_info['child_table']}",
                        tags=["auto_sync", "relationship", "fk"],
                        source="schema_sync_fk",
                        user_id=user_id,
                    )
                    # FK entrante : parent_table est référencée par child_table
                    doc_incoming = (
                        f"FK entrante: {fk_info['child_table']}"
                        f"({', '.join(col_parts)}) → {fk_info['parent_table']}. "
                        f"Constraint: {fk_info['constraint']}. "
                        f"(La table {fk_info['child_table']} dépend de {fk_info['parent_table']})"
                    )
                    await self.training_store.add_documentation(
                        doc=doc_incoming,
                        category=f"relation:{fk_info['parent_table']}←{fk_info['child_table']}",
                        tags=["auto_sync", "relationship", "fk_incoming"],
                        source="schema_sync_fk",
                        user_id=user_id,
                    )
                    fk_count += 1

                logger.info("✅ FK sync: %d relations (sortantes+entrantes)", fk_count)
            except Exception as fk_err:  # noqa: BLE001
                # FK sync non-bloquant MAIS critique pour la connaissance des
                # jointures d'Iris → tracé incomplet (#76). Si manquant, Iris
                # peut générer des jointures fausses/absentes silencieusement.
                _completeness.mark("fk", fk_err)

            changes["fk_synced"] = fk_count

            inferred_count = 0

            if _cancelled():
                return {"success": False, "error": "Synchronisation annulée."}
            await _progress("cardinality", 25, "Comptage des lignes par table...")

            # ========================================
            # 4. Cardinalité des tables (nombre de lignes) — batch
            # ========================================
            cardinality_count = 0
            try:
                card_query = """
                    SELECT
                        t.name AS table_name,
                        SUM(p.rows) AS row_count
                    FROM sys.tables t
                    INNER JOIN sys.partitions p ON t.object_id = p.object_id
                    WHERE p.index_id IN (0, 1)
                    GROUP BY t.name
                    ORDER BY t.name
                """
                card_result = await connector.execute(
                    card_query,
                    max_rows=get_schema_sync_max_rows_views(),
                    bypass_admin_cap=True,
                )
                for row in card_result.to_dicts():
                    tname = row.get("table_name", "")
                    rcount = row.get("row_count", 0)
                    if tname:
                        await self.training_store.add_documentation(
                            doc=json.dumps({"row_count": rcount}),
                            category=f"table_stats:{tname}",
                            tags=["auto_sync", "cardinality", tname],
                            source="schema_sync",
                            user_id=user_id,
                        )
                        cardinality_count += 1
                logger.info("✅ Cardinalité: %d tables", cardinality_count)
            except Exception as card_err:  # noqa: BLE001
                _completeness.mark("cardinality", card_err)
            changes["cardinality_synced"] = cardinality_count

            if _cancelled():
                return {"success": False, "error": "Synchronisation annulée."}

            # ========================================
            # 5. Enrichissement programmatique par table
            #    (stats colonnes, valeurs anonymisées)
            #    INCRÉMENTAL : seules les tables avec DDL changé sont re-enrichies.
            #    Pas d'appel LLM — 100% programmatique.
            # ========================================
            # Déterminer quelles tables enrichir :
            # - force_full=True → toutes les tables
            # - sinon → seulement celles dont le DDL a changé (ou nouvelles)
            # Enrichir : tables modifiées + tables sans column_stats
            if force_full:
                tables_to_enrich = tables_list
            else:
                # Tables dont le DDL a changé
                changed = {
                    r["TABLE_NAME"] for r in tables_list if r["TABLE_NAME"] in changed_tables
                }
                # Tables sans column_stats (perdues après recréation BDD, etc.)
                existing_stats = set()
                try:
                    all_cs = await self.training_store.get_all_column_stats()
                    existing_stats = set(all_cs.keys())
                except Exception:
                    pass
                missing_stats = {
                    r["TABLE_NAME"] for r in tables_list if r["TABLE_NAME"] not in existing_stats
                }
                all_to_enrich = changed | missing_stats
                tables_to_enrich = [r for r in tables_list if r["TABLE_NAME"] in all_to_enrich]
                if missing_stats - changed:
                    logger.info(
                        "Sync: %d tables sans column_stats ajoutées à l'enrichissement",
                        len(missing_stats - changed),
                    )

            if tables_to_enrich:
                await _progress(
                    "enrichment",
                    30,
                    f"Enrichissement de {len(tables_to_enrich)} table(s) modifiée(s)...",
                )
            else:
                await _progress("enrichment", 90, "Aucune table modifiée — enrichissement skippé")

            stats_count = 0
            values_count = 0
            # B1 — FTS5-aware bulk insert : DROP les triggers vm_ai/vm_ad/vm_au
            # avant la phase 5 (×5-10 plus rapide sur gros bulk insert), puis
            # REBUILD + RECREATE après. Le `try/finally` (extérieur) garantit
            # la restauration même sur CancelledError (qui n'est pas Exception
            # en Python 3.8+) ou cancel admin mi-sync.
            from app.services.ai.schema_enricher import (
                fts5_disable_triggers_for_bulk,
                fts5_rebuild_and_recreate_triggers,
            )

            fts5_was_active = False
            try:
                fts5_was_active = await fts5_disable_triggers_for_bulk()
            except Exception:
                logger.warning(
                    "Disable FTS5 triggers échoué — sync continuera "
                    "avec triggers actifs (perf dégradée).",
                    exc_info=True,
                )

            try:
                from app.services.ai.schema_enricher import get_schema_enricher

                enricher = get_schema_enricher()
                # Review #4 : reset le flag de circuit breaker à chaque sync.
                # Sinon un timeout Sage transitoire désactive l'enrichissement
                # de manière permanente jusqu'au redémarrage du process.
                enricher._sage_unreachable = False

                total_enrich = len(tables_to_enrich)
                for idx, row in enumerate(tables_to_enrich):
                    if _cancelled():
                        break
                    table_name = row["TABLE_NAME"]
                    raw_columns = columns_by_table.get(table_name, [])
                    if not raw_columns:
                        continue
                    # Progression granulaire : 30% → 90% pendant l'enrichissement
                    enrich_pct = 30 + int(60 * idx / max(total_enrich, 1))
                    if idx % 5 == 0:
                        await _progress(
                            "enrichment",
                            enrich_pct,
                            f"Enrichissement table {idx + 1}/{total_enrich} ({table_name})...",
                        )

                    # Convertir le format INFORMATION_SCHEMA → format get_columns()
                    # pour éviter 388 requêtes Sage supplémentaires.
                    columns_info = [
                        {
                            "name": c["COLUMN_NAME"],
                            "type": c["DATA_TYPE"],
                            "nullable": c["IS_NULLABLE"] == "YES",
                            "max_length": c.get("CHARACTER_MAXIMUM_LENGTH"),
                            "default": c.get("COLUMN_DEFAULT"),
                        }
                        for c in raw_columns
                    ]

                    # 5a. Stats colonnes (distinct, null_pct, min/max)
                    # T5 — On capture le payload pour le passer comme hint à
                    # sample_column_values : permet la stratification par cardinalité
                    # sans re-requêter Sage (le distinct est déjà calculé ici).
                    column_stats_payload: Dict[str, Dict[str, Any]] = {}
                    try:
                        stats_result = await enricher.collect_column_stats(
                            table_name,
                            columns_info,
                            connector=connector,
                            sql_table_name=table_name,
                        )
                        column_stats_payload = stats_result.get("columns") or {}
                        stats_count += 1
                    except Exception as stats_err:
                        logger.warning(
                            "Stats %s échouées (%s): %s",
                            table_name,
                            type(stats_err).__name__,
                            stats_err,
                        )
                    # T5 — Observabilité : si stats vides AVEC colonnes présentes,
                    # la stratification value_mapping est désactivée pour cette
                    # table. Alerte admin pour ne pas avoir une régression silencieuse.
                    if columns_info and not column_stats_payload:
                        logger.warning(
                            "Stats vides pour %s (%d colonnes) — stratification "
                            "value_mapping désactivée (fallback exhaustif).",
                            table_name,
                            len(columns_info),
                        )

                    # 5b. Valeurs distinctes anonymisées
                    try:
                        vals = await enricher.sample_column_values(
                            table_name,
                            columns_info,
                            connector=connector,
                            sql_table_name=table_name,
                            column_stats_hint=column_stats_payload or None,
                        )
                        values_count += len(vals)
                    except Exception as val_err:
                        logger.warning(
                            "Valeurs %s échouées (%s): %s",
                            table_name,
                            type(val_err).__name__,
                            val_err,
                        )

                logger.info(
                    "✅ Enrichissement programmatique: %d tables stats, %d colonnes values",
                    stats_count,
                    values_count,
                )

                # B2 — Cleanup des orphelins : si une (table, colonne) existe
                # dans value_mapping mais plus dans la BDD source actuelle
                # (suppression côté Sage), on retire ses valeurs. Sinon
                # pollution permanente de l'index — la recherche retourne des
                # matches sur des colonnes disparues. À l'intérieur du même
                # try/except enrich pour ne pas faire échouer la sync sur ce
                # nettoyage non-critique.
                #
                # Review #3 : skip si all_columns_truncated (vue partielle de
                # la BDD source). Sinon les colonnes hors-cap deviennent
                # faussement orphelines → DELETE de valeurs valides.
                try:
                    valid_cols = {
                        (t, c["COLUMN_NAME"]) for t, cols in columns_by_table.items() for c in cols
                    }
                    if valid_cols and not all_columns_truncated:
                        from sqlalchemy import text as _sqltext

                        async with get_session() as _sess:
                            current = await _sess.execute(
                                _sqltext(
                                    "SELECT DISTINCT table_name, column_name " "FROM value_mapping"
                                )
                            )
                            current_set = {(row[0], row[1]) for row in current.fetchall()}
                            orphans = current_set - valid_cols
                            if orphans:
                                logger.info(
                                    "B2 — purge de %d (table,col) orphelins de "
                                    "value_mapping (suppressions côté Sage)",
                                    len(orphans),
                                )
                                # DELETE par batches de 500 (limite SQLite IN ~32k
                                # mais on reste prudent pour éviter les locks longs).
                                #
                                # **Commit PAR BATCH** (fix multi-user 2026-05-22) :
                                # avant ce fix, le ``await _sess.commit()`` était
                                # HORS la boucle → le verrou writer SQLite était
                                # tenu pendant TOUS les DELETE (~1-5 s pour 1k-5k
                                # orphelins), bloquant tout autre user qui voulait
                                # écrire (scan-workbook, upload, etc.). Avec un
                                # commit après chaque batch, le verrou est
                                # relâché ~10x par seconde → un user concurrent
                                # peut s'insérer entre les batches.
                                orphans_list = list(orphans)
                                for i in range(0, len(orphans_list), 500):
                                    # Honorer une annulation user entre 2
                                    # batches — cohérent avec les autres
                                    # phases du sync qui font ``if
                                    # _cancelled(): return`` (cf. lignes
                                    # 1593-1611 plus bas).
                                    if _cancelled():
                                        break
                                    batch = orphans_list[i : i + 500]
                                    # **Bug pré-existant fixé 2026-05-22**
                                    # (adversarial review post-multi-user
                                    # APEX) : l'ancien pattern utilisait
                                    # ``text("... IN (VALUES (?,?)...)")``
                                    # + ``flat_params=[v for tup ...]``,
                                    # ce qui lève silencieusement
                                    # ``ArgumentError: List argument must
                                    # consist only of dictionaries`` dans
                                    # SQLAlchemy text() (positional ``?``
                                    # non supportés avec une liste plate).
                                    # Résultat : le cleanup orphans n'a
                                    # JAMAIS effectivement supprimé une
                                    # ligne (le ``except Exception``
                                    # global plus bas avalait l'erreur en
                                    # log warning). Validé par test
                                    # runtime sur sqlite+aiosqlite en
                                    # mémoire avant fix.
                                    #
                                    # Nouveau pattern : named params dict
                                    # ``:t0,:c0,:t1,:c1,...`` — supporté
                                    # par SQLAlchemy text() sans
                                    # ambiguïté. ~500 placeholders par
                                    # batch reste sous
                                    # ``SQLITE_MAX_VARIABLE_NUMBER``
                                    # (32766 sur build récent).
                                    placeholder_pairs = []
                                    params: Dict[str, Any] = {}
                                    for idx, (tbl, col) in enumerate(batch):
                                        placeholder_pairs.append(f"(:t{idx}, :c{idx})")
                                        params[f"t{idx}"] = tbl
                                        params[f"c{idx}"] = col
                                    values_sql = ",".join(placeholder_pairs)
                                    # FIX P1 #2 : maintenir la cohérence
                                    # FTS5. Les triggers FTS5 sont dropped
                                    # avant la boucle (B0) et rebuilt en
                                    # finally (B1) → fenêtre
                                    # d'inconsistance si crash. Sans le
                                    # DELETE FTS5 ici, un crash entre B0
                                    # et B1 laissait FTS5 contenant des
                                    # rowids inexistants côté
                                    # value_mapping.
                                    #
                                    # Ordre OBLIGATOIRE : DELETE FTS5
                                    # AVANT DELETE value_mapping. Le
                                    # DELETE FTS5 utilise un sub-SELECT
                                    # sur value_mapping pour retrouver
                                    # les rowids cibles — si on
                                    # supprimait value_mapping en
                                    # premier, le sub-SELECT retournerait
                                    # vide et FTS5 garderait ses entrées.
                                    if fts5_was_active:
                                        await _sess.execute(
                                            _sqltext(
                                                f"DELETE FROM value_mapping_fts "
                                                f"WHERE rowid IN ("
                                                f"  SELECT id FROM value_mapping "
                                                f"  WHERE (table_name, column_name) "
                                                f"  IN (VALUES {values_sql})"
                                                f")"
                                            ),
                                            params,
                                        )
                                    await _sess.execute(
                                        _sqltext(
                                            f"DELETE FROM value_mapping "
                                            f"WHERE (table_name, column_name) IN "
                                            f"(VALUES {values_sql})"
                                        ),
                                        params,
                                    )
                                    await _sess.commit()
                except Exception as orph_err:
                    logger.warning(
                        "B2 cleanup orphelins échoué (non-bloquant): %s",
                        orph_err,
                        exc_info=True,
                    )
            except Exception as enrich_err:
                logger.warning(
                    "Enrichissement programmatique échoué (non-bloquant): %s", enrich_err
                )
            finally:
                # B1 — Toujours restaurer FTS5 même si l'enrichissement a
                # crashé au milieu. Sinon les triggers restent dropped et
                # value_mapping_fts devient stale silencieusement.
                if fts5_was_active:
                    try:
                        await _progress("fts5_rebuild", 91, "Reconstruction de l'index FTS5...")
                        await fts5_rebuild_and_recreate_triggers()
                    except Exception:
                        logger.error(
                            "FTS5 rebuild échoué — voir log plus haut pour "
                            "l'action admin requise.",
                            exc_info=True,
                        )

            changes["stats_synced"] = stats_count
            changes["values_synced"] = values_count
            changes["tables_changed"] = len(changed_tables)
            changes["tables_skipped"] = len(tables_list) - len(changed_tables)

            if _cancelled():
                return {"success": False, "error": "Synchronisation annulée."}
            await _progress("inferred", 92, "Détection des relations implicites...")

            # ========================================
            # 6. Détecter les relations INFÉRÉES (soft FK)
            #    Compare les valeurs distinctes LOCALES (ValueMapping)
            #    pour trouver les colonnes de tables différentes qui
            #    partagent les mêmes valeurs. 0 requête SQL Server.
            # ========================================
            try:
                inferred_count = await self._detect_inferred_relations(
                    fk_by_constraint, columns_by_table, user_id
                )
            except Exception as inf_err:  # noqa: BLE001
                # Relations implicites (soft-FK) = jointures non déclarées
                # qu'Iris utilise → tracé incomplet (#76), même classe que la
                # section fk.
                _completeness.mark("inferred", inf_err)
            changes["inferred_fk_count"] = inferred_count

            if _cancelled():
                return {"success": False, "error": "Synchronisation annulée."}
            await _progress("view_mining", 94, "Extraction du contexte métier depuis les vues...")

            # ========================================
            # 6b. View Mining — extraction programmatique de business_context
            # ========================================
            # 3 passes, toutes génériques (aucun nom de table hardcodé) :
            #  • Détecteurs 1 & 2 : par vue (alias multiples + alias de colonnes)
            #  • Détecteur 3     : FK suffix roles (sur le schéma complet)
            #  • Détecteur 4     : co-occurrence de tables dans les vues
            # Chaque passe produit des docs `business_context` avec une source
            # `view_mining:*` qui les distingue des docs manuelles.
            view_mining_count = 0
            try:
                from app.services.ai.view_miner import (
                    mine_view,
                    mine_fk_suffix_roles,
                    mine_cooccurrence,
                    extract_view_tables,
                    FK_ANALYSIS_SOURCE,
                    COOCCURRENCE_SOURCE,
                )

                # Passe 1 & 2 : chaque vue
                # Sans event de progression intermédiaire, l'overlay frontend
                # paraît figé pendant toute la phase (cf. logs : ~14 s pour
                # 435 vues). On émet un progress périodique — le ``percent``
                # reste à ``_PROGRESS_PERCENT_VIEW_MINING`` (pour ne pas
                # empiéter sur ``embeddings``), seul le ``message`` change.
                # Le pas est calculé dynamiquement (cf.
                # ``_VIEW_MINING_TARGET_EVENT_COUNT``) pour que même les
                # petites BDD (10-30 vues) reçoivent plusieurs events.
                total_views_to_mine = len(view_ddls_for_mining)
                progress_every = max(1, total_views_to_mine // _VIEW_MINING_TARGET_EVENT_COUNT)
                for vm_idx, view_info in enumerate(view_ddls_for_mining):
                    if total_views_to_mine > 0 and vm_idx % progress_every == 0:
                        await _progress(
                            "view_mining",
                            _PROGRESS_PERCENT_VIEW_MINING,
                            f"Extraction métier vue {vm_idx + 1}/" f"{total_views_to_mine}...",
                        )
                    try:
                        drafts = mine_view(view_info["name"], view_info["ddl"])
                        source_key = f"view_mining:{view_info['name']}"
                        created = await self.training_store.upsert_auto_business_contexts(
                            drafts,
                            source_key=source_key,
                        )
                        view_mining_count += created
                    except Exception as vm_err:
                        logger.debug(
                            "view_miner.mine_view(%s) échoué: %s",
                            view_info.get("name", "?"),
                            vm_err,
                        )

                # Passe 3 : FK suffix roles (depuis fk_by_constraint déjà collecté)
                await _progress(
                    "view_mining",
                    _PROGRESS_PERCENT_VIEW_MINING,
                    "Analyse des rôles FK (suffixes)...",
                )
                try:
                    fk_input = []
                    for fk_info in fk_by_constraint.values():
                        st = fk_info.get("child_table")
                        tt = fk_info.get("parent_table")
                        # Chaque couple (child_column, parent_column) = 1 FK
                        for child_col, _parent_col in fk_info.get("columns", []):
                            if st and tt and child_col:
                                fk_input.append(
                                    {
                                        "source_table": st,
                                        "source_column": child_col,
                                        "target_table": tt,
                                    }
                                )
                    fk_drafts = mine_fk_suffix_roles(fk_input)
                    created = await self.training_store.upsert_auto_business_contexts(
                        fk_drafts,
                        source_key=FK_ANALYSIS_SOURCE,
                    )
                    view_mining_count += created
                except Exception as fk_mine_err:
                    logger.debug("view_miner.mine_fk_suffix_roles échoué: %s", fk_mine_err)

                # Passe 4 : co-occurrence (tables co-présentes dans les vues)
                await _progress(
                    "view_mining",
                    _PROGRESS_PERCENT_VIEW_MINING,
                    "Analyse de la co-occurrence des tables...",
                )
                try:
                    views_input = []
                    for view_info in view_ddls_for_mining:
                        tables_in_view = extract_view_tables(view_info["ddl"])
                        if tables_in_view:
                            views_input.append(
                                {
                                    "view_name": view_info["name"],
                                    "tables": tables_in_view,
                                }
                            )
                    coc_drafts = mine_cooccurrence(views_input)
                    created = await self.training_store.upsert_auto_business_contexts(
                        coc_drafts,
                        source_key=COOCCURRENCE_SOURCE,
                    )
                    view_mining_count += created
                except Exception as coc_err:
                    logger.debug("view_miner.mine_cooccurrence échoué: %s", coc_err)

                logger.info(
                    "✅ View mining: %d business_context docs générés " "depuis %d vues",
                    view_mining_count,
                    len(view_ddls_for_mining),
                )
            except Exception as mine_err:  # noqa: BLE001
                # Le view mining est non-bloquant : si une erreur survient, le sync
                # principal se termine quand même. Le business_context est une
                # couche d'enrichissement, pas un prérequis — mais tracé incomplet
                # (#76) pour transparence.
                logger.warning("View mining échoué (non-bloquant): %s", mine_err, exc_info=True)
                _completeness.mark("view_mining", mine_err)
            changes["business_context_synced"] = view_mining_count

            duration = time.time() - start_time

            # Logger la sync
            async with get_session() as session:
                sync_record = SchemaSync(
                    sync_type="auto",
                    success=True,
                    tables_added=len(tables_list) + views_synced,  # Tables + Vues
                    total_tables=len(tables_list) + len(views_list),
                    total_columns=total_columns,
                    duration_seconds=duration,
                    triggered_by=user_id,
                    changes_detail={
                        **changes,
                        "views_synced": views_synced,
                        "total_views": len(views_list),
                        # Statut détaillé de la détection version (Bug n°7)
                        # — visible côté admin pour diagnostiquer un échec
                        # silencieux de @@VERSION ou compatibility_level.
                        "version_detection": version_status,
                        # #76 — indicateur de complétude : si des sections ont
                        # échoué (functions/synonyms/fk/cardinality/view_mining),
                        # l'admin le voit dans l'historique de sync malgré
                        # success=True.
                        **_completeness.as_result_fields(),
                    },
                )
                session.add(sync_record)
                await session.commit()

            logger.info(
                "✅ Sage sync: %d tables, %d vues, %d colonnes",
                len(tables_list),
                views_synced,
                total_columns,
            )

            # Invalider le cache du catalogue de tables dans AgentKnowledge
            try:
                from app.services.ai.agent_knowledge import get_agent_knowledge

                get_agent_knowledge().invalidate_table_catalogue()
            except Exception:
                logger.debug("Invalidation cache catalogue échouée", exc_info=True)

            # Phase 2.1 fix #2 (BLOCKING review) — invalider AUSSI le cache
            # des ``UserSchemaView``. Sans ça, après un sync qui ajoute ou
            # modifie ``depends_on`` (vues/fonctions/synonymes), les users
            # actifs continuent de servir une closure stale pendant 60s.
            # Concrètement : un user avec ``deny F_SALAIRES`` pourrait voir
            # une nouvelle vue ``V_PAIE`` dépendant de F_SALAIRES pendant
            # la fenêtre TTL — contournement transitoire du mode invisible.
            try:
                from app.services.data_access.visible_schema import (
                    invalidate_all_view_cache,
                    invalidate_obj_to_deps_cache,
                )

                invalidate_all_view_cache()
                # **#88** — invalider aussi le cache obj_to_deps. Sans cette
                # ligne, les nouvelles VIEW/FUNCTION/SYNONYM ne sont pas vues
                # par la closure transitive pendant 60s (TTL).
                invalidate_obj_to_deps_cache()
            except Exception:
                logger.debug("Invalidation cache visible_schema échouée", exc_info=True)

            # Note: l'enrichissement PROGRAMMATIQUE (stats, valeurs, FKs, cardinalité)
            # est fait ci-dessus pendant le sync. L'enrichissement SÉMANTIQUE (rôles
            # de tables/colonnes via LLM) n'est fait que sur feedback ✅ de l'utilisateur.

            # ========================================
            # 7. Suggestions d'accueil dynamiques
            # ========================================
            await _progress("suggestions", 94, "Génération des suggestions d'accueil...")
            try:
                llm_suggestions = await self.generate_llm_suggestions()
                if llm_suggestions:
                    logger.info("✅ Suggestions LLM génériques: %d", len(llm_suggestions))
                else:
                    logger.info(
                        "Suggestions LLM échouées, le programmatique sera utilisé en fallback"
                    )
            except Exception as sug_err:
                logger.warning("Suggestions d'accueil échouées (non-bloquant): %s", sug_err)

            await _progress(
                "embeddings",
                _PROGRESS_PERCENT_EMBEDDINGS,
                "Indexation des embeddings...",
            )

            # Indexer les embeddings vectoriels (delta uniquement)
            try:
                reindex_counts = await self.training_store.reindex_embeddings()
                if sum(reindex_counts.values()) > 0:
                    logger.info("Embeddings reindexés après Sage sync: %s", reindex_counts)
            except Exception as e:
                logger.debug("Reindex embeddings après sync: %s", e)

            await _progress("done", _PROGRESS_PERCENT_DONE, "Synchronisation terminée !")

            return {
                "success": True,
                "duration": duration,
                "tables_count": len(tables_list),
                "views_count": views_synced,
                "columns_count": total_columns,
                **changes,
                # #76 — ``complete`` (bool) + ``incomplete_sections`` (liste) :
                # le caller/admin sait que la connaissance schéma est partielle
                # même quand ``success=True`` (tables synchronisées, mais une
                # couche d'enrichissement a échoué).
                **_completeness.as_result_fields(),
            }

        except (SQLAlchemyError, ConnectionError, OSError, DatabaseError) as e:
            # DatabaseError inclus (2026-06-09) : les connecteurs lèvent les
            # exceptions applicatives (QueryError/SageConnectionError) — sans
            # lui, un échec connecteur hors-section traversait sans enregistrer
            # de SchemaSync(success=False) ni retourner d'erreur structurée.
            duration = time.time() - start_time
            async with get_session() as session:
                sync_record = SchemaSync(
                    sync_type="auto",
                    success=False,
                    error_message=f"Erreur sync Sage ({type(e).__name__})",
                    duration_seconds=duration,
                    triggered_by=user_id,
                    # Statut version même en échec sync : si la détection
                    # version avait réussi avant le crash, on garde la
                    # trace ; si elle n'avait pas tourné, on a l'init
                    # "not_started" (cf. version_status pré-try ligne ~527).
                    changes_detail={"version_detection": version_status},
                )
                session.add(sync_record)
                await session.commit()

            logger.error("Sage sync échoué: %s", e, exc_info=True)
            return {
                "success": False,
                "error": f"Erreur synchronisation Sage ({type(e).__name__})",
                "duration": duration,
            }
        finally:
            # B11 — Cleanup état partagé : permet au status endpoint de
            # signaler "pas de sync active" et au cooldown de checker depuis
            # quand. Toujours exécuté (succès, exception, cancel).
            self._current_progress = None
            self._active_cancel_event = None
            self._last_completed_at = clock.now()
            # Broadcast done event (toujours, même en cas d'erreur — l'overlay
            # doit se fermer sinon il reste indéfiniment).
            try:
                from app.services.event_bus import get_event_bus

                await get_event_bus().publish("schema_sync.done", {})
            except Exception:
                pass

    async def _detect_and_store_server_version(self, connector) -> Dict[str, Any]:
        """Détecte @@VERSION + compatibility_level du SQL Server actif.

        Bug n°7 (2026-05-26) — historique : ce bloc utilisait un
        try/except qui catchait toutes les exceptions en logger.debug
        (invisible en INFO). Quand la détection foirait, les garde-fous
        compat-level downstream (deja_vu_prefetch._resolve_active_compat_level,
        copilot_agent, {sql_server_version} dans les prompts) tombaient
        en cascade silencieusement. Refactor : helper isolé pour
        testabilité + WARNING + exc_info en cas d'échec + statut
        propagé dans changes_detail pour visibilité admin.

        Mystère C (2026-05-26) — historique : SQLAlchemy détectait
        "valeur inchangée" (server_version = "SQL Server 2014" déjà =
        nouvelle valeur "SQL Server 2014") et skipped le commit, donc
        updated_at restait vieille de plusieurs jours malgré un sync
        réussi. Fix : forcer le bump d'updated_at à chaque sync
        (même valeur ré-écrite = touche au row).

        Args:
            connector: instance SageConnector déjà connectée (la
                connexion est gérée par le caller).

        Returns:
            Dict de statut destiné à être ajouté à
            ``SchemaSync.changes_detail`` :

            * ``ok`` (bool) : succès complet de toute la chaîne
            * ``phase`` (str) : étape la plus avancée atteinte
              (``not_started`` / ``query_version`` / ``query_compat`` /
              ``build_label`` / ``commit_to_db`` / ``invalidate_cache`` /
              ``done``)
            * ``label`` (str|None) : label calculé via
              ``build_server_version_label``
            * ``raw_version`` (str|None) : @@VERSION (200 char max)
            * ``compatibility_level`` (int|None)
            * ``committed`` (bool) : True si la row BDD a bien été écrite
            * ``error`` (str|None) : type + message en cas d'échec
        """
        status: Dict[str, Any] = {
            "ok": False,
            "phase": "not_started",
            "label": None,
            "raw_version": None,
            "compatibility_level": None,
            "committed": False,
            "error": None,
            # Feature #7 (2026-05-26) : delta des capabilities SQL Server
            # entre l'ancien et le nouveau label. Si ``downgrade=True`` et
            # ``broken_capabilities`` non-vide, des paires Q/SQL stockées
            # peuvent nécessiter une réécriture LLM (cf. tasks #13/#14/#15).
            "capability_delta": None,
        }
        try:
            from app.services.database.db_config_service import (
                build_server_version_label,
                compute_capability_delta,
            )

            # bypass_admin_cap : sync interne du schéma BDD, pas une query
            # user-visible. Le plafond /admin/database s'applique aux
            # exécutions user (Iris, datastore SQL) ; le sync doit récupérer
            # toutes les données techniques même si l'admin a configuré un
            # plafond UX bas.
            status["phase"] = "query_version"
            version_result = await connector.execute(
                "SELECT @@VERSION", max_rows=1, bypass_admin_cap=True
            )
            raw_version = str(version_result.rows[0][0]) if version_result.rows else ""
            status["raw_version"] = raw_version[:200]

            status["phase"] = "query_compat"
            compat_result = await connector.execute(
                "SELECT compatibility_level FROM sys.databases WHERE name = DB_NAME()",
                max_rows=1,
                bypass_admin_cap=True,
            )
            compat_level = int(compat_result.rows[0][0]) if compat_result.rows else None
            status["compatibility_level"] = compat_level

            status["phase"] = "build_label"
            version_label = build_server_version_label(raw_version, compat_level)
            status["label"] = version_label

            status["phase"] = "commit_to_db"
            async with get_session() as session:
                from app.models.db_config import DatabaseConnection

                # ``ORDER BY last_activated_at DESC`` puis ``.first()``
                # plutôt que ``scalar_one_or_none()``. Justification :
                # tolérance à l'anomalie data "plusieurs is_active=TRUE"
                # (observée 2026-05-26 : vieille row "Test" + row prod
                # toutes deux actives). Sans cette tolérance, le helper
                # crashait sur ``MultipleResultsFound`` → updated_at
                # jamais bumpé → diagnostic Mystère C bloqué. La version
                # robuste prend la plus récemment activée et logue la
                # violation pour qu'un admin corrige via /admin/database.
                result = await session.execute(
                    select(DatabaseConnection)
                    .where(DatabaseConnection.is_active == True)  # noqa: E712
                    .order_by(DatabaseConnection.last_activated_at.desc().nullslast())
                )
                active_rows = list(result.scalars().all())
                if len(active_rows) > 1:
                    logger.warning(
                        "Anomalie data: %d connexions ``is_active=TRUE`` "
                        "détectées (ids=%s). Devrait être 0 ou 1 max "
                        "(``activate_connection`` enforce single-active). "
                        "Prise de la plus récemment activée (id=%s). À "
                        "corriger via /admin/database (désactiver les "
                        "autres).",
                        len(active_rows),
                        [c.id for c in active_rows],
                        active_rows[0].id,
                    )
                    status["multiple_active_anomaly"] = {
                        "count": len(active_rows),
                        "ids": [c.id for c in active_rows],
                        "selected_id": active_rows[0].id,
                    }
                active_conn = active_rows[0] if active_rows else None
                if active_conn is None:
                    status["error"] = "no_active_connection"
                    logger.warning(
                        "Détection version SQL Server: aucune connexion "
                        "active en BDD locale — impossible de persister le "
                        "label calculé (%s, compat=%s). Les garde-fous "
                        "compat-level downstream vont fallback sur "
                        '"SQL Server" générique (fail-closed).',
                        version_label,
                        compat_level,
                    )
                else:
                    # Capture l'ancien label AVANT mutation pour calculer
                    # le delta de capabilities (Feature #7 2026-05-26).
                    # Si downgrade détecté + broken_capabilities → la
                    # pipeline en aval (task #15) déclenchera la
                    # réécriture LLM des paires Q/SQL impactées.
                    old_label = active_conn.server_version

                    # Force commit + bump updated_at MÊME si server_version
                    # inchangé (Mystère C 2026-05-26). Single source of
                    # truth = la BDD ; on garantit qu'à chaque sync, la
                    # valeur LIVE est ré-écrite et la date de dernière
                    # vérification est bumpée. Sans ce force, SQLAlchemy
                    # détecte "no change" et skip le commit silencieusement.
                    active_conn.server_version = version_label
                    active_conn.updated_at = clock.now()
                    await session.commit()
                    status["committed"] = True
                    logger.info(
                        "Version SQL Server confirmée: %s (compat=%s) — "
                        "connexion id=%s row updated",
                        version_label,
                        compat_level,
                        active_conn.id,
                    )

                    # Calcul du delta capability post-commit. Utilisé en
                    # aval (task #15) pour décider si certaines paires
                    # Q/SQL doivent être réécrites par le LLM.
                    delta = compute_capability_delta(old_label, version_label)
                    status["capability_delta"] = delta
                    if delta["broken_capabilities"]:
                        logger.warning(
                            "Downgrade SQL Server détecté: %s → %s "
                            "(compat %s → %s). Capabilities cassées: %s. "
                            "Les paires Q/SQL stockées utilisant ces "
                            "capabilities seront candidates à la "
                            "réécriture LLM (cf. feature #7).",
                            delta["old_label"],
                            delta["new_label"],
                            delta["old_compat"],
                            delta["new_compat"],
                            delta["broken_capabilities"],
                        )
                    elif delta["new_capabilities"]:
                        logger.info(
                            "Upgrade SQL Server détecté: %s → %s "
                            "(compat %s → %s). Nouvelles capabilities "
                            "dispo: %s. Les paires existantes restent "
                            "valides (informatif, pas d'action auto).",
                            delta["old_label"],
                            delta["new_label"],
                            delta["old_compat"],
                            delta["new_compat"],
                            delta["new_capabilities"],
                        )

            # Mystère B 2026-05-26 : le cache mémoire process
            # (``_cached_version_label``) a été supprimé — la BDD
            # ``database_connections.server_version`` est la SSoT, lue à
            # chaque appel par ``get_sql_server_version_label[_sync]()``.
            # Plus rien à invalider/peupler ici : si le commit BDD
            # ci-dessus a réussi, les prochains getters verront
            # immédiatement la nouvelle valeur. Si la persistance a
            # échoué (no_active_connection), les getters tomberont sur
            # le fallback ``"SQL Server"`` — c'est le comportement
            # voulu (fail-CLOSED côté garde-fous compat-level).

            status["phase"] = "done"
            # ok=True UNIQUEMENT si toute la chaîne a réussi (y compris
            # la persistance BDD). Sinon, status.error contient déjà la
            # raison (ex: "no_active_connection") et ok reste False pour
            # remonter le problème au caller / admin.
            if status["error"] is None:
                status["ok"] = True
        except Exception as ver_err:
            # WARNING + exc_info (PAS logger.debug invisible). Si cette
            # détection foire, tous les garde-fous compat-level downstream
            # (deja_vu_prefetch, copilot_agent, prompts {sql_server_version})
            # vont fail-open en cascade. Statut aussi propagé à
            # changes_detail pour visibilité admin.
            status["error"] = f"{type(ver_err).__name__}: {ver_err}"
            logger.warning(
                "Détection version SQL Server échouée à la phase '%s' "
                "(non-bloquante pour le sync mais les garde-fous compat-level "
                "downstream vont tous fail-open silencieusement) : %s",
                status["phase"],
                ver_err,
                exc_info=True,
            )
        return status

    async def _detect_inferred_relations(
        self,
        fk_by_constraint: dict,
        columns_by_table: dict,
        user_id: Optional[int] = None,
    ) -> int:
        """
        Détecte les relations implicites entre tables en comparant les valeurs
        distinctes stockées localement (ValueMapping). 0 requête SQL Server.

        Approche par index inversé :
        1. Charge toutes les valeurs distinctes depuis ValueMapping
        2. Pour chaque valeur, note quelles (table, colonne) la contiennent
        3. Les colonnes de tables différentes partageant beaucoup de valeurs → relation

        Protections anti-explosion combinatoire :
        - Min 5 valeurs distinctes par colonne (exclut booléens, flags)
        - Max 50 colonnes par valeur (exclut "0", "1", codes génériques)
        - Exécuté dans un thread executor (ne bloque pas l'event loop)
        """
        from app.models.value_mapping import ValueMapping

        # Construire le set des FK explicites pour les exclure
        explicit_fk_set: set[tuple[str, str, str, str]] = set()
        for fk_info in fk_by_constraint.values():
            for child_col, parent_col in fk_info["columns"]:
                explicit_fk_set.add(
                    (
                        fk_info["child_table"].lower(),
                        child_col.lower(),
                        fk_info["parent_table"].lower(),
                        parent_col.lower(),
                    )
                )

        # Nettoyer les anciennes relations inférées avant d'en créer de nouvelles
        await self.training_store.deactivate_by_source("schema_sync_inferred")

        # Charger toutes les valeurs depuis ValueMapping (SQLite local)
        # Clés normalisées en lowercase pour éviter les problèmes de casse
        col_values: dict[tuple[str, str], set[str]] = {}
        async with get_session() as session:
            result = await session.execute(
                select(
                    ValueMapping.table_name,
                    ValueMapping.column_name,
                    ValueMapping.real_value_lower,
                )
            )
            for table, column, value in result.all():
                key = (table.lower(), column.lower())
                if key not in col_values:
                    col_values[key] = set()
                col_values[key].add(value)

        if not col_values:
            logger.info("Inferred FK: aucune valeur dans ValueMapping, skip")
            return 0

        # Filtrer : min 5 valeurs (exclut booléens/flags), max 10K (exclut texte libre)
        col_values = {k: v for k, v in col_values.items() if 5 <= len(v) <= 10_000}

        # Garder une copie des noms originaux (pour le stockage)
        # On utilise les clés lowercase pour la logique, mais les noms originaux pour le doc
        col_original_names: dict[tuple[str, str], tuple[str, str]] = {}
        async with get_session() as session:
            result = await session.execute(
                select(
                    ValueMapping.table_name,
                    ValueMapping.column_name,
                ).distinct()
            )
            for table, column in result.all():
                key = (table.lower(), column.lower())
                if key in col_values:
                    col_original_names[key] = (table, column)

        # CPU-bound : offload dans un thread pour ne pas bloquer l'event loop
        loop = asyncio.get_event_loop()
        pair_results = await loop.run_in_executor(
            None,
            self._compute_inferred_pairs,
            col_values,
            explicit_fk_set,
        )

        # Construire la liste des FK candidates par VALEUR (orientées
        # source→target par cardinalité — la plus petite = probablement la FK).
        value_fks: list[dict] = []
        for (key_a, key_b), overlap, containment, src_distinct, tgt_distinct in pair_results:
            if len(col_values.get(key_a, set())) <= len(col_values.get(key_b, set())):
                src_key, tgt_key = key_a, key_b
            else:
                src_key, tgt_key = key_b, key_a

            src_table, src_col = col_original_names.get(src_key, src_key)
            tgt_table, tgt_col = col_original_names.get(tgt_key, tgt_key)
            value_fks.append(
                {
                    "source_table": src_table,
                    "source_column": src_col,
                    "target_table": tgt_table,
                    "target_column": tgt_col,
                    "containment": float(containment),
                    "overlap": int(overlap),
                    "src_distinct": int(src_distinct),
                    "tgt_distinct": int(tgt_distinct),
                }
            )

        # Détection NAMING (générique, applicable même sur tables vides).
        # ``columns_by_table`` est la sortie INFORMATION_SCHEMA.COLUMNS :
        # {table: [{COLUMN_NAME, ...}, ...]}. On extrait juste la liste
        # de noms de colonnes pour ``detect_naming_fks`` qui est pur.
        tables_columns_names: dict[str, list[str]] = {
            t: [c["COLUMN_NAME"] for c in (cols or [])] for t, cols in columns_by_table.items()
        }
        try:
            from app.services.ai.fk_inference import (
                combine_signals,
                detect_naming_fks,
            )

            naming_fks = detect_naming_fks(tables_columns_names)
        except Exception as nf_err:  # pragma: no cover — défensif
            logger.warning("detect_naming_fks échoué (non-bloquant): %s", nf_err)
            naming_fks = []

        # Combiner les deux signaux : kind + confidence finaux.
        combined = combine_signals(naming_fks=naming_fks, value_fks=value_fks)

        # Persister dans la table dédiée ``inferred_foreign_keys`` (truncate +
        # insert batch). La doc training_store est aussi alimentée pour la
        # rétro-compat avec les RAG existants qui cherchent "relation:..." ;
        # ne pas la supprimer = règle "ne jamais supprimer feature existante".
        inferred_count = await self._persist_inferred_fks(combined, user_id=user_id)

        logger.info(
            "✅ Inferred FK: %d relations détectées (naming=%d, value=%d, combined=%d)",
            inferred_count,
            len(naming_fks),
            len(value_fks),
            len(combined),
        )
        return inferred_count

    async def _persist_inferred_fks(
        self,
        combined: list[dict],
        user_id: Optional[int] = None,
    ) -> int:
        """Tronque ``inferred_foreign_keys`` puis insère ``combined`` en batch,
        et alimente en parallèle la documentation RAG pour rétro-compat.

        Args:
            combined : sortie de ``combine_signals`` — liste de dicts
                ``{source_table, source_column, target_table, target_column,
                kind, confidence, evidence}``.

        Returns:
            Nombre de rows insérées.
        """
        from sqlalchemy import delete

        from app.models.inferred_foreign_key import InferredForeignKey

        # 1. TRUNCATE + INSERT batch dans la table dédiée. Pas de TRUNCATE en
        #    SQLite ; ``DELETE FROM`` est l'équivalent (le WAL le rend rapide
        #    même sur grosses tables). On passe par le constructeur ORM
        #    ``delete()`` plutôt que ``text("DELETE ...")`` pour rester
        #    typé et bénéficier du quoting.
        async with get_session() as session:
            await session.execute(delete(InferredForeignKey))
            for row in combined:
                # ``evidence`` peut être None ou une chaîne — on encode tel
                # quel (déjà formaté par ``combine_signals`` pour debug humain).
                # On garde la chaîne plutôt qu'un JSON pur pour rester lisible
                # avec ``sqlite3 .dump`` sans parsing.
                session.add(
                    InferredForeignKey(
                        source_table=row["source_table"],
                        source_column=row["source_column"],
                        target_table=row["target_table"],
                        target_column=row["target_column"],
                        kind=row["kind"],
                        confidence=float(row["confidence"]),
                        evidence=row.get("evidence"),
                    )
                )
            await session.commit()

        # 2. Alimenter le RAG (documentation) en parallèle — rétro-compat avec
        #    les consommateurs qui cherchent ``category=relation:...``.
        await self.training_store.deactivate_by_source("schema_sync_inferred")
        count = 0
        for row in combined:
            conf_label = (
                "haute"
                if row["confidence"] >= 0.85
                else "moyenne" if row["confidence"] >= 0.6 else "faible"
            )
            src_t = row["source_table"]
            src_c = row["source_column"]
            tgt_t = row["target_table"]
            tgt_c = row["target_column"]
            ev = row.get("evidence") or ""
            doc = (
                f"Relation inférée ({conf_label}, kind={row['kind']}, "
                f"conf={row['confidence']:.2f}): "
                f"{src_t}.{src_c} → {tgt_t}.{tgt_c}. "
                f"Evidence: {ev}. "
                f"JOIN: [{src_t}].[{src_c}] = [{tgt_t}].[{tgt_c}]"
            )
            try:
                await self.training_store.add_documentation(
                    doc=doc,
                    category=f"relation:{tgt_t}→{src_t}",
                    tags=["auto_sync", "relationship", "inferred", conf_label, row["kind"]],
                    source="schema_sync_inferred",
                    user_id=user_id,
                )
                count += 1
            except Exception as add_err:  # pragma: no cover — défensif
                logger.debug("add_documentation inferred FK échoué: %s", add_err)
        return count

    @staticmethod
    def _compute_inferred_pairs(
        col_values: dict[tuple[str, str], set[str]],
        explicit_fk_set: set[tuple[str, str, str, str]],
    ) -> list[tuple]:
        """
        CPU-bound : construit l'index inversé et calcule le containment.
        Exécuté dans un thread executor.

        Returns:
            Liste de (key_a, key_b, overlap, containment, src_distinct, tgt_distinct)
        """
        from collections import Counter

        MAX_COLS_PER_VALUE = 50  # Au-delà, c'est du bruit (codes génériques)

        # Index inversé : valeur → liste de (table_lower, column_lower)
        value_to_cols: dict[str, list[tuple[str, str]]] = {}
        for (table, column), values in col_values.items():
            for v in values:
                if v not in value_to_cols:
                    value_to_cols[v] = []
                value_to_cols[v].append((table, column))

        # Compter les valeurs partagées par paire
        pair_overlap: Counter = Counter()
        for v, cols in value_to_cols.items():
            if len(cols) < 2 or len(cols) > MAX_COLS_PER_VALUE:
                continue
            for i in range(len(cols)):
                for j in range(i + 1, len(cols)):
                    t_a, c_a = cols[i]
                    t_b, c_b = cols[j]
                    if t_a == t_b:
                        continue  # même table (déjà lowercase)
                    pair = (
                        ((t_a, c_a), (t_b, c_b))
                        if (t_a, c_a) < (t_b, c_b)
                        else ((t_b, c_b), (t_a, c_a))
                    )
                    pair_overlap[pair] += 1

        # Calculer le containment et filtrer
        results = []
        for (key_a, key_b), overlap in pair_overlap.items():
            # Exclure les FK explicites
            t_a, c_a = key_a
            t_b, c_b = key_b
            if (t_a, c_a, t_b, c_b) in explicit_fk_set:
                continue
            if (t_b, c_b, t_a, c_a) in explicit_fk_set:
                continue

            set_a = col_values.get(key_a, set())
            set_b = col_values.get(key_b, set())
            if not set_a or not set_b:
                continue

            # Containment basé sur le plus petit set (probable FK)
            smaller = min(len(set_a), len(set_b))
            containment = overlap / smaller

            if containment < 0.5:
                continue

            src_distinct = min(len(set_a), len(set_b))
            tgt_distinct = max(len(set_a), len(set_b))
            results.append((key_a, key_b, overlap, containment, src_distinct, tgt_distinct))

        return results

    async def generate_llm_suggestions(
        self,
        user_id: Optional[int] = None,
    ) -> List[Dict[str, str]]:
        """
        Génère des suggestions via un appel LLM, en lui donnant le contexte
        des tables + l'usage de l'utilisateur. Stocke le résultat en cache.

        **Memoïsé** : court-circuite l'appel LLM si la STRUCTURE du schéma
        (fingerprint des tables/colonnes du top-N) est identique au dernier
        appel et qu'un cache non vide existe — l'input étant déterministe, on
        ne rappelle le LLM que quand la structure change réellement.

        Appelé après un sync réussi (générique) ou quand l'usage user a changé.

        ⚠️ La séquence stockage (``deactivate_by_category`` puis ``add`` en
        boucle) n'est pas transactionnelle : à n'appeler que sous le verrou de
        sync (``_sync_lock`` des entry points ``sync_from_*``), ce qui est le
        cas de l'unique caller. Hors verrou, deux exécutions concurrentes
        pourraient laisser une fenêtre « 0 suggestion active ».

        Returns: liste de suggestions ou [] si échec.
        """
        from app.services.ai.llm_providers import LLMRequest

        # Construire le contexte : top 20 tables avec colonnes
        # Phase α.4.C : génération suggestions LLM = SYSTEM (admin uniquement).
        from app.services.data_access.enforcer import SYSTEM_USER

        all_ddl = await self.training_store.get_all_ddl_contents(user=SYSTEM_USER)
        if not all_ddl:
            return []

        # Scores des tables (réutiliser la logique de profiling)
        table_stats = await self.training_store.get_all_table_stats()
        table_usage: Dict[str, int] = {}
        if user_id:
            try:
                table_usage = await self.training_store.get_user_table_usage(user_id)
            except Exception:
                pass

        # Construire un résumé compact pour le LLM
        table_summaries = []
        for entry in all_ddl:
            tname = entry.get("table_name", "")
            if not tname:
                continue
            ddl = entry.get("content", "")
            # Extraire juste les noms de colonnes et types
            col_re = re.compile(r"^\s+(\w+)\s+(\w+)", re.MULTILINE)
            cols = [f"{m.group(1)} ({m.group(2)})" for m in col_re.finditer(ddl)]
            if not cols:
                continue

            row_count = table_stats.get(tname, 0)
            usage = table_usage.get(tname, 0)

            # Score pour trier — plafonner le nombre de colonnes
            # pour que les tables très larges n'écrasent pas les autres
            score = min(len(cols), 30) + (row_count > 0) * 5 + usage * 10

            table_summaries.append(
                {
                    "name": tname,
                    "cols": cols[:15],  # Max 15 colonnes par table
                    "rows": row_count,
                    "usage": usage,
                    "score": score,
                }
            )

        table_summaries.sort(key=lambda t: t["score"], reverse=True)
        top_tables = table_summaries[:20]

        if not top_tables:
            return []

        # Construire le prompt
        tables_text = ""
        for t in top_tables:
            row_info = f" ({t['rows']} lignes)" if t["rows"] else ""
            usage_info = f" [utilisée {t['usage']}x]" if t["usage"] else ""
            cols_str = ", ".join(t["cols"][:10])
            if len(t["cols"]) > 10:
                cols_str += f" ... (+{len(t['cols']) - 10})"
            tables_text += f"- {t['name']}{row_info}{usage_info} : {cols_str}\n"

        user_context = ""
        if table_usage:
            top_used = sorted(table_usage.items(), key=lambda x: x[1], reverse=True)[:5]
            user_context = (
                "\n\nCet utilisateur interroge fréquemment ces tables : "
                + ", ".join(f"{t} ({n}x)" for t, n in top_used)
                + ". Oriente les suggestions vers ses centres d'intérêt."
            )

        # ── Memoïsation sur fingerprint structurel ───────────────────────
        # L'input de cet appel LLM est la STRUCTURE du schéma (noms de tables
        # + colonnes du top-N, + tables favorites de l'user). Entre deux syncs
        # cette structure ne bouge quasi jamais : seuls les row counts dérivent,
        # et les questions générées n'en dépendent pas. Sans garde, CHAQUE sync
        # (auto 24h + syncs manuels admin + boot) rappelle le LLM avec un input
        # identique → gaspillage déterministe. On hashe la structure (PAS les
        # counts ni compteurs d'usage, volatils) et on court-circuite l'appel
        # quand le cache existant correspond. Doctrine Komptia « Code > Prompt » :
        # ne pas appeler le LLM quand le code peut décider que rien n'a changé.
        # Portée = les tables RÉELLEMENT envoyées au LLM (``top_tables``).
        # Volontaire : les suggestions ne référencent QUE ces tables, donc un
        # changement hors top-N ne modifierait pas la sortie → le re-générer
        # serait du gaspillage. Un changement DANS le top-N (table/colonne
        # ajoutée/supprimée/renommée) reconstruit ``top_tables`` à partir du
        # ``all_ddl`` courant → le hash bouge → régénération. ``sorted`` (tables
        # ET colonnes) rend le hash indépendant de l'ordre des lignes BDD
        # (scores ex-aequo, pas d'ORDER BY garanti) → pas de fausse régénération.
        fp_parts = [f"{t['name']}|{','.join(sorted(t['cols']))}" for t in top_tables]
        if table_usage:
            # tables favorites de l'user, SANS les compteurs (volatils eux aussi)
            fp_parts.append("favs:" + ",".join(sorted(t for t, _ in top_used)))
        input_fingerprint = hashlib.sha256(
            "\n".join(sorted(fp_parts)).encode("utf-8")
        ).hexdigest()

        cache_category = f"welcome_suggestions_llm:user_{user_id or 'generic'}"

        # Skip l'appel LLM si la structure est identique au dernier appel ET
        # qu'un cache non vide existe. Le fingerprint voyage comme tag sur les
        # lignes de suggestions elles-mêmes (cf. boucle de stockage) → une seule
        # lecture renvoie les deux. Toute erreur → on régénère (fail vers la
        # correction, jamais vers du stale silencieux).
        try:
            cached_fp, existing = await self._read_cached_suggestions_with_fp(cache_category)
            if cached_fp == input_fingerprint and existing:
                logger.info(
                    "Suggestions LLM inchangées (schéma structurel identique) "
                    "— skip appel LLM (user=%s, %d en cache)",
                    user_id or "generic",
                    len(existing),
                )
                return existing
        except Exception as fp_err:  # noqa: BLE001 — fingerprint best-effort
            logger.debug("Lecture cache suggestions échouée: %s", fp_err)

        prompt = f"""Voici les tables d'une base de données d'entreprise :

{tables_text}
{user_context}

Génère entre 4 et 8 questions qu'un utilisateur métier (pas technique) poserait naturellement en langage courant.

Règles :
- Questions en français, formulées comme si l'utilisateur parlait à un collègue
- Varier les tables (pas 2 questions sur la même table)
- Varier les types : tendances, tops, anomalies, résumés, comparaisons, listes
- Chaque question doit être autonome (compréhensible sans contexte)
- NE PAS utiliser les noms techniques des tables, reformuler en langage métier (ex: "LigneFactureAchat" → "factures fournisseurs", "EcritureComptable" → "écritures comptables")
- Le label est un résumé très court (2-4 mots max)

Réponds UNIQUEMENT avec un JSON valide, sans texte avant ni après :
[
  {{"prompt": "la question complète", "label": "résumé court"}},
  ...
]"""

        try:
            from app.services.ai.llm_runtime import CallProfile, call_llm

            response = await call_llm(
                CallProfile(caller="schema_sync", max_tokens_soft=1000),
                LLMRequest(
                    prompt=prompt,
                    system="Tu es un assistant qui génère des suggestions de requêtes pour une base de données. Réponds uniquement en JSON.",
                    temperature=0.7,
                ),
            )

            # Parser le JSON de la réponse
            content = response.content.strip()
            # Nettoyer si le LLM a mis des ```json ... ```
            if content.startswith("```"):
                content = content.split("\n", 1)[1] if "\n" in content else content[3:]
                if content.endswith("```"):
                    content = content[:-3]
                content = content.strip()

            suggestions = json.loads(content)
            if not isinstance(suggestions, list):
                logger.warning("LLM suggestions: réponse n'est pas une liste")
                return []

            # Valider et nettoyer
            valid = []
            for s in suggestions:
                if isinstance(s, dict) and "prompt" in s and "label" in s:
                    valid.append({"prompt": str(s["prompt"]), "label": str(s["label"])})
            valid = valid[:8]

            if not valid:
                return []

            # Stocker en cache. Le fingerprint structurel voyage comme tag
            # ``fp:<hash>`` SUR les lignes de suggestions (pas de ligne ni de
            # catégorie séparée → aucun embedding ni candidat RAG supplémentaire ;
            # le tag n'entre pas dans le contenu embeddé ``{category} {doc}``).
            # Le prochain sync court-circuitera l'appel LLM tant que le hash
            # correspond.
            await self.training_store.deactivate_by_category(cache_category)
            for idx, sug in enumerate(valid):
                await self.training_store.add_documentation(
                    doc=json.dumps(sug, ensure_ascii=False),
                    category=f"{cache_category}:{idx}",
                    tags=["welcome_suggestions", "llm_generated", f"fp:{input_fingerprint}"],
                    source="llm_suggestions",
                    user_id=user_id,
                )

            logger.info(
                "✅ Suggestions LLM générées: %d (user=%s)", len(valid), user_id or "generic"
            )
            return valid

        except Exception as e:
            logger.warning("Suggestions LLM échouées (fallback programmatique): %s", e)
            return []

    async def _read_cached_suggestions_with_fp(
        self, cache_category: str
    ) -> Tuple[Optional[str], List[Dict[str, str]]]:
        """Lit en UNE passe les suggestions actives (brutes) d'une catégorie ET
        leur fingerprint structurel (tag ``fp:<hash>`` posé par
        :meth:`generate_llm_suggestions`).

        Returns ``(fingerprint | None, suggestions)``. Le fingerprint alimente
        le skip-path de memoïsation ; les suggestions servent à vérifier qu'un
        cache non vide existe avant de court-circuiter l'appel LLM.

        Volontairement SANS filtre denied (#141) : cette lecture n'alimente que
        la décision interne « régénérer ou non », et son retour ne va qu'au sync
        (cf. caller, qui ne fait que logger ``len()``). Le filtrage user-facing
        reste appliqué par :meth:`get_cached_llm_suggestions`.
        """
        fingerprint: Optional[str] = None
        out: List[Dict[str, str]] = []
        async with get_session() as session:
            from app.models.training_data import TrainingData

            result = await session.execute(
                select(TrainingData)
                .where(
                    TrainingData.category.startswith(cache_category + ":"),
                    TrainingData.is_active == True,  # noqa: E712
                )
                .order_by(TrainingData.category)
            )
            for record in result.scalars().all():
                if fingerprint is None and record.tags:
                    for tag in record.tags.split(","):
                        if tag.startswith("fp:"):
                            fingerprint = tag[3:]
                            break
                try:
                    data = json.loads(record.content)
                    if "prompt" in data and "label" in data:
                        out.append(
                            {"prompt": str(data["prompt"]), "label": str(data["label"])}
                        )
                except (json.JSONDecodeError, TypeError):
                    continue
        return fingerprint, out

    async def get_cached_llm_suggestions(
        self,
        user_id: Optional[int] = None,
    ) -> List[Dict[str, str]]:
        """Lit les suggestions LLM en cache. Essaie user-specific puis générique.

        **Phase 2.5.quinquies (#141)** — Filtre par denied du caller AVANT
        retour. Deux trous historiques refermés :

        1. ``welcome_suggestions_llm:user_generic`` est un **pool partagé**
           généré sans contexte user. Si l'admin a denied ``F_SALAIRES``
           pour l'user A, le générique peut contenir ``"Combien de lignes
           dans F_SALAIRES ?"`` → leak du nom interdit dès le premier
           écran Iris.
        2. Le cache **user-specific** peut être obsolète : généré quand
           l'user n'avait aucune restriction, encore lu après la pose
           d'une règle deny (le sync regénère mais peut être en retard).

        Stratégie : pour chaque branche du cache, on filtre les
        suggestions dont ``prompt`` OU ``label`` contiennent un nom
        denied (via :func:`contains_protected_name`, word boundary
        case-insensitive). Si la branche devient vide après filtre,
        on tente la branche suivante.

        Fail-closed : si le filter load crash, on retourne ``[]`` (pas
        de suggestions = pas de leak), mieux qu'un retour fail-safe
        ``return suggestions`` qui réintroduirait le bug.
        """
        # **Charge le filter une fois** (cache implicite : view a son
        # propre TTL 60s).
        # Sémantique du retour :
        #   - None         → pas de filtrage à appliquer (user_id None /
        #                    admin / sans restrictions)
        #   - tuple        → filtre à appliquer
        #   - exception    → fail-closed (rétrograde sur ``[]``)
        try:
            denied_filter = await self._load_user_suggestion_filter(user_id)
        except Exception as e:
            logger.warning(
                "welcome_suggestions: filter load crash pour user_id=%s "
                "(%s) — fail-closed : retour [] pour éviter leak",
                user_id,
                e,
            )
            return []

        for category_prefix in [
            f"welcome_suggestions_llm:user_{user_id}" if user_id else None,
            "welcome_suggestions_llm:user_generic",
        ]:
            if not category_prefix:
                continue
            suggestions = []
            async with get_session() as session:
                from app.models.training_data import TrainingData

                result = await session.execute(
                    select(TrainingData)
                    .where(
                        TrainingData.category.startswith(category_prefix + ":"),
                        TrainingData.is_active == True,  # noqa: E712
                    )
                    .order_by(TrainingData.category)
                )
                for record in result.scalars().all():
                    try:
                        data = json.loads(record.content)
                        if "prompt" in data and "label" in data:
                            suggestions.append(data)
                    except (json.JSONDecodeError, TypeError):
                        continue

            # **#141** — Filtre denied avant return. Si la branche
            # user-specific est filtrée à vide, on tente generic.
            if denied_filter is not None and suggestions:
                before = len(suggestions)
                suggestions = _filter_suggestions_by_user_denied(suggestions, denied_filter)
                if before != len(suggestions):
                    logger.info(
                        "welcome_suggestions[%s]: %d→%d après filtre denied (user=%s)",
                        category_prefix,
                        before,
                        len(suggestions),
                        user_id,
                    )

            if suggestions:
                return suggestions
        return []

    async def _load_user_suggestion_filter(
        self,
        user_id: Optional[int],
    ) -> Optional[tuple]:
        """**#141** — Charge ``(denied_tables, denied_columns_flat)`` pour
        ``user_id``, ou None si pas de filtrage à appliquer.

        Returns:
            - ``None`` si ``user_id`` est None, user inexistant, admin
              ou sans restrictions (enforcement off / pas de règle) →
              pas de filtrage (court-circuit O(1) pour le caller).
            - ``(frozenset[str], frozenset[str])`` sinon :
              ``(denied_tables_with_closure, denied_columns_flat)``.

        **Raise sur crash** : si la lecture BDD ou
        :func:`build_user_schema_view` échoue, l'exception est
        propagée. Le caller (:meth:`get_cached_llm_suggestions`)
        l'attrape pour appliquer une politique fail-closed (retour
        ``[]``). On NE jamais retourne ``None`` sur erreur — ce serait
        un faux-positif "pas de filtrage" qui réintroduirait le leak.
        """
        if user_id is None:
            return None
        from app.models.user import User
        from app.services.data_access.enforcer import is_user_exempt
        from app.services.data_access.visible_schema import (
            build_user_schema_view,
        )

        async with get_session() as session:
            result = await session.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
        if user is None:
            return None
        if is_user_exempt(user):
            return None
        view = await build_user_schema_view(user)
        if not view.has_restrictions:
            return None
        denied_cols_flat = frozenset(col for cols in view.denied_columns.values() for col in cols)
        return (view.denied_tables_with_closure, denied_cols_flat)

    async def generate_welcome_suggestions(
        self,
        user_id: Optional[int] = None,
    ) -> List[Dict[str, str]]:
        """
        Retourne les suggestions en cache (LLM user-specific > LLM générique).
        Si aucun cache → liste vide (pas de fallback programmatique).

        N'appelle PAS le LLM — utilise uniquement le cache.
        L'appel LLM est déclenché par le sync."""
        return await self.get_cached_llm_suggestions(user_id)

    async def _generate_programmatic_suggestions(
        self,
        user_id: Optional[int] = None,
    ) -> List[Dict[str, str]]:
        """
        Génération programmatique de suggestions (pas d'appel LLM).
        Basée sur les DDL et stats DÉJÀ STOCKÉS localement.

        100% programmatique — 0 appel LLM.
        Si user_id est fourni, personnalise en boostant les tables que l'utilisateur
        interroge fréquemment.

        Returns: liste de {"prompt": "...", "label": "..."} (max 6).
        """
        # Lire les DDL stockés (résultat du dernier sync)
        # Phase α.4.C : génération suggestions programmatiques = SYSTEM.
        from app.services.data_access.enforcer import SYSTEM_USER

        all_ddl = await self.training_store.get_all_ddl_contents(user=SYSTEM_USER)
        if not all_ddl:
            return []

        # Parser les colonnes depuis le texte DDL
        col_re = re.compile(r"^\s+(\w+)\s+(\w+)", re.MULTILINE)
        columns_by_table: Dict[str, List[Dict[str, str]]] = {}
        for entry in all_ddl:
            tname = entry.get("table_name", "")
            ddl_text = entry.get("content", "")
            if not tname or not ddl_text:
                continue
            cols = []
            for m in col_re.finditer(ddl_text):
                cols.append({"name": m.group(1), "type": m.group(2).lower()})
            if cols:
                columns_by_table[tname] = cols

        if not columns_by_table:
            return []

        # Usage personnalisé (si user connecté)
        table_usage: Dict[str, int] = {}
        if user_id:
            try:
                table_usage = await self.training_store.get_user_table_usage(user_id)
            except Exception:
                pass  # non-bloquant

        # Types sémantiques
        DATE_TYPES = {"date", "datetime", "datetime2", "smalldatetime", "timestamp"}
        NUMERIC_TYPES = {"money", "smallmoney", "decimal", "numeric", "float", "real"}
        INT_TYPES = {"int", "bigint", "smallint", "tinyint"}
        AMOUNT_RE = re.compile(
            r"(montant|amount|total|solde|balance|prix|price|ca|chiffre|debit|credit)",
            re.IGNORECASE,
        )
        DATE_RE = re.compile(
            r"(date|dt|jour|day|mois|month|annee|year|created|updated|echeance|due)",
            re.IGNORECASE,
        )
        STATUS_RE = re.compile(
            r"(statut|status|state|etat|type|code|flag|actif|active|sens)",
            re.IGNORECASE,
        )
        LABEL_RE = re.compile(
            r"(nom|name|libelle|label|intitule|designation|description|raison)",
            re.IGNORECASE,
        )

        # Profiler chaque table
        table_profiles: List[Dict[str, Any]] = []
        for table_name, cols in columns_by_table.items():
            profile: Dict[str, Any] = {
                "table": table_name,
                "col_count": len(cols),
                "has_date": False,
                "has_amount": False,
                "has_status": False,
                "has_label": False,
            }
            for col in cols:
                cname, ctype = col["name"], col["type"]
                if ctype in DATE_TYPES or DATE_RE.search(cname):
                    profile["has_date"] = True
                if ctype in NUMERIC_TYPES or (ctype in INT_TYPES and AMOUNT_RE.search(cname)):
                    profile["has_amount"] = True
                if STATUS_RE.search(cname):
                    profile["has_status"] = True
                if LABEL_RE.search(cname):
                    profile["has_label"] = True

            # Score générique
            score = float(min(profile["col_count"], 30))
            if profile["has_date"]:
                score += 8
            if profile["has_amount"]:
                score += 10
            if profile["has_status"]:
                score += 4
            if profile["has_label"]:
                score += 4

            # Boost personnalisé par usage
            usage_count = table_usage.get(table_name, 0)
            if usage_count > 0:
                score += usage_count * 8

            profile["score"] = score
            table_profiles.append(profile)

        table_profiles.sort(key=lambda p: p["score"], reverse=True)
        top_tables = table_profiles[:30]

        # Templates de suggestions — max 1 par table
        templates = [
            (
                lambda p: p["has_amount"] and p["has_date"],
                "Montre-moi l'évolution des montants dans {t} par mois",
                "Évolution mensuelle",
            ),
            (
                lambda p: p["has_amount"] and p["has_label"],
                "Quels sont les 10 enregistrements avec les plus gros montants dans {t} ?",
                "Top 10 par montant",
            ),
            (
                lambda p: p["has_status"],
                "Quelle est la répartition par statut dans {t} ?",
                "Répartition par statut",
            ),
            (
                lambda p: p["has_date"],
                "Quels sont les derniers enregistrements ajoutés dans {t} ?",
                "Derniers ajouts",
            ),
            (
                lambda p: p["has_amount"],
                "Y a-t-il des valeurs NULL ou aberrantes dans les montants de {t} ?",
                "Détection d'anomalies",
            ),
            (
                lambda p: p["col_count"] >= 5,
                "Donne-moi un résumé de la table {t} : combien de lignes, colonnes principales",
                "Vue d'ensemble",
            ),
        ]

        suggestions: List[Dict[str, str]] = []
        used_tables: set = set()

        for condition, prompt_tpl, label in templates:
            if len(suggestions) >= 6:
                break
            for profile in top_tables:
                t = profile["table"]
                if t in used_tables:
                    continue
                if condition(profile):
                    suggestions.append(
                        {
                            "prompt": prompt_tpl.format(t=t),
                            "label": label,
                        }
                    )
                    used_tables.add(t)
                    break

        return suggestions

    async def get_sync_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Récupère l'historique des syncs."""
        limit = min(max(limit, 1), 100)
        async with get_session() as session:
            from sqlalchemy import select

            result = await session.execute(
                select(SchemaSync).order_by(SchemaSync.created_at.desc()).limit(limit)
            )
            syncs = result.scalars().all()
            return [s.to_dict() for s in syncs]

    def _generate_ddl(self, table_name: str, table_info: Dict[str, Any]) -> str:
        """Génère un DDL CREATE TABLE depuis les métadonnées YAML."""
        schema = table_info.get("schema", "dbo")
        lines = [f"CREATE TABLE {schema}.{table_name} ("]

        for i, col in enumerate(table_info.get("columns", [])):
            nullable = "NULL" if col.get("nullable", True) else "NOT NULL"
            desc = f" -- {col['description']}" if col.get("description") else ""
            comma = "," if i < len(table_info.get("columns", [])) - 1 else ""
            lines.append(f"    {col['name']} {col['type']} {nullable}{comma}{desc}")

        # Clé primaire
        pk = table_info.get("primary_key", [])
        if pk:
            lines.append(f"    CONSTRAINT PK_{table_name} PRIMARY KEY ({', '.join(pk)})")

        lines.append(");")

        # Clés étrangères
        for fk in table_info.get("foreign_keys", []):
            lines.append(f"-- FK: {fk['column']} REFERENCES {fk['references']}")

        return "\n".join(lines)

    @staticmethod
    def _extract_join_patterns(view_name: str, sql: str) -> List[Dict[str, str]]:
        """
        Parse le SQL d'une vue pour extraire les JOIN patterns.

        Les vues SQL Server contiennent des jointures validées par le DBA.
        On les extrait et les stocke comme documentation cherchable par le RAG.

        Returns:
            Liste de dicts avec 'doc' (texte cherchable) et 'category' (join_pattern:A+B)
        """
        # Pattern : (LEFT|INNER|RIGHT)? JOIN table (AS alias)? ON (condition)
        join_re = re.compile(
            r"(LEFT|INNER|RIGHT|CROSS|FULL)?\s*JOIN\s+"
            r"(?:dbo\.)?"  # Optionnel dbo.
            r"(\w+)\s+"  # Nom de table
            r"(?:AS\s+)?(\w+)\s+"  # Alias (optionnel AS)
            # Capturer ON condition jusqu'au prochain JOIN ou fin de requête
            # (pas [^)]+) qui casse sur les parenthèses imbriquées)
            r"ON\s*\(?(.+?)(?=\s+(?:LEFT|INNER|RIGHT|CROSS|FULL)\s+JOIN\b|\s+WHERE\b|\s+GROUP\b|\s+ORDER\b|\s*$)",
            re.IGNORECASE | re.DOTALL,
        )
        # Aussi capturer le FROM initial
        from_re = re.compile(
            r"FROM\s+(?:dbo\.)?(\w+)\s+(?:AS\s+)?(\w+)",
            re.IGNORECASE,
        )

        from_match = from_re.search(sql)
        if not from_match:
            return []

        base_table = from_match.group(1)
        patterns = []
        tables_in_view = {base_table.upper()}

        for m in join_re.finditer(sql):
            join_type = (m.group(1) or "INNER").upper()
            joined_table = m.group(2)
            on_condition = m.group(4).strip()

            tables_in_view.add(joined_table.upper())

            # Construire un document cherchable par TF-IDF
            doc = (
                f"Vue {view_name} : {join_type} JOIN {joined_table} "
                f"ON {on_condition}. "
                f"Tables impliquées : {base_table}, {joined_table}."
            )

            # Catégorie = tables triées pour dédup
            cat_key = "+".join(sorted([base_table.upper(), joined_table.upper()]))
            patterns.append(
                {
                    "doc": doc,
                    "category": f"join_pattern:{cat_key}",
                }
            )

        return patterns

    def _generate_ddl_from_info_schema(self, table_name: str, columns: List[Dict[str, Any]]) -> str:
        """Génère un DDL depuis INFORMATION_SCHEMA."""
        lines = [f"CREATE TABLE dbo.{table_name} ("]

        for i, col in enumerate(columns):
            col_name = col["COLUMN_NAME"]
            data_type = col["DATA_TYPE"]
            max_len = col.get("CHARACTER_MAXIMUM_LENGTH")
            nullable = "NULL" if col["IS_NULLABLE"] == "YES" else "NOT NULL"

            type_str = data_type
            if max_len and max_len > 0:
                type_str = f"{data_type}({max_len})"

            comma = "," if i < len(columns) - 1 else ""
            lines.append(f"    {col_name} {type_str} {nullable}{comma}")

        lines.append(");")
        return "\n".join(lines)


# Singleton
_sync_service: Optional[SchemaSyncService] = None


def get_sync_service() -> SchemaSyncService:
    """Singleton SchemaSyncService."""
    global _sync_service
    if _sync_service is None:
        _sync_service = SchemaSyncService()
    return _sync_service
