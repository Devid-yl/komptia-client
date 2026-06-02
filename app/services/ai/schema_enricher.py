"""
Service d'enrichissement sémantique du schéma BDD pour Iris.

Génère des descriptions métier pour les tables et colonnes en appelant
un modèle LLM peu coûteux (Haiku) avec des données anonymisées.

Inspiré de Vanna.ai: enrichissement du schéma pour améliorer la précision NL→SQL.

Workflow:
1. Récupérer un échantillon de 5 lignes depuis la base source
2. Anonymiser l'échantillon (Niveau 2: obfuscation)
3. Appeler Haiku avec DDL + échantillon anonymisé
4. Parser les réponses JSON (table_role, column_roles)
5. Stocker via TrainingStore (add_documentation)
"""

import asyncio
import json
import logging
import re
import time
from collections import deque
from typing import Any, Dict, List, Optional

from app.core import clock
from app.services.ai.training_store import get_training_store
from app.services.ai.llm_providers import LLMRequest, get_llm_manager
from app.services.anonymization.strategies import get_confidentiality_manager
from app.services.database.sage_connector import (
    SageConnector,
    get_sage_connector,
    PYODBC_AVAILABLE,
)
from app.constants_ai import (
    ENRICHMENT_MAX_TOKENS,
)
from app.services.ai.value_mapping_stratification import (
    ColumnValueStats,
    classify_value_type,
    decide_cardinality_tier,
    recommend_sample_cap,
)

logger = logging.getLogger(__name__)

# ---------- Utilitaire de résolution de noms SQL ----------
# schema_sync stocke les vues comme 'schema_viewName' (replace(".", "_"))
# mais les tables régulières comme 'TABLE_NAME' (sans schéma).
# Les requêtes SQL Server ont besoin de [schema].[objectName].
_VUE_DDL_RE = re.compile(r"^-- Vue:\s*(\w+)\.(\w+)")


def _resolve_sql_name(stored_name: str, ddl: str) -> tuple:
    """
    Convertit un nom stocké en (schema, sql_object_name).

    Pour les vues (DDL commence par '-- Vue: schema.viewName'):
        retourne (schema, viewName)
    Pour les tables régulières:
        retourne (config.sage.source_schema, stored_name) — défaut "dbo".

    Exemples:
        _resolve_sql_name('dbo_viewTempBudgAct01_21', '-- Vue: dbo.viewTemp...')
            → ('dbo', 'viewTempBudgAct01_21')
        _resolve_sql_name('F_COMPTES', 'CREATE TABLE F_COMPTES ...')
            → ('dbo', 'F_COMPTES')   # ou (source_schema, ...) si configuré
    """
    if ddl:
        m = _VUE_DDL_RE.match(ddl)
        if m:
            return m.group(1), m.group(2)
    # Fallback générique : lit la config (env var SAGE_DB_SCHEMA, default
    # "dbo"). Évite l'hardcode du schéma source spécifique à un logiciel
    # (cf. règle GÉNÉRICITÉ de CLAUDE.md). get_config est lru_cache → pas
    # d'overhead à l'appel répété.
    from app.config import get_config as _get_config

    return _get_config().sage.source_schema or "dbo", stored_name


def _sql_table_ref(stored_name: str, ddl: str) -> str:
    """Retourne '[schema].[objectName]' pour une requête SQL."""
    schema, obj = _resolve_sql_name(stored_name, ddl)
    return f"[{schema}].[{obj}]"


def _sql_object_name(stored_name: str, ddl: str) -> str:
    """Retourne le nom d'objet SQL Server (sans schéma, pour INFORMATION_SCHEMA)."""
    _, obj = _resolve_sql_name(stored_name, ddl)
    return obj


def _get_db_conventions() -> str:
    """Retourne les notes de conventions BDD depuis la config (vide si non configuré)."""
    try:
        from app.config import get_config

        notes = get_config().sage.conventions_notes
        if notes:
            return f"\nConventions de la base :\n{notes}\n"
    except Exception as e:
        logger.warning("Impossible de charger les conventions BDD depuis la config: %s", e)
    return ""


async def _store_value_mappings(
    table_name: str,
    column_name: str,
    real_values: List[str],
) -> None:
    """Cache des vraies valeurs Sage (table → colonne → valeur) pour la résolution
    de termes utilisateur. PAS d'anonymisation : /data-privacy
    (``anonymization_terms``) est la seule source de vérité pour les pseudos
    runtime — voir ``app/services/anonymization/pseudonymizer.py``.

    Stratégie : DELETE + raw executemany (plus rapide que l'ORM add_all).
    """
    try:
        from app.core.database import get_session
        from app.models.value_mapping import ValueMapping
        from sqlalchemy import delete, text

        now = clock.now().isoformat()

        rows = []
        seen = set()
        for real_val in real_values:
            stripped = str(real_val).strip()
            real_lower = stripped.lower()
            if not real_lower or real_lower in seen:
                continue
            seen.add(real_lower)
            vtype = classify_value_type(stripped)

            rows.append(
                {
                    "tn": table_name,
                    "cn": column_name,
                    "rv": stripped,
                    "rl": real_lower,
                    "vt": vtype,
                    "ca": now,
                }
            )

        if not rows:
            return

        async with get_session() as session:
            await session.execute(
                delete(ValueMapping).where(
                    ValueMapping.table_name == table_name,
                    ValueMapping.column_name == column_name,
                )
            )
            await session.execute(
                text(
                    "INSERT INTO value_mapping "
                    "(table_name, column_name, real_value, real_value_lower, "
                    "value_type, created_at) "
                    "VALUES (:tn, :cn, :rv, :rl, :vt, :ca)"
                ),
                rows,
            )
            await session.commit()
    except Exception as e:
        logger.debug("ValueMapping storage failed for %s.%s: %s", table_name, column_name, e)


async def _store_value_mappings_bulk(
    table_name: str,
    all_value_lists: list[tuple[str, list[str]]],
) -> None:
    """Stocke les vraies valeurs Sage de TOUTES les colonnes d'une table en UNE
    transaction. Plus rapide qu'appeler ``_store_value_mappings`` par colonne
    (SQLite n'autorise qu'un seul writer).

    ``all_value_lists`` : liste de ``(col_name, [real_value, ...])``. Aucune
    valeur anonymisée n'est stockée — cf. doctrine ``/data-privacy`` seule source.
    """
    try:
        from app.core.database import get_session
        from app.models.value_mapping import ValueMapping
        from sqlalchemy import delete, text

        now = clock.now().isoformat()

        all_rows = []
        columns_to_delete = []
        for col_name, real_values in all_value_lists:
            columns_to_delete.append(col_name)
            seen = set()
            for real_val in real_values:
                stripped = str(real_val).strip()
                real_lower = stripped.lower()
                if not real_lower or real_lower in seen:
                    continue
                seen.add(real_lower)
                vtype = classify_value_type(stripped)

                all_rows.append(
                    {
                        "tn": table_name,
                        "cn": col_name,
                        "rv": stripped,
                        "rl": real_lower,
                        "vt": vtype,
                        "ca": now,
                    }
                )

        if not all_rows:
            return

        async with get_session() as session:
            await session.execute(
                delete(ValueMapping).where(
                    ValueMapping.table_name == table_name,
                    ValueMapping.column_name.in_(columns_to_delete),
                )
            )
            await session.execute(
                text(
                    "INSERT INTO value_mapping "
                    "(table_name, column_name, real_value, real_value_lower, "
                    "value_type, created_at) "
                    "VALUES (:tn, :cn, :rv, :rl, :vt, :ca)"
                ),
                all_rows,
            )
            await session.commit()

        logger.debug(
            "ValueMapping bulk: %s — %d colonnes, %d valeurs",
            table_name,
            len(columns_to_delete),
            len(all_rows),
        )
    except Exception as e:
        logger.warning("ValueMapping bulk failed for %s: %s", table_name, e, exc_info=True)


# ────────────────────────────────────────────────────────────────────
# B1 — FTS5-aware bulk insert helpers
# ────────────────────────────────────────────────────────────────────
#
# Problème : les triggers FTS5 vm_ai/vm_ad/vm_au (sur value_mapping)
# multiplient le coût de chaque INSERT par 5-10× car SQLite met à jour
# l'index inversé incrémentalement à chaque ligne. Pour un bulk insert
# de 20-30M lignes (sync schéma), c'est catastrophique.
#
# Pattern correct (issu de la doc SQLite FTS5) :
#   1. DROP triggers
#   2. Bulk INSERT (sans pénalité par ligne)
#   3. INSERT INTO ftstab(ftstab) VALUES('rebuild') — reconstruit en bloc
#   4. CREATE triggers (pour les futurs INSERTs incrémentaux)
#
# Le rebuild bulk est ~5-10× plus rapide que les triggers incrémentaux.
# Le `try/finally` garantit la restauration des triggers même si la phase
# d'enrichissement crashe au milieu — sinon FTS5 reste sans triggers et
# les recherches deviennent stales jusqu'au prochain setup_fts5 manuel.

_FTS5_TRIGGER_NAMES = ("vm_ai", "vm_ad", "vm_au")
_FTS5_TABLE_NAME = "value_mapping_fts"


async def fts5_disable_triggers_for_bulk() -> bool:
    """DROP les 3 triggers FTS5 sur value_mapping.

    Retourne True si au moins un trigger existait (donc à recréer ensuite),
    False si aucun (FTS5 pas configuré → la sync n'a rien à orchestrer).

    En cas d'erreur, retourne False et logue — la sync continue avec les
    triggers en place (pénalité de perf ×5-10 mais pas de corruption).
    """
    try:
        from app.core.database import get_session
        from sqlalchemy import text

        async with get_session() as session:
            result = await session.execute(
                text(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='trigger' AND tbl_name='value_mapping' "
                    "AND name IN ('vm_ai', 'vm_ad', 'vm_au')"
                )
            )
            existing = [row[0] for row in result.fetchall()]
            if not existing:
                return False
            for name in existing:
                # Whitelist via _FTS5_TRIGGER_NAMES — pas d'injection possible
                # même si le nom vient de sqlite_master.
                if name in _FTS5_TRIGGER_NAMES:
                    await session.execute(text(f"DROP TRIGGER IF EXISTS {name}"))
            await session.commit()
            logger.info(
                "FTS5 triggers désactivés pour bulk (%d triggers : %s) — "
                "seront recréés en fin de phase 5",
                len(existing),
                ", ".join(existing),
            )
            return True
    except Exception:
        logger.warning(
            "Désactivation triggers FTS5 échouée — la sync continuera avec "
            "les triggers actifs (perf ×5-10 dégradée). Voir traceback :",
            exc_info=True,
        )
        return False


async def fts5_rebuild_and_recreate_triggers() -> None:
    """REBUILD FTS5 puis recreate les 3 triggers vm_ai/vm_ad/vm_au.

    À appeler en pendant de fts5_disable_triggers_for_bulk(), idéalement
    dans un `finally` pour garantir la restauration même en cas d'exception.

    Si le rebuild échoue, les triggers restent dropped et FTS5 retourne des
    résultats incomplets. L'admin DOIT relancer scripts/setup_fts5_value_mapping.py
    manuellement (message d'erreur explicite).
    """
    from app.core.database import get_session
    from sqlalchemy import text

    async with get_session() as session:
        # Vérifier que la table FTS5 existe — sinon rien à rebuild
        result = await session.execute(
            text(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='value_mapping_fts' LIMIT 1"
            )
        )
        if not result.first():
            logger.warning(
                "value_mapping_fts table absente — skip rebuild + recreate. "
                "Lancer scripts/setup_fts5_value_mapping.py pour initialiser."
            )
            return

        try:
            logger.info("FTS5 rebuild en cours (peut prendre 1-2 min)...")
            await session.execute(
                text("INSERT INTO value_mapping_fts(value_mapping_fts) VALUES('rebuild')")
            )
            # Recréer les triggers (IF NOT EXISTS pour idempotence)
            await session.execute(
                text(
                    "CREATE TRIGGER IF NOT EXISTS vm_ai AFTER INSERT ON value_mapping BEGIN "
                    "INSERT INTO value_mapping_fts(rowid, real_value_lower) "
                    "VALUES (new.id, new.real_value_lower); END"
                )
            )
            await session.execute(
                text(
                    "CREATE TRIGGER IF NOT EXISTS vm_ad AFTER DELETE ON value_mapping BEGIN "
                    "INSERT INTO value_mapping_fts(value_mapping_fts, rowid, real_value_lower) "
                    "VALUES('delete', old.id, old.real_value_lower); END"
                )
            )
            await session.execute(
                text(
                    "CREATE TRIGGER IF NOT EXISTS vm_au AFTER UPDATE ON value_mapping BEGIN "
                    "INSERT INTO value_mapping_fts(value_mapping_fts, rowid, real_value_lower) "
                    "VALUES('delete', old.id, old.real_value_lower); "
                    "INSERT INTO value_mapping_fts(rowid, real_value_lower) "
                    "VALUES (new.id, new.real_value_lower); END"
                )
            )
            await session.commit()
            logger.info("✅ FTS5 rebuild + triggers vm_ai/vm_ad/vm_au recréés")
        except Exception:
            logger.error(
                "FTS5 rebuild OU recreate triggers ÉCHOUÉ — l'index FTS5 est "
                "potentiellement stale et les recherches retourneront des résultats "
                "incomplets. ACTION ADMIN : lancer "
                "`python scripts/setup_fts5_value_mapping.py` manuellement.",
                exc_info=True,
            )
            # Re-raise pour que le caller voit l'échec — le finally du caller
            # peut décider de la suite (mais l'erreur est déjà loggée loud).
            raise


class SchemaEnricher:
    """
    Enrichit le schéma BDD avec des descriptions sémantiques générées par LLM.

    Utilise Haiku (modèle léger) pour générer des descriptions à coût minimal.
    Stocke les résultats dans TrainingStore pour alimentation du RAG.

    Lazy initialization: training_store, llm_manager, confidentiality_manager
    sont instanciés à la première utilisation.
    """

    def __init__(self):
        """Initialise l'enrichisseur avec accesseurs lazy."""
        self._training_store: Optional[Any] = None
        self._llm_manager: Optional[Any] = None
        self._confidentiality_manager: Optional[Any] = None
        self._sage_unreachable: bool = False  # Flag pour skip connexions Sage si injoignable

    @staticmethod
    def _is_conversation_active() -> bool:
        """Vérifie si une conversation utilisateur est en cours.

        Quand c'est le cas, l'enrichissement se met en pause pour ne pas
        concurrencer les requêtes utilisateur sur le budget API (rate limit).
        """
        try:
            from app.services.ai.agent_service import has_active_conversations

            return has_active_conversations()
        except ImportError:
            return False

    @staticmethod
    def _prioritize_tables(table_names: List[str]) -> List[str]:
        """Trie les tables par priorité pour l'enrichissement.

        Heuristique générique (pas de noms hardcodés) :
        - Tables les plus référencées par FK en premier (tables centrales)
        - En cas d'égalité, ordre alphabétique
        """
        try:
            from app.services.ai.schema_loader import get_schema_loader

            schema = get_schema_loader()
            # Phase α.4.C : enrichissement schéma = SYSTEM (job admin).
            # SchemaLoader prend user_view= mais ici on n'a pas de user — on
            # ne filtre pas (sync schéma global). Documenté comme intent
            # système via le commentaire (pas de user_view passé = sync).
            tables_info = schema.get_tables()  # type: ignore[arg-type]  # SYSTEM context, no user_view

            # Compter combien de fois chaque table est référencée en FK
            fk_ref_count: dict[str, int] = {t: 0 for t in table_names}
            for tname in table_names:
                tinfo = tables_info.get(tname, {})
                columns = tinfo.get("columns", [])
                for col in columns:
                    fk_target = col.get("fk_table", "")
                    if fk_target and fk_target in fk_ref_count:
                        fk_ref_count[fk_target] += 1

            return sorted(table_names, key=lambda t: (-fk_ref_count.get(t, 0), t))
        except Exception:
            return sorted(table_names)

    @staticmethod
    async def _create_sage_connector() -> "SageConnector":
        """Retourne le SINGLETON SageConnector -- source unique de vrit.

        Avant avril 2026 cette mthode crait des instances phmres en
        re-lisant la BDD active ou en copiant les params du singleton.
        C'tait une logique DUPLIQUE de ``init_sage_from_db_config``
        qui a tendance  diverger.

        Maintenant le singleton est garanti  jour (cf.
        ``init_sage_from_db_config`` au boot + ``_reload_sage_connector``
        sur chaque update/activate via /admin/database). Si non
        configur, ``connect()`` lvera ``[CONFIG_MANQUANTE]`` proprement
        -- pas de fallback silencieux  des credentials .env vides.
        """
        return get_sage_connector()

    @property
    def training_store(self) -> Any:
        """Lazy accessor pour TrainingStore."""
        if self._training_store is None:
            self._training_store = get_training_store()
        return self._training_store

    @property
    def llm_manager(self) -> Any:
        """Lazy accessor pour LLMManager."""
        if self._llm_manager is None:
            self._llm_manager = get_llm_manager()
        return self._llm_manager

    async def _ensure_providers(self):
        """S'assure que les providers LLM sont chargés (depuis env ou BDD)."""
        from app.services.ai.llm_providers import ensure_providers_from_db

        await ensure_providers_from_db()

    @property
    def confidentiality_manager(self) -> Any:
        """Lazy accessor pour ConfidentialityManager."""
        if self._confidentiality_manager is None:
            self._confidentiality_manager = get_confidentiality_manager()
        return self._confidentiality_manager

    async def enrich_table(
        self,
        table_name: str,
        ddl: str,
        connector: Optional["SageConnector"] = None,
    ) -> Dict[str, Any]:
        """
        Enrichit une table avec une description de rôle et des descriptions de colonnes.

        Workflow:
        1. Récupérer échantillon de 5 lignes depuis Sage (si connecté) — ne sert
           qu'à détecter une connexion morte (`_sage_unreachable`), le contenu
           est ignoré.
        2. Niveau 1 strict — DDL seul envoyé au LLM (pas d'échantillon, même
           obfusqué). Cf. anon-impl-loop tâche #6.
        3. Appeler Haiku avec prompt structuré (DDL + nom + conventions BDD).
        4. Parser réponse JSON.
        5. Stocker descriptions via TrainingStore.add_documentation().

        Args:
            table_name: Nom de la table (ex: "TABLE_NAME")
            ddl: DDL complet de la table (CREATE TABLE ...)
            connector: SageConnector partagé (optionnel). Si fourni, réutilisé sans
                       créer/fermer une nouvelle connexion. Si None, crée et ferme
                       un connector dédié.

        Returns:
            Dict avec:
            - success (bool)
            - table_role (str) si succès
            - column_roles (Dict[str, str]) si succès
            - error (str) si échec

        Note: Les erreurs sont loggées mais ne font pas échouer. Le service continue.
        """
        result: Dict[str, Any] = {
            "success": False,
            "table_name": table_name,
            "table_role": None,
            "column_roles": {},
            "error": None,
        }

        try:
            # Validation stricte du nom de table (lettres, chiffres, underscores)
            if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
                result["error"] = f"Nom de table invalide: {table_name}"
                return result

            # Étape 1: Récupérer un échantillon de 5 lignes depuis Sage
            sample_rows = []
            sample_columns = []
            if PYODBC_AVAILABLE and not self._sage_unreachable:
                owns_connector = connector is None
                local_connector = connector
                try:
                    if owns_connector:
                        local_connector = await self._create_sage_connector()
                        await local_connector.connect()

                    # Bracket-quoting — résoudre le vrai nom SQL (vues: dbo_view → dbo.view)
                    query = f"SELECT TOP 5 * FROM {_sql_table_ref(table_name, ddl)}"
                    # bypass_admin_cap : enrichissement RAG interne, pas
                    # user-visible. ``TOP 5`` cap dj cot serveur ;
                    # le bypass vite que ``min(None, admin_max_rows)``
                    # tronque  moins de 5 lignes si admin a un plafond bas.
                    result_obj = await local_connector.execute(query, bypass_admin_cap=True)
                    sample_rows = result_obj.to_dicts()
                    sample_columns = result_obj.columns

                    logger.debug(
                        "Échantillon de %d lignes récupérées pour %s",
                        len(sample_rows),
                        table_name,
                    )
                except Exception as e:
                    # Détecter les erreurs de connexion (timeout, réseau) pour éviter
                    # de retenter 823 fois avec 14s de timeout chacune
                    err_str = str(e).lower()
                    if "timeout" in err_str or "connexion_impossible" in err_str:
                        self._sage_unreachable = True
                        logger.warning(
                            "Sage injoignable, skip des échantillons pour les tables restantes. "
                            "Enrichissement par DDL seul."
                        )
                    else:
                        logger.warning(
                            "Impossible de récupérer l'échantillon pour %s (%s). "
                            "Enrichissement par DDL seul.",
                            table_name,
                            type(e).__name__,
                        )
                # NOTE : pas de ``finally: await local_connector.close()``.
                # ``_create_sage_connector()`` retourne le SINGLETON
                # (cf. ``schema_enricher.py:465``), partagé avec
                # search_schema / execute_sql / déjà-vu prefetch /
                # check_schema_freshness. Le fermer ici provoque un churn
                # open/close visible côté tools concurrents (cf. fix audit
                # 2026-05-22). Le lifecycle est géré au shutdown via
                # ``close_sage_connector()`` ou ``activate_connection``.

            # Étape 2: Niveau 1 (schéma seul) — l'échantillon n'est PAS envoyé
            # au LLM. L'enrichissement s'appuie uniquement sur DDL + nom de
            # table + conventions BDD. Cf. anon-impl-loop tâche #6 :
            # confidentialité = aucune valeur réelle ne quitte le serveur,
            # même obfusquée. Le sample fetché plus haut sert uniquement à
            # déclencher la détection précoce de Sage injoignable
            # (`_sage_unreachable`) — il est ensuite ignoré.
            del sample_rows, sample_columns

            # Étape 3: Construire le prompt pour Haiku (DDL seul, pas de sample)
            prompt = self._build_enrichment_prompt(table_name, ddl, [], [])

            # Étape 4: Appeler Haiku
            # S'assurer que les providers sont chargés (clés API depuis BDD si pas en env)
            await self._ensure_providers()

            from app.config import get_config

            db_label = get_config().sage.label
            enrichment_system = (
                f"Tu es un analyste de bases de données spécialisé en {db_label}. "
                "Analyse la structure de la table à partir du DDL et des conventions "
                "BDD pour générer des descriptions métier précises. "
                "Aucune donnée réelle n'est fournie (Niveau 1 — schéma seul) : "
                "concentre-toi sur le TYPE des colonnes, leur nom, leur ordre, et "
                "les conventions du schéma. "
                "Réponds UNIQUEMENT en JSON valide, sans texte supplémentaire."
            )

            # Retry avec max_tokens adaptatif si la réponse est tronquée (stop_reason=max_tokens)
            max_retries_truncation = 2
            current_max_tokens = ENRICHMENT_MAX_TOKENS  # 2048 par défaut
            parsed = None

            for attempt in range(max_retries_truncation + 1):
                request = LLMRequest(
                    prompt=prompt,
                    system=enrichment_system,
                    temperature=0.1,
                    max_tokens=current_max_tokens,
                )

                try:
                    from app.services.ai.llm_runtime import (
                        CallProfile,
                        ModelKind,
                        RetryPolicy,
                        call_llm,
                    )

                    response = await call_llm(
                        CallProfile(
                            caller="schema_enrich_table",
                            model_kind=ModelKind.UTILITY,
                            retry=RetryPolicy.NONE,  # retry custom truncation géré par le for attempt
                        ),
                        request,
                    )
                except Exception as llm_err:
                    logger.warning(
                        "LLM échoué pour %s (attempt %d): %s",
                        table_name,
                        attempt + 1,
                        type(llm_err).__name__,
                    )
                    if attempt < max_retries_truncation:
                        await asyncio.sleep(2.0 * (attempt + 1))
                        continue
                    result["error"] = f"LLM {type(llm_err).__name__}"
                    return result
                response_text = response.content.strip()

                # Vérifier si la réponse a été tronquée
                stop_reason = None
                if response.raw_response:
                    stop_reason = response.raw_response.get("stop_reason")

                was_truncated = stop_reason == "max_tokens"

                # Étape 5: Parser la réponse JSON
                # Stripper les blocs markdown (```json ... ```) que les LLM ajoutent souvent
                cleaned_text = response_text
                md_match = re.search(r"```(?:json)?\s*\n?(.*?)```", cleaned_text, re.DOTALL)
                if md_match:
                    cleaned_text = md_match.group(1).strip()

                try:
                    parsed = json.loads(cleaned_text)
                    break  # Parse OK, sortir de la boucle
                except json.JSONDecodeError:
                    # Fallback: chercher un bloc JSON dans la réponse
                    json_match = re.search(r"\{.*\}", cleaned_text, re.DOTALL)
                    if json_match:
                        try:
                            parsed = json.loads(json_match.group(0))
                            break  # Parse OK via fallback
                        except json.JSONDecodeError:
                            pass

                    # JSON invalide — si tronqué, retenter avec plus de tokens
                    if was_truncated and attempt < max_retries_truncation:
                        current_max_tokens = min(current_max_tokens * 2, 8192)
                        logger.warning(
                            "Enrichissement %s tronqué (max_tokens atteint, %d tokens). "
                            "Retry avec max_tokens=%d (tentative %d/%d)",
                            table_name,
                            response.completion_tokens or 0,
                            current_max_tokens,
                            attempt + 1,
                            max_retries_truncation,
                        )
                        await asyncio.sleep(1.0)
                        continue
                    else:
                        # Pas tronqué ou plus de retries — erreur définitive
                        logger.error(
                            "Réponse Haiku invalide pour %s (tronqué=%s, tentative %d). "
                            "Réponse (%d chars): %s",
                            table_name,
                            was_truncated,
                            attempt + 1,
                            len(response_text),
                            response_text[:300],
                        )
                        result["error"] = (
                            "Réponse LLM tronquée" if was_truncated else "Réponse LLM invalide"
                        )
                        return result

            if parsed is None:
                result["error"] = "Réponse LLM invalide après retries"
                return result

            table_role = parsed.get("table_role") or ""
            column_roles = parsed.get("column_roles") or {}

            # Valider les types de la réponse LLM (le LLM peut retourner des types inattendus)
            if not isinstance(table_role, str):
                table_role = str(table_role)
            if not isinstance(column_roles, dict):
                logger.warning(
                    "column_roles invalide pour %s (type=%s), ignoré",
                    table_name,
                    type(column_roles).__name__,
                )
                column_roles = {}

            if not table_role:
                logger.warning("Haiku n'a pas fourni de table_role pour %s", table_name)
                result["error"] = "table_role vide"
                return result

            # Étape 6: Stocker les descriptions via TrainingStore
            try:
                # Stocker le rôle de la table
                if table_role:
                    await self.training_store.add_documentation(
                        doc=table_role,
                        category=f"table_role:{table_name}",
                        tags=["auto_enriched", "schema"],
                        source="schema_enricher",
                    )

                # Stocker les rôles des colonnes
                stored_column_roles = {}
                for col_name, col_desc in column_roles.items():
                    if col_desc:
                        await self.training_store.add_documentation(
                            doc=col_desc,
                            category=f"column_role:{table_name}.{col_name}",
                            tags=["auto_enriched", "schema", "column"],
                            source="schema_enricher",
                        )
                        stored_column_roles[col_name] = col_desc

                result["success"] = True
                result["table_role"] = table_role
                result["column_roles"] = stored_column_roles

                logger.info(
                    "Table %s enrichie: %d colonnes documentées",
                    table_name,
                    len(stored_column_roles),
                )

            except Exception as e:
                logger.error("Erreur lors du stockage des descriptions pour %s: %s", table_name, e)
                result["error"] = "Erreur lors du stockage des descriptions"

        except Exception as e:
            logger.error("Erreur enrichissement %s: %s", table_name, e, exc_info=True)
            result["error"] = f"Erreur enrichissement ({type(e).__name__})"

        return result

    async def sample_column_values(
        self,
        table_name: str,
        columns: List[Dict[str, Any]],
        connector: Optional["SageConnector"] = None,
        sql_table_name: Optional[str] = None,
        column_stats_hint: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, List[str]]:
        """
        Sample les valeurs distinctes de chaque colonne, anonymise, et stocke dans training_data.

        Args:
            table_name: Nom stocké de la table (pour training_store)
            columns: Liste de dicts avec au minimum {"name": str, "type": str}
            connector: SageConnector partagé (optionnel)
            sql_table_name: Nom SQL Server réel (pour les requêtes). Si None, = table_name.
            column_stats_hint: T5 — Si fourni, ``{col_name: {"distinct": N, …}}``
                permet d'appliquer une stratification par cardinalité :
                  - low/mid (≤ 1000 distincts) → fetch exhaustif (comportement actuel)
                  - high (> 1000 distincts) → fetch top-K par fréquence
                Si None, comportement = exhaustif (rétrocompat).

        Returns:
            Dict[column_name → List[anonymized_values]]
        """
        result: Dict[str, List[str]] = {}
        effective_sql_name = sql_table_name or table_name

        if not PYODBC_AVAILABLE or self._sage_unreachable:
            return result

        owns_connector = connector is None
        local_connector = connector
        try:
            if owns_connector:
                local_connector = await self._create_sage_connector()
                await local_connector.connect()

            # Types incompatibles ou inutiles pour la recherche de valeurs
            _skip_types = (
                "ntext",
                "text",
                "image",
                "xml",  # Incompatibles avec DISTINCT
                "uniqueidentifier",  # GUIDs — inutiles pour la recherche
                "varbinary",
                "binary",  # Données binaires
                "timestamp",
                "rowversion",  # Marqueurs internes
            )

            # Collecter les noms de colonnes (exclure les types non utiles)
            col_names = []
            for col_info in columns:
                cn = col_info["name"] if isinstance(col_info, dict) else col_info
                ct = (col_info.get("type") or "").lower() if isinstance(col_info, dict) else ""
                if any(t in ct for t in _skip_types):
                    continue
                col_names.append(cn)

            # Batch parallèle (groupes de 30 colonnes en parallèle)
            BATCH_SIZE = 30
            for batch_start in range(0, len(col_names), BATCH_SIZE):
                if self._sage_unreachable:
                    break
                batch = col_names[batch_start : batch_start + BATCH_SIZE]

                async def _fetch_one(cn: str) -> tuple:
                    try:
                        # T5 — Stratification par cardinalité :
                        # - low/mid (≤ 1000 distincts) → fetch exhaustif (0 = pas de cap)
                        # - high (> 1000) → fetch top-1000 par fréquence (si connecteur le supporte)
                        cap: int | None = None
                        if column_stats_hint:
                            distinct = column_stats_hint.get(cn, {}).get("distinct")
                            if isinstance(distinct, (int, float)) and distinct > 0:
                                tier = decide_cardinality_tier(int(distinct))
                                cap = recommend_sample_cap(tier)
                        if cap is not None:
                            # Fail-soft : si la méthode n'existe pas (ancien
                            # connecteur, mock) OU si elle RAISE au runtime
                            # (timeout, syntax mismatch dialecte), on retombe
                            # sur get_distinct_values borné — top-N par
                            # fréquence est une optimisation, pas un contrat.
                            vals = None
                            top_freq_fn = getattr(
                                local_connector,
                                "get_top_values_with_frequency",
                                None,
                            )
                            if top_freq_fn is not None:
                                try:
                                    pairs = await top_freq_fn(effective_sql_name, cn, cap)
                                    vals = [v for v, _ in pairs]
                                except Exception as top_err:
                                    # Fallback explicite : on log debug et on
                                    # essaie get_distinct_values plutôt que de
                                    # skip la colonne en silence (cf. T5
                                    # principe « aucune garde silencieuse »).
                                    logger.debug(
                                        "get_top_values_with_frequency échoué pour %s.%s "
                                        "(cap=%d) : %s — fallback get_distinct_values",
                                        effective_sql_name,
                                        cn,
                                        cap,
                                        top_err,
                                    )
                            if vals is None:
                                # Phase α.4.C : sampling RAG = SYSTEM (job sync).
                                from app.services.data_access.enforcer import SYSTEM_USER

                                vals = await local_connector.get_distinct_values(
                                    effective_sql_name, cn, cap, user=SYSTEM_USER
                                )
                        else:
                            # 0 = toutes les valeurs distinctes (pas de limite)
                            from app.services.data_access.enforcer import SYSTEM_USER

                            vals = await local_connector.get_distinct_values(
                                effective_sql_name, cn, 0, user=SYSTEM_USER
                            )
                        return cn, vals, None
                    except Exception as fetch_err:
                        return cn, [], fetch_err

                # Phase A : Fetch toutes les colonnes en parallèle depuis Sage
                batch_results = await asyncio.gather(*[_fetch_one(cn) for cn in batch])

                # Phase B : Traiter les résultats et accumuler pour bulk write
                all_value_lists: list[tuple[str, list[str]]] = []

                for col_name, raw_values, error in batch_results:
                    if error:
                        err_str = str(error).lower()
                        if "timeout" in err_str or "connexion_impossible" in err_str:
                            self._sage_unreachable = True
                            logger.warning(
                                "Sage injoignable pendant sampling valeurs %s, skip.",
                                table_name,
                            )
                            break
                        logger.debug("Erreur sampling %s.%s: %s", table_name, col_name, error)
                        continue

                    if not raw_values:
                        continue

                    seen = set()
                    unique_real: list[str] = []
                    for rv in raw_values:
                        if rv is None:
                            continue
                        stripped = str(rv).strip()
                        key = stripped.lower()
                        if not stripped or key in seen:
                            continue
                        seen.add(key)
                        unique_real.append(stripped)

                    if unique_real:
                        result[col_name] = unique_real
                        all_value_lists.append((col_name, unique_real))

                # Phase C : Bulk write — UNE transaction pour toutes les colonnes du batch
                if all_value_lists:
                    for col_name, real_values in all_value_lists:
                        values_json = json.dumps(real_values, ensure_ascii=False)
                        await self.training_store.add_documentation(
                            doc=values_json,
                            category=f"column_values:{table_name}.{col_name}",
                            tags=["auto_enriched", "column_values", table_name],
                            source="schema_enricher",
                        )

                        # T5 — Stats agrégées par colonne (cardinalité, length, type
                        # distribution). Aucune valeur cleartext.
                        try:
                            total_distinct = len(real_values)
                            if column_stats_hint:
                                hint = column_stats_hint.get(col_name, {})
                                hinted = hint.get("distinct")
                                if isinstance(hinted, (int, float)) and hinted > 0:
                                    total_distinct = int(hinted)
                            col_stats_obj = ColumnValueStats.from_sample(
                                iter(real_values),
                                total_distinct=total_distinct,
                            )
                            await self.training_store.add_documentation(
                                doc=json.dumps(col_stats_obj.to_dict(), ensure_ascii=False),
                                category=(f"column_value_stats:{table_name}.{col_name}"),
                                tags=[
                                    "auto_enriched",
                                    "column_value_stats",
                                    table_name,
                                ],
                                source="schema_enricher",
                            )
                        except Exception as stats_err:
                            logger.debug(
                                "ColumnValueStats failed for %s.%s: %s",
                                table_name,
                                col_name,
                                stats_err,
                            )

                    await _store_value_mappings_bulk(table_name, all_value_lists)

        except Exception as e:
            err_str = str(e).lower()
            if "timeout" in err_str or "connexion_impossible" in err_str:
                self._sage_unreachable = True
            logger.warning("Erreur sampling valeurs %s: %s", table_name, e)
        # NOTE singleton (fix audit 2026-05-22) : pas de close — cf.
        # ``_create_sage_connector`` ligne 465 qui retourne le singleton.

        if result:
            logger.info(
                "✓ %s: valeurs distinctes sampées pour %d colonnes",
                table_name,
                len(result),
            )
        return result

    async def collect_column_stats(
        self,
        table_name: str,
        columns: List[Dict[str, Any]],
        connector: Optional["SageConnector"] = None,
        sql_table_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Collecte les stats par colonne (cardinalité, % NULL, min/max) et le row count.

        Stocke dans TrainingStore avec catégorie 'column_stats:{TABLE}'.
        Ces stats enrichissent le DDL affiché au LLM.

        Args:
            table_name: Nom stocké (pour training_store)
            sql_table_name: Nom SQL Server réel (pour les requêtes). Si None, = table_name.

        Returns:
            Dict {"row_count": int, "columns": {col: {"distinct": N, "null_pct": X, ...}}}
        """
        result: Dict[str, Any] = {"row_count": 0, "columns": {}}
        effective_sql_name = sql_table_name or table_name

        if not PYODBC_AVAILABLE:
            return result
        # Ne PAS checker _sage_unreachable ici : un timeout sur UNE table
        # ne doit pas bloquer les stats de TOUTES les autres tables.

        owns_connector = connector is None
        local_connector = connector
        try:
            if owns_connector:
                local_connector = await self._create_sage_connector()
                await local_connector.connect()

            # Collecter stats — utiliser le nom SQL réel pour les requêtes
            col_stats = await local_connector.get_column_stats(effective_sql_name, columns)

            # Extraire le row_count depuis la première colonne
            row_count = 0
            if col_stats:
                first = next(iter(col_stats.values()), {})
                row_count = first.get("total_rows", 0)

            result["row_count"] = row_count
            result["columns"] = col_stats

            if col_stats:
                stats_payload = {
                    "row_count": row_count,
                    "columns": {
                        col: {
                            k: (float(v) if isinstance(v, (int, float)) else str(v))
                            for k, v in stats.items()
                            if k != "total_rows"
                        }
                        for col, stats in col_stats.items()
                    },
                }
                await self.training_store.add_documentation(
                    doc=json.dumps(stats_payload, ensure_ascii=False),
                    category=f"column_stats:{table_name}",
                    tags=["auto_enriched", "column_stats", table_name],
                    source="schema_enricher",
                )

                logger.info(
                    "✓ %s: stats collectées (%d lignes, %d colonnes)",
                    table_name,
                    row_count,
                    len(col_stats),
                )

        except Exception as e:
            logger.warning("collect_column_stats(%s) failed: %s", table_name, e)
        # NOTE singleton (fix audit 2026-05-22) : pas de close — cf.
        # ``_create_sage_connector`` ligne 465 qui retourne le singleton.

        return result

    async def enrich_relationships(
        self,
        table_name: str,
        connector: Optional["SageConnector"] = None,
        sql_table_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Enrichit les relations (foreign keys) d'une table — BIDIRECTIONNEL.

        Query INFORMATION_SCHEMA pour les clés étrangères sortantes (cette table
        référence d'autres) ET entrantes (d'autres tables référencent celle-ci).

        Args:
            table_name: Nom stocké de la table (pour training_store)
            connector: SageConnector partagé (optionnel). Si fourni, réutilisé sans
                       créer/fermer une nouvelle connexion. Si None, crée et ferme
                       un connector dédié.
            sql_table_name: Nom SQL Server réel (pour INFORMATION_SCHEMA). Si None, = table_name.

        Returns:
            Dict avec:
            - success (bool)
            - relationships (List[Dict]) — FK sortantes
            - reverse_relationships (List[Dict]) — FK entrantes
            - error (str) si échec
        """
        effective_sql_name = sql_table_name or table_name
        result: Dict[str, Any] = {
            "success": False,
            "table_name": table_name,
            "relationships": [],
            "reverse_relationships": [],
            "error": None,
        }

        if not PYODBC_AVAILABLE or self._sage_unreachable:
            logger.debug("pyodbc non disponible ou Sage injoignable, skip enrichissement relations")
            result["error"] = "pyodbc not available or sage unreachable"
            return result

        owns_connector = connector is None
        local_connector = connector
        try:
            if owns_connector:
                local_connector = await self._create_sage_connector()
                await local_connector.connect()

            # --- FK sortantes : cette table référence d'autres ---
            fk_outgoing_query = """
            SELECT
                KCU1.CONSTRAINT_NAME,
                KCU1.TABLE_NAME AS child_table,
                KCU1.COLUMN_NAME AS child_column,
                KCU2.TABLE_NAME AS parent_table,
                KCU2.COLUMN_NAME AS parent_column
            FROM INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS RC
            JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE KCU1
                ON RC.CONSTRAINT_NAME = KCU1.CONSTRAINT_NAME
            JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE KCU2
                ON RC.UNIQUE_CONSTRAINT_NAME = KCU2.CONSTRAINT_NAME
            WHERE KCU1.TABLE_NAME = ?
            ORDER BY KCU1.ORDINAL_POSITION
            """
            # bypass_admin_cap : sync interne FK, pas user-visible.
            result_obj = await local_connector.execute(
                fk_outgoing_query, (effective_sql_name,), bypass_admin_cap=True
            )
            fk_rows = result_obj.to_dicts()

            fk_map: Dict[str, Dict[str, Any]] = {}
            for row in fk_rows:
                fk_name = row.get("CONSTRAINT_NAME", "")
                if fk_name not in fk_map:
                    fk_map[fk_name] = {
                        "fk_name": fk_name,
                        "parent_table": row.get("parent_table", ""),
                        "child_table": row.get("child_table", ""),
                        "columns": [],
                    }
                child_col = row.get("child_column", "")
                parent_col = row.get("parent_column", "")
                if child_col and parent_col:
                    fk_map[fk_name]["columns"].append(f"{child_col} → {parent_col}")

            for fk_name, fk_info in fk_map.items():
                columns = ", ".join(fk_info["columns"])
                desc = (
                    f"FK sortante: {fk_info['child_table']}.{columns} → "
                    f"{fk_info['parent_table']}. Constraint: {fk_name}."
                )
                try:
                    await self.training_store.add_documentation(
                        doc=desc,
                        category=f"relation:{fk_info['parent_table']}→{fk_info['child_table']}",
                        tags=["auto_enriched", "relationship", "outgoing"],
                        source="schema_enricher",
                    )
                    result["relationships"].append(fk_info)
                except Exception as e:
                    logger.error("Erreur stockage relation sortante %s: %s", fk_name, e)

            # --- FK entrantes : d'autres tables référencent celle-ci ---
            fk_incoming_query = """
            SELECT
                KCU1.CONSTRAINT_NAME,
                KCU1.TABLE_NAME AS child_table,
                KCU1.COLUMN_NAME AS child_column,
                KCU2.TABLE_NAME AS parent_table,
                KCU2.COLUMN_NAME AS parent_column
            FROM INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS RC
            JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE KCU1
                ON RC.CONSTRAINT_NAME = KCU1.CONSTRAINT_NAME
            JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE KCU2
                ON RC.UNIQUE_CONSTRAINT_NAME = KCU2.CONSTRAINT_NAME
            WHERE KCU2.TABLE_NAME = ?
            ORDER BY KCU1.ORDINAL_POSITION
            """
            rev_result_obj = await local_connector.execute(
                fk_incoming_query, (effective_sql_name,), bypass_admin_cap=True
            )
            rev_fk_rows = rev_result_obj.to_dicts()

            rev_fk_map: Dict[str, Dict[str, Any]] = {}
            for row in rev_fk_rows:
                fk_name = row.get("CONSTRAINT_NAME", "")
                if fk_name not in rev_fk_map:
                    rev_fk_map[fk_name] = {
                        "fk_name": fk_name,
                        "referencing_table": row.get("child_table", ""),
                        "parent_table": row.get("parent_table", ""),
                        "columns": [],
                    }
                child_col = row.get("child_column", "")
                parent_col = row.get("parent_column", "")
                if child_col and parent_col:
                    rev_fk_map[fk_name]["columns"].append(f"{child_col} → {parent_col}")

            for fk_name, fk_info in rev_fk_map.items():
                columns = ", ".join(fk_info["columns"])
                desc = (
                    f"FK entrante: {fk_info['referencing_table']}.{columns} → "
                    f"{table_name}. Constraint: {fk_name}. "
                    f"(La table {fk_info['referencing_table']} dépend de {table_name})"
                )
                try:
                    await self.training_store.add_documentation(
                        doc=desc,
                        category=f"relation:{table_name}←{fk_info['referencing_table']}",
                        tags=["auto_enriched", "relationship", "incoming"],
                        source="schema_enricher",
                    )
                    result["reverse_relationships"].append(fk_info)
                except Exception as e:
                    logger.error("Erreur stockage relation entrante %s: %s", fk_name, e)

            result["success"] = True
            logger.info(
                "✓ %s: %d FK sortantes, %d FK entrantes documentées",
                table_name,
                len(result["relationships"]),
                len(result["reverse_relationships"]),
            )

        except Exception as e:
            # Détecter les erreurs de connexion pour éviter de retenter
            # sur chaque table restante (14s timeout × 388 tables = des heures)
            err_str = str(e).lower()
            if "timeout" in err_str or "connexion_impossible" in err_str:
                self._sage_unreachable = True
                logger.warning(
                    "Sage injoignable pendant enrichissement relations de %s, "
                    "skip des relations pour les tables restantes.",
                    table_name,
                )
            else:
                logger.error("Erreur enrichissement relations %s: %s", table_name, e, exc_info=True)
            result["error"] = f"Erreur enrichissement relations ({type(e).__name__})"
        # NOTE singleton (fix audit 2026-05-22) : pas de close — cf.
        # ``_create_sage_connector`` ligne 465 qui retourne le singleton.

        return result

    async def enrich_all_tables(
        self, table_names: List[str], ddl_map: Dict[str, str], programmatic_only: bool = False
    ) -> Dict[str, Any]:
        """
        Enrichit toutes les tables, leurs relations ET construit le graphe de grappes.

        Workflow complet :
        1. Enrichir chaque table (rôle + colonnes via LLM) — SKIP si programmatic_only=True
        2. Enrichir les relations bidirectionnelles (FK sortantes + entrantes)
        3. Construire le graphe complet des FK et identifier les grappes
        4. Générer les alias métier pour chaque table enrichie

        Args:
            table_names: Liste des noms de tables à enrichir
            ddl_map: Dict[table_name → DDL] pour chaque table
            programmatic_only: Si True, ne faire que le travail programmatique (sampling,
                stats, relations) — SKIP tous les appels LLM. Utilisé pour le cold-start.

        Returns:
            Dict avec résumé complet de l'enrichissement
        """
        summary: Dict[str, Any] = {
            "success": False,
            "tables_enriched": 0,
            "relationships_count": 0,
            "reverse_relationships_count": 0,
            "columns_sampled": 0,
            "clusters_found": 0,
            "aliases_generated": 0,
            "cardinality_extracted": 0,
            "errors": {},
        }

        if not table_names:
            return summary

        # Reset le flag Sage pour retenter la connexion à chaque appel complet
        self._sage_unreachable = False

        # Prioriser les tables les plus connectées (FK)
        # Les tables les plus demandées sont enrichies en premier
        table_names = self._prioritize_tables(table_names)
        logger.info("Enrichissement complet en cours: %d tables...", len(table_names))

        # Créer UNE seule connexion Sage partagée pour tout l'enrichissement
        # (au lieu d'une connexion par table × 2 méthodes = 776 connexions pour 388 tables)
        shared_connector = None
        if PYODBC_AVAILABLE:
            try:
                shared_connector = await self._create_sage_connector()
                await shared_connector.connect()
                logger.info("Connexion Sage partagée ouverte pour l'enrichissement")
            except Exception as e:
                err_str = str(e).lower()
                if "timeout" in err_str or "connexion_impossible" in err_str:
                    self._sage_unreachable = True
                    logger.warning(
                        "Sage injoignable au démarrage de l'enrichissement. "
                        "Enrichissement par DDL seul."
                    )
                else:
                    logger.warning("Erreur connexion Sage partagée: %s. DDL seul.", e)
                shared_connector = None

        # Phase 1 & 2 : Enrichir les tables par batch + relations bidirectionnelles
        # PAUSE automatique si une conversation utilisateur est en cours
        # SKIP LLM si programmatic_only=True (cold-start: structure données seulement)
        BATCH_SIZE = 15
        enriched_tables: Dict[str, Dict] = {}
        try:
            # Préparer les tables valides avec leur DDL
            valid_tables = [(tn, ddl_map[tn]) for tn in table_names if ddl_map.get(tn)]
            for tn in table_names:
                if not ddl_map.get(tn):
                    logger.warning("DDL manquant pour %s, skip", tn)

            if not valid_tables:
                logger.info("Aucune table avec DDL valide à enrichir")
                summary["success"] = True
                return summary

            if programmatic_only:
                logger.info("Mode programmatic_only: structure données seulement, skip LLM")

            # Traiter par batch
            for batch_start in range(0, len(valid_tables), BATCH_SIZE):
                batch = valid_tables[batch_start : batch_start + BATCH_SIZE]
                batch_idx = batch_start // BATCH_SIZE + 1
                total_batches = (len(valid_tables) + BATCH_SIZE - 1) // BATCH_SIZE

                # Pause si une conversation utilisateur est active
                # Safety timeout : max 15 min de pause pour laisser le temps aux
                # conversations longues. Au-delà, reprise forcée (compteur probablement
                # bloqué par un generator abandonné sans finally).
                if self._is_conversation_active():
                    logger.info(
                        "Enrichissement en pause: conversation active (batch %d/%d)",
                        batch_idx,
                        total_batches,
                    )
                    pause_start = time.perf_counter()
                    max_pause = 900.0  # 15 minutes max (conversations longues)
                    while self._is_conversation_active():
                        elapsed = time.perf_counter() - pause_start
                        if elapsed > max_pause:
                            logger.warning(
                                "Enrichissement: pause timeout (%.0fs). Reprise forcée.", elapsed
                            )
                            break
                        await asyncio.sleep(2.0)
                    else:
                        logger.info("Enrichissement reprend: conversation terminée")

                # Throttle léger entre les batches (pas avant le premier)
                if batch_start > 0:
                    await asyncio.sleep(0.5)

                # LLM enrichment (batch + fallback individuel) — SKIP si programmatic_only
                if not programmatic_only:
                    # Préparer les données du batch (DDL + échantillons)
                    batch_data = []
                    for table_name, ddl in batch:
                        td: Dict[str, Any] = {
                            "table_name": table_name,
                            "ddl": ddl,
                            "sample_rows": [],
                            "columns": [],
                        }

                        # Niveau 1 (schéma seul) : aucun échantillon n'est envoyé
                        # au LLM. La probe Sage est conservée uniquement pour
                        # détecter une connexion morte (`_sage_unreachable`)
                        # avant la prochaine table — son résultat est ignoré.
                        if shared_connector and not self._sage_unreachable:
                            try:
                                query = f"SELECT TOP 1 * FROM {_sql_table_ref(table_name, ddl)}"
                                await shared_connector.execute(query, bypass_admin_cap=True)
                            except Exception as sample_err:
                                logger.debug(
                                    "Probe Sage indisponible pour %s (DDL seul): %s",
                                    table_name,
                                    sample_err,
                                )

                        batch_data.append(td)

                    # Appel batch LLM
                    batch_table_names = [td["table_name"] for td in batch_data]
                    logger.info(
                        "Batch %d/%d: enrichissement de %s",
                        batch_idx,
                        total_batches,
                        batch_table_names,
                    )

                    batch_results = await self.enrich_tables_batch(batch_data)

                    # Traiter les résultats et fallback individuel si échec
                    for table_name, ddl in batch:
                        br = batch_results.get(table_name, {})
                        if br.get("success"):
                            summary["tables_enriched"] += 1
                            enriched_tables[table_name] = br
                        else:
                            # Fallback : enrichissement individuel
                            logger.info("Batch échoué pour %s, fallback individuel", table_name)
                            single_result = await self.enrich_table(
                                table_name, ddl, connector=shared_connector
                            )
                            if single_result["success"]:
                                summary["tables_enriched"] += 1
                                enriched_tables[table_name] = single_result
                            else:
                                summary["errors"][table_name] = single_result.get(
                                    "error", "unknown"
                                )

                # Programmatic work: sampling, stats, relationships (PARALLÈLE entre tables)
                # Chaque table utilise sa propre connexion Sage (pyodbc = pas thread-safe)
                # Sémaphore pour limiter les connexions simultanées
                _TABLE_SEMAPHORE = asyncio.Semaphore(15)

                async def _process_table(table_name: str, ddl: str) -> dict:
                    """Traite une table avec sa propre connexion Sage."""
                    result = {"columns_sampled": 0, "rels": 0, "reverse_rels": 0}
                    sql_name = _sql_object_name(table_name, ddl)
                    if self._sage_unreachable:
                        return result

                    async with _TABLE_SEMAPHORE:
                        local_conn = None
                        try:
                            local_conn = await self._create_sage_connector()
                            await local_conn.connect()

                            # Phase α.4.C : enrichissement = SYSTEM (job sync).
                            from app.services.data_access.enforcer import SYSTEM_USER

                            columns_info = await local_conn.get_columns(sql_name, user=SYSTEM_USER)
                            if columns_info:
                                # T5 — Ordre : stats AVANT samples pour pouvoir
                                # passer la cardinalité distinct comme hint au
                                # sampler (stratification par cardinalité).
                                stats_result = await self.collect_column_stats(
                                    table_name,
                                    columns_info,
                                    connector=local_conn,
                                    sql_table_name=sql_name,
                                )
                                column_stats_payload = stats_result.get("columns") or {}
                                # T5 — Observabilité : stats vides avec colonnes
                                # présentes = régression silencieuse (toutes
                                # high-card retombent sur exhaustif). Alerte admin.
                                if columns_info and not column_stats_payload:
                                    logger.warning(
                                        "Stats vides pour %s (%d colonnes) — "
                                        "stratification value_mapping désactivée pour "
                                        "cette table (fallback exhaustif).",
                                        table_name,
                                        len(columns_info),
                                    )

                                values_result = await self.sample_column_values(
                                    table_name,
                                    columns_info,
                                    connector=local_conn,
                                    sql_table_name=sql_name,
                                    column_stats_hint=column_stats_payload or None,
                                )
                                result["columns_sampled"] = len(values_result)

                            # Relations bidirectionnelles
                            rel_result = await self.enrich_relationships(
                                table_name,
                                connector=local_conn,
                                sql_table_name=sql_name,
                            )
                            if rel_result["success"]:
                                result["rels"] = len(rel_result.get("relationships", []))
                                result["reverse_rels"] = len(
                                    rel_result.get("reverse_relationships", [])
                                )

                        except Exception as col_err:
                            err_str = str(col_err).lower()
                            if "timeout" in err_str or "connexion_impossible" in err_str:
                                self._sage_unreachable = True
                            logger.debug("Traitement %s: %s", table_name, col_err)
                        # NOTE singleton (fix audit 2026-05-22) : pas de
                        # ``local_conn.close()``. Cf. ``_create_sage_connector``
                        # ligne 465 qui retourne le singleton.
                    return result

                table_results = await asyncio.gather(
                    *[_process_table(tn, ddl) for tn, ddl in batch],
                    return_exceptions=True,
                )
                for tr in table_results:
                    if isinstance(tr, dict):
                        summary["columns_sampled"] += tr["columns_sampled"]
                        summary["relationships_count"] += tr["rels"]
                        summary["reverse_relationships_count"] += tr["reverse_rels"]
        finally:
            # NOTE singleton (fix audit 2026-05-22) : ancien finally fermait
            # ``shared_connector`` ; supprimé car ``_create_sage_connector``
            # (ligne 465) retourne le singleton. Le ``try``/``finally`` est
            # conservé (pas de ``close`` mais préserve la sémantique
            # ``try-with-cleanup`` du bloc, qui pourrait recevoir d'autres
            # cleanups futurs sans recréer la structure).
            pass

        # Phase 2b : Extraire la cardinalité (nombre de lignes par table).
        # On peut RÉUTILISER le singleton (toujours connecté grâce au fix
        # singleton — l'ancienne note « shared_connector a été fermé »
        # ne s'applique plus).
        card_connector = None
        if PYODBC_AVAILABLE and not self._sage_unreachable:
            try:
                card_connector = await self._create_sage_connector()
                await card_connector.connect()

                cardinality_query = """
                    SELECT
                        t.name AS table_name,
                        SUM(p.rows) AS row_count
                    FROM sys.tables t
                    INNER JOIN sys.partitions p ON t.object_id = p.object_id
                    WHERE p.index_id IN (0, 1)
                    GROUP BY t.name
                    ORDER BY t.name
                """
                # bypass_admin_cap : sync interne cardinalits, pas user-visible.
                card_result = await card_connector.execute(cardinality_query, bypass_admin_cap=True)
                card_rows = card_result.to_dicts()

                for row in card_rows:
                    tname = row.get("table_name", "")
                    rcount = row.get("row_count", 0)
                    if tname in enriched_tables or tname in table_names:
                        stats = json.dumps({"row_count": rcount})
                        await self.training_store.add_documentation(
                            doc=stats,
                            category=f"table_stats:{tname}",
                            tags=["auto_enriched", "cardinality", tname],
                            source="auto_enrichment",
                        )

                summary["cardinality_extracted"] = len(card_rows)
                logger.info("Cardinalité extraite pour %d tables", len(card_rows))
            except Exception as e:
                logger.warning("Impossible d'extraire la cardinalité: %s", e)
                summary["cardinality_extracted"] = 0
            # NOTE singleton (fix audit 2026-05-22) : pas de close sur
            # ``card_connector``. Cf. ``_create_sage_connector`` ligne 465.

        # Phase 2c : Détecter les vues et documenter leurs tables sources
        # Les vues consolident souvent plusieurs tables (ex: viewGroupes01 = Groupes + Dossiers).
        # Le LLM confond fréquemment tables de base et vues — cette doc l'aide à choisir.
        summary["views_documented"] = 0
        view_connector = None
        if PYODBC_AVAILABLE and not self._sage_unreachable:
            try:
                view_connector = await self._create_sage_connector()
                await view_connector.connect()

                # Récupérer toutes les vues et leurs définitions
                view_query = """
                    SELECT v.name AS view_name, m.definition
                    FROM sys.views v
                    JOIN sys.sql_modules m ON v.object_id = m.object_id
                    WHERE m.definition IS NOT NULL
                """
                # bypass_admin_cap : sync interne dfinitions de vues.
                view_result = await view_connector.execute(view_query, bypass_admin_cap=True)
                view_rows = view_result.to_dicts()

                # Tables enrichies = celles qu'on connaît
                known_tables = {n.upper() for n in table_names}

                for row in view_rows:
                    vname = row.get("view_name", "")
                    vdef = row.get("definition", "") or ""
                    if not vname or not vdef:
                        continue

                    # Extraire les tables référencées dans la définition de la vue
                    # Patterns SQL Server supportés :
                    #   FROM dbo.TableName / FROM [dbo].[TableName] / FROM TableName
                    #   JOIN dbo.TableName / JOIN [dbo].[TableName] / JOIN TableName
                    referenced = set()
                    for match in re.finditer(
                        r"(?:FROM|JOIN)\s+" r"(?:\[?dbo\]?\.\[?)?(\w+)\]?",
                        vdef,
                        re.IGNORECASE,
                    ):
                        ref_table = match.group(1).upper()
                        if ref_table in known_tables and ref_table != vname.upper():
                            referenced.add(ref_table)

                    if referenced:
                        # Documenter la composition de la vue
                        ref_list = ", ".join(sorted(referenced))
                        doc = (
                            f"La vue {vname} consolide les tables : {ref_list}. "
                            f"Préférer cette vue quand on a besoin de colonnes issues "
                            f"de plusieurs de ces tables (évite de refaire les JOINs)."
                        )
                        try:
                            await self.training_store.add_documentation(
                                doc=doc,
                                category=f"view_composition:{vname}",
                                tags=["auto_enriched", "view_mapping"],
                                source="schema_enricher",
                            )
                            summary["views_documented"] += 1
                        except Exception as e:
                            logger.debug("Erreur doc vue %s: %s", vname, e)

                logger.info(
                    "✓ %d vues documentées (composition table→vue)", summary["views_documented"]
                )
            except Exception as e:
                logger.warning("Impossible de détecter les vues: %s", e)
            # NOTE singleton (fix audit 2026-05-22) : pas de close sur
            # ``view_connector``. Cf. ``_create_sage_connector`` ligne 465.

        # Phase 3 : Construire le graphe de grappes
        try:
            graph_result = await self.build_table_graph(table_names)
            summary["clusters_found"] = graph_result.get("clusters_count", 0)
        except Exception as e:
            logger.error("Erreur construction du graphe de grappes: %s", e)
            summary["errors"]["_graph"] = f"Erreur construction graphe ({type(e).__name__})"

        # Phase 4 : Générer les alias métier pour les tables enrichies
        for i, (table_name, table_data) in enumerate(enriched_tables.items()):
            try:
                alias_count = await self.enrich_business_aliases(
                    table_name,
                    ddl_map.get(table_name, ""),
                    table_data.get("table_role", ""),
                    table_data.get("column_roles", {}),
                )
                summary["aliases_generated"] += alias_count
            except Exception as e:
                logger.warning("Erreur génération alias pour %s: %s", table_name, e)

        summary["success"] = summary["tables_enriched"] > 0
        logger.info(
            "✓ Enrichissement complet terminé: %d tables, %d colonnes sampées, "
            "%d FK sortantes, %d FK entrantes, %d grappes, %d alias",
            summary["tables_enriched"],
            summary["columns_sampled"],
            summary["relationships_count"],
            summary["reverse_relationships_count"],
            summary["clusters_found"],
            summary["aliases_generated"],
        )

        return summary

    async def enrich_changed_tables(self, changes: List[Any]) -> Dict[str, Any]:
        """
        Enrichit les tables affectées par des changements de schéma.

        Takes a list of SchemaChange objects (from schema_freshness.py) et enrichit
        uniquement les tables ajoutées ou modifiées.

        Récupère le DDL depuis TrainingStore pour chaque table.

        Args:
            changes: Liste de SchemaChange objects

        Returns:
            Dict avec résumé d'enrichissement
        """
        summary: Dict[str, Any] = {
            "success": False,
            "tables_processed": 0,
            "errors": {},
        }

        if not changes:
            return summary

        # Identifier les tables affectées
        affected_tables = set()
        for change in changes:
            # Enrichir seulement pour 'table_added' ou 'column_added'
            if hasattr(change, "change_type"):
                change_type = change.change_type
            else:
                change_type = change.get("change_type", "")

            if change_type in ("table_added", "column_added"):
                if hasattr(change, "table_name"):
                    affected_tables.add(change.table_name)
                else:
                    affected_tables.add(change.get("table_name", ""))

        if not affected_tables:
            logger.debug("Aucune table affectée par les changements de schéma")
            return summary

        logger.info("Enrichissement des %d tables affectées...", len(affected_tables))

        # Connexion Sage partagée pour toutes les tables changées
        shared_connector = None
        if PYODBC_AVAILABLE and not self._sage_unreachable:
            try:
                shared_connector = await self._create_sage_connector()
                await shared_connector.connect()
            except Exception:
                shared_connector = None

        # Récupérer DDL et enrichir chaque table
        try:
            for table_name in affected_tables:
                if not table_name:
                    continue

                try:
                    # Récupérer DDL depuis TrainingStore
                    # Phase α.4.C : enrichissement = SYSTEM.
                    from app.services.data_access.enforcer import SYSTEM_USER

                    related_ddl = await self.training_store.get_ddl_by_table_names(
                        [table_name], user=SYSTEM_USER
                    )
                    if not related_ddl:
                        logger.warning("Aucun DDL trouvé pour %s", table_name)
                        summary["errors"][table_name] = "DDL not found"
                        continue

                    ddl = related_ddl[0].get("content", "")
                    if not ddl:
                        logger.warning("DDL vide pour %s", table_name)
                        summary["errors"][table_name] = "DDL empty"
                        continue

                    # Enrichir table (rôle + colonnes)
                    result = await self.enrich_table(table_name, ddl, connector=shared_connector)
                    if result["success"]:
                        summary["tables_processed"] += 1
                    else:
                        summary["errors"][table_name] = result.get("error", "unknown")

                    # Enrichir relations (FK sortantes + entrantes)
                    sql_name = _sql_object_name(table_name, ddl)
                    await self.enrich_relationships(
                        table_name,
                        connector=shared_connector,
                        sql_table_name=sql_name,
                    )

                except Exception as e:
                    logger.error("Erreur enrichissement %s: %s", table_name, e)
                    summary["errors"][table_name] = f"Erreur enrichissement ({type(e).__name__})"
        finally:
            # NOTE singleton (fix audit 2026-05-22) : ancien finally fermait
            # ``shared_connector`` ; supprimé car retourne le singleton.
            pass

        summary["success"] = summary["tables_processed"] > 0
        logger.info("✓ %d tables enrichies", summary["tables_processed"])

        return summary

    async def build_table_graph(self, table_names: List[str]) -> Dict[str, Any]:
        """
        Construit le graphe complet des FK entre toutes les tables et identifie
        les grappes fonctionnelles (composantes connexes).

        Traverse TOUTES les FK (sortantes + entrantes) pour grouper les tables
        qui fonctionnent ensemble. Documente chaque grappe dans le training store.

        Args:
            table_names: Liste de toutes les tables connues

        Returns:
            Dict avec clusters_count, clusters (list of table groups)
        """
        result: Dict[str, Any] = {
            "success": False,
            "clusters_count": 0,
            "clusters": [],
        }

        if not PYODBC_AVAILABLE or not table_names or self._sage_unreachable:
            return result

        connector = None
        try:
            connector = await self._create_sage_connector()
            await connector.connect()

            # Récupérer TOUTES les FK de la BDD en une seule requête
            all_fk_query = """
            SELECT
                KCU1.TABLE_NAME AS child_table,
                KCU2.TABLE_NAME AS parent_table
            FROM INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS RC
            JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE KCU1
                ON RC.CONSTRAINT_NAME = KCU1.CONSTRAINT_NAME
            JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE KCU2
                ON RC.UNIQUE_CONSTRAINT_NAME = KCU2.CONSTRAINT_NAME
            """
            # bypass_admin_cap : sync interne FK globales.
            fk_result = await connector.execute(all_fk_query, bypass_admin_cap=True)
            fk_rows = fk_result.to_dicts()

            # Construire le graphe d'adjacence (non orienté pour les grappes)
            table_set = set(t.upper() for t in table_names)
            adjacency: Dict[str, set] = {t: set() for t in table_set}

            for row in fk_rows:
                child = (row.get("child_table") or "").upper()
                parent = (row.get("parent_table") or "").upper()
                if child in adjacency and parent in adjacency:
                    adjacency[child].add(parent)
                    adjacency[parent].add(child)

            # BFS pour identifier les composantes connexes (grappes)
            visited: set = set()
            clusters: List[List[str]] = []

            for table in table_set:
                if table in visited:
                    continue
                # BFS depuis cette table
                cluster: List[str] = []
                queue = deque([table])
                while queue:
                    current = queue.popleft()
                    if current in visited:
                        continue
                    visited.add(current)
                    cluster.append(current)
                    for neighbor in adjacency.get(current, set()):
                        if neighbor not in visited:
                            queue.append(neighbor)
                clusters.append(sorted(cluster))

            # Filtrer : ne documenter que les grappes de 2+ tables
            significant_clusters = [c for c in clusters if len(c) >= 2]
            # Trier par taille décroissante
            significant_clusters.sort(key=len, reverse=True)

            # Documenter chaque grappe dans le training store
            for _i, cluster in enumerate(significant_clusters):
                # Identifier la table "hub" (celle avec le plus de connexions)
                hub = max(cluster, key=lambda t: len(adjacency.get(t, set())))

                # Construire la description avec les chemins de jointure
                join_paths = []
                for table in cluster:
                    neighbors = adjacency.get(table, set()) & set(cluster)
                    for neighbor in sorted(neighbors):
                        pair = tuple(sorted([table, neighbor]))
                        path = f"{pair[0]} ↔ {pair[1]}"
                        if path not in join_paths:
                            join_paths.append(path)

                desc = (
                    f"Grappe de {len(cluster)} tables fonctionnant ensemble : "
                    f"{', '.join(cluster)}. "
                    f"Table centrale : {hub}. "
                    f"Liens : {'; '.join(join_paths)}."
                )

                try:
                    await self.training_store.add_documentation(
                        doc=desc,
                        category=f"cluster:{hub}",
                        tags=["auto_enriched", "cluster", "graph"],
                        source="schema_enricher",
                    )
                except Exception as e:
                    logger.error("Erreur stockage grappe %s: %s", hub, e)

                # Aussi taguer chaque table avec sa grappe
                for table in cluster:
                    try:
                        await self.training_store.add_documentation(
                            doc=f"Appartient à la grappe {hub} ({len(cluster)} tables). "
                            f"Tables liées : {', '.join(t for t in cluster if t != table)}.",
                            category=f"cluster_member:{table}",
                            tags=["auto_enriched", "cluster"],
                            source="schema_enricher",
                        )
                    except Exception as e:
                        logger.warning("Erreur stockage membre grappe %s: %s", table, e)

            result["success"] = True
            result["clusters_count"] = len(significant_clusters)
            result["clusters"] = [
                {"hub": max(c, key=lambda t: len(adjacency.get(t, set()))), "tables": c}
                for c in significant_clusters
            ]

            logger.info(
                "✓ Graphe de grappes : %d grappes identifiées sur %d tables",
                len(significant_clusters),
                len(table_set),
            )

        except Exception as e:
            logger.error("Erreur construction graphe de grappes: %s", e, exc_info=True)
            result["error"] = f"Erreur construction graphe ({type(e).__name__})"
        # NOTE singleton (fix audit 2026-05-22) : pas de close sur
        # ``connector``. Cf. ``_create_sage_connector`` ligne 465.

        return result

    async def enrich_business_aliases(
        self,
        table_name: str,
        ddl: str,
        table_role: str,
        column_roles: Dict[str, str],
    ) -> int:
        """
        Génère des synonymes/alias métier pour une table et ses colonnes.

        Demande à Haiku de proposer les termes naturels qu'un utilisateur
        pourrait employer pour désigner cette table ou ses colonnes.
        Ex: "dépenses" → Production.proPrixRevientTotal

        Args:
            table_name: Nom de la table
            ddl: DDL de la table
            table_role: Description du rôle (issue de enrich_table)
            column_roles: Descriptions des colonnes (issue de enrich_table)

        Returns:
            Nombre d'alias générés et stockés
        """
        if not table_role:
            return 0

        await self._ensure_providers()

        col_descriptions = "\n".join(f"  - {col}: {desc}" for col, desc in column_roles.items())

        prompt = f"""Table : {table_name}
Rôle : {table_role}
Colonnes :
{col_descriptions}

Génère des synonymes/alias métier.

Réponds UNIQUEMENT en JSON valide :
{{
  "table_aliases": ["alias1", "alias2", ...],
  "column_aliases": {{
    "COLUMN_NAME": ["alias1", "alias2"],
    ...
  }}
}}
"""
        try:
            from app.config import get_config

            db_label = get_config().sage.label
            from app.services.ai.llm_runtime import CallProfile, ModelKind, call_llm
            from app.services.anonymization import anonymize_for_llm
            from app.services.anonymization.proxy import (
                get_confidentiality_prompt,
            )

            # Schema enrichment : sync programmatique (cf. CLAUDE.md
            # « Sync = programmatique »), pas de user_id. Le payload contient
            # uniquement des noms de tables/colonnes (métadonnées schéma,
            # pas confidentielles). On garde le proxy en mode système
            # (``user_id=None``) pour la couche PII regex défensive — un
            # nom de colonne peut accidentellement contenir un fragment
            # qui matche EMAIL/SIRET.
            base_system = (
                f"Tu es un expert en terminologie comptable française et {db_label}. "
                "Génère des synonymes que des comptables utiliseraient en langage naturel. "
                "Réponds UNIQUEMENT en JSON valide."
            )
            prompt_anon, restore_fn = await anonymize_for_llm(None, prompt, "SCHEMA_ENRICH")

            response = await call_llm(
                CallProfile(
                    caller="schema_enrich_aliases",
                    model_kind=ModelKind.UTILITY,
                    max_tokens_soft=1024,
                ),
                LLMRequest(
                    prompt=prompt_anon,
                    system=(get_confidentiality_prompt("SCHEMA_ENRICH") + "\n\n" + base_system),
                    temperature=0.2,
                ),
            )
            # Parse JSON ENCORE anonymisé puis restaurer la structure
            # (review adversariale tâche #7 — EPIC E4). Si on faisait
            # ``restore_fn(response.content)`` AVANT ``json.loads``, un
            # cleartext contenant ``"``, ``\`` ou ``\n`` casserait le
            # parsing silencieusement (un placeholder ``[EMAIL_1]``
            # restauré en ``o'brien@x.fr`` est OK ici, mais la
            # défense en profondeur impose le bon ordre partout).
            # En SCHEMA_ENRICH, ``user_id=None`` → seuls les tokens
            # PII regex peuvent apparaître ; ils ne contiennent jamais
            # de caractères JSON-spéciaux, donc parse safe.
            anon_text = (response.content or "").strip()

            # Stripper les blocs markdown sur le raw anonymisé (les
            # backticks ne tokenisent rien ; on garde le pattern
            # original).
            cleaned_text = anon_text
            md_match = re.search(r"```(?:json)?\s*\n?(.*?)```", cleaned_text, re.DOTALL)
            if md_match:
                cleaned_text = md_match.group(1).strip()

            try:
                parsed = json.loads(cleaned_text)
            except json.JSONDecodeError:
                json_match = re.search(r"\{.*\}", cleaned_text, re.DOTALL)
                if json_match:
                    try:
                        parsed = json.loads(json_match.group(0))
                    except json.JSONDecodeError:
                        logger.warning(
                            "Réponse alias non-JSON pour enrichissement: %.200s",
                            anon_text,
                        )
                        return 0
                else:
                    logger.warning(
                        "Pas de JSON dans la réponse alias (%d chars): %.200s",
                        len(anon_text),
                        anon_text,
                    )
                    return 0

            # Restaurer la structure parsée (walker récursif sur dict/
            # list/str). Pas de mutation de ``response.content`` — cf.
            # EPIC E5 (raw_response / completion_tokens divergence).
            parsed = restore_fn(parsed)
            if not isinstance(parsed, dict):
                logger.warning("Réponse alias post-restore non dict: %r", type(parsed).__name__)
                return 0

            alias_count = 0

            # Stocker les alias de table
            for alias in parsed.get("table_aliases") or []:
                alias_clean = alias.strip().lower()
                if alias_clean:
                    await self.training_store.add_documentation(
                        doc=f'L\'expression "{alias_clean}" désigne la table {table_name}. '
                        f"Rôle : {table_role}",
                        category=f"alias:{alias_clean}",
                        tags=["business_alias", "table_alias", table_name],
                        source="schema_enricher",
                    )
                    alias_count += 1

            # Stocker les alias de colonnes
            for col_name, aliases in (parsed.get("column_aliases") or {}).items():
                for alias in aliases:
                    alias_clean = alias.strip().lower()
                    if alias_clean:
                        col_desc = column_roles.get(col_name, "")
                        await self.training_store.add_documentation(
                            doc=f'L\'expression "{alias_clean}" correspond à '
                            f"{table_name}.{col_name}. {col_desc}",
                            category=f"alias:{alias_clean}",
                            tags=["business_alias", "column_alias", table_name, col_name],
                            source="schema_enricher",
                        )
                        alias_count += 1

            logger.info("✓ %s: %d alias métier générés", table_name, alias_count)
            return alias_count

        except Exception as e:
            logger.warning("Erreur génération alias pour %s: %s", table_name, e)
            return 0

    def _build_enrichment_prompt(
        self, table_name: str, ddl: str, sample_rows: List[Dict[str, Any]], columns: List[str]
    ) -> str:
        """
        Construit le prompt pour appel Haiku.

        Inclut:
        - Nom de la table
        - DDL complet
        - Échantillon anonymisé (max 5 lignes)
        - Conventions BDD (si configurées)

        Args:
            table_name: Nom de la table
            ddl: DDL CREATE TABLE
            sample_rows: Lignes anonymisées
            columns: Noms des colonnes

        Returns:
            Prompt structuré pour Haiku
        """
        sample_text = ""
        if sample_rows:
            sample_text = "Échantillon de données (anonymisé):\n"
            for i, row in enumerate(sample_rows[:5], 1):
                row_str = ", ".join(
                    [f"{col}: {row.get(col, 'NULL')}" for col in columns if col in row]
                )
                sample_text += f"  Ligne {i}: {row_str}\n"

        prompt = f"""Analyse cette table SQL et décris son rôle métier.

Table: {table_name}

DDL:
```sql
{ddl}
```

{sample_text}

{_get_db_conventions()}

Tâche:
1. Décris en 1-2 phrases le rôle métier de cette table (ex: "Table des comptes généraux utilisés pour la saisie comptable" ou "Historique des écritures comptables pour audit")
2. Pour chaque colonne, décris son rôle en 1 phrase (ex: "Identifiant unique du compte", "Numéro de compte général au format XXX", "Montant en débit/crédit")

Réponds UNIQUEMENT en JSON valide, sans texte supplémentaire:
{{
  "table_role": "Description du rôle de la table en 1-2 phrases",
  "column_roles": {{
    "COLUMN_NAME1": "Description de la colonne",
    "COLUMN_NAME2": "Description de la colonne",
    ...
  }}
}}
"""
        return prompt

    def _build_batch_enrichment_prompt(
        self,
        tables_data: List[Dict[str, Any]],
    ) -> str:
        """
        Construit un prompt pour enrichir un batch de tables en un seul appel LLM.

        Chaque entrée de tables_data contient:
        - table_name: str
        - ddl: str
        - sample_rows: List[Dict] (anonymisé)
        - columns: List[str]
        """
        tables_blocks = []
        for td in tables_data:
            table_name = td["table_name"]
            ddl = td["ddl"]
            sample_rows = td.get("sample_rows", [])
            columns = td.get("columns", [])

            sample_text = ""
            if sample_rows:
                sample_text = "Échantillon (anonymisé):\n"
                for i, row in enumerate(sample_rows[:3], 1):  # 3 lignes au lieu de 5 en batch
                    row_str = ", ".join(
                        f"{col}: {row.get(col, 'NULL')}" for col in columns if col in row
                    )
                    sample_text += f"  Ligne {i}: {row_str}\n"

            tables_blocks.append(f"### {table_name}\n```sql\n{ddl}\n```\n{sample_text}")

        prompt = f"""Analyse ces tables SQL et décris leur rôle métier.

{_get_db_conventions()}

{chr(10).join(tables_blocks)}

Pour CHAQUE table, fournis:
1. Le rôle métier en 1-2 phrases
2. Pour chaque colonne, son rôle en 1 phrase

Réponds UNIQUEMENT en JSON valide, sans texte supplémentaire:
{{
  "tables": {{
    "TABLE_NAME1": {{
      "table_role": "Description du rôle",
      "column_roles": {{
        "COLUMN_NAME1": "Description",
        ...
      }}
    }},
    "TABLE_NAME2": {{
      "table_role": "Description du rôle",
      "column_roles": {{...}}
    }}
  }}
}}
"""
        return prompt

    async def enrich_tables_batch(
        self,
        tables_data: List[Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Enrichit un batch de tables en un seul appel LLM.

        Plus économique que table-par-table : les conventions ne sont envoyées qu'une fois,
        et le LLM peut s'appuyer sur le contexte croisé des tables du batch pour mieux comprendre.

        Args:
            tables_data: Liste de dicts avec table_name, ddl, sample_rows, columns

        Returns:
            Dict[table_name → {"success": bool, "table_role": str, "column_roles": dict}]
        """
        results = {}
        if not tables_data:
            return results

        table_names = [td["table_name"] for td in tables_data]
        prompt = self._build_batch_enrichment_prompt(tables_data)

        from app.config import get_config

        db_label = get_config().sage.label
        enrichment_system = (
            f"Tu es un analyste de bases de données spécialisé en {db_label}. "
            "Analyse la structure des tables et les échantillons (anonymisés) "
            "pour générer des descriptions métier précises. "
            "Réponds UNIQUEMENT en JSON valide, sans texte supplémentaire."
        )

        # Adaptive max_tokens : plus de tables = plus de tokens nécessaires
        base_tokens = ENRICHMENT_MAX_TOKENS
        estimated_tokens = base_tokens * len(tables_data)
        current_max_tokens = min(estimated_tokens, 8192)

        max_retries_truncation = 2
        parsed = None

        await self._ensure_providers()

        for attempt in range(max_retries_truncation + 1):
            request = LLMRequest(
                prompt=prompt,
                system=enrichment_system,
                temperature=0.1,
                max_tokens=current_max_tokens,
            )

            try:
                from app.services.ai.llm_runtime import (
                    CallProfile,
                    ModelKind,
                    RetryPolicy,
                    call_llm,
                )

                response = await call_llm(
                    CallProfile(
                        caller="schema_enrich_batch",
                        model_kind=ModelKind.UTILITY,
                        retry=RetryPolicy.NONE,  # retry custom truncation géré par le for attempt
                    ),
                    request,
                )
            except Exception as llm_err:
                # ReadTimeout, ConnectTimeout, ou autre erreur réseau
                logger.warning(
                    "Batch LLM échoué (attempt %d/%d) pour %s: %s",
                    attempt + 1,
                    max_retries_truncation + 1,
                    table_names,
                    type(llm_err).__name__,
                )
                if attempt < max_retries_truncation:
                    await asyncio.sleep(2.0 * (attempt + 1))
                    continue
                # Toutes les tentatives épuisées — marquer comme échouées
                for tn in table_names:
                    results[tn] = {
                        "success": False,
                        "error": f"LLM {type(llm_err).__name__}",
                    }
                return results
            response_text = response.content.strip()

            stop_reason = None
            if response.raw_response:
                stop_reason = response.raw_response.get("stop_reason")
            was_truncated = stop_reason == "max_tokens"

            # Parser JSON
            cleaned_text = response_text
            md_match = re.search(r"```(?:json)?\s*\n?(.*?)```", cleaned_text, re.DOTALL)
            if md_match:
                cleaned_text = md_match.group(1).strip()

            try:
                parsed = json.loads(cleaned_text)
                break
            except json.JSONDecodeError:
                json_match = re.search(r"\{.*\}", cleaned_text, re.DOTALL)
                if json_match:
                    try:
                        parsed = json.loads(json_match.group(0))
                        break
                    except json.JSONDecodeError:
                        pass

                if was_truncated and attempt < max_retries_truncation:
                    current_max_tokens = min(current_max_tokens * 2, 16384)
                    logger.warning(
                        "Batch enrichissement tronqué (%d tables). Retry max_tokens=%d",
                        len(tables_data),
                        current_max_tokens,
                    )
                    await asyncio.sleep(1.0)
                    continue
                else:
                    logger.error(
                        "Batch enrichissement échoué pour %s. Réponse: %s",
                        table_names,
                        response_text[:300],
                    )
                    # Fallback : marquer toutes les tables comme échouées
                    for tn in table_names:
                        results[tn] = {"success": False, "error": "Batch parse failed"}
                    return results

        if parsed is None:
            for tn in table_names:
                results[tn] = {"success": False, "error": "No valid JSON after retries"}
            return results

        # Extraire les résultats par table
        tables_result = parsed.get("tables", parsed)  # Fallback si pas de wrapper "tables"
        for td in tables_data:
            tn = td["table_name"]
            table_data = tables_result.get(tn, {})
            table_role = table_data.get("table_role", "")
            column_roles = table_data.get("column_roles", {})

            if not table_role:
                results[tn] = {"success": False, "error": "table_role vide dans batch"}
                continue

            # Stocker via TrainingStore
            try:
                await self.training_store.add_documentation(
                    doc=table_role,
                    category=f"table_role:{tn}",
                    tags=["auto_enriched", "schema"],
                    source="schema_enricher",
                )

                stored_roles = {}
                for col_name, col_desc in column_roles.items():
                    if col_desc:
                        await self.training_store.add_documentation(
                            doc=col_desc,
                            category=f"column_role:{tn}.{col_name}",
                            tags=["auto_enriched", "schema", "column"],
                            source="schema_enricher",
                        )
                        stored_roles[col_name] = col_desc

                results[tn] = {
                    "success": True,
                    "table_role": table_role,
                    "column_roles": stored_roles,
                }
                logger.info("✓ %s (batch): %d colonnes documentées", tn, len(stored_roles))
            except Exception as e:
                logger.error("Erreur stockage batch pour %s: %s", tn, e)
                results[tn] = {
                    "success": False,
                    "error": f"Erreur stockage batch ({type(e).__name__})",
                }

        return results


# Singleton module-level
_schema_enricher: Optional[SchemaEnricher] = None


def get_schema_enricher() -> SchemaEnricher:
    """Récupère ou crée le singleton SchemaEnricher."""
    global _schema_enricher
    if _schema_enricher is None:
        _schema_enricher = SchemaEnricher()
        logger.info("SchemaEnricher initialisé")
    return _schema_enricher
