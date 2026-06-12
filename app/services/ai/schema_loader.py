"""
Service SchemaLoader pour Komptia.

Charge et fournit le contexte du schéma de la base source.

**Mode invisible (Phase α.2)** : toutes les méthodes publiques qui exposent
des noms de tables / colonnes / requêtes acceptent un argument
``user_view: Optional[UserSchemaView] = None``. Le caller (typiquement un
handler async) est responsable de matérialiser la vue UNE FOIS via
``await build_user_schema_view(user)`` puis de la passer aux méthodes
filtrées. ``user_view=None`` (défaut) = comportement legacy, aucun filtre,
zéro régression pour les call-sites pas encore migrés.

**Pourquoi explicit view au lieu de user** : ce module est *synchrone*
(legacy avant async migration). ``build_user_schema_view`` est async. Donc
on ne peut pas le matérialiser en interne sans casser la signature des
méthodes. Le pattern explicit force aussi le caller à voir clairement que
la matérialisation a un coût (load BDD + cache TTL 60s), ce qui aide à
éviter les appels redondants.

**Anti-pattern à éviter** : lire ``loader.schema["tables"]`` ou
``loader._schema`` directement pour bypass le filtre. Le linter Phase α.12
flaguera ces accès. Toujours passer par les méthodes filtrantes.

**Scope α.2 vs α.4** : cette Phase ouvre l'API filtrante. Tant que les
call-sites consommateurs (``sql_validator``, ``agent_tools``,
``schema_enricher``, ``training_store``, ``ai_admin``) n'ont pas été
migrés pour passer ``user_view=`` (Phase α.4), le mode invisible reste
creux côté SchemaLoader. C'est une stratégie délibérée : fermer toutes
les portes (α.1, α.2, α.3) AVANT de propager l'user (α.4). Ne pas
déclarer le mode invisible « complet » tant qu'α.4 n'est pas done.
"""

import re
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from functools import lru_cache
import logging

from app.services.data_access.visible_schema import UserSchemaView

logger = logging.getLogger(__name__)


def _view_filters(user_view: Optional[UserSchemaView]) -> bool:
    """True si la vue impose un filtre actif (ni None, ni admin, ni sans
    règle). Permet aux méthodes SchemaLoader de court-circuiter en O(1)
    pour les 95% d'appels sans restriction."""
    return user_view is not None and user_view.has_restrictions


#: Caractères à retirer des identifiants SQL Server quotés/bracketés
#: avant comparaison : ``[table]``, ``"table"``, `` `table` ``, ainsi
#: que les espaces parasites. SQL Server tolère plusieurs styles de
#: quoting selon QUOTED_IDENTIFIER.
_IDENT_STRIP_RE = re.compile(r'[\[\]"`\s]')


def _fk_target_visible(references: str, user_view: UserSchemaView) -> bool:
    """Détermine si la table cible d'une FK est visible par cet user.

    Le champ ``references`` du YAML est typiquement ``"F_SALAIRES(id)"``,
    ``"schema.F_SALAIRES(id)"``, ``"[dbo].[F_SALAIRES](id)"``,
    ``"db.dbo.F_SALAIRES"`` etc. On normalise en strippant brackets,
    guillemets, backticks et espaces avant comparaison.

    Si parsing échoue ou retourne une chaîne vide → fail-CLOSED (FK
    retirée par prudence — cohérent avec ``rewrite_ddl_for_view``).
    Phase α.2 fix CRITICAL #3 : robustesse aux formats SQL Server quotés.
    """
    if not references:
        return False
    target = references.strip()
    # 1) Retirer les parenthèses (col1, col2) si présentes
    paren_idx = target.find("(")
    if paren_idx != -1:
        target = target[:paren_idx].strip()
    # 2) Retirer le préfixe schema/database si présent : prendre TOUJOURS
    # le dernier segment pour gérer 2-part ("dbo.T") ET 3-part ("db.dbo.T").
    if "." in target:
        target = target.rsplit(".", 1)[-1]
    # 3) Normaliser : retirer brackets, quotes, espaces.
    target = _IDENT_STRIP_RE.sub("", target)
    if not target:
        return False
    return user_view.can_see_table(target)


class SchemaLoader:
    """
    Charge et fournit l'accès au schéma de la base source.

    Le schéma est chargé depuis data/schema_context.yaml et mis en cache.
    """

    def __init__(self, schema_path: Optional[Path] = None):
        """
        Initialise le loader.

        Args:
            schema_path: Chemin vers schema_context.yaml (optionnel)
        """
        if schema_path is None:
            # Chemin par défaut: data/schema_context.yaml à la racine du projet
            base_dir = Path(__file__).resolve().parent.parent.parent.parent
            schema_path = base_dir / "data" / "schema_context.yaml"

        self.schema_path = Path(schema_path)
        self._schema: Optional[Dict[str, Any]] = None

    def load(self) -> Dict[str, Any]:
        """
        Charge le schéma depuis le fichier YAML (si disponible) ou depuis la base de données.

        Returns:
            Dictionnaire contenant le schéma complet
        """
        # Essayer de charger depuis YAML d'abord (pour tests/dev)
        if self.schema_path.exists():
            logger.info("Chargement du schéma depuis %s", self.schema_path)
            try:
                with open(self.schema_path, "r", encoding="utf-8") as f:
                    self._schema = yaml.safe_load(f)
                if not isinstance(self._schema, dict):
                    raise ValueError("Le fichier YAML ne contient pas un dictionnaire")
                logger.info(
                    "Schéma chargé depuis YAML: %d tables",
                    len(self._schema.get("tables", {})),
                )
                return self._schema
            except (OSError, yaml.YAMLError, ValueError) as e:
                logger.warning("Erreur lecture YAML: %s, chargement depuis la base...", e)

        # Sinon, charger depuis la base de données (training_data)
        logger.info("Chargement du schéma depuis training_data...")
        try:
            from app.config import get_config  # utilisé plus bas (sage.database)
            from app.core.database import open_local_sqlite_connection

            # Connexion DBAPI brute sur la BDD LOCALE, AVEC le PRAGMA key
            # SQLCipher posé par le helper (sinon base chiffrée illisible :
            # « file is not a database »).
            conn = open_local_sqlite_connection(timeout=5.0)
            try:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA busy_timeout = 30000")
                cursor = conn.cursor()

                # Récupérer les noms de tables distincts depuis training_data
                cursor.execute("""
                    SELECT DISTINCT table_name
                    FROM training_data
                    WHERE data_type IN ('DDL', 'ddl')
                    AND is_active = 1
                    AND table_name IS NOT NULL
                    ORDER BY table_name
                """)

                table_names = [row[0] for row in cursor.fetchall()]
            finally:
                conn.close()

            # Construire le schéma avec les tables trouvées
            tables_dict = {}
            for table_name in table_names:
                tables_dict[table_name] = {
                    "description": f"Table {table_name}",
                    "columns": [],  # Colonnes non chargées ici (optimisation)
                }

            self._schema = {
                "database": get_config().sage.database,
                "tables": tables_dict,
                "metadata": {
                    "notes": [f"Schéma chargé depuis training_data: {len(tables_dict)} tables"],
                    "common_queries": [],
                },
            }

            logger.info("Schéma chargé depuis training_data: %d tables", len(tables_dict))
            return self._schema

        except (OSError, ValueError) as e:
            logger.warning("Impossible de charger le schéma depuis la base: %s", e)
            # Retourner un schéma vide pour ne pas planter l'application
            from app.config import get_config

            self._schema = {
                "database": get_config().sage.database,
                "tables": {},
                "metadata": {"notes": [], "common_queries": []},
            }
            return self._schema

    @property
    def schema(self) -> Dict[str, Any]:
        """
        Retourne le schéma (le charge si nécessaire).

        Returns:
            Schéma complet
        """
        if self._schema is None:
            self.load()
        return self._schema

    def get_tables(
        self,
        *,
        user_view: Optional[UserSchemaView] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Retourne toutes les tables du schéma.

        Args:
            user_view: optionnel — si fourni avec restrictions, retire les
                tables invisibles (mode invisible Phase α.2). ``None``
                (défaut) = comportement legacy.

        Returns:
            Dictionnaire {nom_table: métadonnées}, filtré si ``user_view``
            impose des restrictions.
        """
        all_tables = self.schema.get("tables", {})
        if not _view_filters(user_view):
            return all_tables
        # Filtrage à la source : on ne renvoie que les tables que cet
        # user a le droit de voir. Le filtre se fait sur le nom (UPPERCASE
        # côté view, original côté schema_context.yaml).
        return {name: meta for name, meta in all_tables.items() if user_view.can_see_table(name)}

    def get_table(
        self,
        table_name: str,
        *,
        user_view: Optional[UserSchemaView] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Retourne les métadonnées d'une table spécifique.

        Args:
            table_name: Nom de la table
            user_view: optionnel — si la table est invisible pour cet
                user, retourne ``None`` comme si elle n'existait pas
                (mode invisible Phase α.2 : on ne distingue pas
                « inexistante » et « interdite »).

        Returns:
            Métadonnées de la table, ``None`` si non trouvée OU invisible.
        """
        if _view_filters(user_view) and not user_view.can_see_table(table_name):
            return None
        return self.schema.get("tables", {}).get(table_name)

    def get_table_columns(
        self,
        table_name: str,
        *,
        user_view: Optional[UserSchemaView] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retourne les colonnes d'une table.

        Args:
            table_name: Nom de la table
            user_view: optionnel — si la table est invisible, retourne
                ``[]`` ; sinon, filtre les colonnes interdites.

        Returns:
            Liste des colonnes (filtrée si ``user_view`` impose des
            restrictions de colonne pour cette table).
        """
        table = self.get_table(table_name, user_view=user_view)
        if not table:
            return []
        cols = table.get("columns", [])
        if not _view_filters(user_view):
            return cols
        # Filtrer les colonnes interdites. ``can_see_column`` retourne
        # True si DDL inconnu côté view (permissif : la source de vérité
        # est la BDD, pas le YAML).
        return [c for c in cols if user_view.can_see_column(table_name, c.get("name", ""))]

    def get_table_description(
        self,
        table_name: str,
        *,
        user_view: Optional[UserSchemaView] = None,
    ) -> str:
        """
        Retourne la description métier d'une table.

        Args:
            table_name: Nom de la table
            user_view: optionnel — table invisible → ``""``.

        Returns:
            Description de la table ou chaîne vide.
        """
        table = self.get_table(table_name, user_view=user_view)
        if table:
            return table.get("description", "")
        return ""

    def format_table_context(
        self,
        table_name: str,
        include_samples: bool = False,
        *,
        user_view: Optional[UserSchemaView] = None,
    ) -> str:
        """
        Formate les métadonnées d'une table pour un prompt LLM.

        Args:
            table_name: Nom de la table
            include_samples: Inclure les exemples de données
            user_view: optionnel — table invisible → message générique
                (pas de mention du nom). Sinon : filtre les colonnes
                interdites + retire les FK qui référencent des tables
                invisibles (pour ne pas leaker leur nom dans
                ``REFERENCES F_SECRET(id)``).

        Returns:
            Texte formaté décrivant la table.
        """
        # ── Mode invisible : si la table est interdite, message générique
        # qui ne distingue pas « inconnue » et « interdite » ET qui ne
        # mentionne PAS le nom demandé (sinon oracle attack : le LLM peut
        # tester par dichotomie quels noms existent). Phase α.2 fix
        # CRITICAL #4.
        if _view_filters(user_view) and not user_view.can_see_table(table_name):
            return "Table demandée non trouvée."

        table = self.get_table(table_name, user_view=user_view)
        if not table:
            # Si on a un user_view actif, on retire aussi le nom du message
            # pour éviter de confirmer l'absence d'une table donnée.
            if _view_filters(user_view):
                return "Table demandée non trouvée."
            return f"Table {table_name} non trouvée."

        schema_name = table.get("schema", "dbo")
        lines = [
            f"## Table: {schema_name}.{table_name}",
            f"Description: {table.get('description', '')}",
            "",
            "Colonnes:",
        ]

        for col in table.get("columns", []):
            # Phase α.2 — Filtrage colonne au format (defense-in-depth :
            # get_table_columns filtre déjà, mais on ne dépend pas du
            # cache de la méthode appelante).
            col_name = col.get("name", "")
            if _view_filters(user_view) and not user_view.can_see_column(table_name, col_name):
                continue
            nullable = "NULL" if col.get("nullable") else "NOT NULL"
            desc_text = col.get("description", "")
            desc = f" -- {desc_text}" if desc_text else ""
            lines.append(f"  - {col_name or '?'} {col.get('type', '?')} {nullable}{desc}")

        # Clé primaire
        pk = table.get("primary_key")
        if pk:
            if _view_filters(user_view):
                # Filtre PK aux colonnes visibles (peu probable qu'une PK
                # soit deny, mais on reste cohérent).
                pk = [c for c in pk if user_view.can_see_column(table_name, c)]
            if pk:
                pk_cols = ", ".join(pk)
                lines.append(f"\nClé primaire: {pk_cols}")

        # Clés étrangères — Phase α.2 fix BLOCKING équivalent du α.1 :
        # une FK vers une table invisible leakerait son nom dans le prompt.
        fks = table.get("foreign_keys") or []
        if _view_filters(user_view):
            fks = [
                fk
                for fk in fks
                if _fk_target_visible(fk.get("references", ""), user_view)
                and user_view.can_see_column(table_name, fk.get("column", ""))
            ]
        if fks:
            lines.append("\nRelations:")
            for fk in fks:
                lines.append(f"  - {fk.get('column', '?')} → {fk.get('references', '?')}")

        # Exemples de données
        if include_samples and table.get("sample_data"):
            lines.append("\nExemples de données:")
            for i, sample in enumerate(table["sample_data"][:3], 1):
                lines.append(f"  Exemple {i}: {sample}")

        return "\n".join(lines)

    def format_all_tables_context(
        self,
        include_samples: bool = False,
        *,
        user_view: Optional[UserSchemaView] = None,
    ) -> str:
        """
        Formate toutes les tables pour un prompt LLM.

        Args:
            include_samples: Inclure les exemples de données
            user_view: optionnel — itère uniquement sur les tables
                visibles ; chaque section délègue à
                :meth:`format_table_context` avec la même view (FK +
                colonnes filtrées).

        Returns:
            Texte formaté décrivant toutes les tables (filtrées).
        """
        from app.config import get_config

        tables = self.get_tables(user_view=user_view)

        sections = [
            f"# Schéma Base de Données: {self.schema.get('database', get_config().sage.database)}",
            "",
            f"Nombre de tables: {len(tables)}",
            "",
        ]

        for table_name in sorted(tables.keys()):
            sections.append(
                self.format_table_context(table_name, include_samples, user_view=user_view)
            )
            sections.append("")  # Ligne vide entre les tables

        return "\n".join(sections)

    def get_common_queries(
        self,
        *,
        user_view: Optional[UserSchemaView] = None,
    ) -> List[Dict[str, str]]:
        """
        Retourne les requêtes SQL courantes définies dans les métadonnées.

        Args:
            user_view: optionnel — retire les requêtes qui référencent
                une table interdite pour cet user (via
                ``llm_context.is_sql_safe_for_view``). Sinon le LLM
                verrait dans un exemple ``SELECT ... FROM F_SECRET``,
                ce qui leak le nom (cf. fix CRITICAL #4 de la review α.1).

        Returns:
            Liste des requêtes (filtrée si ``user_view`` impose des
            restrictions).
        """
        metadata = self.schema.get("metadata", {})
        queries = metadata.get("common_queries", []) or []
        if not _view_filters(user_view):
            return queries
        # Import du checker en dehors de la boucle. Si l'import lui-même
        # plante (module data_access cassé), fail-CLOSED total (rare et
        # grave — vaut le coup de tout couper).
        try:
            from app.services.data_access.llm_context import is_sql_safe_for_view
        except Exception as exc:
            logger.error(
                "schema_loader.get_common_queries: import is_sql_safe_for_view "
                "impossible (fail-closed total, [] retourné): %s",
                exc,
                exc_info=True,
            )
            return []

        # Fail-CLOSED PAR-QUERY (Phase α.2 fix CRITICAL #5) : si UNE
        # query plante au parsing, on la retire mais on garde les autres.
        # Sinon une regex pathologique sur 1 query buggée privait l'user
        # de TOUS les exemples few-shot, dégradant silencieusement la
        # qualité de réponse pour les users restreints.
        safe = []
        for q in queries:
            sql = (q.get("sql") or "").strip()
            if not sql:
                continue
            try:
                if is_sql_safe_for_view(sql, user_view):
                    safe.append(q)
            except Exception as exc:
                logger.warning(
                    "schema_loader.get_common_queries: query '%s' a échoué "
                    "au filtrage mode invisible (skip, autres queries OK): %s",
                    q.get("description", "?"),
                    exc,
                )
                continue
        return safe

    def format_common_queries(
        self,
        *,
        user_view: Optional[UserSchemaView] = None,
    ) -> str:
        """
        Formate les requêtes courantes pour un prompt LLM.

        Args:
            user_view: optionnel — propagé à :meth:`get_common_queries`.

        Returns:
            Texte formaté avec exemples de requêtes (filtrés selon
            ``user_view``).
        """
        queries = self.get_common_queries(user_view=user_view)

        if not queries:
            return ""

        lines = ["# Exemples de Requêtes Courantes", ""]

        for i, query in enumerate(queries, 1):
            lines.append(f"{i}. {query['description']}")
            lines.append("```sql")
            lines.append(query["sql"].strip())
            lines.append("```")
            lines.append("")

        return "\n".join(lines)


@lru_cache()
def get_schema_loader() -> SchemaLoader:
    """
    Retourne une instance singleton du SchemaLoader.

    Returns:
        Instance SchemaLoader (mise en cache)
    """
    loader = SchemaLoader()
    loader.load()  # Précharger le schéma
    return loader
