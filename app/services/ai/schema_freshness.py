"""
Service de vérification de la fraîcheur du schéma BDD.

Vérifie si le schéma DDL stocké est à jour par rapport à la base source (SQL Server).
Détecte:
- Tables ajoutées/supprimées
- Colonnes ajoutées/supprimées/modifiées
- Changements de types et de nullable (via hash SHA256)
"""

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select, desc

from app.services.ai.training_store import get_training_store
from app.core.database import get_session
from app.models.ai_performance import SchemaSync
from app.services.database.sage_connector import get_sage_connector, PYODBC_AVAILABLE

logger = logging.getLogger(__name__)


@dataclass
class SchemaChange:
    """Représente un changement détecté dans le schéma."""

    change_type: (
        str  # 'table_added', 'table_removed', 'column_added', 'column_removed', 'column_modified'
    )
    table_name: str
    column_name: Optional[str] = None
    old_value: Optional[str] = None
    new_value: Optional[str] = None


@dataclass
class FreshnessReport:
    """Rapport sur la fraîcheur du schéma."""

    is_fresh: bool
    last_sync: Optional[datetime] = None
    changes: list[SchemaChange] = field(default_factory=list)
    tables_added: list[str] = field(default_factory=list)
    tables_removed: list[str] = field(default_factory=list)
    columns_changed: list[str] = field(default_factory=list)
    error_message: Optional[str] = None


class SchemaFreshnessChecker:
    """Vérifie la fraîcheur du schéma BDD."""

    def __init__(self):
        self.training_store = get_training_store()

    async def check(self) -> FreshnessReport:
        """
        Vérifie si le schéma stocké est à jour.

        Compare:
        - Tables stockées vs tables en live
        - Colonnes par table (count via INFORMATION_SCHEMA)

        Returns:
            FreshnessReport avec les changements détectés

        En cas d'erreur:
        - Si pyodbc indisponible: retourne un rapport avec erreur
        - Si connexion échoue: retourne is_fresh=False avec error_message (fail-closed)
        """
        if not PYODBC_AVAILABLE:
            return FreshnessReport(
                is_fresh=False,
                error_message="pyodbc non disponible - impossible de vérifier",
            )

        try:
            # Récupérer le schéma stocké — Phase α.4.C : freshness check = SYSTEM.
            from app.services.data_access.enforcer import SYSTEM_USER

            stored_tables = await self.training_store.get_all_table_names(user=SYSTEM_USER)
            stored_set = set(stored_tables) if stored_tables else set()

            # Récupérer la dernière sync
            last_sync = await self.get_last_sync_time()

            # Récupérer le schéma en live depuis Sage.
            #
            # ⚠️ NE PAS faire ``finally: connector.close()`` ici :
            # ``get_sage_connector()`` retourne le SINGLETON (cf.
            # ``sage_connector.py:1855``). Le fermer après usage le
            # déconnecte pour TOUS les autres callers concurrents
            # (search_schema, execute_sql, déjà-vu prefetch, etc.) qui
            # devront reconnecter au prochain appel — d'où le churn
            # observé 2026-05-22 (2 cycles open/close par check). Le
            # lifecycle du singleton est géré au shutdown via
            # ``close_sage_connector()`` ou à l'activation d'une autre
            # BDD via ``activate_connection``. ``connect()`` est
            # idempotent (no-op si déjà connecté) donc l'appeler ici
            # reste OK.
            connector = get_sage_connector()
            await connector.connect()
            live_tables = await self._get_live_tables(connector)
            live_set = set(live_tables) if live_tables else set()

            # Initialiser le rapport
            report = FreshnessReport(
                is_fresh=True,
                last_sync=last_sync,
            )

            # Détecter les tables ajoutées
            tables_added = live_set - stored_set
            if tables_added:
                report.is_fresh = False
                report.tables_added = sorted(list(tables_added))
                for table_name in tables_added:
                    report.changes.append(
                        SchemaChange(
                            change_type="table_added",
                            table_name=table_name,
                        )
                    )

            # Détecter les tables supprimées
            tables_removed = stored_set - live_set
            if tables_removed:
                report.is_fresh = False
                report.tables_removed = sorted(list(tables_removed))
                for table_name in tables_removed:
                    report.changes.append(
                        SchemaChange(
                            change_type="table_removed",
                            table_name=table_name,
                        )
                    )

            # Pour les tables de base qui existent dans les deux, comparer les colonnes.
            # Les vues (avec préfixe schema, ex: dbo_viewXxx) sont exclues car
            # INFORMATION_SCHEMA.COLUMNS ne reconnaît pas leur nom transformé.
            common_tables = stored_set & live_set
            # Les vues ont un préfixe schema_ (contiennent _ avant le premier caractère
            # majuscule ou mot). Les tables de base n'ont pas de préfixe schema.
            base_tables_only = {
                t for t in common_tables if "_" not in t or not t.startswith("dbo_")
            }
            if base_tables_only:
                # Singleton réutilisé — pas de close en finally (cf.
                # commentaire au-dessus). ``connect()`` est idempotent.
                await connector.connect()
                for table_name in sorted(base_tables_only):
                    columns_changed = await self._check_table_columns(connector, table_name)
                    if columns_changed:
                        report.is_fresh = False
                        report.columns_changed.append(table_name)
                        report.changes.extend(columns_changed)

            logger.info(
                "Schema freshness check: is_fresh=%s, "
                "tables_added=%d, tables_removed=%d, columns_changed=%d",
                report.is_fresh,
                len(report.tables_added),
                len(report.tables_removed),
                len(report.columns_changed),
            )

            return report

        except Exception:
            logger.error(
                "Erreur lors de la vérification de fraîcheur du schéma",
                exc_info=True,
            )
            # Fail-safe : en cas d'erreur, signaler que le schéma n'est PAS vérifié
            return FreshnessReport(
                is_fresh=False,
                last_sync=await self.get_last_sync_time(),
                error_message="Erreur de vérification du schéma. Consultez les logs.",
            )

    async def get_last_sync_time(self) -> Optional[datetime]:
        """Récupère le timestamp de la dernière synchronisation réussie."""
        try:
            async with get_session() as session:
                stmt = (
                    select(SchemaSync)
                    .where(SchemaSync.success == True)  # noqa: E712
                    .order_by(desc(SchemaSync.created_at))
                    .limit(1)
                )
                result = await session.execute(stmt)
                sync = result.scalar_one_or_none()
                if sync:
                    return sync.created_at
        except Exception:
            logger.error("Erreur lors de la récupération de la dernière sync", exc_info=True)

        return None

    async def _get_live_tables(self, connector) -> list[str]:
        """
        Récupère la liste des tables ET vues Sage.

        Les tables viennent de INFORMATION_SCHEMA.TABLES (BASE TABLE).
        Les vues viennent de sys.views, avec la même transformation de nom
        que schema_sync (dbo.viewName → dbo_viewName) pour que la comparaison
        stored vs live soit cohérente.
        """
        tables = []

        # 1. Tables de base
        sql_tables = (
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA = 'dbo' AND TABLE_TYPE = 'BASE TABLE' "
            "ORDER BY TABLE_NAME"
        )
        try:
            # bypass_admin_cap : sync interne du schma BDD, pas une
            # query user-visible. Le plafond /admin/database s'applique
            # aux excutions user (Iris, datastore SQL) ; le check de
            # fracheur doit voir TOUTES les tables.
            result = await connector.execute(sql_tables, bypass_admin_cap=True)
            tables.extend(row[0] for row in result.rows)
        except Exception:
            logger.error("Erreur lors de la récupération des tables en live", exc_info=True)
            return []

        # 2. Vues — même convention de nommage que schema_sync:
        #    dbo.viewName → dbo_viewName (replace "." par "_")
        sql_views = (
            "SELECT s.name AS schema_name, v.name AS view_name "
            "FROM sys.views v "
            "JOIN sys.schemas s ON v.schema_id = s.schema_id "
            "ORDER BY s.name, v.name"
        )
        try:
            result = await connector.execute(sql_views, bypass_admin_cap=True)
            for row in result.rows:
                schema_name, view_name = row[0], row[1]
                if schema_name and view_name:
                    # Reproduit schema_sync.py line 346: full_view_name.replace(".", "_")
                    full_name = f"{schema_name}_{view_name}"
                    tables.append(full_name)
        except Exception:
            logger.error("Erreur lors de la récupération des vues en live", exc_info=True)
            # On continue avec les tables seules plutôt que d'échouer complètement

        return tables

    @staticmethod
    def _compute_columns_hash(columns: list[tuple[str, str, str]]) -> str:
        """Calcule un hash SHA256 des colonnes (name, type, nullable) triées."""
        canonical = "|".join(
            f"{name}:{dtype}:{nullable}"
            for name, dtype, nullable in sorted(columns, key=lambda c: c[0].lower())
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _extract_columns_full_from_ddl(ddl_content: str) -> list[tuple[str, str, str]]:
        """Extrait (name, type, nullable) de chaque colonne depuis le DDL stocké.

        Todo #29 — Permet de comparer un hash STORED avec un hash LIVE pour
        détecter les changements de TYPE de colonne (varchar(50) → varchar(200),
        INT → BIGINT, etc.) même quand les noms restent identiques.

        Format DDL attendu (généré par ``schema_sync``) :
            CREATE TABLE dbo.TableName (
                ColName  type  NULL/NOT NULL,
                ...
            );

        Pattern compatible avec :
        - Types simples : ``int``, ``varchar``, ``datetime``
        - Types paramétrés : ``varchar(50)``, ``decimal(18,4)``
        - Nullable : ``NULL``, ``NOT NULL`` (insensible à la casse)

        Skip les keywords SQL (CONSTRAINT, PRIMARY KEY, etc.) en début de ligne.
        Retourne ``[]`` si pas de DDL ou aucune colonne parsée — fail-safe.
        """
        if not ddl_content:
            return []

        _SQL_KEYWORDS = frozenset(
            {
                "CONSTRAINT",
                "PRIMARY",
                "FOREIGN",
                "KEY",
                "INDEX",
                "UNIQUE",
                "CHECK",
            }
        )
        # Pattern : indentation + nom + type (optionnellement paramétré) + NULL/NOT NULL
        # Capture 3 groupes : name, type (avec ()), nullable_str
        col_pattern = re.compile(
            r"^\s{2,}(\w+)\s+(\w+(?:\([^)]*\))?)\s+(NOT\s+NULL|NULL)",
            re.MULTILINE | re.IGNORECASE,
        )
        columns: list[tuple[str, str, str]] = []
        for match in col_pattern.finditer(ddl_content):
            col_name = match.group(1)
            if col_name.upper() in _SQL_KEYWORDS:
                continue
            col_type = match.group(2).lower()
            # Normaliser le nullable : "NOT NULL" / "NULL" (avec ou sans espaces)
            nullable_raw = match.group(3).upper().replace(" ", "")
            nullable = "NOT NULL" if nullable_raw == "NOTNULL" else "NULL"
            columns.append((col_name, col_type, nullable))
        return columns

    async def _check_table_columns(self, connector, table_name: str) -> list[SchemaChange]:
        """
        Vérifie les colonnes d'une table en live via hash SHA256.

        Compare un hash des colonnes live (nom, type, nullable) avec les colonnes
        stockées. Détecte ajouts, suppressions ET modifications de type/nullable.
        """
        changes = []

        try:
            # Récupérer les colonnes détaillées en live.
            # Todo #29 — On fetch aussi CHARACTER_MAXIMUM_LENGTH +
            # NUMERIC_PRECISION/SCALE pour construire un type normalisé
            # ``varchar(50)`` / ``decimal(18,4)`` qui match le format
            # parsé depuis le DDL stocké. Sans ces colonnes, INFORMATION_
            # SCHEMA.DATA_TYPE retourne juste ``varchar`` (sans taille) →
            # mismatch permanent vs le DDL stocké → false positive.
            sql = (
                "SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, "
                "CHARACTER_MAXIMUM_LENGTH, NUMERIC_PRECISION, NUMERIC_SCALE "
                "FROM INFORMATION_SCHEMA.COLUMNS "
                "WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = ? "
                "ORDER BY ORDINAL_POSITION"
            )
            result = await connector.execute(sql, (table_name,), bypass_admin_cap=True)

            def _normalize_live_type(
                data_type: Any, char_max: Any, num_prec: Any, num_scale: Any
            ) -> str:
                """Construit ``varchar(50)``/``decimal(18,4)`` depuis les
                colonnes INFORMATION_SCHEMA — aligné avec le format du DDL
                stocké (cf. ``_extract_columns_full_from_ddl``).
                """
                dt = str(data_type or "").lower()
                if char_max is not None and char_max != -1:
                    try:
                        return f"{dt}({int(char_max)})"
                    except (TypeError, ValueError):
                        return dt
                if num_prec is not None and num_scale is not None:
                    try:
                        return f"{dt}({int(num_prec)},{int(num_scale)})"
                    except (TypeError, ValueError):
                        return dt
                return dt

            live_columns: list[tuple[str, str, str]] = []
            for row in result.rows or []:
                # Rétrocompat : si le mock/test ne fournit que (name, type, nullable)
                # sans les colonnes additionnelles, on retombe sur le format minimal.
                if len(row) >= 6:
                    name, data_type, is_nullable, char_max, num_prec, num_scale = row[:6]
                    norm_type = _normalize_live_type(data_type, char_max, num_prec, num_scale)
                elif len(row) >= 3:
                    name, data_type, is_nullable = row[:3]
                    norm_type = str(data_type or "").lower()
                else:
                    # Row malformée — skip plutôt que de crasher.
                    continue
                live_columns.append((str(name), norm_type, str(is_nullable or "")))
            live_names = {col[0].lower() for col in live_columns}
            live_hash = self._compute_columns_hash(live_columns)

            # Récupérer les colonnes stockées
            stored_column_names = await self.training_store.get_table_column_names(table_name)
            stored_names = (
                {c.lower() for c in stored_column_names} if stored_column_names else set()
            )

            # Détecter les colonnes ajoutées
            added = live_names - stored_names
            for col in sorted(added):
                changes.append(
                    SchemaChange(
                        change_type="column_added",
                        table_name=table_name,
                        column_name=col,
                    )
                )

            # Détecter les colonnes supprimées
            removed = stored_names - live_names
            for col in sorted(removed):
                changes.append(
                    SchemaChange(
                        change_type="column_removed",
                        table_name=table_name,
                        column_name=col,
                    )
                )

            # Même si les noms sont identiques, le hash détecte les changements
            # de type ou de nullable (ex: varchar(50) → varchar(100), NOT NULL → NULL).
            # Todo #29 — Extraction des types depuis le DDL stocké pour comparer
            # un hash stored vs live. Avant cette modif on tombait sur un fallback
            # « count différent » qui ratait toute modification pure de type.
            if not added and not removed and stored_names:
                stored_hash: Optional[str] = None
                try:
                    ddls = await self.training_store.get_ddl_by_table_names(
                        [table_name], n_results=1
                    )
                    if ddls:
                        ddl_content = ddls[0].get("content", "") or ""
                        stored_columns = self._extract_columns_full_from_ddl(ddl_content)
                        if stored_columns:
                            stored_hash = self._compute_columns_hash(stored_columns)
                except Exception as parse_err:  # noqa: BLE001
                    # Parsing DDL fragile par nature — fail-safe, on retombe
                    # sur le fallback count différent ci-dessous.
                    logger.debug(
                        "schema_freshness: parsing DDL stocké échoué pour %s: %s",
                        table_name,
                        parse_err,
                    )

                if stored_hash is not None and stored_hash != live_hash:
                    # Changement de type/nullable détecté même avec noms identiques.
                    changes.append(
                        SchemaChange(
                            change_type="column_modified",
                            table_name=table_name,
                            old_value=f"hash: {stored_hash}",
                            new_value=f"hash: {live_hash}",
                        )
                    )
                elif stored_hash is None and len(live_columns) != len(stored_names):
                    # Fallback count différent (DDL stocké non parseable).
                    # Préservé pour rétrocompat — Komptia tolère un DDL legacy
                    # qui ne matche pas le pattern actuel.
                    changes.append(
                        SchemaChange(
                            change_type="column_modified",
                            table_name=table_name,
                            old_value=str(len(stored_names)),
                            new_value=f"{len(live_columns)} (hash: {live_hash})",
                        )
                    )

            if changes:
                logger.info(
                    "Table %s: %d changement(s) détecté(s) (hash live: %s)",
                    table_name,
                    len(changes),
                    live_hash,
                )

        except Exception as e:
            from app.services.diagnostics import get_error_watchdog

            watchdog = get_error_watchdog()
            if watchdog.record("schema_freshness", type(e).__name__):
                logger.error(
                    "Erreur lors de la vérification des colonnes de %s",
                    table_name,
                    exc_info=True,
                )

        return changes


# Singleton instance
_freshness_checker: Optional[SchemaFreshnessChecker] = None


def get_freshness_checker() -> SchemaFreshnessChecker:
    """Retourne l'instance singleton du checker de fraîcheur du schéma."""
    global _freshness_checker
    if _freshness_checker is None:
        _freshness_checker = SchemaFreshnessChecker()
    return _freshness_checker
