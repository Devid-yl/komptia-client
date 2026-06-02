"""
Connecteur SQLite local — copie de la base Sage.

Même interface que SageConnector pour permettre les tests locaux
sans connexion au serveur SQL Server.

Traduit automatiquement les requêtes SQL Server → SQLite.
"""

import asyncio
import re
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import threading

from app.config import config
from app.utils.logger import get_logger
from app.core.exceptions import SageConnectionError, QueryError
from app.services.database.sql_translator import translate_sqlserver_to_sqlite
from app.utils.sql_scan import strip_all_sql_comments

logger = get_logger(__name__)

# Pool de threads (partagé)
_executor: Optional[ThreadPoolExecutor] = None
_executor_lock = threading.Lock()


@dataclass
class QueryResult:
    """Résultat d'une requête SQL — identique à sage_connector.QueryResult"""

    columns: List[str]
    rows: List[Tuple[Any, ...]]
    row_count: int
    execution_time_ms: float
    truncated: bool = False  # True si max_rows atteint (il y avait plus de lignes)

    def _deduplicate_columns(self) -> List[str]:
        """Retourne les noms de colonnes avec suffixes pour les doublons."""
        seen: Dict[str, int] = {}
        result: List[str] = []
        for col in self.columns:
            if col in seen:
                seen[col] += 1
                result.append(f"{col}_{seen[col]}")
            else:
                seen[col] = 1
                result.append(col)
        return result

    def to_dicts(self) -> List[Dict[str, Any]]:
        """Convertit les résultats en liste de dictionnaires.

        Gère les colonnes dupliquées en ajoutant un suffixe _2, _3, etc.
        """
        unique_cols = self._deduplicate_columns()
        return [dict(zip(unique_cols, row)) for row in self.rows]

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le premier résultat en dictionnaire"""
        if self.rows:
            return dict(zip(self._deduplicate_columns(), self.rows[0]))
        return {}


class SqliteSageConnector:
    """
    Connecteur SQLite local avec la même interface que SageConnector.

    Lit les données depuis une copie SQLite de la base Sage.
    Traduit automatiquement la syntaxe SQL Server en SQLite.
    """

    def __init__(
        self,
        db_path: str = None,
        max_rows: int = None,
    ) -> None:
        from app.config import DATA_DIR

        self.db_path = db_path or str(DATA_DIR / "sage_copy.db")
        self.max_rows = max_rows or config.sage.max_rows
        self.timeout = 30  # Pas de timeout réseau, mais gardé pour compatibilité

        # Attributs pour l'interface SageConnector
        self.host = "localhost (SQLite)"
        self.port = 0
        self.database = Path(self.db_path).stem
        self.username = "local"

        # Thread-local storage : chaque thread du pool a sa propre connexion SQLite.
        # SQLite interdit d'utiliser une connexion créée dans un autre thread.
        self._local = threading.local()
        self._connections: list[sqlite3.Connection] = []  # Registre pour close() propre
        self._conn_lock = threading.Lock()
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    def _get_executor(self) -> ThreadPoolExecutor:
        global _executor
        if _executor is None:
            with _executor_lock:
                if _executor is None:
                    _executor = ThreadPoolExecutor(
                        max_workers=config.database.pool_size,
                        thread_name_prefix="sqlite-sage",
                    )
        return _executor

    def _get_thread_connection(self) -> sqlite3.Connection:
        """Retourne la connexion SQLite du thread courant, en la créant si nécessaire.

        Chaque thread du pool maintient sa propre connexion (thread-local).
        SQLite en mode WAL supporte les lectures concurrentes sans problème.
        """
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            return conn

        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA cache_size=-64000")  # 64 Mo
        conn.row_factory = None  # Tuples bruts
        self._local.conn = conn
        with self._conn_lock:
            self._connections.append(conn)
        return conn

    async def connect(self) -> None:
        """Vérifie que le fichier SQLite existe et marque le connecteur comme prêt.

        Les connexions réelles sont créées à la demande dans chaque thread (thread-local).
        """
        if self._connected:
            return

        db_file = Path(self.db_path)
        if not db_file.exists():
            raise SageConnectionError(
                f"[CONNEXION_IMPOSSIBLE] Fichier SQLite introuvable: {self.db_path}. "
                f"Lancez scripts/copy_sage_to_sqlite.py pour créer la copie locale."
            )

        # Vérifier qu'on peut ouvrir le fichier (test dans un thread du pool)
        def _test_connect():
            conn = sqlite3.connect(self.db_path, timeout=30)
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            conn.close()

        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(self._get_executor(), _test_connect)
            self._connected = True
            logger.info(
                "✅ Connecté à SQLite local: %s",
                self.db_path,
            )
        except (sqlite3.Error, OSError) as e:
            raise SageConnectionError(f"Impossible d'ouvrir la copie SQLite: {e}") from e

    async def close(self) -> None:
        """Ferme toutes les connexions thread-local et réinitialise l'état."""
        with self._conn_lock:
            for conn in self._connections:
                try:
                    conn.close()
                except Exception as e:
                    # P5.1 (audit 2026-05-26) — Promu DEBUG → WARNING (cf.
                    # sage_connector close pour la doctrine). Un close raté
                    # laisse un file descriptor SQLite zombie qui peut bloquer
                    # les écritures futures (sqlite_busy).
                    logger.warning("Erreur fermeture connexion SQLite: %s", e)
            self._connections.clear()
        self._local = threading.local()
        self._connected = False
        logger.info("Connexion SQLite locale fermée")

    @staticmethod
    def _intercept_metadata_query(sql: str) -> Optional[str]:
        """Intercepte les requêtes de métadonnées SQL Server et les traduit en SQLite.

        SQL Server utilise INFORMATION_SCHEMA, sys.views etc.
        SQLite utilise sqlite_master et PRAGMAs — pas de traduction AST possible,
        il faut réécrire complètement.

        Note: @@VERSION n'est PAS intercepté volontairement — en mode SQLite,
        retourner une fausse version polluerait la BDD (server_version) et les
        prompts LLM. Mieux vaut laisser l'erreur remonter, les appelants la
        gèrent via try/except.
        """
        normalized = " ".join(sql.split()).upper()

        # INFORMATION_SCHEMA.TABLES → sqlite_master WHERE type='table'
        if "INFORMATION_SCHEMA.TABLES" in normalized:
            # COUNT(*) → compter directement
            if "COUNT(*)" in normalized or "COUNT (" in normalized:
                return (
                    "SELECT COUNT(*) FROM sqlite_master "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
                    "AND name != '_sage_views'"
                )

            # Detect which columns are SELECTed (avant le FROM)
            select_part = normalized.split("FROM")[0] if "FROM" in normalized else normalized
            has_schema = "TABLE_SCHEMA" in select_part
            has_name = "TABLE_NAME" in select_part

            cols = []
            if has_schema:
                cols.append("'dbo' AS TABLE_SCHEMA")
            if has_name or not cols:
                cols.append("name AS TABLE_NAME")

            return (
                f"SELECT {', '.join(cols)} "
                "FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
                "AND name != '_sage_views' "
                "ORDER BY name"
            )

        # CROSS JOIN sys.sql_modules m WHERE m.object_id = OBJECT_ID(?)
        # Pattern : chunked DDL retrieval (cf. app/services/ai/schema_sync.py
        # `_load_view_ddl_chunked`). Le caller récupère la DDL d'UNE vue par
        # chunks de 2000 chars (max 64 chunks = 128 KB). On reconstitue depuis
        # _sage_views.definition côté SQLite via une CTE récursive équivalente.
        # Plus spécifique que SYS.VIEWS (a OBJECT_ID(...) — le `(` distingue
        # l'appel de fonction de la colonne `object_id`).
        if "SYS.SQL_MODULES" in normalized and "OBJECT_ID(" in normalized:
            return (
                "WITH RECURSIVE chunks(n) AS ("
                "  SELECT 1 UNION ALL SELECT n+1 FROM chunks WHERE n < 64"
                "), input_name AS (SELECT ? AS n), "
                "view_def AS ("
                "  SELECT v.definition AS definition, "
                "         length(v.definition) AS total_len "
                "  FROM _sage_views v, input_name i "
                "  WHERE v.view_name = i.n "
                "     OR (v.schema_name || '.' || v.view_name) = i.n "
                "  LIMIT 1"
                ") "
                "SELECT c.n AS chunk_idx, "
                "       substr(d.definition, (c.n - 1) * 2000 + 1, 2000) AS chunk_data, "
                "       d.total_len AS total_len "
                "FROM chunks c, view_def d "
                "WHERE (c.n - 1) * 2000 < d.total_len "
                "ORDER BY c.n"
            )

        # SELECT v.name, m.definition FROM sys.views v JOIN sys.sql_modules m
        # Pattern : récupération de TOUTES les vues + leur DDL (utilisé par
        # schema_enricher view mining ligne 1458). Doit être avant la règle
        # SYS.VIEWS générique qui ne retourne que les noms.
        if "SYS.SQL_MODULES" in normalized and "SYS.VIEWS" in normalized:
            return (
                "SELECT view_name AS view_name, "
                "       definition AS definition "
                "FROM _sage_views "
                "WHERE definition IS NOT NULL "
                "ORDER BY view_name"
            )

        # sys.views JOIN sys.schemas → _sage_views
        if "SYS.VIEWS" in normalized:
            return (
                "SELECT schema_name, view_name "
                "FROM _sage_views "
                "ORDER BY schema_name, view_name"
            )

        # OBJECT_DEFINITION(OBJECT_ID(?)) → _sage_views.definition
        # Le caller passe soit "viewname" soit "schema.viewname" — on accepte les 2.
        if "OBJECT_DEFINITION" in normalized and "OBJECT_ID" in normalized:
            return (
                "WITH input_name AS (SELECT ? AS n) "
                "SELECT v.definition FROM _sage_views v, input_name "
                "WHERE v.view_name = n OR (v.schema_name || '.' || v.view_name) = n "
                "LIMIT 1"
            )

        # INFORMATION_SCHEMA.COLUMNS → pragma_table_info() (SQLite table-valued)
        if "INFORMATION_SCHEMA.COLUMNS" in normalized:
            return (
                "SELECT m.name AS TABLE_NAME, "
                "       ti.name AS COLUMN_NAME, "
                "       ti.type AS DATA_TYPE, "
                "       NULL AS CHARACTER_MAXIMUM_LENGTH, "
                "       CASE WHEN ti.\"notnull\" = 1 THEN 'NO' ELSE 'YES' END AS IS_NULLABLE, "
                "       ti.dflt_value AS COLUMN_DEFAULT "
                "FROM sqlite_master m "
                "JOIN pragma_table_info(m.name) ti "
                "WHERE m.type = 'table' "
                "  AND m.name NOT LIKE 'sqlite_%' "
                "  AND m.name != '_sage_views' "
                "ORDER BY m.name, ti.cid"
            )

        return None

    async def execute(
        self,
        query: str,
        params: Tuple[Any, ...] = None,
        max_rows: int = None,
        bypass_admin_cap: bool = False,
    ) -> QueryResult:
        """
        Exécute une requête SQL Server (traduite automatiquement en SQLite).

        Interface identique à SageConnector.execute(). bypass_admin_cap est
        accepté pour compatibilité de signature mais non utilisé : la copie
        SQLite locale n'est pas soumise au plafond UX de /admin/database.
        """
        _ = bypass_admin_cap
        if not self._connected:
            await self.connect()

        effective_max_rows = max_rows or self.max_rows

        # Intercepter les requêtes de métadonnées SQL Server
        original_query = query
        intercepted = self._intercept_metadata_query(query)
        if intercepted is not None:
            translated_query = intercepted
            logger.debug("Metadata query interceptée: %s → %s", query[:80], translated_query[:80])
        else:
            # Traduire SQL Server → SQLite via sqlglot
            translated_query = translate_sqlserver_to_sqlite(query)

        if translated_query != original_query:
            logger.debug(
                "SQL traduit: %s → %s",
                original_query[:100],
                translated_query[:100],
            )

        # Strip ALL SQL comments avant binding paramètres (chantier T6).
        # Defense-in-depth : sqlite3 stdlib n'a pas le bug observé en
        # pyodbc qmark (cf. `strip_all_sql_comments` docstring), mais on
        # applique pour consistance + futures évolutions de driver.
        sanitized_translated = strip_all_sql_comments(translated_query)

        def _execute():
            conn = self._get_thread_connection()
            start = time.perf_counter()
            cursor = conn.cursor()
            try:
                if params:
                    cursor.execute(sanitized_translated, params)
                else:
                    cursor.execute(sanitized_translated)

                # Récupérer les colonnes
                columns = [desc[0] for desc in cursor.description] if cursor.description else []

                # Récupérer les lignes (avec limite)
                rows = cursor.fetchmany(effective_max_rows)

                # Détecter si les résultats ont été tronqués — SANS faux positif.
                # #65 (A8-F1) — ``len(rows) >= effective_max_rows`` était FAUX quand
                # le résultat fait EXACTEMENT le cap (complet) : l'user voyait
                # « tronqué » sur un résultat intégral (données fausses silencieuses).
                # ``fetchmany(cap)`` ne retourne jamais plus que le cap :
                #   - len(rows) <  cap  ⇒ complet (jamais tronqué)
                #   - len(rows) == cap  ⇒ AMBIGU → sonder UNE ligne au-delà du cap.
                #     Seule une ligne RÉELLE supplémentaire prouve la troncature.
                # (Un ``fetchone()`` qui lève est capturé par ``except sqlite3.Error``
                # ci-dessous → erreur surfacée, jamais un faux « complet ».)
                was_truncated = False
                if len(rows) >= effective_max_rows:
                    was_truncated = cursor.fetchone() is not None

                elapsed = (time.perf_counter() - start) * 1000

                return QueryResult(
                    columns=columns,
                    rows=[tuple(row) for row in rows],
                    row_count=len(rows),
                    execution_time_ms=round(elapsed, 2),
                    truncated=was_truncated,
                )
            except sqlite3.Error as e:
                elapsed = (time.perf_counter() - start) * 1000
                logger.warning(
                    "Erreur SQL SQLite (%.1fms): %s\nOriginal: %s\nTraduit: %s",
                    elapsed,
                    e,
                    original_query[:200],
                    translated_query[:200],
                )
                raise
            finally:
                cursor.close()

        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(self._get_executor(), _execute)
        except sqlite3.OperationalError as e:
            raise QueryError(
                f"Erreur SQL (traduit depuis SQL Server): {e}\n"
                f"Requête originale: {original_query[:200]}\n"
                f"Requête traduite: {translated_query[:200]}"
            )
        except sqlite3.Error as e:
            raise QueryError(f"Erreur SQLite: {e}")

    async def execute_write(
        self,
        sql: str,
        params: Tuple[Any, ...] = None,
        dry_run: bool = True,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """Exécute une écriture SQL en transaction (mode SQLite local).

        Mêmes garanties que ``SageConnector.execute_write`` : transaction
        explicite, ROLLBACK si dry_run, sinon COMMIT. Le SQL doit avoir
        passé ``write_validator.parse_and_validate_write()``.
        """
        del timeout  # noqa: ARG002 — sqlite3 timeout est connection-level
        if not self._connected:
            await self.connect()

        upper = sql.strip().upper()
        if upper.startswith("SELECT") or upper.startswith("WITH"):
            raise QueryError("execute_write() refuse les SELECT — utilisez execute().")

        def _execute_write_sync() -> Dict[str, Any]:
            import time as _t

            start_time = _t.perf_counter()
            conn = self._get_thread_connection()
            cursor = conn.cursor()
            try:
                # SQLite : BEGIN explicite (sinon autocommit comportement
                # ambigu selon isolation_level).
                cursor.execute("BEGIN")
                if params:
                    cursor.execute(sql, params)
                else:
                    cursor.execute(sql)
                rows_affected = int(cursor.rowcount or 0)
                if dry_run:
                    conn.rollback()
                else:
                    conn.commit()
                return {
                    "rows_affected": rows_affected,
                    "duration_ms": (_t.perf_counter() - start_time) * 1000,
                    "dry_run": dry_run,
                    "sql_executed": sql,
                }
            except Exception:
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
                raise
            finally:
                cursor.close()

        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(self._get_executor(), _execute_write_sync)
        except sqlite3.Error as exc:
            logger.warning(
                "execute_write SQLite error",
                extra={"sql": sql[:200], "dry_run": dry_run},
                exc_info=True,
            )
            raise QueryError(f"Erreur SQLite: {exc}")

    async def execute_scalar(self, query: str, params: Tuple[Any, ...] = None) -> Any:
        """Exécute une requête et retourne une seule valeur."""
        result = await self.execute(query, params, max_rows=1)
        if result.rows and result.rows[0]:
            return result.rows[0][0]
        return None

    async def explain_plan(
        self,
        sql: str,
        params: Optional[Tuple[Any, ...]] = None,
        *,
        timeout: float = 5.0,
    ) -> Optional[str]:
        """T27 — Plan d'exécution préventif (no-op pour SQLite).

        SQLite n'a pas l'équivalent ``SHOWPLAN_XML`` de SQL Server.
        ``EXPLAIN QUERY PLAN`` existe mais retourne un format texte
        non-structuré (rows ``id|parent|notused|detail``) incompatible
        avec le parser XML T-SQL.

        Cette méthode retourne ``None`` — le caller (T27 plan preview)
        skip silencieusement le warning en mode SQLite.

        Future V2 : exposer un parser dédié EXPLAIN QUERY PLAN si on
        veut le warning aussi en dev local.
        """
        del sql, params, timeout  # noqa: ARG002 — interface stable, no-op
        return None

    async def health_check(self) -> bool:
        """Vérifie que la connexion est active."""
        try:
            result = await self.execute_scalar("SELECT 1")
            return result == 1
        except (QueryError, SageConnectionError):
            return False

    async def get_tables(self, user: Any = None) -> List[str]:
        """Liste les tables (exclut les tables internes SQLite et _sage_views).

        Args:
            user: optionnel — Phase α.3 mode invisible. ``user=None`` =
                comportement legacy (compat tests / call-sites système).
                Sinon : filtre les tables interdites pour cet user.
        """
        result = await self.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != '_sage_views' "
            "ORDER BY name"
        )
        all_tables = [row[0] for row in result.rows]

        # Phase α.3 — Filtre mode invisible
        from app.services.data_access.enforcer import should_filter_for

        if not await should_filter_for(user):
            return all_tables
        try:
            from app.services.data_access.visible_schema import (
                build_user_schema_view,
            )

            view = await build_user_schema_view(user)
            if not view.has_restrictions:
                return all_tables
            return [t for t in all_tables if t and view.can_see_table(t)]
        except Exception as exc:
            logger.error(
                "SqliteSageConnector.get_tables: filtrage mode invisible "
                "échoué (fail-closed, [] retourné): %s",
                exc,
                exc_info=True,
            )
            return []

    async def get_columns(
        self,
        table_name: str,
        user: Any = None,
    ) -> List[Dict[str, Any]]:
        """Liste les colonnes d'une table.

        Args:
            table_name: Nom de la table (validé identifiant).
            user: optionnel — Phase α.3 mode invisible. Si table
                invisible → ``[]``. Sinon : filtre les colonnes
                interdites.
        """
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")

        # Phase α.3 — Pré-check table visible AVANT PRAGMA.
        from app.services.data_access.enforcer import should_filter_for

        view_for_filter = None
        if await should_filter_for(user):
            try:
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view_for_filter = await build_user_schema_view(user)
                if view_for_filter.has_restrictions and not view_for_filter.can_see_table(
                    table_name
                ):
                    return []
            except Exception as exc:
                logger.error(
                    "SqliteSageConnector.get_columns: filtrage mode "
                    "invisible échoué (fail-closed, [] retourné): %s",
                    exc,
                    exc_info=True,
                )
                return []

        result = await self.execute(f"PRAGMA table_info([{table_name}])")

        columns = []
        for row in result.rows:
            # PRAGMA table_info retourne: cid, name, type, notnull, dflt_value, pk
            col_type = (row[2] or "TEXT").upper()
            columns.append(
                {
                    "name": row[1],
                    "type": _sqlite_type_to_sqlserver(col_type),
                    "nullable": not bool(row[3]),
                    "max_length": None,
                    "precision": None,
                    "default": row[4],
                }
            )

        # Phase α.3 — Filtre colonnes interdites si view active.
        if view_for_filter is None or not view_for_filter.has_restrictions:
            return columns
        return [
            c
            for c in columns
            if c.get("name") and view_for_filter.can_see_column(table_name, c["name"])
        ]

    async def get_distinct_values(
        self,
        table_name: str,
        column_name: str,
        max_values: int = 0,
        user: Any = None,
    ) -> List[str]:
        """Récupère les valeurs distinctes d'une colonne. 0 = toutes.

        Args:
            table_name, column_name: validés identifiants.
            max_values: limite.
            user: Phase α.3 fix BLOCKING #2 — table/col invisible → [].
        """
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", column_name):
            raise ValueError(f"Nom de colonne invalide: {column_name}")

        # Phase α.3 — Pré-check user (cf. SageConnector.get_distinct_values).
        from app.services.data_access.enforcer import should_filter_for

        if await should_filter_for(user):
            try:
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view = await build_user_schema_view(user)
                if view.has_restrictions and (
                    not view.can_see_table(table_name)
                    or not view.can_see_column(table_name, column_name)
                ):
                    return []
            except Exception as exc:
                logger.error(
                    "SqliteSageConnector.get_distinct_values: filtrage "
                    "mode invisible échoué (fail-closed, [] retourné): %s",
                    exc,
                    exc_info=True,
                )
                return []

        limit_clause = f" LIMIT {int(max_values)}" if max_values > 0 else ""
        result = await self.execute(
            f"SELECT DISTINCT [{column_name}] FROM [{table_name}] "
            f"WHERE [{column_name}] IS NOT NULL{limit_clause}"
        )
        return [str(row[0]) for row in result.rows if row[0] is not None]

    async def get_top_values_with_frequency(
        self,
        table_name: str,
        column_name: str,
        top_n: int = 1000,
        user: Any = None,
    ) -> List[tuple]:
        """Top-N valeurs distinctes par fréquence DESC — mirror SQLite de
        ``SageConnector.get_top_values_with_frequency`` (T5).

        Args:
            table_name: nom de table validé
            column_name: nom de colonne validé
            top_n: cap (≤ 0 = défaut 1000)

        Returns:
            List[(value, count)] triée par count DESC.
        """
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", column_name):
            raise ValueError(f"Nom de colonne invalide: {column_name}")

        # Phase α.3 — Pré-check user.
        from app.services.data_access.enforcer import should_filter_for

        if await should_filter_for(user):
            try:
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view = await build_user_schema_view(user)
                if view.has_restrictions and (
                    not view.can_see_table(table_name)
                    or not view.can_see_column(table_name, column_name)
                ):
                    return []
            except Exception as exc:
                logger.error(
                    "SqliteSageConnector.get_top_values_with_frequency: "
                    "filtrage mode invisible échoué (fail-closed, [] retourné): %s",
                    exc,
                    exc_info=True,
                )
                return []

        cap = top_n if isinstance(top_n, int) and top_n > 0 else 1000
        result = await self.execute(
            f"SELECT [{column_name}] AS v, COUNT(*) AS n "
            f"FROM [{table_name}] "
            f"WHERE [{column_name}] IS NOT NULL "
            f"GROUP BY [{column_name}] "
            f"ORDER BY COUNT(*) DESC LIMIT {cap}"
        )
        return [(str(row[0]), int(row[1])) for row in result.rows if row[0] is not None]

    async def get_table_row_count(self, table_name: str) -> int:
        """Retourne le nombre de lignes d'une table."""
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")

        result = await self.execute(f"SELECT COUNT(*) FROM [{table_name}]", max_rows=1)
        return int(result.rows[0][0]) if result.rows else 0

    async def get_column_stats(
        self, table_name: str, columns: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """Collecte les stats par colonne."""
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")

        stats: Dict[str, Dict[str, Any]] = {}
        select_parts = ["COUNT(*) AS _total_rows"]
        col_names = []

        for col_info in columns:
            col_name = col_info["name"] if isinstance(col_info, dict) else col_info
            if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", col_name):
                continue

            col_type = ""
            if isinstance(col_info, dict):
                col_type = (col_info.get("type") or "").lower()

            col_names.append(col_name)
            safe_col = f"[{col_name}]"

            select_parts.append(f"COUNT(DISTINCT {safe_col}) AS [{col_name}__distinct]")
            select_parts.append(
                f"SUM(CASE WHEN {safe_col} IS NULL THEN 1 ELSE 0 END) " f"AS [{col_name}__nulls]"
            )

            # Min/max pour numériques
            if any(t in col_type for t in ("int", "numeric", "decimal", "float", "money", "real")):
                select_parts.append(f"MIN({safe_col}) AS [{col_name}__min]")
                select_parts.append(f"MAX({safe_col}) AS [{col_name}__max]")

        if not col_names:
            return stats

        query = f"SELECT {', '.join(select_parts)} FROM [{table_name}]"

        try:
            result = await self.execute(query, max_rows=1)
            if not result.rows:
                return stats

            row = result.rows[0]
            total_rows = int(row[0]) if row[0] else 0

            col_idx = 1
            for col_name in col_names:
                col_stats: Dict[str, Any] = {"total_rows": total_rows}
                col_stats["distinct"] = int(row[col_idx]) if row[col_idx] is not None else 0
                col_stats["nulls"] = int(row[col_idx + 1]) if row[col_idx + 1] is not None else 0
                col_stats["null_pct"] = (
                    round(col_stats["nulls"] / total_rows * 100, 1) if total_rows > 0 else 0
                )
                col_idx += 2

                col_info = next(
                    (c for c in columns if (c["name"] if isinstance(c, dict) else c) == col_name),
                    None,
                )
                col_type = ""
                if isinstance(col_info, dict):
                    col_type = (col_info.get("type") or "").lower()
                if any(
                    t in col_type for t in ("int", "numeric", "decimal", "float", "money", "real")
                ):
                    if col_idx + 1 < len(row):
                        col_stats["min_val"] = row[col_idx]
                        col_stats["max_val"] = row[col_idx + 1]
                        col_idx += 2

                stats[col_name] = col_stats

        except Exception as e:
            # P5.1 (audit 2026-05-26) — Promu DEBUG → WARNING (cf. sage_connector
            # get_column_stats pour la doctrine). Stats échouées → Iris reçoit
            # ``{}`` sans visibilité.
            logger.warning("get_column_stats(%s) failed: %s", table_name, e)

        return stats

    # ── Méthodes méta-schéma (interface agnostique partagée avec SageConnector) ──
    # Ces méthodes existent pour que le code applicatif (ex: agent_tools.introspect_table)
    # n'ait pas à connaître le dialecte. Côté SQL Server : INFORMATION_SCHEMA + sys.*.
    # Côté SQLite : PRAGMA. Format de retour identique entre les deux.

    async def get_indexes(self, table_name: str) -> List[Dict[str, Any]]:
        """Retourne ``[{"column_name": str, "is_unique": bool}, ...]`` pour la table.

        Une colonne apparaît une fois par index où elle figure (multi-colonne =
        plusieurs entries). ``is_unique`` reflète l'index, pas la colonne — une
        colonne peut être marquée unique via plusieurs index, le caller agrège.
        """
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")

        idx_list = await self.execute(f"PRAGMA index_list([{table_name}])")
        results: List[Dict[str, Any]] = []
        for idx_row in idx_list.rows:
            # PRAGMA index_list: [seq, name, unique, origin, partial]
            idx_name = idx_row[1]
            is_unique = bool(idx_row[2])
            if not isinstance(idx_name, str) or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", idx_name):
                continue
            cols = await self.execute(f"PRAGMA index_info([{idx_name}])")
            # PRAGMA index_info: [seqno, cid, name]
            for col_row in cols.rows:
                col_name = col_row[2]
                if col_name:
                    results.append({"column_name": col_name, "is_unique": is_unique})
        return results

    async def get_identity_columns(self, table_name: str) -> List[str]:
        """Colonnes auto-incrémentées. SQLite : détecte ``AUTOINCREMENT`` dans le DDL.

        Note : ROWID implicite (cas par défaut sur INTEGER PRIMARY KEY) n'est PAS
        retourné — le caller le détecte via la colonne pk + type INTEGER si besoin.
        """
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")

        ddl_result = await self.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name = ?",
            (table_name,),
        )
        if not ddl_result.rows or not ddl_result.rows[0][0]:
            return []
        ddl = ddl_result.rows[0][0]
        if "AUTOINCREMENT" not in ddl.upper():
            return []
        # Parse minimal : trouver le nom de colonne suivi de INTEGER PRIMARY KEY AUTOINCREMENT
        # SQLite n'autorise AUTOINCREMENT que sur INTEGER PRIMARY KEY → une seule colonne
        match = re.search(
            r'["\[]?([A-Za-z_][A-Za-z0-9_]*)["\]]?\s+INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT',
            ddl,
            re.IGNORECASE,
        )
        return [match.group(1)] if match else []

    async def get_primary_keys(self, table_name: str) -> List[str]:
        """PK ordonnées par position (PK composite supportée)."""
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")

        result = await self.execute(f"PRAGMA table_info([{table_name}])")
        # PRAGMA table_info: [cid, name, type, notnull, dflt_value, pk]
        # pk > 0 = position dans PK composite (1, 2, ...). pk == 0 = pas dans PK.
        pk_cols = [(row[5], row[1]) for row in result.rows if row[5] and row[5] > 0]
        pk_cols.sort(key=lambda t: t[0])
        return [col_name for _, col_name in pk_cols]

    async def get_foreign_keys(
        self,
        table_name: str,
        user: Any = None,
    ) -> List[Dict[str, Any]]:
        """FK sortantes : ``[{"column", "references_table", "references_column", "constraint_name"}]``.

        SQLite n'a pas de nom de constraint nommé en interne — on synthétise
        ``"fk_<table>_<id>"`` pour rester compatible avec le format attendu.

        Args:
            user: Phase α.3 fix BLOCKING #3 — filtre les FK vers des
                tables invisibles.
        """
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")

        # Phase α.3 — Pré-check user.
        from app.services.data_access.enforcer import should_filter_for

        view_for_filter = None
        if await should_filter_for(user):
            try:
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view_for_filter = await build_user_schema_view(user)
                if view_for_filter.has_restrictions and not view_for_filter.can_see_table(
                    table_name
                ):
                    return []
            except Exception as exc:
                logger.error(
                    "SqliteSageConnector.get_foreign_keys: filtrage mode "
                    "invisible échoué (fail-closed, [] retourné): %s",
                    exc,
                    exc_info=True,
                )
                return []

        result = await self.execute(f"PRAGMA foreign_key_list([{table_name}])")
        # PRAGMA foreign_key_list: [id, seq, table, from, to, on_update, on_delete, match]
        fks: List[Dict[str, Any]] = []
        for row in result.rows:
            fk_id = row[0]
            ref_table = row[2]
            from_col = row[3]
            to_col = row[4]
            fks.append(
                {
                    "column": from_col,
                    "references_table": ref_table,
                    "references_column": to_col,
                    "constraint_name": f"fk_{table_name}_{fk_id}",
                }
            )

        # Phase α.3 — Retirer les FK vers tables invisibles.
        if view_for_filter is None or not view_for_filter.has_restrictions:
            return fks
        return [
            fk
            for fk in fks
            if fk.get("references_table")
            and view_for_filter.can_see_table(fk["references_table"])
            and view_for_filter.can_see_column(table_name, fk.get("column", ""))
        ]

    async def get_referencing_foreign_keys(
        self,
        table_name: str,
        user: Any = None,
    ) -> List[Dict[str, Any]]:
        """FK entrantes : autres tables qui pointent vers ``table_name``.

        ``[{"referencing_table", "referencing_column", "referenced_column", "constraint_name"}]``.

        SQLite n'a pas de catalogue inverse ; on doit scanner les FK de chaque
        table. Coût O(N tables) par appel — acceptable pour usage introspect
        ponctuel, à mémoïser si appelé en boucle.

        Args:
            user: Phase α.3 — retire les FK depuis tables invisibles.
        """
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")

        from app.services.data_access.enforcer import should_filter_for

        view_for_filter = None
        if await should_filter_for(user):
            try:
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view_for_filter = await build_user_schema_view(user)
                if view_for_filter.has_restrictions and not view_for_filter.can_see_table(
                    table_name
                ):
                    return []
            except Exception as exc:
                logger.error(
                    "SqliteSageConnector.get_referencing_foreign_keys: "
                    "filtrage mode invisible échoué (fail-closed, [] retourné): %s",
                    exc,
                    exc_info=True,
                )
                return []

        # Propager user à get_tables pour ne pas itérer sur des tables
        # invisibles (économie + cohérence du log SQL).
        all_tables = await self.get_tables(user=user)
        results: List[Dict[str, Any]] = []
        for other_table in all_tables:
            if other_table == table_name:
                continue
            try:
                fk_result = await self.execute(f"PRAGMA foreign_key_list([{other_table}])")
            except Exception as fk_exc:  # noqa: BLE001
                # P5.1 (audit 2026-05-26) — Promu silent `continue` → WARNING :
                # un PRAGMA invalide sur une table donnée (corruption, schéma
                # malformé, table verrouillée) skippe silencieusement → si TOUTES
                # les FK entrantes vers la table cible sont sur des tables qui
                # crashent, le caller voit ``[]`` ("aucune FK entrante") qui est
                # une **fausse vérité silencieuse**. WARNING permet à l'admin
                # d'identifier les tables problématiques.
                logger.warning(
                    "get_referencing_foreign_keys: PRAGMA échoué sur '%s' (skip): %s",
                    other_table,
                    fk_exc,
                )
                continue
            for row in fk_result.rows:
                if row[2] == table_name:  # `table` (référencée) == notre table
                    results.append(
                        {
                            "referencing_table": other_table,
                            "referencing_column": row[3],
                            "referenced_column": row[4],
                            "constraint_name": f"fk_{other_table}_{row[0]}",
                        }
                    )

        # Defense-in-depth : même filtre que get_foreign_keys (cohérence).
        if view_for_filter is None or not view_for_filter.has_restrictions:
            return results
        return [
            ref
            for ref in results
            if ref.get("referencing_table")
            and view_for_filter.can_see_table(ref["referencing_table"])
        ]

    async def get_check_constraints(self, table_name: str) -> List[Dict[str, Any]]:
        """CHECK constraints : ``[{"constraint_name", "clause"}]``.

        SQLite ne nomme pas les CHECK et n'expose pas de catalogue dédié — il
        faudrait parser le DDL. Pour le MVP on retourne []; le caller a déjà
        un try/except qui gère ce cas.
        """
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")
        return []

    async def get_schema_context(self) -> Dict[str, Any]:
        """Génère le contexte schéma pour l'IA."""
        tables = await self.get_tables()
        tables = tables[:50]
        columns_list = await asyncio.gather(*(self.get_columns(table) for table in tables))
        return dict(zip(tables, columns_list))


# ── Helpers ──────────────────────────────────────────────────────────────


def _sqlite_type_to_sqlserver(sqlite_type: str) -> str:
    """
    Reconvertit un type SQLite vers le type SQL Server d'origine (approximatif).

    Utile pour que le code qui lit les types (ex: get_column_stats) fonctionne
    avec les mêmes heuristiques que sur SQL Server.
    """
    t = sqlite_type.upper().strip()
    if t == "INTEGER":
        return "int"
    if t == "REAL":
        return "decimal"
    if t == "BLOB":
        return "varbinary"
    if t == "TEXT":
        return "nvarchar"
    return "nvarchar"


# ── Singleton ────────────────────────────────────────────────────────────

_sqlite_connector: Optional[SqliteSageConnector] = None


def get_sqlite_sage_connector(db_path: str = None) -> SqliteSageConnector:
    """Retourne l'instance globale du connecteur SQLite Sage."""
    global _sqlite_connector
    if _sqlite_connector is None:
        _sqlite_connector = SqliteSageConnector(db_path=db_path)
    return _sqlite_connector


async def close_sqlite_sage_connector() -> None:
    """Ferme le connecteur global SQLite."""
    global _sqlite_connector, _executor
    if _sqlite_connector:
        await _sqlite_connector.close()
        _sqlite_connector = None
    if _executor:
        _executor.shutdown(wait=False)
        _executor = None


@asynccontextmanager
async def sqlite_sage_connection(db_path: str = None):
    """Context manager compatible avec sage_connection()."""
    connector = get_sqlite_sage_connector(db_path)
    if not connector.is_connected:
        await connector.connect()
    yield connector
