"""
Validateur SQL pour Komptia.

Valide et sécurise les requêtes SQL générées par le LLM:
- Parse et valide la syntaxe
- Bloque les opérations dangereuses (INSERT, UPDATE, DELETE, DROP, etc.)
- Vérifie que les tables et colonnes existent
- Ajoute automatiquement TOP si absent
- Whitelist des tables autorisées
"""

import re
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from difflib import get_close_matches
from enum import Enum

import sqlparse
from sqlparse.sql import Statement, Identifier, IdentifierList
from sqlparse.tokens import Keyword, DML

from app.core.exceptions import ValidationError as _CoreValidationError
from app.services.ai.cte_regex import CTE_HEADER_RE as _CTE_HEADER_RE
from app.services.ai.schema_loader import get_schema_loader
from app.constants import DEFAULT_TOP_ROWS

logger = logging.getLogger(__name__)


class ValidationError(_CoreValidationError):
    """Validation SQL refusée (table inconnue, opération dangereuse, ...).

    Hérite de :class:`app.core.exceptions.ValidationError` pour qu'un
    ``except ValidationError`` (qu'il vienne du core ou de ce module) attrape
    bien les deux. Avant cette unification, deux types parallèles existaient
    et un handler attrapant l'un manquait silencieusement l'autre.
    """

    default_code = "AI_SQL_VALIDATION_ERROR"
    http_status = 400


class SecurityLevel(Enum):
    """Niveau de sécurité pour la validation."""

    STRICT = "strict"  # Bloque tout sauf SELECT sur tables whitelistées
    MODERATE = "moderate"  # Permet SELECT avec vérifications
    PERMISSIVE = "permissive"  # Permet plus d'opérations (dev only)


# Opérations SQL dangereuses à bloquer (mots complets avec \b...\b)
DANGEROUS_KEYWORDS = {
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "CREATE",
    "ALTER",
    "TRUNCATE",
    "EXEC",
    "EXECUTE",
    "GRANT",
    "REVOKE",
    "BACKUP",
    "RESTORE",
    "OPENROWSET",
    "OPENDATASOURCE",
    "WAITFOR",
    "SHUTDOWN",
}

# Préfixes dangereux (stored procedures) — match \bprefix sans \b final
# car sp_executesql, xp_cmdshell etc. ne sont pas des mots complets
DANGEROUS_PREFIXES = {"sp_", "xp_"}

# Pattern composite : "SELECT ... INTO" (les deux mots sont séparés)
DANGEROUS_PATTERNS = {
    r"\bSELECT\b.+?\bINTO\b": "SELECT INTO",
    r"\bBULK\s+INSERT\b": "BULK INSERT",
}

# Words that appear after a dot but aren't column names (SQL types, keywords)
_NOT_COLUMN_NAMES = frozenset(
    {
        "DBO",
        "VALUE",
        "VALUES",
        "NULL",
        "TRUE",
        "FALSE",
        "VARCHAR",
        "NVARCHAR",
        "CHAR",
        "NCHAR",
        "INT",
        "BIGINT",
        "SMALLINT",
        "TINYINT",
        "FLOAT",
        "REAL",
        "DECIMAL",
        "NUMERIC",
        "BIT",
        "DATE",
        "DATETIME",
        "MONEY",
        "SMALLMONEY",
        "TEXT",
        "NTEXT",
        "IMAGE",
        "UNIQUEIDENTIFIER",
        "XML",
    }
)

# Excel-like cell references: 1-2 uppercase letters + 1-4 digits
# Matches B3, C5, D10, AA1, AB2 — typical spreadsheet coordinates
_EXCEL_REF_RE = re.compile(r"\b([A-Z]{1,2}\d{1,4})\b", re.IGNORECASE)


def _strip_sql_comments(sql: str) -> str:
    """
    Strip SQL comments (line -- and block /* */) to analyze only executable code.

    Removes both line comments (--) and block comments (/* */) to prevent
    dangerous keywords hidden in comments from being missed or causing
    false positives.

    Args:
        sql: SQL query string

    Returns:
        SQL without comments, with comment regions replaced by spaces
    """
    # Remove block comments (/* ... */) — handles nested, uses DOTALL
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    # Remove line comments (-- ...\n)
    sql = re.sub(r"--[^\n]*", " ", sql)
    return sql


def check_sql_dangerous(sql: str) -> List[str]:
    """
    Vérifie la présence de mots-clés/patterns dangereux dans du SQL.

    Fonction standalone utilisable par sql_validator et training_store.
    Gère 3 types de patterns : mots complets, préfixes, et patterns composites.

    Strip les commentaires SQL avant de vérifier pour éviter les faux positifs
    (keywords dans les commentaires) et les vrais négatifs (keywords cachés
    dans les commentaires qui pourraient être exécutés).

    Returns:
        Liste des mots-clés dangereux trouvés
    """
    # Strip comments first to avoid false positives/negatives
    sql_clean = _strip_sql_comments(sql)
    sql_upper = sql_clean.upper()
    found = []

    # 1. Mots-clés complets (word boundaries des deux côtés)
    for keyword in DANGEROUS_KEYWORDS:
        pattern = r"\b" + re.escape(keyword) + r"\b"
        if re.search(pattern, sql_upper):
            found.append(keyword)

    # 2. Préfixes (sp_, xp_) — word boundary seulement au début
    for prefix in DANGEROUS_PREFIXES:
        pattern = r"\b" + re.escape(prefix.upper())
        if re.search(pattern, sql_upper):
            found.append(prefix)

    # 3. Patterns composites (SELECT INTO, BULK INSERT)
    for pattern, label in DANGEROUS_PATTERNS.items():
        if re.search(pattern, sql_upper, re.DOTALL):
            found.append(label)

    return found


# ---------------------------------------------------------------------------
# Column validation cache — loaded once from DDL in training_data (SQLite)
# ---------------------------------------------------------------------------
_columns_cache: Optional[Dict[str, Set[str]]] = None


def _load_all_columns_from_ddl() -> Dict[str, Set[str]]:
    """Load column names from all DDL records in training_data (synchronous).

    Returns a dict mapping TABLE_NAME (uppercase) → set of COLUMN_NAME (uppercase).
    Results are cached module-level (DDL doesn't change at runtime).
    """
    global _columns_cache
    if _columns_cache is not None:
        return _columns_cache

    result: Dict[str, Set[str]] = {}
    try:
        import sqlite3
        from app.config import get_config

        config = get_config()
        db_path = config.database.path

        conn = sqlite3.connect(str(db_path), timeout=5.0)
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA busy_timeout = 5000")
            cursor = conn.cursor()
            cursor.execute("""
                SELECT table_name, content
                FROM training_data
                WHERE data_type IN ('DDL', 'ddl')
                AND is_active = 1
                AND table_name IS NOT NULL
                AND content IS NOT NULL
            """)

            _DDL_SKIP = frozenset(
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
            col_pattern = re.compile(r"^\s{2,}(\w+)\s+\w+", re.MULTILINE)

            for table_name, ddl_content in cursor.fetchall():
                cols: Set[str] = set()
                for match in col_pattern.finditer(ddl_content):
                    col_name = match.group(1).upper()
                    if col_name not in _DDL_SKIP:
                        cols.add(col_name)
                if cols:
                    upper_name = table_name.upper()
                    result[upper_name] = cols
                    # Also store without dbo_ prefix (SQL uses both forms)
                    if upper_name.startswith("DBO_"):
                        result[upper_name[4:]] = cols
        finally:
            conn.close()
    except Exception as e:
        logger.debug("Failed to load DDL columns for validation: %s", e)

    _columns_cache = result
    logger.debug("Column validation cache loaded: %d tables", len(result))
    return result


def invalidate_columns_cache() -> None:
    """Invalidate the module-level columns cache (call after schema sync)."""
    global _columns_cache
    _columns_cache = None


class SQLValidator:
    """
    Validateur de requêtes SQL pour sécuriser les requêtes générées.

    Vérifie la syntaxe, bloque les opérations dangereuses, et valide
    que les tables/colonnes utilisées existent dans le schéma.
    """

    def __init__(
        self,
        security_level: SecurityLevel = SecurityLevel.STRICT,
        max_results: int = 1000,
        default_top: int = DEFAULT_TOP_ROWS,
    ):
        """
        Initialise le validateur.

        Args:
            security_level: Niveau de sécurité pour la validation
            max_results: Nombre maximum de résultats autorisés
            default_top: Valeur TOP par défaut à ajouter si absente
        """
        self.security_level = security_level
        self.max_results = max_results
        self.default_top = default_top
        self.schema_loader = get_schema_loader()

        # Construire la whitelist des tables autorisées
        # + charger les colonnes connues depuis le schema_loader (si disponibles)
        self.allowed_tables: Set[str] = set()
        self.allowed_columns: Dict[str, Set[str]] = {}
        for table_name, meta in self.schema_loader.get_tables().items():
            upper = table_name.upper()
            self.allowed_tables.add(upper)
            if upper.startswith("DBO_"):
                self.allowed_tables.add(upper[4:])

            # Extract column names if available (from YAML or mock)
            cols_raw = meta.get("columns", []) if isinstance(meta, dict) else []
            if cols_raw:
                col_set: Set[str] = set()
                for c in cols_raw:
                    if isinstance(c, dict):
                        col_set.add(c.get("name", "").upper())
                    else:
                        col_set.add(str(c).upper())
                col_set.discard("")
                if col_set:
                    self.allowed_columns[upper] = col_set
                    if upper.startswith("DBO_"):
                        self.allowed_columns[upper[4:]] = col_set

        logger.info(
            "SQLValidator initialisé: level=%s, max_results=%d, allowed_tables=%d",
            security_level.value,
            max_results,
            len(self.allowed_tables),
        )

    def parse_sql(self, sql: str) -> List[Statement]:
        """
        Parse le SQL avec sqlparse.

        Args:
            sql: Requête SQL à parser

        Returns:
            Liste de statements SQL parsés

        Raises:
            ValidationError: Si le SQL ne peut pas être parsé
        """
        if not sql or not sql.strip():
            raise ValidationError("SQL vide")

        try:
            statements = sqlparse.parse(sql)

            if not statements:
                raise ValidationError("Aucun statement SQL trouvé")

            return statements

        except (ValueError, KeyError):
            raise ValidationError("Erreur de parsing SQL")

    def extract_tables(self, statement: Statement) -> Set[str]:
        """
        Extrait les noms de tables depuis un statement SQL.

        Args:
            statement: Statement SQL parsé

        Returns:
            Ensemble des noms de tables trouvés
        """
        tables = set()

        from_seen = False
        for token in statement.tokens:
            # Chercher après FROM ou JOIN
            if token.ttype is Keyword and token.value.upper() in (
                "FROM",
                "JOIN",
                "INNER",
                "LEFT",
                "RIGHT",
                "FULL",
            ):
                from_seen = True
                continue

            if from_seen:
                if isinstance(token, Identifier):
                    # Extraire le nom de table (peut inclure schema.table)
                    table_name = token.get_real_name()
                    if table_name:
                        tables.add(table_name.upper())
                    from_seen = False

                elif isinstance(token, IdentifierList):
                    # Plusieurs tables
                    for identifier in token.get_identifiers():
                        table_name = identifier.get_real_name()
                        if table_name:
                            tables.add(table_name.upper())
                    from_seen = False

                elif token.ttype is Keyword:
                    from_seen = False

        return tables

    def extract_tables_from_sql_text(self, sql: str) -> Set[str]:
        """
        Fallback d'extraction des tables directement depuis le texte SQL.
        Gère mieux certains cas (hints, parenthèses, format non standard).
        """
        tables = set()
        pattern = re.compile(
            r"\b(?:FROM|JOIN)\s+([\[\]\w\.]+)",
            re.IGNORECASE,
        )

        for match in pattern.finditer(sql):
            raw = match.group(1) or ""
            parts = re.split(r"\]\.\[|\]\.|\.\[|\.", raw)
            table_name = parts[-1].strip("[]").upper()
            if not table_name or not re.match(r"^\w+$", table_name):
                continue
            tables.add(table_name)

        return tables

    def _extract_cte_names(self, sql: str) -> Set[str]:
        """
        Extrait les noms de CTE définis par WITH ... AS (...).
        Gère les CTE multiples séparées par des virgules, et la liste de
        colonnes optionnelle T-SQL ``WITH cte(col1, col2) AS (...)``.

        Ex:
          WITH DonneesAvecCategorie AS (...), Totaux AS (...)
          WITH COLLABS(cod) AS (SELECT cod FROM (VALUES ...))
        """
        cte_names = set()
        for match in _CTE_HEADER_RE.finditer(sql):
            cte_names.add(match.group(1).upper())
        return cte_names

    def _extract_subquery_aliases(self, sql: str) -> Set[str]:
        """
        Extrait les alias de sous-requêtes: ) AS AliasName
        """
        aliases = set()
        pattern = re.compile(r"\)\s+AS\s+(\w+)", re.IGNORECASE)
        for match in pattern.finditer(sql):
            alias = match.group(1).upper()
            # Exclure les mots-clés SQL courants
            if alias not in {
                "VARCHAR",
                "INT",
                "NVARCHAR",
                "DECIMAL",
                "NUMERIC",
                "BIT",
                "DATE",
                "DATETIME",
            }:
                aliases.add(alias)
        return aliases

    def _extract_cte_bodies_and_outer(self, sql: str) -> Tuple[Dict[str, str], str]:
        """
        Extraits les corps SQL de chaque CTE et la requête extérieure.

        Returns:
            (dict[cte_name_upper → body_sql], outer_query_sql)
        """
        bodies: Dict[str, str] = {}

        last_end = 0
        for match in _CTE_HEADER_RE.finditer(sql):
            cte_name = match.group(1).upper()
            start = match.end()  # Juste après le ( ouvrant
            depth = 1
            pos = start
            while pos < len(sql) and depth > 0:
                ch = sql[pos]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                elif ch == "'":
                    # Sauter les littéraux string (gérer les '' échappés)
                    pos += 1
                    while pos < len(sql):
                        if sql[pos] == "'" and (pos + 1 >= len(sql) or sql[pos + 1] != "'"):
                            break
                        if sql[pos] == "'":
                            pos += 1  # Sauter ''
                        pos += 1
                pos += 1

            if depth == 0:
                bodies[cte_name] = sql[start : pos - 1]
                last_end = pos

        outer = sql[last_end:].strip() if last_end > 0 else ""
        return bodies, outer

    def _find_cte_alias_leaks(self, sql: str) -> List[str]:
        """
        Détecte les alias CTE internes (FROM/JOIN dans le corps d'un CTE)
        utilisés illégalement comme qualifiants dans la requête extérieure.

        Exemple de fuite :
            WITH CTE AS (SELECT c.Name FROM Customers AS c)
            SELECT c.Name FROM CTE   -- 'c' n'est valide que dans le CTE !

        Returns:
            Liste de messages d'erreur pour chaque fuite détectée.
        """
        cte_bodies, outer_query = self._extract_cte_bodies_and_outer(sql)
        if not cte_bodies or not outer_query:
            return []

        # Alias déclarés DANS les corps de CTE
        cte_internal_aliases: Set[str] = set()
        for body in cte_bodies.values():
            body_qualifiers = self.extract_declared_qualifiers(body)
            cte_internal_aliases.update(body_qualifiers)

        # Les noms de CTE eux-mêmes sont valides dans la requête extérieure
        cte_internal_aliases -= set(cte_bodies.keys())

        if not cte_internal_aliases:
            return []

        # Alias déclarés dans la requête extérieure (FROM/JOIN de l'outer)
        outer_qualifiers = self.extract_declared_qualifiers(outer_query)
        outer_qualifiers.update(cte_bodies.keys())

        # Ne signaler que les alias PAS redéclarés dans la requête extérieure
        leaked_candidates = cte_internal_aliases - outer_qualifiers

        if not leaked_candidates:
            return []

        # Trouver lesquels sont réellement UTILISÉS dans la requête extérieure
        used_in_outer = set(
            m.group(1).upper()
            for m in re.finditer(r"\b([A-Za-z_][\w]*)\s*\.\s*[A-Za-z_][\w]*", outer_query)
        )

        leaks = sorted(leaked_candidates & used_in_outer)

        errors = []
        for alias in leaks:
            errors.append(
                f"Alias CTE interne '{alias}' utilisé hors du CTE — "
                f"les alias définis dans un CTE ne sont pas visibles à l'extérieur. "
                f"Utilisez directement le nom de colonne exposé par le CTE."
            )

        return errors

    def _check_duplicate_cte_columns(self, sql: str) -> List[str]:
        """
        Détecte les colonnes dupliquées dans le SELECT des CTE.
        SQL Server error 8156: "The column 'X' was specified multiple times for 'Y'"
        """
        errors: List[str] = []
        cte_bodies, _ = self._extract_cte_bodies_and_outer(sql)
        if not cte_bodies:
            return errors

        for cte_name, body in cte_bodies.items():
            select_match = re.search(
                r"\bSELECT\b(.*?)\bFROM\b",
                body,
                re.IGNORECASE | re.DOTALL,
            )
            if not select_match:
                continue

            select_clause = select_match.group(1)
            columns = self._split_select_columns(select_clause)

            seen: Dict[str, int] = {}
            for col_expr in columns:
                output_name = self._get_output_column_name(col_expr)
                if not output_name:
                    continue

                name_upper = output_name.upper()
                if name_upper in seen:
                    errors.append(
                        f"Colonne dupliquée '{output_name}' dans le SELECT "
                        f"du CTE '{cte_name}' (erreur SQL Server 8156)"
                    )
                else:
                    seen[name_upper] = 1

        return errors

    @staticmethod
    def _split_select_columns(select_clause: str) -> List[str]:
        """Split SELECT clause by commas, respecting parentheses and strings."""
        columns: List[str] = []
        depth = 0
        current: List[str] = []
        in_string = False

        for ch in select_clause:
            if ch == "'" and not in_string:
                in_string = True
                current.append(ch)
            elif ch == "'" and in_string:
                in_string = False
                current.append(ch)
            elif in_string:
                current.append(ch)
            elif ch == "(":
                depth += 1
                current.append(ch)
            elif ch == ")":
                depth -= 1
                current.append(ch)
            elif ch == "," and depth == 0:
                token = "".join(current).strip()
                if token:
                    columns.append(token)
                current = []
            else:
                current.append(ch)

        remaining = "".join(current).strip()
        if remaining:
            columns.append(remaining)

        return columns

    @staticmethod
    def _get_output_column_name(col_expr: str) -> str:
        """
        Extract output column name from a SELECT expression.
        "Table.Column" → "Column", "expr AS alias" → "alias", "*" → ""
        """
        expr = col_expr.strip()
        if not expr or expr == "*":
            return ""

        as_match = re.search(r"\bAS\s+\[?([A-Za-z_]\w*)\]?\s*$", expr, re.IGNORECASE)
        if as_match:
            return as_match.group(1)

        qualified_match = re.match(
            r"^(?:\[?[A-Za-z_]\w*\]?\s*\.\s*)*\[?([A-Za-z_]\w*)\]?\s*$", expr
        )
        if qualified_match:
            return qualified_match.group(1)

        return ""

    def _detect_excel_references(
        self,
        sql: str,
        cte_names: Set[str],
        subquery_aliases: Set[str],
    ) -> List[str]:
        """Detect Excel-style cell references (B3, C5, AA10) used as SQL identifiers.

        The LLM sometimes confuses spreadsheet coordinates [row, col] with SQL
        column names, generating SQL like SELECT ISNULL(B3, 0) + ISNULL(B4, 0).

        Returns:
            List of error messages (empty if no Excel refs found)
        """
        # Clean SQL: strip comments and string literals
        clean = _strip_sql_comments(sql)
        clean = re.sub(r"N?'[^']*'", "''", clean)  # neutralize string literals
        clean = clean.replace("[", "").replace("]", "")

        # Collect known identifiers to exclude
        alias_to_table = self._extract_alias_to_table_map(sql)
        declared_aliases = set(alias_to_table.keys())

        # Gather all known column names across all tables
        known_columns = dict(self.allowed_columns) if self.allowed_columns else {}
        if not known_columns:
            known_columns = _load_all_columns_from_ddl()
        all_known_cols: Set[str] = set()
        for cols in known_columns.values():
            all_known_cols.update(cols)

        excel_refs: Set[str] = set()

        for match in _EXCEL_REF_RE.finditer(clean):
            ref = match.group(1).upper()

            # Skip if preceded by a dot (qualified reference like table.B3)
            start = match.start()
            if start > 0 and clean[start - 1] == ".":
                continue

            # Skip declared table aliases, CTE names, subquery aliases
            if ref in declared_aliases or ref in cte_names or ref in subquery_aliases:
                continue

            # Skip if it's a known column in any table
            if ref in all_known_cols:
                continue

            # Skip common SQL identifiers that look like Excel refs
            # (e.g., N used in N'string' — already neutralized, but be safe)
            if ref in _NOT_COLUMN_NAMES:
                continue

            excel_refs.add(ref)

        if not excel_refs:
            return []

        refs_str = ", ".join(sorted(excel_refs))
        return [
            f"Références tableur détectées dans le SQL : {refs_str}. "
            "Ces identifiants ressemblent à des coordonnées de cellules (B3, C5, etc.), "
            "pas à des colonnes SQL. Utilise les vrais noms de colonnes de la base de données."
        ]

    def check_dangerous_keywords(self, sql: str) -> List[str]:
        """
        Vérifie la présence de mots-clés dangereux dans le SQL.

        Args:
            sql: Requête SQL

        Returns:
            Liste des mots-clés dangereux trouvés
        """
        found_dangerous = check_sql_dangerous(sql)
        return found_dangerous

    def check_select_only(self, statement: Statement) -> bool:
        """
        Vérifie que le statement est un SELECT (ou WITH ... SELECT pour les CTE).

        Args:
            statement: Statement SQL parsé

        Returns:
            True si c'est un SELECT ou WITH+SELECT, False sinon
        """
        # Obtenir le premier token significatif
        first_token = statement.token_first(skip_ws=True, skip_cm=True)

        if first_token and first_token.ttype is DML:
            return first_token.value.upper() == "SELECT"

        # Support des CTE: WITH ... AS (...) SELECT ...
        # sqlparse utilise Token.Keyword.CTE pour le mot WITH
        if first_token and first_token.value.upper() == "WITH":
            # Vérifier qu'il y a un SELECT quelque part après
            sql_text = str(statement).upper()
            return bool(re.search(r"\bSELECT\b", sql_text))

        return False

    def check_tables_exist(self, tables: Set[str]) -> Tuple[bool, List[str]]:
        """
        Vérifie que toutes les tables existent dans le schéma.

        Args:
            tables: Ensemble des noms de tables à vérifier

        Returns:
            Tuple (toutes_existent, tables_inexistantes)
        """
        unknown_tables = []

        for table in tables:
            if table not in self.allowed_tables:
                unknown_tables.append(table)

        return len(unknown_tables) == 0, unknown_tables

    @staticmethod
    def _extract_alias_to_table_map(sql: str) -> Dict[str, str]:
        """Map table aliases to real table names from FROM/JOIN clauses.

        Returns:
            Dict mapping ALIAS (uppercase) → TABLE_NAME (uppercase)
        """
        mapping: Dict[str, str] = {}
        clean = _strip_sql_comments(sql)
        pattern = re.compile(
            r"\b(?:FROM|JOIN)\s+(?:(?:\[?\w+\]?\.){0,2})\[?(\w+)\]?\s+(?:AS\s+)?\[?(\w+)\]?",
            re.IGNORECASE,
        )
        _SKIP_ALIASES = frozenset(
            {
                "ON",
                "WHERE",
                "AND",
                "OR",
                "SET",
                "AS",
                "INNER",
                "LEFT",
                "RIGHT",
                "FULL",
                "CROSS",
                "OUTER",
                "JOIN",
                "GROUP",
                "ORDER",
                "HAVING",
                "UNION",
                "EXCEPT",
                "INTERSECT",
                "WITH",
                "INTO",
                "VALUES",
            }
        )
        for match in pattern.finditer(clean):
            table = match.group(1).upper()
            alias = match.group(2).upper()
            if alias not in _SKIP_ALIASES:
                mapping[alias] = table
        return mapping

    def check_columns_exist(
        self,
        sql: str,
        tables: Set[str],
        cte_names: Set[str],
        subquery_aliases: Set[str],
    ) -> Tuple[List[str], List[str]]:
        """Validate qualified column references (alias.column) against DDL schema.

        Checks that each table.column or alias.column points to a real column
        in the table's DDL. Provides fuzzy-match suggestions for typos.

        Args:
            sql: SQL query to validate
            tables: Real table names (CTEs/subqueries already excluded)
            cte_names: CTE names defined with WITH...AS
            subquery_aliases: Subquery alias names

        Returns:
            Tuple of (errors, warnings)
        """
        errors: List[str] = []
        warnings: List[str] = []

        # Prefer schema_loader columns (from YAML/mock), fall back to DDL
        known_columns = dict(self.allowed_columns)
        if not known_columns:
            known_columns = _load_all_columns_from_ddl()
        else:
            # Supplement with DDL for tables not in schema_loader
            ddl_columns = _load_all_columns_from_ddl()
            for k, v in ddl_columns.items():
                if k not in known_columns:
                    known_columns[k] = v
        if not known_columns:
            return errors, warnings

        # Clean SQL: strip comments, string literals, and brackets
        clean_sql = _strip_sql_comments(sql)
        clean_sql = re.sub(r"'[^']*'", "''", clean_sql)  # neutralize string literals
        clean_sql = clean_sql.replace("[", "").replace("]", "")

        alias_to_table = self._extract_alias_to_table_map(sql)

        # Track invalid columns: col_name → table_name
        invalid_columns: Dict[str, str] = {}
        checked: Set[Tuple[str, str]] = set()

        for match in re.finditer(r"\b(\w+)\.(\w+)\b", clean_sql):
            qualifier = match.group(1).upper()
            col_name = match.group(2).upper()

            # Skip schema qualifiers and non-column keywords
            if qualifier in {"DBO"}:
                continue
            if col_name in _NOT_COLUMN_NAMES:
                continue

            # Skip CTE and subquery references (their columns are virtual)
            if qualifier in cte_names or qualifier in subquery_aliases:
                continue

            # Resolve alias → table name
            table_name = alias_to_table.get(qualifier, qualifier)

            # If resolved table is a CTE or subquery, skip
            if table_name in cte_names or table_name in subquery_aliases:
                continue

            # Skip if table not in loaded DDL (can't validate)
            if table_name not in known_columns:
                continue

            # Deduplicate (same table+column pair)
            key = (table_name, col_name)
            if key in checked:
                continue
            checked.add(key)

            # Validate column exists
            if col_name not in known_columns[table_name]:
                invalid_columns[col_name] = table_name

        if not invalid_columns:
            return errors, warnings

        # Fuzzy-match suggestions
        suggestions: Dict[str, str] = {}
        for bad_col, table_name in invalid_columns.items():
            table_cols = known_columns.get(table_name, set())
            if not table_cols:
                continue
            lower_to_original = {c.lower(): c for c in table_cols}
            matches = get_close_matches(
                bad_col.lower(), list(lower_to_original.keys()), n=1, cutoff=0.6
            )
            if matches:
                suggestions[bad_col] = lower_to_original[matches[0]]

        # Build error message grouped by table
        by_table: Dict[str, List[str]] = {}
        for col, tbl in invalid_columns.items():
            by_table.setdefault(tbl, []).append(col)

        parts = []
        for tbl, cols in sorted(by_table.items()):
            parts.append(f"{tbl}: {', '.join(sorted(cols))}")

        error_msg = f"Colonnes inexistantes détectées : {' | '.join(parts)}."
        if suggestions:
            sugg_parts = [f"{bad} → {good}" for bad, good in suggestions.items()]
            error_msg += f" Suggestions : {' | '.join(sugg_parts)}."

        errors.append(error_msg)
        return errors, warnings

    def extract_declared_qualifiers(self, sql: str) -> Set[str]:
        """
        Extrait les qualifiants déclarés dans FROM/JOIN (table et alias).
        """
        qualifiers = set()

        # Negative lookahead empêche le regex de CONSOMMER les mots réservés
        # comme alias implicite (sinon finditer avance au-delà et rate le JOIN suivant)
        _RESERVED_LA = (
            r"(?!(?:ON|WHERE|GROUP|ORDER|HAVING|INNER|LEFT|RIGHT"
            r"|FULL|JOIN|OUTER|CROSS|SELECT|SET|INTO|UNION"
            r"|EXCEPT|INTERSECT|FETCH|WITH)\b)"
        )
        pattern = re.compile(
            r"\b(?:FROM|JOIN)\s+([\[\]\w\.]+)" r"(?:\s+(?:AS\s+|" + _RESERVED_LA + r")(\w+))?",
            re.IGNORECASE,
        )

        for match in pattern.finditer(sql):
            raw_table = match.group(1) or ""
            parts = re.split(r"\]\.\[|\]\.|\.\[|\.", raw_table)
            table_name = parts[-1].strip("[]").upper()
            alias = match.group(2)

            if table_name and re.match(r"^\w+$", table_name):
                qualifiers.add(table_name)

            if alias:
                qualifiers.add(alias.upper())

        return qualifiers

    def find_unknown_qualifiers(self, sql: str, tables: Set[str]) -> List[str]:
        """
        Détecte les qualifiants de type table.colonne non déclarés.
        """
        declared = self.extract_declared_qualifiers(sql)
        declared.update(tables)

        # Ajouter aussi les alias de CTE internes : dans les ON(),
        # les qualifiants comme Fac01.col sont utilisés mais ne
        # correspondent pas toujours aux FROM/JOIN regex si le
        # LLM modifie légèrement la syntaxe.
        # Heuristique : tout qualifiant utilisé dans un ON(...)
        # est considéré comme déclaré (il réfère une table visible).
        on_refs = set(
            m.group(1).upper()
            for m in re.finditer(r"\bON\s*\(([^)]+)\)", sql, re.IGNORECASE)
            for m2 in [m]
            for m in re.finditer(
                r"\b([A-Za-z_][\w]*)\s*\.\s*[A-Za-z_][\w]*",
                m2.group(1),
            )
        )
        declared.update(on_refs)

        # Qualifiants utilisés dans des expressions du type qualifier.colonne
        used = set(
            match.group(1).upper()
            for match in re.finditer(r"\b([A-Za-z_][\w]*)\s*\.\s*[A-Za-z_][\w]*", sql)
        )

        known_schemas = {"DBO"}
        unknown = sorted(
            qualifier
            for qualifier in used
            if (qualifier not in declared and qualifier not in known_schemas)
        )
        return unknown

    @staticmethod
    def _insert_top_after_select(sql: str, top: int) -> str:
        """
        Insère TOP N après le premier SELECT (et après DISTINCT si présent).

        SQL Server syntax: SELECT [DISTINCT] TOP N ...
        """
        # Gère SELECT DISTINCT TOP N ... (DISTINCT doit être AVANT TOP)
        pattern = r"(\bSELECT\s+)(DISTINCT\s+)?"
        match = re.match(pattern, sql, re.IGNORECASE)
        if match:
            select_part = match.group(1)  # "SELECT "
            distinct_part = match.group(2) or ""  # "DISTINCT " ou ""
            rest = sql[match.end() :]
            return f"{select_part}{distinct_part}TOP {top} {rest}"
        return sql

    def add_top_limit(self, sql: str, top: Optional[int] = None) -> str:
        """
        Ajoute TOP si absent dans un SELECT et convertit LIMIT en TOP.

        Args:
            sql: Requête SQL
            top: Valeur TOP à ajouter (défaut: self.default_top)

        Returns:
            SQL avec TOP ajouté/converti si nécessaire
        """
        if top is None:
            top = self.default_top

        # Si TOP est déjà présent, ne rien faire
        if re.search(r"\bTOP\s+\d+\b", sql, re.IGNORECASE):
            logger.debug("TOP déjà présent, pas de modification")
            return sql

        # Si LIMIT est présent (syntaxe MySQL/PostgreSQL), le convertir en TOP
        limit_match = re.search(r"\bLIMIT\s+(\d+)\b", sql, re.IGNORECASE)
        if limit_match:
            limit_value = limit_match.group(1)
            # Supprimer LIMIT
            sql = re.sub(r"\bLIMIT\s+\d+\b", "", sql, flags=re.IGNORECASE).strip()
            # Ajouter TOP après SELECT (et DISTINCT si présent)
            # SQL Server: SELECT [DISTINCT] TOP N ...
            sql = self._insert_top_after_select(sql, int(limit_value))
            logger.info("LIMIT %s converti en TOP %s", limit_value, limit_value)
            return sql

        # Ajouter TOP après le SELECT principal
        # Pour les CTE (WITH ... AS (...) SELECT ...), il faut cibler
        # le SELECT externe, pas celui à l'intérieur de la CTE.
        if re.match(r"\s*WITH\b", sql, re.IGNORECASE):
            # Trouver le SELECT à profondeur 0 (hors parenthèses)
            depth = 0
            main_select_pos = None
            sql_upper = sql.upper()
            for i in range(len(sql)):
                if sql[i] == "(":
                    depth += 1
                elif sql[i] == ")":
                    depth -= 1
                elif depth == 0 and sql_upper[i : i + 6] == "SELECT":
                    # Vérifier que c'est bien le mot SELECT (pas un sous-mot)
                    before_ok = i == 0 or not sql[i - 1].isalnum()
                    after_ok = i + 6 >= len(sql) or not sql[i + 6].isalnum()
                    if before_ok and after_ok:
                        main_select_pos = i

            if main_select_pos is not None:
                # Utiliser _insert_top_after_select sur le SELECT principal
                rest = sql[main_select_pos:]
                modified_rest = self._insert_top_after_select(rest, top)
                modified_sql = sql[:main_select_pos] + modified_rest
                logger.info("TOP %d ajouté au SELECT principal (CTE)", top)
                return modified_sql

        # Cas standard: ajouter TOP après le premier SELECT (et DISTINCT si présent)
        modified_sql = self._insert_top_after_select(sql, top)

        if modified_sql != sql:
            logger.info("TOP %d ajouté automatiquement", top)

        return modified_sql

    def _has_invalid_aggregate_usage(self, sql: str) -> bool:
        """
        Détecte un usage invalide fréquent: agrégats avec colonnes non agrégées
        sans GROUP BY.
        """
        has_aggregate = bool(re.search(r"\b(SUM|COUNT|AVG|MIN|MAX)\s*\(", sql, re.IGNORECASE))
        has_group_by = bool(re.search(r"\bGROUP\s+BY\b", sql, re.IGNORECASE))

        if not has_aggregate or has_group_by:
            return False

        match = re.search(
            r"^\s*SELECT\s+(?:TOP\s+\d+\s+)?(.*?)\s+FROM\s",
            sql,
            re.IGNORECASE | re.DOTALL,
        )
        if not match:
            return False

        select_clause = match.group(1)
        select_items = [item.strip() for item in select_clause.split(",") if item.strip()]
        if not select_items:
            return False

        for item in select_items:
            is_aggregate = bool(re.search(r"\b(SUM|COUNT|AVG|MIN|MAX)\s*\(", item, re.IGNORECASE))
            if not is_aggregate:
                return True

        return False

    def _check_query_complexity(self, sql: str) -> List[str]:
        """Détecte les requêtes complexes et retourne des warnings non bloquants.

        Softening 2026-05-25 : ces patterns ne bloquent plus l'exécution (les
        limites 5 CTE / 4 niveaux étaient arbitraires — SQL Server supporte
        bien plus). Le caller injecte les chaînes retournées dans
        ``result["warnings"]`` à titre informatif.
        """
        warnings = []
        # Count CTE definitions
        cte_count = len(re.findall(r"\bAS\s*\(", sql, re.IGNORECASE))
        if cte_count > 5:
            warnings.append(
                f"Requête à {cte_count} CTEs : surveille la perf et la lisibilité "
                "(envisage de découper en sous-requêtes nommées si la lecture devient difficile)."
            )
        # Count nesting depth (subqueries)
        max_depth = 0
        depth = 0
        for char in sql:
            if char == "(":
                depth += 1
                max_depth = max(max_depth, depth)
            elif char == ")":
                depth -= 1
        if max_depth > 4:
            warnings.append(
                f"Requête à {max_depth} niveaux d'imbrication : surveille la lisibilité "
                "(envisage de plat l'imbrication via CTE pour faciliter le debug)."
            )
        return warnings

    def validate(
        self, sql: str, add_top: bool = False, check_tables: bool = True
    ) -> Dict[str, Any]:
        """
        Valide une requête SQL complète.

        Args:
            sql: Requête SQL à valider
            add_top: Ajouter TOP automatiquement si absent
            check_tables: Vérifier que les tables existent

        Returns:
            Dictionnaire avec résultats de validation:
                - valid: bool
                - sql: SQL modifié (avec TOP si ajouté)
                - errors: Liste des erreurs
                - warnings: Liste des avertissements
                - tables_used: Liste des tables utilisées

        Raises:
            ValidationError: Si la validation échoue en mode strict
        """
        result = {"valid": True, "sql": sql, "errors": [], "warnings": [], "tables_used": []}

        try:
            # 1. Parse le SQL
            statements = self.parse_sql(sql)

            if len(statements) > 1:
                error = "Plusieurs statements SQL détectés (seul un SELECT est autorisé)"
                result["errors"].append(error)
                result["valid"] = False

                if self.security_level == SecurityLevel.STRICT:
                    raise ValidationError(error)

            statement = statements[0]

            # 2. Vérifier que c'est un SELECT
            if not self.check_select_only(statement):
                error = "Seules les requêtes SELECT sont autorisées"
                result["errors"].append(error)
                result["valid"] = False

                if self.security_level == SecurityLevel.STRICT:
                    raise ValidationError(error)

            # 3. Vérifier les mots-clés dangereux
            dangerous = self.check_dangerous_keywords(sql)
            if dangerous:
                error = f"Mots-clés dangereux détectés: {', '.join(dangerous)}"
                result["errors"].append(error)
                result["valid"] = False

                if self.security_level == SecurityLevel.STRICT:
                    raise ValidationError(error)

            # 3a. Warnings de complexité (non bloquants depuis 2026-05-25)
            # Les limites historiques 5 CTE / 4 nesting étaient arbitraires —
            # SQL Server supporte bien plus. On garde un signal informatif.
            complexity_warnings = self._check_query_complexity(sql)
            if complexity_warnings:
                result["warnings"].extend(complexity_warnings)

            # 4. Extraire et vérifier les tables
            tables = self.extract_tables(statement)

            # Fusionner systématiquement parser + regex pour éviter les faux négatifs
            # (sqlparse peut rater certaines syntaxes JOIN/hints)
            has_from_or_join = bool(re.search(r"\b(FROM|JOIN)\b", sql, re.IGNORECASE))
            if has_from_or_join:
                tables_from_text = self.extract_tables_from_sql_text(sql)
                tables = set(tables).union(tables_from_text)

            # Exclure les noms de CTE définis par WITH ... AS (...)
            cte_names = self._extract_cte_names(sql)
            if cte_names:
                tables = tables - cte_names
                logger.debug("CTE détectées (exclues de la validation): %s", cte_names)

            # Exclure les sous-requêtes aliasées (subquery aliases)
            subquery_aliases = self._extract_subquery_aliases(sql)
            if subquery_aliases:
                tables = tables - subquery_aliases

            result["tables_used"] = list(tables)

            if check_tables:
                if has_from_or_join and not tables:
                    error = "Impossible d'extraire les tables depuis la requête SQL"
                    result["errors"].append(error)
                    result["valid"] = False
                    if self.security_level == SecurityLevel.STRICT:
                        raise ValidationError(error)

                all_exist, unknown = self.check_tables_exist(tables)

                if not all_exist:
                    # Log détaillé côté serveur (pour debug)
                    logger.warning("Tables inexistantes détectées: %s", ", ".join(unknown))
                    # Message générique pour l'utilisateur (évite l'énumération du schéma)
                    error = "La requête référence des tables non disponibles."
                    result["errors"].append(error)
                    result["valid"] = False

                    if self.security_level == SecurityLevel.STRICT:
                        raise ValidationError(error)

                # 4a. Validate column names against DDL schema
                if tables:
                    col_errors, col_warnings = self.check_columns_exist(
                        sql, tables, cte_names, subquery_aliases
                    )
                    for col_error in col_errors:
                        result["errors"].append(col_error)
                        result["valid"] = False
                        if self.security_level == SecurityLevel.STRICT:
                            raise ValidationError(col_error)
                    result["warnings"].extend(col_warnings)

                    # 4a-bis. Detect Excel-style cell references (B3, C5, etc.)
                    excel_errors = self._detect_excel_references(sql, cte_names, subquery_aliases)
                    for excel_err in excel_errors:
                        result["errors"].append(excel_err)
                        result["valid"] = False
                        if self.security_level == SecurityLevel.STRICT:
                            raise ValidationError(excel_err)

            # 3b. Vérifier un anti-pattern fréquent sur les filtres d'année absolue
            # Ex invalide métier: DATEADD(year, 2025, GETDATE())
            invalid_year_dateadd = re.search(
                r"DATEADD\s*\(\s*year\s*,\s*(19|20)\d{2}\s*,\s*GETDATE\s*\(\s*\)\s*\)",
                sql,
                re.IGNORECASE,
            )
            if invalid_year_dateadd:
                error = (
                    "Filtre année invalide: n'utilisez pas DATEADD(year, YYYY, GETDATE()). "
                    "Utilisez YEAR(date_col)=YYYY ou un intervalle de dates."
                )
                result["errors"].append(error)
                result["valid"] = False

                if self.security_level == SecurityLevel.STRICT:
                    raise ValidationError(error)

            # 3c. Détecter agrégats sans GROUP BY (cas fréquent du LLM)
            if self._has_invalid_aggregate_usage(sql):
                error = (
                    "Agrégation invalide: présence d'agrégats avec colonnes non agrégées "
                    "sans GROUP BY."
                )
                result["errors"].append(error)
                result["valid"] = False

                if self.security_level == SecurityLevel.STRICT:
                    raise ValidationError(error)

            # 4b. Vérifier les qualifiants table.colonne non déclarés
            if check_tables:
                unknown_qualifiers = self.find_unknown_qualifiers(sql, tables)
                if unknown_qualifiers:
                    error = f"Qualifiants de table inconnus: {', '.join(unknown_qualifiers)}"
                    result["errors"].append(error)
                    result["valid"] = False

                    if self.security_level == SecurityLevel.STRICT:
                        raise ValidationError(error)

            # 4c. Détecter les alias CTE internes utilisés dans la requête extérieure
            if cte_names:
                cte_leak_errors = self._find_cte_alias_leaks(sql)
                for leak_error in cte_leak_errors:
                    result["errors"].append(leak_error)
                    result["valid"] = False

            # 4c-bis. Détecter les colonnes dupliquées dans le SELECT des CTE
            if cte_names:
                dup_errors = self._check_duplicate_cte_columns(sql)
                for dup_err in dup_errors:
                    result["errors"].append(dup_err)
                    result["valid"] = False

            # 4d. Corriger l'ordre TOP/DISTINCT (SQL Server exige DISTINCT avant TOP)
            # Le LLM génère souvent "SELECT TOP N DISTINCT ..." au lieu de "SELECT DISTINCT TOP N ..."
            top_distinct_fix = re.search(
                r"\bSELECT\s+(TOP\s+\d+)\s+(DISTINCT)\b", sql, re.IGNORECASE
            )
            if top_distinct_fix:
                old_fragment = top_distinct_fix.group(0)
                top_part = top_distinct_fix.group(1)
                distinct_part = top_distinct_fix.group(2)
                new_fragment = f"SELECT {distinct_part} {top_part}"
                sql = sql[: top_distinct_fix.start()] + new_fragment + sql[top_distinct_fix.end() :]
                result["sql"] = sql
                logger.info("Correction syntaxe: '%s' → '%s'", old_fragment, new_fragment)

            # 5. Ajouter TOP si nécessaire
            if add_top and result["valid"]:
                result["sql"] = self.add_top_limit(sql)
                result["corrected_sql"] = result["sql"]  # Alias pour VannaEnhancedGenerator

            # 6. Vérifier la taille du TOP
            top_match = re.search(r"\bTOP\s+(\d+)\b", result["sql"], re.IGNORECASE)
            if top_match:
                top_value = int(top_match.group(1))
                if top_value > self.max_results:
                    warning = f"TOP {top_value} dépasse la limite ({self.max_results})"
                    result["warnings"].append(warning)
                    logger.warning(warning)

            if result["valid"]:
                logger.info(
                    "✓ SQL validé: %d tables, %d warnings",
                    len(result["tables_used"]),
                    len(result["warnings"]),
                )
            else:
                logger.warning("✗ SQL invalide: %d erreurs", len(result["errors"]))

            return result

        except ValidationError:
            raise
        except (ValueError, KeyError):
            error = "Erreur lors de la validation SQL"
            logger.error(error, exc_info=True)
            result["errors"].append(error)
            result["valid"] = False

            if self.security_level == SecurityLevel.STRICT:
                raise ValidationError(error)

            return result

    def validate_and_fix(self, sql: str, check_tables: bool = True) -> str:
        """
        Valide le SQL et retourne la version corrigée (avec TOP ajouté).

        Args:
            sql: Requête SQL à valider
            check_tables: Si True, vérifie que les tables existent dans allowed_tables (défaut: True)

        Returns:
            SQL validé et corrigé

        Raises:
            ValidationError: Si la validation échoue
        """
        result = self.validate(sql, add_top=True, check_tables=check_tables)

        if not result["valid"]:
            errors_str = "; ".join(result["errors"])
            raise ValidationError(f"SQL invalide: {errors_str}")

        return result["sql"]

    def validate_batch(self, sql_list: list[str], check_tables: bool = True) -> list[dict]:
        """
        Valide plusieurs candidats SQL en batch.

        Utile pour le système multi-candidats (consensus voting) :
        valide les 3 candidats et marque lesquels passent.

        Args:
            sql_list: Liste de requêtes SQL à valider
            check_tables: Vérifier les tables

        Returns:
            Liste de résultats de validation (même format que validate())
        """
        results = []
        for sql in sql_list:
            try:
                result = self.validate(sql, add_top=False, check_tables=check_tables)
                results.append(result)
            except ValidationError as e:
                results.append(
                    {
                        "valid": False,
                        "sql": sql,
                        "errors": [str(e)],
                        "warnings": [],
                        "tables_used": [],
                    }
                )
        return results


# ===========================================================================
# Doctrine « 100 % justifié » (2026-05-26) — Single Source of Truth pour Iris
# ===========================================================================
#
# Avant : 4 sources de vérité distinctes pour valider une SQL Iris
#   1. agent_tools._enforce_sql_guards  (read_only / system_table / placeholder)
#   2. agent_tools._validate_sql_columns (parser maison → BUG MINUTE/HOUR…)
#   3. orchestrator_tools.execute_count guards (write blocking dupliqué)
#   4. sql_validator.SQLValidator.validate (validator OO complet)
#
# Conséquence : asymétries entre `test_sql`, `execute_sql`, `run_pipeline`
#   (defensible blame exit pour Iris → « le système se trompe »).
#
# Après : `validate_for_iris(sql, user, connector)` est l'UNIQUE point d'entrée
#   pour la validation côté tools Iris. Chaque blocage retourne un `Proof`
#   structuré (rule_id, evidence, sql_server_says, suggested_fix) qu'Iris peut
#   inspecter et vérifier. Plus de message opaque type « server_guard ».
#
# Oracle de vérité = SQL Server lui-même via `SET PARSEONLY ON` (syntaxe) et
#   `SET FMTONLY ON` (binding tables/colonnes, zero I/O). Plus de liste fermée
#   de keywords T-SQL maintenue à la main → bug `DATEDIFF(MINUTE, ...)` éliminé
#   par construction.

import dataclasses
import hashlib
from dataclasses import dataclass, field
from typing import Any as _Any  # éviter conflit avec autres imports

# Pattern unique pour les opérations d'écriture (anciennement dans agent_tools
# `_WRITE_PATTERN` ET dans orchestrator_tools `_BLOCKED`). Single source.
_VALIDATOR_WRITE_PATTERN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|EXEC|EXECUTE|"
    r"MERGE|BACKUP|RESTORE|GRANT|REVOKE|SHUTDOWN|WAITFOR)\b",
    re.IGNORECASE,
)

# Pattern pour bloquer SELECT direct sur tables système (info leakage RLS).
_VALIDATOR_SYSTEM_TABLE_PATTERN = re.compile(
    r"\bFROM\s+\[?(?:INFORMATION_SCHEMA|sys)\b",
    re.IGNORECASE,
)

# Tokens anonymisés non quotés (anti-injection + garantie substitution PII).
# **SINGLE SOURCE OF TRUTH (T16-M4/M9, 2026-05-26)** — Si une nouvelle
# catégorie PII est ajoutée à l'anonymizer (ex: NUMERO_SECU_N), elle DOIT
# être ajoutée ICI et nulle part ailleurs. Les anciens patterns redondants
# dans agent_tools.py (`_PLACEHOLDER_PATTERN` + `_UNQUOTED_PLACEHOLDER_PATTERN`)
# ont été supprimés.
#
# Couvre :
#   - tokens `~xxx` (pseudonymizer runtime, format §...§ legacy ou ~ABC)
#   - catalogue PII `[<TYPE>_<N>]` (NOM, PRENOM, SOCIETE, VALEUR, ADRESSE,
#     SIRET, SIREN, TEL, EMAIL, DATE)
_VALIDATOR_UNQUOTED_PLACEHOLDER_PATTERN = re.compile(
    r"(?<!['\"])(?<!\w)~[A-Za-z0-9_.]{2,}(?!\w)"
    r"|(?<!['\"])\[(?:NOM|PRENOM|SOCIETE|VALEUR|ADRESSE|SIRET|SIREN|TEL|EMAIL|DATE)_\d+\](?!['\"])",
)


@dataclass(frozen=True)
class Proof:
    """Preuve formelle d'un blocage retournée à Iris.

    Iris peut INSPECTER la preuve (rule_id, evidence, sql_server_says) au lieu
    d'inférer la raison d'un message générique. Si elle estime que la preuve
    est fausse, elle peut le contester explicitement (future appeal_verdict)
    plutôt que choisir silencieusement un tool alternatif.
    """

    rule_id: str  # ex: "READ_ONLY_DB", "SYNTAX_INVALID", "ACCESS_DENIED"
    rule_doc: str  # description humaine 1-3 phrases
    evidence: Dict[str, Any]  # éléments factuels (token, position, identifier...)
    sql_hash: str  # sha256(sql)[:8] pour traçabilité
    sql_server_says: Optional[str] = None  # message brut SQL Server (verbatim, jamais normalisé)
    suggested_fix: Optional[str] = None  # action concrète proposée à Iris
    provenance: Optional[List[Dict[str, Any]]] = None  # arbre des transformations système

    def to_human_message(self) -> str:
        """Message FR concaténé (compat avec ancien format `error` string)."""
        parts: List[str] = [self.rule_doc]
        if self.sql_server_says:
            parts.append(f"SQL Server : {self.sql_server_says}")
        if self.suggested_fix:
            parts.append(f"Suggestion : {self.suggested_fix}")
        return "\n".join(parts)

    def to_tool_result(self) -> Dict[str, Any]:
        """Format JSON pour Iris.

        Compat ascendante : conserve `success=False`, `blocked_by=<rule_id>`,
        `error=<human_message>`, `suggestions` (ces 4 clés étaient déjà
        attendues par les call sites legacy). Nouveau : ajoute la clé `proof`
        avec la structure complète.

        **T16-C3 (2026-05-26)** — La clé legacy `suggestions: list[str]` a été
        ré-ajoutée pour préserver la compat avec `copilot_iris_bridge.py:311`
        qui faisait `validation_err.get("suggestions")` pour alimenter
        `result["schema_suggestions"]`. Sans cette clé, le copilot recevait
        `None` silencieusement et la feature « suggestions schéma » était
        amputée. La liste contient `suggested_fix` si présent, sinon vide.
        """
        return {
            "success": False,
            "blocked_by": self.rule_id,
            "error": self.to_human_message(),
            # Compat legacy : copilot_iris_bridge + tests existants lisent `suggestions`
            "suggestions": [self.suggested_fix] if self.suggested_fix else [],
            "proof": {
                "rule_id": self.rule_id,
                "rule_doc": self.rule_doc,
                "evidence": self.evidence,
                "sql_hash": self.sql_hash,
                "sql_server_says": self.sql_server_says,
                "suggested_fix": self.suggested_fix,
                "provenance": self.provenance,
            },
            "columns": [],
            "row_count": 0,
            "execution_time_ms": 0,
        }


@dataclass(frozen=True)
class Verdict:
    """Résultat d'une validation : passes (bool) + proof (si rejeté)."""

    passes: bool
    proof: Optional[Proof] = None  # toujours présent si passes=False
    sql_used: Optional[str] = None  # SQL après transformations RLS (si différent)
    provenance: Optional[List[Dict[str, Any]]] = None  # arbre transformations


def _compute_sql_hash(sql: str) -> str:
    """sha256(sql)[:8] — identifiant court mais collision-safe pour traçabilité."""
    return hashlib.sha256(sql.encode("utf-8", errors="replace")).hexdigest()[:8]


def _provenance_entry(step: str, **kwargs: Any) -> Dict[str, Any]:
    """Helper pour construire une entrée de provenance trail."""
    entry: Dict[str, Any] = {"step": step}
    entry.update(kwargs)
    return entry


def _strip_sql_for_guard_check(sql: str) -> str:
    """Neutralise commentaires + string literals pour les guards déterministes.

    **T16-C2 (2026-05-26)** — Sans ce strip, `SELECT * FROM Factures
    /* INSERT comment */ WHERE 1=1` était rejeté à tort comme DML car le
    `_VALIDATOR_WRITE_PATTERN` matchait `INSERT` dans le commentaire. Idem
    pour `WHERE notes = 'INSERT a fait planter le système'`.

    Stratégie défensive :
    1. Strip block comments `/* ... */` (DOTALL)
    2. Strip line comments `-- ...`
    3. Neutralise string literals `'...'` → `''` (sans toucher au content)

    Le SQL retourné est UNIQUEMENT pour la vérification regex des guards —
    le SQL original (avec commentaires + strings) reste celui passé à
    l'oracle SQL Server et à l'exécution.
    """
    # Order matters : strip block comments first (DOTALL match)
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    sql = re.sub(r"--[^\n]*", " ", sql)
    # Neutralise string literals — match non-greedy entre 2 apostrophes.
    # Note : ne gère pas parfaitement les `''` escaped (chaînes type 'l''ami')
    # mais c'est un strip défensif, pas une parse SQL complète. Le pire cas :
    # un mot DML resterait visible dans une chaîne complexe → faux POSITIF
    # (bloqué à tort), résolu par Iris qui voit l'evidence et corrige.
    sql = re.sub(r"'[^']*'", "''", sql)
    return sql


def _check_deterministic_guards(
    sql: str,
    sql_hash: str,
    provenance: List[Dict[str, Any]],
) -> Verdict:
    """Phase 1 du validator unique : gardes 100% déterministes.

    Aucune heuristique. Aucun appel LLM. Tous les rejets sont basés sur des
    regex/AST → reproductibles par Iris qui peut vérifier la preuve.

    **T16-C2 (2026-05-26)** : les regex de guards opèrent sur le SQL avec
    commentaires + string literals neutralisés (via `_strip_sql_for_guard_check`)
    pour éviter les faux positifs sur `SELECT * FROM x /* INSERT */`. Le SQL
    original reste celui passé à l'oracle et à l'exécution.

    Args:
        sql: requête utilisateur (après normalisation)
        sql_hash: hash pré-calculé pour traçabilité
        provenance: liste accumulée (mutée en place pour ajout d'entrées)

    Returns:
        Verdict(passes=True) si toutes les gardes passent, ou Verdict avec
        Proof structuré indiquant la première garde violée.
    """
    # Strip commentaires + string literals pour la vérification regex SEULEMENT.
    # Le `sql` paramètre (avec contenu intact) reste utilisé pour les Proof
    # evidence (positions) et pour l'oracle SQL Server.
    sql_for_check = _strip_sql_for_guard_check(sql)

    # ── Garde 1 : DB read-only (DML interdit) ─────────────────────────────
    write_match = _VALIDATOR_WRITE_PATTERN.search(sql_for_check)
    if write_match:
        provenance.append(
            _provenance_entry(
                "guard_read_only",
                matched_keyword=write_match.group().upper(),
                position=write_match.start(),
            )
        )
        return Verdict(
            passes=False,
            proof=Proof(
                rule_id="READ_ONLY_DB",
                rule_doc=(
                    "La base de données source est en LECTURE SEULE par configuration "
                    "administrative (DatabaseConnection). Seules les requêtes SELECT "
                    "sont autorisées."
                ),
                evidence={
                    "matched_keyword": write_match.group().upper(),
                    "position": write_match.start(),
                },
                sql_hash=sql_hash,
                suggested_fix=(
                    "Reformule la requête en SELECT uniquement. Aucune modification "
                    "de la base source n'est possible depuis Komptia."
                ),
                provenance=list(provenance),
            ),
            provenance=provenance,
        )

    # ── Garde 2 : tables système (anti information leakage RLS) ────────────
    system_match = _VALIDATOR_SYSTEM_TABLE_PATTERN.search(sql_for_check)
    if system_match:
        provenance.append(
            _provenance_entry(
                "guard_system_table",
                matched=system_match.group(),
                position=system_match.start(),
            )
        )
        return Verdict(
            passes=False,
            proof=Proof(
                rule_id="USE_DEDICATED_TOOL",
                rule_doc=(
                    "Accès direct à INFORMATION_SCHEMA / sys.* bloqué : ces tables "
                    "exposent le schéma complet (bypass du mode invisible RLS) et "
                    "peuvent diverger du cache local. Tools dédiés disponibles."
                ),
                evidence={
                    "matched_pattern": system_match.group(),
                    "position": system_match.start(),
                },
                sql_hash=sql_hash,
                suggested_fix=(
                    "Utilise les tools dédiés :\n"
                    "  - inspect_table('NomTable') → colonnes, types, FK\n"
                    "  - search_schema → trouver une table/colonne par mots-clés\n"
                    "  - get_database_schema → liste complète des tables visibles"
                ),
                provenance=list(provenance),
            ),
            provenance=provenance,
        )

    # ── Garde 3 : tokens anonymisés non quotés (anti SQL injection) ────────
    # NOTE T16-C2 : `unquoted` opère sur `sql` ORIGINAL (pas `sql_for_check`)
    # car les tokens `~XXX` non quotés DOIVENT être détectés MÊME s'ils sont
    # dans une chaîne tronquée par le strip. Le sens même de ce guard est de
    # protéger contre des tokens dans des positions inattendues. Le strip
    # neutraliserait `'~XXX'` (quoted, donc OK) → faux négatif acceptable
    # (le système suppose qu'une chaîne quotée n'a pas besoin de pseudo).
    unquoted_matches = _VALIDATOR_UNQUOTED_PLACEHOLDER_PATTERN.findall(sql)
    if unquoted_matches:
        unique_tokens = sorted(set(unquoted_matches))[:10]
        provenance.append(
            _provenance_entry("guard_unquoted_placeholder", count=len(unique_tokens))
        )
        return Verdict(
            passes=False,
            proof=Proof(
                rule_id="TOKEN_INJECTION_RISK",
                rule_doc=(
                    "Tokens anonymisés (~XXX ou [EMAIL_X]) détectés sans guillemets "
                    "simples. Le quotage est obligatoire pour empêcher l'injection SQL "
                    "et garantir la substitution côté pseudonymizer."
                ),
                evidence={"unquoted_tokens": unique_tokens},
                sql_hash=sql_hash,
                suggested_fix=(
                    "Correct  : WHERE col = '~DPNT' (avec quotes)\n"
                    "Incorrect: WHERE col = ~DPNT (sans quotes — bloqué)"
                ),
                provenance=list(provenance),
            ),
            provenance=provenance,
        )

    return Verdict(passes=True)


async def validate_sql_via_sqlserver(sql: str, connector: Any) -> Verdict:
    """Oracle de vérité : SQL Server lui-même valide la syntaxe + binding.

    `SET PARSEONLY ON` : vérifie la syntaxe via le parser officiel SQL Server
        (zero I/O, ~5-30ms). Couvre TOUTE la grammaire T-SQL — pas de liste
        fermée de keywords à maintenir. C'est l'oracle ultime.

    `SET FMTONLY ON` : exécute la requête en mode dry-run (zero rows) pour
        vérifier que toutes les tables/colonnes existent et sont accessibles
        avec les droits courants. Coût négligeable (compile uniquement).

    Cette fonction REMPLACE le validator maison `_validate_sql_columns`
    (agent_tools.py) qui avait une liste fermée `sql_keywords` oubliant
    MINUTE/HOUR/SECOND/MILLISECOND → bug `DATEDIFF(MINUTE, ...)` du log user.

    Args:
        sql: SQL à valider (déjà normalisée et passée par les guards déterministes)
        connector: SageConnector avec méthode `execute(sql)` async

    Returns:
        Verdict(passes=True) si SQL Server accepte syntaxe ET binding.
        Verdict avec Proof.sql_server_says (message brut) sinon.
    """
    # T16-M8 (D1-F3) : on doit distinguer une erreur de SYNTAXE/binding (verdict
    # actionnable par Iris) d'une INDISPONIBILITÉ de l'oracle (Sage injoignable).
    # ``SageConnectionError`` est RE-RAISE pour que le caller applique le fail-open
    # transitoire documenté (cf. ``validate_for_iris`` docstring + les 3 call-sites
    # d'``agent_tools`` qui le catchent) — sinon on retournait un faux
    # « SYNTAX_INVALID » trompeur (« corrige tes datepart keywords ») alors que la
    # syntaxe est parfaite et que c'est juste la BDD qui est down.
    # Source canonique de l'exception (même classe que celle catchée par les
    # call-sites d'agent_tools) ; import paresseux pour éviter tout cycle.
    from app.core.exceptions import SageConnectionError

    sql_hash = _compute_sql_hash(sql)

    # Phase 1 : PARSEONLY — vérifier la syntaxe via parser officiel
    parseonly_sql = f"SET PARSEONLY ON;\n{sql};\nSET PARSEONLY OFF;"
    try:
        await connector.execute(parseonly_sql)
    except SageConnectionError:
        raise  # oracle injoignable → fail-open transitoire côté caller
    except Exception as exc:  # noqa: BLE001 — capture toute exception ODBC/pyodbc
        return Verdict(
            passes=False,
            proof=Proof(
                rule_id="SYNTAX_INVALID",
                rule_doc=(
                    "Le parser officiel SQL Server a rejeté la syntaxe via "
                    "SET PARSEONLY ON. C'est l'oracle ultime — si SQL Server "
                    "dit que la syntaxe est invalide, elle l'est. Aucune liste "
                    "de keywords maintenue manuellement n'intervient."
                ),
                evidence={"phase": "PARSEONLY", "exception_class": type(exc).__name__},
                sql_hash=sql_hash,
                sql_server_says=str(exc)[:1000],
                suggested_fix=(
                    "Lis le message SQL Server (`sql_server_says`) — il indique "
                    "la ligne, la position et le token en erreur. Corrige la syntaxe. "
                    "Note : les datepart keywords (YEAR, MONTH, DAY, HOUR, MINUTE, "
                    "SECOND, MILLISECOND, WEEK, QUARTER...) sont des arguments des "
                    "fonctions DATEDIFF/DATEADD/DATEPART/DATENAME — pas des colonnes."
                ),
            ),
        )

    # Phase 2 : FMTONLY — vérifier le binding tables/colonnes (zero rows)
    fmtonly_sql = f"SET FMTONLY ON;\n{sql};\nSET FMTONLY OFF;"
    try:
        await connector.execute(fmtonly_sql)
    except SageConnectionError:
        raise  # oracle injoignable (idem PARSEONLY) → fail-open transitoire
    except Exception as exc:  # noqa: BLE001
        return Verdict(
            passes=False,
            proof=Proof(
                rule_id="IDENTIFIER_UNKNOWN",
                rule_doc=(
                    "SQL Server n'a pas trouvé une table ou une colonne référencée "
                    "(vérifié via SET FMTONLY ON, zero I/O). L'identifier n'existe "
                    "pas dans le schéma BDD ou n'est pas accessible avec les droits "
                    "courants (RLS)."
                ),
                evidence={"phase": "FMTONLY", "exception_class": type(exc).__name__},
                sql_hash=sql_hash,
                sql_server_says=str(exc)[:1000],
                suggested_fix=(
                    "Vérifie le nom exact avec :\n"
                    "  - inspect_table('NomTable') → colonnes (casse, orthographe)\n"
                    "  - search_schema('terme') → trouver une table/colonne similaire\n"
                    "Si l'erreur mentionne une colonne qui semble exister, elle est "
                    "peut-être cachée par les règles d'accès (data-privacy)."
                ),
            ),
        )

    return Verdict(passes=True, sql_used=sql)


async def validate_for_iris(
    sql: str,
    user: Any,
    connector: Any,
    *,
    skip_oracle: bool = False,
) -> Verdict:
    """**Single Source of Truth** : valider une SQL générée par Iris.

    Combine en un seul point d'entrée :
      1. Gardes déterministes (read_only, system_table, unquoted_placeholder)
      2. RLS via `data_access_enforcer.enforce_sql`
      3. Oracle SQL Server via PARSEONLY + FMTONLY (sauf `skip_oracle=True`)

    Tous les tools Iris (`_handle_test_sql`, `_handle_execute_sql`,
    `_handle_run_pipeline`, `copilot_iris_bridge.ask_iris`, `execute_count`)
    DOIVENT appeler cette fonction et uniquement celle-ci. Cela rend
    l'asymétrie entre tools **impossible par construction** (un seul code path).

    Args:
        sql: requête à valider
        user: utilisateur authentifié (pour RLS). `None` ou `SYSTEM_USER` bypass.
        connector: SageConnector (avec méthode `execute(sql)` async)
        skip_oracle: si True, ne fait pas PARSEONLY/FMTONLY (utilisé par les
            call-sites qui ont déjà validé via un autre chemin, ou en tests).

    Returns:
        Verdict avec :
          - `passes=True` + `sql_used` (SQL après transformations RLS éventuelles)
          - `passes=False` + `proof` (Proof structuré inspectable par Iris)
        Toujours `provenance` (arbre des transformations appliquées).

    **Fail-open transitoire (T16-M8 doc, 2026-05-26)** : si l'oracle SQL Server
    est temporairement inaccessible (`SageConnectionError`), le caller (wrapper
    `_validate_sql_columns` / `_handle_execute_sql` / `_handle_test_sql`) DOIT
    catcher l'exception et faire passer la query (laissant l'exécution réelle
    reporter l'erreur réseau à l'utilisateur via son canal normal).

    **CRITIQUE** : ce fail-open ne s'applique QU'À l'oracle (Phase 3). Les guards
    déterministes (Phase 1 : read_only, system_table, unquoted_placeholder)
    et le RLS (Phase 2) sont exécutés AVANT l'oracle et restent actifs même
    en cas de Sage down. Voir `test_M8_deterministic_guards_active_even_when_sage_down`.
    """
    sql_hash = _compute_sql_hash(sql)
    provenance: List[Dict[str, Any]] = [
        _provenance_entry(
            "user_input",
            sql_hash=sql_hash,
            sql_len=len(sql),
        )
    ]

    # ── Phase 0 : Normalisation syntaxique T-SQL ────────────────────────────
    # **T16-C1 (2026-05-26)** — Déplacé depuis `_handle_execute_sql` pour
    # éliminer l'asymétrie avec `_handle_test_sql` (qui ne normalisait pas →
    # `SELECT * FROM x LIMIT 10` était rejeté par PARSEONLY côté test_sql
    # mais réécrit en TOP 10 côté execute_sql). Maintenant les 2 tools
    # héritent automatiquement de la même normalisation.
    #
    # Lazy import : `_normalize_sql_syntax` vit dans `agent_tools.py` pour
    # raisons historiques. Cycle évité car l'import se fait à l'exécution
    # de la fonction, pas au module load time.
    try:
        from app.services.ai.agent_tools import _normalize_sql_syntax

        sql, _normalizations = _normalize_sql_syntax(sql)
        if _normalizations:
            provenance.append(
                _provenance_entry(
                    "normalize_sql_syntax",
                    transformations=_normalizations,
                )
            )
            # Recompute hash car le SQL a changé (les guards / oracle voient le SQL normalisé)
            sql_hash = _compute_sql_hash(sql)
    except Exception as _norm_exc:  # noqa: BLE001 — fail-open sur normalisation
        # Sans normalisation, certaines syntaxes MySQL/Postgres (LIMIT)
        # seront rejetées par PARSEONLY. C'est OK : Iris reçoit alors un
        # SYNTAX_INVALID actionnable.
        logger.debug(
            "_normalize_sql_syntax failed (skipping): %s", _norm_exc
        )

    # ── Phase 1 : Gardes déterministes ─────────────────────────────────────
    guard_verdict = _check_deterministic_guards(sql, sql_hash, provenance)
    if not guard_verdict.passes:
        return guard_verdict

    # ── Phase 2 : RLS (data_access enforcer) ──────────────────────────────
    try:
        from app.services.data_access import enforcer as data_access_enforcer

        sql_after_rls, rls_decision = await data_access_enforcer.enforce_sql(sql, user)
        provenance.append(
            _provenance_entry(
                "rls_enforce",
                denied=rls_decision.is_denied,
                sql_modified=(sql != sql_after_rls),
            )
        )
        if rls_decision.is_denied:
            return Verdict(
                passes=False,
                proof=Proof(
                    rule_id="ACCESS_DENIED",
                    rule_doc=(
                        "Les règles de Row-Level Security (RLS) configurées par "
                        "l'administrateur refusent l'accès à cette donnée pour "
                        "l'utilisateur courant."
                    ),
                    evidence={
                        "blocking_table": rls_decision.blocking_table,
                        "blocking_column": rls_decision.blocking_column,
                        "reason": rls_decision.reason,
                    },
                    sql_hash=sql_hash,
                    suggested_fix=rls_decision.user_message,
                    provenance=list(provenance),
                ),
                provenance=provenance,
            )
        sql = sql_after_rls
    except Exception as exc:  # noqa: BLE001
        # Fail-closed : si l'enforcer crash on refuse plutôt que leak.
        logger.error(
            "data_access enforcer crashed (BLOCKING for safety): %s",
            exc,
            exc_info=True,
        )
        provenance.append(
            _provenance_entry(
                "rls_enforcer_crashed",
                exception_class=type(exc).__name__,
            )
        )
        return Verdict(
            passes=False,
            proof=Proof(
                rule_id="ACCESS_CHECK_FAILED",
                rule_doc=(
                    "Le module data_access (RLS) a levé une exception non gérée. "
                    "Par sécurité, la requête est bloquée (fail-closed) pour éviter "
                    "tout risque de fuite de données."
                ),
                evidence={"exception_class": type(exc).__name__},
                sql_hash=sql_hash,
                sql_server_says=str(exc)[:500],
                suggested_fix=(
                    "Ce blocage indique un bug interne du module data_access. "
                    "Signale-le à l'administrateur via le bouton Signaler — c'est "
                    "à investiguer côté code, pas en reformulant ta requête."
                ),
                provenance=list(provenance),
            ),
            provenance=provenance,
        )

    # ── Phase 3 : Oracle SQL Server (PARSEONLY + FMTONLY) ─────────────────
    if not skip_oracle:
        oracle_verdict = await validate_sql_via_sqlserver(sql, connector)
        provenance.append(
            _provenance_entry(
                "sql_server_oracle",
                passes=oracle_verdict.passes,
                rule_id=oracle_verdict.proof.rule_id if oracle_verdict.proof else None,
            )
        )
        if not oracle_verdict.passes:
            assert oracle_verdict.proof is not None
            return Verdict(
                passes=False,
                proof=dataclasses.replace(
                    oracle_verdict.proof,
                    provenance=list(provenance),
                ),
                provenance=provenance,
            )

    return Verdict(passes=True, sql_used=sql, provenance=provenance)
