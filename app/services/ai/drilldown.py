"""
Drill-down service for SQL query results.

Analyzes SQL queries to determine which columns are drillable (aggregates, window functions,
or columns sourced from aggregated CTEs), and builds drill-down queries that show the
underlying detail rows.

Uses sqlglot for robust T-SQL parsing (handles CTEs, JOINs, subqueries, window functions).

Supports two modes:
1. GROUP BY drill-down: outer SELECT has GROUP BY → filter by PARTITION BY / GROUP BY dims
2. CTE drill-down: outer SELECT has no GROUP BY but columns come from aggregated CTEs
   → drill into the source CTE, removing its GROUP BY
"""

import logging
from typing import Any

import sqlglot
from sqlglot import exp

logger = logging.getLogger(__name__)


def analyze_columns(sql: str) -> list[dict]:
    """Analyze a SQL query and return metadata for each SELECT column.

    For each column:
    - name: column name or alias
    - is_drillable: True if drill-down would produce useful results
    - filter_dimensions: column names to use as drill-down WHERE filters
    - type: 'window', 'aggregate', 'column', 'cte_aggregate', 'cte_column', 'computed'
    - source_cte: name of the CTE this column comes from (if applicable)
    """
    try:
        parsed = sqlglot.parse_one(sql, dialect="tsql")
    except Exception as e:
        logger.warning(f"[drilldown] Failed to parse SQL: {e}")
        return []

    select = _find_outer_select(parsed)
    if select is None:
        return []

    group_by_cols = _extract_group_by_columns(select)

    # If outer SELECT has GROUP BY → standard mode (window/aggregate analysis)
    if group_by_cols:
        # Map GROUP BY expressions to their SELECT aliases
        # Handles expressions like YEAR(facDate) → annee, MONTH(facDate) → mois
        gb_aliases = _map_group_by_to_select_aliases(select)
        expr_to_alias = _build_expr_to_alias_map(select)
        result = []
        for expr in select.expressions:
            col_info = _analyze_select_expression(expr, gb_aliases, expr_to_alias)
            result.append(col_info)
        return result

    # No GROUP BY in outer SELECT → CTE mode
    # Map table aliases to CTE names, and analyze which CTEs have GROUP BY
    cte_map = _build_cte_map(parsed)  # {alias: cte_name}
    cte_info = _analyze_ctes(parsed)  # {cte_name: {group_by: [...], has_aggregates: bool}}
    join_keys = _extract_join_keys(select)  # {alias: column_name} — the join key per table alias

    result = []
    for expr in select.expressions:
        col_info = _analyze_cte_column(expr, cte_map, cte_info, join_keys)
        result.append(col_info)
    return result


def build_drilldown_query(
    original_sql: str,
    col_index: int,
    row_values: dict[str, Any],
    column_metadata: list[dict] | None = None,
) -> str | list[dict] | None:
    """Build drill-down query(ies) for a clicked cell.

    Returns:
        - str: a single SQL query
        - list[dict]: multiple queries for multi-CTE drill-down
          Each dict: {"sql": str, "label": str, "cte_name": str}
        - None: not drillable (no meaningful drill-down possible)
    """
    try:
        parsed = sqlglot.parse_one(original_sql, dialect="tsql")
    except Exception as e:
        logger.error(f"[drilldown] Failed to parse SQL: {e}")
        return original_sql

    select = _find_outer_select(parsed)
    if select is None:
        return original_sql

    if column_metadata is None:
        column_metadata = analyze_columns(original_sql)

    if col_index < 0 or col_index >= len(column_metadata):
        col_index = 0

    clicked_col = column_metadata[col_index]
    logger.info(
        f"[drilldown] Column {col_index}: type={clicked_col.get('type')}, "
        f"drillable={clicked_col.get('is_drillable')}, "
        f"source_cte={clicked_col.get('source_cte')}, "
        f"source_ctes={bool(clicked_col.get('source_ctes'))}, "
        f"dims={clicked_col.get('filter_dimensions')}"
    )

    # Multi-CTE drill-down (e.g., rentabilite = F.total - P.total, or COALESCE(P.x, F.x))
    if clicked_col.get("source_ctes"):
        queries = []
        for cte_ref in clicked_col["source_ctes"]:
            fake_col = {
                "source_cte": cte_ref["cte_name"],
                "join_key": cte_ref["join_key"],
                "filter_dimensions": cte_ref["filter_dimensions"],
            }
            sql = _build_cte_drilldown(parsed, fake_col, row_values, original_sql)
            queries.append(
                {
                    "sql": sql,
                    "label": cte_ref["cte_name"],
                    "cte_name": cte_ref["cte_name"],
                }
            )
        return queries

    # Single CTE drill-down mode
    if clicked_col.get("source_cte"):
        return _build_cte_drilldown(parsed, clicked_col, row_values, original_sql)

    # Standard GROUP BY drill-down mode
    filter_dims = clicked_col.get("filter_dimensions", [])
    # R4 — résout les alias d'expression (``YEAR(f.d) AS annee``) en expression
    # réelle pour ne pas émettre ``WHERE [annee]`` (alias inexistant dans le
    # détail SELECT *, refusé par SQL Server).
    alias_to_real = _build_alias_to_real(select)
    extra_conditions = _build_where_conditions(filter_dims, row_values, alias_to_real)

    if not extra_conditions and not _extract_group_by_columns(select):
        logger.info("[drilldown] No filters to apply and no GROUP BY — skipping drill-down")
        return None

    return _rebuild_drilldown_sql(parsed, select, extra_conditions, original_sql)


# =====================================================================
# Internal helpers — AST navigation
# =====================================================================


def _find_outer_select(parsed: exp.Expression) -> exp.Select | None:
    """Find the outermost SELECT (skips CTEs and subqueries)."""
    if isinstance(parsed, exp.Select):
        return parsed

    for node in parsed.walk():
        if isinstance(node, exp.Select):
            parent = node.parent
            while parent:
                if isinstance(parent, (exp.CTE, exp.Subquery)):
                    break
                parent = parent.parent
            else:
                return node

    return parsed.find(exp.Select)


def _extract_group_by_columns(select: exp.Select) -> list[str]:
    """Extract column names from GROUP BY clause (direct only, not from CTEs/subqueries)."""
    group = select.args.get("group")
    if group is None:
        return []
    return [_expr_to_col_name(e) for e in group.expressions if _expr_to_col_name(e)]


def _expr_to_col_name(expr: exp.Expression) -> str:
    """Extract a simple column name from an expression.

    Handles wrapped expressions like ISNULL(col, val), COALESCE(col, val),
    by extracting the first Column argument.
    """
    if isinstance(expr, exp.Column):
        return expr.name
    if isinstance(expr, exp.Alias):
        return expr.alias
    if isinstance(expr, exp.Identifier):
        return expr.name
    # ISNULL, COALESCE, and similar functions wrapping a column
    if isinstance(expr, (exp.Func, exp.Anonymous)):
        for arg in expr.args.values():
            if isinstance(arg, exp.Column):
                return arg.name
            if isinstance(arg, list):
                for item in arg:
                    if isinstance(item, exp.Column):
                        return item.name
    if hasattr(expr, "name") and isinstance(getattr(expr, "name"), str):
        return expr.name
    return ""


def _expr_table_alias(expr: exp.Expression) -> str:
    """Extract the table alias from an expression like P.CmProd2023."""
    inner = expr.this if isinstance(expr, exp.Alias) else expr
    if isinstance(inner, exp.Column) and inner.table:
        return inner.table
    return ""


# =====================================================================
# Standard GROUP BY drill-down
# =====================================================================


def _normalize_expr_sql(expr: exp.Expression) -> str:
    """Normalize an expression's SQL for comparison (lowercase, no spaces)."""
    try:
        return expr.sql(dialect="tsql").lower().replace(" ", "")
    except Exception:
        return ""


def _map_group_by_to_select_aliases(select: exp.Select) -> list[str]:
    """Map each GROUP BY expression to its SELECT alias.

    Compares GROUP BY expressions with SELECT inner expressions by normalized SQL.
    Handles expression GROUP BY like YEAR(facDate) → annee.

    Returns aliases in GROUP BY order.
    """
    group = select.args.get("group")
    if group is None:
        return []

    # Build SELECT expression lookup: normalized SQL → alias
    select_lookup: dict[str, str] = {}
    for sel_expr in select.expressions:
        inner = sel_expr.this if isinstance(sel_expr, exp.Alias) else sel_expr
        alias = sel_expr.alias if isinstance(sel_expr, exp.Alias) else _expr_to_col_name(sel_expr)
        if alias:
            key = _normalize_expr_sql(inner)
            if key:
                select_lookup[key] = alias

    aliases = []
    for gb_expr in group.expressions:
        gb_key = _normalize_expr_sql(gb_expr)
        alias = select_lookup.get(gb_key)
        if alias:
            aliases.append(alias)
        else:
            # Fallback: raw column name
            name = _expr_to_col_name(gb_expr)
            aliases.append(name if name else str(gb_expr))

    return aliases


def _build_expr_to_alias_map(select: exp.Select) -> dict[str, str]:
    """Build mapping from normalized expression SQL → SELECT alias.

    Used to resolve PARTITION BY expressions to their SELECT aliases.
    """
    result: dict[str, str] = {}
    for sel_expr in select.expressions:
        inner = sel_expr.this if isinstance(sel_expr, exp.Alias) else sel_expr
        alias = sel_expr.alias if isinstance(sel_expr, exp.Alias) else _expr_to_col_name(sel_expr)
        if alias:
            key = _normalize_expr_sql(inner)
            if key:
                result[key] = alias
    return result


def _analyze_select_expression(
    expr: exp.Expression,
    group_by_aliases: list[str],
    expr_to_alias: dict[str, str] | None = None,
) -> dict:
    """Analyze a SELECT expression for GROUP BY queries.

    group_by_aliases: SELECT aliases of GROUP BY columns (handles expressions).
    expr_to_alias: normalized expr SQL → SELECT alias (for PARTITION BY resolution).
    """
    name = expr.alias if isinstance(expr, exp.Alias) else _expr_to_col_name(expr) or str(expr)
    inner = expr.this if isinstance(expr, exp.Alias) else expr

    # Window function — filter by PARTITION BY columns (not all GROUP BY cols)
    window = inner.find(exp.Window)
    if window is not None:
        partition_cols = _extract_partition_by(window, expr_to_alias)
        return {
            "name": name,
            "is_drillable": True,
            "filter_dimensions": partition_cols,
            "type": "window",
        }

    # Aggregate function
    if inner.find(exp.AggFunc) is not None:
        return {
            "name": name,
            "is_drillable": True,
            "filter_dimensions": group_by_aliases,
            "type": "aggregate",
        }

    # Plain column or expression matching a GROUP BY alias
    if name in group_by_aliases:
        return {
            "name": name,
            "is_drillable": True,
            "filter_dimensions": group_by_aliases,
            "type": "column",
        }

    # Unknown expression
    return {"name": name, "is_drillable": False, "filter_dimensions": [], "type": "computed"}


def _extract_partition_by(
    window: exp.Window,
    expr_to_alias: dict[str, str] | None = None,
) -> list[str]:
    """Extract PARTITION BY column names, resolved to SELECT aliases."""
    partition_exprs = window.args.get("partition_by")
    if not partition_exprs:
        return []

    result = []
    for e in partition_exprs:
        # Try to resolve via expression-to-alias map first
        if expr_to_alias:
            key = _normalize_expr_sql(e)
            alias = expr_to_alias.get(key)
            if alias:
                result.append(alias)
                continue
        # Fallback: raw column name
        name = _expr_to_col_name(e)
        if name:
            result.append(name)
    return result


def build_drill_predicate(expr: str, value: Any) -> str | None:
    """Build ONE WHERE predicate ``<expr> = <literal>`` (or ``<expr> IS NULL``).

    ``expr`` is the left-hand SQL expression already qualified/quoted by the
    caller (e.g. ``[colname]`` or an LLM-provided expression ``YEAR(f.facDate)``).
    The value is escaped to a T-SQL literal. Returns ``None`` when the value
    cannot be used in an equality filter (``inf`` / ``nan``) — caller skips it.

    **Single source of truth** for drill-down value escaping: replaces the four
    copies of ``str(v).replace(chr(39), chr(39)*2)`` that lived in this module
    (``_build_where_conditions`` + ``_build_cte_drilldown``) and is reused by
    ``DrillDownHandler`` to bind row values into the LLM-generated skeleton
    WITHOUT ever sending those values to the LLM (confidentiality Niveau 4/5).
    """
    import math

    if value is None:
        return f"{expr} IS NULL"
    if isinstance(value, bool):
        # bool est sous-classe d'int : ``<expr> = True`` est invalide en T-SQL.
        # On mappe sur un bit 1/0.
        return f"{expr} = {1 if value else 0}"
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            return None  # inf/nan — can't filter by these
        return f"{expr} = {value}"
    return f"{expr} = '{str(value).replace(chr(39), chr(39) * 2)}'"


def _build_alias_to_real(select_node: exp.Select) -> dict[str, str]:
    """Map ``alias_select(lower) → SQL de l'expression interne``.

    Résout une dimension agrégée par EXPRESSION (ex. ``YEAR(f.facDate) AS annee``
    → ``{'annee': 'YEAR(f.facDate)'}``). Gère ISNULL/COALESCE/etc. **SSoT partagée**
    entre le mode standard GROUP BY (``build_drilldown_query``) et le mode CTE
    (``_build_cte_drilldown``) — évite la duplication de cette boucle.
    """
    mapping: dict[str, str] = {}
    for sel_expr in select_node.expressions:
        if isinstance(sel_expr, exp.Alias):
            try:
                mapping[sel_expr.alias.lower()] = sel_expr.this.sql(dialect="tsql")
            except Exception:
                continue
    return mapping


def _build_where_conditions(
    filter_dims: list[str],
    row_values: dict[str, Any],
    alias_to_real: dict[str, str] | None = None,
) -> list[str]:
    """Build WHERE conditions from dimension names and row values.

    ``alias_to_real`` (R4) résout un alias SELECT → expression réelle : dans la
    requête de détail (``SELECT *``, sans GROUP BY) un alias d'expression
    (``YEAR(f.d) AS annee``) n'est PAS une colonne, donc ``WHERE [annee] = …``
    serait rejeté par SQL Server (« Invalid column name 'annee' »). Sans
    résolution disponible, on retombe sur ``[dim]`` (cas d'une vraie colonne,
    ex. ``GROUP BY region`` → ``[region]`` valide).
    """
    conditions = []
    amap = alias_to_real or {}
    for dim in filter_dims:
        if dim not in row_values:
            continue
        lhs = amap.get(dim.lower()) or f"[{dim}]"
        predicate = build_drill_predicate(lhs, row_values[dim])
        if predicate is not None:
            conditions.append(predicate)
    return conditions


def _rebuild_drilldown_sql(
    parsed: exp.Expression, select: exp.Select, extra_conditions: list[str], original_sql: str = ""
) -> str:
    """Rebuild SQL for standard GROUP BY drill-down.

    Uses regex on original SQL text (not AST reconstruction, which mangles aliases).
    """
    import re

    sql = original_sql if original_sql else parsed.sql(dialect="tsql")

    try:
        # Step 1: Find the last SELECT at paren depth 0 (= the outer SELECT)
        outer_select_pos = -1
        for m in re.finditer(r"\bSELECT\b", sql, re.IGNORECASE):
            depth = 0
            for ch in sql[: m.start()]:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
            if depth == 0:
                outer_select_pos = m.start()

        if outer_select_pos < 0:
            logger.error("[drilldown] Could not find outer SELECT")
            return sql

        cte_prefix = sql[:outer_select_pos].strip()
        outer_query = sql[outer_select_pos:]

        # Step 2: In the outer query, find FROM, WHERE, GROUP BY positions (at depth 0)
        def find_keyword(text, keyword):
            for m in re.finditer(r"\b" + keyword + r"\b", text, re.IGNORECASE):
                d = 0
                for ch in text[: m.start()]:
                    if ch == "(":
                        d += 1
                    elif ch == ")":
                        d -= 1
                if d == 0:
                    return m.start()
            return -1

        from_pos = find_keyword(outer_query, "FROM")
        where_pos = find_keyword(outer_query, "WHERE")
        group_pos = find_keyword(outer_query, "GROUP BY")
        order_pos = find_keyword(outer_query, "ORDER BY")

        if from_pos < 0:
            logger.error("[drilldown] Could not find FROM in outer query")
            return sql

        # Step 3: Extract FROM clause (stops at WHERE, GROUP BY, or ORDER BY)
        boundaries = [p for p in [where_pos, group_pos, order_pos] if p > from_pos]
        from_end = min(boundaries) if boundaries else len(outer_query)
        from_clause = outer_query[from_pos:from_end].strip()

        # Step 4: Extract existing WHERE clause (stops at GROUP BY or ORDER BY)
        existing_where = ""
        if where_pos > 0:
            where_boundaries = [p for p in [group_pos, order_pos] if p > where_pos]
            where_end = min(where_boundaries) if where_boundaries else len(outer_query)
            existing_where = outer_query[where_pos + 5 : where_end].strip()  # +5 = len("WHERE")

        # Step 5: Build drill-down query (no GROUP BY, no ORDER BY)
        parts = []
        if cte_prefix:
            parts.append(cte_prefix)
        parts.append("SELECT *")
        parts.append(from_clause)

        where_parts = []
        if existing_where:
            where_parts.append(f"({existing_where})")
        where_parts.extend(extra_conditions)

        if where_parts:
            parts.append("WHERE " + " AND ".join(where_parts))

        result = "\n".join(parts)
        logger.debug(f"[drilldown] Rebuilt SQL:\n{result}")
        return result

    except Exception as e:
        logger.error(f"[drilldown] Failed to rebuild SQL: {e}")
        return sql


# =====================================================================
# CTE drill-down — for queries with no outer GROUP BY
# =====================================================================


def _build_cte_map(parsed: exp.Expression) -> dict[str, str]:
    """Map table aliases in the outer FROM to CTE names.

    Example: FROM Production2023 P → {'P': 'Production2023'}
    """
    select = _find_outer_select(parsed)
    if select is None:
        return {}

    alias_map = {}

    # FROM clause
    from_clause = select.find(exp.From)
    if from_clause:
        for table in from_clause.find_all(exp.Table):
            table_name = table.name
            table_alias = table.alias or table_name
            alias_map[table_alias] = table_name

    # JOINs
    for join in select.find_all(exp.Join):
        for table in join.find_all(exp.Table):
            table_name = table.name
            table_alias = table.alias or table_name
            alias_map[table_alias] = table_name

    return alias_map


def _extract_group_by_aliases(cte_select: exp.Select) -> list[str]:
    """Extract the SELECT aliases for GROUP BY columns in a CTE.

    For: SELECT d.dosNomDossier AS Dossier, Col01.colCodeCollabo AS expert, SUM(...) AS total
         GROUP BY d.dosNomDossier, Col01.colCodeCollabo
    Returns: ['Dossier', 'expert']

    Also handles expression GROUP BY like ISNULL(d.col, 'N/A') by comparing
    normalized SQL text with SELECT inner expressions.
    """
    # Reuse the same robust approach as the standard mode
    return _map_group_by_to_select_aliases(cte_select)


def _analyze_ctes(parsed: exp.Expression) -> dict[str, dict]:
    """Analyze each CTE to find GROUP BY columns and whether it has aggregates.

    Returns: {cte_name: {group_by: [col_names], group_by_aliases: [aliases],
              has_aggregates: bool, select_node: Select}}
    """
    result = {}
    with_clause = parsed.find(exp.With)
    if with_clause is None:
        return result

    for cte in with_clause.find_all(exp.CTE):
        cte_name = cte.alias
        cte_select = cte.find(exp.Select)
        if cte_select is None:
            continue

        gb = _extract_group_by_columns(cte_select)
        gb_aliases = _extract_group_by_aliases(cte_select)
        has_agg = cte_select.find(exp.AggFunc) is not None

        result[cte_name] = {
            "group_by": gb,
            "group_by_aliases": gb_aliases,
            "has_aggregates": has_agg,
            "select_node": cte_select,
            "cte_node": cte,
        }

    return result


def _extract_join_keys(select: exp.Select) -> dict[str, str]:
    """Extract the join key column for each table alias.

    For: FULL OUTER JOIN Production2024 P2 ON COALESCE(P.Dossier, F.Dossier) = P2.Dossier
    Returns: {'P2': 'Dossier'}
    """
    keys = {}

    # Also check FROM for the first table
    from_clause = select.find(exp.From)
    if from_clause:
        for table in from_clause.find_all(exp.Table):
            alias = table.alias or table.name
            # First table has no ON clause, find its key from the first JOIN's ON
            break

    for join in select.find_all(exp.Join):
        on_clause = join.find(exp.EQ)
        if on_clause is None:
            continue

        # Find which side references which alias
        for table in join.find_all(exp.Table):
            alias = table.alias or table.name

            # Look for columns referencing this alias in the ON clause
            for col in on_clause.find_all(exp.Column):
                if col.table == alias:
                    keys[alias] = col.name
                    break

    # For the first table in FROM (no JOIN), infer from other join keys
    if from_clause:
        for table in from_clause.find_all(exp.Table):
            alias = table.alias or table.name
            if alias not in keys:
                # Check if any ON clause references this alias
                for join in select.find_all(exp.Join):
                    for eq in join.find_all(exp.EQ):
                        for col in eq.find_all(exp.Column):
                            if col.table == alias:
                                keys[alias] = col.name
                                break
                        if alias in keys:
                            break
                    if alias in keys:
                        break
            break  # Only first table

    return keys


def _analyze_cte_column(
    expr: exp.Expression,
    cte_map: dict[str, str],
    cte_info: dict[str, dict],
    join_keys: dict[str, str],
) -> dict:
    """Analyze a column in the outer SELECT to trace it back to its source CTE."""
    name = expr.alias if isinstance(expr, exp.Alias) else _expr_to_col_name(expr) or str(expr)
    inner = expr.this if isinstance(expr, exp.Alias) else expr

    # Get the table alias (e.g., "P" from P.CmProd2023)
    table_alias = _expr_table_alias(expr)

    # If no table alias, check if it's a computed expression (arithmetic)
    if not table_alias:
        # Check if it's an expression involving columns from different CTEs
        aliases_used = set()
        for col in inner.find_all(exp.Column):
            if col.table:
                aliases_used.add(col.table)

        if len(aliases_used) == 0:
            # No table reference at all (constant or function)
            return {
                "name": name,
                "is_drillable": False,
                "filter_dimensions": [],
                "type": "computed",
            }

        if len(aliases_used) > 1:
            # Multiple CTEs involved (e.g., F.total - P.total) → multi-CTE drill-down
            source_ctes = []
            for alias in aliases_used:
                cte_name = cte_map.get(alias)
                if cte_name and cte_name in cte_info:
                    info = cte_info[cte_name]
                    if info["has_aggregates"] or info["group_by"]:
                        jk = join_keys.get(alias, "")
                        gb_aliases = info.get("group_by_aliases", info["group_by"])
                        source_ctes.append(
                            {
                                "cte_name": cte_name,
                                "table_alias": alias,
                                "join_key": jk,
                                "filter_dimensions": gb_aliases,
                            }
                        )
            if source_ctes:
                return {
                    "name": name,
                    "is_drillable": True,
                    "filter_dimensions": source_ctes[0]["filter_dimensions"],
                    "type": "multi_cte",
                    "source_ctes": source_ctes,
                }
            return {
                "name": name,
                "is_drillable": False,
                "filter_dimensions": [],
                "type": "computed",
            }

        # Single alias
        table_alias = aliases_used.pop()

    # Map alias to CTE name
    cte_name = cte_map.get(table_alias)
    if not cte_name or cte_name not in cte_info:
        return {"name": name, "is_drillable": False, "filter_dimensions": [], "type": "column"}

    info = cte_info[cte_name]
    join_key = join_keys.get(table_alias, "")

    # If the CTE has GROUP BY → its columns are aggregated → drillable
    if info["has_aggregates"] or info["group_by"]:
        # Use ALL CTE GROUP BY aliases as filter dimensions (not just the join key)
        # These aliases match the outer SELECT column names and row_values keys
        gb_aliases = info.get("group_by_aliases", info["group_by"])
        return {
            "name": name,
            "is_drillable": True,
            "filter_dimensions": gb_aliases,
            "type": "cte_aggregate",
            "source_cte": cte_name,
            "table_alias": table_alias,
            "join_key": join_key,
        }

    # CTE without aggregates → not drillable (already detail level)
    return {
        "name": name,
        "is_drillable": False,
        "filter_dimensions": [],
        "type": "cte_column",
        "source_cte": cte_name,
    }


def _build_cte_drilldown(
    parsed: exp.Expression,
    clicked_col: dict,
    row_values: dict[str, Any],
    original_sql: str = "",
) -> str:
    """Build a drill-down query into a specific CTE.

    Strategy: extract the CTE body text from the ORIGINAL SQL (not from AST regeneration,
    which can mangle table aliases). Then remove GROUP BY and add WHERE filters.
    """
    cte_name = clicked_col["source_cte"]
    clicked_col.get("join_key", "")

    cte_info = _analyze_ctes(parsed)
    if cte_name not in cte_info:
        return parsed.sql(dialect="tsql")

    try:
        # Extract the raw CTE body text from the original SQL using AST positions
        cte_info[cte_name]["cte_node"]
        cte_select = cte_info[cte_name]["select_node"]

        # Strategy: extract the CTE body from the ORIGINAL SQL text using regex
        # (not from AST, which mangles aliases), remove GROUP BY, replace SELECT
        # columns with *, add drill-down WHERE filter.
        import re

        original_sql_text = original_sql if original_sql else parsed.sql(dialect="tsql")

        # Find "CTE_NAME AS (" in the original SQL
        cte_pattern = re.compile(rf"{re.escape(cte_name)}\s+AS\s*\(", re.IGNORECASE)
        match = cte_pattern.search(original_sql_text)
        if not match:
            logger.warning(f"[drilldown] Could not find CTE '{cte_name}' in SQL")
            return original_sql_text

        # Find matching closing parenthesis
        start = match.end()
        depth, pos = 1, start
        while pos < len(original_sql_text) and depth > 0:
            if original_sql_text[pos] == "(":
                depth += 1
            elif original_sql_text[pos] == ")":
                depth -= 1
            pos += 1
        cte_body = original_sql_text[start : pos - 1].strip()

        # Resolve alias → real expression via AST (robust, handles ISNULL/COALESCE/
        # etc.). SSoT partagée avec le mode standard GROUP BY (R4 — de-dup).
        # E.g. "ISNULL(d.col, 'N/A') AS Name" → {"name": "ISNULL(d.col, 'N/A')"}.
        alias_to_real = _build_alias_to_real(cte_select)

        # Remove GROUP BY (and everything after: HAVING, ORDER BY)
        gb_match = re.search(r"\bGROUP\s+BY\b", cte_body, re.IGNORECASE)
        if gb_match:
            cte_body = cte_body[: gb_match.start()].strip()

        # Replace SELECT <columns> with SELECT * (remove aggregate expressions)
        from_match = re.search(r"\bFROM\b", cte_body, re.IGNORECASE)
        if from_match:
            cte_body = "SELECT * " + cte_body[from_match.start() :]

        # Build extra WHERE for ALL filter dimensions, resolving aliases to real expressions
        filter_dims = clicked_col.get("filter_dimensions", [])
        extra_conditions = []
        for dim in filter_dims:
            if dim not in row_values:
                continue
            # Resolve alias → CTE-internal expression (e.g., "Dossier" → "d.dosNomDossier")
            filter_expr = alias_to_real.get(dim.lower(), dim)
            if filter_expr != dim:
                logger.debug(f"[drilldown] Resolved alias '{dim}' → '{filter_expr}'")
            predicate = build_drill_predicate(filter_expr, row_values[dim])
            if predicate is not None:
                extra_conditions.append(predicate)

        # Append to existing WHERE or create new one
        if extra_conditions:
            extra_sql = " AND ".join(extra_conditions)
            where_match = re.search(r"\bWHERE\b", cte_body, re.IGNORECASE)
            if where_match:
                cte_body += " AND " + extra_sql
            else:
                cte_body += " WHERE " + extra_sql

        return cte_body

    except Exception as e:
        logger.error(f"[drilldown] CTE drill-down failed for {cte_name}: {e}")
        return parsed.sql(dialect="tsql")
