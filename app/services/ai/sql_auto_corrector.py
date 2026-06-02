"""
Auto-correcteur SQL programmatique (sans appel LLM).

Corrige les erreurs SQL courantes détectées par la taxonomie d'erreurs,
en utilisant des transformations regex/parsing déterministes.

Catégories gérées :
- column_not_found → fuzzy match difflib contre les colonnes DDL connues
- agg_no_groupby → ajouter les colonnes non-agrégées manquantes au GROUP BY
- type_mismatch → remplacer CAST(... AS FLOAT) par DECIMAL(18,2), etc.
- having_vs_where → déplacer les conditions avec agrégats de WHERE vers HAVING
- join_error → qualifier les colonnes ambiguës, corriger les identifiants multi-parties
- duplicate_cte_columns → supprimer les colonnes dupliquées dans le SELECT des CTE
"""

import re
import logging
from dataclasses import dataclass
from difflib import get_close_matches

from app.services.ai.sql_error_taxonomy import ErrorClassification

logger = logging.getLogger(__name__)

# Catégories que l'auto-correcteur sait gérer
CORRECTABLE_CATEGORIES = frozenset(
    {
        "column_not_found",
        "agg_no_groupby",
        "type_mismatch",
        "having_vs_where",
        "join_error",
        "duplicate_cte_columns",
    }
)

# Fonctions d'agrégation SQL Server
_AGG_FUNCTIONS = re.compile(
    r"\b(COUNT|SUM|AVG|MIN|MAX|STDEV|STDEVP|VAR|VARP|STRING_AGG)\s*\(",
    re.IGNORECASE,
)

# Pattern pour détecter CAST(... AS FLOAT/REAL)
_CAST_FLOAT_RE = re.compile(
    r"CAST\s*\(([^)]+?)\s+AS\s+(FLOAT|REAL)\s*\)",
    re.IGNORECASE,
)

# Pattern pour détecter les littéraux de date au format 'YYYY-MM-DD'
# SQL Server peut échouer en 22007 selon la locale quand on utilise des tirets.
# Le format 'YYYYMMDD' (sans tirets) est TOUJOURS non ambigu.
# Regex stricte : mois 01-12, jour 01-31 (pas de '9999-99-99' ni versions).
_DATE_LITERAL_RE = re.compile(
    r"'(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])'",
)

# Pattern pour détecter les agrégats dans une expression
_HAS_AGGREGATE_RE = re.compile(
    r"\b(COUNT|SUM|AVG|MIN|MAX)\s*\(",
    re.IGNORECASE,
)


@dataclass
class AutoCorrectionResult:
    """Résultat d'une tentative d'auto-correction."""

    corrected: bool
    sql: str  # SQL corrigé (ou original si pas de correction)
    description: str  # Ce qui a été corrigé
    category: str  # Catégorie de la correction appliquée


def can_auto_correct(classification: ErrorClassification) -> bool:
    """Indique si l'auto-correcteur peut traiter cette catégorie d'erreur."""
    return classification.category in CORRECTABLE_CATEGORIES


async def auto_correct(
    sql: str,
    classification: ErrorClassification,
    known_columns: dict[str, set[str]] | None = None,
) -> AutoCorrectionResult:
    """
    Tente de corriger le SQL programmatiquement.

    Args:
        sql: Requête SQL originale qui a échoué
        classification: Classification de l'erreur (de sql_error_taxonomy)
        known_columns: Dict table_name(UPPER) → set[column_name(UPPER)]
                       Si None, sera chargé depuis le TrainingStore

    Returns:
        AutoCorrectionResult indiquant si une correction a été appliquée
    """
    if not can_auto_correct(classification):
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description="Catégorie non auto-corrigeable",
            category=classification.category,
        )

    category = classification.category

    if category == "column_not_found":
        return await _fix_column_not_found(sql, classification, known_columns)
    elif category == "join_error":
        return await _fix_join_error(sql, classification, known_columns)
    elif category == "agg_no_groupby":
        return _fix_agg_no_groupby(sql, classification)
    elif category == "type_mismatch":
        return _fix_type_mismatch(sql, classification)
    elif category == "having_vs_where":
        return _fix_having_vs_where(sql, classification)
    elif category == "duplicate_cte_columns":
        return _fix_duplicate_cte_columns(sql, classification)

    return AutoCorrectionResult(
        corrected=False, sql=sql, description="Pas de correcteur", category=category
    )


def _extract_cte_bodies(sql: str) -> dict[str, str]:
    """
    Extraits les corps SQL de chaque CTE.

    Returns:
        dict[cte_name_upper → body_sql]
    """
    bodies: dict[str, str] = {}
    cte_pattern = re.compile(r"(?:\bWITH\b|,)\s+(\w+)\s+AS\s*\(", re.IGNORECASE)

    for match in cte_pattern.finditer(sql):
        cte_name = match.group(1).upper()
        start = match.end()
        depth = 1
        pos = start
        while pos < len(sql) and depth > 0:
            ch = sql[pos]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "'":
                pos += 1
                while pos < len(sql):
                    if sql[pos] == "'" and (pos + 1 >= len(sql) or sql[pos + 1] != "'"):
                        break
                    if sql[pos] == "'":
                        pos += 1
                    pos += 1
            pos += 1

        if depth == 0:
            bodies[cte_name] = sql[start : pos - 1]

    return bodies


def _find_outer_query_start(sql: str) -> int:
    """Retourne la position du début de la requête extérieure (après toutes les CTE)."""
    cte_pattern = re.compile(r"(?:\bWITH\b|,)\s+(\w+)\s+AS\s*\(", re.IGNORECASE)

    last_end = 0
    for match in cte_pattern.finditer(sql):
        start = match.end()
        depth = 1
        pos = start
        while pos < len(sql) and depth > 0:
            ch = sql[pos]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "'":
                pos += 1
                while pos < len(sql):
                    if sql[pos] == "'" and (pos + 1 >= len(sql) or sql[pos + 1] != "'"):
                        break
                    if sql[pos] == "'":
                        pos += 1
                    pos += 1
            pos += 1

        if depth == 0:
            last_end = pos

    return last_end


def _fix_duplicate_cte_columns(
    sql: str,
    classification: ErrorClassification,
) -> AutoCorrectionResult:
    """
    Supprime les colonnes dupliquées dans le SELECT des CTE.
    Garde la première occurrence, supprime les suivantes.
    """
    cte_bodies = _extract_cte_bodies(sql)
    if not cte_bodies:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description="Aucune CTE trouvée",
            category="duplicate_cte_columns",
        )

    new_sql = sql
    fixed_ctes: list[str] = []

    for cte_name, body in cte_bodies.items():
        # Extract SELECT clause (before FROM)
        select_match = re.search(
            r"\bSELECT\b(.*?)\bFROM\b",
            body,
            re.IGNORECASE | re.DOTALL,
        )
        if not select_match:
            continue

        select_clause = select_match.group(1)
        columns = _split_select_columns(select_clause)
        if not columns:
            continue

        # Track output names and find duplicates
        seen: dict[str, int] = {}
        unique_columns: list[str] = []
        removed: list[str] = []

        for col_expr in columns:
            output_name = _get_output_column_name(col_expr)
            if not output_name:
                unique_columns.append(col_expr)
                continue

            name_upper = output_name.upper()
            if name_upper in seen:
                removed.append(output_name)
            else:
                seen[name_upper] = 1
                unique_columns.append(col_expr)

        if not removed:
            continue

        # Reconstruct SELECT clause
        new_select = ", ".join(unique_columns)
        old_select = select_match.group(1)
        new_sql = new_sql.replace(
            f"SELECT{old_select}FROM",
            f"SELECT {new_select}\nFROM",
            1,
        )
        fixed_ctes.append(f"{cte_name} (supprimé: {', '.join(removed)})")

    if not fixed_ctes:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description="Pas de colonnes dupliquées détectées dans les CTE",
            category="duplicate_cte_columns",
        )

    return AutoCorrectionResult(
        corrected=True,
        sql=new_sql,
        description=f"Colonnes dupliquées supprimées: {'; '.join(fixed_ctes)}",
        category="duplicate_cte_columns",
    )


def _split_select_columns(select_clause: str) -> list[str]:
    """Split SELECT clause by commas, respecting parentheses and strings."""
    columns: list[str] = []
    depth = 0
    current: list[str] = []
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


def _get_output_column_name(col_expr: str) -> str:
    """
    Extract the output column name from a SELECT expression.
    - "Table.Column" → "Column"
    - "Table.Column AS alias" → "alias"
    - "Column" → "Column"
    - "*" → "" (skip)
    """
    expr = col_expr.strip()
    if not expr or expr == "*":
        return ""

    # Check for AS alias (last AS in expression)
    as_match = re.search(r"\bAS\s+\[?([A-Za-z_]\w*)\]?\s*$", expr, re.IGNORECASE)
    if as_match:
        return as_match.group(1)

    # Check for qualified name: [schema.]table.column or just column
    # Remove any trailing whitespace
    qualified_match = re.match(r"^(?:\[?[A-Za-z_]\w*\]?\s*\.\s*)*\[?([A-Za-z_]\w*)\]?\s*$", expr)
    if qualified_match:
        return qualified_match.group(1)

    # Expression without alias — can't determine output name
    return ""


def _fix_cte_scope_leak(sql: str, bad_identifier: str) -> AutoCorrectionResult:
    """
    Corrige un alias CTE interne utilisé hors du CTE.

    Remplace Alias.Column par le nom de sortie du CTE (alias AS ou nom de colonne).
    Ne remplace que dans la requête extérieure (pas dans le corps du CTE).
    """
    parts = bad_identifier.split(".", 1)
    if len(parts) != 2:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description=f"Identifiant '{bad_identifier}' non parsable",
            category="column_not_found",
        )

    qualifier, column = parts[0].strip(), parts[1].strip()

    cte_bodies = _extract_cte_bodies(sql)
    if not cte_bodies:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description="Aucun CTE détecté dans la requête",
            category="column_not_found",
        )

    # Vérifier si le qualifiant est un alias FROM/JOIN dans un CTE
    output_name = column  # Par défaut : nom de colonne brut
    found_in_cte = False

    for _cte_name, body in cte_bodies.items():
        # Chercher FROM/JOIN ... AS qualifier (ou FROM/JOIN ... qualifier)
        body_pattern = re.compile(
            r"\b(?:FROM|JOIN)\s+[\[\]\w\.]+\s+(?:AS\s+)?" + re.escape(qualifier) + r"\b",
            re.IGNORECASE,
        )
        if not body_pattern.search(body):
            continue

        found_in_cte = True

        # Chercher qualifier.column AS alias → utiliser l'alias
        alias_pattern = re.compile(
            r"\b" + re.escape(qualifier) + r"\." + re.escape(column) + r"\s+AS\s+(\w+)",
            re.IGNORECASE,
        )
        alias_match = alias_pattern.search(body)
        if alias_match:
            output_name = alias_match.group(1)
        # Sinon output_name reste = column (nom de colonne sans qualifiant)
        break

    if not found_in_cte:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description=f"Qualifiant '{qualifier}' non trouvé dans un CTE",
            category="column_not_found",
        )

    # Remplacer UNIQUEMENT dans la requête extérieure
    outer_start = _find_outer_query_start(sql)
    replace_pattern = re.compile(
        r"\b" + re.escape(qualifier) + r"\." + re.escape(column) + r"\b",
        re.IGNORECASE,
    )

    if outer_start > 0:
        cte_part = sql[:outer_start]
        outer_part = sql[outer_start:]
        new_outer = replace_pattern.sub(output_name, outer_part)
        new_sql = cte_part + new_outer
    else:
        new_sql = replace_pattern.sub(output_name, sql)

    if new_sql == sql:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description=f"'{bad_identifier}' non trouvé dans la requête extérieure",
            category="column_not_found",
        )

    logger.info("Auto-correction CTE scope: '%s' → '%s'", bad_identifier, output_name)
    return AutoCorrectionResult(
        corrected=True,
        sql=new_sql,
        description=f"Alias CTE corrigé : '{bad_identifier}' → '{output_name}'",
        category="column_not_found",
    )


# ---- Mots-clés SQL à ignorer comme alias ---- #
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
        "SELECT",
        "FROM",
        "TOP",
        "DISTINCT",
        "NULL",
        "NOT",
        "IN",
        "BETWEEN",
        "LIKE",
        "EXISTS",
        "CASE",
        "WHEN",
        "THEN",
        "ELSE",
        "END",
        "IS",
        "BY",
        "ASC",
        "DESC",
        "OFFSET",
        "FETCH",
        "NEXT",
    }
)

# Pattern FROM/JOIN ... [schema.]table [AS] alias
_FROM_JOIN_ALIAS_RE = re.compile(
    r"\b(?:FROM|JOIN)\s+(?:(?:\[?\w+\]?\.){0,2})\[?(\w+)\]?\s+(?:AS\s+)?\[?(\w+)\]?",
    re.IGNORECASE,
)


def _extract_alias_to_table(sql: str) -> dict[str, str]:
    """Extrait le mapping alias(UPPER) → table(UPPER) depuis FROM/JOIN.

    Gère : FROM Table t, FROM Table AS t, FROM [dbo].[Table] t
    Ignore les mots-clés SQL qui ne sont pas des alias.
    """
    mapping: dict[str, str] = {}
    for match in _FROM_JOIN_ALIAS_RE.finditer(sql):
        table = match.group(1).upper()
        alias = match.group(2).upper()
        if alias not in _SKIP_ALIASES:
            mapping[alias] = table
    return mapping



async def _fix_join_error(
    sql: str,
    classification: ErrorClassification,
    known_columns: dict[str, set[str]] | None = None,
) -> AutoCorrectionResult:
    """
    Corrige les erreurs de jointure :
    - Ambiguous column name → qualifie avec le bon alias
    - Multi-part identifier not bound → trouve le bon qualifiant
    - Correlation name already in use → renomme les alias dupliqués
    """
    bad_fragment = classification.sql_fragment.strip("'\"[] ")
    details_lower = classification.details.lower()

    if known_columns is None:
        known_columns = await _load_known_columns()

    if not known_columns:
        # Correlation name n'a pas besoin de known_columns
        if "correlation" in details_lower and "already" in details_lower:
            return _fix_duplicate_alias(sql)
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description="Aucun DDL connu pour résoudre l'erreur de jointure",
            category="join_error",
        )

    # Cas 1 : Ambiguous column (fragment = nom de colonne sans qualifiant)
    if bad_fragment and "." not in bad_fragment and "ambiguous" in details_lower:
        return _fix_ambiguous_column(sql, bad_fragment, known_columns)

    # Cas 2 : Multi-part identifier not bound (fragment = alias.colonne)
    if bad_fragment and "." in bad_fragment:
        return _fix_bad_qualifier(sql, bad_fragment, known_columns)

    # Cas 3 : Correlation name already in use (pas de fragment utile)
    if "correlation" in details_lower and "already" in details_lower:
        return _fix_duplicate_alias(sql)

    # Cas 4 : Ambiguous sans fragment — essayer d'extraire du message d'erreur
    if "ambiguous" in details_lower:
        col_match = re.search(r"[Aa]mbiguous column name '([^']+)'", classification.details)
        if col_match:
            return _fix_ambiguous_column(sql, col_match.group(1), known_columns)

    # Cas 5 : Multi-part identifier sans fragment — extraire du message
    if "multi-part identifier" in details_lower:
        id_match = re.search(
            r"multi-part identifier\s+['\"]?([^'\"]+?)['\"]?\s+could not be bound",
            classification.details,
            re.IGNORECASE,
        )
        if id_match:
            return _fix_bad_qualifier(sql, id_match.group(1).strip(), known_columns)

    return AutoCorrectionResult(
        corrected=False,
        sql=sql,
        description="Pas d'identifiant fautif extrait de l'erreur de jointure",
        category="join_error",
    )


def _fix_ambiguous_column(
    sql: str,
    column_name: str,
    known_columns: dict[str, set[str]],
) -> AutoCorrectionResult:
    """
    Corrige une colonne ambiguë en la qualifiant avec le bon alias.

    Logique :
    1. Extraire alias→table du SQL
    2. Pour chaque table du query, vérifier si elle a cette colonne
    3. Si exactement 1 table → qualifier toutes les refs non qualifiées
    """
    col_upper = column_name.upper()
    alias_to_table = _extract_alias_to_table(sql)

    if not alias_to_table:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description="Aucun alias détecté dans le SQL pour résoudre l'ambiguïté",
            category="join_error",
        )

    # Trouver quels alias pointent vers des tables ayant cette colonne
    matching_aliases: list[str] = []
    for alias, table in alias_to_table.items():
        table_cols = known_columns.get(table, set())
        if col_upper in {c.upper() for c in table_cols}:
            matching_aliases.append(alias)

    if not matching_aliases:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description=(
                f"Colonne '{column_name}' introuvable dans les tables du query "
                f"({', '.join(alias_to_table.values())})"
            ),
            category="join_error",
        )

    if len(matching_aliases) > 1:
        # Ambiguë dans le schéma aussi → on ne peut pas deviner
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description=(
                f"Colonne '{column_name}' existe dans plusieurs tables du query : "
                f"{', '.join(f'{a}→{alias_to_table[a]}' for a in matching_aliases)}. "
                f"Qualifie manuellement."
            ),
            category="join_error",
        )

    # Exactement 1 table → qualifier toutes les occurrences non qualifiées
    correct_alias = matching_aliases[0]

    # Pattern : colonne NON précédée par un point ou un identifiant+point
    # (= référence non qualifiée). Mot entier, pas dans une string.
    # On cherche column_name qui n'est PAS précédé par "alias."
    unqualified_re = re.compile(
        r"(?<!\w\.)(?<!\w)\b" + re.escape(column_name) + r"\b",
        re.IGNORECASE,
    )

    # Remplacer seulement les occurrences non déjà qualifiées
    def _qualify(m: re.Match) -> str:
        start = m.start()
        # Vérifier qu'il n'y a pas déjà un qualifiant avant
        prefix = sql[max(0, start - 50) : start]
        if re.search(r"\w+\.\s*$", prefix):
            return m.group(0)  # Déjà qualifié
        return f"{correct_alias}.{m.group(0)}"

    new_sql = unqualified_re.sub(_qualify, sql)

    if new_sql == sql:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description=f"Colonne '{column_name}' non trouvée non-qualifiée dans le SQL",
            category="join_error",
        )

    logger.info(
        "Auto-correction join ambiguous: '%s' → '%s.%s'",
        column_name,
        correct_alias,
        column_name,
    )
    return AutoCorrectionResult(
        corrected=True,
        sql=new_sql,
        description=(
            f"Colonne ambiguë '{column_name}' qualifiée avec "
            f"l'alias '{correct_alias}' (table {alias_to_table[correct_alias]})"
        ),
        category="join_error",
    )


def _fix_bad_qualifier(
    sql: str,
    identifier: str,
    known_columns: dict[str, set[str]],
) -> AutoCorrectionResult:
    """
    Corrige un identifiant multi-partie dont le qualifiant ne peut pas être lié.

    Ex: "t.colName" où t n'est pas un alias valide dans le query.
    Cherche quel alias du query possède cette colonne.
    """
    parts = identifier.split(".", 1)
    if len(parts) != 2:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description=f"Identifiant '{identifier}' non parsable (pas de '.')",
            category="join_error",
        )

    bad_alias = parts[0].strip()
    column = parts[1].strip()
    col_upper = column.upper()
    bad_alias_upper = bad_alias.upper()

    alias_to_table = _extract_alias_to_table(sql)

    # L'alias existe-t-il dans la requête ?
    if bad_alias_upper in alias_to_table:
        # L'alias existe mais la table n'a peut-être pas cette colonne
        table = alias_to_table[bad_alias_upper]
        table_cols = known_columns.get(table, set())
        if col_upper in {c.upper() for c in table_cols}:
            # La colonne existe dans la table → pas un problème d'alias,
            # peut-être un problème de scope (CTE, sous-requête)
            return AutoCorrectionResult(
                corrected=False,
                sql=sql,
                description=(
                    f"L'alias '{bad_alias}' et la colonne '{column}' existent, "
                    f"possible problème de scope (CTE/sous-requête)"
                ),
                category="join_error",
            )
        # L'alias existe mais la table n'a pas cette colonne → chercher ailleurs
        correct_alias = _find_alias_with_column(
            col_upper,
            alias_to_table,
            known_columns,
            exclude=bad_alias_upper,
        )
        if correct_alias:
            new_sql = _replace_qualified_ref(sql, bad_alias, column, correct_alias)
            if new_sql != sql:
                logger.info(
                    "Auto-correction join qualifier: '%s.%s' → '%s.%s'",
                    bad_alias,
                    column,
                    correct_alias,
                    column,
                )
                return AutoCorrectionResult(
                    corrected=True,
                    sql=new_sql,
                    description=(
                        f"Qualifiant corrigé : '{bad_alias}.{column}' → "
                        f"'{correct_alias}.{column}' "
                        f"(table {alias_to_table[correct_alias]})"
                    ),
                    category="join_error",
                )
    else:
        # L'alias n'existe pas du tout → trouver le bon alias pour cette colonne
        correct_alias = _find_alias_with_column(
            col_upper,
            alias_to_table,
            known_columns,
        )
        if correct_alias:
            new_sql = _replace_qualified_ref(sql, bad_alias, column, correct_alias)
            if new_sql != sql:
                logger.info(
                    "Auto-correction join unknown alias: '%s.%s' → '%s.%s'",
                    bad_alias,
                    column,
                    correct_alias,
                    column,
                )
                return AutoCorrectionResult(
                    corrected=True,
                    sql=new_sql,
                    description=(
                        f"Alias inconnu '{bad_alias}' remplacé par '{correct_alias}' "
                        f"pour '{column}' (table {alias_to_table[correct_alias]})"
                    ),
                    category="join_error",
                )

    return AutoCorrectionResult(
        corrected=False,
        sql=sql,
        description=(
            f"Impossible de résoudre '{identifier}' : colonne '{column}' "
            f"introuvable dans les tables du query"
        ),
        category="join_error",
    )


def _find_alias_with_column(
    col_upper: str,
    alias_to_table: dict[str, str],
    known_columns: dict[str, set[str]],
    exclude: str = "",
) -> str:
    """Trouve l'alias dont la table possède la colonne donnée.

    Returns:
        L'alias (UPPER) si exactement 1 match, chaîne vide sinon.
    """
    candidates: list[str] = []
    for alias, table in alias_to_table.items():
        if alias == exclude:
            continue
        table_cols = known_columns.get(table, set())
        if col_upper in {c.upper() for c in table_cols}:
            candidates.append(alias)

    if len(candidates) == 1:
        return candidates[0]
    return ""


def _replace_qualified_ref(sql: str, old_alias: str, column: str, new_alias: str) -> str:
    """Remplace old_alias.column par new_alias.column dans le SQL."""
    pattern = re.compile(
        r"\b" + re.escape(old_alias) + r"\." + re.escape(column) + r"\b",
        re.IGNORECASE,
    )
    return pattern.sub(f"{new_alias}.{column}", sql)


def _fix_duplicate_alias(sql: str) -> AutoCorrectionResult:
    """Corrige un alias de corrélation dupliqué en renommant la seconde occurrence."""
    alias_to_table = _extract_alias_to_table(sql)

    # Trouver les doublons en scannant toutes les occurrences
    seen: dict[str, int] = {}
    duplicates: list[str] = []
    for match in _FROM_JOIN_ALIAS_RE.finditer(sql):
        alias = match.group(2).upper()
        if alias in _SKIP_ALIASES:
            continue
        seen[alias] = seen.get(alias, 0) + 1
        if seen[alias] == 2:
            duplicates.append(alias)

    if not duplicates:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description="Aucun alias dupliqué détecté",
            category="join_error",
        )

    new_sql = sql
    renamed: list[str] = []
    for dup_alias in duplicates:
        # Trouver la 2e occurrence de FROM/JOIN ... AS dup_alias
        pattern = re.compile(
            r"(\b(?:FROM|JOIN)\s+(?:\[?\w+\]?\.)?\[?\w+\]?\s+(?:AS\s+)?)"
            + re.escape(dup_alias)
            + r"\b",
            re.IGNORECASE,
        )
        count = 0
        new_alias = f"{dup_alias}2"
        # S'assurer que le nouvel alias n'existe pas déjà
        while new_alias.upper() in alias_to_table or new_alias.upper() in seen:
            new_alias = f"{dup_alias}{count + 3}"
            count += 1

        def _rename_second(m: re.Match) -> str:
            nonlocal count
            count += 1
            if count == 2:
                return m.group(1) + new_alias
            return m.group(0)

        count = 0
        new_sql = pattern.sub(_rename_second, new_sql)
        renamed.append(f"'{dup_alias}' → '{new_alias}'")

    if new_sql == sql:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description="Alias dupliqués détectés mais non corrigés",
            category="join_error",
        )

    desc = "Alias dupliqué(s) renommé(s) : " + ", ".join(renamed)
    logger.info("Auto-correction join duplicate alias: %s", desc)
    return AutoCorrectionResult(
        corrected=True,
        sql=new_sql,
        description=desc,
        category="join_error",
    )


async def _fix_column_not_found(
    sql: str,
    classification: ErrorClassification,
    known_columns: dict[str, set[str]] | None = None,
) -> AutoCorrectionResult:
    """
    Corrige une colonne introuvable par fuzzy matching.

    Utilise le fragment extrait par la taxonomie (ex: 'CT_Intitulé')
    et cherche la colonne la plus proche dans les DDL connus.
    """
    bad_col = classification.sql_fragment.strip("'\"[] ")

    # Priorité : si c'est un identifiant multi-partie (Alias.Column),
    # tenter la correction de scope CTE avant le fuzzy match
    if bad_col and "." in bad_col:
        cte_result = _fix_cte_scope_leak(sql, bad_col)
        if cte_result.corrected:
            return cte_result
    if not bad_col:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description="Pas de nom de colonne identifié dans l'erreur",
            category="column_not_found",
        )

    # Charger les colonnes connues si pas fournies
    if known_columns is None:
        known_columns = await _load_known_columns()

    if not known_columns:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description="Aucun DDL connu pour fuzzy matching",
            category="column_not_found",
        )

    # Chercher dans toutes les tables connues
    bad_upper = bad_col.upper()
    all_columns: dict[str, str] = {}  # col_upper → col_original
    for table_cols in known_columns.values():
        for col in table_cols:
            all_columns[col.upper()] = col

    matches = get_close_matches(bad_upper, all_columns.keys(), n=1, cutoff=0.75)
    if not matches:
        # Pas de fuzzy match → chercher si la colonne existe dans une VUE
        # Les vues consolident plusieurs tables (ex: viewGroupes01 = Groupes + Dossiers)
        # et contiennent des colonnes absentes des tables de base.
        view_hint = await _find_column_in_views(bad_col, known_columns)
        desc = f"Aucune colonne similaire à '{bad_col}' trouvée (cutoff=0.75)"
        if view_hint:
            desc += f". {view_hint}"
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description=desc,
            category="column_not_found",
        )

    good_col = all_columns[matches[0]]

    # Remplacer dans le SQL (insensible à la casse, mot entier)
    pattern = re.compile(r"\b" + re.escape(bad_col) + r"\b", re.IGNORECASE)
    new_sql = pattern.sub(good_col, sql)

    if new_sql == sql:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description=f"Colonne '{bad_col}' non trouvée dans le SQL pour remplacement",
            category="column_not_found",
        )

    logger.info("Auto-correction column: '%s' → '%s'", bad_col, good_col)
    return AutoCorrectionResult(
        corrected=True,
        sql=new_sql,
        description=f"Colonne corrigée : '{bad_col}' → '{good_col}'",
        category="column_not_found",
    )


def _is_in_string(sql: str, pos: int) -> bool:
    """
    Vérifie si une position dans le SQL est à l'intérieur d'une chaîne littérale.
    Gère les échappements SQL Server ('').
    """
    in_str = False
    i = 0
    while i < pos:
        if sql[i] == "'":
            if in_str and i + 1 < len(sql) and sql[i + 1] == "'":
                i += 2
                continue
            in_str = not in_str
        i += 1
    return in_str


def _fix_agg_no_groupby(
    sql: str,
    classification: ErrorClassification,
) -> AutoCorrectionResult:
    """
    Corrige une colonne manquante dans le GROUP BY.

    Si le message d'erreur indique quelle colonne pose problème,
    on l'ajoute au GROUP BY existant.
    """
    bad_col = classification.sql_fragment.strip("'\"[] ")
    if not bad_col:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description="Pas de nom de colonne identifié dans l'erreur",
            category="agg_no_groupby",
        )

    # Vérifier qu'un GROUP BY existe
    groupby_match = re.search(r"\bGROUP\s+BY\b", sql, re.IGNORECASE)
    if not groupby_match or _is_in_string(sql, groupby_match.start()):
        # Pas de GROUP BY → on ne peut pas juste en ajouter un sans analyser le SELECT
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description="Pas de GROUP BY existant, correction trop risquée",
            category="agg_no_groupby",
        )

    # Trouver la fin de la clause GROUP BY (avant ORDER BY, HAVING, ou fin)
    after_groupby = sql[groupby_match.end() :]
    # Trouver le prochain mot-clé SQL qui termine le GROUP BY
    next_clause = re.search(
        r"\b(ORDER\s+BY|HAVING|UNION|EXCEPT|INTERSECT|OFFSET|FETCH|;)\b",
        after_groupby,
        re.IGNORECASE,
    )

    if next_clause:
        insert_pos = groupby_match.end() + next_clause.start()
        new_sql = sql[:insert_pos].rstrip() + ", " + bad_col + " " + sql[insert_pos:]
    else:
        # GROUP BY est la dernière clause
        new_sql = sql.rstrip().rstrip(";") + ", " + bad_col

    logger.info("Auto-correction agg_no_groupby: added '%s' to GROUP BY", bad_col)
    return AutoCorrectionResult(
        corrected=True,
        sql=new_sql,
        description=f"Colonne '{bad_col}' ajoutée au GROUP BY",
        category="agg_no_groupby",
    )


def _fix_type_mismatch(
    sql: str,
    classification: ErrorClassification,
) -> AutoCorrectionResult:
    """
    Corrige les erreurs de type courantes dans SQL Server :
    - CAST(... AS FLOAT/REAL) → CAST(... AS DECIMAL(18,2))
    - Arithmetic overflow → DECIMAL(38,2)
    """
    error_lower = classification.details.lower()
    corrections = []

    # Cas 0 : Date literals 'YYYY-MM-DD' → 'YYYYMMDD' (erreur 22007)
    # SQL Server avec certaines locales rejette '2023-10-01' mais accepte toujours '20231001'
    # "hors limites" seul est trop vague (pourrait être numérique) → exiger "datetime" en combo
    is_datetime_error = (
        "datetime" in error_lower
        or "22007" in error_lower
        or ("hors limites" in error_lower and "date" in error_lower)
    )
    if is_datetime_error:
        new_sql = _DATE_LITERAL_RE.sub(r"'\1\2\3'", sql)
        if new_sql != sql:
            sql = new_sql
            corrections.append("Date 'YYYY-MM-DD' → 'YYYYMMDD' (format non ambigu)")

    # Cas 1 : CAST AS FLOAT → CAST AS DECIMAL(18,2)
    if _CAST_FLOAT_RE.search(sql):
        new_sql = _CAST_FLOAT_RE.sub(r"CAST(\1 AS DECIMAL(18,2))", sql)
        if new_sql != sql:
            sql = new_sql
            corrections.append("CAST(... AS FLOAT) → CAST(... AS DECIMAL(18,2))")

    # Cas 2 : Arithmetic overflow → remplacer DECIMAL(18,x) par DECIMAL(38,x)
    if "overflow" in error_lower or "dépassement" in error_lower:
        pattern = re.compile(r"DECIMAL\s*\(\s*18\s*,\s*(\d+)\s*\)", re.IGNORECASE)
        new_sql = pattern.sub(r"DECIMAL(38,\1)", sql)
        if new_sql != sql:
            sql = new_sql
            corrections.append("DECIMAL(18,x) → DECIMAL(38,x) (overflow)")

    # Cas 3 : Si erreur datetime et qu'aucune correction programmatique n'a marché,
    # ajouter un hint YEAR()/MONTH() dans la description (mais corrected=False
    # car le SQL n'est pas réellement modifié — c'est juste un conseil)
    date_hint = ""
    if is_datetime_error and not corrections:
        # Regex large : match YYYY-MM-DD, YYYYMMDD, YYYY/MM/DD,
        # ou toute chaîne 8-10 chars qui ressemble à une date dans une comparaison
        date_comparison_re = re.compile(
            r"(?:"
            r"(?:>=|<=|>|<|=|BETWEEN)\s*'?\d{4}[-/]?\d{2}[-/]?\d{2}'?"
            r"|CONVERT\s*\(\s*datetime"
            r"|CAST\s*\([^)]*AS\s+datetime"
            r")",
            re.IGNORECASE,
        )
        if date_comparison_re.search(sql):
            date_hint = (
                "SUGGESTION : utilise YEAR(colonne) et MONTH(colonne) pour "
                "filtrer sur les dates au lieu de littéraux. "
                "Exemple : WHERE YEAR(col) >= 2023 AND "
                "(YEAR(col) > 2023 OR MONTH(col) >= 10). "
                "Alternative : CONVERT(datetime, 'YYYYMMDD', 112)."
            )

    if not corrections:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description=date_hint or "Aucun pattern de type mismatch reconnu dans le SQL",
            category="type_mismatch",
        )

    desc = " + ".join(corrections)
    if date_hint:
        desc += f" | {date_hint}"
    logger.info("Auto-correction type_mismatch: %s", desc)
    return AutoCorrectionResult(
        corrected=True,
        sql=sql,
        description=desc,
        category="type_mismatch",
    )


def _fix_having_vs_where(
    sql: str,
    classification: ErrorClassification,
) -> AutoCorrectionResult:
    """
    Déplace les conditions contenant des agrégats de WHERE vers HAVING.

    Détecte les conditions WHERE qui contiennent SUM/COUNT/AVG/etc.
    et les déplace dans une clause HAVING (existante ou nouvelle).
    """
    # Trouver la clause WHERE
    where_match = re.search(r"\bWHERE\b", sql, re.IGNORECASE)
    if not where_match:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description="Pas de clause WHERE trouvée",
            category="having_vs_where",
        )

    # Extraire le contenu entre WHERE et la prochaine clause principale
    after_where = sql[where_match.end() :]
    next_clause = re.search(
        r"\b(GROUP\s+BY|ORDER\s+BY|HAVING|UNION|EXCEPT|INTERSECT|OFFSET|FETCH)\b",
        after_where,
        re.IGNORECASE,
    )

    if next_clause:
        where_body = after_where[: next_clause.start()]
        rest = after_where[next_clause.start() :]
    else:
        where_body = after_where
        rest = ""

    # Séparer les conditions AND
    # Approche simple : split sur AND au top-level (pas dans les parenthèses)
    conditions = _split_conditions(where_body)

    where_conditions = []
    having_conditions = []

    for cond in conditions:
        if _HAS_AGGREGATE_RE.search(cond):
            having_conditions.append(cond.strip())
        else:
            where_conditions.append(cond.strip())

    if not having_conditions:
        return AutoCorrectionResult(
            corrected=False,
            sql=sql,
            description="Aucune condition avec agrégat trouvée dans WHERE",
            category="having_vs_where",
        )

    # Reconstruire le SQL
    before_where = sql[: where_match.start()]

    # WHERE reconstruit (ou supprimé si vide)
    if where_conditions:
        new_where = "WHERE " + " AND ".join(where_conditions)
    else:
        new_where = ""

    # HAVING existant ?
    having_match = re.search(r"\bHAVING\b", rest, re.IGNORECASE)
    if having_match:
        # Ajouter aux conditions HAVING existantes
        insert_pos = having_match.end()
        new_having_part = " " + " AND ".join(having_conditions) + " AND"
        rest = rest[:insert_pos] + new_having_part + rest[insert_pos:]
    else:
        # Insérer HAVING après GROUP BY (avant ORDER BY, ou à la fin)
        having_clause = " HAVING " + " AND ".join(having_conditions)
        order_in_rest = re.search(
            r"\b(ORDER\s+BY|UNION|EXCEPT|INTERSECT|OFFSET|FETCH)\b",
            rest,
            re.IGNORECASE,
        )
        if order_in_rest:
            insert_pos = order_in_rest.start()
            rest = rest[:insert_pos] + having_clause + " " + rest[insert_pos:]
        else:
            rest = rest + having_clause

    new_sql = before_where + new_where + " " + rest
    # Nettoyer les espaces multiples
    new_sql = re.sub(r"  +", " ", new_sql).strip()

    desc = f"{len(having_conditions)} condition(s) déplacée(s) de WHERE vers HAVING"
    logger.info("Auto-correction having_vs_where: %s", desc)
    return AutoCorrectionResult(
        corrected=True,
        sql=new_sql,
        description=desc,
        category="having_vs_where",
    )


def _split_conditions(where_body: str) -> list[str]:
    """
    Sépare les conditions d'un WHERE sur AND au top-level uniquement.

    Gère les parenthèses imbriquées (ne split pas à l'intérieur).
    Les OR restent dans leur bloc de condition.
    """
    # Trouver toutes les positions de AND au top-level (hors parenthèses)
    positions: list[tuple[int, int]] = []
    depth = 0
    body_upper = where_body.upper()
    i = 0

    while i < len(body_upper):
        ch = body_upper[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and body_upper[i : i + 3] == "AND":
            # Vérifier que c'est un mot entier (pas "ANDERSON")
            before_ok = i == 0 or not body_upper[i - 1].isalnum()
            after_pos = i + 3
            after_ok = after_pos >= len(body_upper) or not body_upper[after_pos].isalnum()
            if before_ok and after_ok:
                positions.append((i, after_pos))
        i += 1

    if not positions:
        return [where_body] if where_body.strip() else []

    conditions = []
    prev = 0
    for start, end in positions:
        cond = where_body[prev:start].strip()
        if cond:
            conditions.append(cond)
        prev = end

    # Dernière condition après le dernier AND
    last = where_body[prev:].strip()
    if last:
        conditions.append(last)

    return conditions


async def _find_column_in_views(
    column_name: str,
    known_columns: dict[str, set[str]],
) -> str:
    """Cherche si une colonne introuvable existe dans une vue.

    Quand une colonne n'existe pas dans la table de base (ex: grpCodeEntite
    dans Groupes), elle peut exister dans une vue consolidée (ex: viewGroupes01
    qui joint Groupes + Dossiers).

    Retourne un message d'aide si trouvée, chaîne vide sinon.
    """
    col_upper = column_name.upper()

    # 1. Chercher la colonne exacte dans toutes les tables/vues connues
    found_in: list[str] = []
    for table_name, cols in known_columns.items():
        if col_upper in {c.upper() for c in cols}:
            found_in.append(table_name)

    # Filtrer pour ne garder que les vues (préfixes courants SQL Server)
    views = [
        t
        for t in found_in
        if any(t.upper().startswith(p) for p in ("VIEW", "BOVIEW", "DBO_VIEW", "DBO_BOVIEW"))
    ]

    if views:
        view_list = ", ".join(views[:3])
        return (
            f"SUGGESTION : la colonne '{column_name}' existe dans la/les vue(s) : "
            f"{view_list}. Utilise la vue au lieu de la table de base."
        )

    # 2. Si pas trouvée par colonnes connues, chercher dans la documentation
    # view_composition (enrichissement du schéma) — requête directe en BDD
    try:
        from sqlalchemy import select as sa_select
        from app.models.training_data import TrainingData, TrainingDataType
        from app.core.database import get_session

        # Échapper les wildcards SQL pour éviter le wildcard injection
        escaped = column_name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        async with get_session() as session:
            result = await session.execute(
                sa_select(TrainingData.category, TrainingData.content).where(
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.category.like("view_composition:%"),
                    TrainingData.content.ilike(f"%{escaped}%", escape="\\"),
                )
            )
            rows = result.all()
            if rows:
                view_names = [row[0].split(":", 1)[1] for row in rows if ":" in row[0]]
                if view_names:
                    return (
                        f"SUGGESTION : vérifie les vues suivantes qui pourraient contenir "
                        f"'{column_name}' : {', '.join(view_names[:3])}. "
                        f"Utilise introspect_table sur ces vues pour confirmer."
                    )
    except Exception as exc:
        logger.debug("View search in training data failed: %s", exc)

    # 3. Si la colonne existe dans une table non-vue, mentionner quand même
    if found_in:
        table_list = ", ".join(found_in[:3])
        return (
            f"NOTE : la colonne '{column_name}' existe dans : {table_list}. "
            f"Vérifie que tu utilises la bonne table/vue."
        )

    return ""


async def _load_known_columns() -> dict[str, set[str]]:
    """Charge les colonnes connues depuis le TrainingStore (DDL)."""
    from sqlalchemy import select as sa_select
    from app.models.training_data import TrainingData, TrainingDataType
    from app.core.database import get_session

    known: dict[str, set[str]] = {}
    try:
        async with get_session() as session:
            result = await session.execute(
                sa_select(TrainingData.table_name, TrainingData.content).where(
                    TrainingData.data_type == TrainingDataType.DDL,
                    TrainingData.is_active == True,  # noqa: E712
                )
            )
            for tbl_name, ddl_content in result.all():
                cols = set()
                col_pattern = re.compile(r"^\s{2,}(\w+)\s+\w+", re.MULTILINE)
                skip = {"CONSTRAINT", "PRIMARY", "FOREIGN", "KEY", "INDEX", "UNIQUE", "CHECK"}
                for match in col_pattern.finditer(ddl_content):
                    col = match.group(1).upper()
                    if col not in skip:
                        cols.add(col)
                known[tbl_name.upper()] = cols
    except Exception as exc:
        logger.warning("Failed to load known columns for auto-corrector: %s", exc)

    return known
