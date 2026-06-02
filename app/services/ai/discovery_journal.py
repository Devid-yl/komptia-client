"""
Discovery Journal — Cahier de découvertes persistant pour Iris.

Stocke un résumé compact de ce que l'agent a appris pendant la conversation :
tables inspectées, colonnes clés, FK, valeurs vérifiées, SQL validés, erreurs.

Injecté dans le system prompt pour que le LLM ne perde pas le contexte
entre les messages même après compression de l'historique.

Task #97 — REFONTE-L4 (2026-05-22) : **zéro ID interne BDD émis dans le
Journal**. Vision GÉNÉRICITÉ Komptia (CLAUDE.md) : aucun ID hardcodé ne
doit traverser les conversations comme contexte du tour suivant. Cas
observé run #201 : ``F.facNoEnregDos=471`` hérité du tour précédent via
le Journal → Iris construit ses SQL sur l'ID interne du dossier au lieu
du ``dosNomDossier`` métier → anti-pattern généricité.

Mesures amont (pas de guard aval) :
1. Le champ ``last_sql`` (qui stockait le SQL complet du dernier
   execute_sql réussi) **est retiré**. Le LLM peut toujours référencer
   un SQL antérieur via l'historique conversation natif s'il en a
   besoin — pas via le Journal.
2. L'extraction des filtres WHERE **skip les comparaisons sur valeurs
   entières non quotées** (``col = 471``, ``col IN (12, 34, 56)``).
   Heuristique générique : un entier nu en SQL est presque toujours un
   ID interne (les codes métier sont quotés en TEXT, les années/mois
   passent par des fonctions ``YEAR()``/``MONTH()`` ou sont quotées).
   Faux positifs négligeables, faux négatifs minimaux.
"""

import logging
import re
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Limites pour garder le cahier compact (~2-3K tokens max)
_MAX_TABLES = 30
_MAX_RELATIONS = 30
_MAX_VALIDATED_SQL = 3
_MAX_ERRORS = 10
_MAX_VALUES = 30
_MAX_FILTERS = 20


def empty_journal() -> dict:
    """Structure vide du cahier.

    Task #97 (2026-05-22) : ``last_sql`` retiré — le SQL complet ne doit
    plus être ré-injecté tour-à-tour pour éviter la fuite d'IDs internes
    (cf. docstring module).
    """
    return {
        "tables": {},  # {table_name: [col1, col2, ...]} — colonnes clés
        "relations": [],  # ["<table_A>.<col_fk> → <table_B>.<col_pk>"]
        "values": [],  # ["<table>.<col> contient '<valeur>' (N match)"]
        "validated_sql": [],  # [{"q": "description", "rows": N}] — résumé métier seulement, PAS le SQL brut
        "filters": [],  # ["[<colonne>] IN ('<val_A>')", "[<colonne>] IN ('<val_B>')"] — métier uniquement, IDs filtrés
        "errors": [],  # ["<col_fautive> n'existe pas → utiliser <col_correcte>"]
    }


def update_from_tool_result(
    journal: dict,
    tool_name: str,
    tool_input: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> bool:
    """
    Met à jour le cahier avec les découvertes d'un tool call.

    Returns True si le cahier a été modifié.
    """
    if not isinstance(tool_result, dict):
        return False
    if not tool_result.get("success", True):
        # Erreur — enregistrer si c'est une erreur de colonne/table
        return _record_error(journal, tool_name, tool_input, tool_result)

    changed = False

    if tool_name == "introspect_table":
        changed = _record_introspect(journal, tool_input, tool_result)

    elif tool_name == "search_schema":
        changed = _record_search(journal, tool_input, tool_result)

    elif tool_name == "get_fk_path":
        changed = _record_fk_path(journal, tool_input, tool_result)

    elif tool_name == "execute_sql":
        changed = _record_execute_sql(journal, tool_input, tool_result)

    elif tool_name == "test_sql":
        changed = _record_test_sql(journal, tool_input, tool_result)

    elif tool_name == "get_resolved_values":
        changed = _record_resolved_values(journal, tool_input, tool_result)

    return changed


def format_for_prompt(journal: dict) -> str:
    """Formate le cahier en texte compact pour injection dans le system prompt."""
    if not journal:
        return ""

    parts = []

    # Tables et colonnes
    tables = journal.get("tables", {})
    if tables:
        lines = []
        for tname, cols in list(tables.items())[:_MAX_TABLES]:
            cols_str = ", ".join(cols[:15])
            if len(cols) > 15:
                cols_str += f" (+{len(cols)-15})"
            lines.append(f"  {tname}({cols_str})")
        parts.append("Tables inspectées :\n" + "\n".join(lines))

    # Relations
    relations = journal.get("relations", [])
    if relations:
        parts.append("Relations :\n  " + "\n  ".join(relations[:_MAX_RELATIONS]))

    # Valeurs vérifiées
    values = journal.get("values", [])
    if values:
        parts.append("Valeurs vérifiées :\n  " + "\n  ".join(values[:_MAX_VALUES]))

    # Filtres WHERE validés (critique pour ne pas confondre les colonnes)
    filters = journal.get("filters", [])
    if filters:
        parts.append(
            "Filtres WHERE validés (utilise EXACTEMENT ces correspondances colonne=valeur) :\n  "
            + "\n  ".join(filters[:_MAX_FILTERS])
        )

    # SQL validés
    validated = journal.get("validated_sql", [])
    if validated:
        lines = []
        for v in validated[:_MAX_VALIDATED_SQL]:
            lines.append(f"  ✓ {v.get('q', '?')} → {v.get('rows', '?')} lignes")
        parts.append("SQL validés :\n" + "\n".join(lines))

    # Task #97 (2026-05-22) : bloc « Dernier SQL exécuté » RETIRÉ. Le SQL
    # complet était re-injecté tour-à-tour comme contexte → fuites d'IDs
    # internes (cf. docstring module). Le LLM peut toujours référencer un
    # SQL antérieur via l'historique conversation natif s'il en a besoin.
    # NE PAS ressusciter sans solution de sanitisation amont des IDs.

    # Erreurs corrigées
    errors = journal.get("errors", [])
    if errors:
        parts.append("Erreurs corrigées :\n  " + "\n  ".join(errors[:_MAX_ERRORS]))

    if not parts:
        return ""

    return "## Découvertes de cette conversation\n\n" + "\n\n".join(parts)


# --- Handlers par outil ---


def _record_introspect(journal: dict, tool_input: dict, result: dict) -> bool:
    """Enregistre les colonnes et FK d'une table inspectée."""
    table = tool_input.get("table_name", "")
    if not table:
        return False

    # Colonnes
    columns = result.get("columns") or result.get("table_columns") or []
    if isinstance(columns, list):
        col_names = []
        for c in columns:
            if isinstance(c, dict):
                col_names.append(c.get("name", c.get("column_name", "")))
            elif isinstance(c, str):
                col_names.append(c)
        col_names = [c for c in col_names if c]
        if col_names:
            journal["tables"][table] = col_names

    # FK sortantes
    for fk in result.get("fk_outgoing", []):
        tgt = fk.get("table", "")
        src_col = fk.get("fk_column", "")
        tgt_col = fk.get("column", "")
        if tgt and src_col and tgt_col:
            rel = f"{table}.{src_col} → {tgt}.{tgt_col}"
            if rel not in journal["relations"]:
                journal["relations"].append(rel)

    # FK entrantes
    for fk in result.get("fk_incoming", []):
        src = fk.get("table", "")
        src_col = fk.get("column", "")
        tgt_col = fk.get("fk_column", "")
        if src and src_col and tgt_col:
            rel = f"{src}.{src_col} → {table}.{tgt_col}"
            if rel not in journal["relations"]:
                journal["relations"].append(rel)

    return True


def _record_search(journal: dict, tool_input: dict, result: dict) -> bool:
    """Enregistre les correspondances trouvées par search_schema."""
    matches = result.get("matches") or result.get("results") or []
    if not matches:
        return False

    tool_input.get("keywords", [])
    changed = False
    for m in matches[:5]:
        if not isinstance(m, dict):
            continue
        table = m.get("table") or m.get("table_name", "")
        col = m.get("column") or m.get("column_name", "")
        if table and col:
            # Ajouter la table si pas encore connue
            if table not in journal["tables"]:
                journal["tables"][table] = []
            if col not in journal["tables"][table]:
                journal["tables"][table].append(col)
                changed = True

    return changed


def _record_fk_path(journal: dict, tool_input: dict, result: dict) -> bool:
    """Enregistre un chemin FK découvert."""
    path = result.get("path") or []
    join_template = result.get("join_template", "")
    tool_input.get("from_table", "")
    tool_input.get("to_table", "")

    if not path and not join_template:
        return False

    for edge in path:
        src = edge.get("source", "")
        tgt = edge.get("target", "")
        src_col = edge.get("src_col", "")
        tgt_col = edge.get("tgt_col", "")
        if src and tgt and src_col and tgt_col:
            rel = f"{src}.{src_col} → {tgt}.{tgt_col}"
            if rel not in journal["relations"]:
                journal["relations"].append(rel)

    return True


def _record_execute_sql(journal: dict, tool_input: dict, result: dict) -> bool:
    """Enregistre un SQL exécuté avec succès + extrait les filtres WHERE.

    Task #97 (2026-05-22) : le SQL complet n'est PLUS stocké (``last_sql``
    retiré). Seul un résumé métier `{q, rows}` reste dans ``validated_sql``.
    Évite de re-injecter des IDs internes au tour suivant.
    """
    sql = tool_input.get("sql", "")
    explanation = tool_input.get("explanation", "")
    row_count = result.get("row_count", 0)

    if not sql or row_count is None:
        return False

    # Enregistrer dans la liste des SQL validés (résumé). Si pas
    # d'explication métier (mauvais usage du tool), on ne stocke pas le
    # SQL brut comme placeholder — on met un libellé neutre. Le LLM peut
    # consulter l'historique conv natif pour le SQL exact.
    entry = {
        "q": (explanation[:100] if explanation else f"(SQL sans description — {row_count} lignes)"),
        "rows": row_count,
    }
    journal["validated_sql"] = journal.get("validated_sql", [])[-(_MAX_VALIDATED_SQL - 1) :] + [
        entry
    ]

    # Extraire les filtres WHERE pour que le LLM sache
    # quelle valeur va sur quelle colonne — IDs internes filtrés
    # automatiquement (cf. _extract_where_filters / _is_id_like_filter).
    _extract_where_filters(journal, sql)

    return True


def _looks_like_int_literal(val: Any) -> bool:
    """True si ``val`` représente un littéral entier (typed ou stringifié).

    Couvre 3 cas :
    1. ``int`` Python pur (sqlglot émet ce type pour ``... = 471``)
    2. ``bool`` exclu (sous-classe de int en Python — un flag ``True/False``
       n'est PAS un ID interne)
    3. ``str`` matchant un entier signé (cas adversarial #C2 : Iris peut
       quoter un ID — ``... = '471'`` — par habitude ou parce que la
       colonne est nvarchar côté SGBD source. sqlglot retourne alors
       le ``raw`` string).
    """
    if isinstance(val, bool):
        return False
    if isinstance(val, int):
        return True
    if isinstance(val, str):
        stripped = val.strip()
        if stripped and re.fullmatch(r"-?\d+", stripped):
            return True
    return False


def _is_id_like_filter(predicate) -> bool:
    """True si le prédicat est un filtre sur ID interne probable.

    Task #97 — heuristique générique (pas de pattern de colonne hardcodé
    pour un SGBD spécifique) :
    - opérateur ``=`` ou ``IN`` / ``NOT IN`` (les IDs sont comparés en
      égalité ou exclusion ensembliste, pas en range/LIKE — un filtre
      ``id > 100`` reste métier-plausible)
    - ET valeur(s) entière(s), qu'elles soient typed ``int`` ou quotées
      en string (``'471'``). Adversarial #C2 (2026-05-22) : Iris peut
      quoter un ID par habitude ou si la colonne est ``nvarchar`` — le
      filtre s'applique aussi à ce cas.

    Faux positifs possibles : ``WHERE Mois = 12``, ``WHERE statut = 1``
    — filtres métier sur entier seraient skipés. Trade-off accepté :
    ces filtres sont souvent récurrents et reconstructibles ; un
    faux négatif (ID interne hérité) est bien plus toxique
    qu'un faux positif (filtre récurrent re-saisi par le LLM).

    Note : ``NOT IN`` est traité comme ``IN`` (adversarial #C1) — sqlglot
    porte la négation via l'attribut ``negated`` séparé, l'opérateur reste
    ``"IN"``. Le bug pré-fix : ``NOT IN (1, 2, 3)`` (exclusion d'IDs
    internes) leak vs `regex fallback qui skip. Maintenant cohérent.
    """
    if predicate is None:
        return False
    op = (getattr(predicate, "operator", "") or "").upper()
    if op not in ("=", "IN"):
        return False
    val = getattr(predicate, "value", None)
    if _looks_like_int_literal(val):
        return True
    if isinstance(val, list) and val and all(_looks_like_int_literal(v) for v in val):
        return True
    return False


def _extract_where_filters(journal: dict, sql: str):
    """Extrait les conditions WHERE du SQL et les stocke dans le journal.

    Utilise sqlglot (parser robuste) pour couvrir BETWEEN, IS NULL,
    comparaisons numériques, NOT, parenthèses. Fallback regex si
    sqlglot échoue (SQL mal formé, dialect inconnu).

    Task #97 (2026-05-22) — les filtres jugés « ID interne probable »
    par ``_is_id_like_filter`` sont **silencieusement skipés** pour ne
    pas être ré-injectés dans le prompt du tour suivant. C'est de
    l'ingénierie amont (la donnée n'entre jamais dans le Journal,
    aucune sanitisation aval n'est nécessaire).
    """
    if "filters" not in journal:
        journal["filters"] = []

    # Tentative via sqlglot (B10 : parser structuré, plus complet).
    # On utilise extract_filters_from_sql() pour récupérer les FilterPredicate
    # typés et appliquer le filtre _is_id_like_filter AVANT formatage.
    try:
        from app.services.ai.filter_extractor import (
            extract_filters_from_sql,
            _format_for_journal,
        )

        predicates = extract_filters_from_sql(sql, dialect="tsql")
        if predicates:
            for pred in predicates:
                if _is_id_like_filter(pred):
                    logger.debug(
                        "Journal: filtre ID-interne skipé (task #97) — "
                        "col=%s op=%s val=%r",
                        getattr(pred, "column", "?"),
                        getattr(pred, "operator", "?"),
                        getattr(pred, "value", "?"),
                    )
                    continue
                entry = _format_for_journal(pred)
                if entry and entry not in journal["filters"]:
                    journal["filters"].append(entry)
            journal["filters"] = journal["filters"][-_MAX_FILTERS:]
            return
    except Exception as exc:
        logger.debug("sqlglot filter extraction failed, fallback regex: %s", exc)

    # Fallback regex : patterns basiques (IN, =, LIKE) si sqlglot indispo.
    # Le filtre IDs s'applique aussi ici via détection de littéraux
    # numériques bruts dans la cellule IN/=.
    where_match = re.search(
        r"\bWHERE\b(.+?)(?:\bGROUP\b|\bORDER\b|\bHAVING\b|$)",
        sql,
        re.IGNORECASE | re.DOTALL,
    )
    if not where_match:
        return

    where_clause = where_match.group(1)

    for m in re.finditer(
        r"\[?(\w+)\]?\s+(?:NOT\s+)?IN\s*\(([^)]+)\)",
        where_clause,
        re.IGNORECASE,
    ):
        col = m.group(1)
        vals = m.group(2).strip()
        # Adversarial #SU1 : si la cellule IN contient une sous-requête
        # (``IN (SELECT ...)``), ne pas tenter de classifier — on
        # n'a pas accès aux valeurs littérales. On laisse la regex
        # produire l'entrée (l'extraction sqlglot path fait mieux ;
        # ce fallback est best-effort).
        if re.search(r"\bSELECT\b", vals, re.IGNORECASE):
            pass  # laisse le formattage standard ci-dessous
        # Task #97 — skip si la cellule IN ne contient QUE des entiers
        # non quotés (ex: "471", "12, 34, 56"). Si une quote apparaît
        # ou un opérateur non-numérique → métier, on garde.
        elif re.fullmatch(r"\s*-?\d+(\s*,\s*-?\d+)*\s*", vals):
            logger.debug(
                "Journal: filtre IN ID-interne skipé (task #97, regex fallback) — "
                "col=%s vals=%s",
                col,
                vals,
            )
            continue
        not_prefix = "NOT " if "NOT" in m.group(0).upper().split("IN")[0] else ""
        entry = f"[{col}] {not_prefix}IN ({vals})"
        if entry not in journal["filters"]:
            journal["filters"].append(entry)

    # `=` quoté : déjà filtré (les '...' indiquent une string littérale)
    for m in re.finditer(
        r"\[?(\w+)\]?\s*(=|LIKE|NOT LIKE)\s*'([^']*)'",
        where_clause,
        re.IGNORECASE,
    ):
        col, op, val = m.group(1), m.group(2), m.group(3)
        entry = f"[{col}] {op} '{val}'"
        if entry not in journal["filters"]:
            journal["filters"].append(entry)

    # Task #97 — détecter aussi `col = <int>` non quoté en fallback et le skip
    for m in re.finditer(
        r"\[?(\w+)\]?\s*=\s*(-?\d+)(?!\s*[\.\d'])",
        where_clause,
        re.IGNORECASE,
    ):
        col, val = m.group(1), m.group(2)
        logger.debug(
            "Journal: filtre '=' ID-interne skipé (task #97, regex fallback) — "
            "col=%s val=%s",
            col,
            val,
        )
        # SKIP — pas d'ajout à journal["filters"]

    journal["filters"] = journal["filters"][-_MAX_FILTERS:]


def _record_test_sql(journal: dict, tool_input: dict, result: dict) -> bool:
    """Enregistre un test SQL count."""
    count = result.get("count", -1)
    if count < 0:
        return False
    # Pas d'enregistrement permanent — le count est utile en live mais pas en résumé
    return False


def _record_resolved_values(journal: dict, tool_input: dict, result: dict) -> bool:
    """Enregistre des valeurs vérifiées."""
    term = tool_input.get("term", "")
    table = tool_input.get("table_name", "")
    column = tool_input.get("column_name", "")
    matches = result.get("matches", [])

    if not term or not matches:
        return False

    entry = f"{table}.{column} contient '{term}' ({len(matches)} match)"
    if entry not in journal["values"]:
        journal["values"].append(entry)
    return True


def _record_error(journal: dict, tool_name: str, tool_input: dict, result: dict) -> bool:
    """Enregistre une erreur pour que le LLM ne la répète pas."""
    error = result.get("error", "")
    if not error:
        return False

    # Extraire les colonnes inexistantes si mentionnées
    error_lower = error.lower()
    if "colonne" in error_lower or "column" in error_lower or "inexistant" in error_lower:
        entry = f"Erreur {tool_name}: {error[:150]}"
        if entry not in journal["errors"]:
            journal["errors"].append(entry)
            # Garder seulement les dernières erreurs
            journal["errors"] = journal["errors"][-_MAX_ERRORS:]
            return True

    return False
