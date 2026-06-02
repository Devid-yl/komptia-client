"""Charge un classeur ``.afz.json`` depuis le storage et le convertit au format
attendu par ``run_copilot_agent`` (``tabs_context`` + ``sheet_content`` actif).

**Pourquoi ce module existe**

Le frontend envoyait jusqu'ici tout le ``tabs_context`` inline dans le body
POST ``/api/iris/result-modify``. Pour des classeurs gigantesques (100 MiB+
de JSON, type Excel Online), ça satureait le body et l'event-loop Tornado.
Solution : le frontend envoie un ``workbook_path`` (rel_path dans son
datastore) ; le backend lit le ``.afz.json`` depuis le disque (qui n'a pas
de cap réseau) et reconstruit le contexte.

**Parité avec le frontend**

Le module reproduit la logique de ``_getTabsContext`` /
``_classifyColumnsForSqlTab`` de ``static/js/iris-grid.js`` (l. 10313+ /
10582+) — c'est ce qui structure ce que le LLM voit. Tout écart serait une
régression sémantique sur les outils ``aggregate`` / ``count_rows`` qui
filtrent sur ``cell.match``.

**Sécurité**

Le ``rel_path`` reçu du body est validé via ``app.handlers.datastore.
_safe_path`` (anti path-traversal). L'appelant doit toujours passer le
``user_id`` du token auth — un user A ne peut pas lire le datastore d'un
user B même s'il devine son ``rel_path``.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.handlers.datastore import _safe_path, _user_dir

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constantes (alignées sur le frontend ``_getTabsContext``)
# ---------------------------------------------------------------------------

#: Nombre max de valeurs distinctes listées par colonne textuelle dans
#: ``col_distinct``. Au-delà : ``truncated=True``. Aligné sur
#: ``MAX_DISTINCT`` du frontend.
_COL_DISTINCT_MAX_VALUES = 30

#: Limite de scan des rows pour calculer ``col_distinct`` — protège contre
#: les onglets gigantesques (1M+ rows). Aligné sur ``MAX_SCAN_ROWS``.
_COL_DISTINCT_SCAN_LIMIT = 5000

#: Budget total de chars pour ``col_distinct`` (toutes colonnes confondues).
#: Empêche un onglet à 200 colonnes textuelles d'exploser le prompt LLM.
_COL_DISTINCT_TOTAL_CHARS = 4000

#: Cap des cellules-mesure émises pour un onglet SQL non-actif. Le backend
#: ``_recompute_emit_tab`` itère le ``sheet_content`` complet pour retrouver
#: les matches → garder un cap large évite de perdre des rows et de générer
#: de faux ``no_source``. Aligné sur ``SIBLING_MAX_CELLS_SQL`` frontend.
_SIBLING_MAX_CELLS_SQL = 6000

#: Cap des cellules de label (string) pour un onglet non-SQL non-actif.
_SIBLING_MAX_LABEL_CELLS = 2000

#: Cap des cellules numériques pour un onglet non-SQL non-actif.
_SIBLING_MAX_NUMERIC_CELLS = 500

#: Limite de scan pour la classification dims/measures heuristique. Aligné
#: sur ``sampleLimit = min(n, 1000)``.
_CLASSIFY_SAMPLE_LIMIT = 1000

#: Seuil de pureté numérique : une colonne est "majoritairement numérique"
#: si non-numéric ≤ 5% du nombre de valeurs numériques.
_MOSTLY_NUMERIC_NON_NUM_RATIO = 0.05

#: Heuristique cardinalité : une colonne numérique ≤ N valeurs distinctes
#: OU ≤ 5% du sample est traitée comme dimension (plutôt que mesure).
_HEURISTIC_DIM_MAX_DISTINCT = 50
_HEURISTIC_DIM_DISTINCT_RATIO = 0.05


# ---------------------------------------------------------------------------
# Helpers de lecture et conversion d'une cellule
# ---------------------------------------------------------------------------


def _coerce_number_or_str(value: Any) -> Tuple[Any, bool]:
    """Replique ``Number(s)`` / ``isFinite`` JS pour une valeur de cell.

    Retourne ``(coerced, is_numeric)`` :
    - ``coerced`` : ``int`` ou ``float`` si la valeur représente un nombre fini,
      sinon la string trimée.
    - ``is_numeric`` : True si la valeur est un nombre fini.

    Pourquoi pas un simple ``isinstance(v, (int, float))`` : les rows du
    ``.afz.json`` peuvent contenir des strings sérialisées ("125.0", "2024")
    quand le frontend a fait un import CSV ou un cast quelconque. Le
    frontend appelle ``Number(s)`` sur tout, donc on suit la même règle
    pour préserver la parité.
    """
    if isinstance(value, bool):
        # bool est sous-classe de int en Python — on l'exclut explicitement
        # pour rester cohérent avec JS qui ne convertit pas les bool en
        # number dans ce contexte.
        return value, False
    if isinstance(value, (int, float)):
        # NaN / inf : pas un nombre exploitable.
        if value != value or value in (float("inf"), float("-inf")):
            return value, False
        return value, True
    if not isinstance(value, str):
        return value, False
    s = value.strip()
    if not s:
        return s, False
    # ``Number("1abc")`` retourne NaN en JS ; en Python il faut un test
    # explicite. On accepte les notations standard incluant les flottants.
    try:
        n = float(s)
    except ValueError:
        return s, False
    if n != n or n in (float("inf"), float("-inf")):
        return s, False
    # Si le string représente un entier sans partie décimale, on retourne
    # int — fidélité : le frontend retourne un Number, ici on évite que
    # ``2024`` devienne ``2024.0`` dans le ``match`` (différencie matches
    # exact ``annee=2024`` vs ``annee=2024.0``). Le test
    # ``/^-?\d+(\.\d+)?$/`` du frontend distingue aussi.
    if re.match(r"^-?\d+$", s):
        return int(s), True
    return n, True


def _row_value(row: Any, col_index: int, col_name: str, is_array_format: bool) -> Any:
    """Retourne ``row[col_index]`` (array) ou ``row[col_name]`` (dict)."""
    if is_array_format:
        if isinstance(row, list) and 0 <= col_index < len(row):
            return row[col_index]
        return None
    if isinstance(row, dict):
        return row.get(col_name)
    return None


# ---------------------------------------------------------------------------
# Classification colonnes-dimensions vs colonnes-mesures
# ---------------------------------------------------------------------------


def _extract_top_level_group_by(sql: str) -> str:
    """Retourne la clause ``GROUP BY`` de profondeur 0 (hors sous-requêtes).

    Le frontend ``_classifyColumnsForSqlTab`` cherche la **dernière**
    occurrence ``GROUP BY`` au depth 0 — important pour les SQL avec CTEs
    (WITH ... AS (... GROUP BY ...) SELECT ... GROUP BY ...) où seule la
    GROUP BY finale concerne les colonnes de l'onglet.
    """
    if not sql:
        return ""
    last_start = -1
    depth = 0
    # On parcourt en gardant trace de la profondeur ; à chaque match
    # ``GROUP BY`` on note la position si on est à depth 0.
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth -= 1
            i += 1
            continue
        if depth == 0 and ch.upper() == "G":
            # Test "GROUP BY" insensible à la casse ; on demande un caractère
            # frontière avant et un \s+ après "GROUP".
            if i + 8 <= n and sql[i : i + 5].upper() == "GROUP" and sql[i + 5].isspace():
                # Skip whitespace puis test "BY"
                j = i + 6
                while j < n and sql[j].isspace():
                    j += 1
                if (
                    j + 2 <= n
                    and sql[j : j + 2].upper() == "BY"
                    and (j + 2 == n or not sql[j + 2].isalnum() and sql[j + 2] != "_")
                ):
                    last_start = j + 2
        i += 1
    if last_start == -1:
        return ""
    tail = sql[last_start:]
    # Fin de clause : ORDER BY | HAVING | ; | fin du sql.
    end_match = re.search(r"\bORDER\s+BY\b|\bHAVING\b|;", tail, re.IGNORECASE)
    end_idx = end_match.start() if end_match else len(tail)
    return tail[:end_idx]


def _parse_group_by_columns(group_by_clause: str, columns: List[str]) -> Optional[Dict[str, bool]]:
    """Extrait les colonnes-dimensions déclarées dans le ``GROUP BY``.

    Retourne ``{col_lower: True}`` ou ``None`` si la clause ne donne aucune
    colonne résolvable (cas d'expressions pures type ``GROUP BY YEAR(d)``).
    """
    if not group_by_clause.strip():
        return None
    declared: Dict[str, bool] = {}
    for raw in group_by_clause.split(","):
        expr = raw.strip()
        if not expr:
            continue
        # GROUP BY positionnel : "GROUP BY 1, 2"
        if re.match(r"^\d+$", expr):
            pos = int(expr) - 1
            if 0 <= pos < len(columns):
                declared[columns[pos].lower()] = True
            continue
        # Expression (fonction) : skip — l'heuristique cardinalité prendra
        # le relais sur les colonnes correspondantes.
        if "(" in expr or ")" in expr:
            continue
        # Strip qualifier ``T.col`` et délimiteurs ``"col"`` / ``[col]`` /
        # ``` `col` ```.
        bare = re.sub(r"^[^.\s()]+\.", "", expr)
        bare = re.sub(r"[`\"\[\]]", "", bare).strip()
        if bare:
            declared[bare.lower()] = True
    return declared or None


def _classify_columns_for_sql_tab(
    sql: str,
    columns: List[str],
    rows: List[Any],
    is_array_format: bool,
) -> Tuple[List[str], List[str]]:
    """Sépare les colonnes en ``dims`` vs ``measures``.

    Replique fidèlement ``_classifyColumnsForSqlTab`` du frontend :

    1. Si un ``GROUP BY`` au depth 0 existe et expose au moins UNE colonne
       résolvable, les colonnes du GROUP BY sont des dims, le reste sont
       des measures.
    2. Sinon (pas de GROUP BY OU clause uniquement composée d'expressions) :
       heuristique cardinalité — string ou numeric basse-cardinalité = dim,
       numeric haute-cardinalité = measure.
    """
    declared_dims = _parse_group_by_columns(_extract_top_level_group_by(sql), columns)

    dims: List[str] = []
    measures: List[str] = []
    sample_limit = min(len(rows), _CLASSIFY_SAMPLE_LIMIT)

    for ci, col_name in enumerate(columns):
        if declared_dims is not None:
            if col_name.lower() in declared_dims:
                dims.append(col_name)
            else:
                measures.append(col_name)
            continue

        # Heuristique cardinalité.
        uniques: set = set()
        num_count = 0
        non_num_count = 0
        for ri in range(sample_limit):
            value = _row_value(rows[ri], ci, col_name, is_array_format)
            if value is None or value == "":
                continue
            s = str(value).strip()
            if not s:
                continue
            _, is_num = _coerce_number_or_str(s)
            if is_num:
                num_count += 1
            else:
                non_num_count += 1
            uniques.add(s)
        uq = len(uniques)
        is_mostly_numeric = (
            num_count > 0 and non_num_count <= num_count * _MOSTLY_NUMERIC_NON_NUM_RATIO
        )
        if not is_mostly_numeric:
            dims.append(col_name)
        elif (
            uq <= _HEURISTIC_DIM_MAX_DISTINCT or uq <= sample_limit * _HEURISTIC_DIM_DISTINCT_RATIO
        ):
            dims.append(col_name)
        else:
            measures.append(col_name)

    return dims, measures


# ---------------------------------------------------------------------------
# col_distinct (vocabulaire de chaque colonne pour le LLM)
# ---------------------------------------------------------------------------


def _compute_col_distinct(
    columns: List[str],
    rows: List[Any],
    is_array_format: bool,
) -> Dict[str, Dict[str, Any]]:
    """Calcule ``col_distinct`` — pour chaque colonne, soit une description
    numérique ``{type:'numeric', min, max, distinct}`` soit une description
    textuelle ``{type:'text', values, distinct, truncated}``.

    Replique fidèlement la logique du frontend (cf. ``_getTabsContext``
    l. 10341+) : scan jusqu'à ``_COL_DISTINCT_SCAN_LIMIT``, budget total
    de ``_COL_DISTINCT_TOTAL_CHARS`` chars, top ``_COL_DISTINCT_MAX_VALUES``
    par colonne textuelle.
    """
    if not rows:
        return {}
    scan_limit = min(len(rows), _COL_DISTINCT_SCAN_LIMIT)
    col_distinct: Dict[str, Dict[str, Any]] = {}
    total_chars = 0

    for ci, col_name in enumerate(columns):
        if total_chars >= _COL_DISTINCT_TOTAL_CHARS:
            break
        vals: set = set()
        num_count = 0
        non_num_count = 0
        num_min = float("inf")
        num_max = float("-inf")
        for ri in range(scan_limit):
            v = _row_value(rows[ri], ci, col_name, is_array_format)
            if v is None or v == "":
                continue
            s = str(v).strip()
            if not s:
                continue
            n, is_num = _coerce_number_or_str(s)
            if is_num:
                num_count += 1
                # n peut être int ou float ici
                fn = float(n)
                if fn < num_min:
                    num_min = fn
                if fn > num_max:
                    num_max = fn
            else:
                non_num_count += 1
            vals.add(s)
        unique_count = len(vals)
        if unique_count == 0:
            continue

        is_numeric = num_count > 0 and non_num_count <= num_count * _MOSTLY_NUMERIC_NON_NUM_RATIO
        if is_numeric:
            desc_len = (
                len(col_name)
                + len(": numeric (min=, max=,  distinct)")
                + len(str(num_min))
                + len(str(num_max))
                + len(str(unique_count))
            )
            total_chars += desc_len
            col_distinct[col_name] = {
                "type": "numeric",
                "min": num_min,
                "max": num_max,
                "distinct": unique_count,
            }
        else:
            sliced = sorted(vals)[:_COL_DISTINCT_MAX_VALUES]
            desc_len = len(col_name) + len(": ") + sum(len(s) + 2 for s in sliced)
            total_chars += desc_len
            col_distinct[col_name] = {
                "type": "text",
                "values": sliced,
                "distinct": unique_count,
                "truncated": unique_count > _COL_DISTINCT_MAX_VALUES,
            }

    return col_distinct


# ---------------------------------------------------------------------------
# sheet_content (sparse avec match) pour onglets SQL et non-SQL
# ---------------------------------------------------------------------------


def _build_sheet_content_sql(
    columns: List[str],
    rows: List[Any],
    is_array_format: bool,
    dims: List[str],
    measures: List[str],
    max_cells: int = _SIBLING_MAX_CELLS_SQL,
) -> Tuple[List[Dict[str, Any]], bool]:
    """Génère le ``sheet_content`` sparse pour un onglet SQL.

    Pour chaque row : 1 cellule par mesure avec ``match`` = dimensions de
    cette row. Permet aux outils ``aggregate``/``count_rows`` du copilot
    de filtrer/sommer sans réexécuter le SQL.

    Retourne ``(cells, truncated)``.
    """
    out: List[Dict[str, Any]] = []
    truncated = False
    if not rows or not measures:
        return out, False
    col_index_by_name = {c: i for i, c in enumerate(columns)}

    for ri, row in enumerate(rows):
        if truncated:
            break
        # Construit le match de cette row (dims uniquement).
        row_match: Dict[str, Any] = {}
        for d_col in dims:
            d_ci = col_index_by_name.get(d_col, -1)
            if d_ci < 0:
                continue
            d_val = _row_value(row, d_ci, d_col, is_array_format)
            if d_val is None or d_val == "":
                continue
            d_str = str(d_val).strip()
            if not d_str:
                continue
            n, is_num = _coerce_number_or_str(d_str)
            row_match[d_col] = n if is_num else d_str

        for m_col in measures:
            m_ci = col_index_by_name.get(m_col, -1)
            if m_ci < 0:
                continue
            m_val = _row_value(row, m_ci, m_col, is_array_format)
            if m_val is None or m_val == "":
                continue
            m_str = str(m_val).strip() if isinstance(m_val, str) else str(m_val)
            if not m_str:
                continue
            n, is_num = _coerce_number_or_str(m_str if isinstance(m_val, str) else m_val)
            if not is_num:
                continue
            if len(out) >= max_cells:
                truncated = True
                break
            out.append(
                {
                    "row": ri + 1,
                    "col": m_col,
                    "value": n,
                    "match": dict(row_match),
                }
            )

    return out, truncated


def _build_sheet_content_non_sql(
    columns: List[str],
    rows: List[Any],
    is_array_format: bool,
    cell_details: Optional[Dict[str, Dict[str, Any]]],
    max_label: int = _SIBLING_MAX_LABEL_CELLS,
    max_numeric: int = _SIBLING_MAX_NUMERIC_CELLS,
) -> Tuple[List[Dict[str, Any]], bool, bool]:
    """Génère le ``sheet_content`` pour un onglet non-SQL (template, xlsx,
    dashboard).

    Tronquage **sélectif par rôle** : cellules avec ``cellDetails`` jamais
    tronquées (drill-down précieux), labels (string) cap à ``max_label``,
    numériques cap à ``max_numeric``.

    Retourne ``(cells, label_truncated, numeric_truncated)``.
    """
    out: List[Dict[str, Any]] = []
    label_count = 0
    numeric_count = 0
    label_truncated = False
    numeric_truncated = False
    cell_details = cell_details or {}

    for ri, row in enumerate(rows):
        for ci, col_name in enumerate(columns):
            v = _row_value(row, ci, col_name, is_array_format)
            # Frontend : ``if (!sv && sv !== 0) continue``
            if v is None or v == "":
                continue
            v_str = str(v) if not isinstance(v, str) else v
            v_trim = v_str.strip()
            if not v_trim:
                continue
            detail_key = f"{ri},{ci}"
            detail = cell_details.get(detail_key) if isinstance(cell_details, dict) else None
            has_detail = bool(
                detail
                and isinstance(detail, dict)
                and (
                    detail.get("sql")
                    or detail.get("match")
                    or detail.get("label")
                    or detail.get("description")
                )
            )
            _, is_numeric = _coerce_number_or_str(v if isinstance(v, (int, float)) else v_trim)
            if not has_detail:
                if is_numeric:
                    if numeric_count >= max_numeric:
                        numeric_truncated = True
                        continue
                    numeric_count += 1
                else:
                    if label_count >= max_label:
                        label_truncated = True
                        continue
                    label_count += 1
            entry: Dict[str, Any] = {
                "row": ri + 1,
                "col": col_name,
                "value": v_str,
            }
            if detail:
                if detail.get("sql"):
                    entry["source_sql"] = detail["sql"]
                if detail.get("match"):
                    entry["match"] = detail["match"]
                lbl = detail.get("label") or detail.get("description")
                entry["label"] = lbl
            out.append(entry)

    return out, label_truncated, numeric_truncated


# ---------------------------------------------------------------------------
# Entrée publique : load_workbook_for_copilot
# ---------------------------------------------------------------------------


def _resolve_workbook_path(user_id: int, rel_path: str) -> Optional[Path]:
    """Valide ``rel_path`` côté ``user_id`` et retourne un Path absolu, ou
    ``None`` si le path est invalide / hors-scope user.

    Wrapper autour de ``_safe_path`` qui vérifie en plus l'extension et
    l'existence du fichier (les deux contrôles sont avant la lecture pour
    fail-fast avec un message clair côté caller).
    """
    if not isinstance(rel_path, str) or not rel_path.strip():
        return None
    user_dir = _user_dir(user_id)
    target = _safe_path(user_dir, rel_path.strip())
    if target is None:
        return None
    if target.suffix not in (".json",) or not str(target).endswith(".afz.json"):
        # L'app ne lit que des classeurs Komptia ``.afz.json``. Tout autre
        # fichier (config, csv, etc.) est rejeté — fail-closed.
        return None
    if not target.is_file():
        return None
    return target


def load_workbook_for_copilot(
    user_id: int,
    rel_path: str,
) -> Optional[Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int, Optional[Dict[str, Any]]]]:
    """Charge un classeur ``.afz.json`` et le convertit pour le copilot.

    Args:
        user_id: id du user (token auth) ; sert à scoper le datastore.
        rel_path: chemin relatif du ``.afz.json`` dans le datastore user.

    Returns:
        ``(tabs_context, sheet_content_actif, active_tab_index, raw)`` ou
        ``None`` si le path est invalide / fichier illisible. ``raw`` est
        le dict brut du ``.afz.json`` (utile pour les callers qui veulent
        propager ``copilot_memory`` etc.).
    """
    path = _resolve_workbook_path(user_id, rel_path)
    if path is None:
        return None
    try:
        # SSOT pour la lecture des ``.afz.json`` : ``classeur.reader.
        # _load_json_sync`` détecte les magic bytes gzip (0x1f 0x8b) et
        # décompresse à la volée. Aligné avec ``datastore.py``, ``automation/
        # workbook_loader.py``, ``anonymization/cleanup_job.py`` et
        # ``anonymization/api_service.py`` (refacto gzip transparent du
        # 2026-05-14). Sans ce wrapper, les classeurs uploadés depuis le
        # frontend (stockés gzippés sur disque) faisaient échouer le copilot
        # avec ``UnicodeDecodeError: 'utf-8' codec can't decode byte 0x8b``.
        from app.services.classeur.reader import _load_json_sync

        raw = _load_json_sync(path)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning(
            "load_workbook_for_copilot: lecture .afz.json a échoué (%s): %s",
            path,
            exc,
        )
        return None
    if not isinstance(raw, dict):
        return None
    tabs_raw = raw.get("tabs") or []
    if not isinstance(tabs_raw, list):
        return None

    active_idx = raw.get("active_tab")
    if not isinstance(active_idx, int) or active_idx < 0 or active_idx >= len(tabs_raw):
        active_idx = 0

    tabs_context: List[Dict[str, Any]] = []
    active_sheet_content: List[Dict[str, Any]] = []

    # Pré-pass : dédup SQL identiques (parité frontend).
    seen_sql_hashes: Dict[str, int] = {}
    for tab in tabs_raw:
        if not isinstance(tab, dict):
            continue
        tab_sql = tab.get("sql") or ""
        if tab_sql:
            key = f"{len(tab_sql)}:{tab_sql[:200]}"
            seen_sql_hashes[key] = seen_sql_hashes.get(key, 0) + 1

    emitted_sql_hashes: Dict[str, bool] = {}
    for i, tab in enumerate(tabs_raw):
        if not isinstance(tab, dict):
            continue
        tab_sql = tab.get("sql") or ""
        is_active = i == active_idx
        if tab_sql and not is_active:
            key = f"{len(tab_sql)}:{tab_sql[:200]}"
            if emitted_sql_hashes.get(key):
                continue
            emitted_sql_hashes[key] = True

        columns = tab.get("columns") or []
        if not isinstance(columns, list):
            columns = []
        rows = tab.get("rows") or []
        if not isinstance(rows, list):
            rows = []
        is_array_format = bool(tab.get("isArrayFormat"))
        merges = tab.get("merges") or []
        if not isinstance(merges, list):
            merges = []
        cell_details = tab.get("cellDetails") if isinstance(tab.get("cellDetails"), dict) else None

        entry: Dict[str, Any] = {
            "label": tab.get("label", f"Tab {i + 1}"),
            "sql": tab_sql,
            "columns": list(columns),
            "row_count": int(tab.get("totalRowCount") or len(rows)),
            "is_active": is_active,
            "merges": merges,
            "_tabIndex": i,
        }
        if tab_sql and seen_sql_hashes.get(f"{len(tab_sql)}:{tab_sql[:200]}", 0) > 1:
            entry["label"] = (
                f"{entry['label']} (×{seen_sql_hashes[f'{len(tab_sql)}:{tab_sql[:200]}']})"
            )

        # col_distinct : uniquement pour les tabs SQL non-actifs (parité frontend).
        if not is_active and tab_sql and rows:
            col_distinct = _compute_col_distinct(columns, rows, is_array_format)
            if col_distinct:
                entry["col_distinct"] = col_distinct

        # sheet_content : pour TOUS les onglets sœurs (non-actifs) avec rows ;
        # pour l'actif, le contenu va dans ``sheet_content`` top-level.
        sheet_content_cells: List[Dict[str, Any]] = []
        sql_truncated = False
        label_truncated = False
        numeric_truncated = False
        if rows:
            if tab_sql:
                dims, measures = _classify_columns_for_sql_tab(
                    tab_sql, list(columns), rows, is_array_format
                )
                sheet_content_cells, sql_truncated = _build_sheet_content_sql(
                    list(columns),
                    rows,
                    is_array_format,
                    dims,
                    measures,
                )
            else:
                (
                    sheet_content_cells,
                    label_truncated,
                    numeric_truncated,
                ) = _build_sheet_content_non_sql(list(columns), rows, is_array_format, cell_details)

            if sql_truncated:
                sheet_content_cells.append(
                    {
                        "row": 0,
                        "col": "_meta",
                        "value": (
                            f"(contenu tronqué — feuille dépasse "
                            f"{_SIBLING_MAX_CELLS_SQL} cellules)"
                        ),
                    }
                )
            elif label_truncated or numeric_truncated:
                parts = []
                if label_truncated:
                    parts.append(f"labels > {_SIBLING_MAX_LABEL_CELLS}")
                if numeric_truncated:
                    parts.append(f"valeurs numériques > {_SIBLING_MAX_NUMERIC_CELLS}")
                sheet_content_cells.append(
                    {
                        "row": 0,
                        "col": "_meta",
                        "value": (
                            f"(tronqué — {', '.join(parts)}). "
                            f"Les cellules avec cellDetails sont préservées."
                        ),
                    }
                )

        if is_active:
            active_sheet_content = sheet_content_cells
        else:
            if sheet_content_cells:
                entry["sheet_content"] = sheet_content_cells

        tabs_context.append(entry)

    return tabs_context, active_sheet_content, active_idx, raw
