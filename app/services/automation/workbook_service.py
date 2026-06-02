"""
Service de manipulation du `workbook` DAG — type unifie des donnees inter-nodes.

Definitions (cf. docs/design_automations_dag.md §1.1, §1.6) :
- `workbook` = classeur multi-onglets, structure identique au format `.afz.json`
  de Komptia : `{"version": 1, "tabs": [{"label", "columns", "rows", "sql",
  "totalRowCount", "cellDetails"}]}`.
- Chaque `extract_*` produit un workbook a 1 onglet (sauf `extract_workbook`
  qui peut en produire N).
- Fan-in = fusion de classeurs : union des onglets de tous les parents dans
  un classeur unique. Collision de labels → suffixe `_1, _2, ...` automatique.

Conception :
- Pur : pas d'acces DB, pas d'I/O. Testable en unite trivialement.
- Generique : accepte des dicts ou des objets ORM, duck typing.
- Pas de cap memoire applicatif : suppression de `MAX_ROWS_PER_STEP_OUTPUT`
  le 2026-05-27 (décision user P0 Q9 doctrine "SSoT admin OU pas de limite").
  La SSoT pour les caps de lignes est `DatabaseConnection.max_rows` qui
  cape le SQL EN AMONT. Si l'admin met `None`/illimité, on respecte.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Sequence


# -----------------------------------------------------------------------------
# Conversions
# -----------------------------------------------------------------------------


def rows_to_workbook(
    rows: Sequence[Dict[str, Any]],
    *,
    tab_label: str,
    sql: Optional[str] = None,
) -> Dict[str, Any]:
    """Convertit une liste de dicts (resultat SQL brut) en workbook a 1 onglet.

    Args:
        rows: Liste de dicts. Chaque dict = une ligne.
        tab_label: Nom de l'onglet (obligatoire, champ `name` du node source
            par convention).
        sql: SQL d'origine (optionnel, stocke dans l'onglet pour audit).

    Returns:
        Workbook dict au format `.afz.json` a 1 onglet.
    """
    columns = list(rows[0].keys()) if rows else []
    all_rows = list(rows)
    warnings: List[str] = []

    tab: Dict[str, Any] = {
        "label": tab_label,
        "columns": columns,
        "rows": all_rows,
        "totalRowCount": len(rows),
    }
    if sql:
        tab["sql"] = sql

    return {
        "version": 1,
        "app": "komptia",
        "tabs": [tab],
        "warnings": warnings,
    }


def tab_to_dict_rows(tab: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convertit rows + columns d'un tab en liste de dicts unifies.

    Le code Komptia stocke les rows soit comme ``List[List[Any]]`` (format
    array, plus compact) soit comme ``List[Dict[str, Any]]`` (format objet,
    plus lisible) selon la source — extract_sql renvoie en general des
    dicts via ``_execute_query``, mais les .afz.json sauvegardes peuvent
    contenir des arrays. Ce helper unifie en dict.

    Source unique : centralise ici pour eviter les divergences entre les
    appelants (executor._tab_to_dict_rows en delegate). Helper publique
    reutilisable pour tout module qui doit normaliser le format des rows
    avant traitement (filtrage, agregation, etc.).
    """
    columns = list(tab.get("columns") or [])
    rows = list(tab.get("rows") or [])
    out: List[Dict[str, Any]] = []
    for r in rows:
        if isinstance(r, dict):
            out.append(r)
        elif isinstance(r, list):
            out.append({col: r[i] if i < len(r) else None for i, col in enumerate(columns)})
    return out


def workbook_row_count(workbook: Dict[str, Any]) -> int:
    """Somme des lignes de tous les onglets du workbook."""
    return sum(len(tab.get("rows", [])) for tab in workbook.get("tabs", []))


def workbook_tab_labels(workbook: Dict[str, Any]) -> List[str]:
    """Liste des labels d'onglets du workbook."""
    return [tab.get("label", "") for tab in workbook.get("tabs", [])]


# -----------------------------------------------------------------------------
# Merge (fan-in)
# -----------------------------------------------------------------------------


def count_total_rows_in_workbooks(
    workbooks: Sequence[Dict[str, Any]],
) -> int:
    """Cluster-T 2026-05-26 — Compte le nombre total de rows dans une
    séquence de workbooks (somme sur tous les tabs de tous les workbooks).

    Utilisé par le DAG executor AVANT ``merge_workbooks`` pour détecter
    un fan-in OOM : 5 parents × 100k rows = 500k rows → tester contre
    ``automation.max_total_rows`` avant la fusion (qui charge tout en RAM).

    Defensif : ignore les workbooks non-dict, tabs non-list, rows non-list.
    """
    total = 0
    for wb in workbooks:
        if not isinstance(wb, dict):
            continue
        tabs = wb.get("tabs")
        if not isinstance(tabs, list):
            continue
        for tab in tabs:
            if not isinstance(tab, dict):
                continue
            rows = tab.get("rows")
            if isinstance(rows, list):
                total += len(rows)
    return total


def merge_workbooks(
    workbooks: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Fusionne N workbooks en un seul result_area.

    Strategie (cf. design §1.6) :
    - Union des onglets de tous les workbooks entrants.
    - Collision de labels → suffixe `_1, _2, ...` automatique. Le premier
      garde son label, les suivants sont suffixes.
    - Les warnings de chaque workbook sont aggreges.

    Args:
        workbooks: Sequence de workbooks a merger. Ordre important :
            si collision, le 1er garde son label.

    Returns:
        Workbook unifie (version, tabs, warnings).

    **CONTRAT DE MUTATION (Cluster-T 2026-05-26)** : les ``rows`` des tabs
    fusionnés sont des **shared references** avec les workbooks parents.
    Le ``new_tab = dict(tab)`` ci-dessous est une copie shallow : le
    dictionnaire tab est neuf MAIS la liste ``rows`` et ses dicts internes
    sont partagés. Conséquences pour les callers :

    1. **Lecture OK** : itérer / accéder en lecture est safe.
    2. **Mutation ROW INTERDITE** : ``row["x"] = y`` mute le parent (et tous
       les siblings via fan-out). Les step adapters doivent re-builder
       leurs propres rows si transformation requise.
    3. **Append/pop sur tab.rows INTERDIT** : idem, mute le parent.
    4. **Deep-copy non fait par défaut** : doubler la RAM pour 500k rows
       est inacceptable. Le contrat read-only est la mitigation.

    Si un adapter doit muter, il DOIT faire ``new_rows = [dict(r) for r
    in tab["rows"]]`` avant.
    """
    merged_tabs: List[Dict[str, Any]] = []
    merged_warnings: List[str] = []
    seen_labels: Dict[str, int] = {}  # label_base -> prochain suffixe

    for wb in workbooks:
        if not isinstance(wb, dict):
            continue
        merged_warnings.extend(wb.get("warnings", []))
        for tab in wb.get("tabs", []):
            if not isinstance(tab, dict):
                continue
            raw_label = tab.get("label", "").strip() or f"Tab_{len(merged_tabs)}"
            if raw_label not in seen_labels:
                seen_labels[raw_label] = 1
                final_label = raw_label
            else:
                suffix = seen_labels[raw_label]
                seen_labels[raw_label] += 1
                final_label = f"{raw_label}_{suffix}"
                merged_warnings.append(
                    f"Collision de label d'onglet '{raw_label}' → renomme en '{final_label}' "
                    f"a la fusion (fan-in). Precisez des tab_label uniques pour eviter ce warning."
                )
            # Copie defensive (evite les modifications en place d'un parent)
            new_tab = dict(tab)
            new_tab["label"] = final_label
            merged_tabs.append(new_tab)

    return {
        "version": 1,
        "app": "komptia",
        "tabs": merged_tabs,
        "warnings": merged_warnings,
    }


# -----------------------------------------------------------------------------
# Snapshot pour step_output (avec troncature defensive)
# -----------------------------------------------------------------------------


def workbook_snapshot_for_db(
    workbook: Dict[str, Any],
    *,
    max_rows_per_tab: int = 100,
) -> Dict[str, Any]:
    """Produit une version tronquee d'un workbook pour stockage step_output en BDD.

    Evite de stocker 50k lignes dans une colonne JSON (explosion DB, lecture
    lente de l'historique). Garde les metadonnees completes + N lignes par
    onglet pour l'UI debug.

    Args:
        workbook: Workbook complet en RAM.
        max_rows_per_tab: Nombre de lignes max conservees par onglet (defaut
            100 : assez pour que l'UI affiche un echantillon, pas assez pour
            faire exploser la DB).

    Returns:
        Workbook tronque, meta enrichies (`_snapshot_truncated`).
    """
    snapshot_tabs: List[Dict[str, Any]] = []
    any_truncated = False
    for tab in workbook.get("tabs", []):
        rows = tab.get("rows", [])
        total = len(rows)
        if total > max_rows_per_tab:
            any_truncated = True
            snap_rows = rows[:max_rows_per_tab]
        else:
            snap_rows = rows
        snapshot_tabs.append(
            {
                "label": tab.get("label", ""),
                "columns": tab.get("columns", []),
                "rows": snap_rows,
                "totalRowCount": tab.get("totalRowCount", total),
                "_snapshot_included_rows": len(snap_rows),
            }
        )

    return {
        "version": 1,
        "tabs": snapshot_tabs,
        "_snapshot_truncated": any_truncated,
        "_snapshot_max_rows_per_tab": max_rows_per_tab,
    }


# -----------------------------------------------------------------------------
# Hash stable d'un workbook (pour idempotency_key)
# -----------------------------------------------------------------------------


def workbook_stable_hash(workbook: Dict[str, Any]) -> str:
    """Calcule un hash stable du contenu du workbook.

    Utilise pour idempotency_key : deux workbooks avec les memes onglets
    (meme labels, memes columns, memes rows) produisent le meme hash. Les
    warnings et meta non-deterministes sont exclus.

    Implementation : JSON canonique (sort_keys=True, separators sans
    espaces) + sha256. Stable entre Python runs/machines.
    """
    canonical: Dict[str, Any] = {
        "tabs": [
            {
                "label": tab.get("label", ""),
                "columns": list(tab.get("columns", [])),
                "rows": list(tab.get("rows", [])),
            }
            for tab in workbook.get("tabs", [])
        ]
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
