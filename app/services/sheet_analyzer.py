"""
Sheet Analyzer — Analyse structurelle programmatique d'une feuille de calcul.

Détermine la structure d'une feuille (titre, en-têtes, sections, signification
de chaque cellule vide) SANS appel LLM. Le code fait le travail, pas le modèle.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Patterns de détection
_EXERCISE_RE = re.compile(r"\d{4}/\d{4}")
_MONTH_NAMES_FR = [
    "janvier",
    "février",
    "mars",
    "avril",
    "mai",
    "juin",
    "juillet",
    "août",
    "septembre",
    "octobre",
    "novembre",
    "décembre",
]
_TOTAL_KEYWORDS = {"total", "totaux", "somme", "sous-total", "sous-totaux"}
_MONTH_SECTION_RE = re.compile(r"suivi\s+facturation", re.IGNORECASE)


def _col_sort_key(col: str) -> tuple:
    """Clé de tri pour colonnes spreadsheet : A < B < ... < Z < AA < AB."""
    return (len(col), col)


@dataclass
class CellMeaning:
    """Signification déterminée d'une cellule vide."""

    row: int
    col: str
    meaning: str
    dimensions: Dict[str, str] = field(default_factory=dict)
    is_total: bool = False


@dataclass
class SheetSection:
    """Section détectée dans la feuille."""

    type: str  # "annual", "monthly", "total", "header", "title"
    rows: List[int] = field(default_factory=list)
    label: str = ""


@dataclass
class SheetAnalysis:
    """Résultat complet de l'analyse structurelle."""

    title: Optional[str] = None
    implicit_filters: List[str] = field(default_factory=list)
    col_headers: Dict[str, str] = field(default_factory=dict)
    col_header_row: Optional[int] = None
    row_headers: Dict[int, str] = field(default_factory=dict)
    row_header_col: Optional[str] = None
    sections: List[SheetSection] = field(default_factory=list)
    empty_cells: List[CellMeaning] = field(default_factory=list)
    confidence: float = 0.0  # 0-1, à quel point l'analyse est fiable


def analyze_sheet(
    sheet_content: List[Dict[str, Any]],
    tabs_context: Optional[List[Dict[str, Any]]] = None,
    tab_label: Optional[str] = None,
    distinct_values: Optional[Dict[str, List[str]]] = None,
) -> SheetAnalysis:
    """
    Analyse la structure d'une feuille de calcul à partir de son contenu.

    Args:
        sheet_content: Liste de {row, col, value} (cellules remplies, 1-based rows).
        tabs_context: Contexte des autres onglets (label, sql, columns).
        tab_label: Label de l'onglet actif.
        distinct_values: Valeurs distinctes connues des colonnes de dimension.
            Format: {"col_name": ["val1", "val2", ...]}

    Returns:
        SheetAnalysis avec titre, en-têtes, sections, et signification
        de chaque cellule vide.
    """
    if not sheet_content:
        return SheetAnalysis()

    # Indexer les cellules par position
    cells_by_pos = {}  # (row, col) → value
    all_rows = set()
    all_cols = []
    col_order = {}  # col → index d'apparition

    for cell in sheet_content:
        row = cell.get("row", 0)
        col = str(cell.get("col", ""))
        value = str(cell.get("value", "")).strip()
        if value:
            cells_by_pos[(row, col)] = value
            all_rows.add(row)
            if col not in col_order:
                col_order[col] = len(col_order)
                all_cols.append(col)

    if not cells_by_pos:
        return SheetAnalysis()

    analysis = SheetAnalysis()

    # 1. Détecter le titre
    analysis.title, title_row = _detect_title(cells_by_pos, all_rows, all_cols, tab_label)

    # 2. Extraire les filtres implicites du titre
    if analysis.title and distinct_values:
        analysis.implicit_filters = _extract_implicit_filters(analysis.title, distinct_values)

    # 3. Détecter les en-têtes de colonnes
    analysis.col_headers, analysis.col_header_row = _detect_col_headers(
        cells_by_pos, all_rows, all_cols, title_row
    )

    # 4. Détecter les en-têtes de lignes
    analysis.row_headers, analysis.row_header_col = _detect_row_headers(
        cells_by_pos, all_rows, all_cols, analysis.col_header_row, title_row
    )

    # 5. Détecter les sections
    analysis.sections = _detect_sections(analysis.row_headers)

    # 6. Déterminer la signification des cellules vides
    analysis.empty_cells = _determine_empty_cells(analysis, cells_by_pos, all_rows, all_cols)

    # 7. Calculer la confiance
    analysis.confidence = _compute_confidence(analysis)

    return analysis


def _detect_title(
    cells: Dict[Tuple[int, str], str],
    rows: set,
    cols: List[str],
    tab_label: Optional[str],
) -> Tuple[Optional[str], Optional[int]]:
    """Détecte le titre de la feuille. Retourne (titre, numéro de ligne)."""
    # Stratégie 1 : Ligne 1 avec une seule cellule remplie
    row_1_cells = {col: val for (r, col), val in cells.items() if r == 1}
    if len(row_1_cells) == 1:
        val = list(row_1_cells.values())[0]
        if not _is_numeric(val):
            return val, 1

    # Stratégie 2 : Ligne avec "Ratio", "Suivi", "Tableau" etc.
    for row in sorted(rows):
        row_cells = {col: val for (r, col), val in cells.items() if r == row}
        if len(row_cells) == 1:
            val = list(row_cells.values())[0]
            if any(kw in val.lower() for kw in ["ratio", "suivi", "tableau", "bilan"]):
                return val, row

    # Stratégie 3 : Utiliser le label de l'onglet comme titre
    if tab_label:
        return tab_label, None

    return None, None


def _detect_col_headers(
    cells: Dict[Tuple[int, str], str],
    rows: set,
    cols: List[str],
    title_row: Optional[int],
) -> Tuple[Dict[str, str], Optional[int]]:
    """Détecte la ligne d'en-têtes de colonnes."""
    best_row = None
    best_count = 0
    best_headers = {}

    # Chercher la ligne avec le plus de cellules texte non-numériques
    # En excluant la ligne titre
    for row in sorted(rows):
        if row == title_row:
            continue
        row_cells = {col: val for (r, col), val in cells.items() if r == row}
        text_count = sum(1 for v in row_cells.values() if not _is_numeric(v))
        if text_count > best_count:
            best_count = text_count
            best_row = row
            best_headers = row_cells

    if best_row and best_count >= 2:
        # D1 fix: sort by column position for consistent left-to-right ordering
        # regardless of cell input order from the frontend
        sorted_headers = dict(sorted(best_headers.items(), key=lambda kv: _col_sort_key(kv[0])))
        return sorted_headers, best_row
    return {}, None


def _detect_row_headers(
    cells: Dict[Tuple[int, str], str],
    rows: set,
    cols: List[str],
    col_header_row: Optional[int],
    title_row: Optional[int] = None,
) -> Tuple[Dict[int, str], Optional[str]]:
    """Détecte la colonne d'en-têtes de lignes."""
    if not cols:
        return {}, None

    skip_rows = {col_header_row, title_row} - {None}

    # Candidats : les 3 premières colonnes
    candidates = cols[:3]
    best_col = None
    best_headers = {}
    best_score = 0

    for col in candidates:
        headers = {}
        text_count = 0
        for row in sorted(rows):
            if row in skip_rows:
                continue
            val = cells.get((row, col))
            if val and not _is_numeric(val):
                headers[row] = val
                text_count += 1
        if text_count > best_score:
            best_score = text_count
            best_col = col
            best_headers = headers

    # Merge : si des mois sont en colonne C mais pas en colonne A, les ajouter
    if best_col and best_headers:
        for col in candidates:
            if col == best_col:
                continue
            for row in sorted(rows):
                if row in skip_rows or row in best_headers:
                    continue
                val = cells.get((row, col))
                if val and not _is_numeric(val):
                    val_lower = val.lower().strip()
                    if any(m in val_lower for m in _MONTH_NAMES_FR):
                        best_headers[row] = val

    return best_headers, best_col


def _detect_sections(row_headers: Dict[int, str]) -> List[SheetSection]:
    """Détecte les sections dans la feuille à partir des en-têtes de lignes."""
    sections = []
    annual_rows = []
    monthly_rows = []
    total_rows = []

    for row, header in sorted(row_headers.items()):
        header_lower = header.lower().strip()

        # "Suivi facturation Exercice 2025/2026" is a section title, not annual data
        if _MONTH_SECTION_RE.search(header):
            continue
        elif _EXERCISE_RE.search(header) and "exercice" in header_lower:
            annual_rows.append(row)
        elif any(m in header_lower for m in _MONTH_NAMES_FR):
            monthly_rows.append(row)
        elif header_lower in _TOTAL_KEYWORDS:
            total_rows.append(row)

    if annual_rows:
        sections.append(SheetSection(type="annual", rows=annual_rows, label="Par exercice"))
    if total_rows:
        sections.append(SheetSection(type="total", rows=total_rows, label="Totaux"))
    if monthly_rows:
        sections.append(SheetSection(type="monthly", rows=monthly_rows, label="Suivi mensuel"))

    return sections


def _determine_empty_cells(
    analysis: SheetAnalysis,
    cells: Dict[Tuple[int, str], str],
    rows: set,
    cols: List[str],
) -> List[CellMeaning]:
    """Détermine la signification de chaque cellule vide."""
    empty_cells = []
    if not analysis.col_headers or not analysis.row_headers:
        return empty_cells

    # Toutes les lignes de données (pas le titre, pas les en-têtes)
    data_rows = set(analysis.row_headers.keys())

    # Colonnes de données (celles qui ont un en-tête, sauf la colonne des labels)
    # D1 fix: sort for consistent left-to-right ordering
    data_cols = sorted(
        (col for col in analysis.col_headers if col != analysis.row_header_col),
        key=_col_sort_key,
    )

    for row in sorted(data_rows):
        row_header = analysis.row_headers.get(row, "")
        if not row_header:
            continue

        for col in data_cols:
            # Si la cellule est déjà remplie → skip
            if (row, col) in cells:
                continue

            col_header = analysis.col_headers.get(col, "")
            if not col_header:
                continue

            # Construire la signification
            dimensions = {}
            is_total = row_header.lower().strip() in _TOTAL_KEYWORDS

            if is_total:
                meaning = f"Total de la colonne {col_header}"
            else:
                meaning = f"{col_header} pour {row_header}"
                # Enrichir avec les filtres implicites
                if analysis.implicit_filters:
                    filters_str = ", ".join(analysis.implicit_filters)
                    meaning += f" (filtré sur {filters_str})"

                # Ajouter les dimensions détectées
                if _EXERCISE_RE.search(row_header):
                    dimensions["exercice"] = row_header.strip()
                for month_name in _MONTH_NAMES_FR:
                    if month_name in row_header.lower():
                        dimensions["mois"] = month_name.capitalize()
                        break

                dimensions["col_header"] = col_header

            empty_cells.append(
                CellMeaning(
                    row=row,
                    col=col,
                    meaning=meaning,
                    dimensions=dimensions,
                    is_total=is_total,
                )
            )

    return empty_cells


def _extract_implicit_filters(title: str, distinct_values: Dict[str, List[str]]) -> List[str]:
    """Extrait les filtres implicites du titre en cross-référençant les valeurs connues."""
    filters = []
    title_lower = title.lower()
    title_words = re.findall(r"[a-zà-ÿ]+", title_lower)

    for col_name, values in distinct_values.items():
        for val in values:
            val_lower = str(val).lower()
            # Match exact d'un mot du titre avec une valeur connue
            if val_lower in title_words and len(val_lower) >= 3:
                filters.append(str(val))

    return filters


def _compute_confidence(analysis: SheetAnalysis) -> float:
    """Calcule un score de confiance pour l'analyse (0-1)."""
    score = 0.0
    if analysis.title:
        score += 0.2
    if analysis.col_headers and len(analysis.col_headers) >= 2:
        score += 0.3
    if analysis.row_headers and len(analysis.row_headers) >= 2:
        score += 0.3
    if analysis.sections:
        score += 0.1
    if analysis.empty_cells:
        score += 0.1
    return min(score, 1.0)


def _is_numeric(value: str) -> bool:
    """Vérifie si une valeur est numérique (entier, décimal, format FR)."""
    cleaned = value.replace(" ", "").replace("\u202f", "").replace(",", ".")
    try:
        float(cleaned)
        return True
    except ValueError:
        return False


def format_analysis_for_prompt(analysis: SheetAnalysis) -> str:
    """
    Formate l'analyse en texte structuré pour inclusion dans le prompt LLM.

    Retourne un bloc prêt à injecter dans le prompt utilisateur.
    """
    if analysis.confidence < 0.3:
        return ""

    parts = []

    # Titre et filtres
    if analysis.title:
        parts.append(f"## Analyse de la feuille")
        parts.append(f"**Titre** : {analysis.title}")
        if analysis.implicit_filters:
            filters_str = ", ".join(analysis.implicit_filters)
            parts.append(
                f"**FILTRE OBLIGATOIRE** : TOUTES les requêtes DOIVENT filtrer sur : {filters_str}"
            )

    # Structure détectée
    if analysis.sections:
        section_descs = []
        for s in analysis.sections:
            rows_str = ", ".join(str(r) for r in s.rows[:5])
            if len(s.rows) > 5:
                rows_str += f"... ({len(s.rows)} lignes)"
            section_descs.append(f"- {s.label} (lignes {rows_str})")
        parts.append("**Structure** :\n" + "\n".join(section_descs))

    # Cellules à remplir
    if analysis.empty_cells:
        cell_descs = []
        for cell in analysis.empty_cells:
            cell_descs.append(f"- [{cell.row}, {cell.col}] = {cell.meaning}")
        parts.append("## Cellules à remplir (déterminées par le système)\n" + "\n".join(cell_descs))

    return "\n\n".join(parts)
