"""
Service d'analyse des valeurs NULL dans les résultats de requêtes SQL.

Fournit :
- Statistiques NULL par colonne (compte, ratio, échantillon non-NULL)
- Détection programmatique des groupes de colonnes co-NULL (Jaccard sur les
  ensembles de lignes)
- Synthèse globale (densité, lignes complètes vs incomplètes)

Ce service est **purement quantitatif** : il ne classe PAS les colonnes
(« optionnelle », « requise », « erreur de corruption »…). L'interprétation
sémantique des ratios revient au LLM appelant, qui voit le nom des colonnes
et la nature de la requête. Avant le 2026-05-01, ce module embarquait 29
regex hardcodées (français + anglais) sur des noms comme `fax`, `mobile`,
`remarque`, `^id$`, `^libelle`, `^statut`… pour décider si une colonne était
« optionnelle » ou « requise ». C'était un anti-pattern « 2+2=4 » : tout
schéma qui n'utilisait pas ce vocabulaire précis (autre langue, conventions
custom) recevait une classification silencieusement fausse. La directive
2026-05-01 (cf. mémoire `feedback_no_restrictive_lists.md`) impose le
principe générateur : on remonte la donnée brute, le LLM raisonne dessus.

Le service reste générique : il travaille sur des résultats de requêtes
(listes de dicts), pas sur une BDD spécifique.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ColumnNullStats:
    """Statistiques NULL pour une colonne — purement quantitatives."""

    column_name: str
    null_count: int
    total_rows: int
    null_ratio: float
    sample_non_null_values: List[Any] = field(default_factory=list, repr=False)
    co_null_columns: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"ColumnNullStats(column_name={self.column_name!r}, "
            f"null_count={self.null_count}, total_rows={self.total_rows}, "
            f"null_ratio={self.null_ratio:.4f})"
        )

    @property
    def is_fully_null(self) -> bool:
        return self.null_count == self.total_rows and self.total_rows > 0

    @property
    def has_nulls(self) -> bool:
        return self.null_count > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "column_name": self.column_name,
            "null_count": self.null_count,
            "total_rows": self.total_rows,
            "null_ratio": round(self.null_ratio, 4),
            "null_percent": round(self.null_ratio * 100, 1),
            "is_fully_null": self.is_fully_null,
            "co_null_columns": self.co_null_columns,
        }


@dataclass
class NullAnalysisResult:
    """Résultat complet de l'analyse NULL — données brutes pour le LLM."""

    total_rows: int
    total_columns: int
    columns_with_nulls: int
    total_null_cells: int
    null_density: float
    column_stats: List[ColumnNullStats]
    co_occurrence_groups: List[List[str]]
    rows_with_any_null: int
    rows_fully_complete: int
    # #81 — combien de colonnes ont réellement été passées à l'analyse de
    # co-occurrence vs combien ont été OMISES par le cap. Défauts à 0 pour la
    # rétro-compat (early-return sans dépassement).
    co_occurrence_columns_analyzed: int = 0
    co_occurrence_columns_omitted: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "total_rows": self.total_rows,
            "total_columns": self.total_columns,
            "columns_with_nulls": self.columns_with_nulls,
            "total_null_cells": self.total_null_cells,
            "null_density": round(self.null_density, 4),
            "null_density_percent": round(self.null_density * 100, 1),
            "rows_with_any_null": self.rows_with_any_null,
            "rows_fully_complete": self.rows_fully_complete,
            "completeness_percent": round(
                (self.rows_fully_complete / self.total_rows * 100) if self.total_rows > 0 else 100,
                1,
            ),
            "column_stats": [cs.to_dict() for cs in self.column_stats if cs.has_nulls],
            "co_occurrence_groups": self.co_occurrence_groups,
        }
        # #81 — quand le cap a écarté des colonnes, le LLM DOIT savoir que la
        # co-occurrence est PARTIELLE (sinon il conclut « ces colonnes-là sont
        # les seules liées » alors que les colonnes 101+ n'ont pas été testées).
        if self.co_occurrence_columns_omitted > 0:
            d["co_occurrence_truncated"] = True
            d["co_occurrence_columns_analyzed"] = self.co_occurrence_columns_analyzed
            d["co_occurrence_columns_omitted"] = self.co_occurrence_columns_omitted
        return d


# ---------------------------------------------------------------------------
# Co-occurrence analysis (purement quantitative — Jaccard programmatique)
# ---------------------------------------------------------------------------

# Cap dur du nombre de colonnes analysées en co-occurrence (protège du
# O(N²) sur des résultats très larges). #81 — le dépassement est désormais
# SURFACÉ (to_dict + report) pour que le LLM ne présente pas une analyse
# partielle comme exhaustive. SSoT : utilisé par _find_co_occurrence_groups
# ET analyze_nulls (calcul du nombre de colonnes omises).
_CO_OCCURRENCE_MAX_COLUMNS = 100


def _find_co_occurrence_groups(
    rows: List[Dict[str, Any]], columns_with_nulls: List[str]
) -> List[List[str]]:
    """Identifie les groupes de colonnes qui ont tendance à être NULL ensemble.

    Deux colonnes sont « co-NULL » si > 70 % de leurs NULL apparaissent sur
    les mêmes lignes (similarité de Jaccard via intersection / min). Pas de
    seuil métier — c'est une observation algébrique générique.
    """
    if not rows or len(columns_with_nulls) < 2:
        return []

    # Cap pour éviter l'explosion O(N²) sur des résultats très larges.
    # Le nombre de colonnes omises est recalculé et surfacé par analyze_nulls.
    if len(columns_with_nulls) > _CO_OCCURRENCE_MAX_COLUMNS:
        logger.warning(
            "Co-occurrence analysis capped at %d columns (got %d)",
            _CO_OCCURRENCE_MAX_COLUMNS,
            len(columns_with_nulls),
        )
        columns_with_nulls = columns_with_nulls[:_CO_OCCURRENCE_MAX_COLUMNS]

    # Construire les ensembles de lignes NULL par colonne
    null_row_sets: Dict[str, set] = {}
    for col in columns_with_nulls:
        null_row_sets[col] = {i for i, row in enumerate(rows) if row.get(col) is None}

    # Matrice de co-occurrence
    co_null_pairs: List[Tuple[str, str]] = []
    cols = list(columns_with_nulls)
    for i in range(len(cols)):
        for j in range(i + 1, len(cols)):
            set_a = null_row_sets[cols[i]]
            set_b = null_row_sets[cols[j]]
            if not set_a or not set_b:
                continue
            # Jaccard-like: intersection / min(|A|, |B|)
            overlap = len(set_a & set_b)
            min_size = min(len(set_a), len(set_b))
            if min_size > 0 and overlap / min_size > 0.70:
                co_null_pairs.append((cols[i], cols[j]))

    # Union-Find pour grouper les paires
    if not co_null_pairs:
        return []

    parent: Dict[str, str] = {}

    def find(x: str) -> str:
        while parent.get(x, x) != x:
            parent[x] = parent.get(parent[x], parent[x])
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for a, b in co_null_pairs:
        parent.setdefault(a, a)
        parent.setdefault(b, b)
        union(a, b)

    groups: Dict[str, List[str]] = {}
    for col in parent:
        root = find(col)
        groups.setdefault(root, []).append(col)

    # Ne retourner que les groupes de 2+ colonnes
    return [sorted(g) for g in groups.values() if len(g) >= 2]


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------


def analyze_nulls(
    rows: List[Dict[str, Any]],
    columns: Optional[List[str]] = None,
) -> NullAnalysisResult:
    """Analyse complète des valeurs NULL dans un jeu de résultats.

    Retourne **uniquement des observations programmatiques** : ratios,
    densité, co-occurrences, échantillons non-NULL. Aucune interprétation
    sémantique n'est faite ici — le LLM appelant interprète à partir du
    nom des colonnes et du contexte de la requête.

    Args:
        rows: Liste de dicts (résultat d'une requête SQL).
        columns: Liste ordonnée des noms de colonnes. Si None, déduit des clés.

    Returns:
        NullAnalysisResult avec statistiques quantitatives + co-occurrences.
    """
    if not rows:
        return NullAnalysisResult(
            total_rows=0,
            total_columns=len(columns) if columns else 0,
            columns_with_nulls=0,
            total_null_cells=0,
            null_density=0.0,
            column_stats=[],
            co_occurrence_groups=[],
            rows_with_any_null=0,
            rows_fully_complete=0,
        )

    # Déduire les colonnes si non fournies
    if columns is None:
        all_keys: set = set()
        for row in rows:
            all_keys.update(row.keys())
        columns = sorted(all_keys)

    total_rows = len(rows)
    total_columns = len(columns)

    # Calculer les stats NULL par colonne
    column_stats: List[ColumnNullStats] = []
    columns_with_nulls_names: List[str] = []
    total_null_cells = 0

    for col in columns:
        null_count = 0
        non_null_samples: List[Any] = []

        for row in rows:
            val = row.get(col)
            if val is None:
                null_count += 1
            elif len(non_null_samples) < 3:
                non_null_samples.append(val)

        if null_count > 0:
            columns_with_nulls_names.append(col)

        total_null_cells += null_count
        null_ratio = null_count / total_rows if total_rows > 0 else 0.0

        column_stats.append(
            ColumnNullStats(
                column_name=col,
                null_count=null_count,
                total_rows=total_rows,
                null_ratio=null_ratio,
                sample_non_null_values=non_null_samples,
            )
        )

    # Co-occurrence
    co_groups = _find_co_occurrence_groups(rows, columns_with_nulls_names)
    # #81 — combien de colonnes le cap a-t-il écartées de l'analyse de
    # co-occurrence ? (SSoT du cap : _CO_OCCURRENCE_MAX_COLUMNS)
    _n_co_cols = len(columns_with_nulls_names)
    co_cols_analyzed = min(_n_co_cols, _CO_OCCURRENCE_MAX_COLUMNS)
    co_cols_omitted = max(0, _n_co_cols - _CO_OCCURRENCE_MAX_COLUMNS)

    # Annoter les co-null columns sur chaque stat
    co_map: Dict[str, List[str]] = {}
    for group in co_groups:
        for col in group:
            co_map[col] = [c for c in group if c != col]
    for stat in column_stats:
        stat.co_null_columns = co_map.get(stat.column_name, [])

    # Lignes complètes vs incomplètes
    rows_with_any_null = sum(1 for row in rows if any(row.get(col) is None for col in columns))

    total_cells = total_rows * total_columns
    null_density = total_null_cells / total_cells if total_cells > 0 else 0.0

    return NullAnalysisResult(
        total_rows=total_rows,
        total_columns=total_columns,
        columns_with_nulls=len(columns_with_nulls_names),
        total_null_cells=total_null_cells,
        null_density=null_density,
        column_stats=column_stats,
        co_occurrence_groups=co_groups,
        rows_with_any_null=rows_with_any_null,
        rows_fully_complete=total_rows - rows_with_any_null,
        co_occurrence_columns_analyzed=co_cols_analyzed,
        co_occurrence_columns_omitted=co_cols_omitted,
    )


# ---------------------------------------------------------------------------
# Report generation — purement factuel
# ---------------------------------------------------------------------------


def generate_null_report(analysis: NullAnalysisResult) -> str:
    """Génère un rapport factuel de l'analyse NULL pour l'utilisateur.

    Le rapport est en français, sans interprétation sémantique. Il liste
    les colonnes avec leurs ratios NULL et les groupes co-NULL — c'est au
    LLM appelant de décider, à partir du nom des colonnes et du contexte,
    ce que ces ratios SIGNIFIENT (donnée optionnelle, oubli de saisie,
    erreur d'import, donnée non pertinente pour cette ligne, etc.).
    """
    if analysis.total_rows == 0:
        return "Aucune donnée à analyser."

    lines: List[str] = []
    lines.append("## Analyse de complétude des données\n")

    # Résumé global
    completeness = analysis.rows_fully_complete / analysis.total_rows * 100
    lines.append(
        f"**{analysis.total_rows}** lignes analysées, **{analysis.total_columns}** colonnes."
    )
    lines.append(
        f"**{analysis.rows_fully_complete}** lignes complètes ({completeness:.0f}%), "
        f"**{analysis.rows_with_any_null}** lignes avec au moins une valeur manquante."
    )

    if analysis.columns_with_nulls == 0:
        lines.append("\nToutes les colonnes sont complètes. Aucune valeur manquante détectée.")
        return "\n".join(lines)

    lines.append(
        f"\n**{analysis.columns_with_nulls}** colonne(s) contiennent des valeurs manquantes "
        f"({analysis.total_null_cells} cellules vides au total, "
        f"densité NULL : {analysis.null_density * 100:.1f}%).\n"
    )

    # Détail par colonne (triées par null_ratio décroissant) — pas de classification
    null_stats = sorted(
        [s for s in analysis.column_stats if s.has_nulls],
        key=lambda s: s.null_ratio,
        reverse=True,
    )

    lines.append("### Colonnes avec valeurs manquantes (triées par % NULL décroissant)\n")
    lines.append("| Colonne | Manquantes | % |")
    lines.append("|---------|-----------|---|")
    for stat in null_stats:
        lines.append(
            f"| {stat.column_name} | {stat.null_count}/{stat.total_rows} "
            f"| {stat.null_ratio * 100:.0f}% |"
        )

    # Groupes de co-occurrence
    if analysis.co_occurrence_groups:
        lines.append("\n### Colonnes liées (souvent NULL ensemble)\n")
        for group in analysis.co_occurrence_groups:
            lines.append(f"- {', '.join(group)}")
        lines.append(
            "\nCes colonnes sont fréquemment vides en même temps "
            "(seuil : > 70 % de leurs NULL sur les mêmes lignes)."
        )

    # #81 — quand le cap a écarté des colonnes, le signaler EXPLICITEMENT pour
    # que ni le LLM ni l'utilisateur ne prennent les groupes ci-dessus pour
    # exhaustifs. Formulation neutre vis-à-vis du RÉSULTAT (review Moyen) :
    # qu'il y ait ou non des groupes détectés, on dit seulement que les liens
    # IMPLIQUANT les colonnes non testées ne peuvent être ni affirmés ni exclus
    # — sans laisser entendre que les colonnes testées ont, elles, donné un
    # résultat.
    if analysis.co_occurrence_columns_omitted > 0:
        _total_co = (
            analysis.co_occurrence_columns_analyzed + analysis.co_occurrence_columns_omitted
        )
        lines.append(
            f"\n⚠ Analyse de co-occurrence PARTIELLE : "
            f"{analysis.co_occurrence_columns_analyzed} colonnes sur {_total_co} testées "
            f"({analysis.co_occurrence_columns_omitted} colonnes à NULL non testées, cap de "
            f"performance). D'éventuels liens IMPLIQUANT ces colonnes non testées ne peuvent "
            f"être ni affirmés ni exclus."
        )

    return "\n".join(lines)


def suggest_completion_actions(
    analysis: NullAnalysisResult,
) -> List[Dict[str, Any]]:
    """Liste les colonnes avec NULL, triées par ratio décroissant.

    Pas de classification sémantique : c'est au LLM appelant de décider, à
    partir du nom des colonnes et du contexte de la requête, quelle action
    proposer (vérifier l'import, compléter, ignorer comme optionnel, etc.).
    Le tri par ratio NULL décroissant met en tête les colonnes les plus
    incomplètes — donc les plus susceptibles de mériter attention.
    """
    actions: List[Dict[str, Any]] = []

    for stat in analysis.column_stats:
        if not stat.has_nulls:
            continue
        actions.append(
            {
                "column": stat.column_name,
                "null_count": stat.null_count,
                "null_percent": round(stat.null_ratio * 100, 1),
                "co_null_columns": stat.co_null_columns,
            }
        )

    # Tri par ratio NULL décroissant (les plus vides en premier)
    actions.sort(key=lambda a: -a["null_percent"])
    return actions


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_instance: Optional["NullAnalyzer"] = None


class NullAnalyzer:
    """Singleton d'analyse NULL avec historique des analyses.

    Conserve un cache léger des dernières analyses pour permettre à Iris
    de référencer les résultats précédents.
    """

    def __init__(self) -> None:
        self._recent_analyses: List[Dict[str, Any]] = []
        self._max_history = 10

    def analyze(
        self,
        rows: List[Dict[str, Any]],
        columns: Optional[List[str]] = None,
        source_label: Optional[str] = None,
    ) -> NullAnalysisResult:
        """Analyse un jeu de résultats et stocke dans l'historique."""
        result = analyze_nulls(rows, columns)

        self._recent_analyses.append(
            {
                "source": source_label or "query",
                "total_rows": result.total_rows,
                "columns_with_nulls": result.columns_with_nulls,
                "null_density": result.null_density,
            }
        )
        if len(self._recent_analyses) > self._max_history:
            self._recent_analyses = self._recent_analyses[-self._max_history :]

        logger.info(
            "NULL analysis: %d rows, %d/%d cols with NULLs, density=%.1f%%",
            result.total_rows,
            result.columns_with_nulls,
            result.total_columns,
            result.null_density * 100,
        )
        return result

    def get_recent_analyses(self) -> List[Dict[str, Any]]:
        """Retourne l'historique des analyses récentes."""
        return list(self._recent_analyses)

    def clear_history(self) -> None:
        """Vide l'historique."""
        self._recent_analyses.clear()


def get_null_analyzer() -> NullAnalyzer:
    """Retourne le singleton NullAnalyzer."""
    global _instance
    if _instance is None:
        _instance = NullAnalyzer()
    return _instance
