"""
Stratification ``value_mapping`` par cardinalité de colonne (T5).

L'index ``value_mapping`` est alimenté par ``schema_enricher.sample_column_values``
qui actuellement sample TOUTES les valeurs distinctes d'une colonne (``max_values=0``)
sans considération de cardinalité. Pour une colonne high-card (50K+ distincts), cela
peut produire 50K rows dans ``value_mapping`` — coûteux en stockage et fragile en
synchronisation (timeout Sage, contention SQLite).

Ce module fournit la **logique de stratification** (sans I/O) qui décide :

- **Low-card** (``distinct_count ≤ 100``) : indexation EXHAUSTIVE (100% des valeurs).
- **Mid-card** (``100 < distinct_count ≤ 1000``) : indexation EXHAUSTIVE +
  agrégats (length stats, value_type distribution).
- **High-card** (``distinct_count > 1000``) : Top-1000 valeurs par fréquence +
  agrégats calculés sur la totalité (via SQL GROUP BY).

Le contrat est volontairement **agnostique BDD** (règle GÉNÉRICITÉ Komptia) :
aucun nom de table/colonne hardcodé, juste une politique générale.

Les agrégats stockés alimentent ensuite Phase 2.5 ``_phase_2_5_value_type_compatible``
qui aujourd'hui retourne ``True`` quand ``value_type`` colonne est inconnu
(fallback safe). Avec les agrégats, le préflight peut faire un check intelligent :
``user_value`` compatible avec ``length_min..length_max`` ET ``majority value_type`` ?

Principes T5 (cf. ``.claude/anon-impl-loop/ANON_IMPL_PROMPT.md``) :
1. ``raise`` ⇔ aucune option — fallback gracieux si stats partielles
2. Preuve empirique > heuristique — agrégats SQL > règles arbitraires
3. Aucun artefact ne se perd — coverage_ratio observable
4. Aucune garde silencieuse — ``is_exhaustive`` exposé au caller
"""

from __future__ import annotations

import re
import statistics
from dataclasses import dataclass
from typing import Iterable, Literal

LOW_CARD_THRESHOLD: int = 100
MID_CARD_THRESHOLD: int = 1000
HIGH_CARD_SAMPLE_CAP: int = 1000

CardinalityTier = Literal["low", "mid", "high"]


def decide_cardinality_tier(distinct_count: int) -> CardinalityTier:
    """Classifie une colonne par cardinalité.

    Conventions (boundaries inclusives à low/mid) :
    - ``[0, 100]`` → ``"low"``
    - ``(100, 1000]`` → ``"mid"``
    - ``(1000, ∞)`` → ``"high"``
    """
    if distinct_count < 0:
        raise ValueError(f"distinct_count doit être ≥ 0, reçu {distinct_count!r}")
    if distinct_count <= LOW_CARD_THRESHOLD:
        return "low"
    if distinct_count <= MID_CARD_THRESHOLD:
        return "mid"
    return "high"


def recommend_sample_cap(tier: CardinalityTier) -> int | None:
    """Cap recommandé de valeurs à sampler (``None`` = exhaustif).

    Pour low/mid → exhaustif (les colonnes sont assez petites). Pour high →
    cap à ``HIGH_CARD_SAMPLE_CAP`` (top-N par fréquence).
    """
    if tier == "low" or tier == "mid":
        return None
    if tier == "high":
        return HIGH_CARD_SAMPLE_CAP
    raise ValueError(f"Tier inconnu: {tier!r}")


# Patterns de classification — alignés sur schema_enricher._store_value_mappings
_NUMBER_RE = re.compile(r"^-?\d+(\.\d+)?$")
_DATE_RE = re.compile(r"^\d{4}[/-]\d{2}[/-]\d{2}")


def classify_value_type(value: str) -> str:
    """Type sémantique grossier d'une valeur (cohérent avec ``schema_enricher``).

    Sortie ∈ ``{"empty", "number", "date", "code", "text"}``.

    Note : la classification est identique à celle utilisée pour peupler la
    colonne ``value_type`` de ``value_mapping``. Refactoring nécessite de
    garder les 2 alignés (cf. ``test_classify_value_type_matches_schema_enricher``).
    """
    if not value:
        return "empty"
    val = str(value).strip()
    if not val:
        return "empty"
    if _NUMBER_RE.match(val):
        return "number"
    if _DATE_RE.match(val):
        return "date"
    if len(val) <= 3:
        return "code"
    return "text"


@dataclass(frozen=True)
class LengthStats:
    """Distribution de longueur d'une colonne textuelle."""

    min: int
    max: int
    mean: float
    p50: int
    count: int


def compute_length_stats(values: Iterable[str]) -> LengthStats:
    """Statistiques de longueur des valeurs non-vides.

    Les valeurs vides/None sont filtrées avant calcul. Pour une liste vide,
    retourne ``LengthStats(0, 0, 0.0, 0, 0)`` — un caller peut détecter
    ``count == 0`` pour signaler "pas de données".
    """
    lengths = [len(v) for v in values if v]
    if not lengths:
        return LengthStats(0, 0, 0.0, 0, 0)
    lengths.sort()
    n = len(lengths)
    return LengthStats(
        min=lengths[0],
        max=lengths[-1],
        mean=statistics.fmean(lengths),
        p50=lengths[n // 2],
        count=n,
    )


def compute_value_type_distribution(
    values: Iterable[str],
) -> dict[str, int]:
    """Compte les occurrences de chaque ``value_type`` dans ``values``.

    Retourne un dict ``{value_type: count}`` non-trié. Les types absents ne
    sont PAS présents dans le dict (vs ``count=0``) — caller doit utiliser
    ``.get(type, 0)`` pour les lookups défensifs.
    """
    counts: dict[str, int] = {}
    for v in values:
        t = classify_value_type(v)
        counts[t] = counts.get(t, 0) + 1
    return counts


def majority_value_type(distribution: dict[str, int]) -> str:
    """Type majoritaire dans une distribution. Ignore ``"empty"``.

    Retourne ``""`` si la distribution est vide ou ne contient que ``"empty"``.
    Ce comportement est aligné avec ``pipeline.py::_phase_2_5_lookup_value_type_majority``
    qui retourne aussi ``""`` quand le type majoritaire est NULL/empty.
    """
    if not distribution:
        return ""
    filtered = {t: n for t, n in distribution.items() if t != "empty"}
    if not filtered:
        return ""
    return max(filtered.items(), key=lambda kv: kv[1])[0]


@dataclass(frozen=True)
class ColumnValueStats:
    """Stats agrégées d'une colonne (pour ``value_mapping_stratification``).

    Properties (testables) :
    - ``tier`` reflète la **cardinalité totale** de la colonne (pas le sample size)
    - ``coverage_ratio = min(1.0, sampled_count / total_distinct)``
    - ``is_exhaustive`` ⇔ toutes les valeurs distinctes de la colonne sont indexées
    - ``majority_type`` = type majoritaire excluant ``"empty"``
    """

    total_distinct: int
    sampled_count: int
    tier: CardinalityTier
    length_stats: LengthStats
    value_type_distribution: dict[str, int]
    coverage_ratio: float
    is_exhaustive: bool
    majority_type: str

    @classmethod
    def from_sample(
        cls,
        sampled_values: Iterable[str],
        *,
        total_distinct: int,
    ) -> "ColumnValueStats":
        """Construit ``ColumnValueStats`` depuis un échantillon + cardinalité connue.

        ``total_distinct`` doit être >= 0. Si ``sampled_values`` contient plus
        de ``total_distinct`` éléments (ne devrait pas arriver — incohérence
        upstream), on cap ``coverage_ratio`` à 1.0.

        ``sampled_values`` peut contenir des doublons (post-anonymisation) ;
        on les laisse passer dans ``length_stats`` et ``value_type_distribution``
        car ils reflètent la distribution observée. ``sampled_count`` est le
        nombre d'éléments matérialisés (post-iteration).
        """
        if total_distinct < 0:
            raise ValueError(f"total_distinct doit être ≥ 0, reçu {total_distinct!r}")
        values_list = list(sampled_values)
        n_sampled = len(values_list)
        tier = decide_cardinality_tier(total_distinct)
        length_stats = compute_length_stats(values_list)
        type_dist = compute_value_type_distribution(values_list)

        if total_distinct == 0:
            coverage = 1.0 if n_sampled == 0 else 0.0
        else:
            coverage = min(n_sampled / total_distinct, 1.0)

        is_exhaustive = (total_distinct == 0 and n_sampled == 0) or coverage >= 1.0

        return cls(
            total_distinct=total_distinct,
            sampled_count=n_sampled,
            tier=tier,
            length_stats=length_stats,
            value_type_distribution=type_dist,
            coverage_ratio=coverage,
            is_exhaustive=is_exhaustive,
            majority_type=majority_value_type(type_dist),
        )

    def to_dict(self) -> dict:
        """Sérialise pour training_store (pas de cleartext PII — agrégats seuls)."""
        return {
            "total_distinct": self.total_distinct,
            "sampled_count": self.sampled_count,
            "tier": self.tier,
            "coverage_ratio": round(self.coverage_ratio, 4),
            "is_exhaustive": self.is_exhaustive,
            "majority_type": self.majority_type,
            "length_min": self.length_stats.min,
            "length_max": self.length_stats.max,
            "length_mean": round(self.length_stats.mean, 2),
            "length_p50": self.length_stats.p50,
            "length_count": self.length_stats.count,
            "value_type_distribution": dict(self.value_type_distribution),
        }


def value_compatible_with_stats(
    user_value: str,
    stats: ColumnValueStats,
    *,
    length_slack: int = 0,
) -> bool:
    """Test de compatibilité ``user_value`` ↔ ``ColumnValueStats``.

    Utilisé par le préflight Phase 2.5 comme fallback intelligent quand
    ``user_value`` n'est pas dans ``value_mapping`` (column high-card capped) :

    1. Si ``stats.length_stats.count == 0`` → True (pas de signal pour
       éliminer ; conservateur).
    2. Si ``len(user_value)`` hors ``[length_min - slack, length_max + slack]``
       → False (incompatibilité quasi-certaine).
    3. Sinon, comparer ``classify_value_type(user_value)`` à
       ``stats.majority_type``. Si majority_type vide → True (fallback safe).
       Sinon, ``True`` si compatible (text↔text/code, number↔number/code).

    ``length_slack`` permet de tolérer une marge (espaces parasites, etc.).
    """
    if stats.length_stats.count == 0:
        return True
    user_val_str = str(user_value).strip()
    user_len = len(user_val_str)
    if user_len < stats.length_stats.min - length_slack:
        return False
    if user_len > stats.length_stats.max + length_slack:
        return False
    if not stats.majority_type:
        return True
    user_type = classify_value_type(user_val_str)
    if user_type == "empty":
        return True
    if user_type == stats.majority_type:
        return True
    # Tolérance volontaire alignée sur _phase_2_5_value_type_compatible :
    # text user matche text ou code côté colonne, number matche number ou code.
    if user_type == "text" and stats.majority_type == "code":
        return True
    if user_type == "number" and stats.majority_type == "code":
        return True
    return False
