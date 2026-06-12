"""Préparation des données de camembert (SSoT) — partagée par ``chart_builder``
et ``aggregated_chart_renderer`` (#143).

Un camembert ne peut représenter QUE des valeurs strictement positives et finies.
Filtrer les valeurs ≤ 0 / NaN / inf est nécessaire, MAIS le faire silencieusement
fausse les pourcentages : ``matplotlib.pie(..., autopct=...)`` calcule chaque part
sur ``sum(values)`` — la somme des valeurs RÉELLEMENT AFFICHÉES. Deux corrections
de données-fausses, appliquées de façon identique aux deux renderers :

1. **Troncature → part « Autres »** : au-delà de ``max_slices``, on AGRÈGE la
   queue dans une seule part « Autres (N) » au lieu de la dropper. La somme des
   parts affichées redevient égale au total réel des valeurs positives → les
   pourcentages autopct sont corrects (et le camembert est complet).

2. **Exclusions ≤ 0 surfacées** : les valeurs non représentables (≤ 0 / NaN /
   non numériques) sont comptées dans ``excluded_nonpos`` pour que l'appelant
   l'INDIQUE (légende), au lieu de les masquer.

Fonction pure et déterministe → testable sans matplotlib.
"""
from __future__ import annotations

import math
from typing import Any, Iterable, List, Optional, Tuple


def coerce_positive(val: Any) -> Optional[float]:
    """Convertit ``val`` en float strictement positif et fini, sinon ``None``.

    ``None`` signale « non représentable dans un camembert » (≤ 0, NaN, inf,
    non numérique, booléen). Accepte les chaînes numériques (``"12.5"``).
    Le booléen est rejeté explicitement (``bool ⊂ int`` en Python : sans ce
    garde ``True`` deviendrait une part de valeur 1.0)."""
    if isinstance(val, bool):
        return None
    try:
        f = float(val)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(f) or f <= 0:
        return None
    return f


def prepare_pie_slices(
    raw_pairs: Iterable[Tuple[Any, Any]],
    max_slices: int = 0,
    others_label: str = "Autres",
    label_maxlen: int = 0,
) -> Tuple[List[str], List[float], int, int]:
    """Prépare ``(labels, values, others_count, excluded_nonpos)`` pour un pie.

    - ``raw_pairs`` : itérable de ``(label, raw_value)``.
    - ``max_slices`` : si > 0 et qu'il y a plus de ``max_slices`` parts positives,
      la queue (au-delà des ``max_slices - 1`` premières) est agrégée dans une
      part « Autres (N) ». ``0`` = pas d'agrégation (montre toutes les parts).
    - ``label_maxlen`` : si > 0, tronque les labels à cette longueur.

    Invariant clé : ``sum(values)`` == somme de TOUTES les valeurs positives
    fournies (tête + queue agrégée). C'est ce qui garantit des pourcentages
    autopct corrects vis-à-vis du total réel représentable.
    """
    positives: List[Tuple[str, float]] = []
    excluded_nonpos = 0
    for label, raw in raw_pairs:
        v = coerce_positive(raw)
        if v is None:
            excluded_nonpos += 1
            continue
        text = str(label)
        if label_maxlen > 0:
            text = text[:label_maxlen]
        positives.append((text, v))

    others_count = 0
    if max_slices and max_slices > 0 and len(positives) > max_slices:
        head = positives[: max_slices - 1]
        tail = positives[max_slices - 1:]
        others_count = len(tail)
        # math.fsum : somme exacte (pas d'erreur d'arrondi cumulée sur la queue).
        others_sum = math.fsum(v for _, v in tail)
        positives = head + [(f"{others_label} ({others_count})", others_sum)]

    labels = [p[0] for p in positives]
    values = [p[1] for p in positives]
    return labels, values, others_count, excluded_nonpos
