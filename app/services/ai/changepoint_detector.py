"""Détection de changepoint : la même question donne-t-elle un résultat
fondamentalement différent aujourd'hui qu'avant ?

Compare ``row_count`` de l'exécution courante avec la médiane des N
dernières exécutions réussies d'une question similaire (similarité par
hash de question normalisée). Si l'écart dépasse un seuil relatif, on
émet un ``ChangeAlert`` — ce n'est qu'un signal pour Iris/l'utilisateur,
jamais un blocage.

Anti-2+2=4 :
- aucun seuil absolu par BDD ; les seuils sont relatifs (pourcentage,
  écart-type) ;
- aucune connaissance des noms de tables/colonnes ;
- l'alerte est purement informative et questionne, ne prescrit pas.
"""

from __future__ import annotations

import hashlib
import re
import statistics
import unicodedata
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from sqlalchemy import select

from app.core import clock
from app.core.database import get_session
from app.models.ai_performance import AIPerformanceLog, QueryStatus
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Constants — tuned to minimize false positives
MIN_HISTORICAL_EXECUTIONS = 3  # en dessous, pas assez de baseline
MAX_HISTORICAL_WINDOW_DAYS = 90  # on n'exploite que l'historique récent
DEFAULT_DELTA_THRESHOLD_PCT = 0.40  # 40% de variation relative
DEFAULT_STDDEV_THRESHOLD = 2.5  # nb écarts-types


# ═══════════════════════════════════════════════════════════════════════
# Modèles
# ═══════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ChangeAlert:
    question_hash: str
    current_row_count: int
    historical_median: float
    historical_count: int
    delta_pct: float
    z_score: Optional[float]
    severity: str  # "info" | "warning"
    message: str


# ═══════════════════════════════════════════════════════════════════════
# Normalisation & hash de question
# ═══════════════════════════════════════════════════════════════════════


def _normalize_question(question: str) -> str:
    if not question:
        return ""
    nfkd = unicodedata.normalize("NFKD", str(question))
    text = "".join(c for c in nfkd if not unicodedata.combining(c)).lower()
    text = re.sub(r"[^\w\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def question_signature(question: str) -> str:
    """Empreinte stable (16 chars) d'une question pour regrouper les exécutions."""
    normalized = _normalize_question(question)
    if not normalized:
        return ""
    return hashlib.blake2b(normalized.encode("utf-8"), digest_size=8).hexdigest()


# ═══════════════════════════════════════════════════════════════════════
# Service
# ═══════════════════════════════════════════════════════════════════════


class ChangepointDetector:
    """Compare la cardinalité actuelle à l'historique pour la même question."""

    def __init__(
        self,
        *,
        delta_threshold_pct: float = DEFAULT_DELTA_THRESHOLD_PCT,
        stddev_threshold: float = DEFAULT_STDDEV_THRESHOLD,
        min_history: int = MIN_HISTORICAL_EXECUTIONS,
        window_days: int = MAX_HISTORICAL_WINDOW_DAYS,
    ) -> None:
        self.delta_threshold_pct = max(0.05, float(delta_threshold_pct))
        self.stddev_threshold = max(1.0, float(stddev_threshold))
        self.min_history = max(2, int(min_history))
        self.window_days = max(1, int(window_days))

    async def detect(
        self,
        *,
        question: str,
        current_row_count: int,
    ) -> Optional[ChangeAlert]:
        """Retourne un ``ChangeAlert`` si l'exécution courante dévie nettement
        de l'historique. Sinon ``None``.
        """
        if current_row_count is None or current_row_count < 0:
            return None
        sig = question_signature(question)
        if not sig:
            return None

        historical = await self._historical_row_counts(question)
        if len(historical) < self.min_history:
            return None

        median = float(statistics.median(historical))
        # Éviter la division par zéro : si médiane = 0, on vérifie juste que
        # le courant est aussi ≈ 0 (sinon alerte différente de cardinality).
        if median <= 0:
            if current_row_count > max(self.min_history, 5):
                return ChangeAlert(
                    question_hash=sig,
                    current_row_count=current_row_count,
                    historical_median=0.0,
                    historical_count=len(historical),
                    delta_pct=float("inf"),
                    z_score=None,
                    severity="info",
                    message=(
                        "Cette question retournait historiquement aucune ligne, "
                        f"elle en retourne {current_row_count} aujourd'hui. "
                        "Si tu t'y attendais, tout va bien ; sinon vérifie les "
                        "filtres et la période."
                    ),
                )
            return None

        delta = (current_row_count - median) / median
        abs_delta = abs(delta)

        z_score: Optional[float] = None
        if len(historical) >= 3:
            stddev = statistics.pstdev(historical)
            if stddev > 0:
                z_score = (current_row_count - median) / stddev

        exceeds_delta = abs_delta >= self.delta_threshold_pct
        exceeds_z = z_score is not None and abs(z_score) >= self.stddev_threshold

        if not (exceeds_delta and exceeds_z):
            return None

        direction = "augmenté" if delta > 0 else "diminué"
        pct_formatted = f"{abs_delta * 100:.0f}%"
        severity = "warning" if abs_delta >= 0.5 else "info"
        message = (
            f"Le nombre de lignes a {direction} de {pct_formatted} par rapport "
            f"à la médiane des {len(historical)} dernières exécutions de la "
            f"même question (médiane = {median:.0f} → courant = "
            f"{current_row_count}). Est-ce cohérent avec ce que tu attendais ? "
            "Un changement aussi marqué peut venir (a) d'un changement métier "
            "réel, (b) d'un filtre ou d'une période différente, (c) d'un "
            "problème d'ingestion de données."
        )
        return ChangeAlert(
            question_hash=sig,
            current_row_count=current_row_count,
            historical_median=median,
            historical_count=len(historical),
            delta_pct=delta,
            z_score=z_score,
            severity=severity,
            message=message,
        )

    async def _historical_row_counts(self, question: str) -> list[int]:
        """Extrait les ``row_count`` des exécutions réussies récentes avec
        une question suffisamment similaire.

        Stratégie de matching : comparaison du texte normalisé (stricte).
        On ne joue pas aux similarités floues ici pour éviter les faux
        positifs — si la question diffère même d'un peu, c'est un autre
        cas d'usage.
        """
        normalized_target = _normalize_question(question)
        if not normalized_target:
            return []
        cutoff = clock.now() - timedelta(days=self.window_days)
        try:
            async with get_session() as session:
                stmt = (
                    select(AIPerformanceLog.question, AIPerformanceLog.result_count)
                    .where(AIPerformanceLog.status == QueryStatus.SUCCESS)
                    .where(AIPerformanceLog.created_at >= cutoff)
                    .where(AIPerformanceLog.result_count.is_not(None))
                    .order_by(AIPerformanceLog.created_at.desc())
                    .limit(500)
                )
                result = await session.execute(stmt)
                rows = result.all()
        except Exception as exc:  # noqa: BLE001
            logger.debug("changepoint: history fetch failed (%s)", exc)
            return []

        counts: list[int] = []
        for q, rc in rows:
            if rc is None:
                continue
            if _normalize_question(q) == normalized_target:
                counts.append(int(rc))
                if len(counts) >= 20:  # cap prudentiel
                    break
        return counts


_default_detector: Optional[ChangepointDetector] = None


def get_changepoint_detector() -> ChangepointDetector:
    global _default_detector
    if _default_detector is None:
        _default_detector = ChangepointDetector()
    return _default_detector


__all__ = [
    "ChangeAlert",
    "ChangepointDetector",
    "get_changepoint_detector",
    "question_signature",
]
