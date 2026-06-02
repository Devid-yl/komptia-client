"""
Calibrateur de confiance multi-signal pour la génération SQL.

Combine 4 signaux pour produire un score de confiance fiable :
1. Consensus entre candidats SQL (2/3 identiques = haute confiance)
2. Couverture RAG (schéma + exemples trouvés)
3. Couverture schéma (tables/colonnes vérifiées)
4. Complexité inverse (requête simple = plus fiable)

Retourne une décision : EXECUTE, CONFIRM, ou CLARIFY.
"""

import re
from dataclasses import dataclass, field
from enum import Enum

from app.utils.logger import get_logger

from app.constants_ai import (
    CONFIDENCE_THRESHOLD_EXECUTE,
    CONFIDENCE_THRESHOLD_CONFIRM,
    CONFIDENCE_WEIGHT_CONSENSUS,
    CONFIDENCE_WEIGHT_RAG,
    CONFIDENCE_WEIGHT_SCHEMA,
    CONFIDENCE_WEIGHT_COMPLEXITY,
    SQL_CANDIDATES_MIN_FOR_CONSENSUS,
)

logger = get_logger(__name__)


class ConfidenceAction(str, Enum):
    """Action recommandée basée sur le score de confiance."""

    EXECUTE = "execute"  # Score >= THRESHOLD_EXECUTE → exécuter directement
    CONFIRM = "confirm"  # THRESHOLD_CONFIRM <= score < THRESHOLD_EXECUTE → montrer à l'user
    CLARIFY = "clarify"  # Score < THRESHOLD_CONFIRM → demander clarification


@dataclass
class SQLCandidate:
    """Un candidat SQL avec ses métadonnées."""

    sql: str
    source: str = ""  # "rag_shortcut", "llm_gen", "correction"
    validation_passed: bool = False
    tables_used: list[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class ConfidenceResult:
    """Résultat complet de la calibration."""

    score: float  # 0.0-1.0
    action: ConfidenceAction
    best_candidate: SQLCandidate | None = None
    consensus_count: int = 0  # Nombre de candidats identiques
    signals: dict = field(default_factory=dict)  # Détail des signaux

    @property
    def explanation(self) -> str:
        """Explication du score pour l'utilisateur."""
        parts = [f"Confiance : {self.score:.0%}"]
        if self.consensus_count >= SQL_CANDIDATES_MIN_FOR_CONSENSUS:
            parts.append(f"({self.consensus_count} candidats SQL identiques)")
        if self.action == ConfidenceAction.CLARIFY:
            parts.append("— précisions recommandées")
        elif self.action == ConfidenceAction.CONFIRM:
            parts.append("— vérification conseillée")
        return " ".join(parts)


def _normalize_sql(sql: str) -> str:
    """Normalise un SQL pour comparaison (whitespace, case, aliases)."""
    s = sql.upper().strip()
    # Normaliser les espaces
    s = re.sub(r"\s+", " ", s)
    # Retirer les alias AS xxx pour comparer la structure
    s = re.sub(r"\bAS\s+\w+\b", "", s)
    # Retirer TOP N (peut varier entre candidats)
    s = re.sub(r"\bTOP\s+\d+\b", "TOP", s)
    return s.strip()


def _compute_consensus(candidates: list[SQLCandidate]) -> tuple[int, SQLCandidate | None]:
    """
    Calcule le consensus entre candidats SQL.

    Returns:
        (nombre de candidats identiques au plus fréquent, meilleur candidat)
    """
    if not candidates:
        return 0, None

    if len(candidates) == 1:
        return 1, candidates[0]

    # Normaliser et grouper
    groups: dict[str, list[SQLCandidate]] = {}
    for c in candidates:
        normalized = _normalize_sql(c.sql)
        if normalized not in groups:
            groups[normalized] = []
        groups[normalized].append(c)

    # Trouver le groupe le plus large
    best_group = max(groups.values(), key=len)
    # Préférer le candidat validé dans le groupe
    best = next((c for c in best_group if c.validation_passed), best_group[0])

    return len(best_group), best


def _compute_complexity_score(sql: str) -> float:
    """
    Score inverse de complexité (1.0 = simple, 0.0 = très complexe).

    Heuristique basée sur le nombre de JOINs, CTEs, sous-requêtes.
    """
    sql_upper = sql.upper()

    joins = len(re.findall(r"\bJOIN\b", sql_upper))
    # Compter les CTEs: chaque "identifier AS (" dans un WITH
    ctes = len(re.findall(r"\w+\s+AS\s*\(", sql_upper)) if re.search(r"\bWITH\b", sql_upper) else 0
    subqueries = sql_upper.count("(SELECT")
    having = 1 if re.search(r"\bHAVING\b", sql_upper) else 0

    # Plus il y a de structures complexes, plus la confiance baisse
    complexity_penalty = joins * 0.08 + ctes * 0.12 + subqueries * 0.15 + having * 0.05

    return max(0.0, min(1.0, 1.0 - complexity_penalty))


def calibrate(
    candidates: list[SQLCandidate],
    rag_confidence: float = 0.0,
    schema_tables_found: int = 0,
    schema_tables_expected: int = 1,
) -> ConfidenceResult:
    """
    Calcule un score de confiance composite et recommande une action.

    Args:
        candidates: Liste de candidats SQL (idéalement 3)
        rag_confidence: Score de confiance RAG (0.0-1.0, de agent_knowledge)
        schema_tables_found: Nombre de tables vérifiées dans le schéma
        schema_tables_expected: Nombre de tables attendues par la requête

    Returns:
        ConfidenceResult avec score, action, et meilleur candidat
    """
    if not candidates:
        return ConfidenceResult(
            score=0.0,
            action=ConfidenceAction.CLARIFY,
            signals={"error": "Aucun candidat SQL"},
        )

    # Signal 1 : Consensus
    consensus_count, best_candidate = _compute_consensus(candidates)
    total = len(candidates)
    consensus_score = consensus_count / total if total > 0 else 0.0

    # Signal 2 : RAG (déjà calculé)
    rag_score = min(1.0, rag_confidence)

    # Signal 3 : Couverture schéma
    schema_score = (
        min(1.0, schema_tables_found / max(schema_tables_expected, 1))
        if schema_tables_expected > 0
        else 0.0  # Aucune table attendue détectée = confiance minimale
    )

    # Signal 4 : Complexité inverse
    complexity_score = _compute_complexity_score(best_candidate.sql) if best_candidate else 0.5

    # Score composite pondéré
    score = (
        CONFIDENCE_WEIGHT_CONSENSUS * consensus_score
        + CONFIDENCE_WEIGHT_RAG * rag_score
        + CONFIDENCE_WEIGHT_SCHEMA * schema_score
        + CONFIDENCE_WEIGHT_COMPLEXITY * complexity_score
    )

    # Bonus si consensus parfait (tous identiques)
    if consensus_count == total and total >= SQL_CANDIDATES_MIN_FOR_CONSENSUS:
        score += 0.1

    # Pénalité si aucun candidat n'a passé la validation
    if all(not c.validation_passed for c in candidates):
        score *= 0.5

    # Borner le score dans [0.0, 1.0]
    score = max(0.0, min(1.0, score))

    # Décision
    if score >= CONFIDENCE_THRESHOLD_EXECUTE:
        action = ConfidenceAction.EXECUTE
    elif score >= CONFIDENCE_THRESHOLD_CONFIRM:
        action = ConfidenceAction.CONFIRM
    else:
        action = ConfidenceAction.CLARIFY

    signals = {
        "consensus": f"{consensus_score:.2f} ({consensus_count}/{total})",
        "rag": f"{rag_score:.2f}",
        "schema": f"{schema_score:.2f} ({schema_tables_found}/{schema_tables_expected})",
        "complexity": f"{complexity_score:.2f}",
        "final": f"{score:.2f}",
    }

    logger.info("Confiance calibrée: %.2f → %s | %s", score, action.value, signals)

    return ConfidenceResult(
        score=score,
        action=action,
        best_candidate=best_candidate,
        consensus_count=consensus_count,
        signals=signals,
    )
