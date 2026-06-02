"""Pattern store pour Iris — motifs analytiques réutilisables.

Un **motif analytique** est une structure SQL canonique (ex: rollup avec
totaux superposés, balance âgée, rolling total, top-N…) qui s'applique à
des questions utilisateur partageant une intention similaire.

Philosophie anti-2+2=4 :
- Un motif ne contient AUCUN nom de table/colonne spécifique à une BDD.
- Les placeholders sont nommés par leur RÔLE (<fact_table>, <measure_column>,
  <time_expression>) — le LLM les instancie en cherchant lui-même avec
  ``search_schema`` / ``introspect_table``.
- Le motif aide le LLM à **reconnaître** l'intention analytique et à voir
  la structure SQL type, pas à copier une requête pré-faite.

Source : fichier YAML ``app/services/ai/data/analytical_patterns.yaml`` (seed +
extensions). Chargement avec cache TTL — rechargement automatique si le fichier
change. Fallback dev rétro-compatible sur l'ancien ``data/analytical_patterns.yaml``.
"""

from __future__ import annotations

import logging
import pathlib
import re
import time
from dataclasses import dataclass
from typing import Any, Optional

try:
    import yaml

    _YAML_AVAILABLE = True
except ImportError:  # pragma: no cover
    _YAML_AVAILABLE = False

logger = logging.getLogger(__name__)


# Emplacement par défaut du fichier YAML de patterns.
#
# SOUS ``app/`` (et non ``data/``) à dessein : ``data/`` est exclu de l'image
# Docker ET masqué au runtime par le volume nommé ``komptia-data`` (vide sur un
# client neuf). Un YAML rangé là serait introuvable en prod → Iris perd
# silencieusement toute sa bibliothèque de motifs (dégradation invisible de la
# qualité NL→SQL). Sous ``app/services/ai/data/`` il est embarqué
# automatiquement (``COPY app/`` + rsync ``/app/***``).
_DEFAULT_PATTERNS_PATH = (
    pathlib.Path(__file__).resolve().parent / "data" / "analytical_patterns.yaml"
)

# Fallback dev rétro-compatible : ancien emplacement ``<repo>/data/``. Permet à
# un dev de déposer des extensions locales sans casser, et garantit la
# continuité si le YAML n'a pas encore été déplacé dans une vieille checkout.
_LEGACY_PATTERNS_PATH = (
    pathlib.Path(__file__).resolve().parent.parent.parent.parent
    / "data"
    / "analytical_patterns.yaml"
)

# Cache TTL pour le chargement (en secondes). Le fichier est relu si plus
# récent que le cache.
_CACHE_TTL_SECONDS = 60


@dataclass(frozen=True)
class PatternSignature:
    """Une signature de question : pattern regex + poids.

    Le score final d'un motif sur une question est la somme des poids des
    signatures qui matchent (case-insensitive). Un motif candidat est
    retenu si son score ≥ ``min_score`` du motif.
    """

    pattern: str
    weight: float = 1.0

    def matches(self, question: str) -> bool:
        try:
            return bool(re.search(self.pattern, question, re.IGNORECASE))
        except re.error:
            logger.debug("Regex invalide dans signature : %s", self.pattern)
            return False


@dataclass(frozen=True)
class AnalyticalPattern:
    """Un motif analytique chargé depuis le YAML."""

    slug: str
    name: str
    description: str
    signatures: tuple[PatternSignature, ...]
    sql_skeleton: str
    required_inputs: tuple[dict[str, Any], ...]
    examples: tuple[dict[str, Any], ...]
    tags: tuple[str, ...]
    min_score: float = 1.0  # score seuil pour matcher
    owner: str = "system"
    last_validated: Optional[str] = None

    def score_question(self, question: str) -> float:
        """Score de matching d'une question sur ce motif.

        Somme des poids des signatures qui matchent. 0 si aucune match.
        """
        if not question:
            return 0.0
        total = 0.0
        for sig in self.signatures:
            if sig.matches(question):
                total += sig.weight
        return total

    def to_prompt_block(self) -> str:
        """Rend le motif sous forme Markdown injectable dans un prompt.

        Volontairement TYPÉ abstrait : pas de noms de tables/colonnes
        spécifiques — seulement les rôles et la structure.
        """
        lines = [
            f"### Motif analytique : {self.name}",
            f"_{self.description}_",
            "",
            "**Structure SQL canonique** (à instancier avec TES tables et colonnes) :",
            "```sql",
            self.sql_skeleton.rstrip(),
            "```",
            "",
            "**Rôles à résoudre** (utilise tes outils pour identifier chacun) :",
        ]
        for inp in self.required_inputs:
            if isinstance(inp, dict):
                name = inp.get("name", "?")
                role = inp.get("role", "?")
                desc = inp.get("description", "")
                lines.append(f"- `<{name}>` ({role}) — {desc}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════
# Cache de chargement
# ══════════════════════════════════════════════════════════════════════

_cached_patterns: Optional[tuple[AnalyticalPattern, ...]] = None
_cache_mtime: float = 0.0
_cache_load_time: float = 0.0


def _parse_signature(raw: Any) -> Optional[PatternSignature]:
    if isinstance(raw, str):
        return PatternSignature(pattern=raw, weight=1.0)
    if isinstance(raw, dict):
        pattern = raw.get("pattern")
        if not isinstance(pattern, str):
            return None
        weight = raw.get("weight", 1.0)
        try:
            weight = float(weight)
        except (TypeError, ValueError):
            weight = 1.0
        return PatternSignature(pattern=pattern, weight=weight)
    return None


def _parse_pattern(raw: dict[str, Any]) -> Optional[AnalyticalPattern]:
    """Parse un dict YAML en AnalyticalPattern. Retourne None si invalide."""
    slug = raw.get("slug")
    name = raw.get("name")
    if not isinstance(slug, str) or not isinstance(name, str):
        logger.warning("Pattern sans slug ou name — ignoré : %r", raw.get("slug"))
        return None

    sigs_raw = raw.get("question_signatures") or []
    signatures: list[PatternSignature] = []
    for s in sigs_raw:
        parsed = _parse_signature(s)
        if parsed:
            signatures.append(parsed)

    return AnalyticalPattern(
        slug=slug,
        name=name,
        description=str(raw.get("description") or ""),
        signatures=tuple(signatures),
        sql_skeleton=str(raw.get("sql_skeleton") or ""),
        required_inputs=tuple(
            inp for inp in (raw.get("required_inputs") or []) if isinstance(inp, dict)
        ),
        examples=tuple(ex for ex in (raw.get("examples") or []) if isinstance(ex, dict)),
        tags=tuple(t for t in (raw.get("tags") or []) if isinstance(t, str)),
        min_score=float(raw.get("min_score", 1.0)),
        owner=str(raw.get("owner") or "system"),
        last_validated=raw.get("last_validated"),
    )


def load_patterns(
    path: Optional[pathlib.Path] = None,
    *,
    force_reload: bool = False,
) -> tuple[AnalyticalPattern, ...]:
    """Charge les motifs depuis le YAML avec cache TTL.

    Args:
        path: chemin alternatif (pour les tests). Par défaut :
            ``app/services/ai/data/analytical_patterns.yaml`` (fallback dev sur
            l'ancien ``data/analytical_patterns.yaml`` à la racine).
        force_reload: ignore le cache.

    Returns:
        Tuple de motifs. Vide si fichier absent ou YAML invalide.
    """
    global _cached_patterns, _cache_mtime, _cache_load_time

    if not _YAML_AVAILABLE:
        logger.warning("pyyaml non installé — patterns non chargés")
        return ()

    resolved = path or _DEFAULT_PATTERNS_PATH
    # Fallback dev sur l'ancien emplacement ``data/`` si l'utilisateur n'a pas
    # passé de chemin explicite et que le YAML embarqué n'est pas là (vieille
    # checkout, extension locale). En prod le chemin par défaut sous ``app/``
    # existe toujours → le fallback ne se déclenche pas.
    if path is None and not resolved.exists() and _LEGACY_PATTERNS_PATH.exists():
        resolved = _LEGACY_PATTERNS_PATH
    if not resolved.exists():
        logger.debug("Pattern file introuvable : %s", resolved)
        return ()

    now = time.monotonic()
    mtime = resolved.stat().st_mtime
    cache_valid = (
        not force_reload
        and _cached_patterns is not None
        and mtime == _cache_mtime
        and (now - _cache_load_time) < _CACHE_TTL_SECONDS
    )
    if cache_valid:
        return _cached_patterns  # type: ignore[return-value]

    try:
        with resolved.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as exc:
        logger.error("Échec chargement patterns YAML : %s", exc)
        return ()

    if not isinstance(data, dict):
        logger.error("YAML patterns : format invalide (dict attendu)")
        return ()

    raw_patterns = data.get("patterns") or []
    if not isinstance(raw_patterns, list):
        logger.error("YAML patterns : clé 'patterns' doit être une liste")
        return ()

    parsed: list[AnalyticalPattern] = []
    for raw in raw_patterns:
        if not isinstance(raw, dict):
            continue
        p = _parse_pattern(raw)
        if p is not None:
            parsed.append(p)

    _cached_patterns = tuple(parsed)
    _cache_mtime = mtime
    _cache_load_time = now
    logger.info("Patterns analytiques chargés : %d motifs", len(parsed))
    return _cached_patterns


def invalidate_cache() -> None:
    """Force le prochain ``load_patterns`` à relire le YAML."""
    global _cached_patterns, _cache_mtime, _cache_load_time
    _cached_patterns = None
    _cache_mtime = 0.0
    _cache_load_time = 0.0


# ══════════════════════════════════════════════════════════════════════
# Matcher
# ══════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class PatternMatch:
    """Résultat d'un matching pattern × question."""

    pattern: AnalyticalPattern
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "slug": self.pattern.slug,
            "name": self.pattern.name,
            "score": round(self.score, 2),
            "description": self.pattern.description,
            "tags": list(self.pattern.tags),
        }


def match_patterns(
    question: str,
    *,
    max_results: int = 3,
    patterns_override: Optional[tuple[AnalyticalPattern, ...]] = None,
    exemplar_boosts: Optional[dict[str, float]] = None,
) -> list[PatternMatch]:
    """Retourne les motifs dont le score ≥ min_score, triés par score desc.

    Args:
        question: la question utilisateur en texte naturel.
        max_results: nombre max de matches retournés (top-N).
        patterns_override: liste de patterns à utiliser (tests).
        exemplar_boosts: dict ``{slug: bonus}`` ajouté au score du pattern
            correspondant. Permet de capitaliser sur les validations ✅
            réelles (P2.5 + P4.3). Non-intrusif : si absent, comportement
            inchangé. Les bonus plafonnés côté appelant, ici on les prend
            tels quels.
    """
    patterns = patterns_override if patterns_override is not None else load_patterns()
    if not patterns or not question:
        return []
    matches: list[PatternMatch] = []
    for p in patterns:
        score = p.score_question(question)
        if exemplar_boosts and p.slug in exemplar_boosts:
            score += float(exemplar_boosts[p.slug] or 0.0)
        if score >= p.min_score:
            matches.append(PatternMatch(pattern=p, score=score))
    matches.sort(key=lambda m: m.score, reverse=True)
    return matches[:max_results]


# ══════════════════════════════════════════════════════════════════════
# Exemplar boosts — P2.5 + P4.3
# ══════════════════════════════════════════════════════════════════════

# Bonus max cumulable par pattern. Empêche qu'un pattern très
# fréquemment validé écrase systématiquement les autres.
_EXEMPLAR_BOOST_CAP = 2.0
_EXEMPLAR_BOOST_PER_HIT = 0.5

# Cache (TTL 5 min) pour éviter une requête BDD à chaque match.
_EXEMPLAR_CACHE: dict[str, float] = {}
_EXEMPLAR_CACHE_TS: float = 0.0
_EXEMPLAR_CACHE_TTL = 300


async def fetch_exemplar_boosts(
    *,
    cap: float = _EXEMPLAR_BOOST_CAP,
    per_hit: float = _EXEMPLAR_BOOST_PER_HIT,
    force_reload: bool = False,
) -> dict[str, float]:
    """Compte les exemplars par slug (catégorie ``pattern_exemplar:<slug>``)
    et convertit en bonus de score plafonné.

    Anti-2+2=4 : on ne modifie pas les patterns hardcodés, on alimente juste
    une *prime* de score pour les motifs qui ont des validations réelles.
    Sans exemplars, la table est vide et le matching reste identique.
    """
    global _EXEMPLAR_CACHE, _EXEMPLAR_CACHE_TS
    now = time.time()
    if not force_reload and _EXEMPLAR_CACHE_TS and (now - _EXEMPLAR_CACHE_TS) < _EXEMPLAR_CACHE_TTL:
        return dict(_EXEMPLAR_CACHE)
    try:
        from sqlalchemy import func, select
        from app.core.database import get_session
        from app.models.training_data import TrainingData

        async with get_session() as session:
            stmt = (
                select(TrainingData.category, func.count())
                .where(TrainingData.category.like("pattern_exemplar:%"))
                .where(TrainingData.is_active == True)  # noqa: E712
                .group_by(TrainingData.category)
            )
            result = await session.execute(stmt)
            rows = result.all()
        boosts: dict[str, float] = {}
        for cat, count in rows:
            if not cat:
                continue
            slug = cat.split(":", 1)[1] if ":" in cat else ""
            if not slug:
                continue
            raw = float(count) * per_hit
            boosts[slug] = min(cap, raw)
        _EXEMPLAR_CACHE = boosts
        _EXEMPLAR_CACHE_TS = now
        return dict(boosts)
    except Exception as exc:  # noqa: BLE001
        logger.debug("exemplar boosts fetch failed (%s)", exc)
        return dict(_EXEMPLAR_CACHE)


def invalidate_exemplar_cache() -> None:
    """Force le prochain ``fetch_exemplar_boosts`` à recharger."""
    global _EXEMPLAR_CACHE, _EXEMPLAR_CACHE_TS
    _EXEMPLAR_CACHE = {}
    _EXEMPLAR_CACHE_TS = 0.0
