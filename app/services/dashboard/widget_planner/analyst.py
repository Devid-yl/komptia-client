"""LLM Analyst — première micro-tâche du pipeline widget.

Input :
    - profile obfusqué Niveau 2 (pas de valeurs réelles)
    - user_hint (optionnel)

Output :
    IntentPlan = {intent, transformation?, drill_column?}

L'Analyst a UN seul objectif : décider la forme analytique du widget.
Titre, format, couleur, insight — ce n'est PAS son boulot (c'est le Designer).

Pourquoi obfusquer : pour décider "bar chart groupé par cptLibelle", le LLM
a besoin de la CARDINALITÉ de cptLibelle (≤ 20 catégories) et du TYPE de
faiMontantTotalTTC (numérique), pas des noms de clients ni des montants
exacts. Niveau 2 = defense-in-depth.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from app.services.ai.llm_providers import LLMRequest
from app.services.dashboard.widget_planner._llm_common import (
    LLMCallError,
    call_llm_with_retry,
    get_llm_and_model,
    parse_json_response,
)
from app.services.dashboard.widget_planner.transformations import (
    VALID_TRANSFORM_KINDS,
    validate_recipe,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


_VALID_INTENTS = frozenset({"kpi_single", "comparison", "distribution", "trend", "detail_table"})

_ANALYST_MAX_TOKENS = 700


@dataclass
class IntentPlan:
    """Décision d'analyse — ce que l'Analyst a choisi."""

    intent: str  # kpi_single | comparison | distribution | trend | detail_table
    transformation: Optional[dict[str, Any]] = (
        None  # recette pour transformations.apply_transformation
    )
    drill_column: Optional[str] = None
    reasoning: Optional[str] = None
    # Colonnes suggérées pour le Designer (choix final du chart_type, labels)
    hints: dict[str, Any] = field(default_factory=dict)


def _build_system_prompt() -> str:
    return (
        "Tu es un analyste de données. Tu reçois le PROFIL d'un résultat SQL "
        "(valeurs obfusquées pour confidentialité) et tu dois décider, en "
        "UNE seule micro-tâche, la meilleure façon d'afficher ces données "
        "dans un widget de tableau de bord style Power BI. "
        "Ta seule responsabilité : intent + recette de transformation. "
        "Tu ne décides PAS du titre, ni du format, ni des couleurs "
        "(un autre agent s'en charge). "
        "Tu réponds UNIQUEMENT avec un JSON strict, sans texte autour, "
        "sans code fence."
    )


def _build_user_payload(
    obfuscated_profile: dict[str, Any],
    roles: dict[str, list[str]],
    user_hint: Optional[str],
) -> str:
    parts: list[str] = []

    if user_hint:
        parts.append(f"Instructions de l'utilisateur :\n{user_hint.strip()}")
        parts.append("")

    parts.append("PROFIL DES DONNÉES (valeurs obfusquées — Niveau 2 Komptia) :")
    parts.append("```json")
    parts.append(json.dumps(obfuscated_profile, ensure_ascii=False, default=str))
    parts.append("```")
    parts.append("")
    parts.append("Colonnes groupées par rôle analytique :")
    parts.append("```json")
    parts.append(json.dumps(roles, ensure_ascii=False))
    parts.append("```")
    parts.append("")

    parts.append(
        "Choisis UNE intent analytique dans : "
        f"{sorted(_VALID_INTENTS)}.\n"
        "  * kpi_single    : une valeur agrégée unique à mettre en avant (total, moyenne, count)\n"
        "  * comparison    : comparer des catégories (bar/pie) avec un agrégat\n"
        "  * distribution  : répartition d'un total (pie/donut, ≤ 8 parts)\n"
        "  * trend         : évolution temporelle (line/area sur une date)\n"
        "  * detail_table  : quand aucune agrégation n'apporte plus que le détail brut\n"
    )
    parts.append("")
    parts.append(
        "Puis choisis une RECETTE DE TRANSFORMATION à appliquer en Python "
        f"(`kind` ∈ {sorted(VALID_TRANSFORM_KINDS)}) :\n"
        "  * passthrough       : aucune transformation — rows tels quels (pour detail_table)\n"
        "  * scalar_aggregate  : params = {column, agg} — pour kpi_single\n"
        "  * groupby           : params = {category_col, value_col, agg, sort=desc, limit=20}\n"
        "                          pour comparison/distribution\n"
        "  * time_series       : params = {date_col, value_col, agg, bucket=month}\n"
        "                          pour trend\n"
        "\nRègles :\n"
        "  - Les colonnes citées DOIVENT apparaître dans le profil ci-dessus.\n"
        "  - agg ∈ {sum, avg, count, min, max}\n"
        "  - bucket ∈ {day, week, month, quarter, year}\n"
        '  - Si intent = detail_table, transformation = {kind: "passthrough"}.\n'
        "  - Si les données sont DÉJÀ agrégées (ex: Top 10, une seule ligne), utilise passthrough.\n"
    )
    parts.append("")
    parts.append(
        "drill_column : null ou nom d'une colonne catégorielle pertinente "
        "pour cliquer et filtrer (généralement category_col).\n"
        "hints : objet libre que tu passes au Designer (suggestion de chart_type, "
        "colonne unit, axis labels pertinents)."
    )
    parts.append("")
    parts.append("Réponds STRICTEMENT avec ce JSON :")
    parts.append("""{
  "intent": "comparison|distribution|trend|kpi_single|detail_table",
  "transformation": {
    "kind": "passthrough|scalar_aggregate|groupby|time_series",
    "params": { ... }
  },
  "drill_column": "nom_colonne" ou null,
  "hints": {
    "chart_type": "bar|line|pie|donut|area" ou null,
    "unit_column": "nom_colonne" ou null,
    "x_label": "..." ou null,
    "y_label": "..." ou null
  },
  "reasoning": "1 phrase — pourquoi ce choix"
}""")
    return "\n".join(parts)


async def analyze_intent(
    obfuscated_profile: dict[str, Any],
    roles: dict[str, list[str]],
    user_hint: Optional[str] = None,
    *,
    user_id: Optional[int] = None,
) -> IntentPlan:
    """Call LLM #1 : décide intent + recette sur profile obfusqué.

    Args:
        user_id: forwardé au proxy d'anonymisation via
            :func:`call_llm_with_retry`. ``None`` (défaut) pour les tests
            qui ne thread pas l'identité utilisateur — la couche PII regex
            reste active dans tous les cas via ``context_kind="WIDGET_PLAN"``.
    """
    llm, model_name, provider_name = await get_llm_and_model()
    raw = await call_llm_with_retry(
        llm,
        LLMRequest(
            prompt=_build_user_payload(obfuscated_profile, roles, user_hint),
            system=_build_system_prompt(),
            model=model_name,
            temperature=0.15,
            max_tokens=_ANALYST_MAX_TOKENS,
        ),
        stage="Analyst",
        provider_name=provider_name,
        user_id=user_id,
        context_kind="WIDGET_PLAN",
    )
    if not raw:
        raise LLMCallError("Réponse Analyst vide")

    data = parse_json_response(raw, "Analyst")
    return _validate(data, obfuscated_profile)


def _validate(data: dict[str, Any], profile: dict[str, Any]) -> IntentPlan:
    """Sanitize + fallback au detail_table si invalide."""
    columns = [c.get("name") for c in (profile.get("columns") or []) if c.get("name")]

    intent = data.get("intent")
    if intent not in _VALID_INTENTS:
        logger.info("Analyst: intent invalide %r → fallback detail_table", intent)
        intent = "detail_table"

    recipe = validate_recipe(data.get("transformation"), columns)
    # Cohérence intent ↔ recipe : si detail_table → passthrough.
    if intent == "detail_table":
        recipe = {"kind": "passthrough", "params": {}}
    # kpi_single sans recipe → force passthrough (degradation gracieuse)
    if recipe is None:
        logger.info("Analyst: recipe invalide → fallback passthrough")
        recipe = {"kind": "passthrough", "params": {}}
        # Si on a dégradé en passthrough, intent doit suivre
        if intent != "detail_table":
            intent = "detail_table"

    drill = data.get("drill_column")
    if isinstance(drill, str):
        drill = drill.strip()
        if drill and drill not in columns:
            logger.info("Analyst: drill_column %r absent → ignoré", drill)
            drill = None
    else:
        drill = None

    hints = data.get("hints") if isinstance(data.get("hints"), dict) else {}
    reasoning = data.get("reasoning")
    if isinstance(reasoning, str):
        reasoning = reasoning.strip()[:300] or None
    else:
        reasoning = None

    return IntentPlan(
        intent=intent,
        transformation=recipe,
        drill_column=drill,
        reasoning=reasoning,
        hints=hints or {},
    )
