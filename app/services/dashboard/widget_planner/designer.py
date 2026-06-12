"""LLM Designer — seconde micro-tâche du pipeline widget.

Input :
    - intent (décidé par l'Analyst)
    - transformed_shape : données AGRÉGÉES réelles (après application de la recette)
    - user_hint (optionnel)
    - hints : suggestions de l'Analyst (chart_type proposé, etc.)

Output :
    RenderSpec = {title, subtitle, chart_type, col_span, number_format, unit, insight, axis_labels}

Le Designer voit les données POST-transformation (petit volume : max ~20 rows
agrégées ou 1 KPI). Pour un bar chart groupé par client, il voit {cptLibelle,
total} — noms réels + montants réels. C'est nécessaire pour un insight
pertinent. Les éventuels tokens ~xxx de l'insight passent ensuite par
``restore_anonymized_values`` côté pipeline avant persistance.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

from app.models.dashboard import DashboardWidget
from app.services.ai.llm_providers import LLMRequest
from app.services.dashboard.widget_planner._llm_common import (
    LLMCallError,
    call_llm_with_retry,
    get_llm_and_model,
    parse_json_response,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


_VALID_WIDGET_TYPES = DashboardWidget.VALID_WIDGET_TYPES
_VALID_CHART_TYPES = DashboardWidget.VALID_CHART_TYPES
_VALID_COL_SPANS = DashboardWidget.VALID_COL_SPANS

_VALID_NUMBER_FORMATS = frozenset(
    {"number", "integer", "decimal", "currency_eur", "percent", "none"}
)

_DESIGNER_MAX_TOKENS = 600
_MAX_TITLE_LEN = 80
# Insight très court — style Power BI : une ligne au plus. Affiché en pied
# de widget, pas en bandeau prominent.
_MAX_INSIGHT_LEN = 140


@dataclass
class RenderSpec:
    """Décisions de présentation prêtes à persister dans le widget.

    Note : ``subtitle`` a été retiré du schéma actif (v3) — redondant avec
    title + insight en termes visuels. Champ conservé dans ``to_dict``
    uniquement pour backward-compat avec les widgets déjà persistés.
    """

    title: str
    widget_type: str  # kpi | chart | table
    chart_type: Optional[str]  # bar | line | pie | donut | area | scatter
    col_span: int
    insight: Optional[str] = None
    unit: Optional[str] = None
    number_format: str = "number"
    x_label: Optional[str] = None
    y_label: Optional[str] = None
    reasoning: Optional[str] = None
    color_hint: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Forme persistée dans data_source_config.render_spec."""
        return {
            "title": self.title,
            "widget_type": self.widget_type,
            "chart_type": self.chart_type,
            "col_span": self.col_span,
            "insight": self.insight,
            "unit": self.unit,
            "number_format": self.number_format,
            "x_label": self.x_label,
            "y_label": self.y_label,
            "color_hint": self.color_hint,
        }


def _build_system_prompt() -> str:
    return (
        "Tu es le Designer d'un widget de tableau de bord style Power BI. "
        "Un agent Analyst a déjà décidé l'INTENT et la TRANSFORMATION — "
        "tu reçois les données DÉJÀ agrégées. Ta mission : habiller le widget "
        "avec le MINIMUM de texte — les chiffres et les visuels doivent parler "
        "d'eux-mêmes (c'est l'esthétique Power BI). "
        "Tu décides : un titre court, le type précis de visualisation, format "
        "des nombres, unité, labels d'axes si utiles, et UNE insight analytique "
        "très courte (≤ 1 ligne). Pas de verbiage. "
        "Tu réponds UNIQUEMENT avec un JSON strict, sans texte autour, "
        "sans code fence."
    )


def _build_user_payload(
    intent: str,
    transformed_shape: dict[str, Any],
    analyst_hints: dict[str, Any],
    user_hint: Optional[str],
) -> str:
    parts: list[str] = []
    if user_hint:
        parts.append(f"Instructions de l'utilisateur :\n{user_hint.strip()}")
        parts.append("")

    parts.append(f"Intent choisie par l'Analyst : {intent}")
    if analyst_hints:
        parts.append(f"Hints Analyst : {json.dumps(analyst_hints, ensure_ascii=False)}")
    parts.append("")

    parts.append("Données APRÈS transformation (c'est ce qui sera rendu) :")
    parts.append("```json")
    # #18f (verdict #51) — couper PAR ITEMS, pas par chars : l'ancien
    # ``[:4000]`` tronquait le JSON en pleine structure (le LLM lisait un
    # objet corrompu sans le savoir). On réduit rows/labels item par item
    # jusqu'à tenir le budget — JSON toujours valide, flags *_truncated
    # posés en conséquence.
    _shape = transformed_shape
    _shape_json = json.dumps(_shape, ensure_ascii=False, default=str)
    if len(_shape_json) > 4000 and isinstance(_shape, dict):
        _shape = dict(_shape)
        for _key in ("rows", "labels"):
            _seq = _shape.get(_key)
            while isinstance(_seq, list) and len(_seq) > 1 and len(_shape_json) > 4000:
                _seq = _seq[:-1]
                _shape[_key] = _seq
                _shape[f"{_key}_truncated"] = True
                _shape_json = json.dumps(_shape, ensure_ascii=False, default=str)
    # Plafond DUR de dernier recours (revue adv. lot 3) : la boucle ne
    # réduit que rows/labels — un shape pathologique (autres clés énormes)
    # ne doit pas produire un prompt non borné. JSON cassé assumé ET
    # annoncé (le flag ci-dessous neutralise les superlatifs).
    if len(_shape_json) > 8000:
        _shape_json = _shape_json[:8000] + "\n… [payload tronqué à 8000 chars]"
        if isinstance(_shape, dict):
            _shape = dict(_shape)
            _shape["rows_truncated"] = True
    parts.append(_shape_json)
    parts.append("```")
    parts.append("")

    _is_partial = isinstance(_shape, dict) and (
        _shape.get("rows_truncated")
        or _shape.get("labels_truncated")
        or _shape.get("datasets_truncated")
        # #48 — chart à agg non additive (avg/min/max) dont des catégories ont été
        # droppées (Top N sur Y) : l'insight ne doit pas affirmer un superlatif
        # global (le vrai max peut être dans les catégories non affichées).
        or _shape.get("truncated_categories")
    )
    if _is_partial:
        parts.append(
            "⚠ ATTENTION : les données ci-dessus sont un ÉCHANTILLON PARTIEL "
            "(voir rows_truncated/labels_truncated et row_count/label_count). "
            "INTERDIT d'affirmer un max/min/classement/superlatif GLOBAL dans "
            "`insight` — il peut être faux sur les données complètes. Dans ce "
            "cas : insight=null, ou limité aux totaux/structures certains."
        )
        parts.append("")

    parts.append(
        "MINIMALISME — style Power BI. Pas de phrases en trop. Les visuels "
        "parlent d'eux-mêmes. Ne remplis QUE ce qui ajoute vraiment de la valeur.\n"
        "\n"
        "Choisis :\n"
        f"- widget_type ∈ {list(_VALID_WIDGET_TYPES)}\n"
        f"- chart_type ∈ {list(_VALID_CHART_TYPES)} si widget_type=chart sinon null\n"
        f"- col_span ∈ {list(_VALID_COL_SPANS)} (respecte le col_span suggéré par l'Analyst)\n"
        "- title : TRÈS COURT (≤ 50 chars idéal, max 80). Pas de ponctuation finale.\n"
        '    Pour un KPI, le title est le LABEL (ex: "Total facturé", pas "Total facturé '
        'sur le trimestre 2024").\n'
        f"- number_format ∈ {sorted(_VALID_NUMBER_FORMATS)}\n"
        "    * number/integer/decimal : nombres (fr-FR, 1 234,56)\n"
        "    * currency_eur : valeurs monétaires €\n"
        "    * percent : pourcentages\n"
        "    * none : brut\n"
        "- unit : null ou suffixe court ('€', 'k€', '%', 'h')\n"
        "- x_label / y_label : null si évident (souvent null est la bonne réponse)\n"
        "- insight : null OU 1 PHRASE TRÈS COURTE (≤ 120 chars) qui ajoute quelque\n"
        "    chose que le chart ne montre pas (un pourcentage, un classement).\n"
        "    Mieux : laisser null que blabla redondant avec le chart.\n"
        "- color_hint : null ou 'brand' | 'positive' | 'negative' | 'neutral'\n"
        "- reasoning : 1 phrase debug (non affichée)\n"
    )
    parts.append("")
    parts.append("Réponds STRICTEMENT avec ce JSON :")
    parts.append("""{
  "widget_type": "kpi|chart|table",
  "chart_type": "bar|line|pie|donut|area|scatter" ou null,
  "col_span": 3|4|6|8|12,
  "title": "...",
  "number_format": "number|integer|decimal|currency_eur|percent|none",
  "unit": "..." ou null,
  "x_label": "..." ou null,
  "y_label": "..." ou null,
  "insight": "..." ou null,
  "color_hint": "brand|positive|negative|neutral" ou null,
  "reasoning": "..."
}""")
    return "\n".join(parts)


async def design_render_spec(
    intent: str,
    transformed_shape: dict[str, Any],
    analyst_hints: dict[str, Any],
    user_hint: Optional[str] = None,
    *,
    user_id: Optional[int] = None,
) -> RenderSpec:
    """Call LLM #2 : décide toute la présentation du widget.

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
            prompt=_build_user_payload(intent, transformed_shape, analyst_hints or {}, user_hint),
            system=_build_system_prompt(),
            model=model_name,
            temperature=0.3,
            max_tokens=_DESIGNER_MAX_TOKENS,
        ),
        stage="Designer",
        provider_name=provider_name,
        user_id=user_id,
        context_kind="WIDGET_PLAN",
    )
    if not raw:
        raise LLMCallError("Réponse Designer vide")

    data = parse_json_response(raw, "Designer")
    return _validate(data, intent, transformed_shape)


def _infer_widget_type(intent: str, shape: dict[str, Any]) -> str:
    """Fallback robuste quand widget_type est invalide dans la réponse LLM."""
    if intent == "kpi_single" or shape.get("type") == "kpi":
        return "kpi"
    if intent == "detail_table" or shape.get("type") == "table":
        return "table"
    return "chart"


def _infer_chart_type(intent: str, shape: dict[str, Any]) -> Optional[str]:
    if intent == "trend":
        return "line"
    if intent == "distribution":
        return "donut"
    if intent == "comparison":
        return "bar"
    # kpi / table → pas de chart_type
    return None


def _str_or_none(val: Any, cap: int) -> Optional[str]:
    if not isinstance(val, str):
        return None
    s = val.strip()
    if not s:
        return None
    return s[:cap]


def _validate(data: dict[str, Any], intent: str, shape: dict[str, Any]) -> RenderSpec:
    title = _str_or_none(data.get("title"), _MAX_TITLE_LEN)
    if not title:
        title = "Widget"  # Ultime fallback — ne bloque pas la création

    widget_type = data.get("widget_type")
    if widget_type not in _VALID_WIDGET_TYPES:
        widget_type = _infer_widget_type(intent, shape)

    chart_type = data.get("chart_type")
    if chart_type in ("", None):
        chart_type = None
    elif chart_type not in _VALID_CHART_TYPES:
        chart_type = None
    if widget_type != "chart":
        chart_type = None  # cohérence
    elif chart_type is None:
        chart_type = _infer_chart_type(intent, shape) or "bar"

    try:
        col_span = int(data.get("col_span"))
    except (TypeError, ValueError):
        col_span = None
    if col_span not in _VALID_COL_SPANS:
        # Défauts sensés par intent
        col_span = 3 if widget_type == "kpi" else (12 if widget_type == "table" else 6)

    number_format = data.get("number_format")
    if number_format not in _VALID_NUMBER_FORMATS:
        number_format = "number"

    color_hint = data.get("color_hint")
    if color_hint not in (None, "brand", "positive", "negative", "neutral"):
        color_hint = None

    return RenderSpec(
        title=title,
        widget_type=widget_type,
        chart_type=chart_type,
        col_span=col_span,
        insight=_str_or_none(data.get("insight"), _MAX_INSIGHT_LEN),
        unit=_str_or_none(data.get("unit"), 10),
        number_format=number_format,
        x_label=_str_or_none(data.get("x_label"), 60),
        y_label=_str_or_none(data.get("y_label"), 60),
        reasoning=_str_or_none(data.get("reasoning"), 300),
        color_hint=color_hint,
    )
