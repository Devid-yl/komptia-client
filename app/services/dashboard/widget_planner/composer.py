"""LLM Composer — décompose UN résultat SQL en N widget proposals.

C'est l'étape-clé du pipeline v3 : au lieu de produire un widget unique (qui
réduit fatalement des données multi-dimensionnelles à 1D), on laisse le LLM
concevoir une **composition** — une mini-dashboard — exploitant toutes les
dimensions disponibles.

Le Composer voit le profile OBFUSQUÉ (Niveau 2) + les rôles des colonnes.
Il rend une liste de 1 à 6 proposals, chacune étant une recette complète
(intent + transformation + col_span suggéré + rôle visuel).

Chaque proposal est ensuite passée par Designer (pour titre/format/insight).
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


_VALID_INTENTS = frozenset(
    {
        "headline_kpi",  # chiffre-clé d'en-tête
        "comparison",  # bar/pie 1D
        "comparison_2d",  # grouped/stacked bar (2 catégories × 1 mesure)
        "trend",  # line/area 1 série
        "trend_multi",  # multi-line 1 date × 1 catégorie × 1 mesure
        "distribution",  # pie/donut
        "top_ranking",  # top N
        "detail_table",  # tableau brut
    }
)

_COMPOSER_MAX_TOKENS = 2000
_MIN_WIDGETS = 1
_MAX_WIDGETS = 6


@dataclass
class WidgetProposal:
    """Une des N proposals que le Composer a décidées."""

    intent: str
    transformation: dict[str, Any]
    suggested_col_span: int
    role: str = "secondary"  # headline_kpi | primary_chart | secondary_chart | detail
    drill_column: Optional[str] = None
    hints: dict[str, Any] = field(default_factory=dict)
    reasoning: Optional[str] = None


def _build_system_prompt() -> str:
    return (
        "Tu es le Composer d'un tableau de bord style Power BI. Tu reçois le "
        "PROFIL d'un résultat SQL (valeurs obfusquées pour confidentialité) "
        "et tu dois concevoir une COMPOSITION de 1 à 6 widgets qui exploitent "
        "ensemble TOUTES les dimensions riches des données (pas seulement une). "
        "Ta seule responsabilité : produire la liste des widgets + leurs "
        "recettes de transformation. Titres, formats, insights — un autre "
        "agent Designer s'en occupe par widget. "
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

    parts.append("PROFIL DES DONNÉES (Niveau 2, valeurs obfusquées) :")
    parts.append("```json")
    parts.append(json.dumps(obfuscated_profile, ensure_ascii=False, default=str))
    parts.append("```")
    parts.append("")
    parts.append("Colonnes par rôle analytique :")
    parts.append("```json")
    parts.append(json.dumps(roles, ensure_ascii=False))
    parts.append("```")
    parts.append("")

    parts.append(
        "CONCEPTION D'UN DASHBOARD :\n"
        "  - Un dashboard Power BI = PLUSIEURS widgets arrangés en GRILLE\n"
        "    HARMONIEUSE — PAS une pile verticale de gros blocs.\n"
        "  - La grille fait 12 colonnes. La somme des col_span d'une LIGNE "
        "logique DOIT être ≤ 12.\n"
        "  - Chaque widget a un RÔLE précis : KPI d'en-tête, comparaison, "
        "tendance, répartition, détail.\n"
        "  - Si 2 catégories riches + 1 mesure → ``groupby_2d`` ou ``top_n_2d``.\n"
        "  - Si 1 date + 1 catégorie + 1 mesure → ``time_series_multi``.\n"
        "  - Si catégorie riche avec beaucoup de modalités → ``groupby`` + limit.\n"
    )
    parts.append("")
    parts.append(
        "⚠️ COLONNES ROLLUP — RÈGLES STRICTES ⚠️\n"
        'Une colonne avec ``"likely_rollup": true`` est le résultat d\'une\n'
        "window function SQL (SUM/AVG/COUNT OVER PARTITION BY…) — la MÊME\n"
        "valeur est RÉPÉTÉE sur plusieurs lignes (cardinalité << nb lignes).\n"
        "Le profile te dit explicitement quelles colonnes le sont via le\n"
        "flag ``likely_rollup``.\n"
        "\n"
        "INTERDICTIONS sur ces colonnes :\n"
        "  ❌ ``scalar_aggregate`` avec agg=sum/avg → DOUBLE-COMPTAGE garanti\n"
        "  ❌ ``groupby`` / ``groupby_2d`` / ``top_n_2d`` / ``time_series*``\n"
        "     avec value_col=rollup → résultats × nb_lignes_par_groupe (faux)\n"
        "\n"
        "USAGE CORRECT des rollups :\n"
        "  ✅ ``scalar_from_column(column=<rollup_col>)`` → lit la valeur telle quelle\n"
        "  ✅ ``scalar_from_column(column=<rollup_col>, filter_col=<dim>,\n"
        "       filter_value=<val>)`` → valeur du rollup pour un sous-ensemble\n"
        "\n"
        "POUR LES AGRÉGATIONS RÉELLES (groupby/top_n/time_series) : ``value_col``\n"
        "DOIT pointer sur une colonne numérique NON-rollup (mesure au niveau-ligne).\n"
    )
    parts.append("")

    parts.append(
        "PATRONS DE LAYOUT (choisis celui qui colle le mieux aux données) :\n"
        "  Patron A (dashboard classique) :\n"
        "    • Ligne 1 : 4 KPIs de col_span=3 chacun        (3+3+3+3 = 12)\n"
        "    • Ligne 2 : 1 primary chart col_span=8 + 1 secondary col_span=4 (8+4)\n"
        "    • Ligne 3 : 1 chart full col_span=12\n"
        "  Patron B (focus distribution/tendance) :\n"
        "    • Ligne 1 : 3 KPIs col_span=4                   (4+4+4 = 12)\n"
        "    • Ligne 2 : 2 charts col_span=6                 (6+6 = 12)\n"
        "    • Ligne 3 : 1 tableau détail col_span=12\n"
        "  Patron C (mono-sujet riche) :\n"
        "    • Ligne 1 : 2 KPIs col_span=3 + 1 chart col_span=6  (3+3+6 = 12)\n"
        "    • Ligne 2 : 1 chart col_span=12\n"
        "  Patron D (simple) :\n"
        "    • Ligne 1 : 1 KPI col_span=3 + 1 chart col_span=9  (3+9 = 12)\n"
        "\n"
        "ÉVITE : aligner 3 charts col_span=12 l'un sous l'autre — c'est monotone.\n"
        "PRÉFÈRE : mélanger tailles pour créer une hiérarchie visuelle.\n"
    )
    parts.append("")

    parts.append(
        f"PROPOSE ENTRE {_MIN_WIDGETS} ET {_MAX_WIDGETS} WIDGETS (idéalement 4-6 pour "
        "remplir un dashboard harmonieux). Pour chaque widget :\n"
        f"  - intent ∈ {sorted(_VALID_INTENTS)}\n"
        "     * headline_kpi    : nombre mis en avant (total, count…)\n"
        "     * comparison      : bar / pie 1 dimension\n"
        "     * comparison_2d   : grouped bar / stacked bar (2 dimensions)\n"
        "     * trend           : line / area 1 série\n"
        "     * trend_multi     : multi-line (évolution par série)\n"
        "     * distribution    : pie / donut\n"
        "     * top_ranking     : top N en barres\n"
        "     * detail_table    : tableau brut (complément seulement)\n"
        f"  - transformation.kind ∈ {sorted(VALID_TRANSFORM_KINDS)}\n"
        '     ex: {kind:"groupby_2d", params:{category_col,series_col,value_col,agg:sum,sort:desc,limit:20}}\n'
        "  - suggested_col_span ∈ [3,4,6,8,12]  — AGENCE EN GRILLE 12 COLONNES.\n"
        "     KPIs : 3 ou 4   ·   Chart secondaire : 4 ou 6   ·   Chart principal : 6 ou 8   ·   Tableau/full : 12\n"
        "  - role ∈ [headline_kpi, primary_chart, secondary_chart, detail]\n"
        "  - drill_column : null ou nom d'une colonne catégorielle pour filtrer\n"
        "  - hints : objet libre (chart_type suggéré, unit_column, x/y_label)\n"
        "  - reasoning : 1 phrase (elle n'est pas affichée à l'utilisateur)\n"
    )
    parts.append("")

    parts.append(
        "RÈGLES STRICTES :\n"
        "  - Toutes les colonnes citées DOIVENT figurer dans le profil.\n"
        "  - Les widgets doivent être COMPLÉMENTAIRES, pas redondants.\n"
        "  - Si la donnée a des ROLLUPS pré-calculés, au moins 2-3 KPIs "
        "extraits de ces colonnes via ``scalar_from_column``.\n"
        "  - Ordre des widgets = ordre d'affichage top→bottom, left→right.\n"
        "  - Les KPIs vont EN PREMIER (ligne 1), charts ENSUITE, table EN DERNIER.\n"
        "  - La SOMME des col_span doit former des lignes cohérentes de 12 "
        "(ex: [3,3,3,3]+[8,4]+[12] = 3 lignes propres).\n"
    )
    parts.append("")

    parts.append("Réponds STRICTEMENT avec ce JSON :")
    parts.append("""{
  "widgets": [
    {
      "intent": "headline_kpi|comparison|comparison_2d|trend|trend_multi|distribution|top_ranking|detail_table",
      "transformation": {
        "kind": "passthrough|scalar_aggregate|scalar_from_column|groupby|groupby_2d|time_series|time_series_multi|top_n_2d",
        "params": { ... }
      },
      "suggested_col_span": 3|4|6|8|12,
      "role": "headline_kpi|primary_chart|secondary_chart|detail",
      "drill_column": "nom_colonne" ou null,
      "hints": { "chart_type": "bar|line|pie|donut|area" ou null },
      "reasoning": "1 phrase"
    },
    ...
  ]
}""")
    return "\n".join(parts)


async def compose_widgets(
    obfuscated_profile: dict[str, Any],
    roles: dict[str, list[str]],
    user_hint: Optional[str] = None,
    *,
    user_id: Optional[int] = None,
) -> list[WidgetProposal]:
    """Call LLM "Composer" : décompose l'analyse en N widgets proposals.

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
            temperature=0.2,
            max_tokens=_COMPOSER_MAX_TOKENS,
        ),
        stage="Composer",
        provider_name=provider_name,
        user_id=user_id,
        context_kind="WIDGET_PLAN",
    )
    if not raw:
        raise LLMCallError("Réponse Composer vide")

    data = parse_json_response(raw, "Composer")
    proposals = _validate(data, obfuscated_profile)
    if not proposals:
        raise LLMCallError("Composer n'a proposé aucun widget valide")
    # Post-process en cascade — on ne fait plus confiance au LLM pour ces
    # invariants critiques, on les enforce en code :
    #   1. Empêche les agrégations sur colonnes ROLLUP (sinon double-comptage)
    #   2. Dégrade les 2D haute cardinalité (sinon légende illisible)
    #   3. Force un layout harmonieux en grille
    proposals = _enforce_rollup_safety(proposals, obfuscated_profile)
    proposals = _degrade_high_cardinality_series(proposals, obfuscated_profile)
    proposals = _harmonize_layout(proposals)
    return proposals


_VALID_ROLES = frozenset({"headline_kpi", "primary_chart", "secondary_chart", "detail"})
_VALID_COL_SPANS_INT = {3, 4, 6, 8, 12}


def _validate(data: dict[str, Any], profile: dict[str, Any]) -> list[WidgetProposal]:
    """Sanitize la liste. Droppe silencieusement les proposals invalides."""
    widgets_raw = data.get("widgets")
    if not isinstance(widgets_raw, list) or not widgets_raw:
        return []

    columns = [c.get("name") for c in (profile.get("columns") or []) if c.get("name")]
    out: list[WidgetProposal] = []

    for i, prop in enumerate(widgets_raw[:_MAX_WIDGETS]):
        if not isinstance(prop, dict):
            logger.info("Composer: widget[%d] ignoré (pas un dict)", i)
            continue

        intent = prop.get("intent")
        if intent not in _VALID_INTENTS:
            logger.info("Composer: widget[%d] intent invalide %r → skip", i, intent)
            continue

        recipe = validate_recipe(prop.get("transformation"), columns)
        if recipe is None:
            # Cas spécial : intent=detail_table sans transformation → passthrough
            if intent == "detail_table":
                recipe = {"kind": "passthrough", "params": {}}
            else:
                logger.info(
                    "Composer: widget[%d] transformation invalide → skip",
                    i,
                )
                continue

        try:
            cs = int(prop.get("suggested_col_span"))
        except (TypeError, ValueError):
            cs = None
        if cs not in _VALID_COL_SPANS_INT:
            cs = _default_col_span(intent)

        role = prop.get("role") if prop.get("role") in _VALID_ROLES else _default_role(intent)

        drill = prop.get("drill_column")
        if isinstance(drill, str):
            drill = drill.strip()
            if drill and drill not in columns:
                drill = None
        else:
            drill = None

        hints = prop.get("hints") if isinstance(prop.get("hints"), dict) else {}
        reasoning = prop.get("reasoning")
        if isinstance(reasoning, str):
            reasoning = reasoning.strip()[:300] or None
        else:
            reasoning = None

        out.append(
            WidgetProposal(
                intent=intent,
                transformation=recipe,
                suggested_col_span=cs,
                role=role,
                drill_column=drill,
                hints=hints or {},
                reasoning=reasoning,
            )
        )

    return out


def _default_col_span(intent: str) -> int:
    # Tailles par défaut pensées pour des GRILLES harmonieuses — pas de
    # piles verticales monotones de col_span=12. Si le LLM ne tranche pas
    # nous-mêmes on privilégie des paires (6+6) ou des ensembles (3+3+3+3).
    if intent == "headline_kpi":
        return 3
    if intent == "detail_table":
        return 12
    if intent == "distribution":
        return 4  # pie/donut → petit
    if intent in ("trend_multi",):
        return 8  # multi-line mérite la largeur mais laisse 4 pour un voisin
    if intent == "comparison_2d":
        return 8
    if intent == "top_ranking":
        return 6
    return 6  # comparison / trend 1 série → paire 6+6


def _default_role(intent: str) -> str:
    if intent == "headline_kpi":
        return "headline_kpi"
    if intent == "detail_table":
        return "detail"
    if intent in ("comparison_2d", "trend_multi", "top_ranking"):
        return "primary_chart"
    return "secondary_chart"


# ------------------------------------------------------------------
# Post-processors : corrigent les décisions LLM avant persistance.
# On fait ici ce que le LLM a du mal à faire de façon fiable : layout
# harmonieux (grille qui somme à 12/ligne) + filtres qualité (cardinalité).
# ------------------------------------------------------------------


def _cardinality_of(profile: dict[str, Any], column: str) -> int:
    """Lit la cardinalité d'une colonne depuis le profile (0 si absente)."""
    for c in profile.get("columns") or []:
        if c.get("name") == column:
            try:
                return int(c.get("cardinality", 0) or 0)
            except (TypeError, ValueError):
                return 0
    return 0


def _type_of(profile: dict[str, Any], column: str) -> str:
    """Lit le type d'une colonne depuis le profile ("text"/"numeric"/"date"/…)."""
    for c in profile.get("columns") or []:
        if c.get("name") == column:
            return c.get("type") or ""
    return ""


def _is_rollup(profile: dict[str, Any], column: str) -> bool:
    """Vrai si la colonne est marquée ``likely_rollup`` par le profiler."""
    if not column:
        return False
    for c in profile.get("columns") or []:
        if c.get("name") == column:
            return bool(c.get("likely_rollup"))
    return False


def _first_non_rollup_numeric(profile: dict[str, Any]) -> Optional[str]:
    """Cherche une colonne numérique RÉELLE (non rollup) — utile pour
    remplacer un value_col rollup dans une agrégation."""
    for c in profile.get("columns") or []:
        if c.get("type") == "numeric" and not c.get("likely_rollup"):
            return c.get("name")
    return None


def _enforce_rollup_safety(
    proposals: list[WidgetProposal], profile: dict[str, Any]
) -> list[WidgetProposal]:
    """Empêche les agrégations naïves sur colonnes rollup.

    Cas traités :
      A) ``scalar_aggregate`` (sum/avg/min/max) sur colonne rollup
         → downgrade en ``scalar_from_column`` (lit la valeur telle quelle).
      B) ``groupby`` / ``groupby_2d`` / ``top_n_2d`` avec ``value_col`` rollup
         → on remplace value_col par la 1re colonne numérique non-rollup
         disponible. Si aucune n'existe, on drop le widget (mieux que faux).
    """
    out: list[WidgetProposal] = []
    fallback_value = _first_non_rollup_numeric(profile)

    for p in proposals:
        recipe = p.transformation or {}
        kind = recipe.get("kind")
        params = recipe.get("params") or {}

        # Cas A : scalar_aggregate sur rollup → scalar_from_column
        if kind == "scalar_aggregate":
            col = params.get("column")
            if _is_rollup(profile, col) and col != "*":
                logger.info(
                    "Composer post: scalar_aggregate(%s, %s) sur ROLLUP "
                    "→ downgrade en scalar_from_column",
                    col,
                    params.get("agg"),
                )
                p.transformation = {
                    "kind": "scalar_from_column",
                    "params": {
                        "column": col,
                        "label": params.get("label") or col,
                    },
                }

        # Cas B : agrégations 1D/2D avec value_col rollup → swap ou drop
        elif kind in ("groupby", "groupby_2d", "top_n_2d", "time_series", "time_series_multi"):
            value_col = params.get("value_col")
            agg = (params.get("agg") or "sum").lower()
            # count(*) sans value_col est sûr
            if value_col and _is_rollup(profile, value_col) and agg != "count":
                if fallback_value:
                    logger.info(
                        "Composer post: %s avec value_col=%s ROLLUP → swap vers %s",
                        kind,
                        value_col,
                        fallback_value,
                    )
                    new_params = dict(params)
                    new_params["value_col"] = fallback_value
                    p.transformation = {"kind": kind, "params": new_params}
                else:
                    logger.info(
                        "Composer post: %s avec value_col=%s ROLLUP et "
                        "AUCUNE colonne numérique non-rollup disponible → DROP widget",
                        kind,
                        value_col,
                    )
                    continue  # drop ce widget

        out.append(p)
    return out


def _degrade_high_cardinality_series(
    proposals: list[WidgetProposal], profile: dict[str, Any]
) -> list[WidgetProposal]:
    """Empêche les 2D/multi-line inappropriés.

    Deux cas dégradés :
      1. series_col est une colonne DATE → un chart "par date" doit être un
         line chart temporel, pas un grouped bar avec N couleurs.
      2. series_col a une cardinalité > 6 → la légende explose, le chart devient
         illisible. On retombe en 1D propre.

    Cap 6 (pas 8) : au-delà de 6 séries la légende prend déjà 2 lignes OU
    pousse le plot à droite avec trop de marge.
    """
    SERIES_CARDINALITY_CAP = 6

    fixed: list[WidgetProposal] = []
    for p in proposals:
        recipe = p.transformation or {}
        kind = recipe.get("kind")
        params = recipe.get("params") or {}
        series_col = params.get("series_col")

        if kind in ("groupby_2d", "top_n_2d") and series_col:
            series_type = _type_of(profile, series_col)
            card = _cardinality_of(profile, series_col)
            # Cas 1 : series_col est une DATE → c'est sémantiquement un trend.
            #          On bascule en time_series (1D) avec la date comme axe X.
            if series_type == "date":
                logger.info(
                    "Composer post: %s avec series_col DATE → time_series (series_col=%r)",
                    kind,
                    series_col,
                )
                p.transformation = {
                    "kind": "time_series",
                    "params": {
                        "date_col": series_col,
                        "value_col": params.get("value_col"),
                        "agg": params.get("agg", "sum"),
                        "bucket": "month",
                    },
                }
                if p.intent == "comparison_2d":
                    p.intent = "trend"
                p.hints = dict(p.hints or {})
                p.hints["chart_type"] = "line"
            # Cas 2 : cardinalité trop haute → downgrade en groupby 1D.
            elif card > SERIES_CARDINALITY_CAP:
                logger.info(
                    "Composer post: %s dégradé en groupby (series_col=%r cardinality=%d > %d)",
                    kind,
                    series_col,
                    card,
                    SERIES_CARDINALITY_CAP,
                )
                new_params = {
                    "category_col": params.get("category_col"),
                    "value_col": params.get("value_col"),
                    "agg": params.get("agg", "sum"),
                    "sort": params.get("sort", "desc"),
                }
                if "limit" in params:
                    new_params["limit"] = params["limit"]
                p.transformation = {"kind": "groupby", "params": new_params}
                if p.intent == "comparison_2d":
                    p.intent = "comparison"
                p.hints = dict(p.hints or {})
                p.hints["chart_type"] = "bar"
        elif kind == "time_series_multi" and series_col:
            card = _cardinality_of(profile, series_col)
            if card > SERIES_CARDINALITY_CAP:
                logger.info(
                    "Composer post: time_series_multi dégradé en time_series "
                    "(series_col=%r cardinality=%d)",
                    series_col,
                    card,
                )
                new_params = {
                    "date_col": params.get("date_col"),
                    "value_col": params.get("value_col"),
                    "agg": params.get("agg", "sum"),
                    "bucket": params.get("bucket", "month"),
                }
                p.transformation = {"kind": "time_series", "params": new_params}
                if p.intent == "trend_multi":
                    p.intent = "trend"
                p.hints = dict(p.hints or {})
                p.hints["chart_type"] = "line"

        fixed.append(p)
    return fixed


def _harmonize_layout(
    proposals: list[WidgetProposal],
) -> list[WidgetProposal]:
    """Force des col_span qui produisent des lignes de grille cohérentes.

    Stratégie :
      1. Sépare les KPIs (en-tête) des non-KPIs, préserve l'ordre Composer.
      2. KPIs → col_span uniforme qui remplit une ligne :
           1 KPI  → 12 (ou plutôt laisse passer — exception)
           2 KPIs → 6+6
           3 KPIs → 4+4+4
           4 KPIs → 3+3+3+3
           5+ KPIs → 3 chacun (déborde sur 2 lignes)
      3. Non-KPIs : on parcourt en paire
           - 1 widget seul → 12
           - 2 widgets → 6+6
           - 3+ widgets → primary (intent=comparison_2d/trend/top_ranking) = 8
             et le suivant (secondary) = 4, puis paire 6+6 ensuite
      4. Détail tableau toujours 12 (va à la fin).

    On NE change PAS l'ordre des proposals, juste les col_span.
    """
    if not proposals:
        return proposals

    kpis = [p for p in proposals if p.intent == "headline_kpi"]
    details = [p for p in proposals if p.intent == "detail_table"]
    mids = [p for p in proposals if p.intent not in ("headline_kpi", "detail_table")]

    # ── 1. KPIs : répartition uniforme par ligne ─────────────────────
    n_k = len(kpis)
    if n_k == 1:
        kpis[0].suggested_col_span = 4  # KPI solo → pas full-width (évite pile monotone)
    elif n_k == 2:
        for k in kpis:
            k.suggested_col_span = 6
    elif n_k == 3:
        for k in kpis:
            k.suggested_col_span = 4
    elif n_k >= 4:
        for k in kpis:
            k.suggested_col_span = 3

    # ── 2. Widgets du milieu : pairs 6+6 ou primary 8 + secondary 4 ──
    i = 0
    while i < len(mids):
        this = mids[i]
        nxt = mids[i + 1] if i + 1 < len(mids) else None
        is_primary = this.intent in ("comparison_2d", "trend_multi", "top_ranking")
        if nxt is None:
            # Un seul → full width
            this.suggested_col_span = 12
            i += 1
        elif is_primary:
            # primary 8 + secondary 4
            this.suggested_col_span = 8
            nxt.suggested_col_span = 4
            i += 2
        else:
            # Paire 6+6
            this.suggested_col_span = 6
            nxt.suggested_col_span = 6
            i += 2

    # ── 3. Détail : full width ───────────────────────────────────────
    for d in details:
        d.suggested_col_span = 12

    # Préserve l'ORDRE initial pour pas ré-organiser le dashboard
    # (sauf tri implicite : KPIs en haut, détails en bas — ce que le LLM
    # produit déjà dans 99% des cas). On garde proposals tel quel.
    return proposals
