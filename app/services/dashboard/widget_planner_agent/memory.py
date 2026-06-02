"""Memory recompute pour l'agent widget_planner.

Au lieu de persister un résumé en BDD (colonne ``ai_memory``) qui
risquerait de mentir après suppression manuelle de widgets, on
recompute le résumé à chaque run depuis la liste réelle des widgets
du dashboard. Avantages :

- 0 migration BDD
- 0 risque de mensonge si l'utilisateur supprime un widget hors agent
- Cohérence garantie (même si plusieurs onglets éditent le même
  dashboard simultanément)

Le résumé est ensuite injecté dans le system prompt de l'agent en
PR 2.4 sous forme ``Widgets déjà présents : [titre (intent), ...]``,
permettant au LLM d'éviter de proposer un widget qui existe déjà sous
une autre forme.

Decision brainstorm 2026-05-17 #2.
"""

from __future__ import annotations

from typing import Any, Optional

from app.utils.logger import get_logger

logger = get_logger(__name__)


# Cap centralisé dans limits.py (fix C3 review globale 2026-05-18).
from app.services.dashboard.widget_planner_agent.limits import (
    MAX_WIDGETS_IN_MEMORY as _MAX_WIDGETS_IN_MEMORY,
)

# Anti prompt-injection : import depuis le module sanitize partagé
# (fix CC1 review globale 2026-05-18 — single source of truth).
from app.services.dashboard.widget_planner_agent._sanitize import (
    CONTROL_CHARS_RE as _CONTROL_CHARS_RE,
)


async def read_existing_widgets_summary(
    dashboard_id: Optional[int],
    user_id: Optional[int],
) -> list[dict[str, Any]]:
    """Lit la liste des widgets actuellement persistés dans le dashboard.

    Réutilise :class:`DashboardBuilderService` (vérification ownership
    via ``Dashboard.user_id == user_id`` — fail-closed si non-owner).

    Args:
        dashboard_id: identifiant cible. ``None`` = tests / scripts sans
            contexte dashboard → liste vide retournée sans erreur.
        user_id: identifiant utilisateur. ``None`` ou propriétaire-mismatch
            → liste vide retournée (fail-closed silencieux pour ne pas
            leaker l'existence du dashboard).

    Returns:
        Liste de dicts ``{title, widget_type, intent, col_span}`` cappée
        à :data:`_MAX_WIDGETS_IN_MEMORY`. L'``intent`` est dérivé du
        ``chart_type`` ou du ``widget_type`` (heuristique légère, sans
        appel LLM).
    """
    if dashboard_id is None or user_id is None:
        # Log debug pour traçabilité (review adversariale 2026-05-17 LOW #6) :
        # si un caller runtime oublie de threader dashboard_id, la memory
        # devient vide silencieusement → LLM duplique. Le debug rend ce
        # bug visible sans gêner les tests.
        logger.debug(
            "widget_planner_agent.memory: dashboard_id=%s user_id=%s → "
            "memory vide (mode test/script attendu).",
            dashboard_id,
            user_id,
        )
        return []

    try:
        from app.core.database import get_session_factory
        from app.services.dashboard.dashboard_builder_service import (
            DashboardBuilderService,
        )

        # On instancie directement plutôt que de coupler à
        # ``app.handlers.dashboard_builder.get_dashboard_builder_service``
        # (couplage handler→service inverse à éviter). Le service est
        # stateless (pas de cache hot path à perdre).
        service = DashboardBuilderService()
        session_factory = get_session_factory()
        async with session_factory() as session:
            dashboard = await service.get_dashboard(session, dashboard_id, user_id)
    except Exception as exc:
        # Non-fatal : on retourne liste vide, le LLM continuera sans
        # contexte mémoire (équivalent dashboard neuf). Log pour debug
        # sans exposer le contenu des widgets.
        logger.warning(
            "widget_planner_agent.memory: lecture widgets dashboard=%s " "user=%s échouée: %s",
            dashboard_id,
            user_id,
            exc,
        )
        return []

    if not dashboard:
        return []

    widgets = dashboard.get("widgets") or []
    summary: list[dict[str, Any]] = []
    for w in widgets[:_MAX_WIDGETS_IN_MEMORY]:
        # Neutralise les chars de contrôle dans le title avant insertion
        # prompt (anti prompt-injection — review adversariale 2026-05-17
        # MEDIUM #3). Le slice [:80] cap aussi l'amplitude.
        raw_title = w.get("title") or ""
        safe_title = _CONTROL_CHARS_RE.sub(" ", raw_title)[:80]
        summary.append(
            {
                "title": safe_title,
                "widget_type": w.get("widget_type") or "unknown",
                "intent": _infer_intent(w),
                "col_span": w.get("col_span"),
            }
        )
    # Si on a tronqué, on signale au LLM dans le format prompt (cf.
    # format_memory_for_prompt). Le total reste dispo via le sentinel
    # ``_total_count`` attaché au premier dict (pattern simple sans
    # refacto de la signature).
    total_count = len(widgets)
    if total_count > _MAX_WIDGETS_IN_MEMORY and summary:
        summary[0]["_total_count"] = total_count
    return summary


def _infer_intent(widget: dict[str, Any]) -> str:
    """Heuristique zero-LLM pour deviner l'intent d'un widget existant.

    Sert UNIQUEMENT à l'affichage memory dans le prompt — pas pour le
    runtime. Les vraies intents sont stockées indirectement dans le
    ``data_source_config.render_spec`` ou peuvent manquer pour les
    widgets pré-pipeline-v2.
    """
    widget_type = widget.get("widget_type")
    chart_type = widget.get("chart_type")
    if widget_type == "kpi":
        return "headline_kpi"
    if widget_type == "table":
        return "detail_table"
    if widget_type == "text":
        return "static_text"
    if widget_type == "chart":
        if chart_type in ("line", "area"):
            return "trend"
        if chart_type in ("pie", "donut"):
            return "distribution"
        if chart_type == "scatter":
            return "comparison_2d"
        return "comparison"
    return "unknown"


def format_memory_for_prompt(widgets: list[dict[str, Any]]) -> str:
    """Convertit la liste de widgets en bloc texte injectable au prompt.

    Format compact : ``- titre [widget_type/intent, col=N]`` par widget.
    Quand la liste est vide, retourne un message explicite plutôt que
    rien (signale au LLM que c'est un dashboard neuf).
    """
    if not widgets:
        return "Dashboard neuf — aucun widget existant. Tu pars d'une page vide."
    lines = ["Widgets déjà présents dans ce dashboard :"]
    total_count: Optional[int] = None
    for w in widgets:
        title = w.get("title") or "(sans titre)"
        wtype = w.get("widget_type", "?")
        intent = w.get("intent", "?")
        colspan = w.get("col_span", "?")
        lines.append(f"- {title} [{wtype}/{intent}, col={colspan}/12]")
        # Sentinel posé par read_existing_widgets_summary quand on a cappé.
        if total_count is None and "_total_count" in w:
            total_count = int(w["_total_count"])
    if total_count is not None and total_count > len(widgets):
        lines.append(
            f"(+ {total_count - len(widgets)} widget(s) non listés — "
            f"dashboard dense, considère qu'il y a peut-être déjà un "
            f"widget couvrant ta proposition.)"
        )
    lines.append(
        "Évite de proposer un widget redondant avec ceux déjà présents. "
        "Si ta proposition couvre la même dimension métier qu'un widget "
        "existant, choisis une autre angle (granularité différente, "
        "comparaison vs absolu, etc.)."
    )
    return "\n".join(lines)
