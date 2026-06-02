"""Agent tool-loop pour la planification de widgets dashboard.

Alternative au pipeline linéaire ``widget_planner`` (Analyst → Composer →
Designer). Garantit l'absence de limites sur les SQL complexes (drill-down
à la demande via tools au lieu de gros payload up-front).

Pattern calqué sur :mod:`app.services.ai.copilot_agent` : boucle
LLM → tool_use → tool_result → LLM jusqu'à ``commit_widgets`` ou ``abort``.

Sources de vérité réutilisées (PAS de duplication) :
- Config LLM : :func:`app.services.ai.llm_providers.get_llm_manager`
  (admin /admin/ai-config)
- Anonymisation : :mod:`app.services.anonymization` (admin /data/privacy)
- Progress store : :mod:`app.services.ai.copilot_progress_store`
- Runtime tool-use : :func:`app.services.ai.llm_runtime.call_llm_with_tools`

Status : SCAFFOLDING (PR 2.1) — boucle réelle en PR 2.4.
"""

from __future__ import annotations

from app.services.dashboard.widget_planner_agent.agent import (
    WidgetPlannerAgentError,
    run_widget_planner_agent,
)
from app.services.dashboard.widget_planner_agent.anonymization import (
    AnonymizationContext,
    AnonymizationLookupError,
    prepare_anonymization,
)
from app.services.dashboard.widget_planner_agent.memory import (
    format_memory_for_prompt,
    read_existing_widgets_summary,
)

__all__ = [
    "AnonymizationContext",
    "AnonymizationLookupError",
    "WidgetPlannerAgentError",
    "format_memory_for_prompt",
    "prepare_anonymization",
    "read_existing_widgets_summary",
    "run_widget_planner_agent",
]

# Auto-check fail-fast au boot (fix C3 review globale 2026-05-18) :
# détecte tout drift entre les caps Python (limits.py) et les maximums
# JSON schema des tools (WIDGET_PLANNER_TOOLS). Sans ça, un dev qui
# change un cap Python sans mettre à jour le schema (ou inversement)
# crée une vulnerability silencieuse.
from app.services.dashboard.widget_planner_agent.limits import assert_schema_aligned

assert_schema_aligned()
