"""Pipeline LLM-driven pour la planification de widgets de dashboard.

Architecture (inspirée du principe Gladys "système orchestre le LLM en micro-tâches") :

    SQL user
       ↓
    1. execute       (système) — si 0 ligne → erreur
    2. profile       (système) — types, cardinalité, ranges, top values
    3. obfuscate     (système) — Niveau 2 sur le profile envoyé au LLM Analyst
    4. Analyst LLM   — décide intent + recette de transformation (pas de SQL)
    5. transform     (système) — applique la recette en Python sur les data réelles
    6. Designer LLM  — décide titre, sous-titre, chart_type, format, insight
    7. restore       (système) — dé-anonymise les éventuels tokens ~xxx dans l'insight
    8. return        — WidgetPlanV2 prêt à persister

Au rafraîchissement d'un widget déjà créé : seules les étapes 1, 5, rendu sont
rejouées. Les décisions LLM (intent, spec) sont persistées à la création.
"""

from app.services.dashboard.widget_planner.pipeline import (
    WidgetPlanV2,
    WidgetPipelineError,
    plan_widget_v2,
    plan_widgets_batch,
)

__all__ = [
    "WidgetPlanV2",
    "WidgetPipelineError",
    "plan_widget_v2",
    "plan_widgets_batch",
]
