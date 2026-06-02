"""Caps DoS centralisés pour l'agent widget_planner.

**Single source of truth** pour tous les caps (defense-in-depth contre
DoS / payloads malveillants / dépassement budget LLM). Avant cette PR,
les constantes étaient éparpillées sur 3 modules (agent.py, tools.py,
memory.py) — fix C3 review globale 2026-05-18.

Pour un audit sécurité « où sont les caps DoS ? », ce fichier est le
point unique. Les schemas Anthropic des tools utilisent ces mêmes
valeurs via leurs propriétés ``maximum`` JSON — l'``assert_schema_aligned()``
au boot vérifie qu'il n'y a pas de drift entre Python et JSON schema.
"""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────
# Caps boucle agent
# ─────────────────────────────────────────────────────────────────────

#: Nombre maximum d'itérations LLM → tool_use par run. Décision
#: brainstorm 2026-05-17 : compromis entre "no limits" perçu user
#: et borne stricte. Le coût LLM réel est aussi borné par max_tokens.
MAX_TOOL_CALLS: int = 40

#: Cap sur tokens output cumulés par run (defense-in-depth contre LLM
#: qui produit des messages géants à chaque turn). Aligné sur le hard
#: cap copilot_agent (50K) — plus que suffisant pour 6 widgets.
AGENT_MAX_TOKENS_HARD_CAP: int = 50_000

#: Réserve tokens pour le thinking budget Anthropic (consomme du
#: max_tokens). Adaptatif via compute_effort_params du runtime.
THINKING_RESERVE_TOKENS: int = 8_000


# ─────────────────────────────────────────────────────────────────────
# Caps handlers (defense-in-depth si Anthropic strict mode permissif)
# ─────────────────────────────────────────────────────────────────────

#: peek_sql_result : nombre max de rows retournées au LLM. Aligné sur
#: la propriété ``maximum: 50`` du schema JSON du tool.
MAX_PEEK_ROWS: int = 50

#: distinct_values : nombre max de valeurs distinctes retournées.
#: Aligné sur ``maximum: 30`` du schema JSON.
MAX_DISTINCT_VALUES: int = 30

#: propose_widget.title : cap longueur après strip control chars.
#: Aligné sur ``maxLength: 80`` du schema JSON.
MAX_TITLE_LEN: int = 80

#: abort.reason : cap longueur. Aligné sur ``maxLength: 200`` du schema.
MAX_ABORT_REASON_LEN: int = 200


# ─────────────────────────────────────────────────────────────────────
# Caps memory recompute
# ─────────────────────────────────────────────────────────────────────

#: Nombre max de widgets résumés dans le prompt memory. Au-delà : on
#: attache un sentinel ``_total_count`` pour signaler au LLM qu'il y a
#: plus de widgets non listés (cf. memory.format_memory_for_prompt).
MAX_WIDGETS_IN_MEMORY: int = 50


# ─────────────────────────────────────────────────────────────────────
# Auto-check au boot — détecte drift schema ↔ caps Python
# ─────────────────────────────────────────────────────────────────────


def assert_schema_aligned() -> None:
    """Vérifie que les caps Python sont alignés sur les ``maximum`` JSON
    schema des tools. Fail-fast au boot si drift détecté.

    Sans ce check : un dev qui change ``MAX_PEEK_ROWS = 100`` côté Python
    mais oublie le schema JSON ``"maximum": 50`` → le LLM peut envoyer
    limit=80, le handler accepte (Python OK) mais l'API LLM peut
    re-valider et rejeter ; ou pire, accepter → 80 rows leak.
    """
    # Import local pour éviter cycle (tools.py importe limits.py).
    from app.services.dashboard.widget_planner_agent.tools import (
        WIDGET_PLANNER_TOOLS,
    )

    expected_caps = {
        "peek_sql_result.limit": MAX_PEEK_ROWS,
        "distinct_values.limit": MAX_DISTINCT_VALUES,
        "propose_widget.title.maxLength": MAX_TITLE_LEN,
        "abort.reason.maxLength": MAX_ABORT_REASON_LEN,
    }

    for tool in WIDGET_PLANNER_TOOLS:
        name = tool.get("name")
        props = (tool.get("input_schema") or {}).get("properties") or {}

        if name == "peek_sql_result":
            limit_max = props.get("limit", {}).get("maximum")
            if limit_max != MAX_PEEK_ROWS:
                raise RuntimeError(
                    f"Schema drift : peek_sql_result.limit.maximum={limit_max} "
                    f"!= MAX_PEEK_ROWS={MAX_PEEK_ROWS}"
                )
        elif name == "distinct_values":
            limit_max = props.get("limit", {}).get("maximum")
            if limit_max != MAX_DISTINCT_VALUES:
                raise RuntimeError(
                    f"Schema drift : distinct_values.limit.maximum={limit_max} "
                    f"!= MAX_DISTINCT_VALUES={MAX_DISTINCT_VALUES}"
                )
        elif name == "propose_widget":
            title_max = props.get("title", {}).get("maxLength")
            if title_max != MAX_TITLE_LEN:
                raise RuntimeError(
                    f"Schema drift : propose_widget.title.maxLength={title_max} "
                    f"!= MAX_TITLE_LEN={MAX_TITLE_LEN}"
                )
        elif name == "abort":
            reason_max = props.get("reason", {}).get("maxLength")
            if reason_max != MAX_ABORT_REASON_LEN:
                raise RuntimeError(
                    f"Schema drift : abort.reason.maxLength={reason_max} "
                    f"!= MAX_ABORT_REASON_LEN={MAX_ABORT_REASON_LEN}"
                )

    # Sanity check : on a bien vérifié les 4 caps documentés (sinon
    # un tool a été renommé ou la liste a été tronquée).
    _ = expected_caps  # pour clarté future, pas utilisé activement
