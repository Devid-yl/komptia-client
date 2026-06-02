"""Helpers de sanitisation partagés entre agent + handlers + memory.

**Single source of truth** pour les patterns de strip control chars
(anti prompt-injection) qui étaient dupliqués 5× dans le package
avant la review globale 2026-05-18 (fix CC1).

Sites précédemment dupliqués :
- ``memory.py`` (`_CONTROL_CHARS_RE`)
- ``tools.py`` (`_sanitize_render_spec` + `_handle_propose_widget`)
- ``agent.py`` (sanitize ``user_hint``)

Tous importent désormais ``CONTROL_CHARS_RE`` et ``strip_control()`` d'ici.
"""

from __future__ import annotations

import re

#: Anti prompt-injection : capture les caractères de contrôle 0x00-0x1F
#: (SAUF ``\n`` et ``\t`` qui sont des chars de mise en forme légitimes
#: dans les contenus texte) + ``\x7f`` (DEL). Remplacés par espace pour
#: neutraliser les tentatives d'injection ``\n\n[SYSTEM] ...`` qui
#: leverageraient une string user-contrôlée injectée brut dans un
#: prompt LLM ou un attribut HTML.
#:
#: Pattern partagé entre :
#: - widget_planner_agent.agent (sanitize ``user_hint``)
#: - widget_planner_agent.tools (``_sanitize_render_spec`` + ``_handle_propose_widget`` title)
#: - widget_planner_agent.memory (titres widgets existants pré-prompt)
CONTROL_CHARS_RE: re.Pattern[str] = re.compile(r"[\x00-\x1f\x7f]")


def strip_control(value: object, cap: int | None = None) -> str:
    """Remplace les chars de contrôle par espaces + cap optionnel.

    Args:
        value: input arbitraire. Si pas un ``str``, retourne ``""``
            (defense-in-depth — ne crash pas si appelé sur dict/int).
        cap: longueur max après sanitisation. ``None`` = pas de cap.

    Returns:
        String nettoyée, optionnellement tronquée. Les chars ``\\n`` et
        ``\\t`` sont préservés (formatage texte légitime).
    """
    if not isinstance(value, str):
        return ""
    out = CONTROL_CHARS_RE.sub(" ", value)
    if cap is not None and cap > 0:
        out = out[:cap]
    return out
