"""Telemetry PASSIVE sur les violations OUTPUT_STYLE_RULES.

Helper central — observer seul, jamais filtrer / rejeter / modifier la
sortie LLM. Permet d'apprendre en agrégat si un provider/modèle
re-produit du box-drawing après un fix prompt-side (régression
silencieuse après provider switch, nouvelle version, etc.).

Doctrine :
- **Non-blocking** : ne lève JAMAIS d'exception, ne modifie JAMAIS le
  texte LLM. Si le module échoue (regex pourrie, logger down), la
  réponse user passe quand même.
- **Pas un guard** : respecte la règle ``feedback_no_downstream_guard_fix_upstream.md``
  — la solution reste l'injection prompt-side ``OUTPUT_STYLE_RULES``.
  Cette telemetry observe en arrière-plan pour détecter une régression.
- **Centralisé** : un seul site qui définit ce qu'est une « violation »
  → un seul site à mettre à jour si on étend le périmètre (nouveau
  caractère, nouveau pattern).
"""

from __future__ import annotations

import re
from typing import Any, Final

from app.utils.logger import get_logger

logger = get_logger(__name__)

# Pattern : 3+ caractères box-drawing consécutifs (≠ usage anecdotique
# du tiret cadratin ou de la flèche inline qui restent légitimes).
# Couvre :
#   ┌ ┐ └ ┘ │ ─ ├ ┤ ┬ ┴ ┼  (Unicode légers)
#   ╔ ╗ ╚ ╝ ║ ═ ╠ ╣ ╦ ╩ ╬  (Unicode doubles)
#   ╭ ╮ ╯ ╰                 (Unicode arrondis)
#   + - | =                  (ASCII art — seulement si grappés 3+)
_BOX_DRAWING_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[─-╿]{3,}"  # box-drawing Unicode
)

# ASCII art : suite de ``+----+`` ou ``|   |`` — détectée séparément
# pour éviter de matcher du markdown table légitime (``|---|---|``
# acceptable car contenu dans une vraie table, mais 3+ lignes
# consécutives de ``|   |`` = dessin).
_ASCII_BOX_PATTERN: Final[re.Pattern[str]] = re.compile(
    # 2+ lignes ``+----+`` ou ``+====+`` dans une fenêtre courte (peut
    # contenir des lignes intermédiaires ``|  txt  |``). Détection souple
    # pour matcher ASCII art typique sans flagger un séparateur isolé.
    r"^[ \t]*\+[\-=+]{3,}\+?[ \t]*$"
    r"(?:.*\n){0,6}?"
    r"^[ \t]*\+[\-=+]{3,}\+?[ \t]*$",
    re.MULTILINE,
)


def detect_output_style_violation(text: str) -> str | None:
    """Détecte si ``text`` contient une violation OUTPUT_STYLE.

    Retourne :
        - ``None`` si pas de violation (cas normal majoritaire) ;
        - ``"box_drawing_unicode"`` si caractères Unicode encadrants ;
        - ``"ascii_art_box"`` si ASCII art ``+----+``/``====``.

    Ne lève JAMAIS. Si ``text`` n'est pas un str, retourne None.
    """
    if not isinstance(text, str) or not text:
        return None
    try:
        if _BOX_DRAWING_PATTERN.search(text):
            return "box_drawing_unicode"
        if _ASCII_BOX_PATTERN.search(text):
            return "ascii_art_box"
    except Exception:  # pragma: no cover — fallback paranoïaque
        return None
    return None


def emit_passive_telemetry(
    text: str,
    *,
    role: Any = None,
    model: Any = None,
    module: str = "unknown",
    user_id: Any = None,
    conversation_id: Any = None,
) -> str | None:
    """Émet un ``logger.warning`` PASSIF si violation détectée.

    Args:
        text: Sortie LLM finale (post-thinking strip, post-suggestions
            parse — celle qu'on yield au front).
        role: AgentRole ou str (libre).
        model: nom du modèle (``manager.default_model_name`` ou similaire).
        module: nom court du caller (``agent_service``,
            ``copilot_agent``, ``result_assistant``, etc.) — facilite le
            grep des logs.
        user_id / conversation_id: contexte pour cross-réf si besoin.

    Returns:
        Le type de violation détecté (str) ou None. Le caller PEUT
        l'utiliser pour incrémenter une métrique custom — il NE DOIT
        PAS filtrer la réponse sur cette base.
    """
    kind = detect_output_style_violation(text)
    if not kind:
        return None
    try:
        logger.warning(
            "output_style_violation kind=%s module=%s role=%s model=%s "
            "user_id=%s conversation_id=%s text_len=%d",
            kind,
            module,
            role,
            model,
            user_id,
            conversation_id,
            len(text),
        )
    except Exception:  # pragma: no cover — never break on telemetry
        pass
    return kind


__all__ = [
    "detect_output_style_violation",
    "emit_passive_telemetry",
]
