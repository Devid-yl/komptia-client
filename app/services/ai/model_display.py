"""Conversion d'un ID de modèle LLM en libellé UI lisible.

Module-level helper neutre — utilisable depuis n'importe quelle couche
(handler, service, worker, CLI). Évite la dépendance ascendante d'un
service vers un handler. Single source of truth pour le mapping
``model_id`` → ``"Claude Sonnet"`` etc.
"""

from __future__ import annotations

import re
from typing import Final

#: Marqueurs de familles de modèles → libellé UI. L'ordre compte pour les
#: collisions théoriques (modèle contenant "haiku" et "sonnet" → haiku gagne).
_MODEL_FAMILY_DISPLAY: Final[tuple[tuple[str, str], ...]] = (
    ("haiku", "Claude Haiku"),
    ("sonnet", "Claude Sonnet"),
    ("opus", "Claude Opus"),
)

#: Suffixe date (8+ chiffres) — on l'efface sur les modèles génériques.
_MODEL_DATE_SUFFIX: Final[re.Pattern[str]] = re.compile(r"-\d{8,}$")

#: Borne haute pour le libellé exposé en attribut ``title=`` côté UI. Le
#: registre BDD est admin-éditable ; sans cap, un id géant remplirait le DOM
#: avec un attribut multi-MB qui ralentirait les redessins (defense-en-profondeur).
_MODEL_DISPLAY_MAX_LEN: Final[int] = 80


def model_display_name(model_id: str) -> str:
    """Convertit un ID de modèle en nom lisible pour l'UI.

    Exemples :
        ``"claude-sonnet-4-20250514"`` → ``"Claude Sonnet"``
        ``"claude-haiku-4-5-20251001"`` → ``"Claude Haiku"``
        ``"gpt-4o"`` → ``"GPT-4O"``
        ``"mistral-large-2"`` → ``"Mistral Large 2"``

    Cap à :data:`_MODEL_DISPLAY_MAX_LEN` pour ne jamais propager un libellé
    artificiellement long depuis le registre admin.
    """
    if not model_id:
        return ""
    mid = model_id.lower()
    for marker, display in _MODEL_FAMILY_DISPLAY:
        if marker in mid:
            return display[:_MODEL_DISPLAY_MAX_LEN]
    if "gpt" in mid:
        return model_id.upper().replace("-", " ")[:_MODEL_DISPLAY_MAX_LEN]
    return _MODEL_DATE_SUFFIX.sub("", model_id).replace("-", " ").title()[:_MODEL_DISPLAY_MAX_LEN]
