"""Helper interne — validation stricte de ``user_id`` (task #38).

Pattern factorisé après le finding #1 review task #35 : ``isinstance(True, int)``
retourne ``True`` en Python (bool ⊂ int), ce qui permettait à un caller
qui passerait par erreur ``current_user.is_active`` (bool) au lieu de
``.id`` d'écrire dans ``anonymization_terms`` sous ``user_id=1``
(cross-user write silencieux).

**Avant** (10+ call-sites dans ``api_service.py``, ``audit.py``) :

.. code-block:: python

    if not isinstance(user_id, int) or user_id <= 0:
        return None  # fail-OPEN sur user_id=True (bool)

**Après** (tous les call-sites passent par ce helper) :

.. code-block:: python

    if not is_valid_user_id(user_id):
        return None  # fail-CLOSED sur bool, str, None, 0, négatif

Defense-in-depth uniforme — un futur sous-module qui valide
``user_id`` doit utiliser ce helper, pas dupliquer la logique.
"""

from __future__ import annotations

from typing import Any


def is_valid_user_id(user_id: Any) -> bool:
    """Retourne ``True`` ssi ``user_id`` est un identifiant utilisateur
    légitime : ``int`` strict positif, **ni** ``None``, **ni** ``bool``,
    **ni** un autre type (``str``, ``float``, etc.).

    Pourquoi exclure ``bool`` explicitement : Python définit ``bool`` comme
    sous-type de ``int``, donc ``isinstance(True, int)`` retourne ``True``
    et ``True > 0`` est ``True``. Sans l'exclusion explicite, un caller
    négligent qui ferait ``upsert_terms(user_id=current_user.is_active, ...)``
    écrirait sous ``user_id=1`` silencieusement (cross-user write).

    Args:
        user_id: Valeur à valider. Peut être de n'importe quel type.

    Returns:
        ``True`` si valide, ``False`` sinon. Jamais ne lève — caller
        décide quoi faire en cas de ``False`` (return None, raise 4xx,
        log warning, etc.).

    Examples:
        >>> is_valid_user_id(1)
        True
        >>> is_valid_user_id(42)
        True
        >>> is_valid_user_id(0)
        False
        >>> is_valid_user_id(-1)
        False
        >>> is_valid_user_id(None)
        False
        >>> is_valid_user_id(True)
        False
        >>> is_valid_user_id(False)
        False
        >>> is_valid_user_id("1")
        False
        >>> is_valid_user_id(1.0)
        False
    """
    if user_id is None:
        return False
    if isinstance(user_id, bool):
        return False
    if not isinstance(user_id, int):
        return False
    if user_id <= 0:
        return False
    return True
