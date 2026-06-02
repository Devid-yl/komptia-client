"""Constantes et helpers d'auth/identité — single source of truth.

Évite la dérive entre ``app/handlers/auth.py``, ``app/services/auth/*``,
``scripts/seed_admin.py``, ``app/models/user.py`` (String(EMAIL_MAX_LENGTH))
et les templates HTML (``maxlength=EMAIL_MAX_LENGTH``).

Toute normalisation d'email pour login/rate-limit/lookup doit transiter
par :func:`casefold_email` ci-dessous. ``str.casefold()`` est l'opérateur
Unicode correct (pas ``str.lower()``) : il gère eszett (``ß`` → ``ss``),
sigma médian grec, capitalisation turque (``İ`` → ``i̇``), etc. ``lower()``
seul ne folde QUE l'ASCII et laisse passer des doublons logiques.

⚠️ SQLite ``LOWER()`` SQL et ``COLLATE NOCASE`` sont aussi ASCII-only.
Toute opération d'unicité case-insensitive en BDD doit donc être faite
côté Python — c'est ce que fait la migration ``lowercase_email`` (cf.
``app/core/database.py``), qui lit les rows en Python, applique
``casefold_email`` et UPDATE par id.
"""

from __future__ import annotations

from typing import Final, Optional

# RFC 5321 §4.5.3.1.3 — longueur max d'un Path (forward-path) : 256 octets
# inclus les chevrons ``<>``, donc 254 caractères max pour l'email lui-même.
# La colonne ``users.email`` est ``String(EMAIL_MAX_LENGTH)`` et le helper
# ``casefold_email`` refuse au-delà — pas de truncate silencieux possible.
EMAIL_MAX_LENGTH: Final[int] = 254


def casefold_email(raw: Optional[str]) -> str:
    """Normalise un email pour login/rate-limit/lookup.

    Pipeline :
        1. ``None`` ou non-``str`` → ``""``
        2. ``strip()`` whitespace périphérique
        3. ``casefold()`` Unicode-aware (≠ ``lower()`` pour ß, İ, etc.)
        4. Refuse (retourne ``""``) si > :data:`EMAIL_MAX_LENGTH` chars

    Le refus volontaire à la longueur (au lieu d'un truncate) ferme le
    canal d'énumération par "email trop long → truncate → match partiel
    accidentel". Un email > 254 chars ne peut pas exister en BDD, donc
    on retombe sur "no match" déterministe.

    L'absence de validation RFC ici (présence de ``@``, TLD, etc.) est
    aussi volontaire : valider donnerait un signal différencié
    "mal formé" vs "inconnu" exploitable pour l'énumération de comptes.
    Le timing constant (bcrypt dummy) côté handler reste la défense.
    """
    if not isinstance(raw, str) or not raw:
        return ""
    normalized = raw.strip().casefold()
    if len(normalized) > EMAIL_MAX_LENGTH:
        return ""
    return normalized
