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


# ── Limite bcrypt sur la longueur des mots de passe — SINGLE SOURCE OF TRUTH ──
#
# bcrypt ne prend en compte que les **72 premiers octets UTF-8** d'un mot de
# passe ; les octets au-delà sont ignorés. Ce comportement diffère selon la
# version de la lib ``bcrypt`` :
#   * 4.x  → tronque **silencieusement** à 72 octets (set ET verify). Un mot de
#            passe de 80 octets « marche » au login, mais avec l'entropie d'un
#            mot de passe de 72 octets — l'utilisateur croit avoir un secret
#            plus fort qu'il ne l'est.
#   * 5.x  → ``hashpw``/``checkpw`` **lèvent ``ValueError``** au-delà de 72 o
#            (vérifié empiriquement sur bcrypt 5.0.0).
#
# Doctrine Komptia (unique pour TOUS les chemins) :
#   * chemin « set » (créer/changer un mot de passe) → **rejeter** au-delà de la
#     limite, avec un message actionnable, AVANT le hachage. L'utilisateur sait
#     ainsi que ses octets 73+ ne compteraient pas (pas de fausse sécurité).
#   * chemin « verify » (login, ré-auth) → **tronquer** à 72 octets avant
#     ``checkpw`` : compat avec les hashes legacy créés sous 4.x (qui tronquait)
#     ET robustesse cross-version (pas de ``ValueError`` sous 5.x).
#
# C'est cette dualité reject-au-set / truncate-au-verify qui rend le code
# *indépendant de la version de bcrypt* et permet de lever le cap ``bcrypt<5``.
PASSWORD_MAX_BYTES: Final[int] = 72


def password_byte_length(password: Optional[str]) -> int:
    """Longueur du mot de passe en octets UTF-8 (``None`` → 0).

    C'est la métrique qui compte pour bcrypt — PAS ``len(str)`` : un emoji
    occupe 1 caractère mais 4 octets, donc 18 emojis (18 chars) = 72 octets.
    """
    return len((password or "").encode("utf-8"))


def password_exceeds_bcrypt_limit(password: Optional[str]) -> bool:
    """``True`` si le mot de passe dépasse :data:`PASSWORD_MAX_BYTES` octets.

    À appeler par tout chemin « set » avant :meth:`PasswordHasher.hash_password`
    pour renvoyer une 400 propre plutôt que de laisser le hasher lever
    :class:`~app.core.exceptions.PasswordTooLongError` (garde-fou de dernier
    recours).
    """
    return password_byte_length(password) > PASSWORD_MAX_BYTES


def encode_password_for_bcrypt(password: Optional[str]) -> bytes:
    """Encode + tronque à :data:`PASSWORD_MAX_BYTES` octets pour bcrypt.

    La troncature est faite **au niveau octet** (``[:72]``), pas au niveau
    caractère — c'est exactement ce que bcrypt 4.x faisait en interne, donc
    c'est ce qui reproduit ses hashes legacy. Couper un caractère multi-octets
    en deux est sans conséquence : bcrypt opère sur des octets bruts, jamais sur
    de l'Unicode décodé. ``None`` → ``b""`` (préserve la doctrine timing-attack :
    un mot de passe vide paie quand même le coût ``checkpw``).
    """
    return (password or "").encode("utf-8")[:PASSWORD_MAX_BYTES]


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
