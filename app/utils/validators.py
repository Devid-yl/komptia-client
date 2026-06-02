"""Helpers de validation et d'assainissement d'entrées utilisateur.

Ce module centralise les primitives qu'une équipe sénior réutilise partout :

* Une seule regex pour valider les adresses email (``EMAIL_REGEX``). Sept
  fichiers de la codebase se trimballaient une variante locale — drift
  garanti si l'un des sites évoluait sans les autres (cf.
  ``GLOBAL_FINDINGS.md`` pattern ``[DUP] regex email fragmentée``).
* :func:`clean_input` pour les strings arrivant d'un navigateur : NBSP
  (``\\xa0`` — souvent collé par un correcteur orthographique) + trim, en
  tolérant les non-strings.
* :func:`strict_bool` : cast booléen **strict** qui refuse les chaînes
  `"false"` / `"0"` (qui `bool()` truande en ``True`` — piège classique sur
  un JSON body).
* :func:`assert_no_crlf` : **défense-in-depth** contre la CRLF header
  injection (CVE-2026-30227 MimeKit, CVE-2026-34975 Plunk, CVE-2026-32178
  .NET SmtpClient). On rejette les valeurs contenant ``\\r`` ou ``\\n``
  **avant** tout downstream (`SMTPClient._sanitize_header` est la dernière
  ligne, pas la seule).

Principes :

* Types stricts (``str`` ou ``bool``, jamais ``Any``) pour que mypy
  attrape les regressions.
* Aucun effet de bord, aucune I/O : helpers purs, testables en isolation.
* Messages d'erreur en français, orientés dev (pas user-facing).
"""

from __future__ import annotations

import re
from typing import Final

__all__ = [
    "EMAIL_REGEX",
    "MAX_EMAIL_LENGTH",
    "assert_no_crlf",
    "clean_input",
    "is_valid_email",
    "strict_bool",
]


# Regex délibérément lax (pas de tentative de couvrir RFC 5321 en entier) :
# - refuse espaces, ``@`` internes, ``\r``/``\n``.
# - exige un local-part, un ``@``, un domaine, un ``.`` et un TLD non vide.
# Pour un formulaire admin ou un contact, ça filtre 99 % des fautes de
# frappe. La vraie validation d'existence d'une boîte mail passe par
# l'envoi d'un email de confirmation — aucune regex ne remplace cela.
EMAIL_REGEX: Final[re.Pattern[str]] = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Borne pragmatique : la RFC 5321 section 4.5.3.1 plafonne à 254 octets
# (local-part 64 + ``@`` 1 + domaine 255, moins le wrapper SMTP). On
# coupe un cran plus bas pour laisser de la marge aux UI qui affichent
# l'adresse.
MAX_EMAIL_LENGTH: Final[int] = 254


def is_valid_email(value: object) -> bool:
    r"""Retourne ``True`` si ``value`` ressemble à une adresse email valide.

    Accepte n'importe quel type en entrée pour simplifier l'usage en
    validation de JSON body non-typé ; toute valeur non-string ou vide
    retourne ``False``.

    Defense anti-webhook-loop (cf. design_automations_dag.md §3.8) : on
    rejette toute valeur contenant ``://`` qui denote une URL — un email
    RFC 5322 ne peut jamais contenir ce trio (ni dans le local-part ni
    dans le domain-part). Sans ce check, un payload comme
    ``https://user:pass@example.com/webhook/abc`` matchait le regex
    permissif (``[^@\s]+@[^@\s]+\.[^@\s]+``) et le SMTP tentait
    l'envoi — vecteur de boucle infinie si l'URL declenche un autre
    workflow.
    """
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if not candidate or len(candidate) > MAX_EMAIL_LENGTH:
        return False
    if "://" in candidate:
        return False
    return EMAIL_REGEX.match(candidate) is not None


def clean_input(value: object) -> object:
    """Nettoie une valeur string (NBSP → espace + trim). Passthrough sinon.

    Le NBSP (``\\xa0``) est la cochonnerie typique d'un correcteur
    orthographique : invisible à l'œil, mais `smtp.gmail.com` devient
    `smtp.gmail.com\\xa0`, et `smtplib` refuse la connexion avec une
    erreur DNS cryptique. On le remplace partout, pas seulement en bord.
    """
    if isinstance(value, str):
        return value.replace("\xa0", " ").strip()
    return value


def strict_bool(value: object, field: str = "valeur") -> bool:
    """Cast booléen strict. Refuse les strings et autres types piégeux.

    ``bool("false") is True`` (parce que la string est non-vide) — c'est
    LE piège classique d'un JSON body qui arrive depuis un navigateur.
    On veut une erreur explicite plutôt qu'un silent fail.
    """
    if isinstance(value, bool):
        return value
    raise ValueError(
        f"Le champ ``{field}`` doit être un booléen JSON (``true``/``false``), pas "
        f"{type(value).__name__}"
    )


def assert_no_crlf(value: str, field: str = "valeur") -> str:
    """Lève ``ValueError`` si ``value`` contient ``\\r`` ou ``\\n``.

    Défense-in-depth contre l'injection CRLF dans les en-têtes email,
    les logs structurés (log forging) et les réponses HTTP. Toute
    valeur propagée à un composant réseau doit passer ici AVANT d'être
    concaténée dans une trame protocolaire.

    Retourne ``value`` inchangée pour permettre le chaînage : ``header =
    assert_no_crlf(from_name, "from_name")``.
    """
    if not isinstance(value, str):
        raise TypeError(f"Le champ ``{field}`` doit être une string, pas {type(value).__name__}")
    if "\r" in value or "\n" in value:
        raise ValueError(
            f"Le champ ``{field}`` contient un caractère CR/LF interdit "
            "(défense anti-injection d'en-tête)."
        )
    return value
