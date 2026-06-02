"""Scrubber de secrets pour les contenus de code source injectés au LLM.

Doctrine :

1. **Defense-in-depth, jamais "trust the LLM".** Même si l'allowlist de
   ``codebase_reader`` empêche la lecture des fichiers ``.env`` et autres,
   un développeur a pu coller une vraie clé API en commentaire dans un
   fichier ``.py`` — c'est arrivé en prod chez beaucoup d'équipes. Ce
   module scrubbe les patterns connus AVANT injection au LLM.

2. **Scrubbing pré ET post-LLM.** ``scrub()`` est appelé sur le contenu
   lu (avant prompt) ET sur la réponse de l'agent (avant retour user).
   Si le LLM avait mémorisé un secret entre tours, le post-scrub le
   masquera dans la réponse — ceinture+bretelles.

3. **Allowlist d'extensibilité.** ``SCRUB_PATTERNS`` est exposé pour
   permettre à l'admin d'ajouter des patterns custom (clés métier
   spécifiques) via un futur ``ai_config.IRIS_SCRUB_PATTERNS_EXTRA``.

4. **Idempotence garantie.** Le sentinel ``<REDACTED_*>`` ne contient
   aucun caractère qui pourrait re-matcher un pattern (pas de tiret
   suivi d'alphanumériques 20+ caractères). Tester ``scrub(scrub(x))
   == scrub(x)`` est dans la suite de tests.

5. **Pas de logging du contenu scrubbé.** Si une regex matchait, on
   logue uniquement le NOM du pattern et la position approximative —
   jamais le secret lui-même (qui pourrait alors finir dans llm_log.md).

Références :
- OWASP Secrets Management Cheat Sheet
- TruffleHog patterns library (inspiration)
- Microsoft Presidio (PII detection patterns)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Final, Union

from app.utils.logger import get_logger

logger = get_logger(__name__)


# Type d'un replacement re.sub : str littéral OU callback ``re.Match -> str``.
# La doc Python re.sub accepte les deux ; on annote précisément pour mypy.
_Replacement = Union[str, Callable[[re.Match[str]], str]]


@dataclass(frozen=True, slots=True)
class _ScrubRule:
    """Une règle de scrubbing nommée (pour debug/log sans fuite)."""

    name: str
    pattern: re.Pattern[str]
    replacement: _Replacement


# ---------------------------------------------------------------------------
# Patterns de scrubbing
#
# Ordre d'application : du plus spécifique au plus générique. Ainsi
# ``sk-ant-...`` matche AVANT ``sk-...`` générique.
# ---------------------------------------------------------------------------

_PATTERNS: Final[tuple[_ScrubRule, ...]] = (
    # --- Clés API LLM ---
    _ScrubRule(
        name="anthropic_api_key",
        # Format Anthropic: sk-ant-api03-... (mix d'alphanumériques + tirets/underscores).
        pattern=re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
        replacement="<REDACTED_ANTHROPIC_KEY>",
    ),
    _ScrubRule(
        name="openai_api_key",
        # Format OpenAI legacy: sk-... (48 chars). Format moderne: sk-proj-... ou sk-svcacct-...
        pattern=re.compile(r"sk-(?:proj|svcacct|admin)?-?[A-Za-z0-9_\-]{20,}"),
        replacement="<REDACTED_OPENAI_KEY>",
    ),
    # NOTE — Mistral n'a pas de préfixe distinctif (32 alphanumériques bruts).
    # Tout pattern aveugle de 32 chars matche les hashes git/md5/UUID sans tiret
    # qui sont fréquents dans du code Python. Désactivé — on s'appuie sur
    # ``secret_key_assignment`` (qui matche `mistral_api_key = "..."`)
    # pour les cas où la clé est en assignation explicite.
    _ScrubRule(
        name="bearer_token",
        # Authorization: Bearer xxxxxxx
        pattern=re.compile(r"(?i)Bearer\s+[A-Za-z0-9._\-]+"),
        replacement="Bearer <REDACTED_TOKEN>",
    ),
    _ScrubRule(
        name="basic_auth",
        # Authorization: Basic dXNlcjpwYXNz
        pattern=re.compile(r"(?i)Basic\s+[A-Za-z0-9+/=]{8,}"),
        replacement="Basic <REDACTED>",
    ),
    # --- JWT ---
    _ScrubRule(
        name="jwt_token",
        # eyJxxx.yyy.zzz (3 segments base64url)
        pattern=re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
        replacement="<REDACTED_JWT>",
    ),
    # --- Clés Komptia spécifiques (cf. .env.example, secrets habituels) ---
    _ScrubRule(
        name="sqlcipher_key",
        # SQLCIPHER_KEY=base64ouhex
        pattern=re.compile(r"(?i)SQLCIPHER_KEY\s*=\s*['\"]?[A-Za-z0-9+/=_\-]{16,}['\"]?"),
        replacement="SQLCIPHER_KEY=<REDACTED>",
    ),
    _ScrubRule(
        name="secret_key_assignment",
        # SECRET_KEY=..., FERNET_KEY=..., XSRF_SECRET=... (Komptia + Tornado conventions)
        pattern=re.compile(
            r"(?i)\b(SECRET_KEY|FERNET_KEY|XSRF_SECRET|COOKIE_SECRET|"
            r"SESSION_SECRET|JWT_SECRET|ENCRYPTION_KEY|API_KEY|API_SECRET|"
            r"AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN)\s*=\s*['\"]?[A-Za-z0-9+/=_\-]{12,}['\"]?"
        ),
        replacement=lambda m: f"{m.group(1)}=<REDACTED>",
    ),
    # --- Mots de passe en assignation ---
    _ScrubRule(
        name="password_assignment",
        # password = "xxxx" / PASSWORD: xxxxx / passwd=xxx
        pattern=re.compile(
            r"(?i)\b(password|passwd|pwd|smtp_password|smtp_pass|db_password|"
            r"sage_password)\s*[=:]\s*['\"][^'\"]{4,}['\"]"
        ),
        replacement=lambda m: f"{m.group(1)}=<REDACTED>",
    ),
    # --- DB connection strings (SQL Server, Postgres, MySQL) ---
    _ScrubRule(
        name="db_connection_string",
        # Driver={SQL Server};Server=...;UID=...;PWD=secret;
        pattern=re.compile(r"(?i)(PWD|Password)\s*=\s*[^;'\"\n]+"),
        replacement=lambda m: f"{m.group(1)}=<REDACTED>",
    ),
    _ScrubRule(
        name="postgres_url",
        # postgres://user:password@host:port/db
        pattern=re.compile(r"(?i)\b(?:postgres|postgresql|mysql|mariadb)://[^:/@\s]+:[^@\s]+@"),
        replacement="postgres://<USER>:<REDACTED>@",
    ),
    # --- Cookies / sessions ---
    _ScrubRule(
        name="set_cookie_value",
        # Set-Cookie: session=xxxx; Path=/...
        pattern=re.compile(r"(?i)\b(session|sid|sessionid|auth)\s*=\s*[A-Za-z0-9._\-]{16,}"),
        replacement=lambda m: f"{m.group(1)}=<REDACTED>",
    ),
    # NOTE — Carte de crédit : le pattern naïf "16 chiffres" matche les
    # IBAN partiels, les n° de compte client, les références internes.
    # Désactivé — un vrai numéro de carte arrive rarement dans le code
    # source ; s'il y arrivait, le test Luhn serait obligatoire pour
    # éviter les faux positifs sur des séquences comptables Komptia.
    # --- IBAN ---
    _ScrubRule(
        name="iban",
        # FR + 2 chiffres + jusqu'à 27 chars alphanumériques
        pattern=re.compile(
            r"\b(?:FR|DE|GB|IT|ES|BE|CH|NL|LU|PT|MC|AT|FI)\d{2}\s?(?:[A-Z0-9]{4}\s?){4,7}[A-Z0-9]{1,4}\b"
        ),
        replacement="<REDACTED_IBAN>",
    ),
    # --- AWS / GCP / Azure ---
    _ScrubRule(
        name="aws_access_key",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        replacement="<REDACTED_AWS_KEY>",
    ),
    _ScrubRule(
        name="aws_secret_access_key",
        # 40 chars base64
        pattern=re.compile(r"(?i)aws.{0,20}?(secret|key).{0,20}?['\"][A-Za-z0-9+/=]{40}['\"]"),
        replacement="<REDACTED_AWS_SECRET>",
    ),
    _ScrubRule(
        name="github_token",
        # ghp_xxx, gho_xxx, ghu_xxx, ghs_xxx, ghr_xxx
        pattern=re.compile(r"\bgh[posru]_[A-Za-z0-9]{36,}\b"),
        replacement="<REDACTED_GITHUB_TOKEN>",
    ),
    _ScrubRule(
        name="slack_token",
        # xoxb-..., xoxa-..., xoxp-...
        pattern=re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{20,}\b"),
        replacement="<REDACTED_SLACK_TOKEN>",
    ),
    _ScrubRule(
        name="stripe_key",
        # sk_live_xxx, sk_test_xxx, pk_live_xxx, pk_test_xxx
        pattern=re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
        replacement="<REDACTED_STRIPE_KEY>",
    ),
    # --- Generic high-entropy hex/base64 (heuristique conservatrice) ---
    # 64+ chars hex consécutifs (hash/key) → masquer.
    _ScrubRule(
        name="long_hex_string",
        pattern=re.compile(r"\b[a-f0-9]{64,}\b"),
        replacement="<REDACTED_HEX>",
    ),
    # 48+ chars base64 dans un assignement (clés Fernet typiques 44 chars)
    _ScrubRule(
        name="long_base64_assignment",
        pattern=re.compile(r"(?i)([a-z_]+)\s*=\s*['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]"),
        replacement=lambda m: f"{m.group(1)}=<REDACTED_B64>",
    ),
)


# ---------------------------------------------------------------------------
# API publique
# ---------------------------------------------------------------------------


def scrub(text: str) -> str:
    """Applique tous les patterns de scrubbing à une chaîne.

    Idempotent : ``scrub(scrub(x)) == scrub(x)``. Le caller peut appeler
    ce module aussi bien pré-injection LLM que post-réponse LLM sans
    risque de double-scrubbing destructif.

    Si ``text`` n'est pas une str (None, dict, list, etc.), retourne tel
    quel. Le caller passe par ``scrub_dict()`` pour les structures.
    """
    if not isinstance(text, str) or not text:
        return text

    result = text
    for rule in _PATTERNS:
        try:
            # ``re.sub`` accepte aussi bien str que callable comme repl
            result = rule.pattern.sub(rule.replacement, result)
        except (re.error, TypeError) as exc:
            # Une regex ratée ne doit pas bloquer le flow complet ; on
            # logue et on poursuit avec les autres règles.
            logger.warning("scrub: rule '%s' raised %s", rule.name, exc)
            continue

    return result


def scrub_dict(payload: Any) -> Any:
    """Walk récursif sur un dict/list/str pour scrubber toutes les
    valeurs textuelles.

    Préserve les clés (les noms de variables comme ``api_key`` ne sont
    pas eux-mêmes des secrets — c'est leur valeur qui l'est). Préserve
    les autres types (int, float, bool, None) tels quels.
    """
    if isinstance(payload, str):
        return scrub(payload)
    if isinstance(payload, dict):
        return {k: scrub_dict(v) for k, v in payload.items()}
    if isinstance(payload, (list, tuple)):
        scrubbed = [scrub_dict(item) for item in payload]
        return scrubbed if isinstance(payload, list) else tuple(scrubbed)
    return payload


__all__ = ["scrub", "scrub_dict"]
