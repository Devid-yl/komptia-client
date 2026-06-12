"""Handlers HTTP pour les webhooks d'automatisation.

Quatre endpoints :

* ``POST   /webhook/<uuid4>``                                   — déclenchement public (token-auth)
* ``GET    /api/automations/<id>/webhooks``                     — liste (ownership)
* ``POST   /api/automations/<id>/webhooks``                     — création (ownership, max 5)
* ``DELETE /api/automations/<id>/webhooks/<wid>``               — suppression (ownership)
* ``POST   /api/automations/<id>/webhooks/<wid>/regenerate``    — rotation du token

Garanties senior (OWASP API Security Top 10 2023 + ASVS v5 + CLAUDE.md)
-----------------------------------------------------------------------

1. **Authentification fail-closed** — endpoint public authentifié par le
   UUID4 du path (≈128 bits d'entropie). Endpoints CRUD décorés par
   ``@require_role("admin", "user")`` (eager-resolved, cf. ``base.py``).
2. **Anti-oracle BOLA (API1:2023)** — tout rejet sur webhook inactif,
   automation inactive, mauvais owner, ou ID inexistant retourne **404**
   avec le même message. Un attaquant qui énumère les tokens/IDs ne peut
   pas distinguer "existe-mais-inaccessible" de "n'existe pas".
3. **Rate-limiting (API4:2023)** — via ``RateLimiter`` partagé, thread-safe :
   - Déclenchement : ``_INBOUND_RATE_MAX`` / fenêtre (par token).
   - Création/suppression/rotation : ``_MUTATION_RATE_MAX`` / fenêtre
     (par user — évite le spam DoS sur la BDD locale).
4. **Validation stricte (API3:2023, API8:2023)** — ``description`` :
   longueur max **422** (pas de troncature silencieuse), CRLF rejeté en
   400 (CWE-93 / CWE-117). Body JSON non-dict → 400. Content-Length
   pré-check → 413 avant désérialisation.
5. **Erreurs déterministes (CWE-209)** — messages client dans
   :class:`_Messages`, jamais ``str(exception)`` vers le client. Détails
   dans les logs structurés corrélables par ``request_id``.
6. **Fire-and-forget sûr (Python 3.12+)** — la tâche background est
   ajoutée à ``_background_tasks`` (strong ref) + ``add_done_callback``
   pour discard. ``asyncio.ensure_future`` sans référence laisse le
   garbage collector supprimer la tâche avant exécution (bug documenté
   depuis Python 3.12, cf. https://docs.python.org/3/library/asyncio-task.html#creating-tasks).
7. **Pas de race sur le compteur** — ``trigger_count`` incrémenté par un
   ``UPDATE ... SET trigger_count = trigger_count + 1`` atomique côté SQL,
   pas par un read-modify-write en Python qui perd des événements sous
   charge concurrente.
8. **trigger_data propagé** — le body JSON du webhook est passé à
   ``execute_automation(..., trigger_data={"webhook": {...}})`` pour que
   le workflow engine puisse résoudre ``{{webhook.body}}``,
   ``{{webhook.method}}``, ``{{webhook.remote_ip}}`` dans les étapes aval.
9. **URL base assainie** — l'URL renvoyée (``to_dict(include_url=True)``)
   utilise ``self.request.protocol`` + ``self.request.host``. Tornado
   filtre déjà le ``Host`` header au niveau de la socket si l'app est
   derrière un reverse-proxy bien configuré (cf. ``trusted_downstream``
   dans ``app/main.py``).
10. **Logs sanitisés (CWE-117)** — nom d'automation injecté dans les
    logs passe par :func:`_log_safe` (défense-in-depth CRLF).
11. **Signature HMAC-SHA256 (FAILLE 2, 2026-06-12)** — opt-in par webhook
    (``require_signature: true`` à la création). Secret partagé généré côté
    serveur (``secrets.token_urlsafe``), stocké en BDD (SQLCipher), montré
    UNE fois (show-once). Inbound : en-têtes ``X-Komptia-Timestamp`` +
    ``X-Komptia-Signature`` (``sha256=HMAC_SHA256(secret, "{ts}.{body}")``),
    vérif :func:`hmac.compare_digest`, fenêtre anti-rejeu (défaut 300 s,
    env ``WEBHOOK_HMAC_TOLERANCE_SECONDS``), 401 uniforme si absente /
    invalide / hors fenêtre. Le token UUID4 reste exigé en complément.

Notes de compat ascendante
--------------------------
Les noms ``_check_rate_limit``, ``_rate_limit_store``, ``_RATE_LIMIT_MAX``,
``_RATE_LIMIT_WINDOW``, ``MAX_WEBHOOKS_PER_AUTOMATION``, ``MAX_PAYLOAD_BYTES``,
``MAX_DESCRIPTION_LENGTH`` restent **exportés** (shim minces) pour les
tests existants qui les importent — la logique est néanmoins déléguée
au ``RateLimiter`` partagé et aux constantes ``Final[int]`` justifiées.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import math
import os
import secrets
import time
import uuid
from typing import Any, Final

import tornado.web
from sqlalchemy import func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core import clock
from app.handlers.base import AuthenticatedHandler, BaseHandler, require_role
from app.models.automation import Automation
from app.models.webhook_trigger import WebhookTrigger
from app.services.automation import execute_automation
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter
from app.utils.validators import assert_no_crlf, clean_input

logger = get_logger(__name__)


# ── Bornes de protection (Final[int], chaque valeur justifiée) ────────────
#
# Magic numbers interdits : chaque constante est ``Final[int]`` avec une
# justification qui explique POURQUOI cette valeur et pas une autre.

#: Nombre max de webhooks par automation. Au-delà, l'UI devient illisible
#: ET on ouvre la porte à un user qui spammerait la création pour remplir
#: la BDD (DoS local). Cinq suffit pour tous les cas légitimes rencontrés
#: (prod, staging, CI, lambdas diverses).
MAX_WEBHOOKS_PER_AUTOMATION: Final[int] = 5

#: Taille max du payload entrant (1 MiB). Un webhook légitime envoie un
#: JSON de quelques KiB ; 1 MiB laisse de la place pour des extensions
#: raisonnables (arrays, champs base64 modérés) sans devenir un vecteur
#: event-loop block (json.loads d'un 100 MiB gèle le worker).
MAX_PAYLOAD_BYTES: Final[int] = 1 * 1024 * 1024

#: Longueur max de la description libre. La textarea UI affiche ~500
#: caractères confortablement — au-delà c'est la doc qui dérive dans un
#: champ pas fait pour (CWE-707 : données hors contrat).
MAX_DESCRIPTION_LENGTH: Final[int] = 500

#: Borne de troncature pour les valeurs injectées dans les logs (CWE-117
#: défense-in-depth). 64 caractères suffisent pour tracer un nom sans
#: polluer le pipeline structuré.
_LOG_FIELD_MAX_LEN: Final[int] = 64

# ── Rate-limit (API4:2023 Unrestricted Resource Consumption) ──────────────

#: Inbound : 60 déclenchements / minute / token. Au-delà c'est un bug
#: côté émetteur ou une attaque (boucle). Chaque déclenchement lance un
#: workflow → CPU + IO, donc on borne.
_INBOUND_RATE_MAX: Final[int] = 60
_INBOUND_RATE_WINDOW: Final[int] = 60

#: Mutations CRUD : 30 / minute / user. Création/suppression/rotation de
#: webhook sont rares en usage normal ; un user qui dépasse scripte
#: quelque chose (ou fuzz).
_MUTATION_RATE_MAX: Final[int] = 30
_MUTATION_RATE_WINDOW: Final[int] = 60

# ── Signature HMAC-SHA256 (FAILLE 2, 2026-06-12) ──────────────────────────
#
# Le token UUID4 dans l'URL reste le 1er facteur (lookup + anti-énumération),
# la signature est le 2e : un émetteur qui possède l'URL mais pas le secret
# (URL leakée dans des logs proxy, historique navigateur, repo CI) ne peut
# plus déclencher l'automatisation. Schéma signé : ``"{timestamp}.{body}"``
# → couvre le corps ET l'horodatage (anti-rejeu par fenêtre temporelle,
# pattern Stripe/GitHub). Secret PAR WEBHOOK, généré côté serveur
# (``secrets.token_urlsafe``), stocké en BDD locale chiffrée SQLCipher,
# montré UNE SEULE FOIS à la création/rotation — jamais en dur dans le code.

_SIGNATURE_HEADER: Final[str] = "X-Komptia-Signature"
_TIMESTAMP_HEADER: Final[str] = "X-Komptia-Timestamp"

#: Entropie du secret généré : 32 octets = 256 bits, aligné sur la taille de
#: bloc de HMAC-SHA256 (un secret plus court affaiblirait la construction,
#: plus long n'ajoute rien). Encodé urlsafe → ~43 chars (fits VARCHAR(128)).
_HMAC_SECRET_BYTES: Final[int] = 32

#: Fenêtre anti-rejeu par défaut (secondes). 300 s = standard industrie
#: (Stripe webhooks) : assez large pour la dérive d'horloge d'émetteurs mal
#: synchronisés NTP, assez courte pour borner la fenêtre d'une requête
#: capturée. Un rejeu DANS la fenêtre reste borné par le rate-limit inbound.
_HMAC_TOLERANCE_SECONDS_DEFAULT: Final[int] = 300


def _hmac_tolerance_seconds() -> int:
    """Fenêtre anti-rejeu effective — override ops ``WEBHOOK_HMAC_TOLERANCE_SECONDS``.

    Lecture dynamique (pas figée à l'import) : ajustable sans redéploiement et
    testable par monkeypatch d'env. Valeur invalide/négative → défaut (fail-safe
    vers le comportement documenté, jamais vers une fenêtre infinie).
    """
    raw = os.environ.get("WEBHOOK_HMAC_TOLERANCE_SECONDS", "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _HMAC_TOLERANCE_SECONDS_DEFAULT
    return value if value > 0 else _HMAC_TOLERANCE_SECONDS_DEFAULT

#: Instance partagée entre tous les handlers (thread-safe, sliding window).
#: Cf. ``app/utils/rate_limiter.py``. La clé encode l'action pour qu'un
#: user saturant les mutations ne bloque pas ses propres lectures.
_rate_limiter: Final[RateLimiter] = RateLimiter()


# ── Messages client (FR, centralisés, Final[str]) ─────────────────────────


class _Messages:
    """Messages d'erreur client centralisés (FR, ton cohérent UI).

    Garder ces constantes en un seul endroit : (1) évite la dérive
    entre handlers, (2) prépare une i18n future, (3) permet aux tests
    d'importer plutôt que de hardcoder des strings (refactor-friendly),
    (4) facilite l'audit sécurité (un seul fichier à grep).
    """

    # Anti-oracle : même message sur toutes les causes de 404, sans
    # distinction "inactif" / "pas owner" / "n'existe pas" — un attaquant
    # qui énumère ne récupère aucun signal de discrimination.
    NOT_FOUND: Final[str] = "Ressource introuvable."

    AUTOMATION_NOT_FOUND: Final[str] = "Automatisation introuvable."
    WEBHOOK_NOT_FOUND: Final[str] = "Webhook introuvable."

    PAYLOAD_TOO_LARGE: Final[str] = (
        f"Payload trop volumineux (max {MAX_PAYLOAD_BYTES // (1024 * 1024)} Mo)."
    )
    DESCRIPTION_TOO_LONG: Final[str] = (
        f"La description doit faire au plus {MAX_DESCRIPTION_LENGTH} caractères."
    )
    INVALID_FIELD_TYPE: Final[str] = "Un champ du body n'est pas du bon type."
    INVALID_CRLF: Final[str] = "Les retours à la ligne dans ce champ sont interdits."
    INVALID_JSON: Final[str] = "Le corps de la requête doit être du JSON valide."

    # CWE-209 : UN SEUL message pour signature absente / invalide / timestamp
    # hors fenêtre — un attaquant ne doit pas savoir QUELLE partie a échoué
    # (sinon il distingue « secret faux » de « horloge décalée » et affine).
    SIGNATURE_INVALID: Final[str] = "Signature de webhook absente ou invalide."

    RATE_LIMITED_INBOUND: Final[str] = (
        f"Trop de déclenchements ({_INBOUND_RATE_MAX}/minute) — patientez."
    )
    RATE_LIMITED_MUTATION: Final[str] = (
        f"Trop d'opérations ({_MUTATION_RATE_MAX}/minute) — patientez."
    )

    MAX_WEBHOOKS_REACHED: Final[str] = (
        f"Maximum {MAX_WEBHOOKS_PER_AUTOMATION} webhooks par automatisation."
    )
    WEBHOOK_INACTIVE: Final[str] = "Webhook inactif."  # 403 explicite (pas BOLA ici)

    INTERNAL_ERROR: Final[str] = "Une erreur interne est survenue."
    SERVICE_UNAVAILABLE: Final[str] = "Service temporairement indisponible."

    REGENERATED: Final[str] = "Token régénéré — l'ancienne URL ne fonctionnera plus."
    DELETED: Final[str] = "Webhook supprimé."


# ── Fire-and-forget tracker (anti-GC bug Python 3.12+) ────────────────────
#
# ``asyncio.ensure_future(coro)`` sans conserver une référence à la Task
# peut être garbage-collecté avant la fin de l'exécution. Documenté dans
# la doc Python depuis 3.12 :
# https://docs.python.org/3/library/asyncio-task.html#asyncio.create_task
# Le fix canonical : garder une strong ref jusqu'à done_callback.

_background_tasks: Final[set[asyncio.Task[Any]]] = set()


def _spawn_background(coro: Any) -> asyncio.Task[Any]:
    """Crée une Task et la garde en strong ref jusqu'à sa fin.

    Retour utile pour les tests qui veulent await la fin d'exécution.
    """
    task = asyncio.ensure_future(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


async def _execute_webhook_automation(
    automation_id: int,
    webhook_id: int,
    trigger_data: dict[str, Any] | None = None,
) -> None:
    """Fire-and-forget wrapper avec logging d'exceptions.

    Invoqué en background — les exceptions sont loggées, pas propagées
    (sinon la Task termine en ``exception set but not retrieved``). Le
    ``trigger_data`` est propagé pour que ``{{webhook.body}}`` et
    consorts soient résolus par le workflow engine.
    """
    try:
        await execute_automation(
            automation_id,
            manual=False,
            trigger_data=trigger_data,
            trigger_source="webhook",
            triggered_by_user_id=None,
        )
    except Exception:  # noqa: BLE001 — fire-and-forget : on log tout
        logger.exception(
            "Echec execution webhook-triggered",
            extra={
                "automation_id": automation_id,
                "webhook_id": webhook_id,
            },
        )


# ── Helpers purs (testables sans handler) ─────────────────────────────────


def _log_safe(value: str | None, *, max_len: int = _LOG_FIELD_MAX_LEN) -> str:
    """Sanitise une string pour injection dans une ligne de log.

    * ``None`` ou non-string → ``"<none>"``.
    * Caractères de contrôle (``\\r``, ``\\n``, ``\\t``, etc.) → ``?``
      pour empêcher l'injection de fausses lignes (CWE-117).
    * Tronqué à ``max_len`` pour éviter la pollution.
    """
    if not isinstance(value, str):
        return "<none>"
    cleaned = "".join(
        c if (c.isprintable() and c not in ("\r", "\n", "\t")) else "?" for c in value
    )
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 1] + "…"
    return cleaned


def _check_rate(*, key: str, max_requests: int, window_seconds: int, message: str) -> None:
    """Lève HTTP 429 si la clé a dépassé sa fenêtre glissante."""
    if not _rate_limiter.check(key, max_requests=max_requests, window_seconds=window_seconds):
        raise tornado.web.HTTPError(429, message)


def _verify_webhook_signature(
    secret: str,
    timestamp_header: str | None,
    signature_header: str | None,
    body: bytes,
    *,
    now_epoch: float | None = None,
    tolerance_seconds: int | None = None,
) -> bool:
    """Vérifie la signature HMAC-SHA256 d'une requête webhook entrante.

    Contrat émetteur (documenté dans la réponse de création du webhook) :

    * ``X-Komptia-Timestamp`` : epoch Unix en secondes (entier) au moment de
      l'envoi.
    * ``X-Komptia-Signature`` : ``sha256=<hex>`` (préfixe optionnel) où
      ``<hex> = HMAC_SHA256(secret, f"{timestamp}.{body_brut}")`` en
      hexadécimal minuscule.

    Garanties :

    * **Anti-rejeu** : ``|now - timestamp| > tolérance`` → rejet. Le timestamp
      étant DANS le payload signé, il ne peut pas être réécrit sans le secret.
      (Une horloge émetteur EN AVANCE est aussi rejetée — symétrique, évite
      qu'un attaquant pré-date des requêtes utilisables plus tard.)
    * **Timing-safe** : ``hmac.compare_digest`` (CWE-208).
    * **Fail-closed** : tout header absent/malformé → ``False``, jamais
      d'exception propagée (un body exotique ne doit pas produire un 500
      qui bypasserait le 401).

    Pure (injectable ``now_epoch``/``tolerance_seconds``) → testable sans
    handler ni horloge réelle.
    """
    if not secret or not timestamp_header or not signature_header:
        return False
    try:
        ts = float(str(timestamp_header).strip())
    except (TypeError, ValueError):
        return False
    # ``float('nan')`` parse sans exception MAIS toute comparaison avec NaN
    # vaut False → ``abs(now - ts) > tolerance`` serait traversé : la fenêtre
    # anti-rejeu serait annulée pour ce timestamp. ``inf`` est rejeté par la
    # comparaison, NaN doit l'être explicitement (revue adversariale 2026-06-12).
    if not math.isfinite(ts):
        return False
    now = time.time() if now_epoch is None else now_epoch
    tolerance = _hmac_tolerance_seconds() if tolerance_seconds is None else tolerance_seconds
    if abs(now - ts) > tolerance:
        return False

    received = str(signature_header).strip()
    if received.lower().startswith("sha256="):
        received = received[len("sha256=") :]
    # Décodage hex AVANT compare : ``hmac.compare_digest`` sur des str lève
    # TypeError si un caractère non-ASCII s'y trouve (Tornado décode les
    # headers en latin-1 → octet >= 0x80 possible). Un header malformé doit
    # produire ``False`` (→ 401), JAMAIS une exception (→ 500 + oracle
    # 500-vs-401, CWE-209). ``bytes.fromhex`` rejette non-hex, non-ASCII et
    # longueur impaire d'un coup, et tolère la casse.
    try:
        received_bytes = bytes.fromhex(received)
    except ValueError:
        return False
    # La signature couvre le timestamp TEL QU'ENVOYÉ (pas re-normalisé) :
    # l'émetteur signe f"{son_ts}.{body}" — on reconstruit à l'identique.
    signed_payload = str(timestamp_header).strip().encode("utf-8") + b"." + (body or b"")
    expected = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).digest()
    return hmac.compare_digest(expected, received_bytes)


def _parse_description_or_error(body: dict[str, Any]) -> str | None:
    """Extrait et valide ``description`` depuis un body JSON.

    * Absent ou vide → ``None``.
    * Non-string → 400 ``INVALID_FIELD_TYPE`` (cf. ``[...] pass`` silencieux
      pré-refactor qui droppait l'input utilisateur sans feedback).
    * CRLF → 400 ``INVALID_CRLF`` (défense-in-depth CWE-93/117).
    * Trop long → 422 ``DESCRIPTION_TOO_LONG`` (RFC 9110 §15.5.14).
    """
    raw = body.get("description")
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        raise tornado.web.HTTPError(400, _Messages.INVALID_FIELD_TYPE)
    candidate = clean_input(raw)
    if not isinstance(candidate, str):
        raise tornado.web.HTTPError(400, _Messages.INVALID_FIELD_TYPE)
    if not candidate:
        return None
    try:
        assert_no_crlf(candidate, field="description")
    except ValueError as exc:
        raise tornado.web.HTTPError(400, _Messages.INVALID_CRLF) from exc
    if len(candidate) > MAX_DESCRIPTION_LENGTH:
        raise tornado.web.HTTPError(422, _Messages.DESCRIPTION_TOO_LONG)
    return candidate


def _parse_body_or_error(handler: BaseHandler) -> dict[str, Any]:
    """Parse le body JSON avec pré-check Content-Length.

    * ``Content-Length`` > ``MAX_PAYLOAD_BYTES`` → 413 avant parse JSON.
    * Body effectif > ``MAX_PAYLOAD_BYTES`` → 413.
    * Body vide → ``{}`` (tolérance : le description est optionnelle).
    * JSON invalide → 400 via ``BaseHandler.get_json_body``.
    """
    request = handler.request
    content_length_header = request.headers.get("Content-Length")
    if content_length_header is not None:
        try:
            content_length = int(content_length_header)
        except (ValueError, TypeError):
            content_length = 0
        if content_length > MAX_PAYLOAD_BYTES:
            raise tornado.web.HTTPError(413, _Messages.PAYLOAD_TOO_LARGE)

    if request.body is not None and len(request.body) > MAX_PAYLOAD_BYTES:
        raise tornado.web.HTTPError(413, _Messages.PAYLOAD_TOO_LARGE)

    if not request.body:
        return {}

    try:
        return handler.get_json_body()
    except tornado.web.HTTPError:
        # ``get_json_body`` lève déjà 400 avec un message FR — on remappe.
        raise tornado.web.HTTPError(400, _Messages.INVALID_JSON)


def _build_trigger_data(handler: BaseHandler) -> dict[str, Any]:
    """Construit le dict ``trigger_data`` propagé à ``execute_automation``.

    Contient **uniquement** des champs non-sensibles :

    * ``webhook.method`` — méthode HTTP (toujours ``POST`` en pratique).
    * ``webhook.remote_ip`` — IP source (peut servir au filtrage aval).
    * ``webhook.body`` — body JSON si parseable, sinon ``None``.

    Le body n'est **pas** re-parsé si mal formé : on retourne ``None`` plutôt
    qu'une exception (le déclenchement reste valide même avec un body non-JSON).
    """
    request = handler.request
    parsed_body: dict[str, Any] | None
    try:
        parsed_body = handler.get_json_body() if request.body else None
    except tornado.web.HTTPError:
        parsed_body = None

    return {
        "webhook": {
            "method": request.method,
            "remote_ip": request.remote_ip,
            "body": parsed_body,
        }
    }


async def _fetch_automation_or_404(
    session: AsyncSession,
    *,
    automation_id: int,
    requesting_user_id: int,
    requesting_user_is_admin: bool,
) -> Automation:
    """Récupère une :class:`Automation` par ID ou lève 404 (anti-oracle BOLA).

    Retourne 404 quand l'automation n'existe pas **OU** quand le user
    demandeur n'en est pas propriétaire (et n'est pas admin). Un
    attaquant qui énumère les IDs reçoit le même 404 pour "existe-mais-
    à-quelqu'un-d'autre" et "n'existe pas" — aucun oracle.
    """
    automation = await session.get(Automation, automation_id)
    if automation is None:
        raise tornado.web.HTTPError(404, _Messages.AUTOMATION_NOT_FOUND)
    if not requesting_user_is_admin and automation.user_id != requesting_user_id:
        raise tornado.web.HTTPError(404, _Messages.AUTOMATION_NOT_FOUND)
    return automation


async def _fetch_webhook_or_404(
    session: AsyncSession,
    *,
    webhook_id: int,
    automation_id: int,
) -> WebhookTrigger:
    """Récupère un :class:`WebhookTrigger` ou lève 404.

    La contrainte ``automation_id`` est imposée dans la requête : un
    webhook "existe" pour le caller uniquement s'il est lié à l'automation
    demandée. Évite qu'un URL ``/automations/10/webhooks/42`` révèle
    l'existence du webhook 42 attaché à une autre automation.
    """
    result = await session.execute(
        select(WebhookTrigger).where(
            WebhookTrigger.id == webhook_id,
            WebhookTrigger.automation_id == automation_id,
        )
    )
    webhook = result.scalars().first()
    if webhook is None:
        raise tornado.web.HTTPError(404, _Messages.WEBHOOK_NOT_FOUND)
    return webhook


def _base_url(handler: BaseHandler) -> str:
    """Construit ``<scheme>://<host>`` depuis la requête courante.

    Tornado filtre déjà le Host header au niveau socket si l'app est
    derrière un reverse-proxy correctement configuré (cf.
    ``trusted_downstream`` / ``xheaders`` dans ``app/main.py``).
    """
    return f"{handler.request.protocol}://{handler.request.host}"


# ── Shim compatibilité rétro (tests existants) ────────────────────────────
#
# Les tests ``test_webhooks.py`` + ``test_webhook_triggers.py`` importent
# ``_check_rate_limit``, ``_rate_limit_store``, ``_RATE_LIMIT_MAX``,
# ``_RATE_LIMIT_WINDOW`` du module. Historiquement c'était un rate-limiter
# ad-hoc (dict global). On remappe sur le ``RateLimiter`` partagé — même
# sémantique (sliding window, clé = token), mais thread-safe et partagé
# avec le reste du codebase. Le store ``_rate_limit_store`` n'est plus
# source de vérité ; il reste exposé pour que les tests qui le ``clear()``
# continuent de fonctionner (opération idempotente côté limiter partagé
# puisqu'on appelle ``_rate_limiter._requests.clear()`` via le shim).

_RATE_LIMIT_MAX: Final[int] = _INBOUND_RATE_MAX
_RATE_LIMIT_WINDOW: Final[int] = _INBOUND_RATE_WINDOW


class _RateLimitStoreShim:
    """Proxy vers ``_rate_limiter._requests`` pour compat tests."""

    def __getitem__(self, key: str) -> list[float]:
        return _rate_limiter._requests[key]

    def __setitem__(self, key: str, value: list[float]) -> None:
        _rate_limiter._requests[key] = value

    def __delitem__(self, key: str) -> None:
        del _rate_limiter._requests[key]

    def __contains__(self, key: object) -> bool:
        return key in _rate_limiter._requests

    def __iter__(self) -> Any:
        return iter(_rate_limiter._requests)

    def __len__(self) -> int:
        return len(_rate_limiter._requests)

    def clear(self) -> None:
        _rate_limiter._requests.clear()

    def pop(self, key: str, default: Any = None) -> Any:
        return _rate_limiter._requests.pop(key, default)

    def get(self, key: str, default: Any = None) -> Any:
        return _rate_limiter._requests.get(key, default)


_rate_limit_store: Final[_RateLimitStoreShim] = _RateLimitStoreShim()


def _check_rate_limit(token: str) -> bool:
    """Délègue au ``RateLimiter`` partagé avec clé = token (compat tests).

    Retourne ``True`` si la requête est autorisée, ``False`` si rate-limitée.
    Les autres usages (mutation user-scoped) emploient des clés préfixées
    ``webhook:mutation:<uid>`` qui ne peuvent pas entrer en collision avec
    un UUID4 (36 chars, format distinct).
    """
    return _rate_limiter.check(
        token,
        max_requests=_INBOUND_RATE_MAX,
        window_seconds=_INBOUND_RATE_WINDOW,
    )


# ── Public inbound endpoint ───────────────────────────────────────────────


class WebhookInboundHandler(BaseHandler):
    """``POST /webhook/<uuid4>`` — déclenchement public par token.

    * **XSRF désactivé** — l'endpoint est explicitement public, le token
      UUID4 dans le path fait office d'authentification.
    * **Rate-limit par token** après lookup (pas avant : sinon un attaquant
      qui spam des tokens aléatoires sature le store du limiter).
    * **202 Accepted** — l'exécution tourne en background ; on répond
      immédiatement pour que l'émetteur (GitHub Actions, Zapier, etc.) ne
      timeout pas sur une automation longue.
    """

    def check_xsrf_cookie(self) -> None:
        """XSRF désactivé : endpoint public authentifié par token URL."""

    async def post(self, token: str) -> None:
        """Déclenche l'automation liée au token."""
        # ── Pré-check taille body (avant toute I/O DB) ──
        if len(self.request.body) > MAX_PAYLOAD_BYTES:
            self.write_json(
                {"success": False, "error": _Messages.PAYLOAD_TOO_LARGE},
                413,
            )
            return

        # ── Lookup webhook + capture des champs nécessaires avant commit ──
        automation_id: int
        automation_name: str
        webhook_id: int
        try:
            async with self.db_session() as session:
                result = await session.execute(
                    select(WebhookTrigger)
                    .options(selectinload(WebhookTrigger.automation))
                    .where(WebhookTrigger.token == token)
                )
                webhook = result.scalars().first()

                # Anti-oracle : webhook inconnu OU automation introuvable
                # OU automation inactive → 404 uniforme. Seul un webhook
                # explicitement désactivé (is_active=False) retourne 403
                # pour signaler à un intégrateur autorisé qu'il faut
                # réactiver le webhook côté UI.
                if webhook is None or webhook.automation is None:
                    raise tornado.web.HTTPError(404, _Messages.NOT_FOUND)

                # Rate-limit dès que le token est validé EXISTANT (avant les
                # checks d'état webhook/automation/owner). A7-C5 Point 2
                # (adversarial) : un token valide dont l'état devient invalide
                # (owner coupé, auto désactivée) reste ainsi borné — sinon un
                # martèlement non rate-limité (1 lookup User/req) était possible.
                # Placé APRÈS le lookup pour qu'un attaquant tapant des tokens
                # aléatoires (404 ci-dessus) ne pollue pas le store du limiter.
                # ── Signature HMAC-SHA256 (FAILLE 2) ──
                # Vérifiée AVANT tout oracle d'état (is_active 403, automation
                # 404…) ET AVANT le rate-limit par token : sinon un porteur de
                # l'URL SANS le secret pourrait épuiser le budget 60/min du
                # token avec des requêtes non signées → 429 pour l'émetteur
                # signé LÉGITIME (DoS, revue adversariale 2026-06-12). Le coût
                # d'un HMAC-SHA256 sur un body ≤ 1 Mio est négligeable ; les
                # échecs répétés sont bornés par un limiteur DÉDIÉ (clé
                # ``sigfail:<token>``) qui ne touche pas le budget légitime.
                # Webhooks sans secret (NULL) = compat token-seul, inchangés.
                # 401 uniforme (CWE-209) pour absente / invalide / hors fenêtre.
                if webhook.hmac_secret:
                    if not _verify_webhook_signature(
                        webhook.hmac_secret,
                        self.request.headers.get(_TIMESTAMP_HEADER),
                        self.request.headers.get(_SIGNATURE_HEADER),
                        self.request.body or b"",
                    ):
                        if not _rate_limiter.check(
                            f"webhook:sigfail:{token}",
                            max_requests=_INBOUND_RATE_MAX,
                            window_seconds=_INBOUND_RATE_WINDOW,
                        ):
                            raise tornado.web.HTTPError(
                                429, _Messages.RATE_LIMITED_INBOUND
                            )
                        logger.warning(
                            "webhook signature rejetee",
                            extra={
                                "request_id": self.request_id,
                                "webhook_id": webhook.id,
                                "has_signature": bool(
                                    self.request.headers.get(_SIGNATURE_HEADER)
                                ),
                                "has_timestamp": bool(
                                    self.request.headers.get(_TIMESTAMP_HEADER)
                                ),
                                "remote_ip": self.request.remote_ip,
                            },
                        )
                        raise tornado.web.HTTPError(401, _Messages.SIGNATURE_INVALID)

                if not _check_rate_limit(token):
                    raise tornado.web.HTTPError(429, _Messages.RATE_LIMITED_INBOUND)

                if not webhook.is_active:
                    self.write_json(
                        {"success": False, "error": _Messages.WEBHOOK_INACTIVE},
                        403,
                    )
                    return

                if not webhook.automation.is_active:
                    # Anti-oracle : on ne révèle pas à un attaquant que le
                    # token est valide mais l'automation est désactivée.
                    raise tornado.web.HTTPError(404, _Messages.NOT_FOUND)

                # A7-C5 — Le PROPRIÉTAIRE de l'automation doit être ACTIF. Sans
                # ce check, un compte désactivé/révoqué garde son webhook comme
                # vecteur d'exécution (et d'accès aux données source). 404
                # anti-oracle, uniforme avec « automation inactive » — ne révèle
                # pas qu'un token valide est rattaché à un compte coupé.
                # Defense-in-depth : l'executor refuse aussi en fail-closed les
                # runs déclenchés dont l'owner est introuvable/désactivé.
                from app.models.user import User

                owner = await session.get(User, webhook.automation.user_id)
                if owner is None or not owner.is_active:
                    raise tornado.web.HTTPError(404, _Messages.NOT_FOUND)

                # S2 — Kill-switch global FLAG_AUTOMATIONS_DISABLED.
                # L'admin doit pouvoir couper TOUTES les exécutions (UI,
                # scheduler, webhook). Avant : seul UI/scheduler honoraient.
                # Ici : 503 Service Unavailable (l'intégrateur sait que
                # le service est temporairement coupé, pas une erreur d'auth).
                from app.models.feature_flag import FLAG_AUTOMATIONS_DISABLED
                from app.services.automation.feature_flag_service import is_truthy

                # A7-M15b — BUG : ce check utilisait la STRING littérale
                # "FLAG_AUTOMATIONS_DISABLED" (le NOM de la constante), alors que
                # le flag réel est sa VALEUR "automations-disabled" (cf.
                # FeatureFlag, test_feature_flag.py). Conséquence : quand l'admin
                # activait le kill-switch, les runs WEBHOOK continuaient (check du
                # mauvais nom → default False). On passe par la constante (SSoT).
                if await is_truthy(session, FLAG_AUTOMATIONS_DISABLED, default=False):
                    raise tornado.web.HTTPError(
                        503, "Automatisations temporairement désactivées par l'administrateur."
                    )

                # Capture avant UPDATE + commit (expire_on_commit safe).
                automation_id = webhook.automation_id
                automation_name = webhook.automation.name
                webhook_id = webhook.id

                # UPDATE atomique (pas de read-modify-write en Python).
                # Sous charge concurrente, +1 en Python perdait des
                # événements ; SQL natif gère le verrou.
                await session.execute(
                    update(WebhookTrigger)
                    .where(WebhookTrigger.id == webhook_id)
                    .values(
                        trigger_count=WebhookTrigger.trigger_count + 1,
                        last_triggered_at=clock.now(),
                    )
                )
        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.exception(
                "Erreur SQL dans webhook inbound",
                extra={"request_id": self.request_id, "token_head": token[:8]},
            )
            raise tornado.web.HTTPError(503, _Messages.SERVICE_UNAVAILABLE)

        # ── Construction trigger_data (hors session DB) ──
        trigger_data = _build_trigger_data(self)

        # ── Fire-and-forget avec strong ref (anti-GC Python 3.12+) ──
        logger.info(
            "webhook triggered",
            extra={
                "request_id": self.request_id,
                "webhook_id": webhook_id,
                "automation_id": automation_id,
                "automation_name": _log_safe(automation_name),
            },
        )
        _spawn_background(_execute_webhook_automation(automation_id, webhook_id, trigger_data))

        # ── 202 Accepted : exécution async en cours ──
        self.write_json(
            {
                "success": True,
                "message": f"Automation '{automation_name}' triggered",
                "automation_id": automation_id,
                "webhook_id": webhook_id,
            },
            202,
        )


# ── Authenticated CRUD endpoints ──────────────────────────────────────────


class WebhookListAPIHandler(AuthenticatedHandler):
    """``GET/POST /api/automations/<id>/webhooks`` — liste + création."""

    @require_role("admin", "user")
    async def get(self, automation_id: str) -> None:
        """Liste les webhooks de l'automation (owner ou admin)."""
        user = self.current_user
        assert user is not None  # garanti par @require_role

        aid = self._parse_int_or_400(automation_id, "automation_id")

        try:
            async with self.db_session() as session:
                await _fetch_automation_or_404(
                    session,
                    automation_id=aid,
                    requesting_user_id=user.id,
                    requesting_user_is_admin=user.is_admin,
                )
                result = await session.execute(
                    select(WebhookTrigger)
                    .where(WebhookTrigger.automation_id == aid)
                    .order_by(WebhookTrigger.created_at.desc())
                )
                webhooks = result.scalars().all()
                base_url = _base_url(self)
                payload = [w.to_dict(include_url=True, base_url=base_url) for w in webhooks]
        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.exception(
                "Erreur SQL liste webhooks",
                extra={"request_id": self.request_id, "user_id": user.id},
            )
            raise tornado.web.HTTPError(500, _Messages.INTERNAL_ERROR)

        self.write_json({"success": True, "webhooks": payload})

    @require_role("admin", "user")
    async def post(self, automation_id: str) -> None:
        """Crée un nouveau webhook (owner ou admin, max 5)."""
        user = self.current_user
        assert user is not None

        _check_rate(
            key=f"webhook:mutation:{user.id}",
            max_requests=_MUTATION_RATE_MAX,
            window_seconds=_MUTATION_RATE_WINDOW,
            message=_Messages.RATE_LIMITED_MUTATION,
        )

        aid = self._parse_int_or_400(automation_id, "automation_id")
        body = _parse_body_or_error(self)
        description = _parse_description_or_error(body)

        # Signature HMAC opt-in : ``require_signature: true`` → secret généré
        # côté serveur, retourné UNE SEULE FOIS dans la réponse de création
        # (show-once — jamais relisible via la liste). Défaut False : les
        # intégrations existantes (token-seul) ne cassent pas.
        require_signature = body.get("require_signature", False)
        if not isinstance(require_signature, bool):
            raise tornado.web.HTTPError(400, _Messages.INVALID_FIELD_TYPE)

        try:
            async with self.db_session() as session:
                await _fetch_automation_or_404(
                    session,
                    automation_id=aid,
                    requesting_user_id=user.id,
                    requesting_user_is_admin=user.is_admin,
                )

                count_result = await session.execute(
                    select(func.count())
                    .select_from(WebhookTrigger)
                    .where(WebhookTrigger.automation_id == aid)
                )
                count = count_result.scalar() or 0

                if count >= MAX_WEBHOOKS_PER_AUTOMATION:
                    # 400 (pas 422) : c'est une limite business explicite,
                    # pas une validation de champ. L'UI affiche ce message.
                    self.write_json(
                        {"success": False, "error": _Messages.MAX_WEBHOOKS_REACHED},
                        400,
                    )
                    return

                webhook = WebhookTrigger(
                    automation_id=aid,
                    token=str(uuid.uuid4()),
                    description=description,
                    hmac_secret=(
                        secrets.token_urlsafe(_HMAC_SECRET_BYTES) if require_signature else None
                    ),
                )
                session.add(webhook)
                await session.flush()
                await session.refresh(webhook)

                base_url = _base_url(self)
                # include_secret : show-once à la création uniquement.
                payload = webhook.to_dict(
                    include_url=True, base_url=base_url, include_secret=True
                )
                if require_signature:
                    payload["signature_help"] = (
                        f"Envoyez les en-têtes {_TIMESTAMP_HEADER} (epoch Unix en "
                        f"secondes) et {_SIGNATURE_HEADER} = sha256=HEX où HEX = "
                        "HMAC_SHA256(secret, '{timestamp}.{corps brut}') en "
                        "hexadécimal minuscule. Fenêtre anti-rejeu : "
                        f"{_hmac_tolerance_seconds()} s. Ce secret ne sera plus "
                        "jamais affiché — notez-le maintenant."
                    )
        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.exception(
                "Erreur SQL creation webhook",
                extra={"request_id": self.request_id, "user_id": user.id},
            )
            raise tornado.web.HTTPError(500, _Messages.INTERNAL_ERROR)

        logger.info(
            "webhook created",
            extra={
                "request_id": self.request_id,
                "user_id": user.id,
                "automation_id": aid,
                "webhook_id": payload.get("id"),
            },
        )
        self.write_json({"success": True, "webhook": payload}, 201)


class WebhookDetailAPIHandler(AuthenticatedHandler):
    """``DELETE /api/automations/<id>/webhooks/<wid>`` — suppression."""

    @require_role("admin", "user")
    async def delete(self, automation_id: str, webhook_id: str) -> None:
        """Supprime un webhook (owner ou admin)."""
        user = self.current_user
        assert user is not None

        _check_rate(
            key=f"webhook:mutation:{user.id}",
            max_requests=_MUTATION_RATE_MAX,
            window_seconds=_MUTATION_RATE_WINDOW,
            message=_Messages.RATE_LIMITED_MUTATION,
        )

        aid = self._parse_int_or_400(automation_id, "automation_id")
        wid = self._parse_int_or_400(webhook_id, "webhook_id")

        try:
            async with self.db_session() as session:
                await _fetch_automation_or_404(
                    session,
                    automation_id=aid,
                    requesting_user_id=user.id,
                    requesting_user_is_admin=user.is_admin,
                )
                webhook = await _fetch_webhook_or_404(session, webhook_id=wid, automation_id=aid)
                # Cleanup rate-limit store pour l'ancien token — évite une
                # fuite mémoire sur les webhooks recréés souvent.
                _rate_limiter._requests.pop(webhook.token, None)
                await session.delete(webhook)
        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.exception(
                "Erreur SQL suppression webhook",
                extra={"request_id": self.request_id, "user_id": user.id},
            )
            raise tornado.web.HTTPError(500, _Messages.INTERNAL_ERROR)

        logger.info(
            "webhook deleted",
            extra={
                "request_id": self.request_id,
                "user_id": user.id,
                "automation_id": aid,
                "webhook_id": wid,
            },
        )
        self.write_json({"success": True, "message": _Messages.DELETED})


class WebhookRegenerateAPIHandler(AuthenticatedHandler):
    """``POST /api/automations/<id>/webhooks/<wid>/regenerate`` — rotation."""

    @require_role("admin", "user")
    async def post(self, automation_id: str, webhook_id: str) -> None:
        """Régénère le token — l'ancienne URL est invalidée immédiatement."""
        user = self.current_user
        assert user is not None

        _check_rate(
            key=f"webhook:mutation:{user.id}",
            max_requests=_MUTATION_RATE_MAX,
            window_seconds=_MUTATION_RATE_WINDOW,
            message=_Messages.RATE_LIMITED_MUTATION,
        )

        aid = self._parse_int_or_400(automation_id, "automation_id")
        wid = self._parse_int_or_400(webhook_id, "webhook_id")

        # ``require_signature`` optionnel au body : True = (ré)génère un
        # secret, False = désactive la signature, absent = conserve l'état
        # actuel (un webhook signé reste signé, secret ROTATIONNÉ avec le
        # token — « regenerate » invalide TOUTES les anciennes créances).
        # Compat ascendante : avant 2026-06-12 ce endpoint IGNORAIT le body —
        # un caller legacy qui poste un body non-JSON ne doit pas recevoir
        # 400 (body optionnel ici) ; on le traite comme vide. Le 413
        # (payload trop volumineux) reste levé.
        try:
            body = _parse_body_or_error(self)
        except tornado.web.HTTPError as _body_exc:
            if _body_exc.status_code == 400:
                body = {}
            else:
                raise
        require_signature = body.get("require_signature")
        if require_signature is not None and not isinstance(require_signature, bool):
            raise tornado.web.HTTPError(400, _Messages.INVALID_FIELD_TYPE)

        try:
            async with self.db_session() as session:
                await _fetch_automation_or_404(
                    session,
                    automation_id=aid,
                    requesting_user_id=user.id,
                    requesting_user_is_admin=user.is_admin,
                )
                webhook = await _fetch_webhook_or_404(session, webhook_id=wid, automation_id=aid)

                old_token = webhook.token
                webhook.token = str(uuid.uuid4())
                keep_signature = (
                    require_signature
                    if require_signature is not None
                    else bool(webhook.hmac_secret)
                )
                webhook.hmac_secret = (
                    secrets.token_urlsafe(_HMAC_SECRET_BYTES) if keep_signature else None
                )
                await session.flush()
                await session.refresh(webhook)

                # Retire l'ancien token du rate-limiter (fuite mémoire).
                _rate_limiter._requests.pop(old_token, None)

                base_url = _base_url(self)
                # include_secret : show-once à la rotation (nouveau secret).
                payload = webhook.to_dict(
                    include_url=True, base_url=base_url, include_secret=True
                )
        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.exception(
                "Erreur SQL regeneration webhook",
                extra={"request_id": self.request_id, "user_id": user.id},
            )
            raise tornado.web.HTTPError(500, _Messages.INTERNAL_ERROR)

        logger.info(
            "webhook token rotated",
            extra={
                "request_id": self.request_id,
                "user_id": user.id,
                "automation_id": aid,
                "webhook_id": wid,
            },
        )
        self.write_json(
            {
                "success": True,
                "webhook": payload,
                "message": _Messages.REGENERATED,
            }
        )


# ── Re-exports pour compat tests (suppression progressive) ─────────────────
# Ces alias ne doivent PAS être utilisés dans du nouveau code — référence
# directe au ``RateLimiter`` partagé et aux constantes ``_INBOUND_*``.
__all__ = [
    "MAX_DESCRIPTION_LENGTH",
    "MAX_PAYLOAD_BYTES",
    "MAX_WEBHOOKS_PER_AUTOMATION",
    "WebhookDetailAPIHandler",
    "WebhookInboundHandler",
    "WebhookListAPIHandler",
    "WebhookRegenerateAPIHandler",
    "_INBOUND_RATE_MAX",
    "_INBOUND_RATE_WINDOW",
    "_MUTATION_RATE_MAX",
    "_MUTATION_RATE_WINDOW",
    "_Messages",
    "_RATE_LIMIT_MAX",
    "_RATE_LIMIT_WINDOW",
    "_HMAC_SECRET_BYTES",
    "_HMAC_TOLERANCE_SECONDS_DEFAULT",
    "_SIGNATURE_HEADER",
    "_TIMESTAMP_HEADER",
    "_build_trigger_data",
    "_check_rate_limit",
    "_execute_webhook_automation",
    "_hmac_tolerance_seconds",
    "_verify_webhook_signature",
    "_log_safe",
    "_parse_body_or_error",
    "_parse_description_or_error",
    "_rate_limit_store",
    "_rate_limiter",
    "_spawn_background",
]
