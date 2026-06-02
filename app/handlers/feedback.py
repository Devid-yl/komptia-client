"""Handler ``POST /api/feedback/report`` — rapport d'erreur utilisateur.

Surface
-------
* :class:`FeedbackReportHandler` — endpoint JSON unique.
  - Disponible **anonyme** (la page de login doit pouvoir signaler).
  - XSRF-protégé (Tornado ``xsrf_cookies=True``).
  - **Triple rate-limit** :
    1. Content-Length contrôlé en ``prepare()`` (refus avant lecture body
       — anti DoS mémoire).
    2. Rate-limit par IP en mémoire process (anti-spam basique).
    3. Rate-limit GLOBAL anonyme (anti distributed-spam via N IPs qui
       saturerait le quota Gmail support).

Conventions
-----------
* Pas de leak de la cible (``support_email``) dans la réponse client.
* Aucun ``str(exception)`` au client ; uniquement des messages FR
  centralisés dans :class:`_Messages`.
* Validation centralisée dans :meth:`FeedbackPayload.from_handler_input`.
"""

from __future__ import annotations

import json
import time
from typing import Any, Final, Optional

import tornado.web

from app.handlers.base import BaseHandler
from app.services.feedback import FeedbackPayload, get_feedback_service
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


# ── Limites et anti-abus ─────────────────────────────────────────────────

#: Max requêtes feedback par IP par fenêtre. Resserrée à 2/3600s suite
#: à la review adversariale (avant : 5/300s × N IPs proxy/Tor pouvait
#: spammer le quota Gmail support). Pour un humain qui signale un bug
#: ce quota est largement suffisant (1-2/heure max attendu).
_RATE_LIMIT_COUNT_PER_IP: Final[int] = 2
_RATE_LIMIT_WINDOW_SECONDS: Final[int] = 3600

#: Rate-limit GLOBAL anonyme (toutes IPs confondues) — protège le quota
#: Gmail support contre une attaque distribuée. Au-delà, le service
#: retombe en JSONL fallback only (pas d'envoi mail) — l'admin peut
#: relire les rapports stockés sans saturer la boîte mail.
_GLOBAL_ANON_LIMIT_PER_HOUR: Final[int] = 60
_GLOBAL_ANON_WINDOW_SECONDS: Final[int] = 3600

#: Taille max du body brut accepté. Au-delà → 413, refusé AVANT
#: lecture/parsing JSON (cf. ``prepare()``). Plafond strictement plus
#: petit que le ``max_body_size`` Tornado (60 MiB) — défense en
#: profondeur contre un payload feedback gonflé.
#:
#: Fix #3 review adversariale 2026-05-19 — recalcul après ajout du
#: payload enrichi (network, performance, app_state, localStorage,
#: server_logs). Somme MAX théorique des caps service :
#:   - console_entries : 100 × 2000 ≈ 200 KB
#:   - stack_trace : 8 KB
#:   - network_requests : 50 × 600 ≈ 30 KB
#:   - performance_timing : 30 × 280 ≈ 9 KB
#:   - app_state : 20 × 580 ≈ 12 KB
#:   - localstorage_debug : 30 × 580 ≈ 18 KB
#:   - extras : 20 × 580 ≈ 12 KB
#:   - message : 4 KB
#:   - overhead JSON : 5 KB
#:   - TOTAL ~300 KB
#: Cap à 512 KB pour marge confortable + slack JSON encoding.
_MAX_BODY_BYTES: Final[int] = 512 * 1024


# ── Messages utilisateur centralisés ─────────────────────────────────────


class _Messages:
    SUCCESS_SENT: Final[str] = "Merci, votre signalement a bien été envoyé à l'équipe support."
    SUCCESS_STORED_ONLY: Final[str] = (
        "Merci, votre signalement a été enregistré localement et sera transmis "
        "à l'équipe dès que le serveur de mail sera configuré."
    )
    BAD_JSON: Final[str] = "Le corps de la requête doit être du JSON valide."
    EMPTY_MESSAGE: Final[str] = "Le message ne peut pas être vide."
    PAYLOAD_TOO_LARGE: Final[str] = "Le rapport est trop volumineux. Réduisez son contenu."
    RATE_LIMITED: Final[str] = (
        "Vous avez envoyé trop de signalements récemment. Réessayez dans quelques minutes."
    )
    INTERNAL_ERROR: Final[str] = "Une erreur est survenue. Réessayez plus tard."


# ── Rate limiter par IP (mémoire process — voir reset_feedback_rate_limiter) ─


_rate_limiter: RateLimiter = RateLimiter()


def reset_feedback_rate_limiter() -> None:
    """Recrée le rate limiter par IP. Utilisé par les tests pour repartir
    d'un état propre (l'instance module-level se conserve sinon entre les
    tests qui partagent le process pytest)."""
    global _rate_limiter, _global_anon_counter, _global_anon_window_start
    _rate_limiter = RateLimiter()
    _global_anon_counter = 0
    _global_anon_window_start = time.monotonic()


# ── Rate limiter GLOBAL anonyme (toutes IPs confondues) ─────────────────

_global_anon_counter: int = 0
_global_anon_window_start: float = time.monotonic()


def _is_global_anon_quota_saturated() -> bool:
    """Retourne True si le quota global anonyme est saturé. Met à jour
    le compteur (rolling window) en passant. Process-local — multi-process
    nécessiterait Redis ou la BDD locale.
    """
    global _global_anon_counter, _global_anon_window_start
    now = time.monotonic()
    if (now - _global_anon_window_start) >= _GLOBAL_ANON_WINDOW_SECONDS:
        _global_anon_counter = 0
        _global_anon_window_start = now
    if _global_anon_counter >= _GLOBAL_ANON_LIMIT_PER_HOUR:
        return True
    _global_anon_counter += 1
    return False


# ── Handler ──────────────────────────────────────────────────────────────


class FeedbackReportHandler(BaseHandler):
    """``POST /api/feedback/report`` — soumet un rapport d'erreur."""

    # `check_xsrf_cookie` reste actif (héritage RequestHandler).

    async def prepare(self) -> None:
        """Override : on rejette les payloads trop gros AVANT lecture body.

        Tornado bufferise jusqu'à ``max_body_size`` (60 MiB) avant
        d'invoquer ``post()``. Si on attend ``post()`` pour vérifier la
        taille, on a déjà payé le coût mémoire/CPU. Le check
        ``Content-Length`` ici **est consultatif** (le client peut mentir)
        mais coupe la majorité du trafic abusif tôt.
        """
        await super().prepare()
        try:
            content_length = int(self.request.headers.get("Content-Length") or "0")
        except ValueError:
            content_length = 0
        if content_length > _MAX_BODY_BYTES:
            raise tornado.web.HTTPError(413, _Messages.PAYLOAD_TOO_LARGE)

    async def post(self) -> None:
        # 1. Rate-limit par IP AVANT lecture body (défense en profondeur).
        client_ip = self.request.remote_ip or "unknown"
        if not _rate_limiter.check(
            f"feedback:{client_ip}",
            max_requests=_RATE_LIMIT_COUNT_PER_IP,
            window_seconds=_RATE_LIMIT_WINDOW_SECONDS,
        ):
            logger.warning(
                "Feedback rate-limit IP atteint",
                extra={"ip": client_ip, "request_id": getattr(self, "request_id", "?")},
            )
            self.set_status(429)
            self.set_header("Retry-After", str(_RATE_LIMIT_WINDOW_SECONDS))
            self.write_json(
                {"ok": False, "error": "rate_limited", "message": _Messages.RATE_LIMITED},
                status=429,
            )
            return

        # 2. Plafond local sur le body brut (re-check après prepare()).
        body_bytes = self.request.body or b""
        if len(body_bytes) > _MAX_BODY_BYTES:
            raise tornado.web.HTTPError(413, _Messages.PAYLOAD_TOO_LARGE)

        # 3. Parsing JSON robuste — ne JAMAIS leaker l'exception au client.
        try:
            payload_in: dict[str, Any] = json.loads(body_bytes or b"{}")
            if not isinstance(payload_in, dict):
                raise ValueError("payload root must be an object")
        except (json.JSONDecodeError, ValueError):
            raise tornado.web.HTTPError(400, _Messages.BAD_JSON)

        # 4. Rate-limit GLOBAL anonyme (saturation quota mail)
        # ── Cas anonyme : on consomme le quota global. Si saturé,
        # on bascule en JSONL fallback ONLY (le service écrira sans
        # envoyer mail), sans afficher d'erreur à l'utilisateur (UX
        # douce — son signalement est quand même persisté).
        is_anonymous = self.current_user is None
        force_no_send = False
        if is_anonymous and _is_global_anon_quota_saturated():
            logger.warning(
                "Feedback rate-limit GLOBAL anonyme atteint — bascule JSONL fallback",
                extra={
                    "ip": client_ip,
                    "limit_per_hour": _GLOBAL_ANON_LIMIT_PER_HOUR,
                    "request_id": getattr(self, "request_id", "?"),
                },
            )
            force_no_send = True

        # 5. Capture des attributs ``current_user`` AVANT submit pour
        # éviter MissingGreenlet si la session SQLAlchemy est expirée.
        current_user_id: Optional[int] = None
        current_username: Optional[str] = None
        if self.current_user is not None:
            try:
                current_user_id = int(self.current_user.id)
                current_username = str(self.current_user.username)
            except Exception:  # noqa: BLE001 — defensive, capture les attrs primitifs
                pass

        # 6. Construction du payload validé. Accepte ``captured_at`` du
        # client si fourni (heure réelle de l'erreur côté navigateur).
        client_captured_at = payload_in.get("captured_at")
        try:
            payload = FeedbackPayload.from_handler_input(
                message=str(payload_in.get("message", "")),
                page=payload_in.get("page"),
                user_agent=payload_in.get("user_agent"),
                browser_version=payload_in.get("browser_version"),
                stack_trace=payload_in.get("stack_trace"),
                console_entries=payload_in.get("console_entries") or [],
                extras=payload_in.get("extras") or {},
                client_captured_at=str(client_captured_at) if client_captured_at else None,
                request_id=getattr(self, "request_id", ""),
                client_ip=client_ip,
                user_id=current_user_id,
                username=current_username,
                # Payload enrichi 2026-05-19 — toutes les nouvelles sections
                # passent par ``FeedbackPayload.from_handler_input`` qui applique
                # sanitize + caps anti-DoS + filtre anti-leak credential.
                network_requests=payload_in.get("network_requests") or [],
                performance_timing=payload_in.get("performance_timing") or {},
                app_state=payload_in.get("app_state") or {},
                localstorage_debug=payload_in.get("localstorage_debug") or {},
            )
        except ValueError as exc:
            raise tornado.web.HTTPError(400, str(exc))

        # 7. Délégation au service. Le service ne lève jamais — fail-safe.
        try:
            result = await get_feedback_service().submit(payload, force_no_send=force_no_send)
        except Exception:  # noqa: BLE001 — fail-safe absolu
            logger.exception(
                "FeedbackReportHandler: erreur inattendue",
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            self.write_json(
                {"ok": False, "message": _Messages.INTERNAL_ERROR},
                status=500,
            )
            return

        sent = bool(result.get("sent"))
        stored = bool(result.get("stored"))

        # ADV-M11 : si on n'a NI envoyé ni persisté, c'est un échec —
        # l'utilisateur ne doit pas voir un faux succès.
        if not sent and not stored:
            logger.error(
                "FeedbackReportHandler: ni envoyé ni persisté",
                extra={"request_id": payload.request_id},
            )
            self.write_json(
                {"ok": False, "sent": False, "stored": False, "message": _Messages.INTERNAL_ERROR},
                status=500,
            )
            return

        user_message = _Messages.SUCCESS_SENT if sent else _Messages.SUCCESS_STORED_ONLY

        logger.info(
            "Feedback reçu",
            extra={
                "request_id": payload.request_id,
                "user_id": payload.user_id,
                "sent": sent,
                "stored": stored,
                "page": payload.page,
            },
        )

        self.write_json(
            {
                "ok": True,
                "sent": sent,
                "stored": stored,
                "message": user_message,
            }
        )
