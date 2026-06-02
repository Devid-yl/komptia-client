"""WebSocket de preview d'étapes : ``/ws/automations/(\\d+)/preview``.

Permet à l'utilisateur de cliquer ▶ sur un noeud du DAG dans
``/automations/N/edit`` et de voir le résultat sans quitter la page.

Sécurité (alignée sur ``IrisWebSocketHandler``)
-----------------------------------------------

* **check_origin** : refuse toute origine dont le ``netloc`` ne matche
  pas le ``Host`` de la requête (anti-XSRF WebSocket).
* **Cookie session_token** : validé via ``_load_current_user`` (mêmes
  invariants que les handlers HTTP).
* **XSRF** : ``check_xsrf_cookie`` exigé même sur la WS — Tornado peut
  établir une WS sans préflight, le cookie seul ne suffit pas.
* **Ownership 404** : l'automation est résolue dans ``open()`` ; un
  user non-propriétaire est fermé avec ``_WS_CLOSE_AUTH_REQUIRED`` —
  même code qu'un anonyme pour ne pas leak l'existence de l'ID.
* **Rate-limit** : 10 messages / 60 s par user (cf.
  ``RATE_LIMIT_STEP_PREVIEW``). Le ``cancel`` n'est pas rate-limité
  (mécanisme de sécurité : un user doit toujours pouvoir interrompre).
* **Cancel propre** : ``on_close`` set un ``asyncio.Event`` que le
  service preview consulte entre phases ; les awaits longs sont
  protégés par ``asyncio.wait_for`` du côté service.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Coroutine
from typing import Any, Final, Mapping, Optional
from urllib.parse import urlparse

import tornado.iostream
import tornado.web
import tornado.websocket
from sqlalchemy import select

from app.constants import RATE_LIMIT_STEP_PREVIEW
from app.core.database import get_session_factory
from app.models.automation import Automation
from app.models.user import User
from app.services.automation.preview_service import (
    PreviewError,
    StepPreviewResult,
    get_preview_service,
)
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter
from app.utils.request_context import request_scope

logger = get_logger(__name__)


# ── Codes de fermeture WebSocket (alignés sur iris.py) ───────────────


_WS_CLOSE_AUTH_REQUIRED: Final[int] = 4001
_WS_CLOSE_XSRF_FAILED: Final[int] = 4003
_WS_CLOSE_RATE_LIMITED: Final[int] = 4029  # mnemonic pour 429-like


# ── Rate limiters ─────────────────────────────────────────────────────
# Deux quotas distincts :
# - ``_ws_preview_rate_limiter`` : actions ``preview_step`` (10/min, le
#   user qui itère sur sa config humainement).
# - ``_ws_message_rate_limiter`` : tout message entrant (100/min, garde
#   contre un attaquant qui floode des messages malformés pour saturer
#   la WS — le quota preview ne s'applique que sur action préview).


_ws_preview_rate_limiter = RateLimiter()
_ws_message_rate_limiter = RateLimiter()
_MESSAGE_RATE_LIMIT: Final[tuple[int, int]] = (100, 60)

# Cap dur sur le nombre de fire-and-forget pendings par handler — defense
# en profondeur contre le DoS amplifier (un client qui flood des messages
# malformés générerait sinon 1 task/message dans la limite du rate limiter
# 100/min, multiplié par N onglets = N*100 tasks pendantes contendant
# sur ``_write_lock``). Au-delà du cap, on drop silencieusement la nouvelle
# task error-send (le client a déjà été notifié implicitement par les
# erreurs précédentes, et le rate limiter coupe de toute façon le flood).
_MAX_BACKGROUND_TASKS: Final[int] = 256


# ── Messages utilisateur ─────────────────────────────────────────────


class _Messages:
    INVALID_JSON: Final[str] = "Message JSON invalide."
    UNKNOWN_ACTION: Final[str] = "Action inconnue."
    RATE_LIMITED: Final[str] = "Trop de previews. Patientez quelques secondes avant de réessayer."
    BUSY: Final[str] = "Un preview est déjà en cours sur cette connexion."


# ── Handler ──────────────────────────────────────────────────────────


class AutomationPreviewWebSocketHandler(tornado.websocket.WebSocketHandler):
    """WebSocket de preview d'étape pour ``/ws/automations/(\\d+)/preview``.

    Protocole entrant (JSON) :
        - ``{"action": "preview_step", "step_id": int, "max_rows": int?}``
        - ``{"action": "cancel"}``
        - ``{"action": "ping"}`` (cluster-P heartbeat client)

    Protocole sortant (JSON) :
        - ``{"type": "ready"}`` après ``open()``
        - ``{"type": "preview_start", "step_id": int, "chain": [step_ids]}``
        - ``{"type": "preview_progress", "step_id": int, "phase": str, "message": str}``
        - ``{"type": "preview_step_result", ...StepPreviewResult.to_dict()}``
        - ``{"type": "preview_error", "step_id": int?, "category": str, "message": str}``
        - ``{"type": "preview_complete", "ok": bool}``
        - ``{"type": "pong", "ts": float}`` (cluster-P heartbeat response)
    """

    current_user: Optional[User]
    automation_id: int
    _cancel_event: asyncio.Event
    _running_task: Optional[asyncio.Task[None]]
    _write_lock: asyncio.Lock
    # Cluster-A 2026-05-26 — strong-ref set pour les tasks fire-and-forget.
    # Python 3.12+ GC peut éliminer des tasks référencées seulement par
    # asyncio.ensure_future(). Pattern aligné sur webhooks.py:_background_tasks
    # mais per-handler pour isolation (pas de cross-handler leak).
    _background_tasks: set[asyncio.Task[Any]]

    # ── Lifecycle ────────────────────────────────────────────────

    def check_origin(self, origin: str) -> bool:
        """Whitelist explicite via env var, fail-closed hors dev/test.

        S8 — derrière un reverse-proxy avec X-Forwarded-Host non normalisé,
        comparer ``parsed.netloc == request_host`` peut diverger. La defense
        en profondeur recommande une whitelist explicite via
        ``KOMPTIA_ALLOWED_ORIGINS`` (CSV : ``https://app.komptia.fr,https://komptia.local``).

        Cluster-A 2026-05-26 — fail-closed en non-dev (prod/staging/qa) si la
        whitelist est vide : sans whitelist, le seul garde-fou est le Host
        header qui est forgeable cross-origin. En dev/test on garde le Host
        check comme fallback pour ne pas casser le développement local.
        """
        import os

        parsed = urlparse(origin)
        if not parsed.netloc:
            return False

        # Whitelist explicite via env (recommandé en prod) — path principal.
        # Comparison case-insensitive : RFC 3986 spécifie que scheme et host
        # sont case-insensitive. Un browser envoie l'Origin lowercased mais
        # un client non-browser (curl, ws lib custom) peut envoyer une casse
        # arbitraire. On normalise les deux côtés pour éviter à la fois les
        # faux négatifs (browser legit) et les bypass (attaquant case-fold).
        raw = os.environ.get("KOMPTIA_ALLOWED_ORIGINS", "").strip()
        if raw:
            allowed = {o.strip().rstrip("/").lower() for o in raw.split(",") if o.strip()}
            return origin.rstrip("/").lower() in allowed

        # Aucune whitelist : autorisé UNIQUEMENT en dev/test. Tout autre
        # environnement (production, staging, qa, …) doit fail-closed —
        # l'admin DOIT configurer ``KOMPTIA_ALLOWED_ORIGINS``.
        try:
            from app.config import get_config

            env = (get_config().environment or "").strip().lower()
        except Exception:  # noqa: BLE001 — fail-closed si config indisponible
            logger.critical(
                "WS preview check_origin REFUSED: config unavailable + "
                "KOMPTIA_ALLOWED_ORIGINS empty (origin=%s)",
                origin,
            )
            return False

        if env not in {"development", "dev", "test", "testing"}:
            logger.critical(
                "WS preview check_origin REFUSED: KOMPTIA_ALLOWED_ORIGINS "
                "empty in environment=%s (origin=%s) — set the env var to a "
                "CSV whitelist before going live",
                env or "(empty)",
                origin,
            )
            return False

        # Dev/test : fallback Host check (préserve le comportement existant).
        request_host = self.request.headers.get("Host", "")
        return parsed.netloc == request_host

    async def open(self, automation_id: str) -> None:  # type: ignore[override]
        """Authentifie + valide ownership avant d'accepter la WS."""
        try:
            self.automation_id = int(automation_id)
        except (TypeError, ValueError):
            self.close(_WS_CLOSE_AUTH_REQUIRED, "Bad automation id")
            return

        user = await self._load_current_user()
        if user is None:
            logger.warning("WS preview: connexion sans user authentifié")
            self.close(_WS_CLOSE_AUTH_REQUIRED, "Authentication required")
            return

        try:
            self.check_xsrf_cookie()
        except Exception:  # noqa: BLE001 — Tornado peut lever HTTPError ou Suspicious
            logger.warning("WS preview: XSRF validation failed for user_id=%s", user.id)
            self.close(_WS_CLOSE_XSRF_FAILED, "XSRF validation failed")
            return

        # Ownership : 404-like via fermeture auth-required (pas de leak).
        owned = await self._is_owner(user.id, self.automation_id)
        if not owned:
            logger.warning(
                "WS preview: user %s tente d'accéder à automation %s non-ownée",
                user.id,
                self.automation_id,
            )
            self.close(_WS_CLOSE_AUTH_REQUIRED, "Not found")
            return

        self.current_user = user
        self._cancel_event = asyncio.Event()
        self._running_task = None
        self._write_lock = asyncio.Lock()
        self._background_tasks = set()
        logger.info(
            "WS preview ouvert: user_id=%s, automation_id=%s, ip=%s",
            user.id,
            self.automation_id,
            self.request.remote_ip,
        )
        await self._safe_send({"type": "ready"})

    def on_close(self) -> None:
        cancel_event = getattr(self, "_cancel_event", None)
        if cancel_event is not None:
            cancel_event.set()
        running_task = getattr(self, "_running_task", None)
        if running_task is not None and not running_task.done():
            running_task.cancel()
        # Cluster-A 2026-05-26 — cancel les fire-and-forget pending pour
        # éviter qu'ils tentent un write sur une WS fermée (logged
        # warning sinon dans _safe_send via WebSocketClosedError).
        for task in tuple(getattr(self, "_background_tasks", set())):
            if not task.done():
                task.cancel()
        user_id = getattr(getattr(self, "current_user", None), "id", "?")
        logger.info(
            "WS preview fermé: user_id=%s, automation_id=%s, code=%s",
            user_id,
            getattr(self, "automation_id", "?"),
            self.close_code,
        )

    # ── Auth helpers ─────────────────────────────────────────────

    async def _load_current_user(self) -> Optional[User]:
        """Miroir de ``IrisWebSocketHandler._load_current_user`` — même
        plomberie session_manager pour rester cohérent (single source
        of truth de l'auth WS)."""
        try:
            token_bytes = self.get_secure_cookie("session_token")
            if not token_bytes:
                return None
            token_str = token_bytes.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            logger.warning("WS preview: cookie session_token corrompu")
            return None
        try:
            from app.services.auth.session_manager import get_session_manager

            session_manager = get_session_manager()
            return await session_manager.get_user_from_token(token_str)
        except Exception as exc:  # noqa: BLE001 — fail-safe : anonymous
            logger.warning("WS preview: erreur load user: %s", exc)
            return None

    async def _is_owner(self, user_id: int, automation_id: int) -> bool:
        session_factory = get_session_factory()
        async with session_factory() as session:
            row = await session.execute(
                select(Automation.user_id).where(Automation.id == automation_id)
            )
            owner_id = row.scalar_one_or_none()
        return owner_id is not None and owner_id == user_id

    # ── Rate limit ───────────────────────────────────────────────

    def _is_rate_limited(self) -> bool:
        user_id = getattr(getattr(self, "current_user", None), "id", None)
        if not isinstance(user_id, int):
            return True  # fail-closed
        max_msgs, window = RATE_LIMIT_STEP_PREVIEW
        allowed = _ws_preview_rate_limiter.check(f"step-preview-ws:{user_id}", max_msgs, window)
        return not allowed

    # ── Incoming ─────────────────────────────────────────────────

    def on_message(self, raw_message: str | bytes) -> None:
        # Defense en profondeur : Tornado peut livrer un ``on_message``
        # avant que l'``open`` async n'ait fini son auth + ownership
        # (ex: BDD lente). Sans ce guard on lève AttributeError sur
        # ``_cancel_event`` / ``current_user`` non encore initialisés.
        #
        # Cluster-A 2026-05-26 — on ferme explicitement la WS au lieu
        # de drop silencieux : (a) UX cohérente (le client voit la
        # raison via le code 4001), (b) ferme un canal latent qui
        # pourrait être probe-d par un attaquant pour timing oracle.
        if (
            getattr(self, "current_user", None) is None
            or getattr(self, "_cancel_event", None) is None
        ):
            logger.warning(
                "WS preview: message received before open() completed (auto=%s)",
                getattr(self, "automation_id", "?"),
            )
            try:
                self.close(_WS_CLOSE_AUTH_REQUIRED, "Auth not ready")
            except Exception:  # noqa: BLE001 — close peut lever si déjà fermée
                pass
            return
        # Rate-limit message-level (anti-flood JSON invalides). Quota
        # plus permissif que ``preview_step`` (100/min vs 10/min) —
        # objectif : éviter qu'un attaquant sature la WS sans pénaliser
        # un usage légitime.
        user_id = self.current_user.id  # type: ignore[union-attr]
        if not _ws_message_rate_limiter.check(
            f"step-preview-msg:{user_id}",
            _MESSAGE_RATE_LIMIT[0],
            _MESSAGE_RATE_LIMIT[1],
        ):
            # Pas d'envoi d'erreur (qui amplifierait le DoS). On drop
            # silencieusement le message.
            return
        try:
            text = (
                raw_message.decode("utf-8")
                if isinstance(raw_message, (bytes, bytearray))
                else raw_message
            )
            payload = json.loads(text)
        except (ValueError, UnicodeDecodeError):
            self._schedule_background(self._safe_send_error(_Messages.INVALID_JSON))
            return
        if not isinstance(payload, Mapping):
            self._schedule_background(self._safe_send_error(_Messages.INVALID_JSON))
            return

        action = payload.get("action")

        if action == "cancel":
            # ``cancel`` n'est jamais rate-limité : c'est un mécanisme de
            # sécurité (un user doit toujours pouvoir stopper un preview
            # qu'il a lancé par erreur).
            self._cancel_event.set()
            running = self._running_task
            if running is not None and not running.done():
                running.cancel()
            return

        if action == "ping":
            # Cluster-P 2026-05-26 — Heartbeat client → réponse pong.
            # Pas de rate-limit (le quota générique de la WS suffit, 100/min
            # >> les 2-3 pings/min d'un client normal qui ping toutes les 25s).
            # Évite que proxies (ALB/Nginx default 60s idle timeout) coupent
            # silencieusement la WS pendant un preview long ou un edit
            # statique. Le client mesure aussi le délai pong pour détecter
            # un WS zombie (TCP ouvert mais proxy a fermé sa moitié).
            import time as _time

            self._schedule_background(
                self._safe_send({"type": "pong", "ts": _time.time()})
            )
            return

        if action != "preview_step":
            self._schedule_background(self._safe_send_error(_Messages.UNKNOWN_ACTION))
            return

        if self._is_rate_limited():
            self._schedule_background(self._safe_send_error(_Messages.RATE_LIMITED))
            return

        # Concurrence : un seul preview à la fois par WS. Si un preview
        # tourne déjà, on cancel d'abord puis on enchaîne.
        if self._running_task is not None and not self._running_task.done():
            self._cancel_event.set()
            self._running_task.cancel()

        self._cancel_event = asyncio.Event()  # reset pour le nouveau run
        self._running_task = asyncio.ensure_future(self._run_preview(payload))
        # Cluster-A 2026-05-26 — done_callback pour log les exceptions
        # qui crashent _run_preview avant le 1er await ou en dehors du try
        # interne. Sans ça, asyncio loggue "Task exception was never
        # retrieved" au GC, pollution + bypass de l'UX client.
        self._running_task.add_done_callback(self._log_unhandled_run_exception)

    # ── Run preview ──────────────────────────────────────────────

    async def _run_preview(self, payload: Mapping[str, Any]) -> None:
        # Pose le ``request_scope`` (user_id + request_id) pour que les
        # appels LLM déclenchés par le preview (ex. step ``format_copilot``,
        # etc.) soient correctement attribués dans
        # ``ai_performance_logs.user_id``. Comme ``IrisWebSocketHandler``,
        # ce handler étend directement ``WebSocketHandler`` (pas
        # ``BaseHandler``) → ``set_request_context()`` n'est jamais appelé
        # automatiquement, donc sans ce scope le tracker LLM voit un
        # ``current_user_id() == None`` et la consommation est attribuée
        # à "Système" au lieu du user qui a cliqué ▶.
        scope_user_id = getattr(self.current_user, "id", None)
        scope_request_id = f"automation-preview-ws-{uuid.uuid4().hex[:12]}"
        with request_scope(
            request_id=scope_request_id,
            user_id=scope_user_id,
        ):
            await self._run_preview_impl(payload)

    async def _run_preview_impl(self, payload: Mapping[str, Any]) -> None:
        try:
            step_id_raw = payload.get("step_id")
            try:
                step_id = int(step_id_raw)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                await self._safe_send_error(
                    "step_id invalide.",
                    step_id=step_id_raw if isinstance(step_id_raw, int) else None,
                )
                return
            max_rows_raw = payload.get("max_rows")
            try:
                max_rows = int(max_rows_raw) if max_rows_raw is not None else None
            except (TypeError, ValueError):
                max_rows = None
            if isinstance(max_rows, int) and (max_rows < 1 or max_rows > 1000):
                # Bornes défensives : 1 minimum (utile pour smoke-test),
                # 1000 max (au-delà ce n'est plus un preview, c'est un run).
                max_rows = None

            await self._safe_send({"type": "preview_start", "step_id": step_id})

            service = get_preview_service()
            try:
                result: StepPreviewResult = await service.preview_step(
                    user_id=self.current_user.id,  # type: ignore[union-attr]
                    automation_id=self.automation_id,
                    step_id=step_id,
                    max_rows=max_rows,
                    on_progress=self._on_progress,
                    cancel_event=self._cancel_event,
                )
            except PreviewError as exc:
                # Cluster-A 2026-05-26 — identity check appliqué uniformément
                # aux 3 branches d'exception (PreviewError, CancelledError,
                # Exception) pour éviter que la task obsolète n'émette des
                # messages erreur sur un nouveau flow client déjà initié.
                if self._is_current_running_task():
                    await self._send_preview_failure(
                        step_id=step_id,
                        category=exc.category,
                        message=str(exc),
                    )
                return
            except asyncio.CancelledError:
                if self._is_current_running_task():
                    await self._send_preview_failure(
                        step_id=step_id,
                        category="cancelled",
                        message="Preview annulé.",
                    )
                return
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:  # noqa: BLE001
                logger.error(
                    "WS preview: crash service preview_step (user=%s auto=%s step=%s)",
                    getattr(self.current_user, "id", "?"),
                    self.automation_id,
                    step_id,
                    exc_info=True,
                )
                if self._is_current_running_task():
                    await self._send_preview_failure(
                        step_id=step_id,
                        category="internal",
                        message="Erreur interne. L'incident a été enregistré.",
                    )
                return

            await self._safe_send({"type": "preview_step_result", **result.to_dict()})
            await self._safe_send({"type": "preview_complete", "step_id": step_id, "ok": True})
        finally:
            # Race-safe : ne pas écraser ``_running_task`` si un nouveau
            # preview a déjà été démarré entre-temps (l'``on_message``
            # suivant a remplacé ``self._running_task`` par sa propre
            # task). On compare l'identité avant de poser ``None``.
            try:
                current = asyncio.current_task()
            except RuntimeError:
                current = None
            if current is None or self._running_task is current:
                self._running_task = None

    async def _on_progress(self, step_id: int, phase: str, message: str) -> None:
        await self._safe_send(
            {
                "type": "preview_progress",
                "step_id": step_id,
                "phase": phase,
                "message": message,
            }
        )

    # ── Send helpers (sérialisés sur ``_write_lock``) ────────────

    async def _safe_send(self, payload: Mapping[str, Any]) -> None:
        try:
            data = json.dumps(payload, default=str)
        except (TypeError, ValueError):
            logger.error("WS preview: payload non-sérialisable: %r", payload)
            return
        async with self._write_lock:
            try:
                self.write_message(data)
            except (
                tornado.websocket.WebSocketClosedError,
                tornado.iostream.StreamClosedError,
            ):
                # WS fermée pendant l'envoi — pas grave, on log info.
                # Cluster-A 2026-05-26 — `StreamClosedError` peut être levé
                # par `write_message` post-close (en plus de WebSocketClosedError)
                # selon le timing du disconnect, et générait sinon des
                # tracebacks bruyants au shutdown / client disconnect mid-flight.
                logger.info(
                    "WS preview: ferme pendant write (user=%s auto=%s)",
                    getattr(self.current_user, "id", "?"),
                    getattr(self, "automation_id", "?"),
                )

    async def _safe_send_error(self, message: str, *, step_id: Optional[int] = None) -> None:
        payload: dict = {
            "type": "preview_error",
            "category": "client",
            "message": message,
        }
        if step_id is not None:
            payload["step_id"] = step_id
        await self._safe_send(payload)

    # ── Helpers internes : send_failure, identity, task tracking ──

    async def _send_preview_failure(
        self, *, step_id: int, category: str, message: str
    ) -> None:
        """Émet la paire ``preview_error + preview_complete(ok=False)``.

        Centralisé pour éviter la duplication entre les 3 branches d'exception
        de ``_run_preview_impl`` (PreviewError, CancelledError, Exception).
        Une seule source de vérité pour le format wire.
        """
        await self._safe_send(
            {
                "type": "preview_error",
                "step_id": step_id,
                "category": category,
                "message": message,
            }
        )
        await self._safe_send(
            {"type": "preview_complete", "step_id": step_id, "ok": False}
        )

    def _is_current_running_task(self) -> bool:
        """True si la task qui appelle est encore ``self._running_task``.

        Cluster-A 2026-05-26 — utilisé par les 3 branches d'exception de
        ``_run_preview_impl`` pour ne PAS émettre de messages obsolètes
        quand un nouveau preview a remplacé l'ancienne task entre-temps.
        ``asyncio.current_task()`` peut lever ``RuntimeError`` (event loop
        absent) — dans ce cas on retourne False (fail-safe : ne pas émettre).
        """
        try:
            current = asyncio.current_task()
        except RuntimeError:
            return False
        return current is not None and self._running_task is current

    def _log_unhandled_run_exception(self, task: asyncio.Task[Any]) -> None:
        """Done-callback pour ``self._running_task`` — log les exceptions
        non-attrapées par ``_run_preview_impl`` (ex. crash avant le 1er
        await dans ``_run_preview``, import error sur ``request_scope``).
        Sans ce callback, asyncio rapporte "Task exception was never
        retrieved" au GC, polluant les logs et bypassant l'UX client.
        """
        if task.cancelled():
            return
        try:
            exc = task.exception()
        except (asyncio.CancelledError, asyncio.InvalidStateError):
            return
        if exc is not None:
            logger.error(
                "WS preview: unhandled exception in _run_preview task "
                "(user=%s auto=%s): %r",
                getattr(self.current_user, "id", "?"),
                getattr(self, "automation_id", "?"),
                exc,
                exc_info=(type(exc), exc, exc.__traceback__),
            )

    def _schedule_background(
        self, coro: Coroutine[Any, Any, Any]
    ) -> Optional[asyncio.Task[Any]]:
        """Crée une task fire-and-forget avec strong-ref tracking + cap.

        Cluster-A 2026-05-26 — ``asyncio.ensure_future(coro)`` sans
        référence laisse le GC Python 3.12+ supprimer la tâche avant
        son exécution (les erreurs de validation envoyées au client
        ne partaient parfois pas). On la stocke dans
        ``self._background_tasks`` jusqu'à completion. Pattern aligné
        sur ``app/handlers/webhooks.py:_background_tasks`` mais
        per-handler (pas module-level) pour deux raisons : (1) isolation,
        (2) ``on_close`` peut cancel les pendings de CE handler.

        Cap dur ``_MAX_BACKGROUND_TASKS`` : defense en profondeur contre
        un flood de messages malformés qui sinon ferait croître le set
        proportionnellement au rate-limit (100/min) × nb d'onglets.
        Au-delà du cap, on drop la coroutine en la fermant proprement
        et on retourne ``None`` — pas d'amplification DoS.
        """
        if not hasattr(self, "_background_tasks") or self._background_tasks is None:
            # Defensive : si on_message est appelée AVANT open() (cas
            # qui ferme la WS via fix-2 mais ce schedule pourrait
            # arriver depuis ailleurs), on init lazy le set.
            self._background_tasks = set()
        if len(self._background_tasks) >= _MAX_BACKGROUND_TASKS:
            # Fermer la coroutine sans l'awaiter pour éviter un
            # RuntimeWarning "never awaited".
            coro.close()
            logger.warning(
                "WS preview: background task cap reached (%d), dropping "
                "(user=%s auto=%s)",
                _MAX_BACKGROUND_TASKS,
                getattr(self.current_user, "id", "?"),
                getattr(self, "automation_id", "?"),
            )
            return None
        task = asyncio.ensure_future(coro)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return task
