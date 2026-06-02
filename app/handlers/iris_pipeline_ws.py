"""WebSocket pipeline NL→SQL : ``/ws/iris/pipeline``.

Permet à l'agent SQL d'Iris (et au panneau frontend dédié) de :

- **start** un nouveau ``PipelineRun`` à partir d'une requête NL.
- **subscribe** à un run existant pour suivre sa progression (multi-onglets).
- **cancel** un run actif.
- **pause / resume** (snapshot intermédiaire — implémentation Lot ultérieur).
- **ask_user_response** : résoudre une question Q/A pendante (Phase 1.2.5,
  1.2.6, 3 — ``AskUserBridge``).

(``goto_phase`` n'est PAS exposé pour l'instant — l'infrastructure BDD
est en place via ``is_superseded`` mais le call-site backend est volontairement
absent pour ne pas faire de promesse creuse au LLM/UI. À implémenter
quand le besoin est confirmé.)

Sécurité (alignée sur ``IrisWebSocketHandler`` et
``AutomationPreviewWebSocketHandler``) :

- ``check_origin`` : refuse toute origine dont le ``netloc`` ne matche pas
  le ``Host`` (anti-XSRF WebSocket).
- Cookie ``session_token`` validé via ``_load_current_user``.
- ``check_xsrf_cookie()`` exigé même sur la WS.
- Isolation par ``user_id`` : un user ne peut subscribe / cancel / inspecter
  que ses propres runs (404-like si tentative cross-user).
- Rate-limit start : 5 / 60s (la pipeline coûte cher en LLM tokens).
- Rate-limit message : 200 / 60s (anti-flood générique).
- Cancel non rate-limited (mécanisme de sécurité — un user doit toujours
  pouvoir interrompre).
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Final, Optional
from urllib.parse import urlparse

import tornado.web
import tornado.websocket

from app.core.database import get_session_factory
from app.models.pipeline_run import (
    PipelineMode,
    PipelineRun,
    TriggeredVia,
)
from app.models.user import User
from app.services.ai.pipeline_event_bus import get_event_bus
from app.services.ai.pipeline_runner import (
    QuotaExceededError,
    cancel_run as runner_cancel_run,
    get_runner,
    start_pipeline_run,
)
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter
from app.utils.request_context import request_scope

logger = get_logger(__name__)

# Strong-refs des tasks de cleanup fire-and-forget créées dans on_close. Sans
# ça, Python 3.12+ (asyncio ne garde qu'une WeakSet des tasks) peut GC la task
# AVANT son exécution → unsubscribe du bus + grace-cancel silencieusement
# sautés (abonnement WS / run qui fuit). Le handler étant en teardown au moment
# du on_close, la ref ne peut PAS vivre sur l'instance → set module-level.
# Cf. mémoire feedback_asyncio_create_task_strong_ref + pattern _audit_tasks.
_pipeline_ws_cleanup_tasks: set = set()


# ── Codes de fermeture WebSocket ───────────────────────────────────

_WS_CLOSE_AUTH_REQUIRED: Final[int] = 4001
_WS_CLOSE_XSRF_FAILED: Final[int] = 4003
_WS_CLOSE_RATE_LIMITED: Final[int] = 4029


# ── Rate limiters ──────────────────────────────────────────────────

_ws_start_rate_limiter = RateLimiter()
_ws_message_rate_limiter = RateLimiter()
_START_RATE_LIMIT: Final[tuple[int, int]] = (5, 60)
_MESSAGE_RATE_LIMIT: Final[tuple[int, int]] = (200, 60)


# ── Ownership cache court (fix #18 review adv) ─────────────────────
# Évite la requête SQL répétée à chaque action WS pour vérifier qu'un
# run appartient bien au user. TTL court (30s) — un run change rarement
# de propriétaire, et la session WS dure typiquement quelques minutes.

import time as _time

_OWNERSHIP_CACHE: dict[tuple[int, int], tuple[bool, float]] = {}
_OWNERSHIP_CACHE_TTL = 30.0
# A6-F1 (axe 21 — croissance non bornée) : la purge ci-dessous est PARESSEUSE
# (elle ne retire que la clé qu'on relit). Un run relu une seule fois puis
# jamais (user déconnecté, run unique) laisse son entrée jusqu'à expiration
# logique MAIS sans jamais être physiquement retirée → fuite mémoire lente sur
# une instance long-running qui voit beaucoup de runs. On borne par deux
# mécanismes : (1) un sweep throttlé des entrées expirées à chaque écriture,
# (2) un cap dur avec éviction des plus anciennes. Le cache est un PUR
# optimiseur — sa source d'autorité reste la requête SQL d'ownership, donc
# évincer/vider est toujours sûr (jamais de donnée fausse).
_OWNERSHIP_CACHE_MAX: Final[int] = 10_000
_OWNERSHIP_CACHE_SWEEP_INTERVAL: Final[float] = 60.0
_ownership_last_sweep: float = 0.0


def _ownership_cache_get(user_id: int, run_id: int) -> Optional[bool]:
    entry = _OWNERSHIP_CACHE.get((user_id, run_id))
    if entry is None:
        return None
    is_owner, expires_at = entry
    if _time.monotonic() > expires_at:
        _OWNERSHIP_CACHE.pop((user_id, run_id), None)
        return None
    return is_owner


def _ownership_cache_set(user_id: int, run_id: int, is_owner: bool) -> None:
    global _ownership_last_sweep
    now = _time.monotonic()

    # (1) Sweep throttlé des entrées expirées — borne la croissance même quand
    # les clés ne sont jamais relues (sinon elles ne seraient jamais retirées).
    if now - _ownership_last_sweep > _OWNERSHIP_CACHE_SWEEP_INTERVAL:
        _ownership_last_sweep = now
        for key in [k for k, (_, exp) in _OWNERSHIP_CACHE.items() if now > exp]:
            _OWNERSHIP_CACHE.pop(key, None)

    # (2) Cap dur : si encore plein après sweep (afflux massif sous l'intervalle),
    # évince ~50 % des entrées par ordre d'INSERTION. NB : un re-set d'une clé
    # existante NE la déplace PAS en fin de dict (sémantique Python) — donc
    # « ordre d'insertion » ≠ strictement « ordre d'expiration » pour les clés
    # ré-écrites. Évincer une entrée encore fraîche est sans conséquence : le
    # cache est un PUR optimiseur (autorité = requête SQL d'ownership), le seul
    # coût est un cache-miss → une requête SQL de plus. Jamais de donnée fausse.
    if len(_OWNERSHIP_CACHE) >= _OWNERSHIP_CACHE_MAX:
        for key in list(_OWNERSHIP_CACHE.keys())[: _OWNERSHIP_CACHE_MAX // 2]:
            _OWNERSHIP_CACHE.pop(key, None)

    _OWNERSHIP_CACHE[(user_id, run_id)] = (is_owner, now + _OWNERSHIP_CACHE_TTL)


# ── Messages utilisateur ───────────────────────────────────────────


class _Messages:
    INVALID_JSON: Final[str] = "Message JSON invalide."
    UNKNOWN_ACTION: Final[str] = "Action inconnue."
    RATE_LIMITED_START: Final[str] = (
        "Trop de runs lancés récemment. Patiente avant d'en démarrer un nouveau."
    )
    NOT_OWNER: Final[str] = "Run inaccessible."
    NOT_FOUND: Final[str] = "Run introuvable."


# BLOCKING #1 review pipeline retiré : ``_VALID_PHASES`` était une 3ᵉ
# source de vérité non utilisée (code mort). Tout consommateur lisant les
# phase_id valides doit importer ``PHASE_LABELS`` depuis pipeline_runner.


class IrisPipelineWebSocketHandler(tornado.websocket.WebSocketHandler):
    """WebSocket pour la supervision pipeline NL→SQL.

    Protocole entrant (JSON) :
        - ``{"action": "start", "query_nl": str, "mode": "ir"|"legacy"?,
              "block_all_views": bool?, "use_sage": bool?,
              "conversation_id": int?}``
        - ``{"action": "subscribe", "run_id": int}``
        - ``{"action": "unsubscribe", "run_id": int}``
        - ``{"action": "cancel", "run_id": int}``
        - ``{"action": "ask_user_response", "run_id": int, "ask_id": str,
              "response": str}``

    Protocole sortant : voir ``pipeline_runner._make_progress_callback``
    + events de ce handler (``ready``, ``error``, ``rate_limited``).
    """

    current_user: Optional[User]
    _subscriber_id: str
    _subscribed_runs: set[int]
    _write_lock: asyncio.Lock

    # ── Lifecycle ──────────────────────────────────────────────────

    def initialize(self) -> None:
        """Pose les attributs aux valeurs par défaut.

        Tornado appelle ``initialize()`` AVANT ``open()`` à chaque connexion.
        Sans ça, si ``on_close()`` est appelé avant ``open()`` (cas rare —
        XSRF refusé pendant ``open``), les attributs ne sont pas définis
        et ``getattr(self, "_subscribed_runs", set())`` était la seule
        protection. Fix #27 review adversariale.
        """

        self.current_user = None
        self._subscriber_id = ""
        self._subscribed_runs = set()
        self._write_lock = asyncio.Lock()

    def check_origin(self, origin: str) -> bool:
        """Host check (parité avec IrisWebSocketHandler)."""

        try:
            parsed = urlparse(origin)
        except Exception:  # noqa: BLE001
            return False
        request_host = self.request.headers.get("Host", "")
        if not request_host:
            return False
        return parsed.netloc == request_host

    async def open(self) -> None:  # type: ignore[override]
        try:
            self.check_xsrf_cookie()
        except tornado.web.HTTPError:
            self.close(_WS_CLOSE_XSRF_FAILED, "XSRF token manquant ou invalide.")
            return

        user = await self._load_current_user()
        if user is None:
            self.close(_WS_CLOSE_AUTH_REQUIRED, "Authentification requise.")
            return

        self.current_user = user
        self._subscriber_id = uuid.uuid4().hex
        self._subscribed_runs = set()
        self._write_lock = asyncio.Lock()

        await self._safe_send({"type": "ready", "subscriber_id": self._subscriber_id})

    def on_close(self) -> None:
        # Désabonner de tous les runs sans bloquer la coroutine ``on_close``
        # (Tornado l'appelle en sync — fire-and-forget les unsubscribes).
        runs = list(getattr(self, "_subscribed_runs", set()))
        if not runs:
            return
        get_event_bus()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # Loop arrêté (shutdown) → impossible de cleanup, log et accepte
            # la fuite mémoire ponctuelle (le close_channel après run terminal
            # finira de toute façon par libérer).
            logger.warning(
                "IrisPipelineWS.on_close: no running loop, skipping unsubscribe (subs=%s)",
                runs,
            )
            return
        for run_id in runs:
            try:
                task = loop.create_task(self._unsubscribe_and_maybe_grace(run_id))
                _pipeline_ws_cleanup_tasks.add(task)
                task.add_done_callback(_pipeline_ws_cleanup_tasks.discard)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "IrisPipelineWS.on_close: create_task failed (run=%s)",
                    run_id,
                )

    async def _unsubscribe_and_maybe_grace(self, run_id: int) -> None:
        """Désabonne ce handler, et si plus aucun subscriber → grace cancel.

        Le grace de 60s permet à l'user de refresh sans perdre son run.
        Si personne ne resubscribe, le runner cancel pour ne pas brûler
        des tokens LLM dans le vide.
        """

        bus = get_event_bus()
        await bus.unsubscribe(run_id, self._subscriber_id)
        # Plus aucun subscriber actif sur ce run → grace cancel
        if not await bus.has_subscribers(run_id):
            user_id = getattr(self.current_user, "id", None)
            if isinstance(user_id, int) and user_id > 0:
                runner = await get_runner(run_id, user_id)
                if runner is not None:
                    await runner.schedule_grace_cancel(grace_seconds=60.0)

    # ── Dispatch ──────────────────────────────────────────────────

    async def on_message(self, raw_msg: str | bytes) -> None:  # type: ignore[override]
        # Rate-limit générique anti-flood
        user_id = getattr(self.current_user, "id", None)
        if user_id is None:
            await self._safe_send({"type": "error", "message": "Session expirée."})
            return
        if not _ws_message_rate_limiter.check(f"pipeline_ws_msg:{user_id}", *_MESSAGE_RATE_LIMIT):
            await self._safe_send({"type": "rate_limited", "message": "Trop de messages."})
            return

        try:
            payload = json.loads(raw_msg)
        except (json.JSONDecodeError, TypeError, ValueError):
            await self._safe_send({"type": "error", "message": _Messages.INVALID_JSON})
            return

        if not isinstance(payload, dict):
            await self._safe_send({"type": "error", "message": _Messages.INVALID_JSON})
            return

        action = payload.get("action")
        try:
            if action == "start":
                await self._action_start(payload)
            elif action == "subscribe":
                await self._action_subscribe(payload)
            elif action == "unsubscribe":
                await self._action_unsubscribe(payload)
            elif action == "cancel":
                await self._action_cancel(payload)
            elif action == "ask_user_response":
                await self._action_ask_user_response(payload)
            else:
                await self._safe_send({"type": "error", "message": _Messages.UNKNOWN_ACTION})
        except Exception:  # noqa: BLE001
            logger.exception("IrisPipelineWS: action %r raised", action)
            await self._safe_send(
                {"type": "error", "message": "Erreur interne — voir logs serveur."}
            )

    # ── Actions ───────────────────────────────────────────────────

    async def _action_start(self, payload: dict) -> None:
        user_id = self.current_user.id  # type: ignore[union-attr]
        if not _ws_start_rate_limiter.check(f"pipeline_ws_start:{user_id}", *_START_RATE_LIMIT):
            await self._safe_send({"type": "rate_limited", "message": _Messages.RATE_LIMITED_START})
            return

        query_nl = (payload.get("query_nl") or "").strip()
        if not query_nl or len(query_nl) > 5000:
            await self._safe_send(
                {
                    "type": "error",
                    "message": ("query_nl requis (1 à 5000 caractères)."),
                }
            )
            return

        mode_raw = (payload.get("mode") or "ir").strip().lower()
        try:
            mode = PipelineMode(mode_raw)
        except ValueError:
            await self._safe_send({"type": "error", "message": f"Mode invalide '{mode_raw}'."})
            return

        # task #82 — défaut False : vues incluses dans le shortlist Phase 1.5.
        block_all_views = bool(payload.get("block_all_views", False))
        use_sage = bool(payload.get("use_sage", True))
        conversation_id_raw = payload.get("conversation_id")
        conversation_id: Optional[int] = None
        if isinstance(conversation_id_raw, int) and conversation_id_raw > 0:
            conversation_id = conversation_id_raw

        request_id = f"iris-pipeline-ws-{uuid.uuid4().hex[:12]}"
        with request_scope(request_id=request_id, user_id=user_id):
            try:
                run = await start_pipeline_run(
                    user_id=user_id,
                    query_nl=query_nl,
                    mode=mode,
                    block_all_views=block_all_views,
                    use_sage=use_sage,
                    conversation_id=conversation_id,
                    triggered_via=TriggeredVia.IRIS_PANEL,
                    request_id=request_id,
                )
            except QuotaExceededError as exc:
                await self._safe_send(
                    {
                        "type": "rate_limited",
                        "message": (f"Quota journalier atteint ({exc.limit} runs/24h)."),
                    }
                )
                return
            except FileExistsError:
                await self._safe_send(
                    {
                        "type": "error",
                        "message": ("Conflit interne : output_dir collision. Réessaie."),
                    }
                )
                return
            except Exception as exc:  # noqa: BLE001
                logger.exception("IrisPipelineWS: start_pipeline_run failed")
                # P6 SÉCURITÉ (audit 2026-05-26) — idem iris_pipeline_api :
                # avant ``f"Échec démarrage : {exc}"`` leakait raw exception.
                # Helper SSoT P2.1 (audience="user") catégorise + sanitize.
                from app.services.data_access.error_messages import (
                    sanitize_sql_for_client,
                )

                _payload = await sanitize_sql_for_client(
                    exc, self.current_user, audience="user"
                )
                await self._safe_send(
                    {
                        "type": "error",
                        "message": "Échec démarrage : " + _payload["message"],
                        "category": _payload["category"],
                    }
                )
                return

        # Auto-subscribe sur le run créé
        await self._do_subscribe(run.id, send_acknowledge=False)
        await self._safe_send(
            {
                "type": "pipeline_run_created",
                "run_id": run.id,
                "status": run.status.value,
                "query_nl": query_nl,
            }
        )

    async def _action_subscribe(self, payload: dict) -> None:
        run_id = payload.get("run_id")
        if not isinstance(run_id, int):
            await self._safe_send({"type": "error", "message": "run_id requis (int)."})
            return
        if not await self._verify_ownership(run_id):
            await self._safe_send({"type": "error", "message": _Messages.NOT_FOUND})
            return
        await self._do_subscribe(run_id)

    async def _do_subscribe(self, run_id: int, *, send_acknowledge: bool = True) -> None:
        bus = get_event_bus()
        await bus.subscribe(run_id, self._subscriber_id, self._make_event_callback(run_id))
        self._subscribed_runs.add(run_id)
        # Si un grace_cancel était programmé après un refresh accidentel,
        # l'annuler — le user est revenu à temps. Le run continue.
        # Ownership check via get_runner(user_id) : un user qui subscribe
        # à un run d'un autre n'a pas le droit d'aborter son grace cancel.
        user_id = self.current_user.id  # type: ignore[union-attr]
        runner = await get_runner(run_id, user_id)
        if runner is not None:
            runner.abort_grace_cancel()
        if send_acknowledge:
            await self._safe_send({"type": "subscribed", "run_id": run_id})

    async def _action_unsubscribe(self, payload: dict) -> None:
        run_id = payload.get("run_id")
        if not isinstance(run_id, int):
            return
        bus = get_event_bus()
        await bus.unsubscribe(run_id, self._subscriber_id)
        self._subscribed_runs.discard(run_id)
        await self._safe_send({"type": "unsubscribed", "run_id": run_id})

    async def _action_cancel(self, payload: dict) -> None:
        run_id = payload.get("run_id")
        if not isinstance(run_id, int):
            await self._safe_send({"type": "error", "message": "run_id requis (int)."})
            return
        if not await self._verify_ownership(run_id):
            await self._safe_send({"type": "error", "message": _Messages.NOT_FOUND})
            return
        ok = await runner_cancel_run(run_id, by_user_id=self.current_user.id)  # type: ignore[union-attr]
        await self._safe_send({"type": "cancel_acknowledged", "run_id": run_id, "ok": ok})

    # Cap longueur réponse ask_user — défense en profondeur contre payload
    # géant (DoS asymétrique faible). Une vraie réponse à un Q/A pipeline
    # est typiquement <50 chars ("oui", "Option 2", "ENTITE_X"). Au-delà
    # de 2 KB, c'est probablement un bug client ou un abus.
    _ASK_RESPONSE_MAX_CHARS = 2048

    async def _action_ask_user_response(self, payload: dict) -> None:
        run_id = payload.get("run_id")
        ask_id = (payload.get("ask_id") or "").strip()
        response = payload.get("response")
        if not isinstance(run_id, int) or not ask_id or response is None:
            await self._safe_send(
                {
                    "type": "error",
                    "message": "Paramètres : run_id (int), ask_id (str), response (str).",
                }
            )
            return
        # Cap longueur — applicable à `response` après str() pour ne pas
        # laisser passer un payload géant via un type non-string.
        response_str = str(response)
        if len(response_str) > self._ASK_RESPONSE_MAX_CHARS:
            await self._safe_send(
                {
                    "type": "error",
                    "message": (f"Réponse trop longue (max {self._ASK_RESPONSE_MAX_CHARS} chars)."),
                }
            )
            return
        if not await self._verify_ownership(run_id):
            await self._safe_send({"type": "error", "message": _Messages.NOT_FOUND})
            return

        runner = await get_runner(run_id, self.current_user.id)  # type: ignore[union-attr]
        if runner is None:
            await self._safe_send(
                {
                    "type": "error",
                    "message": ("Run pas actif sur ce serveur (peut-être terminé entre temps)."),
                }
            )
            return
        ok = await runner.ask_user_bridge.submit_response(ask_id, response_str)
        await self._safe_send(
            {"type": "ask_user_acknowledged", "run_id": run_id, "ask_id": ask_id, "ok": ok}
        )

    # ── Helpers ──────────────────────────────────────────────────

    def _make_event_callback(self, run_id: int):
        async def _cb(event: dict) -> None:
            # Enrichit chaque event sortant avec le run_id (le bus le porte
            # déjà côté serveur, mais le client multi-runs en a besoin).
            payload = {**event, "run_id": run_id}
            await self._safe_send(payload)

        return _cb

    async def _verify_ownership(self, run_id: int) -> bool:
        """Vérifie que ``run_id`` appartient au user courant.

        Retourne False si run inexistant OU pas owner (anti-leak existence).
        Cache TTL 30s (fix #18) — un run change rarement de propriétaire,
        évite N+1 selects dans les sessions WS multi-actions.
        """

        user_id = getattr(self.current_user, "id", None)
        if user_id is None:
            return False
        cached = _ownership_cache_get(user_id, run_id)
        if cached is not None:
            return cached
        async with get_session_factory()() as session:
            run = await session.get(PipelineRun, run_id)
            is_owner = run is not None and run.user_id == user_id
        _ownership_cache_set(user_id, run_id, is_owner)
        return is_owner

    async def _safe_send(self, payload: dict) -> None:
        try:
            data = json.dumps(payload, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            logger.exception("IrisPipelineWS: payload non sérialisable")
            return
        async with self._write_lock:
            try:
                await self.write_message(data)
            except tornado.websocket.WebSocketClosedError:
                pass
            except Exception:  # noqa: BLE001
                logger.exception("IrisPipelineWS: write_message failed")

    async def _load_current_user(self) -> Optional[User]:
        """Charge l'utilisateur depuis le cookie ``session_token``.

        Pattern aligné sur ``IrisWebSocketHandler`` (cf. doctrine
        ``app/handlers/iris.py``). En cas d'erreur, retourne None — le
        caller close avec _WS_CLOSE_AUTH_REQUIRED.
        """

        try:
            from app.services.auth.session_manager import get_session_manager
        except ImportError:
            logger.exception("IrisPipelineWS: session_manager unavailable")
            return None
        # get_secure_cookie (PAS get_cookie) : le cookie est posé via
        # set_secure_cookie(session.id) → il faut le décoder pour récupérer
        # le session.id brut attendu par get_user_from_token. get_cookie
        # renverrait le blob signé `id|ts|sig` → auth toujours en échec
        # (close 4001). Miroir de IrisWebSocketHandler._load_current_user.
        try:
            token_bytes = self.get_secure_cookie("session_token")
            if not token_bytes:
                return None
            token = token_bytes.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            logger.warning("IrisPipelineWS: cookie session_token corrompu")
            return None
        try:
            session_manager = get_session_manager()
            user = await session_manager.get_user_from_token(token)
        except Exception:  # noqa: BLE001
            logger.exception("IrisPipelineWS: token validation failed")
            return None
        return user
