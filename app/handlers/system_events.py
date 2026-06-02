"""Handler SSE global pour broadcaster des événements système à tous les
utilisateurs authentifiés (overlay sync schéma, etc.).

Endpoint : ``GET /api/system/events``. Réponse ``text/event-stream``. Les
clients (toutes les pages via ``base.html``) maintiennent une connexion
``EventSource`` permanente et reçoivent les événements push depuis
``app.services.event_bus.get_event_bus()``.

Sécurité : auth requise (un anonyme ne reçoit pas les notifications
internes). Pas de filtre par RÔLE (les overlays système sont informationnels
et destinés à tous), MAIS filtre par TYPE d'événement (C3-F1, défense en
profondeur) : seuls les événements système-wide (``_SYSTEM_BROADCAST_EVENT_TYPES``)
sont forwardés. Aujourd'hui le bus de ce SSE (``app.services.event_bus``) ne
reçoit QUE des ``schema_sync.*`` (pas de fuite actuelle), mais comme ce SSE est
``@authenticated`` non scopé, le filtre garantit fail-closed qu'un futur publisher
per-user ajouté par erreur à CE bus (à ne pas confondre avec le bus DISTINCT
``app.services.ai.pipeline_event_bus``, keyé par ``run_id``, qui alimente le WS
``iris_pipeline_ws``) ne fuiterait pas vers tous les connectés.
"""

from __future__ import annotations

import asyncio
import json
import logging

from tornado.iostream import StreamClosedError

from app.core import clock
from app.handlers.base import BaseHandler, authenticated
from app.services.event_bus import get_event_bus

logger = logging.getLogger(__name__)

# Fenêtre pendant laquelle on considère un sync "tout juste terminé" — sert
# à fermer la race fetch-vs-SSE-subscribe : si le snapshot REST est demandé
# moins de N secondes après la fin d'un sync, on renvoie ``just_completed=True``
# pour que l'overlay client affiche la complétion (sinon le ``done`` event
# peut être passé avant que le client subscribe au SSE → overlay vide).
_RECENT_DONE_WINDOW_SECONDS = 30.0

# Heartbeat SSE pour éviter timeout proxy (cf. SSE_HEARTBEAT_SECONDS dans
# ai_config.py — alignement intentionnel sur 15s).
_HEARTBEAT_SECONDS = 15.0

#: C3-F1 (défense en profondeur, fail-closed) — whitelist des types d'événements
#: que ce SSE a le droit de forwarder.
#:
#: État ACTUEL (vérifié) : le bus de ce SSE est ``app.services.event_bus``, et ses
#: SEULS publishers sont les ``schema_sync.*`` de ``schema_sync.py``. Il n'y a donc
#: pas de fuite aujourd'hui. ⚠️ NE PAS confondre avec ``app.services.ai.
#: pipeline_event_bus`` (bus DISTINCT, keyé par ``run_id`` int, payloads pipeline
#: avec traceback/SQL) qui alimente le WS ``iris_pipeline_ws`` — celui-là n'est
#: PAS écouté ici.
#:
#: Pourquoi ce filtre quand même : ce SSE est ``@authenticated`` (TOUT user, sans
#: scoping par user/rôle) et broadcast à tous. Si un futur publisher per-user était
#: ajouté par erreur à CE bus (ex. confusion avec ``pipeline_event_bus`` lors d'un
#: refactor), forwarder l'intégralité ferait fuiter ses payloads vers tous les
#: connectés. La whitelist garantit fail-closed : tout type non listé est DROP, un
#: nouvel événement ne peut pas fuiter par défaut.
#:
#: ⚠️ COUPLAGE : doit rester aligné sur les ``publish("schema_sync.…")`` de
#: ``schema_sync.py``. Un type système ajouté là mais oublié ici serait droppé
#: silencieusement → overlay muet (cf. ``global_sync_overlay.js`` qui ne gère que
#: ces 3 types).
_SYSTEM_BROADCAST_EVENT_TYPES = frozenset(
    {"schema_sync.started", "schema_sync.progress", "schema_sync.done"}
)


class SystemEventsSSEHandler(BaseHandler):
    """``GET /api/system/events`` — flux SSE des événements système."""

    @authenticated
    async def get(self) -> None:
        self.set_header("Content-Type", "text/event-stream; charset=utf-8")
        self.set_header("Cache-Control", "no-cache")
        self.set_header("Connection", "keep-alive")
        self.set_header("X-Accel-Buffering", "no")  # nginx no buffering
        # Retry suggéré au client si la connexion casse.
        self.write("retry: 5000\n\n")
        await self.flush()

        bus = get_event_bus()
        queue = await bus.subscribe()
        try:
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=_HEARTBEAT_SECONDS)
                except asyncio.TimeoutError:
                    # Heartbeat — keepalive proxy/load balancer.
                    self.write(": ping\n\n")
                    await self.flush()
                    continue
                # C3-F1 (fail-closed) : ne forwarder QUE les événements
                # système-wide whitelistés. Tout autre type est DROP ici → un
                # éventuel publisher per-user ajouté par erreur à ce bus ne
                # fuiterait pas via ce SSE non scopé.
                if payload.get("type") not in _SYSTEM_BROADCAST_EVENT_TYPES:
                    continue
                self.write(f"data: {json.dumps(payload, default=str)}\n\n")
                await self.flush()
        except (StreamClosedError, asyncio.CancelledError):
            # Client a fermé la connexion ou shutdown — sortie propre.
            pass
        finally:
            await bus.unsubscribe(queue)


class SystemSyncStatusHandler(BaseHandler):
    """``GET /api/system/sync-status`` — snapshot synchrone de la sync.

    Variante filtrée du endpoint admin ``GET /api/ai/schema/sync``.
    Accessible à tous les users authentifiés car l'overlay sync (chargé via
    ``base.html``) est affiché pour tous. Permet à l'overlay de se
    réafficher après une navigation (page refresh) en plein milieu d'une
    sync sans dépendre d'un éventuel ``schema_sync.progress`` sur le bus
    (qui peut tomber dans une fenêtre silencieuse — ex. ``view_mining``
    ~14 s sans event de progression entre deux passes).

    Champs retournés (active=True) :

    * ``step``, ``percent``, ``message`` : reflet filtré de
      ``_current_progress`` (cf. :meth:`SchemaSyncService.get_overlay_progress`
      pour le critère exact).
    * ``elapsed_seconds`` : secondes écoulées depuis le démarrage du sync.

    Champs retournés (active=False) :

    * ``just_completed`` : true si la sync s'est terminée dans la fenêtre
      ``_RECENT_DONE_WINDOW_SECONDS`` — sert à fermer la race
      fetch-vs-SSE-subscribe (si le client se reconnecte juste après le
      ``done`` event, il a raté l'event et resterait sans rien afficher
      sans ce flag).

    Fail-soft : si le service de sync est indisponible (cycle d'import,
    erreur runtime), on répond ``{"active": false}`` plutôt que de
    propager une 500 — bruit serveur silencieux côté UX (le
    ``.catch()`` JS swallow). On log un warning pour traçabilité.
    """

    @authenticated
    async def get(self) -> None:
        try:
            # Import paresseux pour éviter le cycle d'import au boot.
            from app.services.ai.schema_sync import get_sync_service

            sync_service = get_sync_service()
            overlay_progress = sync_service.get_overlay_progress()
            last_completed = sync_service.get_last_completed_at()
        except Exception:
            logger.warning(
                "sync-status: service indisponible, fail-soft à active=False",
                exc_info=True,
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            self.set_header("Content-Type", "application/json; charset=UTF-8")
            self.write({"active": False})
            return

        self.set_header("Content-Type", "application/json; charset=UTF-8")
        if overlay_progress is not None:
            self.write({"active": True, **overlay_progress})
            return

        # Sync inactive — vérifier la fenêtre "just_completed" pour combler
        # la race fetch-vs-SSE-subscribe.
        just_completed = False
        if last_completed is not None:
            elapsed = (clock.now() - last_completed).total_seconds()
            just_completed = 0 <= elapsed <= _RECENT_DONE_WINDOW_SECONDS
        self.write({"active": False, "just_completed": just_completed})
