"""Pub/sub in-process pour les événements d'un run pipeline.

Multiplexe les events émis par un ``PipelineRunner`` vers N abonnés (UI multi-
onglets, observabilité admin). Stocke un **buffer borné** des derniers events
pour replay à la souscription tardive : un client qui rejoint la conversation
après le ``phase_start`` ne rate rien.

Doctrine :

- **In-process only** — pas de Redis/PubSub externe. Les abonnés sont des WS
  Tornado actifs sur la même instance. Si on scale horizontalement, ce
  module devient le point d'extension (échange d'un backend Redis trivial
  via interface).
- **Bornage strict** — buffer N=100 events par ``run_id`` (drop oldest).
  Empêche un client lent de saturer la mémoire serveur.
- **Lifecycle aligné sur ``PipelineRun``** — le bus libère le buffer quand
  le run atteint un état terminal (success/failed/cancelled) ET qu'aucun
  abonné n'écoute plus.
- **Thread-safety** — toutes les opérations passent par ``asyncio.Lock``
  (un par ``run_id``). Pas de mutation directe d'état.
- **Pas de logique métier** — le bus ne sait pas ce que sont les events,
  il les transporte en opaque.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Deque, Dict

logger = logging.getLogger(__name__)

# Un callback peut être sync ou async — le bus normalise via ``ensure_awaitable``.
EventCallback = Callable[[Dict[str, Any]], Awaitable[None]]

# Buffer max par run. 100 events couvre ~12 phases × 8 sub-events + marges.
# Adapter via env si besoin (mais ne JAMAIS retirer le bornage).
_MAX_BUFFER_PER_RUN = 100


@dataclass
class _RunChannel:
    """État d'un canal pour un ``run_id`` donné.

    - ``buffer`` : deque borné des derniers events (replay à la subscribe).
    - ``subscribers`` : dict ``subscriber_id → callback``. ID arbitraire
      choisi par l'appelant (typiquement ``ws_handler_id``).
    - ``lock`` : sérialise mutations + dispatch.
    - ``closed`` : True après ``close_channel()``. Toute publish ultérieure
      est ignorée. Évite les races avec abonnés qui se déconnectent.
    - ``next_seq`` : compteur monotone par canal — chaque event publié
      reçoit un ``seq`` unique. Permet au client de dédupliquer les
      events potentiellement reçus 2× (replay+live race) et de détecter
      les trous (gap dans la séquence → resubscribe). Fix #12 review adv.
    """

    buffer: Deque[Dict[str, Any]] = field(default_factory=lambda: deque(maxlen=_MAX_BUFFER_PER_RUN))
    subscribers: Dict[str, EventCallback] = field(default_factory=dict)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    closed: bool = False
    next_seq: int = 0


class PipelineEventBus:
    """Bus pub/sub in-process pour les events de pipeline runs.

    Singleton via ``get_event_bus()``. Ne pas instancier directement dans
    les call-sites — toujours passer par le getter pour bénéficier de
    l'unicité.
    """

    def __init__(self) -> None:
        self._channels: Dict[int, _RunChannel] = {}
        self._global_lock = asyncio.Lock()

    async def _get_or_create_channel(self, run_id: int) -> _RunChannel:
        """Récupère ou crée le canal pour un run.

        Garde-fou : sérialisé par ``_global_lock`` pour éviter race
        d'initialisation (deux subscribes simultanés sur run_id inconnu
        créeraient deux _RunChannel).
        """

        async with self._global_lock:
            if run_id not in self._channels:
                self._channels[run_id] = _RunChannel()
            return self._channels[run_id]

    async def publish(self, run_id: int, event: Dict[str, Any]) -> None:
        """Publie un event sur le canal du run.

        - Ajoute au buffer (drop oldest si plein).
        - Dispatche aux abonnés ; un callback en erreur ne casse PAS les
          autres (chaque dispatch est wrappé en try/except).
        """

        channel = await self._get_or_create_channel(run_id)
        async with channel.lock:
            if channel.closed:
                # Run terminé + canal fermé → on ignore les events tardifs.
                return
            # Stamp le seq number AVANT d'ajouter au buffer/dispatch (fix #12).
            # Mutation in-place — le caller verra son event enrichi.
            event = {**event, "seq": channel.next_seq}
            channel.next_seq += 1
            channel.buffer.append(event)
            # Snapshot des callbacks pour dispatcher hors lock (évite
            # deadlock si un callback subscribe/unsubscribe).
            callbacks = list(channel.subscribers.values())

        for callback in callbacks:
            try:
                await callback(event)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "PipelineEventBus.publish: subscriber callback raised "
                    "(run_id=%s, event_type=%s)",
                    run_id,
                    event.get("type"),
                )

    async def subscribe(self, run_id: int, subscriber_id: str, callback: EventCallback) -> None:
        """Abonne un callback au canal et lui rejoue le buffer.

        Le callback reçoit IMMÉDIATEMENT les events bufferisés (replay)
        puis les events futurs. Si le callback crashe pendant le replay,
        l'abonnement est conservé (le caller doit gérer ses erreurs).
        """

        channel = await self._get_or_create_channel(run_id)
        async with channel.lock:
            channel.subscribers[subscriber_id] = callback
            replay = list(channel.buffer)

        for event in replay:
            try:
                await callback(event)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "PipelineEventBus.subscribe: replay callback raised "
                    "(run_id=%s, subscriber=%s)",
                    run_id,
                    subscriber_id,
                )

    async def unsubscribe(self, run_id: int, subscriber_id: str) -> None:
        """Désabonne. No-op si pas abonné."""

        channel = self._channels.get(run_id)
        if channel is None:
            return
        async with channel.lock:
            channel.subscribers.pop(subscriber_id, None)

    async def has_subscribers(self, run_id: int) -> bool:
        channel = self._channels.get(run_id)
        if channel is None:
            return False
        async with channel.lock:
            return bool(channel.subscribers)

    async def close_channel(self, run_id: int) -> None:
        """Ferme le canal d'un run terminal et libère ses ressources.

        Idempotent. À appeler quand le runner détecte un état terminal
        ET qu'on est sûr qu'aucun abonné ne va revenir (typiquement après
        un délai de grâce).
        """

        channel = self._channels.get(run_id)
        if channel is None:
            return
        async with channel.lock:
            channel.closed = True
            channel.subscribers.clear()
            channel.buffer.clear()
        async with self._global_lock:
            self._channels.pop(run_id, None)


# ── Singleton ──────────────────────────────────────────────────────────

_BUS_INSTANCE: PipelineEventBus | None = None


def get_event_bus() -> PipelineEventBus:
    """Retourne l'instance unique du bus (initialisation lazy).

    Pas de réinitialisation runtime : les abonnés actifs ne doivent pas
    être perdus.
    """

    global _BUS_INSTANCE
    if _BUS_INSTANCE is None:
        _BUS_INSTANCE = PipelineEventBus()
    return _BUS_INSTANCE
