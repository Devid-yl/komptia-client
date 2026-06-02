"""Event bus simple en mémoire pour broadcaster des événements système à
tous les clients SSE connectés (overlay sync schéma global, etc.).

Pas de persistence : un client qui se reconnecte après un événement ne le
verra pas. Le bus est utile uniquement pour les notifications "live"
(progression sync schéma) qui n'ont pas de valeur au-delà de la session.

Implémentation : une liste d'``asyncio.Queue`` (1 par subscriber). Le
publisher pousse sur toutes. Le subscriber lit la sienne au fil. Quand
le client SSE se déconnecte, il appelle ``unsubscribe`` pour retirer sa
queue. Aucune dépendance externe.

Pour scale multi-process : remplacer par Redis pub/sub. Pour Komptia
single-process Tornado actuel, c'est largement suffisant.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class EventBus:
    """Pub/sub mémoire. Singleton via ``get_event_bus()``."""

    def __init__(self) -> None:
        self._subscribers: List[asyncio.Queue] = []
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue:
        """Retourne une queue dédiée au subscriber. À unsubscribe en finally."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._subscribers.append(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue) -> None:
        async with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    async def publish(self, event_type: str, data: Dict[str, Any]) -> None:
        """Pousse l'événement sur toutes les queues. Si une queue est pleine
        (subscriber lent), on drop l'event pour ce subscriber (best-effort,
        on ne bloque jamais le publisher)."""
        payload = {"type": event_type, "data": data}
        async with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                logger.warning("EventBus: queue full pour 1 subscriber, drop event %s", event_type)


_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus
