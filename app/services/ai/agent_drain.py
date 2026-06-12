"""Drain helper pour consommer un async generator avec timeouts.

Extrait pour testabilité — la logique "per-event timeout + wall-clock cap +
aclosing()" est complexe et doit pouvoir être testée sans monter une
WebSocket Tornado.

Contexte
--------
``IrisAgent.run(...)`` est un async generator qui yield des events
``{"type": ..., ...}``. Sans wrapper, un LLM hung ou un appel SQL Sage
qui ne revient jamais bloque la WS du user + le lock conversation
indéfiniment. En multi-user (depuis l'audit 2026-05-22), ça gaspille des
ressources serveur sans feedback à l'utilisateur.

Ce helper applique 2 couches de protection :

1. **Per-event timeout** : si un seul event prend plus que
   ``per_event_timeout_s``, on coupe. Couvre les LLM hung et les SQL
   Sage qui timeout sans erreur.
2. **Wall-clock cap total** : si le run cumule plus que
   ``total_timeout_s``, on coupe. Couvre l'attaque "heartbeat
   smuggling" — un agent qui yield un event toutes les 290 s sans rien
   produire de réel.

Sur timeout, le helper lève :class:`AgentEventTimeout` ou
:class:`AgentRunWallClockTimeout`. Le caller catch et applique sa
politique de cleanup (logger, send_error, reset cancel_event, etc.).

Le ``contextlib.aclosing`` enveloppe l'agent generator pour garantir
``aclose()`` quand le helper sort proprement (timeout, fin normale,
exception propagée). **Mais** : si le CALLER break ou raise dans son
``async for``, Python n'appelle ``aclose()`` sur le helper qu'à la
finalisation par le event loop (potentiellement plus tard). Pour
garantir un cleanup synchrone, le caller doit lui-même wrapper le
helper dans ``contextlib.aclosing`` :

.. code-block:: python

    async with contextlib.aclosing(
        drain_agent_events(gen, per_event_timeout_s=300, total_timeout_s=1800)
    ) as drained:
        async for event in drained:
            ...
            if some_condition:
                break  # aclose() du helper ET de gen garanti
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import AsyncIterator, Awaitable, Mapping

# Marqueur de type pour les events produits par ``IrisAgent.run``. Trop
# variable pour typer en TypedDict sans casser les call-sites — on garde
# ``Mapping`` lâche.
AgentEvent = Mapping[str, object]


class AgentEventTimeout(asyncio.TimeoutError):
    """Levée quand un SEUL event prend plus que ``per_event_timeout_s``.

    Hérite de ``asyncio.TimeoutError`` pour rester compatible avec les
    callers qui catch déjà ``TimeoutError``, tout en permettant aux
    callers raffinés de distinguer per-event vs wall-clock.
    """

    def __init__(self, timeout_s: float):
        super().__init__()
        self.timeout_s = timeout_s


class AgentRunWallClockTimeout(asyncio.TimeoutError):
    """Levée quand le run cumule plus que ``total_timeout_s``.

    Évite l'attaque heartbeat smuggling (agent qui yield un event
    toutes les ~290 s sans produire de résultat utile)."""

    def __init__(self, timeout_s: float, elapsed_s: float):
        super().__init__()
        self.timeout_s = timeout_s
        self.elapsed_s = elapsed_s


async def drain_agent_events(
    agent_generator: AsyncIterator[AgentEvent],
    *,
    per_event_timeout_s: float,
    total_timeout_s: float,
    monotonic: Awaitable[float] | None = None,
    interactive_event_types: "frozenset[str] | None" = None,
) -> AsyncIterator[AgentEvent]:
    """Yield les events du ``agent_generator`` avec timeouts.

    Args:
        agent_generator: l'async iterator retourné par
            ``IrisAgent.run(...)``. Sera fermé via ``aclose()`` à la
            sortie de cette coroutine (succès, timeout, ou exception
            caller).
        per_event_timeout_s: délai max par event individuel.
        total_timeout_s: délai max cumulé pour tout le run.
        monotonic: hook pour les tests — fonction qui retourne le
            temps monotone. ``None`` = ``time.monotonic`` standard.

    Yields:
        Chaque event du generator, dans l'ordre, sans modification.

    Raises:
        AgentEventTimeout: un event a pris plus de
            ``per_event_timeout_s``.
        AgentRunWallClockTimeout: le run total dépasse
            ``total_timeout_s``.
        Toute autre exception levée par le generator est propagée
            telle quelle (le caller décide de la gestion).
    """
    if per_event_timeout_s <= 0:
        raise ValueError(f"per_event_timeout_s must be > 0, got {per_event_timeout_s}")
    if total_timeout_s <= 0:
        raise ValueError(f"total_timeout_s must be > 0, got {total_timeout_s}")
    if total_timeout_s < per_event_timeout_s:
        # Pas un bug, juste suspect — le caller a mal configuré.
        # On laisse passer (le total dominera).
        pass

    _now = monotonic if monotonic is not None else time.monotonic
    start = _now()
    _interactive = interactive_event_types or frozenset()
    # L'event PRÉCÉDENT attend-il une réponse de l'utilisateur (consentement,
    # clarification, question pipeline) ? Si oui, le prochain event peut tarder
    # le temps que l'user réponde → on NE lui applique PAS le per-event timeout
    # (sinon le run est tué à ``per_event_timeout_s`` avec un message « requête
    # trop longue » trompeur ; cf. audit UX PIPE-2). On défère au wall-clock cap
    # — les timeouts backend de chaque gate (consent 300s, ask_user 120s)
    # ferment de toute façon avant.
    last_was_interactive = False

    async with contextlib.aclosing(agent_generator) as _gen:
        _iter = _gen.__aiter__()
        while True:
            elapsed = _now() - start
            remaining_total = total_timeout_s - elapsed
            if remaining_total <= 0:
                raise AgentRunWallClockTimeout(total_timeout_s, elapsed)
            # Le wait_for effectif = min(per-event, restant total). Après un
            # event interactif, ``base`` = restant total (pas de cap per-event)
            # → l'user a jusqu'au wall-clock pour répondre. Si l'event hit ce
            # timeout réduit, on lève AgentEventTimeout (sauf si le restant total
            # dominait → wall-clock déguisé).
            base = remaining_total if last_was_interactive else per_event_timeout_s
            effective_timeout = min(base, remaining_total)
            try:
                event = await asyncio.wait_for(
                    _iter.__anext__(),
                    timeout=effective_timeout,
                )
            except StopAsyncIteration:
                # Fin normale du generator — sortir propre.
                return
            except asyncio.TimeoutError:
                # Distinguer per-event vs total : si le restant total
                # était plus petit que per-event au moment du wait,
                # c'est en réalité un wall-clock timeout déguisé.
                if effective_timeout == remaining_total:
                    raise AgentRunWallClockTimeout(total_timeout_s, _now() - start)
                raise AgentEventTimeout(per_event_timeout_s)
            last_was_interactive = str(event.get("type", "")) in _interactive
            yield event


__all__ = [
    "AgentEvent",
    "AgentEventTimeout",
    "AgentRunWallClockTimeout",
    "drain_agent_events",
]
