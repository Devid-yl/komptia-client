"""Bridge ``input()`` ↔ WebSocket pour les Q/A interactifs de la pipeline.

La pipeline ``scripts/pipeline.py`` contient des ``input()`` synchrones aux
phases 1.2.5, 1.2.6 et 3 (lignes ~5762, ~6177, ~8548). En CLI ils bloquent
le terminal en attendant une réponse humaine. Quand la pipeline tourne sous
Iris, on n'a **pas de stdin** — un ``input()`` brut bloquerait l'event loop
indéfiniment et freeze le serveur Tornado.

Solution : remplacer (ou monkey-patch) les ``input()`` par un appel à
``AskUserBridge.ask()`` qui :

1. Émet un event ``pipeline_ask_user`` sur le bus (frontend ouvre une modal).
2. Attend une ``asyncio.Future`` résolue par le frontend via WS action
   ``ask_user_response``.
3. Timeout configurable (défaut 120s) → fallback gracieux : retourne une
   réponse par défaut documentée dans le contexte de la question. Pas de
   blocage indéfini, pas d'erreur fatale (cf. mémoire
   ``feedback_no_pedagogical_hard_blocks.md``).

Doctrine :

- **ContextVar pour scope** — un bridge par run actif. Les phases pipeline
  appellent ``input_via_bridge()`` qui résout depuis ContextVar courant.
  Si pas de bridge actif (mode CLI), fallback sur ``builtins.input()``.
- **Idempotence côté UI** — chaque ``ask`` a un ID unique pour permettre
  retry/replay si la modal frontend se ferme accidentellement.
- **Confidentialité** — les questions/réponses passent par event_bus →
  loggées dans le buffer mais pas en BDD (pas dans
  ``PipelinePhaseExecution.metadata_summary``).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.services.ai.pipeline_event_bus import get_event_bus

logger = logging.getLogger(__name__)

# Timeout par défaut. La pipeline peut prendre du temps mais 2 min est large
# pour qu'un humain réponde à une question simple. Configurable via param.
_DEFAULT_TIMEOUT_SECONDS = 120.0


@dataclass
class PendingAsk:
    """Une question en attente de réponse utilisateur."""

    ask_id: str
    question: str
    context: Dict[str, Any]
    future: asyncio.Future[str]


class AskUserBridge:
    """Bridge un appel ``input()`` synchrone vers un Q/A async via WS.

    Une instance par ``PipelineRun`` actif. Le runner injecte le bridge
    courant via ``set_current_bridge()`` AVANT d'appeler ``run_pipeline()``,
    puis le pop à la fin (try/finally).
    """

    def __init__(self, run_id: int, default_timeout: float = _DEFAULT_TIMEOUT_SECONDS):
        self.run_id = run_id
        self.default_timeout = default_timeout
        self._pending: Dict[str, PendingAsk] = {}
        self._lock = asyncio.Lock()

    async def ask(
        self,
        question: str,
        *,
        context: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        default_response: str = "",
    ) -> str:
        """Pose une question à l'utilisateur via le bus WS.

        Si timeout : retourne ``default_response`` (dégradation gracieuse).
        Si ``default_response`` est vide → retourne chaîne vide (la pipeline
        traite typiquement comme "skip"/"continue" selon la phase).
        """

        ask_id = uuid.uuid4().hex[:12]
        ctx = dict(context or {})
        loop = asyncio.get_running_loop()
        future: asyncio.Future[str] = loop.create_future()

        async with self._lock:
            self._pending[ask_id] = PendingAsk(
                ask_id=ask_id, question=question, context=ctx, future=future
            )

        # Émet l'event sur le bus → frontend ouvre modal.
        # ``interaction_kind`` aligne ce payload sur la taxonomie unifiée
        # côté JS (cf. ``static/js/iris.js::renderInteraction``).
        await get_event_bus().publish(
            self.run_id,
            {
                "type": "pipeline_ask_user",
                "interaction_kind": "open_question",
                "ask_id": ask_id,
                "question": question,
                "context": ctx,
            },
        )

        timeout_value = timeout if timeout is not None else self.default_timeout
        try:
            answer = await asyncio.wait_for(future, timeout=timeout_value)
            return answer
        except asyncio.TimeoutError:
            logger.warning(
                "AskUserBridge: timeout after %.1fs (run_id=%s, ask_id=%s) "
                "— returning default response",
                timeout_value,
                self.run_id,
                ask_id,
            )
            return default_response
        finally:
            async with self._lock:
                self._pending.pop(ask_id, None)

    async def submit_response(self, ask_id: str, response: str) -> bool:
        """Résout une question pendante avec la réponse utilisateur.

        Retourne True si la question a été trouvée et résolue, False sinon
        (ID inconnu, déjà résolue, ou timeout entretemps).
        """

        async with self._lock:
            pending = self._pending.get(ask_id)
        if pending is None:
            return False
        if pending.future.done():
            return False
        pending.future.set_result(response)
        return True

    async def cancel_all(self, reason: str = "run_cancelled") -> None:
        """Annule toutes les questions pendantes (run cancelled).

        Résout chaque future avec une exception pour que les coroutines
        ``ask()`` quittent immédiatement avec ``CancelledError`` si
        propagé, ou avec le default si on prefère un fallback gracieux.
        Ici on choisit ``CancelledError`` — laisse la phase pipeline
        décider de son comportement.
        """

        async with self._lock:
            pending = list(self._pending.values())
            self._pending.clear()
        for ask in pending:
            if not ask.future.done():
                ask.future.set_exception(asyncio.CancelledError(reason))


# ── ContextVar : bridge actif pour la coroutine courante ─────────────
#
# Doctrine (PEP 567 + Python 3.10+) : ``asyncio.create_task()`` capture
# automatiquement le ``Context`` du caller au moment du create. Chaque
# sub-task possède donc son propre slot ContextVar — pas de fuite entre
# 2 ``PipelineRunner`` concurrents tant que :
#
# 1. ``set_current_bridge`` est appelé DANS la coroutine du run (et
#    pas dans le parent qui crée la task) — c'est ce que fait
#    ``_run()`` du runner.
# 2. Tout code synchrone exécuté en background utilise
#    ``asyncio.to_thread`` (qui copy le contexte) ou
#    ``loop.run_in_executor`` avec un wrapper ``contextvars.copy_context().run``.
#
# Si un futur dev introduit un `run_in_executor` brut, le bridge fuit
# vers un autre run. À surveiller via la grep CI ``run_in_executor``.

_current_bridge: ContextVar[Optional[AskUserBridge]] = ContextVar(
    "_current_pipeline_ask_user_bridge", default=None
)


def set_current_bridge(bridge: Optional[AskUserBridge]) -> Any:
    """Pose le bridge courant (à appeler depuis le runner). Retourne le
    token pour ``reset()``.
    """

    return _current_bridge.set(bridge)


def reset_current_bridge(token: Any) -> None:
    """Restaure l'ancien bridge (try/finally du runner)."""

    _current_bridge.reset(token)


def get_current_bridge() -> Optional[AskUserBridge]:
    """Retourne le bridge actif (None si on est en mode CLI / sans Iris)."""

    return _current_bridge.get()


async def ask_via_bridge_or_default(
    question: str,
    *,
    default_response: str = "",
    context: Optional[Dict[str, Any]] = None,
    timeout: Optional[float] = None,
) -> str:
    """Helper : ask via bridge si présent, sinon retourne default.

    À utiliser depuis ``scripts/pipeline.py`` aux call-sites des
    ``input()`` actuels après refactor (Lot suivant).
    """

    bridge = get_current_bridge()
    if bridge is None:
        # Mode CLI / pas de bridge actif. La pipeline fait son
        # ``input()`` original (le call-site doit gérer ce cas en
        # gardant le code legacy intact si ``get_current_bridge()`` est None).
        return default_response
    return await bridge.ask(
        question,
        context=context,
        timeout=timeout,
        default_response=default_response,
    )
