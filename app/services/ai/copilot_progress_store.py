"""Store en mémoire pour la todo-list du copilot_agent en cours + registry
des Tasks asyncio pour la cancellation.

Objectif : permettre au frontend de poller l'état du plan du LLM pendant
qu'un run copilot s'exécute (plusieurs secondes à plusieurs minutes), sans
introduire de WebSocket ou de streaming SSE dans un codebase qui n'en a pas
encore. Le polling lit ici l'état le plus récent écrit par les handlers
plan_add / plan_update.

Design :
- Dict global indexé par ``run_id`` (uuid généré côté frontend).
- Chaque entrée : ``{"plan": list[dict], "updated_at": float}``.
- TTL auto-cleanup 10 minutes : un run qui crash sans appeler
  ``clear_progress`` ne laisse pas de fuite mémoire éternelle.
- Thread-safe via ``asyncio.Lock`` — plusieurs copilots en parallèle
  (onglets multiples, tabs du même user) écrivent/lisent sans race.

Cycle de vie :
1. Frontend génère ``run_id``, le passe en POST
2. Backend crée ctx avec ``ctx.run_id = run_id``
3. Chaque ``plan_add`` / ``plan_update`` écrit via ``set_progress``
4. Frontend polle ``get_progress`` toutes les 1s
5. Fin du run (succès ou erreur) : ``clear_progress(run_id)``

Pas de persistence. Un redémarrage serveur perd tous les runs en cours (OK :
le frontend verra le polling retourner ``None`` et retombera sur le texte
défaut, le run finit comme avant).
"""

from __future__ import annotations

import asyncio
import copy
import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# TTL après lequel une entrée non touchée est considérée morte et supprimée
# au prochain accès. 10 minutes couvre les runs longs (l'e2e stress_noisy
# a tourné 12m45 récemment) sans s'éterniser si le run crash sans cleanup.
_TTL_SECONDS: float = 600.0

# Store global. Clé = (user_id, run_id). Valeur = dict {"plan": list, "updated_at": float}.
#
# CRITICAL : l'isolation par user_id empêche qu'un user authentifié qui
# devine ou exfiltre un run_id d'un autre user puisse lire ses subjects de
# task (defense-in-depth même si UUID v4 a 122 bits d'entropie). Le couple
# (user_id, run_id) est vérifié côté GET — pas de leak cross-user possible.
_store: Dict[tuple, Dict[str, Any]] = {}

# Store des asyncio.Task en cours, indexé par (user_id, run_id). Sert à
# propager une cancellation côté serveur quand l'utilisateur clique Stop
# ou ferme l'onglet en plein run. Sans ce store, le copilot continue à
# brûler les tokens LLM (40 tours × $0.50–1) après le départ du client.
# Isolation user identique au _store : on ne peut cancel que son propre run.
#
# Valeur stockée = (task, registered_at). ``registered_at`` sert au cleanup
# TTL (un crash entre register_task et le finally laisserait sinon une
# entrée fantôme jusqu'au prochain redémarrage).
_tasks: Dict[tuple, tuple] = {}

# Cap dur sur les Tasks enregistrées (DoS protection symétrique à _store).
_MAX_TASKS_ENTRIES: int = 2000

# Store des Futures pour idempotence : si un POST arrive avec un
# ``(user_id, run_id)`` déjà en cours (double-clic Send, retry réseau),
# on await la même Future au lieu de relancer un appel LLM payant.
# Clé = (user_id, run_id). Valeur = (Future, registered_at).
# Cleanup : la Future est retirée dans ``release_run`` à la fin du run
# (succès ou exception). Filet TTL pour les crashs avant release.
_inflight: Dict[tuple, tuple] = {}
_MAX_INFLIGHT_ENTRIES: int = 2000
_INFLIGHT_TTL_SECONDS: float = 1800.0  # 30 min, parité avec _tasks

# TTL des Tasks : si une entrée reste >TTL sans être touchée, on la considère
# orpheline (le finally du run a été skip pour une raison ou une autre) et
# on la purge. Doit être >= max durée d'un run copilot. MAX_TURNS=40 × ~30s
# de timeout LLM = 20min worst-case. On prend 30min pour marge.
_TASKS_TTL_SECONDS: float = 1800.0

# Tombstones de cancellation (fix 2026-06-11, tâche #14) : un cancel qui
# arrive AVANT register_task (fenêtre claim_run → register_task, ex:
# on_connection_close immédiat) ne trouvait rien à canceller → le run
# continuait à brûler des tokens. On mémorise l'intention ; register_task
# la consomme et cancel immédiatement le Task qui s'inscrit. TTL court :
# la fenêtre couverte est de quelques ms — au-delà, un tombstone périmé
# ne doit pas tuer un futur run légitime.
#
# Hypothèse cliente (documentée, review #14) : le frontend génère un
# run_id NEUF (crypto.randomUUID) à CHAQUE submit — un retry/resubmit ne
# réutilise jamais le run_id d'un run cancellé. Un client qui violerait
# ce contrat dans les 60s d'un cancel verrait son run tué à l'inscription
# (defense-in-depth assumée : TTL court + clé scoped user).
_cancel_requested: Dict[tuple, float] = {}
_CANCEL_TOMBSTONE_TTL_SECONDS: float = 60.0


def _cleanup_tombstones_unlocked() -> None:
    """Purge les tombstones expirés. Doit être appelé sous ``_lock``."""
    now = time.time()
    expired = [k for k, ts in _cancel_requested.items() if now - ts > _CANCEL_TOMBSTONE_TTL_SECONDS]
    for k in expired:
        _cancel_requested.pop(k, None)


# Cap dur sur le nombre d'entrées pour empêcher un DoS par accumulation
# (user malveillant qui POSTe 10k fois sans attendre TTL). Au-delà, on
# evict la plus vieille entrée (LRU via updated_at).
_MAX_STORE_ENTRIES: int = 2000

# Lock pour tous les accès mutants. asyncio.Lock suffit car tous les callers
# sont async (Tornado + copilot_agent). Pas de thread pool côté copilot.
_lock = asyncio.Lock()


def _mark_exception_retrieved(fut: Any) -> None:
    """Consomme l'exception d'une Future résolue par le store lui-même
    (purge TTL, eviction LRU) — fix review #14 : si AUCUN doublon n'a
    jamais await cette Future (cas le plus fréquent), asyncio loggue
    « Future exception was never retrieved » à son GC, exactement le
    bruit de logs que cette tâche vise à réduire. ``fut.exception()``
    marque l'exception comme lue SANS la consommer pour d'éventuels
    awaiters réels (ils la reçoivent toujours)."""
    try:
        if fut is not None and fut.done() and not fut.cancelled():
            fut.exception()
    except Exception:  # noqa: BLE001 — best-effort, jamais bloquant
        pass


def _make_key(user_id: Any, run_id: str) -> Optional[tuple]:
    """Construit la clé composite (user_id, run_id). Retourne None si invalide.

    Fail-closed : input mal formé → rien écrit ni lu.
    """
    if not isinstance(run_id, str) or not run_id:
        return None
    if user_id is None:
        return None
    return (str(user_id), run_id)


async def set_progress(
    user_id: Any,
    run_id: str,
    plan: List[Dict[str, Any]],
) -> None:
    """Écrit l'état courant du plan pour ce run (scope user).

    Accepte un plan vide (le LLM n'a rien tracké — pas d'erreur, le polling
    retournera simplement ``task_in_progress: null``). Copie profonde du plan
    pour isoler le store des mutations ultérieures du ctx.

    Si le store atteint ``_MAX_STORE_ENTRIES``, la plus vieille entrée est
    évincée avant l'écriture (LRU). Protection DoS.

    Préserve le champ ``tool_in_use`` si déjà présent (écriture orthogonale
    via ``set_tool_in_use``).
    """
    key = _make_key(user_id, run_id)
    if key is None:
        return
    async with _lock:
        _cleanup_expired_unlocked()
        # Cap dur : evict LRU si plein. Plus vieille = plus petit updated_at.
        if len(_store) >= _MAX_STORE_ENTRIES and key not in _store:
            oldest_key = min(
                _store.keys(),
                key=lambda k: _store[k].get("updated_at", 0),
            )
            _store.pop(oldest_key, None)
        prev = _store.get(key, {})
        _store[key] = {
            "plan": copy.deepcopy(plan),
            # Préserve tool_in_use : set_progress et set_tool_in_use sont
            # appelés indépendamment depuis des chemins différents, on ne
            # veut pas que l'un écrase silencieusement l'autre.
            "tool_in_use": prev.get("tool_in_use"),
            "updated_at": time.time(),
        }


async def set_tool_in_use(
    user_id: Any,
    run_id: str,
    tool_name: Optional[str],
) -> None:
    """Écrit le nom du tool actuellement en cours d'exécution dans le store.

    Appelé par la boucle ``run_copilot_agent`` avant chaque dispatch
    d'outil. ``tool_name=None`` n'est pas attendu en pratique (le caller
    ne reset plus à None entre dispatches — review adv High #2), mais
    supporté pour clean-up explicite.

    Le frontend polle ``/api/iris/task-progress`` et affiche cette valeur
    en plus du subject de plan_in_progress, ce qui donne deux niveaux de
    feedback : "ce que je veux faire" (plan) + "ce que je fais en ce
    moment" (tool). Cumul = transparence maximale sans logs.

    Préserve le plan existant — set_tool_in_use n'écrase que tool_in_use.
    """
    key = _make_key(user_id, run_id)
    if key is None:
        return
    normalized = tool_name if isinstance(tool_name, str) and tool_name else None
    async with _lock:
        # Cleanup systématique (parité avec set_progress). Sans ça,
        # une entrée ressuscitée laissait passer les voisines expirées
        # → fuite mémoire lente (review adv Medium #3).
        _cleanup_expired_unlocked()
        prev = _store.get(key)
        if prev is None:
            # Pas encore d'entrée (le LLM n'a pas appelé plan_add). On crée
            # quand même pour exposer tool_in_use isolément.
            if len(_store) >= _MAX_STORE_ENTRIES:
                oldest_key = min(
                    _store.keys(),
                    key=lambda k: _store[k].get("updated_at", 0),
                )
                _store.pop(oldest_key, None)
            _store[key] = {
                "plan": [],
                "tool_in_use": normalized,
                "updated_at": time.time(),
            }
            return
        prev["tool_in_use"] = normalized
        prev["updated_at"] = time.time()


async def get_progress(
    user_id: Any,
    run_id: str,
) -> Optional[List[Dict[str, Any]]]:
    """Retourne le plan du run (scope user), ou ``None`` si inconnu/expiré.

    ``None`` est un signal au caller (endpoint HTTP) qu'il peut retourner
    ``task_in_progress: null`` au frontend — pas d'erreur, juste « rien à
    montrer ». Le frontend retombera sur le texte défaut.

    Si un user B tente de lire le run_id d'un user A, il n'aura rien : la
    clé ``(B, run_id_de_A)`` n'existe pas dans le store.
    """
    key = _make_key(user_id, run_id)
    if key is None:
        return None
    async with _lock:
        _cleanup_expired_unlocked()
        entry = _store.get(key)
        if entry is None:
            return None
        # Copie défensive : empêche le caller de muter le store.
        return copy.deepcopy(entry["plan"])


async def get_tool_in_use(user_id: Any, run_id: str) -> Optional[str]:
    """Retourne le nom du tool actuellement exécuté pour ce run, ou
    ``None`` si aucun (entre deux tours, run terminé, ou run inconnu).

    Le caller (endpoint HTTP) traduit le nom technique en label français
    avant affichage. La séparation (raw tool name côté store, mapping
    côté endpoint) facilite l'évolution du mapping sans toucher au store.
    """
    key = _make_key(user_id, run_id)
    if key is None:
        return None
    async with _lock:
        # Cleanup TTL (fix 2026-06-11, tâche #14) : parité avec
        # get_progress. Sans lui, un run crashé sans clear_progress
        # continuait d'exposer un tool_in_use FANTÔME (« Exécution de
        # aggregate… » affiché des heures après la mort du run) tant
        # qu'aucun autre accès ne purgait l'entrée.
        _cleanup_expired_unlocked()
        entry = _store.get(key)
        if entry is None:
            return None
        tool = entry.get("tool_in_use")
        return tool if isinstance(tool, str) and tool else None


async def clear_progress(user_id: Any, run_id: str) -> None:
    """Supprime l'entrée. Appelé à la fin du run (succès ou erreur).

    Silent si (user_id, run_id) absent — l'idée est que le cleanup soit
    appelé défensivement depuis plusieurs points sans risque de double-purge.
    """
    key = _make_key(user_id, run_id)
    if key is None:
        return
    async with _lock:
        _store.pop(key, None)


def _cleanup_expired_unlocked() -> None:
    """Supprime les entrées dont updated_at dépasse le TTL. Doit être appelé
    sous _lock. Cheap : scan du dict, un ``time.time()`` par appel.
    """
    now = time.time()
    expired = [
        rid for rid, entry in _store.items() if now - entry.get("updated_at", 0) > _TTL_SECONDS
    ]
    for rid in expired:
        _store.pop(rid, None)


# ── Cancellation : registry des asyncio.Task en cours ────────────────


def _cleanup_tasks_unlocked() -> None:
    """Purge les Tasks orphelines : (a) finies (done() == True), (b) TTL
    dépassé. Doit être appelé sous ``_lock``. O(n) sur la taille du dict.

    Sans ce cleanup, une entrée fantôme peut subsister si :
    - le finally du run a levé une exception avant unregister_task,
    - un CancelledError a été levé pile entre register_task et l'entrée
      du try du caller (window de race fine),
    - le task a été cancellé hors de notre flow.
    """
    now = time.time()
    dead = []
    for k, val in _tasks.items():
        # Compat : valeur ancien format (juste Task, sans tuple)
        if isinstance(val, tuple):
            task, registered_at = val[0], val[1]
        else:
            task = val
            registered_at = 0.0
        if task is None or (hasattr(task, "done") and task.done()):
            dead.append(k)
        elif registered_at > 0 and now - registered_at > _TASKS_TTL_SECONDS:
            dead.append(k)
    for k in dead:
        _tasks.pop(k, None)


async def register_task(user_id: Any, run_id: str, task: "asyncio.Task[Any]") -> None:
    """Enregistre la Task asyncio qui exécute ``run_copilot_agent``.

    Appelé au démarrage du run, AVANT toute opération longue (LLM call,
    BDD anonymisation). Si ``(user_id, run_id)`` est déjà présent avec
    un Task encore vivant, on cancel l'ancien et on logue un warning :
    une resoumission rapide ne doit pas laisser un Task orphelin brûler
    des tokens en parallèle du nouveau.

    Cleanup défensif des Tasks done() / TTL avant insertion (évite que
    des crashs antérieurs au finally accumulent indéfiniment des entrées).
    Cap dur ``_MAX_TASKS_ENTRIES`` (eviction LRU par registered_at).
    """
    key = _make_key(user_id, run_id)
    if key is None:
        return
    async with _lock:
        _cleanup_tasks_unlocked()
        # Si une entrée vivante existe déjà sous cette clé : cancel-la
        # avant de la remplacer. Sinon le 1er run devient orphelin
        # (impossible à cancel via API) — gaspillage $$ + tokens.
        existing = _tasks.get(key)
        if isinstance(existing, tuple):
            existing_task = existing[0]
            if existing_task is not None and not existing_task.done():
                logger.warning(
                    "register_task: collision sur (user=%s, run=%s) — "
                    "cancellation de l'ancien Task vivant.",
                    user_id,
                    run_id,
                )
                try:
                    existing_task.cancel()
                except Exception:  # noqa: BLE001
                    logger.debug("cancel ancien Task a levé", exc_info=True)
        # Cap LRU : si plein, evict l'entrée la plus ancienne (vraisemblablement
        # orpheline). Pas notre clé courante (sinon on s'auto-evict).
        if len(_tasks) >= _MAX_TASKS_ENTRIES and key not in _tasks:
            try:
                oldest_key = min(
                    _tasks.keys(),
                    key=lambda k: (_tasks[k][1] if isinstance(_tasks[k], tuple) else 0.0),
                )
                _tasks.pop(oldest_key, None)
            except ValueError:
                pass  # dict vide entre-temps
        _tasks[key] = (task, time.time())
        # Tombstone : un cancel est arrivé AVANT cette inscription
        # (fenêtre claim→register). Honore l'intention immédiatement —
        # sans ça le run tournait jusqu'au bout, incancellable.
        _cleanup_tombstones_unlocked()
        if _cancel_requested.pop(key, None) is not None:
            logger.info(
                "register_task: cancel demandé avant l'inscription "
                "(user=%s, run=%s) — cancellation immédiate.",
                user_id,
                run_id,
            )
            try:
                task.cancel()
            except Exception:  # noqa: BLE001
                logger.debug("cancel tombstone a levé", exc_info=True)


async def unregister_task(
    user_id: Any,
    run_id: str,
    task: Optional["asyncio.Task[Any]"] = None,
) -> None:
    """Retire le Task du registry. Silent si absent — double-purge OK.

    Fix 2026-06-11 (tâche #14) : la docstring promettait la comparaison
    par identité mais le code popait INCONDITIONNELLEMENT — le finally
    d'un run A remplacé (collision register_task → A cancellé, B inscrit)
    purgeait l'entrée du SUCCESSEUR B, qui devenait incancellable via
    l'API (Stop sans effet, tokens brûlés jusqu'au bout). Le caller passe
    désormais sa référence de Task : si l'entrée pointe vers un AUTRE
    Task encore vivant, on ne touche pas (c'est l'entrée du successeur).
    ``task=None`` (legacy) garde l'ancien comportement.
    """
    key = _make_key(user_id, run_id)
    if key is None:
        return
    async with _lock:
        entry = _tasks.get(key)
        if entry is None:
            return
        current = entry[0] if isinstance(entry, tuple) else entry
        if task is not None and current is not None and current is not task:
            # L'entrée appartient à un autre Task (successeur). On ne la
            # purge que s'il est déjà fini (entrée morte de toute façon).
            if not (hasattr(current, "done") and current.done()):
                return
        _tasks.pop(key, None)


async def cancel_task(user_id: Any, run_id: str) -> bool:
    """Annule le Task associé à ``(user_id, run_id)``. Retourne True si
    un task vivant a été cancellé, False sinon (run déjà fini, run_id
    inconnu, user_id ne correspond pas).

    Le cancellation propage ``asyncio.CancelledError`` dans la boucle du
    copilot — la prochaine ``await`` (typiquement ``call_llm_with_tools``)
    lève, le ``except CancelledError`` du ``run_copilot_agent`` cleanup
    et retourne ``{"type": "cancelled"}`` au caller. Le coût LLM est
    arrêté immédiatement (sauf le tour en vol, qui est inévitable).
    """
    key = _make_key(user_id, run_id)
    if key is None:
        return False
    async with _lock:
        _cleanup_tasks_unlocked()
        entry = _tasks.get(key)
        if entry is None:
            # Tombstone (fix 2026-06-11, tâche #14) : le run a peut-être
            # été claim mais pas encore register (fenêtre de quelques ms).
            # Mémorise l'intention — register_task la consommera et
            # cancellera immédiatement. Sans run en vol, le tombstone
            # expire en _CANCEL_TOMBSTONE_TTL_SECONDS sans effet.
            _cleanup_tombstones_unlocked()
            _cancel_requested[key] = time.time()
            return False
        if isinstance(entry, tuple):
            task = entry[0]
        else:
            task = entry
        if task is None or (hasattr(task, "done") and task.done()):
            _tasks.pop(key, None)
            return False
        task.cancel()
        # On ne pop pas ici : le finally du run_copilot_agent fera
        # unregister_task. Si on pop maintenant, un second cancel
        # concurrent pourrait croire qu'il n'y a rien à canceller.
        return True


# ── Idempotence : claim/release pattern pour dedup runs concurrents ──


def _cleanup_inflight_unlocked() -> None:
    """Purge les Futures orphelines (done sans release, ou TTL dépassé).
    Doit être appelé sous ``_lock``.

    Fix 2026-06-11 (tâche #14) : une Future TTL-expirée mais PAS done a
    encore potentiellement des awaiters (POSTs doublons). La purger sans
    la résoudre les laissait suspendus jusqu'à leur propre timeout — on
    leur set une exception explicite (même pattern que l'eviction LRU de
    ``claim_run``).
    """
    now = time.time()
    dead = []
    for k, val in _inflight.items():
        if isinstance(val, tuple):
            fut, registered_at = val[0], val[1]
        else:
            fut = val
            registered_at = 0.0
        if fut is None or (hasattr(fut, "done") and fut.done()):
            dead.append(k)
        elif registered_at > 0 and now - registered_at > _INFLIGHT_TTL_SECONDS:
            dead.append(k)
    for k in dead:
        evicted = _inflight.pop(k, None)
        fut = evicted[0] if isinstance(evicted, tuple) else evicted
        if fut is not None and hasattr(fut, "done") and not fut.done():
            try:
                fut.set_exception(RuntimeError("inflight Future expirée (TTL) sans release_run"))
                _mark_exception_retrieved(fut)
            except Exception:  # noqa: BLE001 — Future cancellée entre-temps
                pass


async def claim_run(
    user_id: Any,
    run_id: str,
) -> tuple:
    """Tente de réserver l'exécution d'un ``(user_id, run_id)``.

    Returns ``(is_owner, future)``.

    - ``is_owner=True`` : le caller doit exécuter le run et appeler
      ``release_run`` à la fin avec le résultat (ou l'exception). La
      Future retournée est celle que les autres callers concurrents
      vont await.
    - ``is_owner=False`` : un autre caller a déjà claim ce ``run_id``.
      Le caller doit ``await future`` et propager le résultat (ou
      l'exception). Pas relancer le LLM.

    Si ``run_id`` ou ``user_id`` est invalide (None/vide) → on retourne
    ``(True, Future())`` mais la Future n'est PAS stockée — le caller
    se comporte comme un owner solitaire (comportement legacy : pas
    d'idempotence, mais pas de crash non plus).
    """
    key = _make_key(user_id, run_id)
    if key is None:
        # Pas de clé → pas de dedup possible, comportement legacy.
        loop = asyncio.get_running_loop()
        return True, loop.create_future()
    async with _lock:
        _cleanup_inflight_unlocked()
        existing = _inflight.get(key)
        if isinstance(existing, tuple):
            existing_fut = existing[0]
            if existing_fut is not None and not existing_fut.done():
                logger.info(
                    "claim_run: doublon détecté (user=%s, run=%s) — "
                    "le caller va await la Future existante.",
                    user_id,
                    run_id,
                )
                return False, existing_fut
        # Cap LRU : si plein, evict la plus ancienne done/expirée. La
        # Future évincée est explicitement cancellée pour libérer les
        # awaiters concurrents (sans ça, ils resteraient bloqués jusqu'à
        # leur propre timeout — cf review adversariale Critical #4).
        if len(_inflight) >= _MAX_INFLIGHT_ENTRIES and key not in _inflight:
            try:
                oldest_key = min(
                    _inflight.keys(),
                    key=lambda k: (_inflight[k][1] if isinstance(_inflight[k], tuple) else 0.0),
                )
                evicted = _inflight.pop(oldest_key, None)
                if isinstance(evicted, tuple):
                    evicted_fut = evicted[0]
                    if (
                        evicted_fut is not None
                        and hasattr(evicted_fut, "done")
                        and not evicted_fut.done()
                    ):
                        try:
                            evicted_fut.set_exception(
                                RuntimeError("inflight Future evicted (LRU cap reached)")
                            )
                            _mark_exception_retrieved(evicted_fut)
                        except Exception:  # noqa: BLE001
                            pass
            except ValueError:
                pass
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        _inflight[key] = (fut, time.time())
        return True, fut


async def release_run(
    user_id: Any,
    run_id: str,
    result: Any = None,
    exception: Optional[BaseException] = None,
) -> None:
    """Signale la fin d'un run claimé. Set le résultat (ou l'exception)
    sur la Future associée et retire l'entrée du store. Silent si la
    clé est absente (double-purge OK) ou la Future déjà résolue.

    Doit être appelé dans le ``finally`` du caller pour garantir que
    les awaiters ne restent pas bloqués indéfiniment.
    """
    key = _make_key(user_id, run_id)
    if key is None:
        return
    async with _lock:
        entry = _inflight.pop(key, None)
    if entry is None:
        return
    fut = entry[0] if isinstance(entry, tuple) else entry
    if fut is None or fut.done():
        return
    try:
        if exception is not None:
            fut.set_exception(exception)
        else:
            fut.set_result(result)
    except Exception:  # noqa: BLE001
        # Future déjà cancellée par un autre chemin — silencieux.
        logger.debug(
            "release_run: set_result/exception a levé (Future cancellée ?)",
            exc_info=True,
        )


async def finalize_run(
    user_id: Any,
    run_id: str,
    result: Any = None,
    task: Optional["asyncio.Task[Any]"] = None,
) -> None:
    """Cleanup de fin de run en UNE séquence garantie (fix 2026-06-11,
    tâche #14) : release_run → unregister_task → clear_progress, chaque
    étape isolée dans son try/except — un échec n'empêche pas les
    suivantes.

    Conçu pour être lancé comme Task INDÉPENDANTE depuis le finally du
    handler (``asyncio.create_task`` + ``shield``) : une cancellation
    ré-entrante du handler (2e clic Stop pendant le finally) n'atteint
    pas cette coroutine — les trois stores sont nettoyés dans tous les
    cas. L'ancien pattern (3 awaits shieldés successifs dans le finally,
    chacun suivi de ``except CancelledError: raise``) sautait les
    cleanups restants dès la première ré-entrance — exactement la fuite
    ``_tasks``/``_store`` qu'il prétendait empêcher.
    """
    try:
        await release_run(user_id, run_id, result=result)
    except Exception:  # noqa: BLE001
        logger.debug("finalize_run: release_run a levé", exc_info=True)
    try:
        await unregister_task(user_id, run_id, task=task)
    except Exception:  # noqa: BLE001
        logger.debug("finalize_run: unregister_task a levé", exc_info=True)
    try:
        await clear_progress(user_id, run_id)
    except Exception:  # noqa: BLE001
        logger.debug("finalize_run: clear_progress a levé", exc_info=True)


# Helpers de test / debug — pas utilisés en production.


async def _reset_for_tests() -> None:
    """Vide entièrement le store. Réservé aux tests unitaires."""
    async with _lock:
        _store.clear()
        _tasks.clear()
        _inflight.clear()
        _cancel_requested.clear()


async def _snapshot_for_tests() -> Dict[str, Dict[str, Any]]:
    """Retourne une copie du store complet. Réservé aux tests unitaires."""
    async with _lock:
        return copy.deepcopy(_store)
