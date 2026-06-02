"""Verrous per-user pour les opérations read-modify-write sur
``AnonymizationTerm`` (task #23 — finding #2 review adversariale task #20).

**Problème** : ``upsert_terms`` et ``replace_state`` font un cycle
``SELECT origins → merge en Python → UPSERT/UPDATE``. SQLite WAL ne
sérialise pas ce cycle Python (seuls les commits sont atomiques). Sous
concurrence (ex: 2 tabs Iris/datastore ouverts par le même user, ou
``asyncio.create_task`` de scan_sql_result_terms qui croise un
scan_workbook_terms en cours), 2 tâches lisent l'état ``{A}`` au même
moment puis chacune écrit ``{A, B}`` puis ``{A, C}`` — la 2ème écrasure
**perd ``B`` silencieusement**.

**Solution** : :class:`asyncio.Lock` per user_id, acquis dans les
fonctions read-modify-write (``upsert_terms``, ``replace_state``).
Garantit que pour UN user donné, ces opérations sont sérialisées dans
l'event loop Tornado.

**Réentrance via** :class:`contextvars.ContextVar` : ``replace_state``
appelle ``upsert_terms`` à l'intérieur de sa propre section critique ;
sans réentrance, on aurait un deadlock (``asyncio.Lock`` n'est pas
réentrant). On stocke le ``user_id`` actuellement détenu dans une
:class:`ContextVar` task-locale ; les call sites enfants qui voient
le même ``user_id`` sautent l'acquire (no-op safe).

**Scope du fix** : protège les paths ASYNC ↔ ASYNC dans l'event loop
Tornado (le cas le plus probable et impactant). Le job nightly
``cleanup_unused_anonymization_terms_job`` tourne SYNC dans un thread
APScheduler séparé — race orthogonale traitée par les transactions
SQLite-level (chaque session sync valide son own snapshot).
"""

from __future__ import annotations

import asyncio
import logging
import threading
import weakref
from contextlib import asynccontextmanager
from typing import AsyncIterator, Set, Tuple

from app.services.anonymization.user_id_guard import is_valid_user_id

logger = logging.getLogger(__name__)

#: Mapping ``user_id → asyncio.Lock`` via :class:`weakref.WeakValueDictionary`
#: (task #33). Cleanup automatique : dès que plus aucune coroutine ne tient
#: une référence forte à un lock (acquired OU en attente), le GC le ramasse
#: et l'entry est évincée du dict. Pas de growth non bornée
#: (axe Komptia #21).
#:
#: **Pourquoi WeakValueDictionary vs cleanup explicite** :
#:
#: - Aucun timer/sweep périodique à wire dans le scheduler.
#: - Pas de risque d'évincer un lock encore utilisé (le GC ne ramasse
#:   pas un objet avec ref-count > 0 ; la coroutine en cours a toujours
#:   une strong ref locale via la variable du context manager).
#: - Le pattern double-checked locking via ``_creation_lock`` (threading)
#:   reste correct : la lecture initiale tente le get, le miss prend le
#:   verrou méta puis re-check, et la création insère dans le WVD.
_user_locks: "weakref.WeakValueDictionary[int, asyncio.Lock]" = weakref.WeakValueDictionary()

#: Verrou méta thread-safe protégeant la création atomique d'une entrée
#: dans :data:`_user_locks`. ``threading.Lock`` plutôt qu'``asyncio.Lock``
#: pour 2 raisons :
#:
#: 1. Pas de couplage à un event loop spécifique au module-load (fix
#:    finding #2 review adversariale task #23) — ``asyncio.Lock()`` au
#:    module-load peut s'attacher au mauvais loop si le runtime redémarre
#:    le loop (tests asyncio.run multiples, scripts standalone).
#: 2. Le critical section est purement synchrone (dict get/set), pas
#:    besoin d'awaiter.
_creation_lock: threading.Lock = threading.Lock()

#: Set de ``(task_id, user_id)`` déjà détenus. Remplace l'ancienne
#: ContextVar (fix finding #3 review adversariale task #23 — ContextVar
#: est propagée à travers ``asyncio.gather`` via ``copy_context()``, ce
#: qui faisait que 2 children gather() voyaient ``_held == user_id`` et
#: sautaient le lock ⇒ race revenait silencieusement). Avec ``id(task)``
#: chaque Task créée par ``gather`` a son propre identifiant ⇒ pas de
#: réentrance accidentelle cross-task.
#:
#: Modifications uniquement depuis l'event loop asyncio (single-threaded),
#: donc pas besoin de protection thread-safe sur le set lui-même.
_held_pairs: Set[Tuple[int, int]] = set()


def _get_or_create_lock(user_id: int) -> asyncio.Lock:
    """Retourne le lock pour ``user_id``, en créant l'entrée si absente.

    Atomique grâce à :data:`_creation_lock` (threading.Lock, créé lazily
    à l'usage, pas au module-load) — sans ce verrou méta, on pourrait
    avoir 2 coroutines qui matchent simultanément le miss et créent 2
    locks différents → split-brain.

    ``asyncio.Lock()`` créé ici (vs au module-load) garantit qu'il
    s'attache au loop courant — important si Komptia run plusieurs
    event loops séquentiels (tests).
    """
    existing = _user_locks.get(user_id)
    if existing is not None:
        return existing
    with _creation_lock:
        existing = _user_locks.get(user_id)
        if existing is not None:
            return existing
        new_lock = asyncio.Lock()
        _user_locks[user_id] = new_lock
        return new_lock


def _current_task_id() -> int:
    """Retourne ``id(asyncio.current_task())`` ou ``0`` si pas dans un
    contexte asyncio Task (cas exotique sync). 2 Tasks distinctes ont
    forcément ``id`` distinct (CPython object identity)."""
    task = asyncio.current_task()
    return id(task) if task is not None else 0


@asynccontextmanager
async def acquire_user_anon_lock(user_id: int) -> AsyncIterator[None]:
    """Acquire le lock per-user pour les opérations read-modify-write
    sur ``anonymization_terms``.

    Usage::

        async with acquire_user_anon_lock(user_id):
            # SELECT ... UPDATE ... protégé contre les writers concurrents
            await upsert_terms(session, user_id, terms)

    **Réentrance correcte** : si la **MÊME Task asyncio** a déjà
    acquired ce lock (via un parent appel séquentiel), le `with` block
    est un no-op (pas de deadlock).

    **Pas de réentrance accidentelle via gather** : 2 children créés
    par ``asyncio.gather`` sont des Tasks DISTINCTES → leurs `task_id`
    diffèrent → chacune passe par le vrai acquire → sérialisation
    préservée. C'est le fix du finding #3 review : l'ancienne
    implémentation via ``ContextVar`` était propagée à travers
    ``copy_context()`` au moment du scheduling par gather, ce qui
    rendait les children "réentrantes" et cassait la sérialisation.

    Args:
        user_id: identifiant utilisateur. Si ``<= 0`` ou ``None``, le
            ``with`` block est no-op (rien à protéger côté user-scoped).
            Un caller qui passe une valeur **non-int** (ex: ``"1"`` non
            casté) reçoit un WARNING log — defense-in-depth, le caller
            doit fixer son code en amont.
    """
    # task #38 : helper partagé pour validation user_id (exclut bool
    # malgré isinstance(True, int) == True). Log warning explicite si
    # un caller négligent passe une mauvaise valeur — defense-in-depth.
    if not is_valid_user_id(user_id):
        if user_id is not None and user_id != 0:
            logger.warning(
                "acquire_user_anon_lock: user_id invalide (%r, type=%s), "
                "lock skipped — caller doit fournir un int strictement positif",
                user_id,
                type(user_id).__name__,
            )
        yield
        return

    task_id = _current_task_id()
    pair = (task_id, user_id)

    if pair in _held_pairs:
        # Réentrance même Task → no-op safe.
        yield
        return

    lock = _get_or_create_lock(user_id)
    async with lock:
        _held_pairs.add(pair)
        try:
            yield
        finally:
            _held_pairs.discard(pair)


def _testing_reset_state() -> None:
    """Reset interne pour les tests unitaires — vide le registry des
    locks et le set de réentrance. Ne JAMAIS appeler hors tests : ferait
    perdre la sérialisation en cours."""
    _user_locks.clear()
    _held_pairs.clear()
