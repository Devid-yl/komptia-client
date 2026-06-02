"""Retry helper pour ``sqlite3.OperationalError: database is locked``.

Contexte
--------
Avec ``SQLite + WAL + NullPool`` (cf. ``app/core/database.py``), un seul
writer peut écrire à la fois. Le ``busy_timeout`` (30 s) couvre la majorité
des contentions transitoires, mais quand une session tient une transaction
en écriture le temps d'un appel LLM ou d'un traitement lourd, les writes
courts (audit_logs, user_activity_summary) tombent en
``OperationalError: database is locked`` et finissent en HTTP 500 pour
l'utilisateur.

Ce module fournit un retry exponentiel pour **wraper les writes idempotents**
afin qu'ils survivent à une contention brève sans propager d'erreur à
l'utilisateur.

Quand l'utiliser
----------------
- ✅ INSERT idempotent (``ON CONFLICT DO NOTHING`` / ``ON CONFLICT … UPDATE``)
- ✅ UPDATE idempotent (positionne une valeur sans dépendre de l'état précédent)
- ✅ DELETE par clé (idempotent : déjà supprimé = no-op)
- ✅ Audit log (perdre 1 ligne sur N retries-failed est acceptable)
- ❌ INSERT non-idempotent qui ferait des doublons (commande user, paiement…)
- ❌ Opération qui dépend du résultat d'une lecture précédente dans la même
  transaction (le retry recrée la coro, donc la lecture est rejouée — peut
  produire une valeur différente)

Le retry ne masque PAS les autres erreurs : seul ``database is locked``
(et ``database table is locked``) est retryé. Tout autre ``OperationalError``
est propagé immédiatement.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Awaitable, Callable, TypeVar

from sqlalchemy.exc import OperationalError

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Marqueurs SQLite pour identifier le "lock transitoire" vs une autre
# ``OperationalError`` (qui ne doit PAS être retryée — schéma invalide,
# colonne manquante, etc.). Comparé en minuscules.
_LOCKED_MARKERS: tuple[str, ...] = (
    "database is locked",
    "database table is locked",
)


def _is_locked_error(exc: BaseException) -> bool:
    """Vrai si ``exc`` est une ``OperationalError`` indiquant un lock transitoire.

    Inspecte ``exc.orig`` (la cause DB-API, contient le vrai message
    SQLite) en priorité ; fallback sur le ``.args`` ou ``repr`` si
    l'exception est mal formée (cas adversarial / test). On ne
    ``str(exc)`` PAS direct : SQLAlchemy ≥ 2.0 a une représentation
    riche qui peut crasher si l'objet n'a pas été instancié via le
    constructeur normal (cf. test ``test_handles_missing_orig``).
    """
    if not isinstance(exc, OperationalError):
        return False
    raw = getattr(exc, "orig", None)
    if raw is not None:
        try:
            msg = str(raw).lower()
        except Exception:  # noqa: BLE001 — défense en profondeur
            msg = repr(raw).lower()
    else:
        # Pas d'``orig`` (cas rare) — lire ``args`` qui est toujours présent
        # sur BaseException, plutôt que ``str(exc)`` qui peut crasher.
        try:
            msg = " ".join(str(a) for a in (exc.args or ())).lower()
        except Exception:  # noqa: BLE001
            msg = repr(exc).lower()
    return any(marker in msg for marker in _LOCKED_MARKERS)


async def retry_on_locked(
    coro_factory: Callable[[], Awaitable[T]],
    *,
    max_attempts: int = 3,
    base_delay_s: float = 0.1,
    max_delay_s: float = 2.0,
    operation_name: str = "db-write",
) -> T:
    """Exécute ``coro_factory()`` avec retry exponentiel sur "database is locked".

    Le caller passe un **factory** (lambda qui retourne une coroutine) et
    non une coroutine déjà créée — une coroutine ne peut être awaited qu'une
    seule fois. Le factory est invoqué frais à chaque tentative.

    Backoff : ``base_delay_s * 2^(attempt-1)``, capé à ``max_delay_s``,
    avec jitter ×[1.0, 2.0) pour éviter la résonance entre callers
    concurrents.

    Lève la dernière ``OperationalError`` si toutes les tentatives échouent.
    Toute autre exception (schéma invalide, IntegrityError, etc.) est
    propagée immédiatement sans retry.

    Args:
        coro_factory: ``lambda: my_async_op()`` — chaque appel crée une
            nouvelle coroutine fraîche.
        max_attempts: Nombre total de tentatives (incluant la première).
            Doit être ≥ 1.
        base_delay_s: Délai de base avant le 1er retry (après le 1er échec).
        max_delay_s: Délai max après backoff (cap dur).
        operation_name: Label pour les logs — identifie l'opération en cas
            de retry / abandon.

    Returns:
        Le résultat de ``coro_factory()`` à la première tentative qui réussit.
    """
    if max_attempts < 1:
        raise ValueError(f"max_attempts must be >= 1, got {max_attempts}")

    last_exc: OperationalError | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return await coro_factory()
        except OperationalError as exc:
            if not _is_locked_error(exc):
                # Autre OperationalError (schéma invalide, syntax…) — ne pas
                # retry, propager direct.
                raise
            last_exc = exc
            if attempt >= max_attempts:
                logger.warning(
                    "retry_on_locked: abandon de %s après %d tentatives "
                    "(database is locked persiste)",
                    operation_name,
                    attempt,
                )
                raise
            delay = min(max_delay_s, base_delay_s * (2 ** (attempt - 1)))
            # Jitter dans [1.0, 2.0) — évite la résonance entre callers concurrents.
            delay = delay * (1.0 + random.random())
            logger.info(
                "retry_on_locked: %s locked (tentative %d/%d), retry dans %.0f ms",
                operation_name,
                attempt,
                max_attempts,
                delay * 1000,
            )
            await asyncio.sleep(delay)

    # Unreachable — la boucle ci-dessus return ou raise avant d'arriver ici.
    assert last_exc is not None
    raise last_exc


__all__ = ["retry_on_locked", "_is_locked_error"]
