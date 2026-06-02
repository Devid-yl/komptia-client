"""Service de tracking d'activité utilisateur — alimente
``UserActivitySummary`` qui sert aux triggers comportementaux (T3.2) et
au dashboard ``/admin/onboarding-metrics`` (T3.3).

Doctrine sénior :

1. **UPSERT atomique avec throttle in-memory**. Le hook ``BaseHandler.prepare()``
   est appelé à CHAQUE requête HTTP authentifiée. Faire un UPSERT BDD par
   requête est coûteux (à 100 req/s = 100 UPSERT/s). On cache en mémoire
   ``user_id -> last_seen_at_local`` et on ne re-pousse en BDD que si la
   dernière écriture date de plus de ``_THROTTLE_SECONDS``. Réduit
   typiquement de ~99 % les écritures.

2. **Best-effort, ne casse jamais la requête principale**. Tous les
   tracking calls sont wrappés en ``try/except`` côté caller. La perte
   d'un update d'activity ne doit jamais provoquer un 5xx au client.

3. **Lazy-create**. La première écriture pour un user inconnu crée la
   ligne. Pas de backfill au boot — les users existants sont matérialisés
   à leur prochain accès authentifié.

4. **Counters monotones**. ``track_iris_query`` etc. utilisent
   ``total_iris_queries = total_iris_queries + 1`` côté SQL pour
   incrémenter atomiquement, jamais une lecture+écriture côté Python
   (race condition multi-process).

5. **Cleanup via CASCADE + filet de sécurité**. La suppression d'un User
   cascade vers ``user_activity_summary`` (FK ondelete). Le job
   ``cleanup_orphan_activity_summaries_sync`` est un filet de sécurité
   pour les éventuels orphelins (race condition au DELETE manuel SQL).
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from datetime import datetime
from app.core import clock
from typing import Final, Optional

from sqlalchemy import delete, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.user_activity_summary import UserActivitySummary
from app.services.anonymization.user_id_guard import is_valid_user_id

logger = logging.getLogger("komptia." + __name__)

# Throttle des updates ``last_seen_at`` : on n'écrit en BDD que si la
# dernière écriture pour cet user date de plus de ce délai. 60 secondes
# garde une bonne résolution pour les triggers (« inactif depuis 7 jours »
# ne perd rien à une granularité de la minute) tout en évitant un UPSERT
# par clic. À 100 req/s pour 10 users actifs : 10/60 ≈ 0.17 UPSERT/s
# au lieu de 100. Réduction × 600.
_THROTTLE_SECONDS: Final[float] = 60.0

# Plafond mémoire du cache de throttle (axe 21 Komptia : pas de croissance
# non bornée). Au-delà de ce nombre d'entrées, le check effectue un GC
# opportuniste qui supprime les entrées dont la dernière écriture date
# de plus de 2× la fenêtre de throttle (donc devenues inutiles).
_MAX_CACHE_SIZE: Final[int] = 10000

# Cache thread-safe ``user_id -> dernier flush_at (epoch monotonic float)``.
# ``RLock`` pour permettre les call sites qui pourraient ré-entrer
# (théoriquement improbable mais défensif). Borné par ``_MAX_CACHE_SIZE``
# avec éviction des entrées stales.
_last_flush_at: dict[int, float] = {}
_last_flush_lock = threading.RLock()

# Set des fire-and-forget tasks créées par :func:`spawn_upsert_last_seen` —
# référence forte requise sur Python 3.12+ pour empêcher le GC de
# collecter une ``asyncio.Task`` avant sa complétion (cf. doc CPython
# ``asyncio.create_task`` — l'event loop ne garde qu'une weakref).
# Chaque task installe son propre ``done_callback`` qui ``discard`` la
# task pour ne pas leaker la mémoire.
_pending_upserts: set[asyncio.Task] = set()


def _utcnow() -> datetime:
    """Timestamp UTC-aware partagé pour cohérence intra-call.

    Délègue à la source de vérité unique :func:`app.core.clock.now`. Conservé
    comme alias local (utilisé ~9 fois dans ce module) — un seul point de routage.
    """
    return clock.now()


def _should_skip_throttled(user_id: int) -> bool:
    """Retourne ``True`` si on a déjà flushé cet user récemment.

    Marque le user comme flushé si on retourne ``False`` (pas skip) —
    c'est une opération conjointe check-and-set pour éviter une race
    entre deux callers qui passeraient simultanément le check.

    Effectue un GC opportuniste quand le cache dépasse ``_MAX_CACHE_SIZE``
    pour borner la mémoire (axe 21 Komptia).
    """
    now = time.monotonic()
    with _last_flush_lock:
        last = _last_flush_at.get(user_id)
        if last is not None and (now - last) < _THROTTLE_SECONDS:
            return True
        # GC opportuniste : si le cache déborde, purge les entrées trop
        # vieilles (déjà passées la fenêtre de throttle × 2) avant
        # d'insérer la nouvelle. Pas de pénalité hot path (déclenché
        # seulement à la saturation).
        if len(_last_flush_at) >= _MAX_CACHE_SIZE:
            cutoff = now - _THROTTLE_SECONDS * 2
            stale_keys = [k for k, v in _last_flush_at.items() if v < cutoff]
            for k in stale_keys:
                del _last_flush_at[k]
            # Fallback ultime : si toutes les entrées sont encore fraîches
            # (rare — explosion d'users actifs simultanés), on retire le
            # plus ancien pour faire de la place.
            if len(_last_flush_at) >= _MAX_CACHE_SIZE:
                oldest_key = min(_last_flush_at, key=_last_flush_at.get)
                del _last_flush_at[oldest_key]
        _last_flush_at[user_id] = now
        return False


def should_update_last_seen(user_id: int) -> bool:
    """Check-and-set du throttle in-memory — API publique.

    Retourne ``True`` si on doit pousser un UPSERT BDD pour cet user
    (premier appel ou fenêtre de throttle écoulée). Retourne ``False``
    si on doit skip silencieusement.

    Conçu pour être appelé par ``BaseHandler.prepare()`` AVANT d'ouvrir
    une session BDD : si retourne ``False``, on évite l'overhead
    d'acquisition de session pour rien. La check-and-set est atomique
    (deux callers concurrents pour le même user_id ne passent pas tous
    les deux).

    **Note 2026-05-22** : pour le pattern fire-and-forget, préférer
    :func:`spawn_upsert_last_seen` qui set le throttle APRÈS commit OK
    (évite la perte d'écriture si la task background échoue).
    """
    return not _should_skip_throttled(user_id)


def _should_skip_throttled_no_set(user_id: int) -> bool:
    """Variante de :func:`_should_skip_throttled` qui ne SET PAS le cache.

    Utilisée par :func:`spawn_upsert_last_seen` : on veut savoir si on
    devrait flusher, sans poser le throttle (qui sera posé via
    :func:`_mark_flushed` après commit BDD réussi). Sinon une task qui
    crash/timeout AVALE l'écriture silencieusement pendant 60 s.
    """
    now = time.monotonic()
    with _last_flush_lock:
        last = _last_flush_at.get(user_id)
        if last is not None and (now - last) < _THROTTLE_SECONDS:
            return True
        return False


def _mark_flushed(user_id: int) -> None:
    """Pose le throttle APRÈS un commit BDD réussi.

    À appeler par les callers qui utilisent :func:`_should_skip_throttled_no_set`
    : check sans set, commit, mark_flushed. Si le commit échoue, on
    ne mark PAS → la prochaine requête retentera.
    """
    with _last_flush_lock:
        # GC opportuniste si le cache déborde (cohérent avec
        # ``_should_skip_throttled``).
        if len(_last_flush_at) >= _MAX_CACHE_SIZE:
            now = time.monotonic()
            cutoff = now - _THROTTLE_SECONDS * 2
            stale_keys = [k for k, v in _last_flush_at.items() if v < cutoff]
            for k in stale_keys:
                del _last_flush_at[k]
            if len(_last_flush_at) >= _MAX_CACHE_SIZE:
                # Pas de marquage si plein — on accepte un double-write
                # plutôt que de virer un autre user au hasard. Très rare.
                return
        _last_flush_at[user_id] = time.monotonic()


def spawn_upsert_last_seen(user_id: int) -> Optional[asyncio.Task]:
    """Crée et stocke une task fire-and-forget pour UPSERT ``last_seen_at``.

    Pattern complet et safe :

    1. Check throttle sans set (``_should_skip_throttled_no_set``).
       Retourne ``None`` si throttled (skip silencieux).
    2. Crée la task via ``asyncio.create_task`` avec un nom debug.
    3. **Stocke la task dans ``_pending_upserts``** — référence forte
       qui empêche Python 3.12+ de GC la task avant complétion (cf.
       review adversariale 2026-05-22 BLOCKING C1). Sans ce stockage,
       une task non-référencée peut être collectée silencieusement.
    4. Pose un ``done_callback(_pending_upserts.discard)`` pour libérer
       la référence à la complétion (pas de fuite mémoire).
    5. La task elle-même (``upsert_last_seen_background``) pose
       ``_mark_flushed(user_id)`` APRÈS un commit réussi — pas avant
       (fix C3 review : sinon la première requête set le throttle, la
       task crash, et 60 s d'écritures sont perdues).

    Retourne la ``Task`` créée (ou ``None`` si throttled) — utile pour
    les tests qui veulent l'awaiter. Le caller production ne doit PAS
    awaiter (sinon on perd le bénéfice fire-and-forget).

    **Cas dégradé important** : si l'event loop est en shutdown, le
    ``asyncio.create_task`` peut lever ``RuntimeError`` ("no running
    event loop"). On catch et logue en DEBUG — le tracking d'activité
    n'est PAS critique au shutdown.
    """
    if not is_valid_user_id(user_id):
        return None
    if _should_skip_throttled_no_set(user_id):
        return None
    try:
        task = asyncio.create_task(
            upsert_last_seen_background(user_id),
            name=f"activity_tracker_upsert_user_{user_id}",
        )
    except RuntimeError:
        # Event loop en shutdown ou non démarré — skip silencieusement.
        logger.debug(
            "spawn_upsert_last_seen user_id=%s : pas d'event loop (shutdown ?), skip",
            user_id,
        )
        return None
    _pending_upserts.add(task)
    task.add_done_callback(_pending_upserts.discard)
    return task


def _reset_throttle_cache() -> None:
    """Vide le cache de throttle ET le set des tasks pendantes — tests.

    Marqueur sentinel ``_test_only`` (vérifié par les tests) pour éviter
    un appel accidentel en prod. Si tu vois ce nom apparaître dans un
    handler ou un service, c'est un bug.
    """
    with _last_flush_lock:
        _last_flush_at.clear()
    # ``_pending_upserts`` n'est PAS thread-safe en lecture, mais on
    # est appelé en setUp/teardown de tests qui contrôlent la concurrence.
    # On annule les éventuelles tasks pendantes pour ne pas leaker entre
    # tests.
    pending_snapshot = list(_pending_upserts)
    _pending_upserts.clear()
    for task in pending_snapshot:
        if not task.done():
            task.cancel()


_reset_throttle_cache._test_only = True  # type: ignore[attr-defined]


# -----------------------------------------------------------------------------
# API publique — updates async
# -----------------------------------------------------------------------------


async def update_last_seen(session: AsyncSession, user_id: int) -> None:
    """Pose ``last_seen_at = NOW`` (et ``first_seen_at`` si la ligne est
    nouvelle).

    Wrapper convenience : check le throttle in-memory puis fait l'UPSERT
    si le throttle laisse passer. Si tu veux contrôler le timing
    d'acquisition de la session BDD (typiquement depuis un hook qui
    n'ouvre la session que si nécessaire), appelle d'abord
    ``should_update_last_seen(user_id)`` puis ``_upsert_last_seen``
    directement — voir ``BaseHandler.prepare()`` pour le pattern.
    """
    if not should_update_last_seen(user_id):
        return
    await _upsert_last_seen(session, user_id)


async def _upsert_last_seen(session: AsyncSession, user_id: int) -> None:
    """UPSERT brut sans throttle — réservé aux callers qui ont déjà fait
    leur propre check via ``should_update_last_seen``."""
    now = _utcnow()
    stmt = (
        sqlite_insert(UserActivitySummary)
        .values(user_id=user_id, first_seen_at=now, last_seen_at=now)
        .on_conflict_do_update(
            index_elements=["user_id"],
            set_={"last_seen_at": now},
        )
    )
    await session.execute(stmt)


async def upsert_last_seen_background(user_id: int) -> None:
    """Wrapper fire-and-forget pour ``_upsert_last_seen`` — ouvre sa propre
    session BDD et avale silencieusement les erreurs (notamment
    ``database is locked``).

    Conçu pour être lancé via :func:`spawn_upsert_last_seen` depuis
    :meth:`BaseHandler.prepare()` afin que le UPSERT ne bloque PAS la
    requête métier en cas de contention BDD (incident /stats à 31 s du
    2026-05-22 : un improve-pseudo qui tient le writer SQLite faisait
    attendre prepare() pendant ``busy_timeout=30s``).

    **Garanties fail-soft** :

    - Toute exception est attrapée et loggée en DEBUG (pas d'unhandled
      task exception qui spammerait les logs).
    - Le caller ne voit jamais d'erreur — la task est totalement
      découplée de la requête HTTP.
    - **``_mark_flushed`` n'est appelé QUE sur commit réussi** (fix C3
      review adversariale 2026-05-22) — sinon la première requête set
      le throttle, la task crash, et 60 s d'écritures sont perdues.
    """
    # Import local — évite cycle import et n'est payé qu'à la 1ʳᵉ
    # invocation par worker (puis Python cache le module).
    from app.core.database import get_session

    try:
        async with get_session() as session:
            await _upsert_last_seen(session, user_id)
            # ``get_session`` commit automatiquement à la sortie du CM,
            # mais le commit n'a pas encore eu lieu ici (sortie de bloc).
        # ``_mark_flushed`` SEULEMENT après que le CM ait commité avec
        # succès. Si l'exception survient pendant le commit
        # (``database is locked``), on saute cette ligne → la prochaine
        # requête retentera.
        _mark_flushed(user_id)
    except Exception:  # noqa: BLE001 — fail-soft total
        logger.debug(
            "upsert_last_seen_background user_id=%s : ignoré (BDD lockée ou autre)",
            user_id,
            exc_info=True,
        )


async def track_iris_query(session: AsyncSession, user_id: int) -> None:
    """Incrémente ``total_iris_queries`` + met à jour ``last_iris_query_at``.

    Pas de throttle — chaque query Iris est un événement métier qu'on
    veut compter exactement. À appeler depuis le handler/service Iris
    une fois la query effectivement exécutée (pas au moment de la
    réception du WebSocket message).
    """
    table = UserActivitySummary.__table__
    now = _utcnow()
    stmt = (
        sqlite_insert(UserActivitySummary)
        .values(
            user_id=user_id,
            first_seen_at=now,
            last_seen_at=now,
            last_iris_query_at=now,
            total_iris_queries=1,
        )
        .on_conflict_do_update(
            index_elements=["user_id"],
            set_={
                "last_seen_at": now,
                "last_iris_query_at": now,
                "total_iris_queries": table.c.total_iris_queries + 1,
            },
        )
    )
    await session.execute(stmt)


async def track_automation_created(session: AsyncSession, user_id: int) -> None:
    """Incrémente ``total_automations_created``. À appeler après le commit
    de l'automation."""
    table = UserActivitySummary.__table__
    now = _utcnow()
    stmt = (
        sqlite_insert(UserActivitySummary)
        .values(
            user_id=user_id,
            first_seen_at=now,
            last_seen_at=now,
            total_automations_created=1,
        )
        .on_conflict_do_update(
            index_elements=["user_id"],
            set_={
                "last_seen_at": now,
                "total_automations_created": table.c.total_automations_created + 1,
            },
        )
    )
    await session.execute(stmt)


async def track_automation_run(session: AsyncSession, user_id: int) -> None:
    """Met à jour ``last_automation_run_at`` (pas de compteur dédié)."""
    now = _utcnow()
    stmt = (
        sqlite_insert(UserActivitySummary)
        .values(
            user_id=user_id,
            first_seen_at=now,
            last_seen_at=now,
            last_automation_run_at=now,
        )
        .on_conflict_do_update(
            index_elements=["user_id"],
            set_={"last_seen_at": now, "last_automation_run_at": now},
        )
    )
    await session.execute(stmt)


async def track_report_generated(session: AsyncSession, user_id: int) -> None:
    """Incrémente ``total_reports_generated`` + maj ``last_report_generated_at``."""
    table = UserActivitySummary.__table__
    now = _utcnow()
    stmt = (
        sqlite_insert(UserActivitySummary)
        .values(
            user_id=user_id,
            first_seen_at=now,
            last_seen_at=now,
            last_report_generated_at=now,
            total_reports_generated=1,
        )
        .on_conflict_do_update(
            index_elements=["user_id"],
            set_={
                "last_seen_at": now,
                "last_report_generated_at": now,
                "total_reports_generated": table.c.total_reports_generated + 1,
            },
        )
    )
    await session.execute(stmt)


async def track_dashboard_viewed(session: AsyncSession, user_id: int) -> None:
    """Met à jour ``last_dashboard_viewed_at`` (pas de compteur dédié —
    le nombre de vues d'un dashboard se mesure côté analytics, pas
    côté résumé d'activité utilisateur)."""
    now = _utcnow()
    stmt = (
        sqlite_insert(UserActivitySummary)
        .values(
            user_id=user_id,
            first_seen_at=now,
            last_seen_at=now,
            last_dashboard_viewed_at=now,
        )
        .on_conflict_do_update(
            index_elements=["user_id"],
            set_={"last_seen_at": now, "last_dashboard_viewed_at": now},
        )
    )
    await session.execute(stmt)


async def mark_nudged(session: AsyncSession, user_id: int) -> None:
    """Met à jour ``last_nudged_at`` à NOW. Appelé par le job de
    behavioral triggers (T3.2) après l'envoi d'un nudge (toast, email)
    pour respecter le throttle 1 nudge / 7 jours / user."""
    now = _utcnow()
    stmt = (
        sqlite_insert(UserActivitySummary)
        .values(
            user_id=user_id,
            first_seen_at=now,
            last_seen_at=now,
            last_nudged_at=now,
        )
        .on_conflict_do_update(
            index_elements=["user_id"],
            set_={"last_seen_at": now, "last_nudged_at": now},
        )
    )
    await session.execute(stmt)


# -----------------------------------------------------------------------------
# Lectures pour T3.2 (triggers) et T3.3 (dashboard)
# -----------------------------------------------------------------------------


async def get_dormant_users(
    session: AsyncSession, inactive_days: int, nudge_throttle_days: int = 7
) -> list[int]:
    """Retourne les user_ids inactifs depuis ``inactive_days`` jours, qui
    n'ont pas reçu de nudge dans les ``nudge_throttle_days`` derniers jours.

    Utilisé par T3.2 (behavioral_triggers). Retourne uniquement les
    user_ids — le caller fera la traduction en email/canal lui-même.
    """
    from datetime import timedelta

    now = _utcnow()
    threshold_seen = now - timedelta(days=inactive_days)
    threshold_nudge = now - timedelta(days=nudge_throttle_days)
    result = await session.execute(
        select(UserActivitySummary.user_id).where(
            UserActivitySummary.last_seen_at < threshold_seen,
            (UserActivitySummary.last_nudged_at.is_(None))
            | (UserActivitySummary.last_nudged_at < threshold_nudge),
        )
    )
    return list(result.scalars().all())


# -----------------------------------------------------------------------------
# Job de cleanup — APScheduler sync (pattern emprunté à
# ``_purge_idempotency_logs_sync`` dans ``app/services/automation/scheduler.py``)
# -----------------------------------------------------------------------------


def cleanup_orphan_activity_summaries_sync() -> int:
    """Job sync APScheduler — supprime les lignes ``user_activity_summary``
    dont le ``user_id`` ne correspond à aucun user.

    Normalement la suppression est en cascade via la FK ``ondelete=
    "CASCADE"``. Ce job est un filet de sécurité pour les rares cas où
    un orphelin pourrait apparaître (DELETE SQL direct contournant
    l'ORM, restauration partielle d'un dump, etc.).

    Retourne le nombre de lignes supprimées (pour log/monitoring).
    Sync car APScheduler crée son propre engine.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from app.core.database import get_db_url

    try:
        engine = create_engine(get_db_url())
        try:
            with Session(engine) as session:
                # Supprime les rows dont user_id n'est pas dans users.id.
                subquery = select(User.id)
                stmt = delete(UserActivitySummary).where(
                    UserActivitySummary.user_id.not_in(subquery)
                )
                result = session.execute(stmt)
                deleted = result.rowcount or 0
                if deleted:
                    session.commit()
                    logger.info(
                        "cleanup_orphan_activity_summaries: %d ligne(s) supprimée(s)",
                        deleted,
                    )
                return deleted
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 — job de fond, ne doit jamais propager
        logger.exception("cleanup_orphan_activity_summaries a échoué")
        return 0
