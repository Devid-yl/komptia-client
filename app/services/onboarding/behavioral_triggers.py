"""Behavioral triggers (T3.2) — identifie les utilisateurs à nudger et
consomme le throttle ``last_nudged_at`` pour respecter le contrat
« 1 nudge max par user par 7 jours, tous canaux confondus ».

Critères d'évaluation (toutes les fonctions retournent ``list[int]`` —
des ``user_id`` à nudger) :

- ``evaluate_dormant_general(session)`` : ``last_seen_at`` > 14j et pas
  nudgé récemment. Candidats principaux pour un email résumé.
- ``evaluate_dormant_iris(session)`` : user actif (first_seen < 3j ago)
  mais qui n'a JAMAIS posé de question à Iris (`last_iris_query_at IS
  NULL`). Candidats pour un toast au prochain login.
- ``evaluate_admin_no_user_invited(session)`` : admin avec welcome
  franchi > 7j mais aucun user non-admin créé. Candidats pour un email
  de rappel.

Toutes les évaluations excluent les users déjà nudgés dans les 7
derniers jours via ``get_dormant_users`` (ou check explicite sur
``last_nudged_at``).

Doctrine sénior :

1. **Plomberie pure, pas d'UI**. Ce module IDENTIFIE et MARQUE
   (``mark_nudged``). L'affichage côté UI (toast au login, email) est
   la responsabilité de modules séparés (T3.x phase 2). Cette séparation
   permet de tester le ciblage sans dépendre du canal.

2. **Throttle global** : ``last_nudged_at`` est global, peu importe le
   canal (toast, email, push). Un user déjà nudgé par toast aujourd'hui
   ne recevra pas d'email demain. Évite la sur-sollicitation.

3. **Job APScheduler sync** : pattern emprunté à
   ``cleanup_orphan_activity_summaries_sync`` (T3.1). Engine sync séparé
   pour ne pas dépendre de l'event loop async Tornado.

4. **Best-effort**. Une erreur sur l'évaluation d'un trigger ne casse
   pas les autres. Le job retourne des stats agrégées pour monitoring.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from app.core import clock
from typing import Final

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User, UserRole
from app.models.user_activity_summary import UserActivitySummary

logger = logging.getLogger("komptia." + __name__)

# Seuils des triggers. Constants explicites pour ne pas dupliquer la
# logique entre l'évaluation et l'affichage UI futur.
_INACTIVE_DAYS_DORMANT: Final[int] = 14
_ACTIVE_DAYS_BUT_NO_IRIS: Final[int] = 3
_ADMIN_SETUP_REMINDER_DAYS: Final[int] = 7
_NUDGE_THROTTLE_DAYS: Final[int] = 7


def _utcnow() -> datetime:
    """Délègue à la source unique :func:`app.core.clock.now` (alias local, ~4 appelants)."""
    return clock.now()


def _not_nudged_recently(threshold_nudge: datetime):
    """Construit le prédicat SQL ``last_nudged_at IS NULL OR < threshold``."""
    return or_(
        UserActivitySummary.last_nudged_at.is_(None),
        UserActivitySummary.last_nudged_at < threshold_nudge,
    )


# -----------------------------------------------------------------------------
# Critères d'évaluation
# -----------------------------------------------------------------------------


async def evaluate_dormant_general(session: AsyncSession) -> list[int]:
    """Users dormants depuis 14+ jours, pas nudgés dans les 7 derniers jours.

    Candidats pour un email résumé hebdo (« Cette semaine sur Komptia :
    12 rapports générés, 3 nouvelles automations »). L'envoi effectif
    est hors-scope T3.2.
    """
    now = _utcnow()
    threshold_seen = now - timedelta(days=_INACTIVE_DAYS_DORMANT)
    threshold_nudge = now - timedelta(days=_NUDGE_THROTTLE_DAYS)

    stmt = select(UserActivitySummary.user_id).where(
        UserActivitySummary.last_seen_at < threshold_seen,
        _not_nudged_recently(threshold_nudge),
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def evaluate_dormant_iris(session: AsyncSession) -> list[int]:
    """Users récemment créés (≥ 3j) qui n'ont JAMAIS posé de question à Iris.

    Candidats pour un toast au prochain login : « Vous n'avez pas encore
    essayé Iris. Voici un exemple en 30 secondes ? ». Filtre les nudges
    récents pour respecter le throttle 7j.
    """
    now = _utcnow()
    threshold_first = now - timedelta(days=_ACTIVE_DAYS_BUT_NO_IRIS)
    threshold_nudge = now - timedelta(days=_NUDGE_THROTTLE_DAYS)

    stmt = select(UserActivitySummary.user_id).where(
        and_(
            UserActivitySummary.first_seen_at < threshold_first,
            UserActivitySummary.last_iris_query_at.is_(None),
            _not_nudged_recently(threshold_nudge),
        )
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def evaluate_admin_no_user_invited(session: AsyncSession) -> list[int]:
    """Admins qui ont vu la checklist depuis 7+ jours mais n'ont créé
    aucun user non-admin.

    Candidats pour un email de rappel : « Komptia est configurée mais
    personne d'autre n'y a accès ». Le critère « pas de user non-admin »
    est vérifié via la présence d'au moins un user avec role != ADMIN.

    Renvoie les user_id des **admins** à nudger (pas les users invités —
    ils n'existent justement pas).
    """
    now = _utcnow()
    threshold_nudge = now - timedelta(days=_NUDGE_THROTTLE_DAYS)
    threshold_setup = now - timedelta(days=_ADMIN_SETUP_REMINDER_DAYS)

    # Y a-t-il au moins un user non-admin ?
    non_admin_count = (
        await session.execute(
            select(func.count()).select_from(User).where(User.role != UserRole.ADMIN)
        )
    ).scalar() or 0
    if non_admin_count > 0:
        return []  # Au moins un user existe → pas de rappel

    # Admins actifs depuis 7+ jours qu'on n'a pas encore nudgés.
    stmt = (
        select(UserActivitySummary.user_id)
        .join(User, User.id == UserActivitySummary.user_id)
        .where(
            User.role == UserRole.ADMIN,
            UserActivitySummary.first_seen_at < threshold_setup,
            _not_nudged_recently(threshold_nudge),
        )
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


# -----------------------------------------------------------------------------
# Orchestrator async (testable) + wrapper sync (APScheduler)
# -----------------------------------------------------------------------------


async def run_daily_triggers(session: AsyncSession) -> dict[str, int]:
    """Évalue tous les triggers et marque les users sélectionnés comme
    nudgés. Best-effort par-trigger (un trigger qui échoue ne bloque
    pas les autres).

    Retourne ``{"dormant_general": N, "dormant_iris": M, "admin_no_user": K,
    "total_nudged": T}`` pour log/monitoring.

    L'envoi effectif des nudges (toast, email) n'est PAS dans ce module.
    Ce travail marque uniquement ``last_nudged_at`` côté BDD ; l'affichage
    devra être fait par un module dédié au canal (frontend toast handler,
    email service) qui RELIT les listes via les fonctions ``evaluate_*``
    juste après ce job.

    Pour le MVP T3.2 : on consomme le throttle (mark_nudged) sans envoyer
    réellement les nudges. Les triggers sont prêts ; brancher l'UI vient
    dans la phase suivante.
    """
    from app.services.onboarding.activity_tracker import mark_nudged

    stats = {
        "dormant_general": 0,
        "dormant_iris": 0,
        "admin_no_user": 0,
        "total_nudged": 0,
    }
    # Set de ``user_id`` déjà nudgés pendant cette run. Permet aux triggers
    # 2 et 3 de filtrer les users déjà ciblés par un trigger précédent
    # (un dormant général n'a pas besoin d'un 2e nudge "no_iris" le même
    # jour). Évite la duplication intra-run.
    nudged_this_run: set[int] = set()

    async def _apply_trigger(name: str, evaluator) -> int:
        """Helper : évalue, filtre les déjà-nudgés, marque, retourne count."""
        try:
            candidates = await evaluator(session)
        except Exception:  # noqa: BLE001
            logger.exception("trigger %s a échoué à l'évaluation", name)
            return 0
        new_targets = [uid for uid in candidates if uid not in nudged_this_run]
        for uid in new_targets:
            try:
                await mark_nudged(session, uid)
                nudged_this_run.add(uid)
            except Exception:  # noqa: BLE001
                logger.exception("mark_nudged a échoué pour user_id=%s", uid)
        return len(new_targets)

    stats["dormant_general"] = await _apply_trigger(
        "evaluate_dormant_general", evaluate_dormant_general
    )
    stats["dormant_iris"] = await _apply_trigger("evaluate_dormant_iris", evaluate_dormant_iris)
    stats["admin_no_user"] = await _apply_trigger(
        "evaluate_admin_no_user_invited", evaluate_admin_no_user_invited
    )

    await session.commit()
    stats["total_nudged"] = len(nudged_this_run)
    return stats


def run_daily_triggers_sync() -> dict[str, int]:
    """Wrapper sync pour APScheduler — crée son propre engine + boucle async.

    ``run_daily_triggers`` exige un ``AsyncSession`` ; on utilise donc
    ``get_database_url`` (driver ``aiosqlite``), PAS ``get_db_url`` qui
    sert au jobstore APScheduler synchrone. ``asyncio.run`` isole la
    boucle async du thread APScheduler.
    """
    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.core.database import get_database_url

    async def _runner() -> dict[str, int]:
        engine = create_async_engine(get_database_url())
        try:
            factory = async_sessionmaker(engine, expire_on_commit=False)
            async with factory() as session:
                return await run_daily_triggers(session)
        finally:
            await engine.dispose()

    try:
        # APScheduler tourne dans un thread séparé sans event loop.
        # ``asyncio.run`` crée un loop dédié pour le runner — propre car
        # le job n'est exécuté qu'1 fois par jour, pas de réutilisation.
        return asyncio.run(_runner())
    except Exception:  # noqa: BLE001
        logger.exception("run_daily_triggers_sync a échoué")
        return {
            "dormant_general": 0,
            "dormant_iris": 0,
            "admin_no_user": 0,
            "total_nudged": 0,
            "error": True,
        }
