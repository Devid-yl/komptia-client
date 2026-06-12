"""
Chargeur d'automatisations
Charge les automatisations actives au démarrage et les ajoute au scheduler
"""

import asyncio
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError

from app.core import clock
from app.utils.logger import get_logger
from app.models.automation import Automation
from app.models.execution import Execution
from app.core.database import dedicated_session_scope, get_session_factory
from app.services.automation.scheduler import get_scheduler
from app.services.automation.executor import execute_automation
from app.services.email.smtp_client import run_then_drain_email_log

logger = get_logger(__name__)

# A7-C2 — statuts terminaux d'une Execution, dérivés de la SSoT du modèle
# (``Execution.terminal_statuses()`` ↔ ``Execution.is_finished``) pour éviter
# toute divergence si un statut terminal est ajouté.
_TERMINAL_EXECUTION_STATUSES: tuple[str, ...] = Execution.terminal_statuses()


def _once_run_date_in_past(schedule_config: dict) -> bool:
    """True si le ``run_date`` d'une auto ``once`` est dans le passé.

    Fail-safe : un ``run_date`` absent / illisible renvoie ``False`` (on
    PRÉSERVE l'auto plutôt que de la désactiver à tort). Le ``run_date`` est
    stocké en ISO tz-aware (cf. ``_validate_schedule_payload``) ; on tolère
    un datetime naïf (interprété UTC) pour robustesse.
    """
    from datetime import datetime, timezone

    raw = (schedule_config or {}).get("run_date")
    if not raw:
        return False
    try:
        dt = datetime.fromisoformat(raw) if isinstance(raw, str) else raw
        if not isinstance(dt, datetime):
            return False
    except (ValueError, TypeError):
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt < clock.now()


async def _run_automation_with_kill_switch_check(auto_id: int) -> None:
    """Execute une automation après check du kill-switch global.

    S2 — FLAG_AUTOMATIONS_DISABLED couvre les 3 entry-points : UI (déjà),
    webhook (cf. webhooks.py), scheduler (ici). Si actif, log + skip — pas
    d'erreur (le scheduler ne doit pas planter, juste sauter ce tick).
    """
    from app.models.feature_flag import FLAG_AUTOMATIONS_DISABLED
    from app.services.automation.feature_flag_service import is_truthy

    session_factory = get_session_factory()
    async with session_factory() as session:
        # A7-M15b — BUG : la STRING "FLAG_AUTOMATIONS_DISABLED" (nom de la
        # constante) ≠ le flag réel "automations-disabled" (sa valeur). Le
        # kill-switch ne coupait donc PAS les runs SCHEDULED (ce path). On passe
        # par la constante (SSoT, cohérent avec executor).
        if await is_truthy(session, FLAG_AUTOMATIONS_DISABLED, default=False):
            logger.warning(
                "Automation %d skipped: kill-switch '%s' actif",
                auto_id,
                FLAG_AUTOMATIONS_DISABLED,
            )
            return

        # Orphan-job guard : si l'auto a été supprimée de la BDD mais que
        # le job APScheduler n'a pas été unschedule (race au restart,
        # KeyError silencieux dans unschedule_automation, delete handler
        # qui ignore le retour False), on skip gracefully au lieu de laisser
        # execute_automation raise ValueError à chaque tick scheduled.
        # Le job orphelin restant sera purgé par le cleanup mensuel.
        # On check uniquement l'existence (pas is_active : execute_automation
        # le re-vérifie en aval avec sa propre session). Scalar select sur
        # PK indexée → pas de chargement d'ORM object, évite tout risque
        # de lazy-load post-session-close.
        exists = await session.scalar(select(Automation.id).where(Automation.id == auto_id))
        if exists is None:
            logger.warning(
                "Automation %d skipped: introuvable en BDD "
                "(job APScheduler orphelin, sera purgé par cleanup mensuel)",
                auto_id,
            )
            return
    # TOCTOU note : une suppression entre la sortie de l'`async with` et
    # le `execute_automation` ci-dessous reste théoriquement possible
    # (fenêtre sub-seconde). execute_automation:127 re-raise ValueError
    # dans ce cas — comportement original conservé, juste plus si
    # 31 jours de firings sur job orphelin.

    await execute_automation(
        auto_id,
        manual=False,
        trigger_source="scheduled",
        triggered_by_user_id=None,
    )


def _run_automation_sync(auto_id: int) -> None:
    """
    Sync wrapper for async execute_automation.

    APScheduler uses ThreadPoolExecutor which cannot handle async functions.
    asyncio.run() crée proprement un event loop, exécute la coroutine, puis nettoie
    toutes les ressources (tasks, generators) automatiquement.

    S2 — délègue à `_run_automation_with_kill_switch_check` qui vérifie
    le flag global FLAG_AUTOMATIONS_DISABLED avant tout work effectif.

    Args:
        auto_id: ID de l'automatisation à exécuter
    """

    async def _job() -> None:
        # Engine async DÉDIÉ à CETTE boucle asyncio.run (thread scheduler) : ne PAS
        # réutiliser l'engine global poolé, lié à la boucle Tornado (sinon cross-loop
        # → « Future attached to a different loop »). Cf. dedicated_session_scope.
        async with dedicated_session_scope():
            await run_then_drain_email_log(_run_automation_with_kill_switch_check(auto_id))

    asyncio.run(_job())


async def load_active_automations():
    """
    Charge toutes les automatisations actives et les planifie dans le scheduler

    Cette fonction est appelée au démarrage de l'application pour restaurer
    les automatisations après un redémarrage.
    """
    try:
        logger.info("🔄 Chargement des automatisations actives...")

        # Récupérer le scheduler
        scheduler = get_scheduler()

        # Récupérer les automatisations actives — capturer les données AVANT session close
        session_factory = get_session_factory()
        async with session_factory() as session:
            result = await session.execute(
                select(Automation).where(Automation.is_active == True)  # noqa: E712
            )
            automations_data = [
                {
                    "id": a.id,
                    "name": a.name,
                    "schedule_type": a.schedule_type,
                    "schedule_config": a.schedule_config or {},
                }
                for a in result.scalars().all()
            ]

            # A7-C2 backstop boot — quelles autos ``once`` ont DÉJÀ une exécution
            # terminale ? Combinée avec ``run_date`` passé, c'est la preuve
            # qu'elles ont tiré → ce sont des zombies (is_active resté True
            # d'avant le fix executor). On les désactivera au lieu de les
            # ré-ajouter (sinon re-fire si run_date ∈ fenêtre misfire_grace).
            once_ids = [a["id"] for a in automations_data if a["schedule_type"] == "once"]
            fired_once_ids: set = set()
            if once_ids:
                # ⚠️ Filtre ``trigger_source=='scheduled'`` (adversarial A7-C2) :
                # seul un run PLANIFIÉ terminal prouve que la 'once' a tiré son
                # unique planification. Sans ça, un simple TEST MANUEL (Execution
                # trigger_source='manual') d'une 'once' encore planifiée la ferait
                # désactiver à tort au boot → perte de planif. Aligne le backstop
                # sur le scoping de l'executor (qui ne flip que sur 'scheduled').
                exec_res = await session.execute(
                    select(Execution.automation_id)
                    .where(
                        Execution.automation_id.in_(once_ids),
                        Execution.status.in_(_TERMINAL_EXECUTION_STATUSES),
                        Execution.trigger_source == "scheduled",
                    )
                    .distinct()
                )
                fired_once_ids = {row[0] for row in exec_res.all()}

        if not automations_data:
            logger.info("ℹ️ Aucune automatisation active trouvée")
            return

        # Ajouter chaque automatisation au scheduler (données scalaires, pas d'ORM)
        loaded_count = 0
        skipped_existing = 0
        once_zombie_ids: list = []
        for auto_data in automations_data:
            try:
                job_id = f"automation_{auto_data['id']}"

                # A7-C2 backstop boot — auto ``once`` DÉJÀ tirée (exécution
                # terminale) ET ``run_date`` passé = zombie. On ne la
                # ré-ajoute PAS (sinon re-fire silencieux si run_date dans la
                # fenêtre misfire_grace) et on la désactivera après la boucle.
                # ⚠️ run_date FUTUR → préservé (cas : 'once' planifiée demain
                # mais testée manuellement aujourd'hui → ne pas tuer la
                # planification). Jamais tirée → préservé (catch-up misfire
                # légitime laissé à APScheduler).
                if (
                    auto_data["schedule_type"] == "once"
                    and auto_data["id"] in fired_once_ids
                    and _once_run_date_in_past(auto_data["schedule_config"])
                ):
                    once_zombie_ids.append(auto_data["id"])
                    logger.info(
                        "Auto 'once' #%d déjà exécutée (run_date passé) → non "
                        "replanifiée + désactivée (A7-C2 backstop boot).",
                        auto_data["id"],
                    )
                    continue

                # Cluster-F (F3) 2026-05-26 — Préserver le ``next_run_time``
                # persisté par ``SQLAlchemyJobStore``. Avant : ``replace_existing
                # =True`` recalculait next_run à boot, annulant le rattrapage
                # ``misfire_grace_time`` + ``coalesce=True`` (un job qui
                # devait fire à 09:00 alors que scheduler down jusqu'à 09:10
                # ne se déclenchait JAMAIS car next_run réécrasé à 09:00
                # lendemain). On ne ré-add que si le job est ABSENT du store.
                # Le ``schedule_automation`` runtime (loader.py:194) conserve
                # ``replace_existing=True`` car c'est légitime (user a édité
                # la config et veut écraser).
                if scheduler.get_job(job_id) is not None:
                    skipped_existing += 1
                    logger.info(
                        "Automatisation déjà persistée (next_run préservé): %s",
                        auto_data["name"],
                        extra={"automation_id": auto_data["id"], "job_id": job_id},
                    )
                    continue

                # B4 — Fonction module-level + args (PAS lambda inline).
                # APScheduler SQLAlchemyJobStore sérialise via cloudpickle ;
                # une lambda imbriquée dans une fonction async N'EST PAS
                # sérialisable et casse au reboot ("Job cannot be
                # serialized"). Aligné sur scheduler.py:768 (DashboardSchedule).
                scheduler.add_job(
                    job_id=job_id,
                    func=_run_automation_sync,
                    trigger_type=auto_data["schedule_type"],
                    trigger_config=auto_data["schedule_config"],
                    name=f"Automation: {auto_data['name']}",
                    replace_existing=True,
                    args=[auto_data["id"]],
                )

                loaded_count += 1

                logger.info(
                    "Automatisation chargée: %s",
                    auto_data["name"],
                    extra={
                        "automation_id": auto_data["id"],
                        "schedule_type": auto_data["schedule_type"],
                        "job_id": job_id,
                    },
                )

            except (SQLAlchemyError, ValueError):
                logger.error(
                    "Erreur chargement automatisation %d",
                    auto_data["id"],
                    extra={"automation_id": auto_data["id"], "automation_name": auto_data["name"]},
                    exc_info=True,
                )

        logger.info(
            "%d/%d automatisations chargées avec succès (%d préservées du jobstore)",
            loaded_count,
            len(automations_data),
            skipped_existing,
        )

        # A7-C2 backstop boot — désactive en batch les zombies 'once' détectés
        # (déjà exécutés + run_date passé). is_active=False + paused_reason pour
        # le badge UI, dans une session dédiée (la session de lecture est close).
        if once_zombie_ids:
            async with session_factory() as deact_session:
                await deact_session.execute(
                    update(Automation)
                    .where(Automation.id.in_(once_zombie_ids))
                    .values(
                        is_active=False,
                        paused_reason="once_completed",
                        paused_at=clock.now(),
                    )
                )
                await deact_session.commit()
            logger.info(
                "A7-C2 : %d auto(s) 'once' zombie(s) désactivée(s) au boot.",
                len(once_zombie_ids),
            )

    except SQLAlchemyError:
        logger.error("Erreur lors du chargement des automatisations", exc_info=True)


async def schedule_automation(automation: Automation) -> bool:
    """
    Planifie une automatisation dans le scheduler

    Args:
        automation: Instance Automation à planifier

    Returns:
        True si planification réussie, False sinon
    """
    try:
        # Capture scalar values immediately — automation may be a detached ORM object
        auto_id = automation.id
        auto_name = automation.name
        auto_active = automation.is_active
        auto_schedule_type = automation.schedule_type
        auto_schedule_config = automation.schedule_config or {}

        if not auto_active:
            logger.warning("Tentative de planification d'une automatisation inactive: %d", auto_id)
            return False

        scheduler = get_scheduler()

        # A7-F4 — worker passif (follower OU SCHEDULER_ENABLED=false) : add_job
        # stockerait un job dans un scheduler jamais démarré → False (pas un faux
        # succès) pour que le caller surface le warning via `scheduled_ok`.
        # `is True` : robuste aux Mocks de test (attr auto-créé truthy).
        if getattr(scheduler, "_is_passive_worker", False) is True:
            logger.warning(
                "Automatisation %d activée en BDD mais NON planifiée (worker "
                "passif sans scheduler) — effective au redémarrage du leader.",
                auto_id,
            )
            return False

        job_id = f"automation_{auto_id}"

        # B4 — Fonction module-level + args (cf. load_active_automations).
        scheduler.add_job(
            job_id=job_id,
            func=_run_automation_sync,
            trigger_type=auto_schedule_type,
            trigger_config=auto_schedule_config,
            name=f"Automation: {auto_name}",
            replace_existing=True,
            args=[auto_id],
        )

        logger.info(
            "Automatisation planifiée: %s",
            auto_name,
            extra={"automation_id": auto_id, "job_id": job_id},
        )

        return True

    except Exception:
        logger.error("Erreur planification automatisation", exc_info=True)
        return False


async def unschedule_automation(automation_id: int) -> bool:
    """
    Retire une automatisation du scheduler

    Args:
        automation_id: ID de l'automatisation

    Returns:
        True si retrait réussi, False sinon
    """
    try:
        scheduler = get_scheduler()
        job_id = f"automation_{automation_id}"

        result = scheduler.remove_job(job_id)

        if result:
            logger.info(
                "✅ Automatisation retirée du scheduler",
                extra={"automation_id": automation_id, "job_id": job_id},
            )
        else:
            logger.warning(
                "⚠️ Job non trouvé dans le scheduler",
                extra={"automation_id": automation_id, "job_id": job_id},
            )

        return result

    except Exception:
        logger.error("Erreur retrait automatisation %d", automation_id, exc_info=True)
        return False
