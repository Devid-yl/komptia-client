"""Recent data queries for dashboard service.

⚠️ Source d'historique : ``AIPerformanceLog`` (vraie table alimentée par
Iris), pas ``SearchHistory`` (legacy vide). Cf. ``admin_stats.py`` docstring.

Les templates dashboard utilisent ``s.question``, ``s.success``, ``s.feedback``,
``s.result_count``, ``s.generation_time``, ``s.error_message`` et ``s.created_at``.
``AIPerformanceLog`` expose tous ces noms (``success`` et ``feedback`` via
``@property`` aliases — cf. model). Pas de changement template requis.
"""

import calendar
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload

from app.constants import DASHBOARD_RECENT_LIMIT, STATS_RECENT_LIMIT, WEEK_DAYS
from app.core import clock
from app.core.database import get_session
from app.models.ai_performance import AIPerformanceLog, QueryStatus
from app.models.user import User
from app.utils.logger import get_logger
from app.services.dashboard.helpers import _get_model

logger = get_logger(__name__)


async def _scrub_searches_for_user(
    searches: list,
    user: object,
) -> list:
    """**Mode invisible rétroactif sur l'historique Iris** — Retourne une
    liste de :class:`SimpleNamespace` mirrorant chaque
    :class:`AIPerformanceLog` mais avec les champs textuels passés au
    scrub :func:`scrub_text_for_user` :

    - ``question`` (la NL question saisie par l'user)
    - ``sql_generated`` (le SQL LLM-générée)
    - ``sql_validated`` (le SQL après validation)
    - ``error_message`` (peut mentionner une table SQL Server)

    Les autres attributs sont copiés tels quels (par référence pour les
    immutables — bool/int/datetime — ce qui est safe).

    **Pourquoi SimpleNamespace et pas mutation in-place** : l'instance
    ORM ``AIPerformanceLog`` retournée par ``scalars().all()`` est
    détachée APRÈS sortie du ``async with get_session()``, donc une
    mutation ne re-déclencherait PAS un COMMIT. Mais c'est fragile :
    si demain quelqu'un wraps cette query dans une session plus
    longue, on persisterait silencieusement le texte scrubé dans la
    BDD (cf. leçon #140 sur les Mapped[dict] partagés). SimpleNamespace
    coupe le lien à l'ORM pour de bon. Coût : ~6 attrs × 8 rows = 48
    allocations, négligeable.

    **Fail-safe** : si le scrub d'un champ crash, on garde la valeur
    originale (mieux qu'un dashboard vide).
    """
    from types import SimpleNamespace

    from app.services.data_access.error_messages import scrub_text_for_user

    async def _safe_scrub(text: object) -> object:
        if not isinstance(text, str) or not text:
            return text
        try:
            return await scrub_text_for_user(text, user, context_label="recent_searches")
        except Exception:
            return text

    out: list = []
    for s in searches:
        out.append(
            SimpleNamespace(
                id=getattr(s, "id", None),
                user_id=getattr(s, "user_id", None),
                question=await _safe_scrub(getattr(s, "question", "")),
                sql_generated=await _safe_scrub(getattr(s, "sql_generated", None)),
                sql_validated=await _safe_scrub(getattr(s, "sql_validated", None)),
                error_message=await _safe_scrub(getattr(s, "error_message", None)),
                success=getattr(s, "success", False),
                feedback=getattr(s, "feedback", None),
                result_count=getattr(s, "result_count", None),
                execution_time=getattr(s, "execution_time", None),
                generation_time=getattr(s, "generation_time", None),
                model_used=getattr(s, "model_used", None),
                model_name=getattr(s, "model_name", None),
                created_at=getattr(s, "created_at", None),
                status=getattr(s, "status", None),
            )
        )
    return out


class RecentDataService:
    """Gère l'accès aux données récentes du dashboard."""

    async def get_recent_searches(
        self,
        user_id: int,
        limit: int = 8,
        *,
        user: Optional[object] = None,
    ) -> list:
        """Recherches récentes d'un utilisateur (questions Iris).

        **#data-access-scrub-history (hors backlog brainstorm)** — Si
        ``user`` est passé (objet User), on scrub ``question``,
        ``sql_generated``, ``sql_validated`` et ``error_message`` pour
        retirer les noms de tables désormais denied. Sans ce scrub, le
        widget "Recherches récentes" du dashboard user affiche les
        anciennes questions Iris contenant des noms de tables que
        l'admin a denied depuis — leak du nom en violation du mode
        invisible rétroactif (même classe que #124 / #140 / #141 / #144).

        Pour éviter de corrompre l'instance ORM en mémoire (et risquer
        un commit silencieux d'un texte scrubé dans la BDD), on
        retourne une liste de :class:`SimpleNamespace` mirrorant les
        attributs lus par le template (``s.success``, ``s.question``,
        ``s.result_count``, ``s.created_at``, ``s.generation_time``,
        ``s.feedback``, ``s.sql_generated``, ``s.sql_validated``,
        ``s.error_message``). Le rendu Jinja2 accède aux attributs de
        manière identique — pas de change template requis.
        """
        try:
            async with get_session() as session:
                result = await session.execute(
                    select(AIPerformanceLog)
                    .where(AIPerformanceLog.user_id == user_id)
                    .order_by(AIPerformanceLog.created_at.desc())
                    .limit(limit)
                )
                searches = result.scalars().all()
            if user is None:
                return searches
            return await _scrub_searches_for_user(searches, user)
        except SQLAlchemyError:
            logger.error("Erreur get_recent_searches", exc_info=True)
            return []

    async def get_recent_searches_all(self, limit: int = STATS_RECENT_LIMIT) -> list:
        """Recherches récentes globales (admin) avec username.

        Filtre les rows ``user_id IS NULL`` (preload schéma au boot, etc.) —
        elles ne sont pas des "recherches utilisateur" au sens dashboard.
        """
        try:
            async with get_session() as session:
                result = await session.execute(
                    select(AIPerformanceLog)
                    .where(AIPerformanceLog.user_id.isnot(None))
                    .order_by(AIPerformanceLog.created_at.desc())
                    .limit(limit)
                )
                searches = result.scalars().all()

                # Batch-fetch usernames pour éviter N+1
                user_ids = {s.user_id for s in searches if s.user_id}
                user_map = {}
                if user_ids:
                    users_r = await session.execute(
                        select(User.id, User.username).where(User.id.in_(user_ids))
                    )
                    user_map = {uid: uname for uid, uname in users_r.all()}

                for s in searches:
                    s._username = user_map.get(s.user_id, "?") if s.user_id else "?"
                return searches
        except SQLAlchemyError:
            logger.error("Erreur get_recent_searches_all", exc_info=True)
            return []

    async def get_user_reports(self, user_id: int, limit: int = DASHBOARD_RECENT_LIMIT) -> list:
        """Rapports récents d'un utilisateur."""
        try:
            Report = _get_model("Report")
            async with get_session() as session:
                result = await session.execute(
                    select(Report)
                    .where(Report.created_by_user_id == user_id)
                    .order_by(Report.created_at.desc())
                    .limit(limit)
                )
                return result.scalars().all()
        except SQLAlchemyError:
            logger.error("Erreur get_user_reports", exc_info=True)
            return []

    async def get_user_automations(self, user_id: int, limit: int = DASHBOARD_RECENT_LIMIT) -> list:
        """Automations récentes d'un utilisateur."""
        try:
            Automation = _get_model("Automation")
            async with get_session() as session:
                result = await session.execute(
                    select(Automation)
                    .where(Automation.user_id == user_id)
                    .order_by(Automation.created_at.desc())
                    .limit(limit)
                )
                return result.scalars().all()
        except SQLAlchemyError:
            logger.error("Erreur get_user_automations", exc_info=True)
            return []

    async def get_recent_executions(
        self,
        user_id: Optional[int] = None,
        limit: int = 8,
    ) -> list:
        """
        Exécutions récentes avec eager loading (résout le N+1).
        Si user_id=None, retourne toutes les exécutions (vue admin).
        """
        try:
            Automation = _get_model("Automation")
            Execution = _get_model("Execution")
            async with get_session() as session:
                query = (
                    select(Execution)
                    .join(Automation, Automation.id == Execution.automation_id)
                    .options(selectinload(Execution.automation))
                )
                if user_id is not None:
                    query = query.where(Automation.user_id == user_id)

                query = query.order_by(Execution.started_at.desc()).limit(limit)
                result = await session.execute(query)
                executions = result.scalars().all()

                # Enrichir avec les noms (grâce à l'eager loading, plus de N+1)
                for ex in executions:
                    ex._automation_name = ex.automation.name if ex.automation else "?"

                # Batch-fetch usernames pour admin view (évite N+1)
                if user_id is None:
                    user_ids = {
                        ex.automation.user_id
                        for ex in executions
                        if ex.automation and ex.automation.user_id
                    }
                    user_map = {}
                    if user_ids:
                        users_r = await session.execute(
                            select(User.id, User.username).where(User.id.in_(user_ids))
                        )
                        user_map = {uid: uname for uid, uname in users_r.all()}

                    for ex in executions:
                        if ex.automation and ex.automation.user_id:
                            ex._username = user_map.get(ex.automation.user_id, "?")
                        else:
                            ex._username = "?"
                else:
                    for ex in executions:
                        ex._username = None

                return executions
        except SQLAlchemyError:
            logger.error("Erreur get_recent_executions", exc_info=True)
            return []

    async def get_top_users(self, limit: int = DASHBOARD_RECENT_LIMIT) -> list:
        """Top utilisateurs par nombre de recherches Iris cette semaine."""
        try:
            week_start = clock.now() - timedelta(days=WEEK_DAYS)
            async with get_session() as session:
                result = await session.execute(
                    select(User.username, func.count(AIPerformanceLog.id).label("search_count"))
                    .join(AIPerformanceLog, AIPerformanceLog.user_id == User.id)
                    .where(AIPerformanceLog.created_at >= week_start)
                    .group_by(User.username)
                    .order_by(func.count(AIPerformanceLog.id).desc())
                    .limit(limit)
                )
                return [{"username": row[0], "search_count": row[1]} for row in result.all()]
        except SQLAlchemyError:
            logger.error("Erreur get_top_users", exc_info=True)
            return []

    async def get_recent_errors(self, limit: int = DASHBOARD_RECENT_LIMIT) -> list:
        """Recherches **utilisateur** échouées récentes (admin).

        Whitelist explicite des 4 statuts d'erreur connus (review adversariale
        finding EXAMINE-2 + BASSE-blacklist) :

        * ``VALIDATION_ERROR`` — SQL généré rejeté par le validateur.
        * ``EXECUTION_ERROR`` — échec sur la BDD source (table inconnue, etc.).
        * ``TIMEOUT`` — la BDD source ne répond pas.
        * ``LLM_ERROR`` — provider IA en panne / timeout côté LLM.

        Si demain on ajoute un statut ``PENDING`` ou ``RUNNING``, il **ne sera
        PAS** inclus ici (fail-closed). Filtre aussi ``user_id IS NOT NULL`` :
        les erreurs des sondes système (preload schéma, agents internes) ne
        polluent pas le widget admin "Dernières erreurs" — l'admin ne s'attend
        qu'à des erreurs de ses utilisateurs humains.
        """
        try:
            async with get_session() as session:
                error_statuses = [
                    QueryStatus.VALIDATION_ERROR,
                    QueryStatus.EXECUTION_ERROR,
                    QueryStatus.TIMEOUT,
                    QueryStatus.LLM_ERROR,
                ]
                result = await session.execute(
                    select(AIPerformanceLog)
                    .where(
                        AIPerformanceLog.user_id.isnot(None),
                        AIPerformanceLog.status.in_(error_statuses),
                    )
                    .order_by(AIPerformanceLog.created_at.desc())
                    .limit(limit)
                )
                searches = result.scalars().all()

                # Batch-fetch usernames pour éviter N+1
                user_ids = {s.user_id for s in searches if s.user_id}
                user_map = {}
                if user_ids:
                    users_r = await session.execute(
                        select(User.id, User.username).where(User.id.in_(user_ids))
                    )
                    user_map = {uid: uname for uid, uname in users_r.all()}

                for s in searches:
                    s._username = user_map.get(s.user_id, "?") if s.user_id else "?"
                return searches
        except SQLAlchemyError:
            logger.error("Erreur get_recent_errors", exc_info=True)
            return []

    async def get_next_automations(self, user_id: int, limit: int = 4) -> list:
        """Prochaines automations planifiées avec ``next_run`` aligné scheduler.

        Source de vérité primaire : APScheduler via
        :func:`app.services.automation.scheduler.get_next_run_for_automation`.
        Lui sait quand le job va RÉELLEMENT tourner (TZ correcte, cron parsé
        comme à l'``add_job``, défauts cohérents avec le runtime).

        Fallback : :func:`calculate_next_execution` si le job n'est pas
        (encore) inscrit dans le scheduler — typiquement au boot froid,
        avant que ``load_active_automations`` ait fini de tourner. Sans ce
        fallback, le user verrait "aucune prochaine exécution" pendant
        quelques secondes alors qu'il vient d'activer une automation.
        Cohérent avec la convention CLAUDE.md "fail-soft" : on affiche le
        meilleur effort, jamais une fausse vacuité.

        ⚠️ TZ normalization (review adversariale finding B1) — APScheduler
        renvoie un ``datetime`` aware en TZ scheduler (``Europe/Paris``).
        ``calculate_next_execution`` renvoie aware en UTC. Si on les mélange
        sans normalisation, le ``strftime`` côté template affiche l'heure
        dans la TZ de l'objet et un user voit "09:00" pour deux créneaux
        qui sont en réalité décalés de plusieurs heures. On normalise tout
        à la TZ du scheduler avant ``_next_run_time = ...``.
        """
        # Import lazy ciblé : ImportError uniquement (pas Exception large).
        # Si l'import échoue pour une autre raison (cycle, dep manquante),
        # on log error explicitement plutôt que de fallback silencieusement
        # (review adversariale finding D-import-silent).
        get_next_run_for_automation = None
        scheduler_tz = None
        try:
            from app.services.automation.scheduler import (
                get_next_run_for_automation,
                get_scheduler,
            )

            try:
                scheduler_tz = get_scheduler().scheduler.timezone
            except Exception:  # noqa: BLE001 — TZ best-effort, fallback UTC
                scheduler_tz = None
        except ImportError:
            logger.warning("Scheduler module non importable — fallback calcul local pour next_run")
        except Exception:  # noqa: BLE001 — autre erreur structurelle, log fort
            logger.error(
                "Erreur init scheduler module dashboard — fallback calcul local",
                exc_info=True,
            )

        from datetime import timezone as _tz

        def _normalize_tz(dt):
            """Aligne un ``datetime`` à la TZ du scheduler pour cohérence affichage.

            Garantie de sortie : tout datetime non-None retourné est aware
            (review adversariale R2-A2). Sans cette garantie, le ``sort``
            ligne 297 mélangeait potentiellement aware (TZ scheduler) et
            naive (cas ``schedule_type="once"`` avec ``run_date`` naive)
            → ``TypeError: can't compare offset-naive and offset-aware``
            → crash silencieux du tableau "Prochaines automations".
            """
            if dt is None:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_tz.utc)
            if scheduler_tz is not None:
                try:
                    return dt.astimezone(scheduler_tz)
                except (ValueError, OverflowError, TypeError):
                    pass
            # Garantie : toujours aware (UTC si pas de TZ scheduler).
            return dt if dt.tzinfo else dt.replace(tzinfo=_tz.utc)

        try:
            Automation = _get_model("Automation")
            async with get_session() as session:
                result = await session.execute(
                    select(Automation)
                    .where(
                        Automation.user_id == user_id, Automation.is_active == True
                    )  # noqa: E712
                    .order_by(Automation.created_at.desc())
                )
                automations = result.scalars().all()

                automation_list = []
                for auto in automations:
                    next_run = None
                    if get_next_run_for_automation is not None:
                        next_run = get_next_run_for_automation(auto.id)
                    if next_run is None:
                        # Fallback calcul local si le job n'est pas inscrit
                        # (boot froid avant load_active_automations).
                        next_run = calculate_next_execution(auto)
                    next_run = _normalize_tz(next_run)
                    if next_run:
                        auto._next_run_time = next_run
                        automation_list.append(auto)

                automation_list.sort(key=lambda a: a._next_run_time)
                return automation_list[:limit]
        except SQLAlchemyError:
            logger.error("Erreur get_next_automations", exc_info=True)
            return []


def calculate_next_execution(automation) -> Optional[datetime]:
    """
    Calcule la prochaine exécution prévue pour une automation.

    ⚠️ FALLBACK uniquement — la SOURCE DE VÉRITÉ pour le ``next_run`` réel
    est :func:`app.services.automation.scheduler.get_next_run_for_automation`,
    qui interroge APScheduler (TZ scheduler, defaults validés à l'``add_job``,
    cron expression rejetée à l'inscription si invalide).

    Cette fonction reste utile pour :

    1. **Boot froid** : avant que ``load_active_automations`` ait fini, le
       scheduler ne connaît pas encore les jobs. Le dashboard affiche une
       estimation calculée localement plutôt qu'un blanc trompeur.
    2. **Preview UX** : un futur formulaire "créer une automation" peut
       afficher un preview du ``next_run`` AVANT de sauvegarder en BDD,
       sans dépendre du scheduler.
    3. **Tests purs** : la logique de calcul reste testable sans mock du
       scheduler (cf. ``tests/unit/test_dashboard_services.py``).

    En production, ``get_next_automations`` appelle d'abord le helper
    scheduler ; si ``None``, fallback sur cette fonction. Garantit que la
    valeur affichée converge vers la VRAIE valeur scheduler dès qu'il est
    démarré.
    """
    if not automation.is_active:
        return None

    try:
        now = clock.now()
        config = automation.schedule_config or {}

        if automation.schedule_type == "daily":
            hour = config.get("hour", 9)
            minute = config.get("minute", 0)
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run = next_run + timedelta(days=1)
            return next_run

        elif automation.schedule_type == "weekly":
            hour = config.get("hour", 9)
            minute = config.get("minute", 0)
            day_of_week = config.get("day_of_week", "monday")
            day_map = {
                "monday": 0,
                "tuesday": 1,
                "wednesday": 2,
                "thursday": 3,
                "friday": 4,
                "saturday": 5,
                "sunday": 6,
            }
            target_day = day_map.get(day_of_week.lower(), 0)
            current_day = now.weekday()
            days_ahead = target_day - current_day
            if days_ahead < 0 or (days_ahead == 0 and now.hour >= hour):
                days_ahead += 7
            next_run = now + timedelta(days=days_ahead)
            next_run = next_run.replace(hour=hour, minute=minute, second=0, microsecond=0)
            return next_run

        elif automation.schedule_type == "monthly":
            hour = config.get("hour", 9)
            minute = config.get("minute", 0)
            day_of_month = config.get("day", 1)
            try:
                next_run = now.replace(
                    day=day_of_month, hour=hour, minute=minute, second=0, microsecond=0
                )
            except ValueError:
                # day_of_month invalide pour ce mois (ex: jour 31 en février)
                last_day = calendar.monthrange(now.year, now.month)[1]
                next_run = now.replace(
                    day=last_day, hour=hour, minute=minute, second=0, microsecond=0
                )
            if next_run <= now:
                if now.month == 12:
                    # Passer au mois suivant
                    try:
                        next_run = next_run.replace(year=now.year + 1, month=1, day=day_of_month)
                    except ValueError:
                        last_day = calendar.monthrange(now.year + 1, 1)[1]
                        next_run = next_run.replace(year=now.year + 1, month=1, day=last_day)
                else:
                    try:
                        next_run = next_run.replace(month=now.month + 1, day=day_of_month)
                    except ValueError:
                        last_day = calendar.monthrange(now.year, now.month + 1)[1]
                        next_run = next_run.replace(month=now.month + 1, day=last_day)
            return next_run

        elif automation.schedule_type == "cron":
            cron_expr = config.get("cron_expression", "")
            if cron_expr:
                try:
                    parts = cron_expr.strip().split()
                    if len(parts) == 5:
                        from apscheduler.triggers.cron import CronTrigger

                        trigger = CronTrigger(
                            minute=parts[0],
                            hour=parts[1],
                            day=parts[2],
                            month=parts[3],
                            day_of_week=parts[4],
                        )
                        next_fire = trigger.get_next_fire_time(None, now)
                        if next_fire:
                            return next_fire
                except (ValueError, KeyError, TypeError):
                    logger.warning(
                        "Erreur calcul next_run cron automation %s",
                        automation.id,
                        exc_info=True,
                    )

        elif automation.schedule_type == "once":
            run_date = config.get("run_date")
            if run_date:
                if isinstance(run_date, str):
                    parsed = datetime.fromisoformat(run_date)
                    # Ensure timezone-aware for safe comparison
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    return parsed
                # Cas datetime déjà construit (tests, futurs callers Python) —
                # forcer aware si naive pour éviter le crash de sort
                # mélangeant aware/naive (review R2-A2).
                if isinstance(run_date, datetime) and run_date.tzinfo is None:
                    return run_date.replace(tzinfo=timezone.utc)
                return run_date

        return None

    except (KeyError, ValueError, AttributeError):
        logger.error(
            "Erreur calcul prochaine exécution automation %s",
            automation.id,
            exc_info=True,
        )
        return None
