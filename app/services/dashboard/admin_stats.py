"""Admin-focused dashboard statistics service.

⚠️ Source d'historique des recherches Iris : ``AIPerformanceLog`` (1 row par
question NL→SQL inscrit par ``agent_service``), PAS ``SearchHistory`` (table
legacy jamais alimentée). Cf. commit "fix(dashboard): migrate to real
search source" pour le contexte de la migration.
"""

from datetime import datetime, timedelta
from typing import Any, Dict

from sqlalchemy import select, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import WEEK_DAYS
from app.core import clock
from app.core.database import get_session
from app.models.ai_performance import AIPerformanceLog, QueryStatus
from app.utils.logger import get_logger
from app.services.dashboard.helpers import (
    _build_daily_searches,
    _get_model,
    bucket_daily_local,
    get_business_timezone,
    local_today_start_utc,
    local_window_start_utc,
)

logger = get_logger(__name__)


class AdminStatsService:
    """Gère les statistiques admin du dashboard."""

    async def get_admin_stats(self) -> Dict[str, Any]:
        """Charge toutes les stats admin en sessions groupées."""
        now = clock.now()
        # « Aujourd'hui » au sens calendrier MÉTIER (config.timezone), pas
        # minuit UTC — sinon les compteurs sont décalés de 1-2 h pour un
        # déploiement non-UTC (cf. helpers.local_today_start_utc).
        today_start = local_today_start_utc(now)
        # « 7 derniers jours » = fenêtre glissante (même instant quelle que
        # soit la TZ) → reste en UTC, pas de borne calendaire.
        week_start = now - timedelta(days=WEEK_DAYS)

        stats: Dict[str, Any] = {
            "total_searches": 0,
            "searches_today": 0,
            "searches_week": 0,
            "successful_searches": 0,
            "success_rate": 0.0,
            "avg_generation_time": 0.0,
            "feedback_positive": 0,
            "feedback_negative": 0,
            "feedback_none": 0,
            "feedback_total": 0,
            "total_users": 0,
            "active_users_week": 0,
            "active_automations": 0,
            "total_automations": 0,
            "total_executions": 0,
            "failed_executions": 0,
            "successful_executions": 0,
            "total_reports": 0,
            "reports_week": 0,
            "emails_sent": 0,
            "emails_failed": 0,
            "ai_model": "\u2014",
            "sage_connected": False,
            "training_data_count": 0,
            "daily_searches": [],
            "_errors": [],
        }

        # Session unique pour toutes les stats DB. Chaque sous-load est isolé
        # dans son PROPRE try/except : une erreur DB sur un KPI (ex: lock
        # timeout SQLite) ne doit PAS faire passer les autres à 0 — l'admin
        # croirait « 0 emails / 0 rapports » alors que ces stats n'ont
        # simplement pas pu charger (faux zéros silencieux, consequences.md Q5).
        # Pattern aligné sur AdminMonitoringService.get_security_stats (sous-loads
        # isolés) — avant, un seul SQLAlchemyError avortait les 5 loaders suivants.
        try:
            async with get_session() as session:
                # Lambdas = création LAZY de la coroutine (await make_coro()) : si
                # un loader lève une exception NON-SQLAlchemyError qui se propage,
                # aucune coroutine suivante n'est créée → pas de RuntimeWarning
                # « coroutine was never awaited » (vs tuple de coroutines eager).
                loaders = (
                    (
                        "recherches",
                        lambda: self._load_admin_search_stats(
                            session, stats, now, today_start, week_start
                        ),
                    ),
                    ("automatisations", lambda: self._load_admin_automation_stats(session, stats)),
                    ("exécutions", lambda: self._load_admin_execution_stats(session, stats)),
                    ("rapports", lambda: self._load_admin_report_stats(session, stats, week_start)),
                    ("emails", lambda: self._load_admin_email_stats(session, stats)),
                    ("training", lambda: self._load_admin_training_stats(session, stats)),
                )
                for label, make_coro in loaders:
                    try:
                        await make_coro()
                    except SQLAlchemyError:
                        logger.warning("stats admin: sous-load %r en erreur", label, exc_info=True)
                        stats["_errors"].append(label)
                        # CRITIQUE : sans rollback, la transaction autobegin reste
                        # en échec après une SQLAlchemyError (ex: « database is
                        # locked ») et TOUS les loaders suivants cascade-failent
                        # (PendingRollbackError) → l'isolation serait illusoire.
                        # On repart sur une transaction propre.
                        try:
                            await session.rollback()
                        except SQLAlchemyError:
                            logger.warning(
                                "stats admin: rollback post-erreur a échoué", exc_info=True
                            )
        except SQLAlchemyError:
            # Échec à l'ouverture de session elle-même → tout reste au défaut.
            logger.error("Erreur stats admin (session)", exc_info=True)
            stats["_errors"].append("Erreur chargement statistiques")

        if not stats["daily_searches"]:
            # Labels en dates LOCALES (cohérent avec le graphe peuplé).
            stats["daily_searches"] = _build_daily_searches(now.astimezone(get_business_timezone()))

        # Stats non-DB (config, services)
        await self._load_admin_system_stats(stats)

        return stats

    async def _load_admin_search_stats(
        self,
        session: AsyncSession,
        stats: dict,
        now: datetime,
        today_start: datetime,
        week_start: datetime,
    ) -> None:
        """Charge les KPI recherche admin depuis ``AIPerformanceLog``.

        Mapping legacy → nouveau :
        * ``SearchHistory.success`` (bool) → ``status == QueryStatus.SUCCESS``
        * ``SearchHistory.feedback`` (str) → ``user_feedback`` (même valeurs)
        * Autres colonnes (``user_id``, ``created_at``, ``generation_time``)
          gardent leur nom — schéma quasi-identique entre les deux tables.

        ⚠️ TOUTES les queries filtrent ``user_id IS NOT NULL`` (review
        adversariale finding EXAMINE-1). ``AIPerformanceLog`` est aussi
        écrit lors de calls Iris **sans contexte utilisateur** (preload
        schéma, sondes système, future automation IA). Ces rows ne sont
        pas des "recherches utilisateur" au sens dashboard — les inclure
        gonflerait silencieusement ``total_searches`` et créerait une
        incohérence avec ``active_users_week`` qui filtre déjà.
        """
        # Filtre commun : seulement les rows attachées à un user humain.
        is_user_call = AIPerformanceLog.user_id.isnot(None)

        stats["total_searches"] = (
            await session.execute(select(func.count(AIPerformanceLog.id)).where(is_user_call))
        ).scalar() or 0

        stats["searches_today"] = (
            await session.execute(
                select(func.count(AIPerformanceLog.id)).where(
                    is_user_call, AIPerformanceLog.created_at >= today_start
                )
            )
        ).scalar() or 0

        stats["searches_week"] = (
            await session.execute(
                select(func.count(AIPerformanceLog.id)).where(
                    is_user_call, AIPerformanceLog.created_at >= week_start
                )
            )
        ).scalar() or 0

        stats["successful_searches"] = (
            await session.execute(
                select(func.count(AIPerformanceLog.id)).where(
                    is_user_call, AIPerformanceLog.status == QueryStatus.SUCCESS
                )
            )
        ).scalar() or 0

        if stats["total_searches"] > 0:
            stats["success_rate"] = (stats["successful_searches"] / stats["total_searches"]) * 100

        stats["avg_generation_time"] = (
            await session.execute(
                select(func.avg(AIPerformanceLog.generation_time)).where(
                    is_user_call, AIPerformanceLog.generation_time.isnot(None)
                )
            )
        ).scalar() or 0.0

        # Feedback (utilisateur sur la qualité de la réponse Iris).
        stats["feedback_positive"] = (
            await session.execute(
                select(func.count(AIPerformanceLog.id)).where(
                    is_user_call, AIPerformanceLog.user_feedback == "positive"
                )
            )
        ).scalar() or 0
        stats["feedback_negative"] = (
            await session.execute(
                select(func.count(AIPerformanceLog.id)).where(
                    is_user_call, AIPerformanceLog.user_feedback == "negative"
                )
            )
        ).scalar() or 0
        # ``max(0, ...)`` : défense anti-largeur-négative de la barre SSR
        # (admin.html). Si pos+neg > total (ex. row dont user_id bascule, ou
        # futur statut de feedback), la soustraction nue passerait négative et
        # casserait le layout silencieusement.
        stats["feedback_none"] = max(
            0,
            stats["total_searches"] - stats["feedback_positive"] - stats["feedback_negative"],
        )
        stats["feedback_total"] = stats["total_searches"]

        # Users (count global) + utilisateurs actifs cette semaine.
        # Bug 2026-05-26 (Agent 2 F1) : SSoT via
        # ``admin_service.count_basic_user_stats`` — partagé avec
        # ``admin.py::AdminHandler.get``. Évite le drift quand on
        # ajoute un filtre (deleted_at, is_user_call, etc.).
        from app.services.admin_service import count_basic_user_stats

        _basic_stats = await count_basic_user_stats(session)
        stats["total_users"] = _basic_stats["total"]
        stats["active_users_week"] = (
            await session.execute(
                select(func.count(func.distinct(AIPerformanceLog.user_id))).where(
                    is_user_call, AIPerformanceLog.created_at >= week_start
                )
            )
        ).scalar() or 0

        # Daily searches sur 7 jours (filtre is_user_call cohérent).
        # Bucketing par jour calendaire LOCAL (config.timezone) côté Python :
        # un GROUP BY func.date(created_at) regrouperait par date UTC, ce qui
        # décale les colonnes du graphe (et la colonne « aujourd'hui ») pour
        # un déploiement non-UTC. Volume 7 j négligeable → on ramène les
        # timestamps et on bucket en Python (DST-correct, cf. helpers).
        window_start = local_window_start_utc(now, 6)
        ts_result = await session.execute(
            select(AIPerformanceLog.created_at).where(
                is_user_call, AIPerformanceLog.created_at >= window_start
            )
        )
        daily_counts = bucket_daily_local((row[0] for row in ts_result.all()), now)
        stats["daily_searches"] = _build_daily_searches(
            now.astimezone(get_business_timezone()), daily_counts
        )

    async def _load_admin_automation_stats(self, session: AsyncSession, stats: dict) -> None:
        Automation = _get_model("Automation")
        stats["total_automations"] = (
            await session.execute(select(func.count(Automation.id)))
        ).scalar() or 0
        stats["active_automations"] = (
            await session.execute(
                select(func.count(Automation.id)).where(Automation.is_active == True)  # noqa: E712
            )
        ).scalar() or 0

    async def _load_admin_execution_stats(self, session: AsyncSession, stats: dict) -> None:
        Execution = _get_model("Execution")
        stats["total_executions"] = (
            await session.execute(select(func.count(Execution.id)))
        ).scalar() or 0
        stats["successful_executions"] = (
            await session.execute(
                select(func.count(Execution.id)).where(Execution.status == "success")
            )
        ).scalar() or 0
        stats["failed_executions"] = (
            await session.execute(
                select(func.count(Execution.id)).where(Execution.status == "failed")
            )
        ).scalar() or 0

    async def _load_admin_report_stats(
        self,
        session: AsyncSession,
        stats: dict,
        week_start: datetime,
    ) -> None:
        Report = _get_model("Report")
        stats["total_reports"] = (
            await session.execute(select(func.count(Report.id)))
        ).scalar() or 0
        stats["reports_week"] = (
            await session.execute(
                select(func.count(Report.id)).where(Report.created_at >= week_start)
            )
        ).scalar() or 0

    async def _load_admin_email_stats(self, session: AsyncSession, stats: dict) -> None:
        EmailLog = _get_model("EmailLog")
        stats["emails_sent"] = (
            await session.execute(
                select(func.count(EmailLog.id)).where(EmailLog.success == True)  # noqa: E712
            )
        ).scalar() or 0
        stats["emails_failed"] = (
            await session.execute(
                select(func.count(EmailLog.id)).where(EmailLog.success == False)  # noqa: E712
            )
        ).scalar() or 0

    async def _load_admin_training_stats(self, session: AsyncSession, stats: dict) -> None:
        TrainingData = _get_model("TrainingData")
        stats["training_data_count"] = (
            await session.execute(select(func.count(TrainingData.id)))
        ).scalar() or 0

    async def _load_admin_system_stats(self, stats: dict) -> None:
        # Modele IA actif : lu DYNAMIQUEMENT depuis ``LLMManager`` (qui
        # reflete le choix admin sauvegarde via ``/admin/ai-config`` ->
        # registre BDD, cf. CLAUDE.md "Architecture LLM dynamique").
        # JAMAIS hardcode -- l'admin doit voir le modele REELLEMENT
        # utilise pour ses requetes (Sonnet, Haiku, GPT-4o, Mistral...).
        # Fallback "Indisponible" si le manager n'est pas initialise
        # (boot tres tot, tests sans LLMManager) -- on n'invente pas
        # de nom de modele, ce qui afficherait une info fausse.
        stats["ai_model"] = "Indisponible"
        stats["ai_provider"] = "Indisponible"
        # Flag d'état pour le point de la health-pill (le template ne doit PAS
        # comparer à la chaîne FR "Indisponible" — couplage fragile). True
        # uniquement quand un vrai modèle est résolu.
        stats["ai_model_available"] = False
        try:
            from app.services.ai.llm_providers import get_llm_manager

            manager = get_llm_manager()
            if manager is not None:
                model_name = getattr(manager, "default_model_name", None)
                if model_name:
                    stats["ai_model"] = str(model_name)
                    stats["ai_model_available"] = True
                provider_name = getattr(manager, "default_provider_name", None) or getattr(
                    manager, "provider_name", None
                )
                if provider_name:
                    stats["ai_provider"] = str(provider_name)
        except (ImportError, AttributeError, RuntimeError):
            # Pas d'erreur fatale -- on garde le label "Indisponible".
            logger.debug("LLMManager non disponible pour ai_model", exc_info=True)

        # Label de la BDD source — JAMAIS hardcode "Sage". CLAUDE.md regle
        # de genericite : le code applicatif ne doit rien contenir de
        # specifique a Sage Coala. ``config.sage.label`` est lu depuis
        # SAGE_DB_LABEL (.env) ou config.yaml ; defaut generique
        # "Base SQL Server".
        try:
            from app.config import get_source_db_label

            stats["source_db_label"] = get_source_db_label()
        except Exception:  # noqa: BLE001 — defensive, fallback generique
            stats["source_db_label"] = "Base SQL Server"

        # ── État de la BDD source pour la health-pill du header ──────────
        # SSoT (review loop F2) : on délègue au snapshot unifié
        # ``get_sage_health_snapshot`` (app/services/database/sage_health.py),
        # EXACTEMENT la même source que le bandeau d'alerte système
        # (admin_monitoring._check_sage_status). Avant ce fix, la pastille
        # recalculait ``connector.is_connected OR last_test_success`` : un
        # ``last_test_success`` persisté (ancien test admin) pouvait afficher
        # la pastille VERTE « connectée » pendant que le bandeau affichait
        # ROUGE « déconnectée » (is_connected False + ≥1 échec circuit-breaker)
        # → deux sources de vérité divergentes sur la MÊME page. Le snapshot
        # gère déjà le faux-warn au boot via l'état distinct ``untested`` (ni
        # connecté, ni en panne) que la pastille rend en neutre (dot muted).
        try:
            from app.services.database.sage_health import get_sage_health_snapshot

            _sage_state = get_sage_health_snapshot().state
        except Exception:  # noqa: BLE001 — fail-closed : on n'affirme pas « connecté »
            _sage_state = "untested"
        # ``sage_status`` : 4 états ("unconfigured"|"untested"|"connected"|
        # "disconnected") pour une pastille honnête (3 rendus distincts).
        # ``sage_connected`` (bool) conservé pour compat — VERT uniquement si
        # réellement connecté (≠ ancien comportement basé sur un test périmé).
        stats["sage_status"] = _sage_state
        stats["sage_connected"] = _sage_state == "connected"
