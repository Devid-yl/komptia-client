"""User-focused dashboard statistics service.

⚠️ Source d'historique : ``AIPerformanceLog`` (vraie table alimentée par
Iris), pas ``SearchHistory`` (legacy vide). Cf. ``admin_stats.py`` docstring.
"""

import asyncio
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict

from sqlalchemy import select, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import WEEK_DAYS
from app.core import clock
from app.core.database import get_session
from app.models.ai_performance import AIPerformanceLog, QueryStatus
from app.models.user_storage import UserStorage
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


class UserStatsService:
    """Gère les statistiques utilisateur du dashboard."""

    async def get_user_stats(self, user_id: int) -> Dict[str, Any]:
        """Charge toutes les stats utilisateur en UNE seule session."""
        now = clock.now()
        # « Aujourd'hui » = calendrier MÉTIER (config.timezone), pas minuit UTC
        # (sinon décalage 1-2 h des compteurs en non-UTC). « 7 jours » reste
        # une fenêtre glissante UTC. Cf. helpers.local_today_start_utc.
        today_start = local_today_start_utc(now)
        week_start = now - timedelta(days=WEEK_DAYS)

        stats: Dict[str, Any] = {
            "total_searches": 0,
            "searches_today": 0,
            "searches_week": 0,
            "successful_searches": 0,
            "success_rate": 0.0,
            "avg_generation_time": 0.0,
            "total_reports": 0,
            "reports_week": 0,
            "active_automations": 0,
            "total_automations": 0,
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "emails_sent": 0,
            "daily_searches": [],
            # Stockage : ces 2 valeurs sont calculees dans
            # ``_load_user_storage_stats`` a partir de ``UserStorage`` (BDD),
            # qui est la source de verite du quota (fichiers + DB unifies,
            # cf. CLAUDE.md "Phase 2 -- accounting BDD unifie"). On garde
            # un fallback filesystem dans ``_load_storage_stats`` pour les
            # users sans row UserStorage encore (jamais uploade).
            "storage_used_mb": 0.0,
            "storage_total_mb": 0.0,
            "storage_quota_percent": 0.0,
            "_errors": [],
        }

        try:
            async with get_session() as session:
                await self._load_user_search_stats(
                    session, user_id, stats, now, today_start, week_start
                )
                await self._load_user_report_stats(session, user_id, stats, week_start)
                await self._load_user_automation_stats(session, user_id, stats)
                await self._load_user_execution_stats(session, user_id, stats)
                await self._load_user_email_stats(session, user_id, stats)
                # Stockage REEL : on lit ``UserStorage`` (quota_used +
                # db_bytes_used) plutot que de walk le filesystem. C'est
                # la meme source que le quota applique cote upload, donc
                # le user voit exactement ce qui compte pour son quota.
                await self._load_user_storage_stats(session, user_id, stats)
        except SQLAlchemyError:
            logger.error("Erreur stats utilisateur %s", user_id, exc_info=True)
            stats["_errors"].append("Erreur chargement statistiques")

        if not stats["daily_searches"]:
            # Labels en dates LOCALES (cohérent avec le graphe peuplé).
            stats["daily_searches"] = _build_daily_searches(now.astimezone(get_business_timezone()))

        # Fallback filesystem : si ``UserStorage`` n'existe pas (user
        # jamais uploade), on calcule a la volee ce qui se trouve sur
        # disque. Avec le refacto quota global AIConfig (2026-05-14),
        # storage_total_mb est toujours peuplé via _get_global_quota →
        # le fallback se déclenche désormais uniquement quand storage_used_mb
        # est resté à 0 (= pas de row UserStorage). On garde le check
        # storage_used_mb == 0.0 comme guard principal.
        if stats["storage_used_mb"] == 0.0:
            try:
                await asyncio.to_thread(self._load_storage_stats_fallback, user_id, stats)
            except Exception:
                logger.error("Erreur calcul stockage utilisateur %s", user_id, exc_info=True)
                stats["_errors"].append("Erreur calcul stockage")

        return stats

    async def _load_user_storage_stats(
        self,
        session: AsyncSession,
        user_id: int,
        stats: dict,
    ) -> None:
        """Lit la row ``UserStorage`` et calcule les MB exposes a l'UI.

        Source de verite :
          * ``UserStorage.quota_used + db_bytes_used`` pour le USED
          * ``AIConfig.STORAGE_QUOTA_PER_USER_BYTES`` pour le LIMIT
            (ignore le ``UserStorage.quota_limit`` qui peut etre stale
            si le user n'a pas re-uploadé depuis le dernier changement
            admin). La valeur live AIConfig garantit que le dashboard
            reflete TOUJOURS le quota courant.

        Si pas de row pour ce user (cas tres frais : jamais uploade),
        les valeurs restent a 0 et le caller fallback sur un walk
        filesystem.
        """
        result = await session.execute(
            select(
                UserStorage.quota_used,
                UserStorage.db_bytes_used,
            ).where(UserStorage.user_id == user_id)
        )
        row = result.first()
        if row is None:
            return
        used_bytes = int((row.quota_used or 0) + (row.db_bytes_used or 0))

        # Source unique de vérité pour le LIMIT = AIConfig admin global.
        # Lazy import pour éviter cycle (dashboard ← storage ← ai_config).
        from app.services.storage_manager import _get_global_quota

        limit_bytes = await _get_global_quota(session)
        limit_bytes = int(limit_bytes or 0)

        # Conversion MB binaire (Mo SI = 1000^2, Mio binaire = 1024^2).
        # On reste sur la convention "Mo binaire" pour rester cohere
        # avec le code legacy (``round(bytes / 1048576, 2)``).
        stats["storage_used_mb"] = round(used_bytes / 1048576.0, 2)
        stats["storage_total_mb"] = round(limit_bytes / 1048576.0, 2)
        stats["storage_quota_percent"] = (
            round(used_bytes / limit_bytes * 100.0, 1) if limit_bytes > 0 else 0.0
        )

    async def _load_user_search_stats(
        self,
        session: AsyncSession,
        user_id: int,
        stats: dict,
        now: datetime,
        today_start: datetime,
        week_start: datetime,
    ) -> None:
        """Idem ``_load_admin_search_stats`` filtré par user_id.

        Source : ``AIPerformanceLog`` (cf. docstring module).
        """
        uf = AIPerformanceLog.user_id == user_id

        stats["total_searches"] = (
            await session.execute(select(func.count(AIPerformanceLog.id)).where(uf))
        ).scalar() or 0

        stats["searches_today"] = (
            await session.execute(
                select(func.count(AIPerformanceLog.id)).where(
                    uf, AIPerformanceLog.created_at >= today_start
                )
            )
        ).scalar() or 0

        stats["searches_week"] = (
            await session.execute(
                select(func.count(AIPerformanceLog.id)).where(
                    uf, AIPerformanceLog.created_at >= week_start
                )
            )
        ).scalar() or 0

        stats["successful_searches"] = (
            await session.execute(
                select(func.count(AIPerformanceLog.id)).where(
                    uf, AIPerformanceLog.status == QueryStatus.SUCCESS
                )
            )
        ).scalar() or 0

        if stats["total_searches"] > 0:
            stats["success_rate"] = (stats["successful_searches"] / stats["total_searches"]) * 100

        stats["avg_generation_time"] = (
            await session.execute(
                select(func.avg(AIPerformanceLog.generation_time)).where(
                    uf, AIPerformanceLog.generation_time.isnot(None)
                )
            )
        ).scalar() or 0.0

        # Recherches quotidiennes (7 derniers jours) filtrées par user.
        # Bucketing par jour calendaire LOCAL (config.timezone) côté Python —
        # un GROUP BY func.date() regrouperait par date UTC et décalerait les
        # colonnes pour un déploiement non-UTC. Cf. admin_stats (même fix).
        window_start = local_window_start_utc(now, 6)
        ts_result = await session.execute(
            select(AIPerformanceLog.created_at).where(
                uf, AIPerformanceLog.created_at >= window_start
            )
        )
        daily_counts = bucket_daily_local((row[0] for row in ts_result.all()), now)

        stats["daily_searches"] = _build_daily_searches(
            now.astimezone(get_business_timezone()), daily_counts
        )

    async def _load_user_report_stats(
        self,
        session: AsyncSession,
        user_id: int,
        stats: dict,
        week_start: datetime,
    ) -> None:
        Report = _get_model("Report")
        stats["total_reports"] = (
            await session.execute(
                select(func.count(Report.id)).where(Report.created_by_user_id == user_id)
            )
        ).scalar() or 0
        stats["reports_week"] = (
            await session.execute(
                select(func.count(Report.id)).where(
                    Report.created_by_user_id == user_id, Report.created_at >= week_start
                )
            )
        ).scalar() or 0

    async def _load_user_automation_stats(
        self,
        session: AsyncSession,
        user_id: int,
        stats: dict,
    ) -> None:
        Automation = _get_model("Automation")
        stats["total_automations"] = (
            await session.execute(
                select(func.count(Automation.id)).where(Automation.user_id == user_id)
            )
        ).scalar() or 0
        stats["active_automations"] = (
            await session.execute(
                select(func.count(Automation.id)).where(
                    Automation.user_id == user_id, Automation.is_active == True  # noqa: E712
                )
            )
        ).scalar() or 0

    async def _load_user_execution_stats(
        self,
        session: AsyncSession,
        user_id: int,
        stats: dict,
    ) -> None:
        Automation = _get_model("Automation")
        Execution = _get_model("Execution")
        sub = select(Automation.id).where(Automation.user_id == user_id)
        stats["total_executions"] = (
            await session.execute(
                select(func.count(Execution.id)).where(Execution.automation_id.in_(sub))
            )
        ).scalar() or 0
        stats["successful_executions"] = (
            await session.execute(
                select(func.count(Execution.id)).where(
                    Execution.automation_id.in_(sub), Execution.status == "success"
                )
            )
        ).scalar() or 0
        stats["failed_executions"] = (
            await session.execute(
                select(func.count(Execution.id)).where(
                    Execution.automation_id.in_(sub), Execution.status == "failed"
                )
            )
        ).scalar() or 0

    async def _load_user_email_stats(
        self,
        session: AsyncSession,
        user_id: int,
        stats: dict,
    ) -> None:
        Automation = _get_model("Automation")
        EmailLog = _get_model("EmailLog")
        sub = select(Automation.id).where(Automation.user_id == user_id)
        stats["emails_sent"] = (
            await session.execute(
                select(func.count(EmailLog.id)).where(
                    EmailLog.automation_id.in_(sub), EmailLog.success == True  # noqa: E712
                )
            )
        ).scalar() or 0

    # Alias rétrocompat : les tests historiques appellent
    # ``_load_storage_stats(...)`` directement. La methode a ete renommee
    # en ``_load_storage_stats_fallback`` pour clarifier qu'elle est
    # appelee uniquement quand ``UserStorage`` est absent. On garde le
    # nom historique pointant sur la nouvelle implementation.
    def _load_storage_stats(self, user_id: int, stats: dict) -> None:
        self._load_storage_stats_fallback(user_id, stats)

    def _load_storage_stats_fallback(self, user_id: int, stats: dict) -> None:
        """Fallback filesystem si pas de row ``UserStorage``.

        Cas d'usage : user qui vient juste d'etre cree, jamais uploade
        de fichier -> pas de row dans ``user_storage`` -> on ne peut pas
        lire son quota. On affiche au moins ce qu'il y a sur disque a la
        place de "0 MB" total. ``storage_total_mb`` reste a 0 (pas de
        quota configure visible) -- l'UI affichera "Mo / quota inconnu"
        ou similaire.
        """
        try:
            base_path = Path(__file__).parent.parent.parent / "data"
            datastore_path = base_path / "datastore" / str(user_id)
            total_size_bytes = 0
            if datastore_path.exists():
                for dirpath, _dirnames, filenames in os.walk(datastore_path):
                    for filename in filenames:
                        try:
                            total_size_bytes += os.path.getsize(os.path.join(dirpath, filename))
                        except OSError:
                            pass
            stats["storage_used_mb"] = round(total_size_bytes / 1048576.0, 2)
        except OSError:
            logger.error("Erreur calcul stockage", exc_info=True)
