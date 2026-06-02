"""
Dashboard charts service — façade qui compose les services dashboard
spécialisés et expose le payload JSON pour ``/api/dashboard/charts``.

Historique : ``DashboardStatsService`` vivait à
``app/services/dashboard_stats_service.py`` (en dehors du package
``dashboard/``), entretenant une asymétrie dans l'arborescence et trois
sources d'imports possibles. La review adversariale a recommandé de
déplacer le module dans le package, à côté de ses dépendances directes
(``user_stats``, ``admin_stats``, ``admin_monitoring``, ``recent_data``).

Surface publique :
- :class:`DashboardStatsService` — façade par composition (créée au boot).
- :func:`get_stats_service` — singleton process-local.
- :func:`_assemble_charts_payload` — fonction pure exposée pour les tests
  (vérifie la défense contre données corrompues amont).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional

from app.constants import DASHBOARD_RECENT_LIMIT, STATS_RECENT_LIMIT
from app.models.user import UserRole
from app.services.dashboard.admin_monitoring import AdminMonitoringService
from app.services.dashboard.admin_stats import AdminStatsService
from app.services.dashboard.recent_data import RecentDataService
from app.services.dashboard.user_stats import UserStatsService

if TYPE_CHECKING:
    from app.models.user import User


class DashboardStatsService:
    """Façade par composition pour les stats dashboard.

    Expose les méthodes attendues par ``DashboardHandler`` et
    ``DashboardChartsAPIHandler``. Chaque méthode délègue au sous-service
    spécialisé. Le singleton ``get_stats_service`` réutilise la même
    instance pour amortir les coûts d'init des sous-services (création
    légère mais évite N instanciations par requête).
    """

    def __init__(self) -> None:
        self._user = UserStatsService()
        self._admin = AdminStatsService()
        self._monitoring = AdminMonitoringService()
        self._recent = RecentDataService()

    # ── User stats delegation ──────────────────────────────────

    async def get_user_stats(self, user_id: int) -> Dict[str, Any]:
        return await self._user.get_user_stats(user_id)

    # ── Admin stats delegation ─────────────────────────────────

    async def get_admin_stats(self) -> Dict[str, Any]:
        return await self._admin.get_admin_stats()

    # ── Monitoring (security + users overview) ─────────────────

    async def get_admin_security_stats(self) -> Dict[str, Any]:
        return await self._monitoring.get_security_stats()

    async def get_admin_users_overview(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """Retourne ``{users, total, truncated, limit}`` (et non une liste plate)
        pour que le template puisse afficher un footer "X/Y comptes affichés".
        """
        return await self._monitoring.get_users_overview(limit)

    # ── Recent data delegation ─────────────────────────────────

    async def get_recent_searches(
        self,
        user_id: int,
        limit: int = 8,
        *,
        user: Optional[object] = None,
    ) -> list:
        return await self._recent.get_recent_searches(user_id, limit, user=user)

    async def get_recent_searches_all(self, limit: Optional[int] = None) -> list:
        if limit is None:
            limit = STATS_RECENT_LIMIT
        return await self._recent.get_recent_searches_all(limit)

    async def get_user_reports(self, user_id: int, limit: Optional[int] = None) -> list:
        if limit is None:
            limit = DASHBOARD_RECENT_LIMIT
        return await self._recent.get_user_reports(user_id, limit)

    async def get_user_automations(self, user_id: int, limit: Optional[int] = None) -> list:
        if limit is None:
            limit = DASHBOARD_RECENT_LIMIT
        return await self._recent.get_user_automations(user_id, limit)

    async def get_recent_executions(
        self,
        user_id: Optional[int] = None,
        limit: int = 8,
    ) -> list:
        return await self._recent.get_recent_executions(user_id, limit)

    async def get_top_users(self, limit: Optional[int] = None) -> list:
        if limit is None:
            limit = DASHBOARD_RECENT_LIMIT
        return await self._recent.get_top_users(limit)

    async def get_recent_errors(self, limit: Optional[int] = None) -> list:
        if limit is None:
            limit = DASHBOARD_RECENT_LIMIT
        return await self._recent.get_recent_errors(limit)

    async def get_next_automations(self, user_id: int, limit: int = 4) -> list:
        return await self._recent.get_next_automations(user_id, limit)

    # ── Charts payload ─────────────────────────────────────────

    async def build_charts_payload(self, user: "User") -> Dict[str, Any]:
        """Build the JSON payload consumed by the dashboard charts endpoint.

        Dispatches on ``user.role`` (fail-closed on unknown roles: ``ValueError``).
        Handler stays thin: ``self.write_json({"success": True, "charts": payload})``.

        Returns
        -------
        dict
            Always contains keys ``daily_searches`` (dict with ``labels``/``values``/
            ``full_labels`` lists) and ``execution_breakdown`` (dict with ``success``/
            ``failed`` non-negative ints). Admin role also gets ``feedback`` and
            ``overview`` sections.
        """
        if user.role == UserRole.ADMIN:
            stats = await self.get_admin_stats()
            is_admin = True
        elif user.role == UserRole.USER:
            stats = await self.get_user_stats(user.id)
            is_admin = False
        else:
            # Fail-closed : un rôle futur doit déclarer explicitement son comportement
            # côté dashboard plutôt que d'hériter de la branche USER par défaut.
            raise ValueError(f"Unsupported user role for dashboard charts: {user.role!r}")

        return _assemble_charts_payload(stats, is_admin=is_admin)


def _assemble_charts_payload(stats: Dict[str, Any], *, is_admin: bool) -> Dict[str, Any]:
    """Assemble le payload charts à partir d'un dict stats déjà chargé.

    Défense stricte :
    - ``daily_searches`` peut contenir des ``None`` suite à une corruption amont :
      on filtre proprement avant le list-comp.
    - ``success_exec``/``failed_exec`` sont lus directement — jamais reconstitués par
      soustraction (l'ancien ``total - success`` comptait les statuts ``pending``/
      ``running``/``cancelled`` comme échecs, une métrique silencieusement fausse).
    """
    raw_daily = stats.get("daily_searches") or []
    daily_entries = [d for d in raw_daily if isinstance(d, dict)]

    labels = [(d.get("short_label") or d.get("label") or "") for d in daily_entries]
    full_labels = [(d.get("label") or "") for d in daily_entries]
    values = [int(d.get("count") or 0) for d in daily_entries]

    success_exec = max(0, int(stats.get("successful_executions") or 0))
    failed_exec = max(0, int(stats.get("failed_executions") or 0))

    charts_data: Dict[str, Any] = {
        "daily_searches": {
            "labels": labels,
            "values": values,
            "full_labels": full_labels,
        },
        "execution_breakdown": {
            "success": success_exec,
            "failed": failed_exec,
        },
    }

    if is_admin:
        charts_data["feedback"] = {
            "positive": int(stats.get("feedback_positive") or 0),
            "negative": int(stats.get("feedback_negative") or 0),
            "none": int(stats.get("feedback_none") or 0),
        }
        charts_data["overview"] = {
            "searches": int(stats.get("total_searches") or 0),
            "reports": int(stats.get("total_reports") or 0),
            "automations": int(stats.get("total_automations") or 0),
            "emails": int(stats.get("emails_sent") or 0),
        }

    return charts_data


# Singleton process-local — la création est légère mais on évite
# N instanciations par requête.
_stats_service: Optional[DashboardStatsService] = None


def get_stats_service() -> DashboardStatsService:
    """Retourne le singleton :class:`DashboardStatsService`."""
    global _stats_service
    if _stats_service is None:
        _stats_service = DashboardStatsService()
    return _stats_service


__all__ = [
    "DashboardStatsService",
    "_assemble_charts_payload",
    "get_stats_service",
]
