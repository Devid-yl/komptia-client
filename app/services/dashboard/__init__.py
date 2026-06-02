"""Dashboard stats services — split from monolithic DashboardStatsService.

Exporte la **façade** ``DashboardStatsService`` (composition des sous-
services) et les sous-services individuels pour les callers qui n'ont
besoin que d'un sous-ensemble (ex. ``UserStatsService`` pour /settings).
"""

from app.services.dashboard.admin_monitoring import AdminMonitoringService
from app.services.dashboard.admin_stats import AdminStatsService
from app.services.dashboard.charts import (
    DashboardStatsService,
    _assemble_charts_payload,
    get_stats_service,
)
from app.services.dashboard.coherence_checker import (
    CoherenceReport,
    CoherenceWarning,
    check_dashboard_coherence,
)
from app.services.dashboard.recent_data import RecentDataService, calculate_next_execution
from app.services.dashboard.user_stats import UserStatsService

__all__ = [
    "AdminMonitoringService",
    "AdminStatsService",
    "CoherenceReport",
    "CoherenceWarning",
    "DashboardStatsService",
    "RecentDataService",
    "UserStatsService",
    "_assemble_charts_payload",
    "calculate_next_execution",
    "check_dashboard_coherence",
    "get_stats_service",
]
