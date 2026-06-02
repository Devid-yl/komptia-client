"""
Service de santé système — métriques applicatives (NON-IA).

Complète ``performance_stats_service`` (qui couvre les recherches IA via
``SearchHistory``) et ``ai/stats_service`` (qui couvre la performance LLM
détaillée). Ce service expose ce qui se passe AUTOUR de l'IA :

- Process : uptime, mémoire, threads, async tasks.
- Stockage local : taille SQLite, comptage des tables critiques.
- Source de données : santé Sage (ping court, fail-safe).
- Synchronisation : dernière sync de schéma (status + durée).
- Activité 7 j : audit, emails, executions, recherches.

Toutes les méthodes sont **fail-safe** : un service externe en panne
retourne un état dégradé documenté plutôt que de faire planter le dashboard.
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import resource
import sys
import threading
import time
from datetime import timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import case, func, select

from app.config import config
from app.core import clock
from app.core.database import get_session
from app.models.ai_performance import AIPerformanceLog, SchemaSync
from app.models.audit import AuditLog
from app.models.email_log import EmailLog
from app.models.execution import Execution
from app.models.search_history import SearchHistory

logger = logging.getLogger(__name__)


# ── Bornes de validation ───────────────────────────────────────
_MIN_DAYS = 1
_MAX_DAYS = 365
_DEFAULT_DAYS = 7

# Timeout court pour le ping Sage : on ne veut PAS bloquer le rendu
# du dashboard si le serveur SQL Server ne répond pas.
_SAGE_PING_TIMEOUT = 3.0  # secondes

# Même logique pour les providers LLM : un provider cloud lent ne doit pas
# bloquer le rendu du dashboard au-delà de ce délai.
_LLM_PING_TIMEOUT = 3.0  # secondes


def _friendly_error_label(exc: BaseException) -> str:
    """Traduit un type d'exception en libellé court prêt à afficher.

    Le texte brut d'une ``pyodbc.Error`` ou d'une ``httpx`` error peut
    contenir des fragments de DSN, de hostname ou d'URLs d'API — utiles en
    logs mais à éviter dans l'UI admin (principe du moindre disclosure).
    Le ``logger.error(..., exc_info=True)`` du call-site conserve le détail.
    """
    if isinstance(exc, asyncio.TimeoutError):
        return "Timeout de connexion"
    name = type(exc).__name__
    mapping = {
        "ConnectionError": "Erreur de connexion",
        "ConnectionRefusedError": "Connexion refusée",
        "ConnectionResetError": "Connexion interrompue",
        "TimeoutError": "Timeout de connexion",
        "OSError": "Erreur réseau/système",
        "FileNotFoundError": "Configuration manquante",
        "ModuleNotFoundError": "Driver absent",
        "ImportError": "Driver absent",
        "ValueError": "Configuration invalide",
        "KeyError": "Clé de configuration manquante",
        "AttributeError": "Erreur de configuration",
    }
    if name in mapping:
        return mapping[name]
    # Driver-specific (pyodbc, httpx, etc.) — on renvoie juste la famille.
    if "pyodbc" in name.lower() or "odbc" in name.lower():
        return "Erreur pilote ODBC"
    if "http" in name.lower():
        return "Erreur HTTP"
    return "Erreur indéterminée"


# Cache du ping Sage : un onglet admin laissé ouvert ne doit pas spammer
# la BDD source. TTL court (30 s) — l'admin obtient un état "frais" en
# rechargeant toutes les ~30 s sans pression continue sur SQL Server.
_SAGE_STATUS_CACHE_TTL = 30.0  # secondes
_sage_status_cache: Optional[Dict[str, Any]] = None
_sage_status_cache_at: float = 0.0

# Tables suivies dans la section "Stockage local". Ordre = ordre d'affichage.
# Format : (label_ui, modèle SQLAlchemy)
_TRACKED_TABLES = (
    ("Logs IA (AIPerformanceLog)", AIPerformanceLog),
    ("Recherches (SearchHistory)", SearchHistory),
    ("Audit (AuditLog)", AuditLog),
    ("Emails (EmailLog)", EmailLog),
    ("Exécutions (Execution)", Execution),
)

# Cache pour le COUNT(*) des _TRACKED_TABLES. Bug 2026-05-26 (Agent 3 P-7) :
# avant, COUNT(*) sans index = full scan SQLite à chaque page-load. Sur
# une BDD locale de 15 GB × 5 tables × multi-admins × auto-refresh 30s =
# stress inutile. TTL 60s : la précision en cours d'affichage est moins
# importante que la stabilité prod (la valeur ne bouge pas par seconde).
_LOCAL_TABLES_CACHE_TTL_SECONDS: float = 60.0
_local_tables_cache: Optional[List[Dict[str, Any]]] = None
_local_tables_cache_at: float = 0.0


# ── Uptime : enregistré au premier appel ──────────────────────
# (le module est importé au démarrage du serveur Tornado par le handler
# performance, donc ``_PROCESS_START_TS`` reflète l'âge du process Python)
_PROCESS_START_TS = time.time()


def _format_duration(seconds: float) -> str:
    """Formate une durée en secondes vers ``Nj Nh Nm`` (compact)."""
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    if days:
        return f"{days}j {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _format_bytes(num_bytes: int) -> str:
    """Formate un nombre d'octets en unité lisible (KB / MB / GB)."""
    if num_bytes is None:
        return "0 B"
    n = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def _ru_maxrss_to_bytes(ru_maxrss: int) -> int:
    """Convertit ``ru_maxrss`` (unité dépendante de l'OS) en octets.

    macOS : déjà en octets. Linux : kibioctets.
    Référence : ``man getrusage`` + Python issue #28239.
    """
    if sys.platform == "darwin":
        return ru_maxrss
    return ru_maxrss * 1024  # Linux & co


class SystemHealthService:
    """Façade unique pour les blocs "système" du dashboard ``/admin/performance``.

    Chaque méthode renvoie un dict ou une liste avec une structure stable :
    le template ne doit jamais se casser même si un service externe échoue.
    """

    @staticmethod
    def _validate_days(days: int) -> int:
        if not isinstance(days, int) or days <= 0:
            return _DEFAULT_DAYS
        return min(max(days, _MIN_DAYS), _MAX_DAYS)

    # ── Process ────────────────────────────────────────────────
    def get_process_info(self) -> Dict[str, Any]:
        """Retourne l'état du process Python qui sert le dashboard.

        Aucun appel I/O — uniquement modules standard. Sûr en cas d'erreur
        (retourne des chaînes ``"-"``). Pas de dépendance ``psutil``.
        """
        try:
            uptime_s = max(0.0, time.time() - _PROCESS_START_TS)
            ru = resource.getrusage(resource.RUSAGE_SELF)
            try:
                tasks_count = len(asyncio.all_tasks())
            except RuntimeError:
                # Pas de boucle event en cours (ne devrait pas arriver
                # dans un handler async, mais defense-in-depth).
                tasks_count = 0
            return {
                "pid": os.getpid(),
                "uptime_seconds": uptime_s,
                "uptime_human": _format_duration(uptime_s),
                "rss_bytes": _ru_maxrss_to_bytes(ru.ru_maxrss),
                "rss_human": _format_bytes(_ru_maxrss_to_bytes(ru.ru_maxrss)),
                "user_cpu_seconds": round(ru.ru_utime, 2),
                "system_cpu_seconds": round(ru.ru_stime, 2),
                "threads": threading.active_count(),
                "async_tasks": tasks_count,
                "python_version": platform.python_version(),
                "platform": f"{platform.system()} {platform.release()}",
            }
        except Exception:
            logger.error("get_process_info failed", exc_info=True)
            return {
                "pid": 0,
                "uptime_seconds": 0,
                "uptime_human": "-",
                "rss_bytes": 0,
                "rss_human": "-",
                "user_cpu_seconds": 0,
                "system_cpu_seconds": 0,
                "threads": 0,
                "async_tasks": 0,
                "python_version": platform.python_version(),
                "platform": "-",
            }

    # ── Stockage local SQLite ─────────────────────────────────
    async def get_local_storage_info(self) -> Dict[str, Any]:
        """Taille du fichier SQLite + comptes des tables critiques.

        Pour chaque table de ``_TRACKED_TABLES``, retourne le nombre de lignes
        (plafonné via ``COUNT(*)`` — peut être lent sur gros volume mais
        SQLite reste rapide pour des tables < 10M lignes).
        """
        db_path = getattr(config.database, "path", None)
        size_bytes = 0
        path_str = "-"
        if db_path:
            path_str = db_path
            try:
                size_bytes = os.path.getsize(db_path)
            except OSError:
                size_bytes = 0

        # Bug 2026-05-26 (Agent 3 P-7) : COUNT(*) sans index = full scan
        # SQLite sur BDD locale 15 GB × 5 tables. Cache TTL 60s pour
        # absorber les multi-admins × auto-refresh 30s.
        global _local_tables_cache, _local_tables_cache_at
        now_mono = time.monotonic()
        if (
            _local_tables_cache is not None
            and (now_mono - _local_tables_cache_at) < _LOCAL_TABLES_CACHE_TTL_SECONDS
        ):
            tables = list(_local_tables_cache)  # copie défensive
        else:
            tables = []
            try:
                async with get_session() as session:
                    for label, model in _TRACKED_TABLES:
                        try:
                            result = await session.execute(select(func.count()).select_from(model))
                            count = int(result.scalar() or 0)
                        except Exception:
                            # Table absente (migration manquante, etc.) → 0
                            count = 0
                        tables.append({"label": label, "count": count})
                # Cache uniquement si le block n'a pas explosé en cours.
                _local_tables_cache = list(tables)
                _local_tables_cache_at = now_mono
            except Exception:
                logger.error("get_local_storage_info: session failure", exc_info=True)
                tables = [{"label": label, "count": 0} for label, _ in _TRACKED_TABLES]

        return {
            "path": path_str,
            "size_bytes": size_bytes,
            "size_human": _format_bytes(size_bytes),
            # Présence d'une clé en config — pas une garantie que SQLCipher
            # est bien actif sur le runtime (driver pyodbc/sqlite-cipher).
            # Le label UI doit refléter cette nuance.
            "encryption_key_configured": bool(getattr(config.database, "encryption_key", None)),
            "tables": tables,
        }

    # ── Source de données Sage ────────────────────────────────
    async def get_source_db_status(self) -> Dict[str, Any]:
        """Ping rapide de la BDD source (Sage Coala ou équivalent).

        Timeboxé à ``_SAGE_PING_TIMEOUT`` secondes ET caché 30 s côté serveur :
        on ne veut pas qu'un onglet admin laissé ouvert qui rafraîchit la
        page mette le serveur SQL Server sous pression. ``error`` est rempli
        en mode dégradé.
        """
        global _sage_status_cache, _sage_status_cache_at
        now = time.time()
        if (
            _sage_status_cache is not None
            and (now - _sage_status_cache_at) < _SAGE_STATUS_CACHE_TTL
        ):
            return _sage_status_cache

        connector_name = "-"
        ok = False
        latency_ms: Optional[int] = None
        error: Optional[str] = None

        try:
            from app.services.database.sage_connector import get_sage_connector

            connector = get_sage_connector()
            connector_name = type(connector).__name__
            t0 = time.perf_counter()
            try:
                ok = await asyncio.wait_for(connector.health_check(), timeout=_SAGE_PING_TIMEOUT)
            except asyncio.TimeoutError as exc:
                error = _friendly_error_label(exc)
                logger.warning(
                    "get_source_db_status: timeout après %.0fs",
                    _SAGE_PING_TIMEOUT,
                )
            else:
                latency_ms = int((time.perf_counter() - t0) * 1000)
                if not ok:
                    error = "Ping refusé par le connecteur"
        except Exception as exc:
            # Connecteur absent (pas configuré, import path différent, etc.)
            # Détail verbeux en logs uniquement ; UI reçoit un libellé court.
            error = _friendly_error_label(exc)
            logger.debug("get_source_db_status: connector unavailable", exc_info=True)

        result = {
            "connector": connector_name,
            "ok": ok,
            "latency_ms": latency_ms,
            "error": error,
            "cached_at": int(now),
        }
        _sage_status_cache = result
        _sage_status_cache_at = now
        return result

    def invalidate_source_db_cache(self) -> None:
        """Force un ping frais au prochain ``get_source_db_status``.

        Appelé par le bouton "Tester maintenant" du dashboard : l'admin veut
        savoir tout de suite si Sage répond, sans attendre l'expiration du
        TTL de 30 s.
        """
        global _sage_status_cache, _sage_status_cache_at
        _sage_status_cache = None
        _sage_status_cache_at = 0.0

    # ── Santé des providers LLM ───────────────────────────────
    async def get_llm_providers_health(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Ping léger de chaque provider LLM configuré.

        Retourne ``providers`` triés par nom, plus ``any_ok`` / ``all_ok``
        pour alimenter facilement le bandeau du dashboard, et ``cache_age_seconds``
        pour afficher honnêtement la fraîcheur des données (le cache TTL côté
        ``LLMManager`` est de 5 min, supérieur au refresh de la page).

        ``force_refresh=True`` bypasse le cache serveur — utilisé par
        ``LLMProvidersPingHandler`` pour le bouton "Tester maintenant".

        Fail-safe : un timeout ou une exception renvoie un dict neutre plutôt
        que de faire planter le rendu.
        """
        try:
            from app.services.ai.llm_providers import get_llm_manager

            manager = get_llm_manager()
            try:
                results = await asyncio.wait_for(
                    manager.health_check_all(force_refresh=force_refresh),
                    timeout=_LLM_PING_TIMEOUT,
                )
            except asyncio.TimeoutError:
                logger.warning("LLM providers health check: timeout")
                return {
                    "providers": [],
                    "any_ok": False,
                    "all_ok": False,
                    "error": _friendly_error_label(asyncio.TimeoutError()),
                    "cache_age_seconds": None,
                }

            providers = [{"name": name, "ok": bool(ok)} for name, ok in sorted(results.items())]
            any_ok = any(p["ok"] for p in providers) if providers else False
            all_ok = all(p["ok"] for p in providers) if providers else False
            return {
                "providers": providers,
                "any_ok": any_ok,
                "all_ok": all_ok,
                "error": None,
                "cache_age_seconds": manager.get_health_cache_age_seconds(),
            }
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("get_llm_providers_health failed", exc_info=True)
            return {
                "providers": [],
                "any_ok": False,
                "all_ok": False,
                "error": _friendly_error_label(exc),
                "cache_age_seconds": None,
            }

    def invalidate_llm_providers_cache(self) -> None:
        """Force un ping frais au prochain ``get_llm_providers_health``.

        Import paresseux pour éviter la dépendance circulaire au démarrage.
        Fail-safe : aucune exception n'est propagée (le bouton UI n'a pas à
        gérer des erreurs d'infrastructure).
        """
        try:
            from app.services.ai.llm_providers import get_llm_manager

            get_llm_manager().invalidate_health_cache()
        except Exception:
            logger.debug("invalidate_llm_providers_cache failed", exc_info=True)

    # ── Conversations Iris en cours ───────────────────────────
    async def get_active_conversations(self) -> int:
        """Nombre de conversations Iris actuellement ouvertes côté serveur.

        Import paresseux pour éviter une dépendance circulaire au démarrage
        (``agent_service`` importe indirectement ce service via l'orchestrateur).
        Fail-safe : retourne 0 si l'import ou la lecture échouent.
        """
        try:
            from app.services.ai.agent_service import get_active_conversations_count

            return int(get_active_conversations_count())
        except Exception:
            logger.debug("get_active_conversations failed", exc_info=True)
            return 0

    # ── Dernière synchronisation de schéma ────────────────────
    async def get_last_schema_sync(self) -> Optional[Dict[str, Any]]:
        """Récupère le dernier SchemaSync (peu importe son issue)."""
        try:
            async with get_session() as session:
                result = await session.execute(
                    select(SchemaSync).order_by(SchemaSync.created_at.desc()).limit(1)
                )
                last = result.scalar_one_or_none()
                if last is None:
                    return None
                # Capture les valeurs avant que la session se ferme
                return {
                    "id": last.id,
                    "sync_type": last.sync_type,
                    "success": bool(last.success),
                    "duration_seconds": float(last.duration_seconds or 0),
                    "tables_added": last.tables_added or 0,
                    "tables_removed": last.tables_removed or 0,
                    "columns_added": last.columns_added or 0,
                    "columns_removed": last.columns_removed or 0,
                    "total_tables": last.total_tables or 0,
                    "total_columns": last.total_columns or 0,
                    "error_message": last.error_message,
                    "triggered_by": last.triggered_by,
                    "created_at": (last.created_at.isoformat() if last.created_at else None),
                }
        except Exception:
            logger.error("get_last_schema_sync failed", exc_info=True)
            return None

    # ── Activité système (audit / emails / executions) ────────
    async def get_activity_counts(self, days: int = _DEFAULT_DAYS) -> Dict[str, Any]:
        """Compteurs d'activité applicative sur la période demandée.

        Sépare clairement les volumes (combien) et les taux d'échec (signal).
        """
        days = self._validate_days(days)
        since = clock.now() - timedelta(days=days)

        result: Dict[str, Any] = {
            "period_days": days,
            "audit_events": 0,
            "emails_sent": 0,
            "emails_failed": 0,
            "emails_failure_rate": 0.0,
            "executions_total": 0,
            "executions_failed": 0,
            "executions_failure_rate": 0.0,
            "searches_total": 0,
        }
        try:
            async with get_session() as session:
                # Audit
                try:
                    q = await session.execute(
                        select(func.count())
                        .select_from(AuditLog)
                        .where(AuditLog.created_at >= since)
                    )
                    result["audit_events"] = int(q.scalar() or 0)
                except Exception:
                    pass

                # Emails (success / failed) — pattern `case` portable, identique
                # à `performance_stats_service.py` (évite le cast bool fragile).
                try:
                    q = await session.execute(
                        select(
                            func.count().label("total"),
                            func.sum(case((EmailLog.success.is_(True), 1), else_=0)).label("ok"),
                        )
                        .select_from(EmailLog)
                        .where(EmailLog.sent_at >= since)
                    )
                    row = q.first()
                    total_e = int(row.total or 0) if row else 0
                    ok_e = int(row.ok or 0) if row else 0
                    failed_e = max(total_e - ok_e, 0)
                    result["emails_sent"] = total_e
                    result["emails_failed"] = failed_e
                    if total_e > 0:
                        result["emails_failure_rate"] = round(failed_e / total_e * 100, 1)
                except Exception:
                    logger.debug("activity: emails query failed", exc_info=True)

                # Executions (total / failed)
                try:
                    q = await session.execute(
                        select(func.count())
                        .select_from(Execution)
                        .where(Execution.started_at >= since)
                    )
                    total_x = int(q.scalar() or 0)
                    q2 = await session.execute(
                        select(func.count())
                        .select_from(Execution)
                        .where(
                            Execution.started_at >= since,
                            Execution.status == "failed",
                        )
                    )
                    failed_x = int(q2.scalar() or 0)
                    result["executions_total"] = total_x
                    result["executions_failed"] = failed_x
                    if total_x > 0:
                        result["executions_failure_rate"] = round(failed_x / total_x * 100, 1)
                except Exception:
                    logger.debug("activity: executions query failed", exc_info=True)

                # Recherches IA — compteur seul. Bug 2026-05-26 (P-1c MOYEN) :
                # ``SearchHistory`` n'est plus écrite par aucun module actif
                # (vérifié par ``grep "SearchHistory(" app/``). On migre vers
                # ``AIPerformanceLog`` qui EST écrite par tous les flux Iris/agent.
                # Sans cette migration, ce compteur restait figé sur l'historique
                # legacy et trompait l'admin sur l'activité réelle de la plateforme.
                # ``SearchHistory`` reste lue par d'autres surfaces (datastore,
                # dashboard builder) — pas de drop ici. Cf. tasks #84/#85.
                try:
                    q = await session.execute(
                        select(func.count())
                        .select_from(AIPerformanceLog)
                        .where(AIPerformanceLog.created_at >= since)
                    )
                    result["searches_total"] = int(q.scalar() or 0)
                except Exception:
                    pass
        except Exception:
            logger.error("get_activity_counts: session failure", exc_info=True)

        return result


# Singleton
_service: Optional[SystemHealthService] = None


def get_system_health_service() -> SystemHealthService:
    """Singleton ``SystemHealthService``."""
    global _service
    if _service is None:
        _service = SystemHealthService()
    return _service
