"""Cleanup mensuel des jobs APScheduler accumulés.

Deux critères de suppression (cf. tâche M3-apscheduler-jobs-expiration) :

1. **Misfired** : ``next_run_time`` plus ancien que ``misfire_max_age_days``
   jours (défaut 365), OU ``next_run_time`` ``None`` ET trigger épuisé
   (``trigger.get_next_fire_time(None, now) is None``). Un job pausé par
   l'admin avec un fire futur possible est **préservé** (kept_active).

2. **Orphans** : job_id qui matche ``automation_{id}`` ou
   ``dashboard_schedule_{id}`` mais l'entité référencée n'existe plus en
   BDD locale. Cas typique : ``DELETE FROM F_AUTOMATION WHERE id=X`` direct
   en SQL au lieu de passer par l'API (le scheduler ne rescan pas la BDD,
   le job reste planifié à vide).

Sentinelle anti-faux-orphan : si la query BDD échoue (table indisponible,
ImportError sur le model, SQLAlchemyError transitoire), on **NE** considère
**PAS** les jobs comme orphans (fail-closed). Sinon une transaction en cours
d'init ou un crash partiel BDD ferait sauter tous les jobs ``automation_*``
en silence.

Les jobs préfixés ``system_`` / ``_komptia_`` (jobs internes Komptia : cleanup
reports, idempotency purge, retention TTL, etc.) sont **toujours** préservés.

Pattern aligné sur :
- ``app/services/cleanup/db_retention.py`` (fail-soft per-table, log explicite)
- ``app/services/cleanup/pipeline_cleanup.py`` (env override + fail-safe)
- ``app/services/automation/scheduler.py:_purge_idempotency_logs_sync``
  (engine sync local, pas de cross-loop)

Job APScheduler : enregistré dans ``start_scheduler`` (cron mensuel le 1er
du mois à 04:45 — après les autres cleanups quotidiens 02:00-04:30 pour
laisser la BDD libre).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core import clock
from app.core.database import get_db_url

logger = logging.getLogger(__name__)


def _create_sync_engine_with_wal():
    """Crée un engine sync avec ``journal_mode=WAL`` + ``busy_timeout=30s``.

    Aligné sur ``AutomationScheduler.__init__`` (scheduler.py:163-170) pour
    ne pas hold un verrou exclusif SQLite qui bloquerait les automations
    en cours de tourner en parallèle du cleanup mensuel. Sans le
    ``busy_timeout``, un ``OperationalError: database is locked`` peut
    surgir au moindre conflit transitoire.

    Pour PostgreSQL/MySQL ces PRAGMA SQLite sont ignorés silencieusement —
    l'event listener s'exécute mais la commande échoue côté driver.
    """
    engine = create_engine(get_db_url())

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record):
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode = WAL")
            cursor.execute("PRAGMA busy_timeout = 30000")
            cursor.close()
        except Exception:  # noqa: BLE001 — non-SQLite : silently ignore
            pass

    return engine


_DEFAULT_MISFIRE_MAX_AGE_DAYS = 365
_ENV_MISFIRE_MAX_AGE_DAYS = "APSCHEDULER_JOBS_MISFIRE_MAX_AGE_DAYS"

# Préfixes des jobs système Komptia — JAMAIS purger. Toute couche système
# (cleanup TTL, recompute quotidien, etc.) DOIT utiliser un de ces préfixes
# sinon son job tombera dans le misfired/orphan check.
#
# NB : ``resume_exec_{exec_id}`` (handlers/wait_response.py:458) est un
# one-shot DateTrigger immédiat qui NE PASSE PAS par cette whitelist —
# c'est volontaire : après exécution (ou misfire_grace_time = 5 min), il
# devient trigger-épuisé et tombe en ``misfired_exhausted``, ce qui est
# le comportement souhaité (cleanup explicite des one-shots fantômes
# laissés par un crash app pendant l'exécution).
_SYSTEM_JOB_PREFIXES = ("system_", "_komptia_")


def _query_active_entity_ids() -> Dict[str, Dict[str, Any]]:
    """Récupère les IDs des entités BDD référencées par les jobs purgeables.

    Returns:
        Dict avec une entrée par catégorie de job purgeable :
        ``{
            "automation": {"ids": set[int], "ok": bool},
            "dashboard_schedule": {"ids": set[int], "ok": bool},
        }``

        ``ok=False`` signale une lecture BDD ratée — le caller DOIT alors
        skip l'orphan check pour cette catégorie (fail-closed : on ne
        peut pas affirmer qu'un job est orphan si on n'a pas pu vérifier).
    """
    result: Dict[str, Dict[str, Any]] = {
        "automation": {"ids": set(), "ok": False},
        "dashboard_schedule": {"ids": set(), "ok": False},
    }

    # WAL + busy_timeout : éviter de bloquer les automations en cours
    # pendant le cleanup mensuel (cf. scheduler.py:163-170 même pattern).
    engine = _create_sync_engine_with_wal()
    try:
        with Session(engine) as session:
            # Automation : table principale des automations user
            try:
                from app.models.automation import Automation

                rows = session.execute(select(Automation.id)).scalars().all()
                result["automation"] = {"ids": set(rows), "ok": True}
            except (SQLAlchemyError, ImportError):
                logger.warning(
                    "cleanup_apscheduler_jobs: query Automation.id échouée — "
                    "orphan check skippé pour 'automation_*' (fail-closed).",
                    exc_info=True,
                )

            # DashboardSchedule : envois récurrents de dashboards
            try:
                from app.models.dashboard import DashboardSchedule

                rows = session.execute(select(DashboardSchedule.id)).scalars().all()
                result["dashboard_schedule"] = {"ids": set(rows), "ok": True}
            except (SQLAlchemyError, ImportError):
                logger.warning(
                    "cleanup_apscheduler_jobs: query DashboardSchedule.id échouée — "
                    "orphan check skippé pour 'dashboard_schedule_*' (fail-closed).",
                    exc_info=True,
                )
    finally:
        engine.dispose()

    return result


def _is_system_job(job_id: str) -> bool:
    """True si le job_id correspond à un job système Komptia (jamais purger)."""
    return any(job_id.startswith(p) for p in _SYSTEM_JOB_PREFIXES)


def _parse_entity_id(job_id: str, prefix: str) -> Optional[int]:
    """Extrait l'ID entité d'un job_id type ``{prefix}{id}``.

    Returns None si le suffixe n'est pas un int valide (job_id malformé,
    ex ``automation_abc`` ou ``automation_42_v2``). Le caller doit alors
    fall-through vers le misfired check.
    """
    if not job_id.startswith(prefix):
        return None
    suffix = job_id[len(prefix) :]
    try:
        return int(suffix)
    except (TypeError, ValueError):
        return None


def _classify_job(
    job,
    threshold_aware: datetime,
    entity_status: Dict[str, Dict[str, Any]],
) -> str:
    """Classifie un job APScheduler.

    Returns:
        Un des labels suivants :
        - ``"system"`` : job système, kept
        - ``"orphan_automation"`` : automation supprimée, à purger
        - ``"orphan_dashboard"`` : dashboard schedule supprimé, à purger
        - ``"misfired_old"`` : next_run_time > threshold dans le passé
        - ``"misfired_exhausted"`` : next_run_time None + trigger épuisé
        - ``"kept_active"`` : job avec exécution future possible
    """
    job_id = job.id

    if _is_system_job(job_id):
        return "system"

    # Orphan check — automation
    # Sentinelle fail-closed COMPLÈTE : si la query BDD a échoué, on ne
    # purge PAS du tout les jobs ``automation_*`` (ni orphan ni misfired).
    # Sinon une panne BDD transitoire pendant le cleanup mensuel pourrait
    # supprimer des jobs runtime légitimes via la branche misfired
    # (next_run_time très ancien sur un job auto qui a été down un an).
    # Le cleanup retentera le mois suivant quand la BDD sera lisible.
    auto_id = _parse_entity_id(job_id, "automation_")
    if auto_id is not None:
        auto_status = entity_status.get("automation", {})
        if not auto_status.get("ok"):
            return "kept_active"
        if auto_id not in auto_status.get("ids", set()):
            return "orphan_automation"
        # Auto existe : fall-through vers misfired check au cas où le
        # job est aussi trop ancien (improbable mais cohérent — l'admin
        # peut re-trigger via /automations qui re-add le job).

    # Orphan check — dashboard_schedule (même logique fail-closed).
    dash_id = _parse_entity_id(job_id, "dashboard_schedule_")
    if dash_id is not None:
        dash_status = entity_status.get("dashboard_schedule", {})
        if not dash_status.get("ok"):
            return "kept_active"
        if dash_id not in dash_status.get("ids", set()):
            return "orphan_dashboard"

    # Misfired check
    next_run = getattr(job, "next_run_time", None)
    if next_run is None:
        # Trigger épuisé ? On demande au trigger lui-même.
        try:
            now_aware = clock.now()
            future_fire = job.trigger.get_next_fire_time(None, now_aware)
        except Exception:  # noqa: BLE001 — trigger malformé, considère épuisé
            future_fire = None
        if future_fire is None:
            return "misfired_exhausted"
        return "kept_active"

    try:
        if next_run < threshold_aware:
            return "misfired_old"
    except TypeError:
        # next_run naive vs threshold aware (cas pathologique). On garde
        # par défaut — ne pas casser le cleanup sur un edge bizarre.
        logger.warning(
            "cleanup_apscheduler_jobs: comparaison TZ échouée pour job %s "
            "(next_run_time=%r, threshold=%r). Skip.",
            job_id,
            next_run,
            threshold_aware,
        )
        return "kept_active"

    return "kept_active"


def cleanup_apscheduler_jobs(
    misfire_max_age_days: int = _DEFAULT_MISFIRE_MAX_AGE_DAYS,
    *,
    dry_run: bool = False,
    scheduler_instance: Optional[Any] = None,
) -> Dict[str, int]:
    """Purge les jobs APScheduler obsolètes (misfired ou orphans).

    Args:
        misfire_max_age_days: seuil en jours pour considérer un job avec
            ``next_run_time`` ancien comme misfired. DOIT être > 0
            (fail-fast sinon — supprimer 100% des jobs ne peut pas être
            un comportement par défaut).
        dry_run: si True, ne supprime rien — retourne les stats de ce
            qui aurait été supprimé. Utile pour audit/preview.
        scheduler_instance: AutomationScheduler à utiliser. Si None,
            utilise le singleton via ``get_scheduler()``.

    Returns:
        Dict de stats :
            - ``scanned_total``: nombre total de jobs scannés
            - ``removed_misfired``: jobs supprimés (misfired_old +
              misfired_exhausted)
            - ``removed_orphan_automation``: jobs orphans
              (automation supprimée)
            - ``removed_orphan_dashboard``: jobs orphans
              (dashboard schedule supprimé)
            - ``kept_system``: jobs système préservés
            - ``kept_active``: jobs avec exécution future possible
            - ``errors``: nombre d'erreurs durant ``remove_job``

    Raises:
        ValueError: si ``misfire_max_age_days <= 0``.
    """
    if misfire_max_age_days <= 0:
        raise ValueError(
            f"cleanup_apscheduler_jobs: misfire_max_age_days doit être > 0 "
            f"(reçu {misfire_max_age_days}); supprimer 100% des jobs ne peut "
            "pas être un comportement par défaut."
        )

    if scheduler_instance is None:
        # Lazy import pour éviter cycle au boot
        from app.services.automation.scheduler import get_scheduler

        scheduler_instance = get_scheduler()

    apscheduler = scheduler_instance.scheduler

    now_aware = clock.now()
    threshold_aware = now_aware - timedelta(days=misfire_max_age_days)

    stats = {
        "scanned_total": 0,
        "removed_misfired": 0,
        "removed_orphan_automation": 0,
        "removed_orphan_dashboard": 0,
        "kept_system": 0,
        "kept_active": 0,
        "errors": 0,
    }

    entity_status = _query_active_entity_ids()

    try:
        jobs = apscheduler.get_jobs()
    except Exception:  # noqa: BLE001 — scheduler indispo, return stats vides
        logger.exception("cleanup_apscheduler_jobs: get_jobs() a échoué — abort")
        return stats

    # Pass 1 : classification (read-only)
    to_remove = []  # liste de (job_id, label)
    for job in jobs:
        stats["scanned_total"] += 1
        try:
            label = _classify_job(job, threshold_aware, entity_status)
        except Exception:  # noqa: BLE001 — job malformé, log et skip
            logger.exception(
                "cleanup_apscheduler_jobs: classification job %r échouée",
                getattr(job, "id", "<unknown>"),
            )
            stats["errors"] += 1
            continue

        if label == "system":
            stats["kept_system"] += 1
        elif label == "kept_active":
            stats["kept_active"] += 1
        elif label in (
            "orphan_automation",
            "orphan_dashboard",
            "misfired_old",
            "misfired_exhausted",
        ):
            to_remove.append((job.id, label))
        else:
            # Cas inattendu — log et keep par défaut
            logger.warning(
                "cleanup_apscheduler_jobs: label inconnu %r pour job %s, kept",
                label,
                job.id,
            )
            stats["kept_active"] += 1

    # Pass 2 : suppression (optionnelle si dry_run)
    for job_id, label in to_remove:
        if not dry_run:
            try:
                apscheduler.remove_job(job_id)
            except Exception as exc:  # noqa: BLE001 — log et continue
                logger.warning(
                    "cleanup_apscheduler_jobs: remove_job(%s) échec : %s",
                    job_id,
                    exc,
                )
                stats["errors"] += 1
                continue

        if label == "orphan_automation":
            stats["removed_orphan_automation"] += 1
        elif label == "orphan_dashboard":
            stats["removed_orphan_dashboard"] += 1
        elif label in ("misfired_old", "misfired_exhausted"):
            stats["removed_misfired"] += 1

    logger.info(
        "cleanup_apscheduler_jobs: scanned=%d removed_misfired=%d "
        "orphan_auto=%d orphan_dash=%d kept_system=%d kept_active=%d "
        "errors=%d dry_run=%s",
        stats["scanned_total"],
        stats["removed_misfired"],
        stats["removed_orphan_automation"],
        stats["removed_orphan_dashboard"],
        stats["kept_system"],
        stats["kept_active"],
        stats["errors"],
        dry_run,
    )
    return stats


def _read_env_misfire_days() -> int:
    """Lit ``APSCHEDULER_JOBS_MISFIRE_MAX_AGE_DAYS`` depuis l'env.

    Fallback sur ``_DEFAULT_MISFIRE_MAX_AGE_DAYS`` si non défini, vide,
    non-int, ou <= 0 (anti-fallback silencieux : log warning visible).
    """
    raw = os.environ.get(_ENV_MISFIRE_MAX_AGE_DAYS, "")
    if not raw:
        return _DEFAULT_MISFIRE_MAX_AGE_DAYS
    try:
        value = int(raw)
        if value <= 0:
            logger.warning(
                "%s = %r interprété comme <= 0, fallback %d jours",
                _ENV_MISFIRE_MAX_AGE_DAYS,
                raw,
                _DEFAULT_MISFIRE_MAX_AGE_DAYS,
            )
            return _DEFAULT_MISFIRE_MAX_AGE_DAYS
        return value
    except (TypeError, ValueError):
        logger.warning(
            "%s = %r non-int, fallback %d jours",
            _ENV_MISFIRE_MAX_AGE_DAYS,
            raw,
            _DEFAULT_MISFIRE_MAX_AGE_DAYS,
        )
        return _DEFAULT_MISFIRE_MAX_AGE_DAYS


def cleanup_apscheduler_jobs_job() -> None:
    """Wrapper APScheduler — appelle ``cleanup_apscheduler_jobs`` avec env.

    Le scheduler ne doit JAMAIS planter sur une exception du cleanup —
    on log et on return None pour que le prochain run (le mois suivant)
    re-tente proprement.
    """
    try:
        days = _read_env_misfire_days()
        cleanup_apscheduler_jobs(misfire_max_age_days=days)
    except Exception:  # noqa: BLE001 — fail-safe scheduler
        logger.exception("cleanup_apscheduler_jobs_job: échec")
