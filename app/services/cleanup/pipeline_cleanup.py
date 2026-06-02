"""Cleanup TTL des ``PipelineRun`` + dossiers ``outputs/runs/{N}``.

Job APScheduler enregistré par ``app.services.automation.scheduler.start_scheduler``.
Tourne quotidiennement (cron 04:30) — après les autres jobs cleanup.

Stratégie :

- Supprime les ``PipelineRun`` plus vieux que ``PIPELINE_RUN_RETENTION_DAYS``
  (env, défaut 30 jours) — calculé sur ``finished_at`` (priorité) ou
  ``created_at`` (fallback pour les runs jamais finis qui sont restés en
  ``failed`` après un crash).
- Le ``cascade="all, delete-orphan"`` côté ORM supprime
  automatiquement les ``PipelinePhaseExecution`` liées.
- Pour chaque run supprimé, supprime le dossier filesystem correspondant
  (``outputs/runs/{run_id}/``). Best-effort : un échec rmtree log un
  warning mais ne bloque pas la transaction.

Doctrine alignée sur ``app/services/cleanup/db_retention.py`` — engine
sync local, isolation transactionnelle, fail-safe.
"""

from __future__ import annotations

import logging
import os
import shutil
from datetime import timedelta
from pathlib import Path

from sqlalchemy import and_, create_engine, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core import clock
from app.core.database import get_db_url

logger = logging.getLogger(__name__)


_DEFAULT_RETENTION_DAYS = 30
# A6-#6 (adversarial) : un run PAUSED est un checkpoint durable resumable, donc
# il n'est PAS purgé par le TTL des terminaux (garde de statut F3) NI réconcilié
# au boot (exclu de reconcile_orphan_runs). Sans cleanup dédié il resterait en
# BDD + dossier disque à VIE → croissance non bornée (axe 21). On le purge après
# une fenêtre d'ABANDON plus longue : un PAUSED jamais repris depuis N jours est
# considéré abandonné (son snapshot est mort). Configurable, borné ≥ rétention.
_DEFAULT_PAUSED_ABANDON_DAYS = 90


def _retention_days() -> int:
    raw = os.environ.get("PIPELINE_RUN_RETENTION_DAYS", str(_DEFAULT_RETENTION_DAYS))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_RETENTION_DAYS
    return max(1, value)


def _paused_abandon_days() -> int:
    """Fenêtre d'abandon des runs PAUSED (env ``PIPELINE_PAUSED_ABANDON_DAYS``).

    Bornée à ``>= _retention_days()`` : un checkpoint PAUSED ne doit jamais être
    purgé PLUS TÔT qu'un run terminal (sinon on perdrait une reprise possible
    avant un run déjà fini).
    """
    raw = os.environ.get("PIPELINE_PAUSED_ABANDON_DAYS", str(_DEFAULT_PAUSED_ABANDON_DAYS))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = _DEFAULT_PAUSED_ABANDON_DAYS
    return max(_retention_days(), value)


def cleanup_pipeline_runs_job() -> None:
    """Job APScheduler sync — purge ``PipelineRun`` au-delà du TTL.

    Supprime aussi les dossiers ``outputs/runs/{run_id}/`` correspondants.
    Best-effort sur le filesystem (un échec rmtree n'invalide pas la
    purge BDD — log warning et continue).
    """

    try:
        from app.models.pipeline_run import PipelineRun, PipelineRunStatus
    except ImportError:
        logger.exception("cleanup_pipeline_runs: PipelineRun model unavailable")
        return

    try:
        from app.services.ai.pipeline_runner import PIPELINE_RUNS_ROOT
    except ImportError:
        logger.exception("cleanup_pipeline_runs: pipeline_runner unavailable")
        PIPELINE_RUNS_ROOT = Path("outputs/runs")  # fallback safe

    retention_days = _retention_days()
    cutoff = clock.now() - timedelta(days=retention_days)
    # Les rows BDD stockent en datetime naive UTC (cf. doctrine ensure_utc) —
    # on aligne pour la comparaison.
    cutoff_naive = cutoff.replace(tzinfo=None)
    # Fenêtre d'abandon distincte (plus longue) pour les PAUSED (A6-#6).
    paused_abandon_days = _paused_abandon_days()
    paused_cutoff_naive = (clock.now() - timedelta(days=paused_abandon_days)).replace(tzinfo=None)

    engine = create_engine(get_db_url())
    deleted_count = 0
    try:
        with Session(engine) as session:
            stmt = select(PipelineRun.id, PipelineRun.output_dir).where(
                or_(
                    # Run terminé (success/failed/cancelled) avec finished_at ancien
                    PipelineRun.finished_at <= cutoff_naive,
                    # A6-F3 : run sans finished_at + created_at ancien — MAIS
                    # seulement s'il est TERMINAL (SSoT PipelineRunStatus.terminal()).
                    # Sans cette garde, un run encore ACTIF (PENDING/RUNNING —
                    # long-running ou bloqué sur un ask_user) créé il y a >TTL jours
                    # était purgé sous ses pieds (perte de données : row + rmtree).
                    # Les zombies PENDING/RUNNING sont réconciliés FAILED au boot
                    # (A6-F2) puis purgés au cycle suivant.
                    and_(
                        PipelineRun.created_at <= cutoff_naive,
                        PipelineRun.status.in_(tuple(PipelineRunStatus.terminal())),
                    ),
                    # A6-#6 : PAUSED abandonné (jamais repris) — purge d'ABANDON
                    # avec un cutoff plus long. PAUSED n'est ni terminal (échappe à
                    # la branche ci-dessus) ni réconcilié au boot (checkpoint durable)
                    # → sans ceci il fuirait row+disque à vie (axe 21).
                    and_(
                        PipelineRun.status == PipelineRunStatus.PAUSED,
                        PipelineRun.created_at <= paused_cutoff_naive,
                    ),
                )
            )
            result = session.execute(stmt)
            to_delete = list(result.all())

            if not to_delete:
                logger.info(
                    "cleanup_pipeline_runs: 0 runs à purger (TTL=%dj)",
                    retention_days,
                )
                return

            for run_id, output_dir in to_delete:
                # Supprime le row BDD (cascade delete-orphan supprimera les
                # PipelinePhaseExecution liées).
                obj = session.get(PipelineRun, run_id)
                if obj is not None:
                    session.delete(obj)
                    deleted_count += 1

                # Supprime le dossier filesystem (best-effort).
                try:
                    if output_dir:
                        target = Path(output_dir)
                    else:
                        target = PIPELINE_RUNS_ROOT / str(run_id)
                    if target.exists() and target.is_dir():
                        # Garde-fou : refuse de rmtree si target est hors de
                        # PIPELINE_RUNS_ROOT (évite un cleanup mal configuré
                        # qui ferait sauter `/etc` ou similaire).
                        target_resolved = target.resolve()
                        root_resolved = PIPELINE_RUNS_ROOT.resolve()
                        try:
                            target_resolved.relative_to(root_resolved)
                        except ValueError:
                            logger.warning(
                                "cleanup_pipeline_runs: refus rmtree (%s hors de %s)",
                                target_resolved,
                                root_resolved,
                            )
                            continue
                        shutil.rmtree(target_resolved)
                except OSError as exc:
                    logger.warning(
                        "cleanup_pipeline_runs: rmtree failed for run %s: %s",
                        run_id,
                        exc,
                    )

            session.commit()
            logger.info(
                "cleanup_pipeline_runs: %d runs purgés (TTL=%dj)",
                deleted_count,
                retention_days,
            )
    except SQLAlchemyError:
        logger.exception("cleanup_pipeline_runs: SQL error")
    finally:
        engine.dispose()
