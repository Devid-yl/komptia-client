"""
Scheduler pour automatisations Komptia.

Utilise APScheduler avec SQLAlchemyJobStore pour la persistance des jobs.
"""

import logging
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import (
    datetime,
    timedelta,
    timezone,
)  # noqa: F401 (timezone: fix bug pré-existant ligne ~295)

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.job import Job

from app.core import clock
from app.core.database import get_db_url, make_sync_engine

logger = logging.getLogger(__name__)


def _purge_orphan_iris_conversations_sync() -> None:
    """Job sync APScheduler : purge les Conversation `source='automation'` orphelines.

    Tasks #7/#46 (2026-05-27, adversarial review) — anti-croissance non
    bornée (axe 21 Komptia). Chaque run d'auto avec step iris crée une
    conv transient (is_active=False, source=AUTOMATION) pour audit. Sans
    cleanup, une auto schedulée */1min génère 525 600 conv/an.

    Suppression : `DELETE FROM conversations WHERE source='automation'
    AND is_active=0 AND created_at < NOW() - INTERVAL X DAY`. La CASCADE
    FK supprime aussi les ConversationMessage et ConversationEvent liés.

    Retention via ``db_retention._get_retention_days("AUTOMATION_CONV_RETENTION_DAYS")``
    default 30j, override via ENV. Pattern aligné sur les autres jobs.
    """
    try:
        from datetime import timedelta

        from sqlalchemy import delete as _sql_delete
        from sqlalchemy.orm import Session

        from app.models.conversation import Conversation, ConversationSource
        from app.services.cleanup.db_retention import _get_retention_days

        retention_days = _get_retention_days("AUTOMATION_CONV_RETENTION_DAYS")
        engine = make_sync_engine(get_db_url())
        try:
            cutoff = clock.now() - timedelta(days=retention_days)
            cutoff_naive_utc = cutoff.replace(tzinfo=None)
            with Session(engine) as session:
                stmt = _sql_delete(Conversation).where(
                    Conversation.source == ConversationSource.AUTOMATION.value,
                    Conversation.is_active.is_(False),
                    Conversation.created_at < cutoff_naive_utc,
                )
                result = session.execute(stmt)
                purged = max(result.rowcount or 0, 0)
                if purged:
                    session.commit()
                    logger.info(
                        "Purge orphan iris conversations: %d conv supprimées "
                        "(retention=%dj, CASCADE messages/events)",
                        purged,
                        retention_days,
                    )
        finally:
            engine.dispose()
    except (SQLAlchemyError, OSError, ConnectionError, ValueError):
        logger.error("Echec purge orphan iris conversations", exc_info=True)


def _purge_idempotency_logs_sync() -> None:
    """Job sync APScheduler : purge les IdempotencyLog expires.

    Pattern aligne sur `cleanup_orphaned_executions_job` /
    `cleanup_expired_reports_job` (engine sync local, pas de cross-loop).
    Tourne dans un thread worker APScheduler — aucun event loop implique.
    """
    try:
        from sqlalchemy import delete as _sql_delete
        from sqlalchemy.orm import Session

        engine = make_sync_engine(get_db_url())
        try:
            now = clock.now()
            with Session(engine) as session:
                # Import here to avoid circular imports
                from app.models.idempotency_log import IdempotencyLog

                # G2 — Filtrage SQL-side. Avant : SELECT * + filtre Python =
                # OOM worker à 1M+ entrees. Maintenant : DELETE WHERE en SQL.
                # Naive UTC pour cohérence avec les rows écrites en datetime.utcnow().
                now_naive_utc = now.replace(tzinfo=None)
                stmt = _sql_delete(IdempotencyLog).where(IdempotencyLog.expires_at <= now_naive_utc)
                result = session.execute(stmt)
                expired_count = max(result.rowcount or 0, 0)
                if expired_count:
                    session.commit()
                    logger.info(
                        "Purge IdempotencyLog: %d entrees expirees supprimees",
                        expired_count,
                    )
        finally:
            engine.dispose()
    except (SQLAlchemyError, OSError, ConnectionError, ValueError):
        logger.error("Echec purge IdempotencyLog", exc_info=True)


def _validate_cron_field(value: str, min_val: int, max_val: int, field_name: str) -> None:
    """Validate a single cron field value."""
    # Allow wildcards
    if value == "*":
        return

    # Handle step values: */N or M-N/S
    if "/" in value:
        parts = value.split("/", 1)
        base, step = parts
        if base != "*":
            _validate_cron_field(base, min_val, max_val, field_name)
        try:
            step_val = int(step)
            if step_val < 1:
                raise ValueError(f"Cron {field_name}: pas invalide '{step}' (doit être >= 1)")
        except ValueError as e:
            if "pas invalide" in str(e):
                raise
            raise ValueError(f"Cron {field_name}: pas non numérique '{step}'")
        return

    # Handle ranges: M-N
    if "-" in value:
        parts = value.split("-", 1)
        if len(parts) == 2:
            try:
                low, high = int(parts[0]), int(parts[1])
                if not (min_val <= low <= max_val and min_val <= high <= max_val):
                    raise ValueError(
                        f"Cron {field_name}: range {low}-{high} hors limites ({min_val}-{max_val})"
                    )
                if low > high:
                    raise ValueError(f"Cron {field_name}: range inversé {low}-{high}")
            except ValueError as e:
                if "Cron" in str(e):
                    raise
                raise ValueError(f"Cron {field_name}: valeur non numérique dans range '{value}'")
        return

    # Handle lists: M,N,O
    if "," in value:
        for item in value.split(","):
            _validate_cron_field(item.strip(), min_val, max_val, field_name)
        return

    # Simple numeric value
    try:
        num = int(value)
        if not (min_val <= num <= max_val):
            raise ValueError(f"Cron {field_name}: valeur {num} hors limites ({min_val}-{max_val})")
    except ValueError as e:
        if "Cron" in str(e):
            raise
        raise ValueError(f"Cron {field_name}: valeur non numérique '{value}'")


def _check_dst_window(cron_expr: str, trigger: "CronTrigger") -> None:
    """Cluster-H (H3) 2026-05-26 — Log warning si cron daily dans la
    fenêtre DST risquée (02:00-03:00) sur timezone à DST (Europe/*, etc.).

    Spring-forward (Mars dernier dim) : 02:30 → "n'existe pas" → cron skip
    silencieusement ce jour. Fall-back (Octobre) : 02:30 → existe DEUX
    FOIS, coalesce ne fire qu'une → data extract perd 1h.

    Best-effort : on parse l'heure du cron, on vérifie si elle est dans
    la fenêtre, et si oui on log. NE BLOQUE PAS — l'admin peut avoir
    une raison légitime.
    """
    try:
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            return
        # Champ heure = parts[1]. Si simple int dans [2, 3) → fenêtre
        hour_field = parts[1]
        if hour_field == "*" or "/" in hour_field or "," in hour_field:
            return  # complexe, on ne traite pas
        if "-" in hour_field:
            # range type "2-3" : warning si overlap
            try:
                lo, hi = map(int, hour_field.split("-"))
            except ValueError:
                return
            if not (lo <= 2 <= hi or lo <= 3 <= hi):
                return
        else:
            try:
                h = int(hour_field)
            except ValueError:
                return
            if h not in (2, 3):
                return

        # Timezone DST-sensitive : Europe/*, America/* (sauf Phoenix/etc),
        # Australia/* (hors WA). Heuristique simple : si le nom contient
        # 'Europe/' ou un autre indicateur DST connu.
        tz = trigger.timezone
        tz_name = str(tz) if tz else ""
        if not any(
            tz_name.startswith(p) for p in ("Europe/", "America/", "Australia/", "Pacific/Auckland")
        ):
            return  # timezone non-DST ou inconnue

        logger.warning(
            "Cron daily %r dans la fenêtre DST risquée (02:00-03:00, "
            "timezone=%s). Au printemps cette heure n'existera pas (skip) "
            "et à l'automne elle existera deux fois (fire une seule, "
            "coalesce=True). Adapter à 01:30 ou 04:00 pour éviter.",
            cron_expr,
            tz_name,
        )
    except Exception:  # noqa: BLE001 — warning best-effort
        # On NE bloque jamais sur l'analyse DST (fail-safe).
        pass


def validate_cron_expression(cron_expr: str) -> None:
    """Validate a full cron expression (5 fields: minute hour day month day_of_week).

    Cluster-H 2026-05-26 — Validation à 3 niveaux :

    1. **Numeric strict** (notre parser custom) — rapide, message d'erreur
       français, refuse les valeurs hors-bornes. Accepté en premier pour
       préserver les tests legacy et les messages familiers.

    2. **APScheduler fallback** (``CronTrigger.from_crontab``) — accepte
       les alias standards (MON-FRI, JAN-DEC, L, W, #) que notre parser
       custom rejette. Si custom rate ET APScheduler accepte → on accepte
       (extension transparente).

    3. **Sémantique** : ``get_next_fire_time(None, now)`` doit retourner
       un datetime. Sinon (ex: "31 février" → calendrier impossible),
       l'expression est syntaxiquement valide mais ne déclenchera JAMAIS
       — c'est un bug silent qu'on doit attraper à la création.

    4. **DST window** (best-effort, log warning seulement) : daily entre
       02:00-03:00 sur timezone DST → skip/duplicate biannuel.
    """
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        raise ValueError(
            f"Expression cron invalide '{cron_expr}': attendu 5 champs, reçu {len(parts)}"
        )

    fields = [
        ("minute", 0, 59),
        ("heure", 0, 23),
        ("jour", 1, 31),
        ("mois", 1, 12),
        ("jour_semaine", 0, 6),
    ]

    # Niveau 1 : parser numeric strict (existant)
    custom_error: Optional[ValueError] = None
    try:
        for (field_name, min_val, max_val), value in zip(fields, parts):
            _validate_cron_field(value, min_val, max_val, field_name)
    except ValueError as exc:
        custom_error = exc

    # Niveau 2 : si custom rate, fallback APScheduler (accepte alias
    # MON-FRI, L, W, #). Si APScheduler accepte aussi → l'expression
    # est valide, on continue. Sinon on remonte l'erreur la plus
    # explicite (custom > APScheduler).
    try:
        trigger = CronTrigger.from_crontab(cron_expr)
    except (ValueError, TypeError) as apscheduler_exc:
        if custom_error is not None:
            raise custom_error
        raise ValueError(
            f"Expression cron '{cron_expr}' rejetée par APScheduler : {apscheduler_exc}"
        ) from apscheduler_exc

    # Si custom a rate mais APScheduler accepte (alias type MON-FRI) :
    # on accepte (extension transparente).

    # Niveau 3 : sémantique — l'expression doit déclencher au moins une fois
    # dans un avenir raisonnable. Cluster-H (H1) : "31 février" parse OK
    # mais next_fire_time = None → silent failure si on laisse passer.
    tz = trigger.timezone or timezone.utc
    try:
        next_fire = trigger.get_next_fire_time(None, clock.now().astimezone(tz))
    except (TypeError, ValueError):
        next_fire = None
    if next_fire is None:
        raise ValueError(
            f"Cette expression cron ne déclenchera jamais : '{cron_expr}'. "
            "Vérifiez les valeurs (ex: 31 février n'existe pas, "
            "ou un range jour/mois impossible)."
        )

    # Niveau 4 : DST window warning (best-effort log)
    _check_dst_window(cron_expr, trigger)


class AutomationScheduler:
    """
    Scheduler pour exécuter les automatisations de manière planifiée.

    Utilise APScheduler avec:
    - BackgroundScheduler: exécution en arrière-plan
    - SQLAlchemyJobStore: persistance en BDD
    - ThreadPoolExecutor: exécution parallèle
    """

    def __init__(self, db_url: Optional[str] = None):
        """
        Initialise le scheduler.

        Args:
            db_url: URL de connexion à la base de données. Si None, utilise get_db_url().
        """
        self.db_url = db_url or get_db_url()

        # Create engine with WAL mode + busy_timeout so APScheduler
        # doesn't hold exclusive locks that block the async app.
        # make_sync_engine pose WAL + busy_timeout (via setup_pragmas) ET
        # PRAGMA key (SQLCipher) — sinon le jobstore APScheduler ne pourrait
        # pas lire une base chiffrée (« file is not a database »).
        engine = make_sync_engine(self.db_url)

        # Configuration du job store
        jobstores = {"default": SQLAlchemyJobStore(engine=engine, tablename="apscheduler_jobs")}

        # Configuration des executors
        # 2026-05-27 (Task #41) : max_workers ENV-configurable car lié à la
        # capacité machine (CPU/RAM). Default 5 = valeur historique.
        # Override via ``KOMPTIA_SCHEDULER_MAX_WORKERS`` (instance-spécifique).
        try:
            _scheduler_max_workers = int(os.environ.get("KOMPTIA_SCHEDULER_MAX_WORKERS", "5"))
            if _scheduler_max_workers < 1:
                _scheduler_max_workers = 5
        except (TypeError, ValueError):
            _scheduler_max_workers = 5
        executors = {"default": ThreadPoolExecutor(max_workers=_scheduler_max_workers)}

        # Configuration générale
        job_defaults = {
            "coalesce": True,  # Fusionner les exécutions manquées
            "max_instances": 1,  # 1 seule instance par job
            "misfire_grace_time": 300,  # 5 minutes de tolérance
        }

        # Créer le scheduler — TZ machine via config.server.timezone
        # (resolu par `_get_default_timezone()` qui retourne un IANA
        # name valide, ex `America/Guadeloupe`, `Europe/Paris`, `UTC`).
        # Hardcoder une TZ specifique (cf. `Europe/Paris` historique)
        # casse silencieusement sur tout deploiement hors France :
        # un cron `daily at 09:00` se declencherait en heure de Paris,
        # pas en heure locale comme l'utilisateur l'attend.
        from app.config import config as _komptia_config

        _tz_name = _komptia_config.server.timezone
        self.scheduler = BackgroundScheduler(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults,
            timezone=_tz_name,
        )

        # A7-F4 — True si ce process a renoncé à démarrer le scheduler
        # (follower du leader-lock, OU KOMPTIA_SCHEDULER_ENABLED=false). Sur un
        # tel worker, ``add_job`` au runtime (toggle d'activation) stockerait un
        # job dans un scheduler mort qui ne se déclenchera JAMAIS → l'utilisateur
        # croit l'auto planifiée (faux « scheduled »). Le flag rend ce cas
        # NON-SILENCIEUX (cf. add_job). Reste False en single-process (défaut).
        self._is_passive_worker = False

        logger.info(
            "AutomationScheduler initialisé (timezone=%s)",
            _tz_name,
        )

    def start(self):
        """Démarre le scheduler.

        ⚠️ G3 cycle 8 — **Multi-worker** : ce scheduler tourne dans le
        process Python courant. Si Tornado est lancé avec ``gunicorn -w N``
        (N workers), CHAQUE worker démarre son propre scheduler →
        N exécutions de chaque cron job → emails dupliqués, BDD chargée.

        **Contrat actuel** : Komptia est conçu pour un **single-process
        Tornado** (event loop async natif). ``make run`` / ``make run-prod``
        respectent cette contrainte. Si l'opérateur passe en multi-worker
        sans précaution, il devra implémenter un leader-election (advisory
        lock SQLite/PG, ou désactiver le scheduler sur tous les workers
        sauf un via env ``KOMPTIA_SCHEDULER_ENABLED=false``).

        Pour minimiser le risque, on log un WARNING explicite si
        ``KOMPTIA_WORKER_COUNT > 1`` au boot — l'admin voit le risque
        avant que les emails dupliqués arrivent en prod.

        **Cluster-F-FOLLOWUP (F2) 2026-05-26 — Leader election file-lock** :
        en plus du WARNING, on tente d'acquérir un ``fcntl.flock`` exclusif
        sur ``KOMPTIA_SCHEDULER_LOCK_PATH`` (défaut
        ``/tmp/komptia_scheduler.lock``). Le 2ᵉ process qui démarre échoue
        à acquérir le lock → log warning + refuse de start (au lieu de
        cron-double-fire silencieux). Le lock est relâché automatiquement
        à process exit (kernel garbage-collection). Approche compatible
        single-host gunicorn multi-worker. Pour Kubernetes multi-pod, il
        faudra un advisory lock BDD (pas implémenté ici — cf. brainstorm
        cluster-F dette).
        """
        if not self.scheduler.running:
            # G3 — Detection multi-worker. La var est posee par main.py
            # (ou docker-compose) si l'app tourne avec plusieurs workers.
            # Sans var, on assume single-worker (defaut sur).
            import os as _os

            worker_count_raw = _os.environ.get("KOMPTIA_WORKER_COUNT", "1")
            try:
                worker_count = int(worker_count_raw)
            except (TypeError, ValueError):
                worker_count = 1
            scheduler_disabled = _os.environ.get("KOMPTIA_SCHEDULER_ENABLED", "true").lower() in (
                "false",
                "0",
                "no",
                "off",
            )
            if scheduler_disabled:
                logger.warning(
                    "⚠️ Scheduler explicitement desactive (KOMPTIA_SCHEDULER_ENABLED=false). "
                    "Aucun cron job ne sera execute par ce process. **CONTRAT** : AU "
                    "MOINS UN worker gunicorn doit avoir SCHEDULER_ENABLED=true (la "
                    "valeur par defaut) — sinon le job de purge IdempotencyLog (horaire) "
                    "ne tourne nulle part et la BDD locale grossit sans bornes (axe 21). "
                    "Ce process refuse-t-il aussi les automatisations cron ? OUI : pas de "
                    "scheduler = pas de declenchement par cron. Les triggers manuels et "
                    "webhooks restent OK (independants du scheduler)."
                )
                self._is_passive_worker = True  # A7-F4
                return  # Skip start
            if worker_count > 1:
                logger.warning(
                    "⚠️ Multi-worker detecte (KOMPTIA_WORKER_COUNT=%d) — chaque "
                    "worker demarre son propre scheduler, ce qui DUPLIQUE les "
                    "executions cron (emails envoyes %dx). Solution : poser "
                    "KOMPTIA_SCHEDULER_ENABLED=false sur tous les workers sauf UN, "
                    "ou laisser le file-lock cluster-F-FOLLOWUP arbitrer.",
                    worker_count,
                    worker_count,
                )

            # Cluster-F-FOLLOWUP (F2) 2026-05-26 — File-lock leader election.
            # Tentative non-bloquante d'acquérir un lock exclusif via
            # fcntl.flock. Si un autre process Komptia détient déjà le lock,
            # on log + skip start. Lock relâché à process exit (kernel).
            # Override path via KOMPTIA_SCHEDULER_LOCK_PATH pour tests/dev.
            self._leader_lock_fd = None
            try:
                import fcntl as _fcntl

                lock_path = _os.environ.get(
                    "KOMPTIA_SCHEDULER_LOCK_PATH",
                    "/tmp/komptia_scheduler.lock",
                )
                # Ouvrir en write (O_CREAT) pour créer le fichier si absent.
                # Le fd est stocké sur self pour éviter GC (qui release le lock).
                fd = _os.open(lock_path, _os.O_CREAT | _os.O_WRONLY, 0o644)
                try:
                    _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                    self._leader_lock_fd = fd
                    logger.info(
                        "Cluster-F-FOLLOWUP : leader lock acquis (%s, pid=%d)",
                        lock_path,
                        _os.getpid(),
                    )
                except (OSError, IOError) as lock_exc:
                    # EWOULDBLOCK / EAGAIN : un autre process détient le lock.
                    _os.close(fd)
                    logger.warning(
                        "⚠️ Scheduler skip start : un autre process Komptia "
                        "détient déjà le leader lock (%s). errno=%s. "
                        "Cluster-F-FOLLOWUP : single-leader enforced — pas "
                        "de double-fire cron.",
                        lock_path,
                        getattr(lock_exc, "errno", "?"),
                    )
                    self._is_passive_worker = True  # A7-F4
                    return  # Skip scheduler.start() → ce process est follower
            except ImportError:
                # fcntl non disponible (Windows). Fallback : pas de leader
                # election → on continue comme avant (warning multi-worker
                # déjà loggé). Komptia cible Linux pour la prod.
                logger.warning(
                    "Cluster-F-FOLLOWUP : fcntl indisponible (Windows ?) — "
                    "leader election désactivée, risque de double-fire en "
                    "multi-worker."
                )
            except Exception as e:  # noqa: BLE001 — defense en profondeur
                # Edge case (fs read-only, perms) : log + continue sans lock
                # plutôt que de bloquer le scheduler entier.
                logger.warning(
                    "Cluster-F-FOLLOWUP : leader lock acquisition échec "
                    "non-bloquant (%s). Continue sans leader election.",
                    e,
                )

            self.scheduler.start()
            logger.info("✅ Scheduler démarré")
            # Phase 2d : job de purge des IdempotencyLog expirees (horaire)
            # Idempotent : si relance, APScheduler replace l'ID existant.
            try:
                self.scheduler.add_job(
                    _purge_idempotency_logs_sync,
                    trigger="interval",
                    hours=1,
                    id="_komptia_purge_idempotency",
                    replace_existing=True,
                    coalesce=True,
                    misfire_grace_time=600,
                )
                logger.info("✅ Job purge idempotency planifie (horaire)")
            except Exception as e:
                logger.warning("Echec planification purge idempotency: %s", e)

            # Tasks #7/#46 (2026-05-27) — Purge quotidienne des Conversation
            # orphelines source='automation' (chaque run iris crée une conv
            # transient, croissance non bornée sinon — axe 21 Komptia).
            # Retention via AUTOMATION_CONV_RETENTION_DAYS (default 30j, ENV).
            try:
                self.scheduler.add_job(
                    _purge_orphan_iris_conversations_sync,
                    trigger="cron",
                    hour=4,
                    minute=17,  # off-peak, off-:00/:30
                    id="_komptia_purge_orphan_iris_conv",
                    replace_existing=True,
                    coalesce=True,
                    misfire_grace_time=3600,
                )
                logger.info("✅ Job purge orphan iris conversations planifie (quotidien 4h17)")
            except Exception as e:
                logger.warning("Echec planification purge orphan iris conv: %s", e)

            # T3.1 : cleanup quotidien des orphelins ``user_activity_summary``.
            # Normalement géré par CASCADE FK (`ondelete="CASCADE"`), ce job
            # est un filet de sécurité pour les DELETE SQL directs ou les
            # restaurations partielles de dump. Cron 3h du matin (faible
            # charge, pas de conflit avec les jobs interval/horaires).
            try:
                from app.services.onboarding.activity_tracker import (
                    cleanup_orphan_activity_summaries_sync,
                )

                self.scheduler.add_job(
                    cleanup_orphan_activity_summaries_sync,
                    trigger="cron",
                    hour=3,
                    minute=0,
                    id="_komptia_cleanup_activity_orphans",
                    replace_existing=True,
                    coalesce=True,
                    misfire_grace_time=3600,
                )
                logger.info("✅ Job cleanup activity orphans planifie (3h00 quotidien)")
            except Exception as e:
                logger.warning("Echec planification cleanup activity orphans: %s", e)

            # T3.2 : behavioral triggers quotidiens à 8h (heure ouvrable
            # française). Identifie les dormants/inactifs Iris/admins sans
            # user invité et consomme le throttle ``last_nudged_at``.
            # L'envoi effectif des nudges (toast, email) vient en T3.x
            # phase 2 — ce job pose la mécanique BDD.
            try:
                from app.services.onboarding.behavioral_triggers import (
                    run_daily_triggers_sync,
                )

                self.scheduler.add_job(
                    run_daily_triggers_sync,
                    trigger="cron",
                    hour=8,
                    minute=0,
                    id="_komptia_behavioral_triggers",
                    replace_existing=True,
                    coalesce=True,
                    misfire_grace_time=3600,
                )
                logger.info("✅ Job behavioral triggers planifie (8h00 quotidien)")
            except Exception as e:
                logger.warning("Echec planification behavioral triggers: %s", e)
        else:
            logger.warning("⚠️ Scheduler déjà en cours d'exécution")

    def shutdown(self, wait: bool = True):
        """
        Arrête le scheduler proprement.

        Args:
            wait: Si True, attend que tous les jobs en cours se terminent.

        Note: On met le scheduler en pause AVANT le shutdown pour empêcher
        le scan des triggers cron pendant que le ThreadPoolExecutor se ferme.
        Sans ça, APScheduler tente de soumettre des jobs en retard
        (coalesce=True) à un pool déjà fermé → RuntimeError.
        """
        if self.scheduler.running:
            try:
                self.scheduler.pause()
            except Exception as e:
                logger.debug("Pause scheduler avant shutdown a échoué (non critique): %s", e)
            self.scheduler.shutdown(wait=wait)
            logger.info("🛑 Scheduler arrêté")
        else:
            logger.warning("⚠️ Scheduler déjà arrêté")

    def add_job(
        self,
        job_id: str,
        func,
        trigger_type: str,
        trigger_config: Dict[str, Any],
        **kwargs,
    ) -> Job:
        """
        Ajoute un job au scheduler.

        Args:
            job_id: ID unique du job (ex: "automation_123")
            func: Fonction à exécuter
            trigger_type: Type de trigger: 'once', 'daily', 'weekly', 'monthly', 'cron'
            trigger_config: Configuration du trigger (dict)
            **kwargs: Arguments additionnels pour le job

        Returns:
            Job créé

        Raises:
            ValueError: Si trigger_type invalide
        """
        # A7-F4 — anti faux « scheduled » silencieux. Sur un worker passif
        # (follower du leader-lock OU KOMPTIA_SCHEDULER_ENABLED=false), le
        # scheduler n'a jamais démarré : APScheduler accepte l'``add_job`` mais
        # le job ne se déclenchera JAMAIS sur ce process. NB : un worker passif
        # exécute QUAND MÊME ``load_active_automations`` au boot (main.py, APRÈS
        # le ``return`` de start()) → des ``add_job`` boot atterrissent ici aussi ;
        # ce warning les couvre tous (boot ET runtime toggle). On rend la
        # situation visible plutôt que de laisser croire l'auto planifiée.
        # `getattr(..., False) is True` : robuste aux instances créées via
        # ``__new__`` (tests) sans __init__, et jamais déclenché par un Mock.
        if getattr(self, "_is_passive_worker", False) is True:
            logger.warning(
                "⚠️ add_job(%s) sur un worker SANS scheduler actif (follower/"
                "SCHEDULER_ENABLED=false) — le job ne se déclenchera PAS sur ce "
                "process. L'activation ne prendra effet qu'au (re)démarrage du "
                "worker leader (qui rescanne les automations actives au boot). "
                "Dette multi-worker : job store partagé requis (cf. backlog).",
                job_id,
            )
        trigger = self._create_trigger(trigger_type, trigger_config)

        # Bug cycle 16 : avant, ``replace_existing=True`` était hardcodé ici
        # ET le caller (loader.py:113) le passait aussi via kwargs → TypeError
        # "got multiple values for keyword argument 'replace_existing'" au
        # boot. On pop la valeur du kwargs avec True comme défaut sain : tout
        # caller qui ne le précise pas obtient l'ancien comportement, mais
        # ceux qui le précisent (comme loader) ne déclenchent plus le doublon.
        replace_existing = kwargs.pop("replace_existing", True)
        job = self.scheduler.add_job(
            func,
            trigger=trigger,
            id=job_id,
            replace_existing=replace_existing,
            **kwargs,
        )

        logger.info("✅ Job ajouté: %s (trigger=%s)", job_id, trigger_type)
        return job

    def remove_job(self, job_id: str) -> bool:
        """
        Supprime un job du scheduler.

        Args:
            job_id: ID du job à supprimer

        Returns:
            True si supprimé, False si non trouvé
        """
        try:
            self.scheduler.remove_job(job_id)
            logger.info("🗑️ Job supprimé: %s", job_id)
            return True
        except (ValueError, KeyError) as e:
            logger.warning("⚠️ Job non trouvé: %s - %s", job_id, e)
            return False

    def pause_job(self, job_id: str) -> bool:
        """Met un job en pause."""
        try:
            self.scheduler.pause_job(job_id)
            logger.info("⏸️ Job mis en pause: %s", job_id)
            return True
        except (ValueError, KeyError) as e:
            logger.warning("⚠️ Erreur pause job %s: %s", job_id, e)
            return False

    def resume_job(self, job_id: str) -> bool:
        """Reprend un job en pause."""
        try:
            self.scheduler.resume_job(job_id)
            logger.info("▶️ Job repris: %s", job_id)
            return True
        except (ValueError, KeyError) as e:
            logger.warning("⚠️ Erreur reprise job %s: %s", job_id, e)
            return False

    def get_job(self, job_id: str) -> Optional[Job]:
        """
        Récupère un job par son ID.

        Args:
            job_id: ID du job

        Returns:
            Job ou None si non trouvé
        """
        return self.scheduler.get_job(job_id)

    def get_jobs(self) -> List[Job]:
        """
        Récupère tous les jobs actifs.

        Returns:
            Liste des jobs
        """
        return self.scheduler.get_jobs()

    def get_job_info(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Récupère les informations détaillées d'un job.

        Args:
            job_id: ID du job

        Returns:
            Dictionnaire avec infos du job ou None
        """
        job = self.get_job(job_id)
        if not job:
            return None

        return {
            "id": job.id,
            "name": job.name,
            "next_run_time": job.next_run_time.isoformat() if job.next_run_time else None,
            "trigger": str(job.trigger),
            "func": f"{job.func.__module__}.{job.func.__name__}",
            "pending": job.pending,
        }

    @staticmethod
    def _safe_int(value, default: int, min_val: int, max_val: int) -> int:
        """Safely convert to int and clamp within bounds."""
        try:
            val = int(value)
            return min(max(val, min_val), max_val)
        except (ValueError, TypeError):
            return default

    def _create_trigger(self, trigger_type: str, config: Dict[str, Any]):
        """Wrapper d'instance autour de :func:`build_trigger` (compat).

        Conservé pour ne pas casser les call-sites existants. Toute logique
        de construction vit dans la fonction module-level afin que le
        preview dry-run et les tests unit puissent l'appeler sans
        instancier ``AutomationScheduler``.
        """
        return build_trigger(trigger_type, config)


# TZ par defaut Komptia : alignee avec ``AutomationScheduler.timezone``
# qui lit ``config.timezone`` au boot. Utilisee comme fallback explicite
# quand ``build_trigger`` est appele hors contexte scheduler (preview
# dry-run, tests unit). Sans ce fallback, ``DateTrigger`` / ``CronTrigger``
# localiseraient les datetime naifs en ``tzlocal()`` qui peut differer.
# La valeur effective est lue dynamiquement dans `_resolve_scheduler_tz`
# (pas de constante hardcodee — cf. incident TZ Europe/Paris hardcodee
# qui cassait sur les deploiements hors France, 2026-05-08).


def _resolve_scheduler_tz():
    """Retourne la TZ a passer aux triggers APScheduler.

    Priorite (1) TZ du scheduler global s'il est demarre, (2) ZoneInfo
    sur ``config.timezone`` (TZ machine resolue au boot via
    ``_get_default_timezone``) sinon. La priorite 1 garantit que si
    l'admin change la TZ scheduler un jour (variable env ou config),
    les triggers s'aligneront. La priorite 2 protege le preview/tests
    qui peuvent tourner sans scheduler initialise.
    """
    try:
        # Acces direct a la variable module sans declencher le singleton :
        # si le scheduler n'a pas encore ete instancie, on tombe dans le
        # fallback. Sinon on respecte la TZ effective du runtime.
        if _scheduler is not None:
            return _scheduler.scheduler.timezone
    except (AttributeError, RuntimeError):
        pass
    # Fallback : lecture dynamique de config.server.timezone (TZ machine).
    from app.config import config as _komptia_config

    tz_name = _komptia_config.server.timezone
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(tz_name)
    except (ImportError, KeyError):
        # Fallback ultime : pytz (presence garantie via APScheduler 3.x).
        # Si tz_name est un alias court non-IANA (ex "AST"), pytz peut
        # aussi echouer — on laisse remonter pour ne pas cacher un bug
        # de detection TZ au boot.
        import pytz

        return pytz.timezone(tz_name)


def build_trigger(trigger_type: str, config: Dict[str, Any]):
    """Construit un Trigger APScheduler à partir du type et de la config.

    Fonction pure (pas de side-effect, pas de scheduler runtime requis) —
    permet au preview dry-run du schedule de calculer les prochaines
    exécutions sans inscrire de job. Aligne sur la doctrine Komptia
    "le système prépare le travail pour le runtime, pas l'inverse".

    **TZ-correctness** : les datetimes naifs sont explicitement localises
    via ``timezone=_resolve_scheduler_tz()`` (TZ machine resolue depuis
    ``config.timezone``) pour eviter qu'APScheduler les interprete en
    TZ systeme via ``tzlocal()`` qui peut differer (cf. issue S-01
    review adversariale 2026-05-07).

    Args:
        trigger_type: 'once' / 'daily' / 'weekly' / 'monthly' / 'cron'.
        config: dict aligne sur ``Automation.schedule_config`` :
            - once    : ``{"run_date": <datetime>}``
            - daily   : ``{"hour": int, "minute": int}``
            - weekly  : ``{"day_of_week": str, "hour": int, "minute": int}``
            - monthly : ``{"day": int, "hour": int, "minute": int}``
            - cron    : ``{"cron": "<5 fields>"}``

    Raises:
        ValueError: trigger_type inconnu, ou config cron invalide.
    """
    tz = _resolve_scheduler_tz()

    if trigger_type == "once":
        # Exécution unique à une date précise. ``timezone=tz`` est crucial :
        # sans ce param, ``DateTrigger`` localise les datetime naifs via
        # ``tzlocal()`` qui peut differer de la TZ scheduler.
        #
        # **Cluster-30 2026-05-26** — Fallback `datetime.now()` était NAIVE
        # sans tz. APScheduler invoquait alors `tzlocal()` au lieu du `tz`
        # résolu via `config.timezone` → trigger « once » planifié à un
        # offset différent quand server-tz ≠ config-tz (cas typique : Docker
        # base image `TZ=UTC` mais Komptia config Europe/Paris). Le user
        # crée « run à 14h » et l'exec part à 12h ou 16h silencieusement.
        # Fix : `datetime.now(tz)` aware avec la TZ scheduler unifiée.
        run_date = config.get("run_date", clock.now().astimezone(tz))
        return DateTrigger(run_date=run_date, timezone=tz)

    elif trigger_type == "daily":
        # Tous les jours à une heure précise
        hour = AutomationScheduler._safe_int(config.get("hour", 9), 9, 0, 23)
        minute = AutomationScheduler._safe_int(config.get("minute", 0), 0, 0, 59)
        return CronTrigger(hour=hour, minute=minute, timezone=tz)

    elif trigger_type == "weekly":
        # Toutes les semaines un jour précis (mon/tue/wed/thu/fri/sat/sun ou liste "mon,wed")
        day_of_week = config.get("day_of_week", "mon")
        hour = AutomationScheduler._safe_int(config.get("hour", 9), 9, 0, 23)
        minute = AutomationScheduler._safe_int(config.get("minute", 0), 0, 0, 59)
        return CronTrigger(day_of_week=day_of_week, hour=hour, minute=minute, timezone=tz)

    elif trigger_type == "monthly":
        # Tous les mois un jour précis
        day = AutomationScheduler._safe_int(config.get("day", 1), 1, 1, 31)
        hour = AutomationScheduler._safe_int(config.get("hour", 9), 9, 0, 23)
        minute = AutomationScheduler._safe_int(config.get("minute", 0), 0, 0, 59)
        # #19 fix 2026-06-11 — un jour > 28 n'existe PAS dans tous les mois
        # (fév=28/29 ; avr/juin/sep/nov=30). ``CronTrigger(day=31)`` SAUTE
        # SILENCIEUSEMENT ces mois → l'automatisation ne tourne pas (ex: aucun
        # rapport en février pour un « mensuel le 31 » = donnée/livraison
        # manquante silencieuse). On interprète day >= 29 comme « dernier jour
        # du mois » (APScheduler ``day='last'``) : l'auto tourne CHAQUE mois sur
        # le dernier jour disponible, jamais sautée. Le preview (même
        # build_trigger, SSoT) reflète les vraies dates. day <= 28 inchangé
        # (existe dans tous les mois).
        day_field = "last" if day >= 29 else day
        return CronTrigger(day=day_field, hour=hour, minute=minute, timezone=tz)

    elif trigger_type == "cron":
        # Expression cron personnalisée
        cron_expr = config.get("cron")
        if not cron_expr:
            raise ValueError("Configuration 'cron' manquante pour trigger_type='cron'")

        # Valider l'expression cron: "minute hour day month day_of_week"
        # Exemple: "0 9 * * 1" = tous les lundis à 9h
        validate_cron_expression(cron_expr)

        parts = cron_expr.split()
        minute, hour, day, month, day_of_week = parts
        return CronTrigger(
            minute=minute,
            hour=hour,
            day=day,
            month=month,
            day_of_week=day_of_week,
            timezone=tz,
        )

    else:
        raise ValueError(f"Type de trigger non supporté: {trigger_type}")


def compute_next_runs(
    trigger,
    n: int = 5,
    *,
    scheduler_tz=None,
) -> List[datetime]:
    """Calcule les ``n`` prochaines exécutions d'un Trigger APScheduler.

    Source de vérité unique pour l'affichage "5 prochaines exécutions"
    dans la modal Planification (preview dry-run + read live). Itère
    ``trigger.get_next_fire_time(previous, now)`` jusqu'à ``n`` fois ou
    épuisement (DateTrigger passé, CronTrigger sans match futur).

    **Subtilité APScheduler** : ``CronTrigger.get_next_fire_time`` calcule
    ``start_date = min(now, previous_fire_time + 1us)``. Si on n'avance
    pas ``now`` à chaque itération, le 2e fire calculé revient au 1er
    (parce que ``min(now_initial, fire_1 + 1us) == now_initial`` quand
    ``fire_1 > now_initial``). On avance donc ``now`` à ``previous +
    1us`` pour que l'itérateur progresse réellement.

    Args:
        trigger: instance ``DateTrigger`` ou ``CronTrigger``.
        n: nombre max d'exécutions à retourner. Clampé ``max(0, int(n))``.
        scheduler_tz: TZ pour le ``now`` aware. ``None`` ⇒ TZ du scheduler
            global (resolue dynamiquement via ``config.timezone``, ie
            la TZ machine). Permet aux tests unit de passer une TZ
            explicite sans démarrer le singleton.

    Returns:
        Liste de ``datetime`` aware (TZ scheduler). Peut être vide si le
        trigger n'a plus d'exécution future (typiquement ``once`` passé).
    """
    if scheduler_tz is None:
        scheduler_tz = get_scheduler().scheduler.timezone
    now_aware = clock.now().astimezone(scheduler_tz)
    now_real = now_aware  # capturé AVANT que la boucle ne mute now_aware
    fires: List[datetime] = []
    prev: Optional[datetime] = None
    for _ in range(max(0, int(n))):
        try:
            next_fire = trigger.get_next_fire_time(prev, now_aware)
        except (ValueError, TypeError, AttributeError):
            # Trigger malformé : normalement déjà bloqué côté validation
            # cron, mais defense-in-depth pour ne pas crasher l'API preview.
            break
        if next_fire is None:
            break
        # A7-M5 — Filtre les fires RÉVOLUS. ``DateTrigger`` ('once') renvoie son
        # ``run_date`` même s'il est PASSÉ (APScheduler ignore ``now`` quand
        # ``previous is None``) → l'API « prochaines exécutions » affichait une
        # date révolue (donnée fausse). Les ``CronTrigger`` renvoient toujours un
        # fire >= now, donc ce filtre ne retire jamais un fire légitime.
        if next_fire >= now_real:
            fires.append(next_fire)
        prev = next_fire
        # Avancer "now" juste après le dernier fire pour que la prochaine
        # itération calcule à partir de ``previous + 1us`` (cf. note plus haut).
        now_aware = next_fire + timedelta(microseconds=1)
    return fires


# Singleton global
_scheduler: Optional[AutomationScheduler] = None


def _build_orphan_error_messages(session, execution) -> tuple[str, str]:
    """**P3.2 (audit 2026-05-26)** — Construit le message user + trace admin
    pour une exécution zombie identifiée par ``cleanup_orphaned_executions_job``.

    Identifie le step le plus récent encore en ``running`` (= point de blocage
    probable). Dump tous les step_executions actifs dans le trace admin.

    Args:
        session: Session SQLAlchemy sync (héritée du job APScheduler).
        execution: l'objet ``Execution`` zombie.

    Returns:
        ``(user_message, admin_traceback)`` : le user_message diffère par
        exécution (utile pour prioriser le diagnostic) ; admin_traceback dump
        les step_executions actifs avec leurs ID/types/started_at.
    """
    from app.models.step_execution import StepExecution

    try:
        active_steps_res = session.execute(
            select(StepExecution)
            .where(
                StepExecution.execution_id == execution.id,
                StepExecution.status == "running",
            )
            .order_by(StepExecution.started_at.desc())
        )
        active_steps = active_steps_res.scalars().all()
    except SQLAlchemyError:
        # Fail-safe : si la query crash, on retombe sur le message générique.
        # Le job a vocation à terminer ; on ne le bloque pas sur un orphan.
        logger.warning(
            "_build_orphan_error_messages: query StepExecution échoué (execution=%s)",
            execution.id,
            exc_info=True,
        )
        return (
            "Exécution interrompue (timeout > 2h)",
            "Marquée comme échouée par le job de nettoyage système. "
            "Détail des steps actifs indisponible (erreur BDD lors du diagnostic).",
        )

    now = clock.now()
    if not active_steps:
        # Cas pathologique : l'execution est running > 2h mais aucun step n'a
        # été initié (ou tous ont changé de statut sans clore l'execution).
        # Cas rare, message générique acceptable.
        user_msg = "Exécution interrompue (timeout > 2h, aucun step actif détecté)"
        admin_trace = (
            "Marquée comme échouée par le job de nettoyage système. "
            "Aucun StepExecution en statut 'running' au moment du nettoyage — "
            "l'exécution était probablement bloquée AVANT de démarrer un step "
            "(thread crashed mid-init, transaction zombie SQLAlchemy, etc.)."
        )
        return user_msg, admin_trace

    blocking_step = active_steps[0]  # plus récent (DESC sort)
    started = blocking_step.started_at
    duration_str = ""
    if started:
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        duration_sec = (now - started).total_seconds()
        if duration_sec < 60:
            duration_str = f"{int(duration_sec)}s"
        elif duration_sec < 3600:
            duration_str = f"{int(duration_sec / 60)}min"
        else:
            hours = int(duration_sec // 3600)
            minutes = int((duration_sec % 3600) // 60)
            duration_str = f"{hours}h{minutes:02d}min"

    step_name = (blocking_step.step_name or "step inconnu").strip()
    step_type = (blocking_step.step_type or "type inconnu").strip()

    user_msg = (
        f"Bloqué sur step « {step_name} » (type={step_type})"
        + (f" depuis {duration_str}" if duration_str else "")
        + " — timeout > 2h"
    )

    admin_lines = [
        "Marquée comme échouée par le job de nettoyage système (cleanup_orphaned_executions).",
        f"{len(active_steps)} step(s) encore en statut 'running' au moment du nettoyage :",
    ]
    for s in active_steps[:20]:  # cap défensif anti-bombe
        ts = s.started_at.isoformat() if s.started_at else "n/a"
        admin_lines.append(
            f"  - step_id={s.id} order={s.step_order} name={s.step_name!r} "
            f"type={s.step_type!r} started_at={ts}"
        )
    if len(active_steps) > 20:
        admin_lines.append(f"  ... ({len(active_steps) - 20} autres tronqués)")

    return user_msg, "\n".join(admin_lines)


def cleanup_orphaned_executions_job():
    """Job système : marque FAILED les exécutions bloquées (RUNNING ou PENDING)
    au-delà du cutoff.

    A7-M4 : on réconcilie aussi les ``pending`` (en plus des ``running``). Une
    Execution restée ``pending`` au-delà du cutoff n'a jamais démarré (crash au
    lancement, OU row 'pending' fantôme créée puis jamais pilotée — cf. C3) →
    sans ça elle reste affichée « en attente » à vie côté UI + fausse les stats.
    ``waiting`` (étape email_wait_response en attente d'une réponse externe) est
    VOLONTAIREMENT exclu : c'est un état long-lived légitime, géré par le TTL
    dédié ``expire_overdue_wait_tokens``.

    Runs synchronously in APScheduler's ThreadPoolExecutor — uses a sync
    SQLAlchemy session to avoid event-loop conflicts with the main async engine.
    """
    try:
        from datetime import timedelta
        from sqlalchemy.orm import Session

        engine = make_sync_engine(get_db_url())
        try:
            cutoff = clock.now() - timedelta(hours=_ORPHAN_EXECUTION_CUTOFF_HOURS)
            with Session(engine) as session:
                # Import here to avoid circular imports
                from app.models.execution import Execution

                result = session.execute(
                    select(Execution).where(
                        Execution.status.in_(("running", "pending")),
                        Execution.started_at < cutoff,
                    )
                )
                orphaned = result.scalars().all()

                # P3.2 (audit 2026-05-26) — Avant : toutes les exécutions
                # zombies recevaient LE MÊME message « Exécution interrompue
                # (timeout > 2h) ». Sur incident prod, 50 zombies = 50 fois
                # le même texte → impossible de prioriser le diagnostic
                # (incident DB ? service down ? bug step X spécifique ?).
                # Maintenant : on query les StepExecution still running de
                # chaque execution et on identifie le step le PLUS récent
                # encore en cours (= probable point de blocage). Le message
                # devient « Bloqué sur step "Extract Sage Clients"
                # (extract_sql) démarré à 14:32 (durée 2h14min) — timeout > 2h ».
                # error_traceback (admin-only) contient la liste complète des
                # step_executions encore actifs au moment du nettoyage.
                from sqlalchemy import update as _sa_update

                reconciled = 0
                for execution in orphaned:
                    if execution.status == "pending":
                        # A7-M4 — restée 'pending' > cutoff = jamais démarrée.
                        # Message dédié (le builder step-based ne s'applique pas :
                        # aucun step n'a été lancé).
                        user_msg = (
                            "Exécution jamais démarrée (restée en attente de "
                            f"lancement > {_ORPHAN_EXECUTION_CUTOFF_HOURS}h)"
                        )
                        admin_trace = (
                            "Marquée FAILED par le job de nettoyage : Execution "
                            "restée 'pending' au-delà du cutoff sans jamais passer "
                            "'running' (crash au lancement, ou row pending orpheline "
                            "jamais pilotée — cf. C3)."
                        )
                        # A7-M4 (adversarial #3) — transition ATOMIQUE conditionnelle :
                        # ne marque failed QUE si le row est ENCORE 'pending'. Anti-race
                        # avec un éventuel pending→running concurrent (autre worker / futur
                        # câblage) qui écraserait un run VIVANT en 'failed' (donnée fausse
                        # silencieuse). Pattern aligné sur wait_response (UPDATE ... WHERE
                        # status=...). rowcount=0 ⇒ déjà démarré ailleurs ⇒ on ne touche pas.
                        res = session.execute(
                            _sa_update(Execution)
                            .where(Execution.id == execution.id, Execution.status == "pending")
                            .values(
                                status="failed",
                                finished_at=clock.now(),
                                error_message=user_msg,
                                error_traceback=admin_trace,
                            )
                        )
                        if res.rowcount:
                            reconciled += 1
                            logger.warning(
                                "Exécution pending orpheline #%d (automation %s) "
                                "marquée FAILED — %s",
                                execution.id,
                                execution.automation_id,
                                user_msg,
                            )
                    else:
                        user_msg, admin_trace = _build_orphan_error_messages(session, execution)
                        execution.mark_failed(user_msg, admin_trace)
                        reconciled += 1
                        logger.warning(
                            "Exécution orpheline #%d (automation %s) marquée FAILED — %s",
                            execution.id,
                            execution.automation_id,
                            user_msg,
                        )
                if reconciled:
                    session.commit()
                    logger.info("%d exécution(s) orpheline(s) nettoyée(s)", reconciled)
        finally:
            engine.dispose()
    except (SQLAlchemyError, OSError, ConnectionError, ValueError):
        logger.error("Erreur nettoyage exécutions orphelines", exc_info=True)


def _resolve_report_path_within_dir(
    report_file_path: str, reports_dir_resolved: Path
) -> Optional[Path]:
    """Résout ``REPORTS_DIR/report_file_path`` et garantit le containment
    anti-traversal (CWE-22) AVANT toute suppression de fichier.

    Utilise ``Path.is_relative_to`` — PAS ``str.startswith`` : un préfixe sans
    séparateur final laisse passer un dossier *frère* dont le nom commence par
    celui du dossier autorisé (ex : base ``…/reports`` matcherait
    ``…/reports_archive/x``). Aligné sur ``report_storage.py`` (3 sites
    ``is_relative_to(REPORTS_DIR.resolve())``).

    Returns:
        Le ``Path`` résolu s'il est contenu dans ``reports_dir_resolved``,
        sinon ``None`` — le caller traite ce cas comme une tentative de
        traversal et n'``unlink`` PAS le fichier.
    """
    # Garde anti-corruption : un ``file_path`` NULL/vide (colonne pourtant
    # ``nullable=False``, mais une ligne legacy/corrompue reste possible) ferait
    # crasher ``reports_dir_resolved / None`` (TypeError) → abort du job ENTIER
    # pour tous les autres rapports. ``""`` résoudrait vers le dossier lui-même.
    # On route ces cas vers la branche "skip + delete record" (retour None).
    if not report_file_path:
        return None
    resolved = (reports_dir_resolved / report_file_path).resolve()
    return resolved if resolved.is_relative_to(reports_dir_resolved) else None


def cleanup_expired_reports_job():
    """Job système sérialisable pour nettoyage des rapports expirés.

    Runs synchronously in APScheduler's ThreadPoolExecutor — uses a sync
    SQLAlchemy session to avoid event-loop conflicts with the main async engine.
    """
    try:
        from pathlib import Path
        from sqlalchemy.orm import Session

        from app.models.report import Report
        from app.config import REPORTS_DIR

        engine = make_sync_engine(get_db_url())
        deleted_count = 0
        try:
            with Session(engine) as session:
                result = session.execute(
                    select(Report).where(Report.is_archived == False)  # noqa: E712
                )
                reports = result.scalars().all()
                file_paths_to_delete = []

                reports_dir_resolved = Path(REPORTS_DIR).resolve()
                for report in reports:
                    if report.is_expired:
                        # Path traversal check (is_relative_to, pas startswith :
                        # cf. _resolve_report_path_within_dir) AVANT tout unlink.
                        file_path = _resolve_report_path_within_dir(
                            report.file_path, reports_dir_resolved
                        )
                        if file_path is None:
                            logger.warning(
                                "Path traversal détecté pour rapport #%s: %s",
                                report.id,
                                report.file_path,
                            )
                            session.delete(report)
                            deleted_count += 1
                            continue
                        if file_path.exists():
                            file_paths_to_delete.append(file_path)
                        session.delete(report)
                        deleted_count += 1

                if deleted_count:
                    session.commit()

                # Delete files after commit
                for fp in file_paths_to_delete:
                    try:
                        fp.unlink()
                    except OSError:
                        logger.warning("Impossible de supprimer le fichier: %s", fp)

            if deleted_count:
                logger.info("%d rapport(s) expiré(s) supprimé(s)", deleted_count)
        finally:
            engine.dispose()
    except (SQLAlchemyError, OSError, ConnectionError, ValueError):
        logger.error("Erreur nettoyage rapports", exc_info=True)


# Cluster-G (G1) 2026-05-26 — TTL par défaut pour les fichiers
# ``automation_reports/`` (PDFs/XLSX générés par l'executor email-step).
# Indépendant de ``Report.expires_at`` BDD (qui couvre les rapports
# user-générés via /api/reports/generate). Configurable via env var
# pour ne pas re-déployer si l'admin veut un autre TTL.
_AUTOMATION_REPORTS_RETENTION_DAYS = int(
    os.environ.get("KOMPTIA_AUTOMATION_REPORTS_RETENTION_DAYS", "30")
)


# #8 (2026-05-28) — Cutoff configurable pour le nettoyage des exécutions
# « zombies » (status RUNNING orphelines après un crash/restart). Remplace un
# ``timedelta(hours=2)`` hardcodé. DOIT rester STRICTEMENT > la durée max d'une
# exécution légitime (``automation.max_duration_seconds``, fallback 300s) :
# sinon une exécution longue mais saine serait marquée FAILED à tort. Override
# via ``KOMPTIA_ORPHAN_EXECUTION_CUTOFF_HOURS``. Parse défensif : env invalide
# ou ≤ 0 → fallback 2h (jamais de crash au boot).
def _read_orphan_cutoff_hours() -> float:
    raw = os.environ.get("KOMPTIA_ORPHAN_EXECUTION_CUTOFF_HOURS", "2")
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return 2.0
    return val if val > 0 else 2.0


_ORPHAN_EXECUTION_CUTOFF_HOURS = _read_orphan_cutoff_hours()


def cleanup_automation_reports_files_job():
    """Cluster-G (G1) 2026-05-26 — Nettoyage filesystem des PDFs/XLSX
    générés par l'executor email-step dans ``config.data_dir / automation_reports/``.

    Pourquoi un job dédié et pas ``cleanup_expired_reports_job`` :
    ces fichiers ne sont PAS tracés via le modèle ``Report`` (qui est
    réservé aux exports user via /api/reports/generate). Ils sont
    référencés indirectement par ``Execution.output_file_path`` mais
    sans expires_at — donc sans cleanup ils s'accumulent indéfiniment
    (axe 21 du contrat : ``pas de croissance non bornée``).

    Doctrine cleanup :
    - Critère : ``mtime < now - TTL`` (défaut 30 j, configurable via
      ``KOMPTIA_AUTOMATION_REPORTS_RETENTION_DAYS``)
    - Pas de cross-check BDD : si fichier > TTL, l'Execution associée
      est aussi > TTL (l'Execution survit en BDD pour audit, mais le
      fichier est archivé sur disque). Trade-off : un "Télécharger"
      sur un Execution > TTL donnera 404 → comportement assumé.
    - Sync (ThreadPool APScheduler), pas de session DB nécessaire.
    """
    import time as _time
    from pathlib import Path as _Path
    from app.config import config as _config

    output_dir = (_config.data_dir / "automation_reports").resolve()
    if not output_dir.exists():
        return

    ttl_seconds = _AUTOMATION_REPORTS_RETENTION_DAYS * 86400
    cutoff = _time.time() - ttl_seconds
    deleted = 0
    bytes_freed = 0
    try:
        for p in output_dir.rglob("*"):
            if not p.is_file():
                continue
            try:
                stat = p.stat()
                if stat.st_mtime < cutoff:
                    size = stat.st_size
                    p.unlink()
                    deleted += 1
                    bytes_freed += size
            except OSError:
                logger.warning(
                    "automation_reports cleanup: échec sur %s",
                    p,
                    exc_info=True,
                )
        # Tente aussi de supprimer les sous-dirs vides (si l'arbo est
        # structurée par auto_id/exec_id par exemple)
        for p in sorted(output_dir.rglob("*"), key=lambda d: len(d.parts), reverse=True):
            if p.is_dir() and p != output_dir:
                try:
                    p.rmdir()
                except OSError:
                    pass
    except OSError:
        logger.error("automation_reports cleanup: erreur scan dir", exc_info=True)
        return

    if deleted:
        logger.info(
            "automation_reports cleanup: %d fichier(s) supprimé(s) (%.1f MB libérés)",
            deleted,
            bytes_freed / (1024 * 1024),
        )


def get_scheduler() -> AutomationScheduler:
    """
    Retourne l'instance singleton du scheduler.

    Returns:
        Instance du scheduler
    """
    global _scheduler
    if _scheduler is None:
        _scheduler = AutomationScheduler()
    return _scheduler


def get_next_run_for_automation(automation_id: int):
    """Lit la prochaine exécution prévue par APScheduler pour une automation.

    Source de vérité unique pour "quand est-ce qu'une automation va vraiment
    tourner ?" : APScheduler. Avant cet helper, ``app/services/dashboard/
    recent_data.py::calculate_next_execution`` recalculait le ``next_run`` à
    partir du ``schedule_config`` brut, avec ses propres règles (defaults
    ``hour=9``, TZ ``timezone.utc``, fallback cron invalide → ``None``). Ce
    calcul pouvait diverger silencieusement de ce qu'APScheduler exécutera
    réellement (TZ scheduler ≠ UTC, ``hour=25`` corrompu clampé à 9 vs
    exception, cron expression invalide rejetée à l'``add_job`` mais
    "calculée" comme ``None`` côté dashboard).

    Convention ``job_id`` : ``"automation_{automation_id}"`` (alignée avec
    ``app/services/automation/runner.py`` qui pose le même format). Si le
    job n'est pas (encore) inscrit (boot froid, scheduler en cours de
    démarrage, automation inactive non chargée), retourne ``None`` — le
    caller doit alors fallback sur son propre calcul si nécessaire.

    Args:
        automation_id: ID de l'automation en BDD.

    Returns:
        ``datetime`` aware (TZ du scheduler) ou ``None`` si pas de job ou
        pas de prochaine exécution prévue (one-shot déjà passé, etc.).
    """
    try:
        scheduler = get_scheduler()
        job = scheduler.get_job(f"automation_{automation_id}")
        if job is None:
            return None
        return job.next_run_time
    except (RuntimeError, AttributeError):
        # ``get_job`` peut lever ``RuntimeError`` si le scheduler n'a pas
        # encore démarré (race au boot). On retourne None plutôt que de
        # faire crasher le dashboard.
        return None


def start_scheduler():
    """Démarre le scheduler global et enregistre les jobs système."""
    scheduler = get_scheduler()
    scheduler.start()

    # Job système : nettoyage quotidien des rapports expirés (US-4.5)
    try:
        scheduler.scheduler.add_job(
            cleanup_expired_reports_job,
            CronTrigger(hour=3, minute=0),  # Tous les jours à 3h du matin
            id="system_cleanup_reports",
            name="Nettoyage rapports expirés",
            replace_existing=True,
        )
        logger.info("✅ Job nettoyage rapports enregistré (quotidien 03:00)")
    except (SQLAlchemyError, OSError, ValueError) as e:
        logger.warning("⚠️ Impossible d'enregistrer le job de nettoyage : %s", e)

    # Cluster-G (G1) 2026-05-26 — Job système : nettoyage des fichiers
    # filesystem ``automation_reports/`` (PDFs/XLSX email-step) > TTL.
    # Quotidien à 03:15 pour ne pas chevaucher avec system_cleanup_reports.
    try:
        scheduler.scheduler.add_job(
            cleanup_automation_reports_files_job,
            CronTrigger(hour=3, minute=15),
            id="system_cleanup_automation_reports_files",
            name="Nettoyage fichiers automation_reports/ (filesystem)",
            replace_existing=True,
        )
        logger.info(
            "✅ Job nettoyage automation_reports/ enregistré (quotidien 03:15, TTL %dj)",
            _AUTOMATION_REPORTS_RETENTION_DAYS,
        )
    except (SQLAlchemyError, OSError, ValueError) as e:
        logger.warning("⚠️ Impossible d'enregistrer le job cleanup automation_reports/ : %s", e)

    # Job système : nettoyage des exécutions orphelines (RUNNING > 2h)
    try:
        scheduler.scheduler.add_job(
            cleanup_orphaned_executions_job,
            CronTrigger(minute=0),  # Toutes les heures
            id="system_cleanup_orphaned_executions",
            name="Nettoyage exécutions orphelines",
            replace_existing=True,
        )
        logger.info("✅ Job nettoyage exécutions orphelines enregistré (horaire)")
    except (SQLAlchemyError, OSError, ValueError) as e:
        logger.warning("⚠️ Impossible d'enregistrer le job de nettoyage exécutions : %s", e)

    # #8 (2026-05-28) — Nettoyage immédiat AU BOOT : sans ça, une exécution
    # restée RUNNING après un crash/restart attendait le prochain tick horaire
    # (jusqu'à ~1h) avant d'être marquée FAILED. On lance le job une fois au
    # démarrage. Cutoff-based : ne touche QUE les RUNNING plus vieilles que le
    # cutoff → jamais une exécution fraîche (safe même si un autre worker
    # tourne). Best-effort : ne bloque pas le boot si la BDD est indisponible.
    try:
        cleanup_orphaned_executions_job()
    except Exception:  # noqa: BLE001
        logger.warning("⚠️ Nettoyage orphelines au boot échoué (non bloquant)", exc_info=True)

    # Job système : nettoyage quotidien des termes d'anonymisation obsolètes
    # (termes en BDD qui ne correspondent plus à aucune valeur dans les
    # classeurs des utilisateurs). Après le cleanup reports (03:00) pour
    # éviter la concurrence SQLite sur la même fenêtre.
    try:
        from app.services.anonymization.cleanup_job import (
            cleanup_unused_anonymization_terms_job,
        )

        scheduler.scheduler.add_job(
            cleanup_unused_anonymization_terms_job,
            CronTrigger(hour=3, minute=30),  # Quotidien 03:30
            id="system_cleanup_anonymization_terms",
            name="Nettoyage termes d'anonymisation obsolètes",
            replace_existing=True,
        )
        logger.info("✅ Job nettoyage termes anonymisation enregistré (quotidien 03:30)")
    except (SQLAlchemyError, OSError, ValueError, ImportError) as e:
        logger.warning("⚠️ Impossible d'enregistrer le job de nettoyage anonymisation : %s", e)

    # Job système : TTL des tables-logs (audit_logs, search_history,
    # ai_performance_logs, email_logs). Quotidien 04:00 (après les autres
    # cleanups, fenêtre de faible activité utilisateur). Les TTL sont
    # configurables via les variables d'environnement
    # ``AUDIT_LOGS_RETENTION_DAYS`` etc. (cf. ``cleanup/db_retention.py``).
    try:
        from app.services.cleanup.db_retention import cleanup_db_retention_job

        scheduler.scheduler.add_job(
            cleanup_db_retention_job,
            CronTrigger(hour=4, minute=0),
            id="system_cleanup_db_retention",
            name="TTL des tables-logs (audit/search/perf/email)",
            replace_existing=True,
        )
        logger.info("✅ Job TTL tables-logs enregistré (quotidien 04:00)")
    except (SQLAlchemyError, OSError, ValueError, ImportError) as e:
        logger.warning("⚠️ Impossible d'enregistrer le job cleanup_db_retention : %s", e)

    # Job système : sauvegarde auto de la BDD locale (OPT-IN — cf. config.backup,
    # défaut désactivé). Snapshot cohérent VACUUM INTO + rotation. Quotidien à
    # config.backup.hour (défaut 03:00, AVANT le cleanup TTL de 04:00 pour
    # sauvegarder l'état complet). Désactivé → aucun job enregistré (0 régression).
    try:
        from app.config import config as _backup_cfg

        if _backup_cfg.backup.enabled:
            from app.services.backup import run_backup_job

            scheduler.scheduler.add_job(
                run_backup_job,
                CronTrigger(hour=_backup_cfg.backup.hour, minute=0),
                id="system_db_backup",
                name="Sauvegarde auto BDD locale + rotation",
                replace_existing=True,
            )
            logger.info(
                "✅ Job backup BDD auto enregistré (quotidien %02d:00, rétention %d copies / %dj)",
                _backup_cfg.backup.hour,
                _backup_cfg.backup.retention_count,
                _backup_cfg.backup.retention_days,
            )
    except (SQLAlchemyError, OSError, ValueError, ImportError) as e:
        logger.warning("⚠️ Impossible d'enregistrer le job backup BDD : %s", e)

    # Job système : surveillance périodique de l'espace disque (runtime). Le
    # boot-check (startup_check) ne voit la saturation qu'au redémarrage ; ce job
    # la capte pendant l'exploitation (cf. zone 10 review). Intervalle configurable
    # (config.disk.check_interval_hours, défaut 6h) ; <= 0 → désactivé.
    try:
        from app.config import config as _disk_cfg

        _disk_interval = _disk_cfg.disk.check_interval_hours
        if _disk_interval > 0:
            from app.services.diagnostics import run_disk_space_check_job

            scheduler.scheduler.add_job(
                run_disk_space_check_job,
                IntervalTrigger(hours=_disk_interval),
                id="system_disk_space_check",
                name="Surveillance espace disque",
                replace_existing=True,
            )
            logger.info("✅ Job surveillance disque enregistré (toutes les %dh)", _disk_interval)
    except (SQLAlchemyError, OSError, ValueError, ImportError) as e:
        logger.warning("⚠️ Impossible d'enregistrer le job surveillance disque : %s", e)

    # Job système : nettoyage des fichiers tmp de preview d'étape.
    # TTL court (60 min cf. ``STEP_PREVIEW_TMP_TTL_SECONDS``) → on tourne
    # toutes les 30 min pour garantir que les fichiers expirés sont
    # purgés dans la fenêtre. Sans ce job, la zone tmp grandirait sans
    # bornes (une preview report = 1 PDF, 50 previews/user/jour =
    # ~25 Mo/user/jour). Cf. axe 21 du contrat Komptia.
    try:
        from app.services.automation.preview_service import (
            cleanup_expired_preview_files,
        )

        scheduler.scheduler.add_job(
            cleanup_expired_preview_files,
            CronTrigger(minute="*/30"),
            id="system_cleanup_step_preview_tmp",
            name="Nettoyage fichiers tmp de preview d'étape",
            replace_existing=True,
        )
        logger.info("✅ Job nettoyage tmp preview étape enregistré (toutes 30 min)")
    except (SQLAlchemyError, OSError, ValueError, ImportError) as e:
        logger.warning("⚠️ Impossible d'enregistrer le job cleanup tmp preview : %s", e)

    # Job systeme : cleanup des WaitToken expires + rappels owner pour
    # les WaitToken qui approchent de l'expiration. Toutes les 15 min.
    # - expires : marque WaitToken='expired' + Execution='failed' + notif owner
    # - reminders : envoie un rappel mail au proprio si reminder_hours_before
    #   est configure et qu'il reste moins de X heures.
    try:
        from app.services.automation.wait_resume import cleanup_wait_tokens_job

        scheduler.scheduler.add_job(
            cleanup_wait_tokens_job,
            CronTrigger(minute="*/15"),
            id="system_cleanup_wait_tokens",
            name="Cleanup wait_tokens expires + rappels owner",
            replace_existing=True,
        )
        logger.info("✅ Job cleanup wait_tokens enregistré (toutes 15 min)")
    except (SQLAlchemyError, OSError, ValueError, ImportError) as e:
        logger.warning("⚠️ Impossible d'enregistrer le job cleanup wait_tokens : %s", e)

    # Job système : cleanup des SqlWriteAuditLog en attente DBA expirés
    # (statut awaiting_dba dont expires_at est dépassé) + détection des
    # zombies executing (crash app pendant l'exécution Sage). Toutes les
    # 15 min — granularité suffisante vs un TTL admin de 24h par défaut.
    #
    # **2026-06-11** (corrige le fix incomplet du 2026-05-19) : le callable
    # planifié doit être (1) MODULE-LEVEL — APScheduler refuse de sérialiser
    # une closure pour le jobstore persistant — ET (2) SYNC — le
    # ``BackgroundScheduler`` (threads) appelle ``job.func()`` sans await,
    # donc une ``async def`` passée directement crée une coroutine jamais
    # awaitée : le job logge "executed successfully" mais ne tourne JAMAIS
    # (RuntimeWarning "coroutine ... was never awaited" constaté en prod).
    # Le 2026-05-19 avait corrigé (1) mais réintroduit (2) en croyant imiter
    # ``cleanup_wait_tokens_job`` — qui est en réalité un wrapper SYNC.
    # Garde-fou : tests/unit/test_scheduler_no_raw_async_jobs.py.
    try:
        from app.services.ai.iris_write_session import cleanup_expired_and_zombie_job

        scheduler.scheduler.add_job(
            cleanup_expired_and_zombie_job,
            CronTrigger(minute="*/15"),
            id="system_cleanup_iris_sql_write",
            name="Cleanup iris_sql_write_audit (expired + zombies)",
            replace_existing=True,
        )
        logger.info("✅ Job cleanup iris_sql_write enregistré (toutes 15 min)")
    except (SQLAlchemyError, OSError, ValueError, ImportError) as e:
        logger.warning("⚠️ Impossible d'enregistrer le job cleanup iris_sql_write : %s", e)

    # Job système : nettoyage des rotations anciennes de ``llm_log.md``.
    # ``llm_logger.py`` rotate automatiquement le fichier actif quand il
    # dépasse ``LLM_LOG_MAX_SIZE_BYTES`` (défaut 50 MB) — il faut juste
    # purger les archives plus âgées que ``LLM_LOG_RETENTION_DAYS`` (défaut
    # 14 jours). Quotidien 03:45 (après les autres jobs cleanup).
    try:
        from app.services.ai.llm_logger import cleanup_old_rotated_logs

        scheduler.scheduler.add_job(
            cleanup_old_rotated_logs,
            CronTrigger(hour=3, minute=45),
            id="system_cleanup_llm_log_rotations",
            name="Nettoyage rotations llm_log.md anciennes",
            replace_existing=True,
        )
        logger.info("✅ Job nettoyage rotations llm_log enregistré (quotidien 03:45)")
    except (SQLAlchemyError, OSError, ValueError, ImportError) as e:
        logger.warning("⚠️ Impossible d'enregistrer le job cleanup llm_log rotations : %s", e)

    # Phase 2 — Recompute quotidien de ``UserStorage.db_bytes_used``
    # pour tous les users. Quotidien 02:00 (avant le cleanup reports
    # à 03:00 et le cleanup anon à 03:30 pour avoir des chiffres
    # frais avant les éventuelles purges qui réduisent l'occupation).
    #
    # **NB — fonction module-level ET sync requise** : APScheduler doit
    # pouvoir sérialiser une référence textuelle ``module:func`` pour le
    # jobstore persistant (une closure imbriquée casse), et le
    # ``BackgroundScheduler`` n'await jamais — une ``async def`` directe ne
    # tournerait JAMAIS (cf. commentaire du job iris_sql_write ci-dessus +
    # tests/unit/test_scheduler_no_raw_async_jobs.py). Le wrapper sync est
    # donc dans ``db_usage.py``.
    try:
        from app.services.db_usage import db_usage_recompute_job_sync

        scheduler.scheduler.add_job(
            db_usage_recompute_job_sync,
            CronTrigger(hour=2, minute=0),  # Quotidien 02:00
            id="system_db_usage_recompute",
            name="Recalcul quota BDD par user (Phase 2 storage accounting)",
            replace_existing=True,
        )
        logger.info("✅ Job recompute db_usage enregistré (quotidien 02:00)")
    except (SQLAlchemyError, OSError, ValueError, ImportError) as e:
        logger.warning("⚠️ Impossible d'enregistrer le job recompute db_usage : %s", e)

    # Job système : TTL des PipelineRun (NL→SQL pipeline runs lancés depuis
    # l'agent SQL d'Iris). Quotidien 04:30 — après les autres cleanups.
    # Configurable via env ``PIPELINE_RUN_RETENTION_DAYS`` (défaut 30j).
    try:
        from app.services.cleanup.pipeline_cleanup import cleanup_pipeline_runs_job

        scheduler.scheduler.add_job(
            cleanup_pipeline_runs_job,
            CronTrigger(hour=4, minute=30),
            id="system_cleanup_pipeline_runs",
            name="TTL des runs pipeline NL→SQL",
            replace_existing=True,
        )
        logger.info("✅ Job TTL pipeline_runs enregistré (quotidien 04:30)")
    except (SQLAlchemyError, OSError, ValueError, ImportError) as e:
        logger.warning("⚠️ Impossible d'enregistrer le job cleanup_pipeline_runs : %s", e)

    # Job système : cleanup mensuel des jobs APScheduler obsolètes.
    # Deux critères : (a) misfired > 365j (next_run_time très ancien ou
    # trigger épuisé sur job pausé), (b) orphans (automation_X /
    # dashboard_schedule_X dont l'entité BDD a été supprimée).
    # Cron mensuel (1er du mois 04:45) — fréquence basse car volume faible
    # et fenêtre d'erreur tolérante (un job orphelin qui survit 1 mois ne
    # cause aucun préjudice tant que sa fonction n'est plus joignable).
    # Configurable via env ``APSCHEDULER_JOBS_MISFIRE_MAX_AGE_DAYS``.
    try:
        from app.services.automation.cleanup_job import (
            cleanup_apscheduler_jobs_job,
        )

        scheduler.scheduler.add_job(
            cleanup_apscheduler_jobs_job,
            CronTrigger(day=1, hour=4, minute=45),
            id="system_cleanup_apscheduler_jobs",
            name="Cleanup jobs APScheduler obsolètes (mensuel)",
            replace_existing=True,
        )
        logger.info("✅ Job cleanup_apscheduler_jobs enregistré (mensuel 1er à 04:45)")
    except (SQLAlchemyError, OSError, ValueError, ImportError) as e:
        logger.warning("⚠️ Impossible d'enregistrer le job cleanup_apscheduler_jobs : %s", e)



def shutdown_scheduler(wait: bool = True):
    """Arrête le scheduler global proprement."""
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=wait)
        _scheduler = None
