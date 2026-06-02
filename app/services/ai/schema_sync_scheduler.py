"""
Scheduler pour la synchronisation automatique du schéma.

Lance la sync à intervalles réguliers selon la configuration.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy.exc import SQLAlchemyError

from app.core import clock
from app.services.ai.config_service import get_ai_config_service, AIConfigKey
from app.services.ai.schema_sync import get_sync_service

logger = logging.getLogger(__name__)


class SchemaSyncScheduler:
    """
    Planificateur de synchronisation automatique du schéma.

    Vérifie périodiquement si une sync est nécessaire et la lance.
    """

    def __init__(self):
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._check_interval = 3600  # Vérifier toutes les heures

    async def _should_sync(self) -> bool:
        """Vérifie si une sync est nécessaire.

        Logique :
        - SCHEMA_SYNC_ENABLED off → False
        - Pas de last_sync → True (premier run après boot ou reset)
        - Intervalle non écoulé → False
        - Intervalle écoulé ET start_time vide → True (comportement legacy)
        - Intervalle écoulé ET start_time défini (HH:MM) → True UNIQUEMENT
          si l'heure locale serveur courante est dans la fenêtre [HH:MM, HH:MM+tick).
          Permet à l'admin de fixer "tous les jours à 3h du matin" sans bruit
          en heures de bureau.
        """
        config = get_ai_config_service()

        enabled = await config.get(AIConfigKey.SCHEMA_SYNC_ENABLED, True)
        if not enabled:
            return False

        interval_hours = await config.get(AIConfigKey.SCHEMA_SYNC_INTERVAL_HOURS, 24)
        last_sync_str = await config.get(AIConfigKey.SCHEMA_SYNC_LAST_RUN)
        start_time_str = await config.get(AIConfigKey.SCHEMA_SYNC_START_TIME, "") or ""

        if not last_sync_str:
            return True

        try:
            last_sync = datetime.fromisoformat(last_sync_str)
            if last_sync.tzinfo is None:
                last_sync = last_sync.replace(tzinfo=timezone.utc)
            next_sync = last_sync + timedelta(hours=interval_hours)
            interval_elapsed = clock.now() >= next_sync
        except (ValueError, TypeError):
            return True

        if not interval_elapsed:
            return False

        # Pas d'heure préférée → comportement actuel (sync au prochain tick).
        start_time_str = start_time_str.strip()
        if not start_time_str:
            return True

        # Parse HH:MM (locale serveur). Format invalide → fallback comportement
        # legacy (sync immédiat) plutôt que de bloquer indéfiniment.
        try:
            hh_str, mm_str = start_time_str.split(":", 1)
            target_h = int(hh_str)
            target_m = int(mm_str)
            if not (0 <= target_h <= 23 and 0 <= target_m <= 59):
                raise ValueError
        except ValueError:
            logger.warning(
                "schema_sync_start_time invalide (%r), fallback comportement legacy",
                start_time_str,
            )
            return True

        # Heure locale de la machine hôte via la source unique : `clock.now_local()`
        # lit `config.server.timezone` (TZ machine résolue au boot) et retombe sur
        # UTC si la résolution échoue. Remplace l'ancien
        # `datetime.now(ZoneInfo(config.server.timezone))` + fallback `datetime.now()`
        # naïf (qui suivait la TZ du process Python, pas celle voulue par l'admin).
        now_local = clock.now_local()
        target_minutes = target_h * 60 + target_m
        now_minutes = now_local.hour * 60 + now_local.minute
        # Fenêtre de tick (par défaut le scheduler tick 1×/h dans run() — voir
        # ``check_interval_seconds``). On accepte ±30 min autour de l'heure
        # cible pour rattraper si le tick a glissé. Si interval_hours < 1h,
        # cette fenêtre s'élargirait artificiellement, donc on cap à 30 min.
        diff = abs(now_minutes - target_minutes)
        diff_circular = min(diff, 1440 - diff)  # diff sur cercle 24h
        return diff_circular <= 30

    async def _run_sync(self):
        """Exécute une synchronisation depuis la base Sage."""
        try:
            # En mode SQLite local, pas de SQL Server à synchroniser
            from app.services.database.sage_connector import (
                get_current_sage_mode,
                is_unconfigured,
            )
            from app.core.exceptions import SageConnectionError

            if get_current_sage_mode() == "sqlite":
                logger.debug("Sync schéma auto ignorée : mode SQLite local (pas de SQL Server)")
                return

            # Skip si /admin/database est vide (la SEULE source de vrit
            # pour la connexion BDD source). Inutile de tenter -- le
            # connecteur lverait [CONFIG_MANQUANTE] et le scheduler
            # crasherait en boucle. Niveau debug pour ne pas spammer
            # les logs tant que l'admin n'a pas encore configur.
            if is_unconfigured():
                logger.debug(
                    "Sync schéma auto ignorée : aucune connexion BDD activée "
                    "(configurez /admin/database pour activer la sync)"
                )
                return

            logger.info("🔄 Démarrage sync schéma automatique depuis Sage...")

            sync_service = get_sync_service()
            result = await sync_service.sync_from_sage() or {}

            if result.get("success"):
                # Mettre à jour le timestamp
                config = get_ai_config_service()
                await config.set(AIConfigKey.SCHEMA_SYNC_LAST_RUN, clock.now().isoformat())

                logger.info(
                    "Sync schéma auto terminée: %d tables",
                    result.get("tables_count", 0),
                )
                # #76 — surfacer l'incomplétude : même avec success:True, des
                # sections (functions/synonyms/fk/inferred/cardinality/
                # view_mining) ont pu échouer → connaissance Iris partielle.
                # L'auto-sync (cron) est le chemin DOMINANT ; sans ce WARNING,
                # une régression récurrente (permissions/timeout) resterait
                # silencieuse (données fausses : jointures manquantes).
                if result.get("complete") is False:
                    _sections = result.get("incomplete_sections") or []
                    logger.warning(
                        "Sync schéma auto INCOMPLÈTE : %d section(s) échouée(s) "
                        "(%s) — connaissance Iris partielle, investiguer les "
                        "permissions/timeouts Sage.",
                        len(_sections),
                        ", ".join(s.get("section", "?") for s in _sections),
                    )
            else:
                logger.warning("Sync schéma auto échouée: %s", result.get("error"))

        except SageConnectionError as exc:
            # Race possible : la config a t dsactive entre le check
            # ``is_unconfigured()`` ci-dessus et l'``execute()``. On log
            # warning et on continue -- le prochain tick re-checkera.
            logger.warning("Sync schéma auto interrompue : %s", exc)
        except (SQLAlchemyError, ConnectionError, asyncio.TimeoutError):
            logger.error("Erreur sync schéma auto", exc_info=True)

    async def _loop(self):
        """Boucle principale du scheduler."""
        while self._running:
            try:
                if await self._should_sync():
                    await self._run_sync()

                # Attendre avant la prochaine vérification
                await asyncio.sleep(self._check_interval)

            except asyncio.CancelledError:
                break
            except (SQLAlchemyError, ConnectionError, asyncio.TimeoutError):
                logger.error("Erreur dans le scheduler sync", exc_info=True)
                await asyncio.sleep(60)  # Attendre 1 min avant de réessayer

    async def start(self):
        """Démarre le scheduler."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("📅 Scheduler sync schéma démarré")

    async def stop(self):
        """Arrête le scheduler."""
        if not self._running:
            return

        self._running = False

        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        logger.info("📅 Scheduler sync schéma arrêté")

    async def trigger_now(self):
        """Force une synchronisation immédiate."""
        await self._run_sync()


# Singleton
_scheduler: Optional[SchemaSyncScheduler] = None


def get_schema_sync_scheduler() -> SchemaSyncScheduler:
    """Retourne l'instance singleton du scheduler."""
    global _scheduler
    if _scheduler is None:
        _scheduler = SchemaSyncScheduler()
    return _scheduler


async def start_schema_sync_scheduler():
    """Démarre le scheduler (à appeler au démarrage de l'app)."""
    scheduler = get_schema_sync_scheduler()
    await scheduler.start()


async def stop_schema_sync_scheduler():
    """Arrête le scheduler (à appeler à l'arrêt de l'app)."""
    scheduler = get_schema_sync_scheduler()
    await scheduler.stop()
