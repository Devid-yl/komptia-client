"""
Scheduler pour la synchronisation automatique du schéma.

Lance la sync à intervalles réguliers selon la configuration.
"""

import asyncio
import logging
import math
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.exc import SQLAlchemyError

from app.core import clock
from app.services.ai.config_service import get_ai_config_service, AIConfigKey
from app.services.ai.schema_sync import get_sync_service

logger = logging.getLogger(__name__)

#: Intervalle minimum par défaut (h) si la config est absente/corrompue.
_DEFAULT_INTERVAL_HOURS = 24.0


def _parse_hhmm(value: str) -> Optional[tuple[int, int]]:
    """Parse ``"HH:MM"`` → ``(h, m)`` validés, sinon ``None``."""
    try:
        hh_str, mm_str = value.split(":", 1)
        h, m = int(hh_str), int(mm_str)
    except (ValueError, AttributeError):
        return None
    if 0 <= h <= 23 and 0 <= m <= 59:
        return h, m
    return None


def _compute_due(
    *,
    enabled: bool,
    now_utc: datetime,
    now_local: datetime,
    last_sync_utc: Optional[datetime],
    interval_hours: float,
    start_time_str: str,
) -> bool:
    """Décide si une sync est due. **Fonction PURE** (aucune I/O) → testable seule.

    Deux modes (calqués sur ``systemd`` ``OnCalendar``/``OnUnitActiveSec``) :

    * **Calendrier** (``start_time`` = ``HH:MM`` valide) : due dès que la dernière
      sync est ANTÉRIEURE au dernier créneau mural dû. Le créneau est ancré sur
      l'horloge murale **locale serveur** → **pas de dérive** ; si l'app était
      down à l'heure prévue, la sync se **rattrape** au prochain réveil ; jamais
      2× pour un même créneau (une fois ``last_sync >= slot``, plus due jusqu'au
      créneau suivant). ``interval_hours`` recule le seuil de
      ``max(0, interval-24)`` h → 24h ⇒ quotidien, 48h ⇒ tous les 2 jours, etc.
    * **Intervalle** (``start_time`` vide/invalide) : legacy — due dès que
      ``now >= last_sync + interval_hours`` (pas d'heure fixe).

    ``last_sync_utc=None`` ⇒ premier run (True). ``enabled=False`` ⇒ False.

    Les comparaisons mêlent aware-UTC (``last_sync_utc``, ``now_utc``) et
    aware-local (créneau dérivé de ``now_local``) : Python compare des **instants
    absolus**, le résultat est donc correct quel que soit le fuseau.

    DST (best-effort) : le créneau est construit via ``now_local.replace(hour, …)``.
    Sur un fuseau à heure d'été, si le créneau tombe dans l'heure « sautée » du
    passage été (inexistante) ou « doublée » du retour, l'instant absolu peut être
    décalé d'~1h ce jour-là (pas de double-run ni de skip de jour — juste la
    fenêtre de décision décalée). Sans objet pour ``America/Guadeloupe`` (UTC−4
    constant, pas de DST). Acceptable pour une sync schéma quotidienne.
    """
    if not enabled:
        return False
    if last_sync_utc is None:
        return True

    # Garde anti-config-corrompue : NaN/inf (ou ≤0) → défaut. Sans `isfinite`,
    # un `inf` passerait (`inf > 0` True) puis ferait lever `OverflowError` au
    # `last_sync_utc + timedelta(hours=inf)` ci-dessous.
    interval = (
        interval_hours
        if (interval_hours and math.isfinite(interval_hours) and interval_hours > 0)
        else _DEFAULT_INTERVAL_HOURS
    )

    parsed = _parse_hhmm((start_time_str or "").strip())
    if parsed is None:
        # Mode intervalle (legacy) : espacement pur depuis la dernière sync.
        return now_utc >= last_sync_utc + timedelta(hours=interval)

    # Mode calendrier : dernier créneau mural <= maintenant (heure locale).
    target_h, target_m = parsed
    slot_local = now_local.replace(hour=target_h, minute=target_m, second=0, microsecond=0)
    if slot_local > now_local:
        slot_local -= timedelta(days=1)
    # Seuil multi-jours : 24h ⇒ slot ; 48h ⇒ slot-24h ; etc.
    threshold = slot_local - timedelta(hours=max(0.0, interval - 24.0))
    return last_sync_utc < threshold


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
        """Vérifie si une sync est nécessaire (décision pure → :func:`_compute_due`).

        Récupère la config et la dernière sync, puis délègue la DÉCISION à la
        fonction pure :func:`_compute_due` (deux modes : calendrier avec
        rattrapage / intervalle legacy — cf. sa docstring).

        Source de « dernière sync » = :meth:`_resolve_last_sync` (table
        ``schema_syncs`` + repli clé config) : ainsi les syncs MANUELLES (qui
        n'écrivent pas toujours la clé config) repoussent bien le planning, et un
        run manqué (app down à l'heure prévue) est RATTRAPÉ au réveil au lieu
        d'être sauté jusqu'au lendemain.
        """
        config = get_ai_config_service()

        enabled = await config.get(AIConfigKey.SCHEMA_SYNC_ENABLED, True)
        if not enabled:
            # Court-circuit : inutile de lire la dernière sync (DB) si désactivé.
            return False

        interval_hours = await config.get(AIConfigKey.SCHEMA_SYNC_INTERVAL_HOURS, 24)
        start_time_str = await config.get(AIConfigKey.SCHEMA_SYNC_START_TIME, "") or ""

        # Observabilité : start_time renseigné mais invalide → on bascule en mode
        # intervalle (cf. _compute_due) ; on le signale pour que l'admin corrige.
        if start_time_str.strip() and _parse_hhmm(start_time_str.strip()) is None:
            logger.warning("schema_sync_start_time invalide (%r) → mode intervalle", start_time_str)

        try:
            interval = float(interval_hours)
        except (TypeError, ValueError):
            interval = _DEFAULT_INTERVAL_HOURS

        last_sync_utc = await self._resolve_last_sync(config)

        return _compute_due(
            enabled=bool(enabled),
            now_utc=clock.now(),
            now_local=clock.now_local(),
            last_sync_utc=last_sync_utc,
            interval_hours=interval,
            start_time_str=start_time_str,
        )

    async def _resolve_last_sync(self, config) -> Optional[datetime]:
        """Dernière sync réussie = ``max(table schema_syncs, clé config)``, aware UTC.

        La table ``schema_syncs`` est la SOURCE DE VÉRITÉ : toute sync y insère
        une ligne, y compris les syncs **manuelles** (qui ne touchent pas
        toujours la clé ``SCHEMA_SYNC_LAST_RUN``). Le repli sur la clé couvre le
        cas où la table serait vide mais la clé présente (résilience). On prend le
        ``max`` pour ne JAMAIS sous-estimer la dernière sync (sous-estimer ⇒
        sur-déclenchement). ``None`` ⇒ aucune source exploitable ⇒ premier run.
        """
        candidates: list[datetime] = []

        # 1. Table schema_syncs — inclut les syncs manuelles.
        try:
            from app.services.ai.schema_freshness import get_freshness_checker

            table_dt = clock.ensure_utc(await get_freshness_checker().get_last_sync_time())
            if table_dt is not None:
                candidates.append(table_dt)
        except Exception:
            logger.warning(
                "Scheduler : échec lecture dernière sync (table schema_syncs)",
                exc_info=True,
            )

        # 2. Clé config (repli / compat ascendante).
        cfg_str = None
        try:
            cfg_str = await config.get(AIConfigKey.SCHEMA_SYNC_LAST_RUN)
        except Exception:
            logger.warning("Scheduler : échec lecture SCHEMA_SYNC_LAST_RUN", exc_info=True)
        if cfg_str:
            try:
                cfg_raw = str(cfg_str)
                # Tolère un suffixe « Z » (cohérent avec clock.to_local) même si
                # notre écriture (clock.now().isoformat()) produit « +00:00 ».
                cfg_iso = cfg_raw[:-1] + "+00:00" if cfg_raw.endswith("Z") else cfg_raw
                cfg_dt = clock.ensure_utc(datetime.fromisoformat(cfg_iso))
                if cfg_dt is not None:
                    candidates.append(cfg_dt)
            except (ValueError, TypeError):
                logger.warning("Scheduler : SCHEMA_SYNC_LAST_RUN illisible (%r)", cfg_str)

        return max(candidates) if candidates else None

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
