"""
Diagnostics & Health Check — Auto-détection des problèmes d'infrastructure.

Ce module existe pour que l'app détecte et signale ses propres problèmes
au lieu de les laisser s'accumuler silencieusement dans les logs.

Quatre mécanismes :

1. :func:`startup_check` — Vérifie les intégrations critiques au démarrage.
2. :class:`ErrorWatchdog` — Détecte les erreurs répétées en runtime et
   prend des mesures (déduplication des spams de logs).
3. :func:`detailed_health` — État complet de l'app (pour ``/health/detailed``).
4. :func:`scheduler_health` — État du scheduler APScheduler + détection
   d'exécutions orphelines (pour ``/health/scheduler``).

Toutes les fonctions sont **fail-safe** : une dépendance qui crashe ne
remonte jamais d'exception au handler appelant — elle dégrade le statut
sémantique et logge le détail côté serveur. Cf. règle CLAUDE.md
« fail-closed » : on refuse plutôt que d'autoriser silencieusement.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import timedelta
from typing import Any, Dict, Final, List, Optional

from app.core import clock

logger = logging.getLogger(__name__)


#: Seuil **d'affichage** au-delà duquel une exécution `running` est considérée
#: orpheline pour le dashboard santé. Volontairement plus tight que le seuil
#: du job de nettoyage automatique (2h) — la philosophie est d'**alerter
#: avant** que le nettoyage agisse, pour qu'un humain investigue une
#: exécution stuck en cours plutôt que de la voir disparaître silencieusement.
ORPHANED_DISPLAY_THRESHOLD_MIN: Final[int] = 30

#: Statut SQL d'une exécution en cours. La SOR (source of record) est
#: :class:`app.models.execution.Execution.status`. Centraliser ici évite la
#: dérive de cas (running vs RUNNING) à grep-time.
EXECUTION_STATUS_RUNNING: Final[str] = "running"


# ============================================================
# 1. Startup validation — Exécuté une fois au démarrage
# ============================================================


async def startup_check() -> Dict[str, Any]:
    """
    Vérifie les intégrations critiques au démarrage.

    Détecte les problèmes AVANT qu'ils ne spamment les logs en production.
    Chaque check est indépendant : un échec ne bloque pas les autres.

    Returns:
        Dict avec status ("ok"|"degraded"|"critical"), checks détaillés, et warnings
    """
    results: Dict[str, Any] = {
        "status": "ok",
        "checks": {},
        "warnings": [],
        "errors": [],
    }

    checks = [
        ("sqlite", _check_sqlite),
        ("admin_seeded", _check_admin_seeded),
        ("training_store_api", _check_training_store_api),
        ("sage_config", _check_sage_config),
        ("llm_config", _check_llm_config),
        ("environment_coherence", _check_environment_coherence),
        ("timezone", _check_timezone_configured),
        ("ws_origins", _check_ws_origins),
        ("debug_off", _check_debug_off),
        ("disk_space", _check_disk_space),
        ("scheduler_enabled", _check_scheduler_enabled),
        # Réutilise la fonction existante du /health (SSoT, pas de duplication) :
        # promue au boot pour détecter le schéma BDD non synchronisé (Iris à l'aveugle).
        ("schema_loaded", _check_training_store_data),
    ]

    for name, check_fn in checks:
        try:
            check_result = await check_fn()
            results["checks"][name] = check_result
            # Sortie actionnable : on accole le champ optionnel ``fix`` au
            # message pour qu'il apparaisse tel quel dans le log de démarrage
            # (cf. main._run_startup_diagnostics) — l'opérateur voit QUOI faire,
            # pas seulement que c'est cassé. Rétro-compatible : les checks sans
            # ``fix`` produisent l'ancien format.
            detail = check_result.get("detail", "unknown")
            fix = check_result.get("fix")
            msg = f"{name}: {detail}" + (f" → FIX: {fix}" if fix else "")
            if check_result["status"] == "error":
                results["errors"].append(msg)
            elif check_result["status"] == "warning":
                results["warnings"].append(msg)
        except Exception:
            logger.error("Startup check '%s' failed", name, exc_info=True)
            results["checks"][name] = {"status": "error", "detail": "check failed"}
            results["errors"].append(f"{name}: check failed")

    # Status global
    if results["errors"]:
        results["status"] = "degraded"
    if any(
        results["checks"].get(c, {}).get("status") == "error"
        for c in ("sqlite",)  # Seul SQLite est critique (sans DB, rien ne marche)
    ):
        results["status"] = "critical"

    return results


async def _check_sqlite() -> Dict[str, str]:
    """Vérifie que SQLite est accessible et fonctionnel."""
    try:
        from app.core.database import get_session
        from sqlalchemy import text

        async with get_session() as session:
            result = await session.execute(text("SELECT 1"))
            result.scalar()
        return {"status": "ok"}
    except Exception:
        logger.error("SQLite health check failed", exc_info=True)
        return {"status": "error", "detail": "SQLite inaccessible"}


async def _check_admin_seeded() -> Dict[str, str]:
    """Vérifie qu'au moins un compte ``role=admin`` ACTIF existe en BDD.

    ADV-S9 : on filtre sur ``is_active=True`` — un admin désactivé ne
    permet pas de se connecter, donc s'il n'y a que des admins désactivés,
    c'est l'équivalent fonctionnel de "0 admin" (impasse silencieuse).
    Avant : on comptait juste ``role=ADMIN`` sans tenir compte du statut.
    """
    try:
        from sqlalchemy import func, select

        from app.core.database import get_session
        from app.models.user import User, UserRole

        async with get_session() as db:
            result = await db.execute(
                select(func.count(User.id))
                .where(User.role == UserRole.ADMIN)
                .where(User.is_active.is_(True))
            )
            active_admin_count = result.scalar() or 0
        if active_admin_count == 0:
            # On regarde si des admins existent mais désactivés pour
            # afficher un message d'aide différencié.
            async with get_session() as db:
                result_total = await db.execute(
                    select(func.count(User.id)).where(User.role == UserRole.ADMIN)
                )
                total_admin = result_total.scalar() or 0
            if total_admin > 0:
                detail = (
                    f"{total_admin} administrateur(s) en base mais TOUS désactivés "
                    "(is_active=False). Réactivez un compte via `python -m scripts.seed_admin --force` "
                    "ou directement en BDD."
                )
            else:
                detail = (
                    "Aucun administrateur en base — l'application n'a pas de "
                    "compte initial. Lancez `make db-seed-admin` "
                    "(ou `python -m scripts.seed_admin`) pour en créer un."
                )
            return {"status": "warning", "detail": detail}
        return {
            "status": "ok",
            "detail": f"{active_admin_count} administrateur(s) actif(s)",
        }
    except Exception:
        logger.warning("Admin-seeded health check failed", exc_info=True)
        return {"status": "warning", "detail": "Comptage administrateurs indisponible"}


async def _check_training_store_api() -> Dict[str, str]:
    """
    Vérifie que TrainingStore expose les méthodes attendues.

    C'est exactement le type de bug silencieux qu'on veut détecter :
    un fichier appelle une méthode qui n'existe pas, et ça ne crashe
    qu'au runtime sur un chemin spécifique.
    """
    try:
        from app.services.ai.training_store import get_training_store

        store = get_training_store()
        # Méthodes critiques que d'autres modules appellent
        required_methods = [
            "get_all_table_names",
            "get_table_column_names",  # Utilisé par schema_freshness
            "get_ddl_by_table_names",
            "get_related_ddl",
            "get_related_documentation",
            "add_ddl",
            "add_documentation",
            "get_stats",
        ]
        missing = [m for m in required_methods if not hasattr(store, m)]
        if missing:
            return {
                "status": "error",
                "detail": f"Méthodes manquantes sur TrainingStore: {', '.join(missing)}",
            }
        return {"status": "ok", "detail": f"{len(required_methods)} méthodes vérifiées"}
    except Exception:
        logger.error("TrainingStore health check failed", exc_info=True)
        return {"status": "error", "detail": "TrainingStore non initialisable"}


async def _check_sage_config() -> Dict[str, str]:
    """Vérifie que la config BDD source est présente (credentials, pas connexion).

    Délègue à :func:`app.services.database.sage_health.get_sage_health_snapshot`
    pour rester aligné sur le statut affiché par le dashboard admin
    (cf. review adversariale finding #39 — éviter trois sources
    divergentes pour la même question "Sage est-il OK ?").
    """
    try:
        from app.services.database.sage_health import get_sage_health_snapshot

        snapshot = get_sage_health_snapshot()
        if snapshot.is_unconfigured:
            return {
                "status": "warning",
                "detail": "Aucune connexion BDD source activée (cf. /admin/database)",
            }
        if not snapshot.has_credentials:
            return {
                "status": "warning",
                "detail": "Pas de credentials BDD source (username vide)",
            }
        return {"status": "ok", "detail": "Credentials BDD source configurées"}
    except Exception:
        logger.warning("Sage config check failed", exc_info=True)
        return {"status": "warning", "detail": "BDD source non configurée"}


async def _check_llm_config() -> Dict[str, str]:
    """Vérifie qu'au moins un provider LLM est configuré."""
    try:
        from app.services.ai.llm_providers import get_llm_manager

        manager = get_llm_manager()
        if not manager.available_providers:
            return {"status": "warning", "detail": "Aucun provider LLM configuré"}

        return {"status": "ok"}
    except Exception:
        logger.warning("LLM config check failed", exc_info=True)
        return {"status": "warning", "detail": "Config LLM non vérifiable"}


async def _check_environment_coherence() -> Dict[str, str]:
    """Cohérence ENVIRONMENT ↔ topologie réelle (proxy + prod déguisée).

    Surface au boot deux pièges silencieux qui sinon ne se voient qu'en testant :
    - ``trust_proxy_headers=true`` avec un ``server.host`` non-loopback → RAPPEL
      (warning, PAS error) : en conteneur ``host=0.0.0.0`` est NORMAL — l'isolation
      vient du mapping hôte ``127.0.0.1:8888`` (docker-compose) que l'app ne peut
      pas introspecter. Le risque (``X-Forwarded-*`` usurpables) n'existe que si
      le port est exposé en direct. On rappelle la précondition, on n'affirme pas
      une erreur (sinon faux positif sur tout déploiement Docker+nginx légitime).
    - ``ENVIRONMENT != production`` alors que des indices de déploiement réel
      existent (SQLCIPHER_KEY posée, BDD source distante) → gardes fail-closed
      désactivées + cookies sans ``Secure`` : l'app paraît saine mais est insécure.
    """
    try:
        from app.config import config

        host = (config.server.host or "").strip()
        if config.server.trust_proxy_headers and host in ("0.0.0.0", "::", ""):
            return {
                "status": "warning",
                "detail": f"trust_proxy_headers=true avec server.host={host!r} (non-loopback)",
                "fix": "VÉRIFIEZ que le port app n'est joignable QUE via le reverse-proxy "
                "(docker-compose: 127.0.0.1:8888). En conteneur host=0.0.0.0 est normal SI le "
                "mapping hôte est loopback ; exposé en direct, les X-Forwarded-* sont usurpables.",
            }
        if not config.is_production():
            indices = []
            if config.database.encryption_key:
                indices.append("SQLCIPHER_KEY posée")
            if (config.sage.host or "localhost").strip() not in ("", "localhost", "127.0.0.1"):
                indices.append("BDD source distante")
            if indices:
                return {
                    "status": "warning",
                    "detail": f"ENVIRONMENT={config.environment} mais indices de prod "
                    f"({', '.join(indices)})",
                    "fix": "Si c'est un vrai déploiement, mettre ENVIRONMENT=production — "
                    "sinon cookies sans Secure + gardes fail-closed désactivées.",
                }
        return {"status": "ok"}
    except Exception:
        logger.warning("Environment coherence check failed", exc_info=True)
        return {"status": "warning", "detail": "Cohérence environnement non vérifiable"}


async def _check_timezone_configured() -> Dict[str, str]:
    """Surface au boot un fuseau horaire = UTC en production (donnée fausse silencieuse).

    Komptia stocke en UTC et convertit à l'AFFICHAGE vers ``config.server.timezone``
    (SSoT). Si le conteneur tourne en UTC faute de variable ``TZ`` (docker-compose
    pose ``TZ=${TZ:-UTC}`` en défaut), toutes les dates s'affichent en UTC SANS
    erreur — ex. +4h pour un cabinet en ``America/Guadeloupe``. On le signale
    (warning, PAS error : un déploiement réellement en UTC est légitime).
    """
    try:
        from app.config import config
        from app.core import clock

        tz_name = clock.machine_tz_name()
        if config.is_production() and tz_name == "UTC":
            return {
                "status": "warning",
                "detail": "Fuseau horaire = UTC : les dates s'affichent en UTC.",
                "fix": "Si vos utilisateurs ne sont pas en UTC, posez TZ=<nom IANA> "
                "(ex. America/Guadeloupe) dans .env puis redémarrez (make update).",
            }
        return {"status": "ok", "detail": f"Fuseau horaire : {tz_name}"}
    except Exception:
        logger.warning("Timezone check failed", exc_info=True)
        return {"status": "warning", "detail": "Fuseau horaire non vérifiable"}


def _origins_missing_scheme(raw_csv: str) -> List[str]:
    """Origines de ``KOMPTIA_ALLOWED_ORIGINS`` (CSV) dépourvues de schéma http(s)://.

    Le navigateur envoie TOUJOURS l'``Origin`` avec son schéma (``https://hôte``).
    Si la whitelist contient ``hôte`` (sans schéma), ``check_origin`` (WS aperçu)
    ne matche JAMAIS → la connexion est refusée SILENCIEUSEMENT. On valide le
    format au boot (fail-loud) plutôt que de laisser chaque connexion échouer
    sans surface. Origine valide = ``http(s)://hôte[:port]`` (schéma + netloc).
    """
    from urllib.parse import urlparse

    bad: List[str] = []
    for token in raw_csv.split(","):
        origin = token.strip()
        if not origin:
            continue
        parsed = urlparse(origin)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            bad.append(origin)
    return bad


async def _check_ws_origins() -> Dict[str, str]:
    """KOMPTIA_ALLOWED_ORIGINS : présent en prod ET bien formé (WS aperçu fail-closed).

    Aligné sur ``app.handlers.automation_preview_ws.check_origin`` :
    - en production, whitelist vide → toute connexion WS d'aperçu est refusée
      (fail-closed anti-CSRF) → on exige sa présence ;
    - whitelist présente mais une origine SANS schéma (``hôte`` au lieu de
      ``https://hôte``) → ``check_origin`` ne matche jamais → refus SILENCIEUX →
      on valide le format au boot.
    Sans ces checks, le symptôme n'apparaît qu'en testant l'aperçu (log serveur,
    aucune surface in-app).
    """
    try:
        import os

        from app.config import config

        raw = os.environ.get("KOMPTIA_ALLOWED_ORIGINS", "").strip()
        if not raw:
            if config.is_production():
                return {
                    "status": "error",
                    "detail": "KOMPTIA_ALLOWED_ORIGINS vide en production",
                    "fix": "Poser KOMPTIA_ALLOWED_ORIGINS=https://<hôte-public> dans .env — sinon "
                    "l'aperçu d'automatisation (/ws/automations/<id>/preview) refuse toute connexion.",
                }
            return {"status": "ok"}

        malformed = _origins_missing_scheme(raw)
        if malformed:
            return {
                "status": "error",
                "detail": f"KOMPTIA_ALLOWED_ORIGINS : origine(s) sans schéma http(s):// : {malformed}",
                "fix": "Chaque origine DOIT inclure son schéma (ex: https://komptia.client.fr). "
                "Sans schéma, le navigateur envoie `https://hôte` mais la whitelist contient `hôte` "
                "→ l'aperçu d'automatisation (WebSocket) est refusé SILENCIEUSEMENT.",
            }
        return {"status": "ok"}
    except Exception:
        logger.warning("WS origins check failed", exc_info=True)
        return {"status": "warning", "detail": "Config WS origins non vérifiable"}


async def _check_debug_off() -> Dict[str, str]:
    """DEBUG ne doit pas être actif en production (fuite de stack traces au navigateur)."""
    try:
        from app.config import config

        if config.is_production() and config.server.debug:
            return {
                "status": "error",
                "detail": "DEBUG=true en production",
                "fix": "Mettre DEBUG=false — Tornado debug expose les stack traces au navigateur.",
            }
        return {"status": "ok"}
    except Exception:
        logger.warning("Debug-off check failed", exc_info=True)
        return {"status": "warning", "detail": "Flag DEBUG non vérifiable"}


async def _check_disk_space() -> Dict[str, str]:
    """Surveille l'espace libre du volume de données (BDD/logs/backups/uploads).

    Sous le seuil critique → status "error" + **log CRITICAL** (saturation
    imminente = crash SQLite « disk I/O error », souvent silencieux jusqu'au
    plantage — cf. zone 10 review). Sous le seuil d'alerte → "warning". Les deux
    seuils sont configurables (``config.disk``, env ``KOMPTIA_DISK_*_FREE_MB``).

    Fail-safe : si la mesure est impossible (FS exotique, permission), on
    n'affirme PAS que tout va bien → "warning" (jamais fail-open silencieux).
    """
    try:
        import os
        import shutil

        from app.config import config

        path = str(config.data_dir)
        free_mb = shutil.disk_usage(path).free / (1024 * 1024)

        # Taille de la BDD locale — contexte best-effort (n'échoue pas le check).
        db_detail = ""
        try:
            db_path = config.database.path
            if os.path.exists(db_path):
                db_detail = f", BDD {os.path.getsize(db_path) / (1024 * 1024):.0f} MB"
        except OSError:
            pass

        warn_mb = config.disk.warn_free_mb
        crit_mb = config.disk.critical_free_mb

        if free_mb < crit_mb:
            logger.critical(
                "Espace disque CRITIQUE : %.0f MB libres sur %s (< %d MB) — risque "
                "de saturation (crash SQLite « disk I/O error »)%s",
                free_mb,
                path,
                crit_mb,
                db_detail,
            )
            return {
                "status": "error",
                "detail": f"{free_mb:.0f} MB libres (< {crit_mb} MB critique){db_detail}",
                "fix": "Libérer de l'espace (purge backups/logs anciens) OU agrandir le "
                "volume. Seuils : KOMPTIA_DISK_CRITICAL_FREE_MB / KOMPTIA_DISK_WARN_FREE_MB.",
            }
        if free_mb < warn_mb:
            logger.warning(
                "Espace disque bas : %.0f MB libres sur %s (< %d MB)%s",
                free_mb,
                path,
                warn_mb,
                db_detail,
            )
            return {
                "status": "warning",
                "detail": f"{free_mb:.0f} MB libres (< {warn_mb} MB alerte){db_detail}",
            }
        return {"status": "ok", "detail": f"{free_mb:.0f} MB libres{db_detail}"}
    except Exception:
        logger.warning("Disk-space check failed", exc_info=True)
        return {"status": "warning", "detail": "Espace disque non vérifiable"}


# Horodatage (monotonic) de la dernière alerte mail disque envoyée — état
# process-local (le scheduler est single-leader). 0.0 = jamais envoyée.
_last_disk_alert_at: float = 0.0


async def _maybe_send_disk_alert(detail: str) -> bool:
    """Envoie une alerte mail « disque critique » au support, avec throttle.

    No-op (retourne ``False``) si : ``support_email`` non configuré, SMTP non
    configuré, ou alerte déjà envoyée dans la fenêtre ``config.disk.alert_throttle_hours``
    (anti-spam — le check tourne toutes les N heures, on ne veut pas N mails).
    Fail-soft : toute erreur d'envoi est loggée, jamais propagée.
    """
    global _last_disk_alert_at
    try:
        import time as _time

        from app.config import config

        now = _time.monotonic()
        throttle_s = max(0, config.disk.alert_throttle_hours) * 3600
        if _last_disk_alert_at and (now - _last_disk_alert_at) < throttle_s:
            return False  # throttlé (alerte récente déjà envoyée)

        from app.services.feedback.feedback_service import resolve_support_email

        recipient = await resolve_support_email()
        if not recipient:
            logger.warning(
                "Alerte disque critique : support_email non configuré → pas de mail "
                "(le log CRITICAL reste la trace). Configurer /admin/smtp-config."
            )
            return False

        from app.services.email.smtp_factory import build_smtp_client_from_db

        client = await build_smtp_client_from_db(fallback_from_name=config.app_name)
        if client is None:
            logger.warning("Alerte disque critique : SMTP non configuré → pas de mail.")
            return False

        subject = f"[{config.app_name}] ALERTE — espace disque critique"
        body_text = (
            f"L'espace disque du serveur {config.app_name} est CRITIQUE : {detail}.\n\n"
            "Risque de saturation imminente (crash SQLite « disk I/O error »). "
            "Action : libérer de l'espace (purge des backups/logs anciens) ou agrandir le volume."
        )
        body_html = (
            "<p><strong>ALERTE — espace disque critique</strong></p>"
            f"<p>{detail}</p>"
            "<p>Risque de saturation imminente (crash SQLite « disk I/O error »). "
            "Libérer de l'espace ou agrandir le volume.</p>"
        )
        await client.send_email(
            recipient, subject, body_html, body_text=body_text, template_name="disk_alert"
        )
        _last_disk_alert_at = now
        logger.info("Alerte disque critique envoyée à %s", recipient)
        return True
    except Exception:  # noqa: BLE001 — fail-soft, jamais bloquer le job
        logger.warning("Alerte disque critique : envoi échoué", exc_info=True)
        return False


def run_disk_space_check_job() -> Optional[Dict[str, str]]:
    """Job scheduler (SYNC) — déclenche périodiquement :func:`_check_disk_space`,
    et envoie une alerte mail throttlée si l'espace est CRITIQUE.

    Le boot-check (``startup_check``) ne voit la saturation qu'au redémarrage ;
    ce job la capte PENDANT l'exploitation (zone 10). ``_check_disk_space`` logue
    déjà CRITICAL/WARNING en interne → on ne re-logue pas (anti-bruit). L'alerte
    mail est gérée ici (PAS au boot : SMTP pas forcément prêt + bruit à l'install).
    Fail-soft : aucune exception ré-émise vers le scheduler.
    Retourne le résultat du check (testabilité) ou ``None`` si échec.
    """
    import asyncio

    from app.core.database import dedicated_session_scope

    async def _run() -> Dict[str, str]:
        result = await _check_disk_space()
        if result.get("status") == "error":
            # _maybe_send_disk_alert lit support_email + config SMTP en BDD → engine
            # dédié à cette boucle asyncio.run (cross-loop : pas l'engine global poolé).
            async with dedicated_session_scope():
                await _maybe_send_disk_alert(result.get("detail", ""))
        return result

    try:
        return asyncio.run(_run())
    except Exception:  # noqa: BLE001 — fail-soft scheduler
        logger.warning("Disk-space periodic check failed", exc_info=True)
        return None


async def _check_scheduler_enabled() -> Dict[str, str]:
    """Avertit si le scheduler est désactivé sur ce process (KOMPTIA_SCHEDULER_ENABLED).

    Mirror EXACT de la logique de ``app.services.automation.scheduler`` (même
    ensemble de valeurs falsy) — pas de divergence d'interprétation. Désactivé
    sur CE process est normal en multi-worker (un seul porte le scheduler via
    leader-lock) ; mais désactivé PARTOUT → aucun cron (automations planifiées +
    purge IdempotencyLog) ne tourne → croissance non bornée de la BDD (axe 21).
    """
    try:
        import os

        if os.environ.get("KOMPTIA_SCHEDULER_ENABLED", "true").lower() in (
            "false",
            "0",
            "no",
            "off",
        ):
            return {
                "status": "warning",
                "detail": "KOMPTIA_SCHEDULER_ENABLED=false sur ce process",
                "fix": "Normal si un AUTRE worker porte le scheduler (leader-lock). Sinon "
                "(déploiement mono-process), aucun cron ne tournera : retirer la variable "
                "ou la mettre à true.",
            }
        return {"status": "ok"}
    except Exception:
        logger.warning("Scheduler-enabled check failed", exc_info=True)
        return {"status": "warning", "detail": "Flag scheduler non vérifiable"}


# ============================================================
# 2. Error Watchdog — Détecte les erreurs répétées en runtime
# ============================================================


class ErrorWatchdog:
    """
    Surveille les erreurs répétées et prend des mesures automatiques.

    Problème résolu : quand une erreur se répète 388 fois dans les logs
    (ex: méthode manquante appelée pour chaque table), personne ne le voit
    jusqu'à ce qu'un humain lise les logs. Ce watchdog détecte le pattern
    et lève un WARNING clair dès que le seuil est atteint.

    Usage:
        watchdog = get_error_watchdog()
        watchdog.record("schema_freshness", "get_table_column_names missing")
        # Après N occurrences, le watchdog log un WARNING consolidé
    """

    # Seuils d'alerte
    WARN_THRESHOLD = 5  # 5 erreurs identiques → WARNING consolidé
    CRITICAL_THRESHOLD = 50  # 50 erreurs identiques → CRITICAL + suggestion de fix

    def __init__(self):
        self._error_counts: Dict[str, int] = defaultdict(int)
        self._error_first_seen: Dict[str, float] = {}
        self._error_last_msg: Dict[str, str] = {}
        self._alerted: Dict[str, bool] = defaultdict(bool)
        self._suppressed_count: Dict[str, int] = defaultdict(int)

    def record(self, category: str, error_msg: str) -> bool:
        """
        Enregistre une erreur. Retourne True si l'erreur est nouvelle (pas encore supprimée).

        Args:
            category: Catégorie de l'erreur (ex: "schema_freshness", "sage_connector")
            error_msg: Message d'erreur (sera dédupliqué par les 80 premiers caractères)

        Returns:
            True si l'erreur doit être loggée normalement, False si supprimée
        """
        # Clé de déduplication : catégorie + début du message
        key = f"{category}:{error_msg[:80]}"

        if key not in self._error_first_seen:
            self._error_first_seen[key] = time.time()
        self._error_counts[key] += 1
        self._error_last_msg[key] = error_msg
        count = self._error_counts[key]

        # Première occurrence → toujours logger
        if count == 1:
            return True

        # Seuil WARNING atteint → alerte consolidée
        if count == self.WARN_THRESHOLD and not self._alerted[key]:
            self._alerted[key] = True
            elapsed = time.time() - self._error_first_seen[key]
            logger.warning(
                "⚠️ WATCHDOG: Erreur répétée %d fois en %.1fs — [%s] %s. "
                "Les occurrences suivantes seront supprimées des logs.",
                count,
                elapsed,
                category,
                error_msg[:120],
            )
            return False

        # Seuil CRITICAL → alerte forte
        if count == self.CRITICAL_THRESHOLD:
            elapsed = time.time() - self._error_first_seen[key]
            logger.error(
                "🚨 WATCHDOG CRITICAL: Erreur répétée %d fois en %.1fs — [%s] %s. "
                "Probablement un bug systémique à corriger.",
                count,
                elapsed,
                category,
                error_msg[:120],
            )
            return False

        # Entre les seuils → supprimer (pas de spam dans les logs)
        if count > self.WARN_THRESHOLD:
            self._suppressed_count[key] += 1
            return False

        return True

    def get_summary(self) -> List[Dict[str, Any]]:
        """Retourne un résumé des erreurs détectées (pour le health check)."""
        summary = []
        for key, count in sorted(self._error_counts.items(), key=lambda x: -x[1]):
            if count >= self.WARN_THRESHOLD:
                category, msg_start = key.split(":", 1)
                summary.append(
                    {
                        "category": category,
                        "message": self._error_last_msg.get(key, msg_start),
                        "count": count,
                        "suppressed": self._suppressed_count.get(key, 0),
                        "first_seen": self._error_first_seen.get(key),
                    }
                )
        return summary

    def reset(self):
        """Reset tous les compteurs (utile après un fix)."""
        self._error_counts.clear()
        self._error_first_seen.clear()
        self._error_last_msg.clear()
        self._alerted.clear()
        self._suppressed_count.clear()


# Singleton
_watchdog: Optional[ErrorWatchdog] = None


def get_error_watchdog() -> ErrorWatchdog:
    """Retourne le singleton ErrorWatchdog."""
    global _watchdog
    if _watchdog is None:
        _watchdog = ErrorWatchdog()
    return _watchdog


# ============================================================
# 3. Detailed health — Pour /health/detailed
# ============================================================


async def detailed_health() -> Dict[str, Any]:
    """
    État complet de l'app. Utilisé par HealthDetailedHandler.

    Vérifie :
    - SQLite (lecture/écriture)
    - Sage (ping connexion si configuré)
    - Training Store (données chargées ?)
    - Watchdog (erreurs répétées en cours ?)
    """
    result: Dict[str, Any] = {
        "status": "healthy",
        "checks": {},
    }

    # SQLite
    result["checks"]["sqlite"] = await _check_sqlite()

    # Sage ping (connexion réelle, pas juste config)
    result["checks"]["sage"] = await _check_sage_connection()

    # Training store stats
    result["checks"]["training_store"] = await _check_training_store_data()

    # Watchdog errors
    watchdog = get_error_watchdog()
    errors = watchdog.get_summary()
    if errors:
        result["checks"]["watchdog"] = {
            "status": "warning",
            "detail": f"{len(errors)} pattern(s) d'erreurs répétées détecté(s)",
            "errors": errors[:5],  # Top 5
        }
    else:
        result["checks"]["watchdog"] = {"status": "ok", "detail": "Aucune erreur répétée"}

    # Status global
    statuses = [c.get("status", "ok") for c in result["checks"].values()]
    if "error" in statuses:
        result["status"] = "unhealthy"
    elif "warning" in statuses:
        result["status"] = "degraded"

    return result


async def _check_sage_connection() -> Dict[str, str]:
    """Teste une vraie connexion à Sage (SELECT 1) avec timeout."""
    try:
        import asyncio
        from app.services.database.sage_connector import get_sage_connector, PYODBC_AVAILABLE

        if not PYODBC_AVAILABLE:
            return {"status": "warning", "detail": "pyodbc non disponible"}

        connector = get_sage_connector()
        if not connector.username:
            return {"status": "warning", "detail": "Pas de credentials Sage"}

        # Tenter un ping rapide avec timeout de 10s
        async def _ping():
            if not connector.is_connected:
                await connector.connect()
            await connector.execute("SELECT 1")

        await asyncio.wait_for(_ping(), timeout=10.0)
        return {"status": "ok"}
    except asyncio.TimeoutError:
        logger.warning("Sage connection health check timed out (10s)")
        return {"status": "warning", "detail": "Sage timeout (10s)"}
    except Exception:
        logger.warning("Sage connection health check failed", exc_info=True)
        return {"status": "warning", "detail": "Sage inaccessible"}


async def _check_training_store_data() -> Dict[str, Any]:
    """Vérifie que le training store a des données."""
    try:
        from app.services.ai.training_store import get_training_store

        store = get_training_store()
        stats = await store.get_stats()
        table_count = stats.get("ddl_count", 0)
        if table_count == 0:
            return {
                "status": "warning",
                "detail": "Training store vide (aucun DDL). Sync schéma nécessaire.",
                "fix": "Lancer la synchro schéma BDD source (/admin/database) — sinon Iris "
                "génère du SQL sans contexte (viole l'invariant 'jamais à l'aveugle').",
            }
        return {
            "status": "ok",
            "detail": f"{table_count} tables, "
            f"{stats.get('documentation_count', 0)} docs, "
            f"{stats.get('question_sql_count', 0)} Q/SQL",
        }
    except Exception:
        logger.warning("Training store data check failed", exc_info=True)
        return {"status": "warning", "detail": "Stats non disponibles"}


# ============================================================
# 4. Scheduler health — Pour /health/scheduler
# ============================================================


async def scheduler_health(
    orphaned_threshold_min: int = ORPHANED_DISPLAY_THRESHOLD_MIN,
) -> Dict[str, Any]:
    """État du scheduler d'automatisations + détection d'exécutions orphelines.

    Retourne un dictionnaire au schéma stable consommé par
    :class:`app.handlers.health.SchedulerHealthHandler` ::

        {
            "status": "healthy" | "degraded" | "unhealthy",
            "scheduler_running": bool,
            "active_jobs": int,
            "orphaned_executions": int | None,  # None si DB inaccessible
            "last_execution": str | None,       # ISO-8601 ou None
            "db_check": "ok" | "error",
        }

    Sémantique du status :

    * ``unhealthy`` — scheduler arrêté ou non initialisé. Plus aucun job
      planifié ne s'exécutera.
    * ``degraded`` — scheduler OK mais : (a) BDD locale inaccessible (on ne
      peut pas affirmer "0 orphelins"), ou (b) au moins une exécution est
      stuck en ``running`` depuis plus de ``orphaned_threshold_min`` minutes.
    * ``healthy`` — scheduler OK, BDD OK, 0 orphelins.

    **Fail-safe** : une exception en lecture DB n'est jamais propagée — on
    rapporte ``db_check="error"`` et on bascule en ``degraded``. Mieux vaut
    un dashboard alarmé qu'une fausse promesse de santé (CLAUDE.md
    fail-closed). Le compteur ``orphaned_executions`` devient ``None`` plutôt
    que ``0`` pour ne pas mentir aux consommateurs Prometheus / Grafana.
    """
    from sqlalchemy import func, select  # local import : SQLAlchemy lourd
    from sqlalchemy.exc import SQLAlchemyError

    from app.core.database import get_session_factory
    from app.models.execution import Execution
    from app.services.automation.scheduler import get_scheduler

    try:
        scheduler = get_scheduler()
    except Exception:
        logger.error("Failed to get scheduler instance", exc_info=True)
        return {
            "status": "unhealthy",
            "scheduler_running": False,
            "active_jobs": 0,
            "orphaned_executions": None,
            "last_execution": None,
            "db_check": "error",
        }

    scheduler_running = bool(scheduler.scheduler and scheduler.scheduler.running)
    try:
        active_jobs = len(scheduler.get_jobs()) if scheduler.scheduler else 0
    except Exception:
        logger.warning("Failed to enumerate scheduler jobs", exc_info=True)
        active_jobs = 0

    orphaned_count: Optional[int]
    last_execution_iso: Optional[str]
    db_ok: bool
    cutoff = clock.now() - timedelta(minutes=orphaned_threshold_min)
    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            count_result = await session.execute(
                select(func.count(Execution.id)).where(
                    Execution.status == EXECUTION_STATUS_RUNNING,
                    Execution.started_at < cutoff,
                )
            )
            orphaned_count = int(count_result.scalar() or 0)

            last_result = await session.execute(
                select(Execution.finished_at)
                .where(Execution.finished_at.isnot(None))
                .order_by(Execution.finished_at.desc())
                .limit(1)
            )
            last_finished = last_result.scalar_one_or_none()
            last_execution_iso = last_finished.isoformat() if last_finished else None
            db_ok = True
    except SQLAlchemyError:
        logger.warning("Database error in scheduler health check", exc_info=True)
        orphaned_count = None
        last_execution_iso = None
        db_ok = False
    except Exception:
        logger.error("Unexpected error in scheduler health check", exc_info=True)
        orphaned_count = None
        last_execution_iso = None
        db_ok = False

    if not scheduler_running:
        status = "unhealthy"
    elif not db_ok:
        # On ne peut pas affirmer "0 orphelins" sans la BDD : dégrader
        # explicitement plutôt que mentir au monitoring (fail-closed).
        status = "degraded"
    elif orphaned_count and orphaned_count > 0:
        status = "degraded"
    else:
        status = "healthy"

    return {
        "status": status,
        "scheduler_running": scheduler_running,
        "active_jobs": active_jobs,
        "orphaned_executions": orphaned_count,
        "last_execution": last_execution_iso,
        "db_check": "ok" if db_ok else "error",
    }
