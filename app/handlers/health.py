"""Endpoints HTTP de santé Komptia.

Trois niveaux exposés (cf. patterns Kubernetes liveness/readiness/startup
et RFC ``draft-inadarei-api-health-check``) :

* ``GET /health`` — sonde **liveness** lightweight pour load-balancer.
  Réponse minimale **publique**, coût constant (zéro I/O), pas de fuite
  d'info. Une instance reste « live » même si Sage est down — la
  signalisation des dépendances dégradées est le rôle des autres endpoints.

* ``GET /health/detailed`` — diagnostic **profond** (SQLite, Sage ping,
  training store, watchdog d'erreurs). **Admin-only** : l'inventaire des
  dépendances + leur état + la version + l'environnement constituent une
  fuite de reconnaissance pour un attaquant (CWE-209). Les sondes
  externes (Datadog, Grafana) doivent passer par un compte admin dédié.

* ``GET /health/scheduler`` — état **APScheduler** + détection des
  exécutions orphelines (RUNNING > N min). **Admin-only** pour les mêmes
  raisons (recon : activité par horaire, métriques internes du moteur).

Conventions de réponse
----------------------
* ``/health`` : ``{"status": "ok"}`` — vocabulaire minimal pour les
  consommateurs LB qui ne lisent que le code HTTP.
* ``/health/detailed`` et ``/health/scheduler`` :
  ``{"status": "healthy"|"degraded"|"unhealthy", ...}`` — vocabulaire riche
  pour la console admin. Mapping HTTP : ``healthy → 200, degraded → 503,
  unhealthy → 503`` (sortir de la rotation LB jusqu'à remediation, plutôt
  que servir des requêtes avec un sous-système silencieusement dégradé).
* Timestamps en ISO-8601 RFC 3339 avec suffixe ``Z`` (jamais ``+00:00``)
  pour cohérence inter-services et alignement Datadog/Grafana — voir
  :func:`_iso_z`.

Sécurité
--------
* ``/health`` ne fuit aucune info : payload constant, pas de version, pas
  d'environnement, pas de timestamp (qui pourrait diverger entre instances
  d'un cluster et fingerprinter une rotation de pods).
* Les erreurs DB du check scheduler sont **fail-safe** : on dégrade le
  status à ``degraded`` avec un champ explicite ``db_check="error"`` et on
  rapporte ``orphaned_executions=None`` au lieu de ``0`` — un fail-OPEN
  silencieux qui rapporterait ``healthy`` est interdit (CLAUDE.md).
* Pas de rate-limiting sur ``/health`` : LB et K8s peuvent hammer le
  endpoint à 1Hz par instance — le coût est négligeable et toute restriction
  introduirait des faux positifs « unhealthy ».
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final

from app.config import config
from app.core import clock
from app.handlers.base import BaseHandler, admin_required
from app.services.diagnostics import (
    _check_sqlite,
    detailed_health,
    scheduler_health,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ── Constantes ────────────────────────────────────────────────────────────

#: Vocabulaire de status retourné par les endpoints détaillés. Aligné sur la
#: convention Kubernetes / load-balancer (200 pour healthy, 503 pour autre).
#: Le simple endpoint ``/health`` utilise un vocabulaire plus minimaliste
#: (``ok``) volontairement distinct, pour les LB qui n'interprètent pas la
#: subtilité ``degraded`` vs ``unhealthy``.
_STATUS_HEALTHY: Final[str] = "healthy"
_STATUS_DEGRADED: Final[str] = "degraded"
_STATUS_UNHEALTHY: Final[str] = "unhealthy"

#: Mapping status → code HTTP. ``degraded`` retourne 503 pour sortir
#: l'instance de la rotation LB jusqu'à remediation. Toute valeur inconnue
#: tombe sur 503 (fail-closed) — un status non listé est une régression.
_STATUS_HTTP_CODE: Final[dict[str, int]] = {
    _STATUS_HEALTHY: 200,
    _STATUS_DEGRADED: 503,
    _STATUS_UNHEALTHY: 503,
}


# ── Helpers ───────────────────────────────────────────────────────────────


def _iso_z(dt: datetime) -> str:
    """Formate un datetime UTC en ISO 8601 RFC 3339 avec suffixe ``Z``.

    ``datetime.isoformat()`` produit ``2026-04-19T12:00:00+00:00`` ; la
    convention RFC 3339 préfère ``Z``, plus court et standard pour les APIs
    (Datadog, Grafana, Loki). N'altère que les datetimes annotés UTC ; un
    datetime naïf ou avec une autre tz est retourné intact pour ne pas
    mentir sur le fuseau.
    """
    iso = dt.isoformat()
    return iso[:-6] + "Z" if iso.endswith("+00:00") else iso


def _http_status_for(status: str) -> int:
    """Mappe un status sémantique vers un code HTTP. Fail-closed: inconnu → 503."""
    return _STATUS_HTTP_CODE.get(status, 503)


async def _build_detailed_response() -> tuple[dict[str, Any], int]:
    """Construit la réponse santé détaillée (SSoT de ``/health/detailed``, admin)."""
    health = await detailed_health()
    status = health["status"]
    response: dict[str, Any] = {
        "status": status,
        "version": config.app_version,
        "environment": config.environment,
        "timestamp": _iso_z(clock.now()),
        "checks": health["checks"],
    }
    return response, _http_status_for(status)


# ── Handlers ──────────────────────────────────────────────────────────────


class HealthHandler(BaseHandler):
    """Endpoint liveness minimaliste, **publique**, sans authentification.

    Cible : load-balancer (AWS ALB, nginx) / sonde liveness Kubernetes.
    Doit rester **lightweight** (zéro I/O DB / Sage / LLM) — une instance
    peut être « live » même si Sage est down ; la signalisation des
    dépendances dégradées est le rôle de ``/health/detailed``.

    Aucune fuite d'info : payload constant, pas de version, pas
    d'environnement, pas de timestamp (qui fingerprintrait l'instance).
    """

    async def get(self) -> None:
        self.write_json({"status": "ok"}, status=200)


class HealthReadyHandler(BaseHandler):
    """Endpoint **readiness** publique : confirme que la BDD locale répond.

    Distinction avec ``/health`` (liveness) : un process peut être *live*
    (Tornado répond) mais pas *ready* si la BDD est verrouillée, en cours
    de migration, ou inaccessible. Kubernetes utilise les deux signaux
    différemment : un pod *not-ready* est sorti de la rotation LB sans
    être tué (pour reprendre quand il sera de nouveau ready), alors qu'un
    pod *not-live* est redémarré. Sans cet endpoint, K8s ne peut pas
    différencier — il redémarre dès que la BDD a un hoquet, ce qui
    aggrave les pannes.

    Sécurité — pas de fuite : payload binaire ``{"ready": bool}``, pas
    de message d'erreur (qui révélerait la cause = recon attaquant).
    Le détail va dans ``/health/detailed`` qui est admin-only.
    """

    async def get(self) -> None:
        check = await _check_sqlite()
        ready = check.get("status") == "ok"
        self.write_json(
            {"ready": ready},
            status=200 if ready else 503,
        )


class HealthDetailedHandler(BaseHandler):
    """Diagnostic profond : SQLite, Sage, training store, watchdog d'erreurs.

    **Admin-only** — l'inventaire des dépendances + leur état + la version
    + l'environnement constituent une fuite de reconnaissance (CWE-209).
    Les sondes externes (Datadog, Grafana) doivent passer par un compte
    admin dédié.
    """

    @admin_required
    async def get(self) -> None:
        response, http_status = await _build_detailed_response()
        self.write_json(response, status=http_status)


class SchedulerHealthHandler(BaseHandler):
    """État du scheduler APScheduler + détection d'exécutions orphelines.

    **Admin-only** : le nombre de jobs actifs + l'état d'orphelinage
    constituent un signal de recon (état interne du moteur, activité par
    horaire). Pas de raison de l'exposer publiquement.

    Délègue toute la logique à :func:`scheduler_health` qui garantit le
    fail-safe sur erreur DB. Le handler reste un thin presenter (SRP) :
    il ajoute juste le timestamp et le mapping HTTP.
    """

    @admin_required
    async def get(self) -> None:
        snapshot = await scheduler_health()
        status = snapshot["status"]
        response = {**snapshot, "timestamp": _iso_z(clock.now())}
        self.write_json(response, status=_http_status_for(status))
