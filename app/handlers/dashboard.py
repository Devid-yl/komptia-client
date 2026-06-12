"""
Dashboard handlers — tableau de bord applicatif (HTML + API charts).

Deux vues distinctes :
- ``DashboardHandler`` — page ``/`` ou ``/dashboard``, rend le template admin ou
  user en fonction du rôle. Dispatch **fail-closed** : tout rôle non explicitement
  géré lève ``HTTPError(403)`` plutôt que de retomber silencieusement sur la vue
  user (cf. CLAUDE.md § « Authz fail-closed : rôle inconnu → 0 permissions »).
- ``DashboardChartsAPIHandler`` — endpoint JSON ``/api/dashboard/charts``
  consommé par Plotly côté front. Le handler délègue la construction du payload
  au service (``DashboardStatsService.build_charts_payload``) pour que la logique
  de présentation reste testable sans serveur HTTP.

La logique de récupération des stats est déléguée à ``DashboardStatsService``,
et les appels indépendants sont parallélisés via ``asyncio.gather`` (chaque
helper du ``RecentDataService`` ouvre sa propre ``AsyncSession`` — pattern
recommandé par la doc SQLAlchemy 2.0 pour le ``gather`` concurrent).
"""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING, Any, Final

from sqlalchemy.exc import SQLAlchemyError
from tornado.web import HTTPError

from sqlalchemy import select

from app.core.database import get_session
from app.handlers.base import BaseHandler, authenticated
from app.models.user import UserRole
from app.models.user_onboarding_progress import UserOnboardingProgress
from app.services.dashboard.charts import (
    DashboardStatsService,
    get_stats_service,
)
from app.utils.logger import get_logger

if TYPE_CHECKING:
    from datetime import datetime

    from app.models.user import User

logger = get_logger(__name__)


# Cache court pour l'API charts. ``private`` : données personnelles, jamais
# partagées par proxy/CDN. ``max-age=60`` : 60 s absorbe les doubles hits
# (chargement template + fetch JS) sans servir de données trop obsolètes.
# ``stale-while-revalidate=300`` : pendant 5 min après expiration du
# max-age, le navigateur peut servir la version cache TANT QU'il revalide
# en background — UX plus fluide (pas de spinner sur F5 rapide), avec
# garantie de fraîcheur revalidée. Sécurité : pas de fuite cross-user car
# ``private`` empêche tout partage entre origines.
_CHARTS_CACHE_CONTROL: Final[str] = "private, max-age=60, stale-while-revalidate=300"

# ``SecurityHeadersMiddleware._apply_cache_control`` pose ``Cache-Control:
# no-store`` + ``Pragma: no-cache`` sur tout ``/api/*`` par défaut. Ce handler
# expose un cache court privé (60 s) — il faut donc :
# 1. Override ``Cache-Control`` (fait via ``set_header`` ci-dessous).
# 2. Effacer ``Pragma`` qui sinon traîne et CONTRADIT ``max-age=60`` aux yeux
#    des proxies HTTP/1.0 et de certains outils d'audit (curl -i les voit
#    tous les deux). Tornado n'a pas de ``clear_header`` officiel, mais
#    réécrire à chaîne vide retire l'en-tête (cf. Tornado http1connection :
#    en-tête vide n'est pas émis).
_PRAGMA_HEADER_NAME: Final[str] = "Pragma"


# Timeout par sous-service au rendu HTML. Backpressure : si une coro lente
# (DB lente, service externe down) prend > N secondes, on la considère
# perdue et on retombe sur sa valeur par défaut (dict vide / liste vide).
# Le bandeau d'erreur en haut du template flagge la perte. Sans ce timeout,
# UN sous-service lent retardait le rendu de TOUTE la page.
#
# Configurable via ``KOMPTIA_DASHBOARD_SUBLOAD_TIMEOUT_S`` (review C3 + R2-A3) —
# le défaut 5 s couvre 99 % des requêtes locales SQLite, mais une instance
# avec Sage Coala distant via VPN peut nécessiter 8-15 s. Le `db_session_
# timeout_s` global est à 30 s — on reste plus court ici car le user attend
# la page.
#
# **Validation min/max** (review R2-A3) : sans bornes, ``=abc`` faisait
# crasher le boot, ``=-5`` rendait wait_for instantané, ``=999999`` figeait
# le rendu. ``[0.5, 60]`` couvre tous les cas réalistes (sub-second à
# 1 minute) ; hors bornes → fallback default + log warning.
#
# ⚠️ Lue **une fois à l'import** — modifier ``.env`` exige redémarrer le
# serveur (cf. tous les autres ``KOMPTIA_*`` du module).
def _env_float_clamped(name: str, default: float, *, minimum: float, maximum: float) -> float:
    """Lit un seuil flottant depuis env avec validation min/max et fail-safe."""
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except (ValueError, TypeError):
        # ``logger`` est défini plus bas dans le module ; au moment de
        # l'import top-level on ne peut pas logger. On laisse silencieux
        # (la valeur par défaut est utilisée — même comportement qu'un
        # ``.env`` absent), pas un crash.
        return default
    if value < minimum or value > maximum:
        return default
    return value


_SUBLOAD_TIMEOUT_S: Final[float] = _env_float_clamped(
    "KOMPTIA_DASHBOARD_SUBLOAD_TIMEOUT_S",
    default=5.0,
    minimum=0.5,
    maximum=60.0,
)


# ── Onboarding tour : seuil de date pour ne PAS le montrer aux users
# existants au moment du déploiement. Sans ce filtre, les comptes créés
# avant le déploiement de la feature verraient un modal de bienvenue
# surprise (review adversariale R2-A6).
#
# Convention : l'admin pose ``KOMPTIA_ONBOARDING_DEPLOY_DATE`` (ISO 8601,
# ex. ``2026-04-29``) au moment du déploiement. Tous les users dont
# ``created_at < cette date`` ne voient pas le tour. Les nouveaux comptes
# créés après le voient.
#
# Si la variable est absente (dev / staging frais), on retombe sur
# ``None`` → le tour s'affiche pour tous (comportement actuel pour pouvoir
# tester en local sans configurer de date).
def _parse_deploy_date() -> "datetime | None":
    from datetime import datetime as _dt, timezone as _tz

    raw = os.environ.get("KOMPTIA_ONBOARDING_DEPLOY_DATE")
    if not raw:
        return None
    try:
        parsed = _dt.fromisoformat(raw)
    except (ValueError, TypeError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_tz.utc)


_ONBOARDING_DEPLOY_DATE = _parse_deploy_date()


def _should_show_onboarding(user: "User") -> bool:
    """Heuristique « newcomer » basée sur ``user.created_at``.

    Conservée pour le tour user (``dashboard_user_v2``) où le créneau
    « créé après le déploiement de l'onboarding » suffit comme signal.

    Pour le tour admin, voir :func:`_should_show_admin_onboarding` qui
    interroge en plus le journal BDD ``user_onboarding_progress`` (Bug
    2026-05-26 F2 CRITIQUE — admin promu après le déploiement ne voyait
    jamais le tour parce que ``created_at`` est figé à la création du
    compte user, pas à la promotion).
    """
    if _ONBOARDING_DEPLOY_DATE is None:
        return True
    created = getattr(user, "created_at", None)
    if created is None:
        return True
    if created.tzinfo is None:
        from datetime import timezone as _tz

        created = created.replace(tzinfo=_tz.utc)
    return created >= _ONBOARDING_DEPLOY_DATE


# Tour key du dashboard admin — SSoT côté Python pour aligner avec le
# ``key`` passé à ``KomptiaOnboarding.start`` dans ``templates/dashboard/admin.html``.
# Si le key change template-side, mettre à jour ICI aussi (test de garde
# vérifie l'alignement).
_ADMIN_TOUR_KEY: Final[str] = "dashboard_admin_v2"


async def _should_show_admin_onboarding(user: "User") -> bool:
    """Décide si l'admin doit voir le tour ``dashboard_admin_v2``.

    Bug 2026-05-26 (F2 CRITIQUE) : avant ce fix, on utilisait simplement
    ``_should_show_onboarding`` qui se basait UNIQUEMENT sur
    ``user.created_at >= _ONBOARDING_DEPLOY_DATE``. Conséquence : un
    utilisateur créé avant le déploiement et promu admin par la suite ne
    voyait JAMAIS le tour admin — sa ``created_at`` était figée à la date
    de création du compte, antérieure au déploiement.

    Politique nouvelle (cohérente avec la SSoT BDD du JS qui consulte
    ``user_onboarding_progress`` via ``/api/onboarding/state``) :

    1. **A déjà été vu** (row avec ``completed_at`` ou ``skipped_at``) →
       jamais re-montré (idempotence ; respecte un skip volontaire).
    2. **Newcomer** (``created_at >= deploy_date``) → montré (tour pour
       les comptes créés après le déploiement).
    3. **Veteran sans row** (``created_at < deploy_date`` mais aucune ligne
       dans ``user_onboarding_progress`` pour ce tour_key) → montré une
       SEULE fois — c'est le scénario « promu après le déploiement ».

    Notes de design :
    - Best-effort BDD : sur SQLAlchemyError, on tombe sur l'heuristique
      ``created_at`` historique (pas de denial-of-feature à cause d'un
      glitch BDD).
    - Pas de mutation BDD ici. La ligne sera créée par le JS quand il
      appellera ``POST /api/onboarding/tours/<key>/start``.
    """
    user_id = getattr(user, "id", None)
    if user_id is None:
        return _should_show_onboarding(user)

    try:
        async with get_session() as session:
            row = (
                await session.execute(
                    select(UserOnboardingProgress).where(
                        UserOnboardingProgress.user_id == user_id,
                        UserOnboardingProgress.tour_key == _ADMIN_TOUR_KEY,
                    )
                )
            ).scalar_one_or_none()
    except SQLAlchemyError:
        logger.warning(
            "Onboarding admin: fallback heuristique created_at (BDD inaccessible)",
            exc_info=True,
        )
        return _should_show_onboarding(user)

    if row is not None and (row.completed_at is not None or row.skipped_at is not None):
        return False
    # Pas de row OU row sans completed_at/skipped_at (started_at peut
    # exister si l'admin a vu le tour mais n'a pas encore agi). Montrer.
    return True


# Message FR user-facing en cas de 500 côté API. Centralisé ici pour ne pas leak
# la stack trace (cf. Phase 8 — OWASP A09).
_CHARTS_UNAVAILABLE_MESSAGE: Final[str] = "Statistiques indisponibles"


class DashboardHandler(BaseHandler):
    """Page d'accueil du dashboard (``GET /`` ou ``GET /dashboard``).

    Dispatch sur ``current_user.role`` :
    - ``UserRole.ADMIN`` → ``dashboard/admin.html`` (vue globale)
    - ``UserRole.USER`` → ``dashboard/user.html`` (vue personnelle)
    - tout autre rôle → ``HTTPError(403)`` (fail-closed)
    """

    @authenticated
    async def get(self) -> None:
        user: User = self.current_user
        service = get_stats_service()
        if user.role == UserRole.ADMIN:
            await self._render_admin_dashboard(user, service)
        elif user.role == UserRole.USER:
            await self._render_user_dashboard(user, service)
        else:
            # Fail-closed : ne JAMAIS retomber sur la vue user par défaut — cela
            # attribuerait silencieusement des capacités non validées à un futur
            # rôle (READER, VIEWER…) au lieu de forcer une décision explicite.
            logger.warning(
                "Accès dashboard refusé : rôle non supporté %r",
                user.role,
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "user_id": getattr(user, "id", None),
                    "user_role": getattr(user.role, "value", str(user.role)),
                },
            )
            raise HTTPError(403, "Rôle utilisateur non supporté pour cette page")

    async def _safe_subload(
        self,
        coro: Any,
        label: str,
        default: Any,
        timeout: float = _SUBLOAD_TIMEOUT_S,
    ) -> Any:
        """Wrap un sous-load dashboard avec timeout + fallback graceful.

        Backpressure : un seul sous-service lent ne doit JAMAIS retarder le
        rendu de toute la page. Si la coro dépasse ``timeout`` ou lève une
        exception inattendue, on log un warning et on retombe sur ``default``
        (typiquement un dict avec ``_errors`` ou une liste vide).

        ⚠️ Filtres explicites — re-raise AVANT le ``except Exception`` :

        * :class:`asyncio.CancelledError` (Python 3.8+ : ``BaseException`` →
          déjà non-attrapée par ``except Exception``, mais explicite ici pour
          documenter l'intention) — la cancel doit propager pour que la
          coroutine HTTP soit nettoyée si le client disconnect.
        * :class:`tornado.web.HTTPError` — un service qui répond
          ``raise HTTPError(403)`` exprime une **décision métier** (quota
          dépassé, accès refusé, etc.). L'avaler en silence et rendre la
          page avec ``default`` masquerait l'authz au caller. On laisse
          remonter pour que :meth:`BaseHandler.write_error` rende un 403/401
          propre. Cf. review adversariale finding A1.

        Le caller annonce ensuite le label dans le bandeau d'erreur en haut
        du template (cf. ``stats._errors`` fusionné par ``_render_admin_dashboard``).
        """
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(
                "Dashboard sub-load timeout (%ss): %s",
                timeout,
                label,
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            return default
        except (asyncio.CancelledError, HTTPError):
            # Re-raise : décisions métier (HTTPError) et cancellation runtime
            # (CancelledError) doivent propager. Cf. docstring ci-dessus.
            raise
        except Exception:  # noqa: BLE001 — fail-safe absolu (page entière sinon perdue)
            logger.error(
                "Dashboard sub-load erreur: %s",
                label,
                exc_info=True,
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            return default

    async def _render_user_dashboard(self, user: "User", service: DashboardStatsService) -> None:
        """Charge en parallèle les 6 jeux de données user puis rend le template.

        Chaque sous-load est encadré par ``_safe_subload`` (timeout +
        fallback) — une dégradation locale (BDD lente sur les rapports,
        scheduler en cours de redémarrage pour next_automations) ne casse
        pas le rendu global.
        """
        (
            stats,
            recent_searches,
            recent_reports,
            user_automations,
            recent_executions,
            next_automations,
        ) = await asyncio.gather(
            self._safe_subload(
                service.get_user_stats(user.id),
                "stats user",
                default={"_errors": ["stats user (timeout)"]},
            ),
            self._safe_subload(
                service.get_recent_searches(user.id, user=user),
                "recherches récentes",
                default=[],
            ),
            self._safe_subload(service.get_user_reports(user.id), "rapports", default=[]),
            self._safe_subload(service.get_user_automations(user.id), "automations", default=[]),
            self._safe_subload(
                service.get_recent_executions(user_id=user.id),
                "exécutions récentes",
                default=[],
            ),
            self._safe_subload(
                service.get_next_automations(user.id, limit=4),
                "prochaines exécutions",
                default=[],
            ),
        )
        self.render(
            "dashboard/user.html",
            user=user,
            stats=stats,
            recent_searches=recent_searches,
            recent_reports=recent_reports,
            user_automations=user_automations,
            recent_executions=recent_executions,
            next_automations=next_automations,
            show_onboarding=_should_show_onboarding(user),
            page_title="Tableau de bord",
        )

    async def _render_admin_dashboard(self, user: "User", service: DashboardStatsService) -> None:
        """Charge en parallèle les jeux de données admin puis rend le template.

        Les 5 datasets historiques (stats, recherches, top users, erreurs,
        exécutions) sont complétés par 2 datasets de monitoring multi-users
        ajoutés en avril 2026 :

        * ``security_stats`` : sessions actives, logins échoués 24h, quotas
          dépassés, exécutions bloquées + alertes système (chaînes prêtes).
        * ``users_overview`` : tableau de TOUS les users avec leurs métriques
          opérationnelles (recherches 7j, stockage, sessions actives) — permet
          à l'admin de monitorer chaque user sans drilldown manuel.
        """
        from app.constants import DASHBOARD_RECENT_LIMIT, STATS_RECENT_LIMIT

        (
            stats,
            recent_searches,
            top_users,
            recent_errors,
            recent_executions,
            security_stats,
            users_overview,
        ) = await asyncio.gather(
            self._safe_subload(
                service.get_admin_stats(),
                "stats admin",
                default={"_errors": ["stats admin (timeout)"]},
            ),
            self._safe_subload(
                service.get_recent_searches_all(limit=STATS_RECENT_LIMIT),
                "recherches récentes",
                default=[],
            ),
            self._safe_subload(service.get_top_users(), "top users", default=[]),
            self._safe_subload(
                service.get_recent_errors(limit=DASHBOARD_RECENT_LIMIT),
                "erreurs récentes",
                default=[],
            ),
            self._safe_subload(
                service.get_recent_executions(user_id=None, limit=STATS_RECENT_LIMIT),
                "exécutions récentes",
                default=[],
            ),
            self._safe_subload(
                service.get_admin_security_stats(),
                "stats sécurité",
                default={"_errors": ["sécurité (timeout)"], "system_alerts": []},
            ),
            self._safe_subload(
                service.get_admin_users_overview(),
                "monitoring users",
                default={"users": [], "total": 0, "truncated": False, "limit": 0},
            ),
        )

        # Fusionne les ``_errors`` du service security dans ceux des stats
        # globales pour que le bandeau d'erreur jaune en haut du template
        # remonte AUSSI les erreurs du service monitoring -- sans cette
        # ligne, une SQLAlchemyError dans `_count_failed_logins` serait
        # loggee mais l'admin verrait juste "0" sans aucun signal qu'un
        # KPI ment. Les noms des sous-loads en erreur sont prefixes par
        # "securite:" pour la traçabilite cote log + UI.
        security_errors = security_stats.get("_errors") or []
        if security_errors:
            stats.setdefault("_errors", []).extend(f"securite: {e}" for e in security_errors)

        # Idem pour le monitoring users : une SQLAlchemyError dans
        # ``get_users_overview`` renvoie désormais ``_errors`` plutôt qu'un
        # silence — on la remonte au bandeau pour ne pas afficher un tableau
        # vide trompeur (erreur vs réellement aucun utilisateur).
        users_errors = users_overview.get("_errors") or []
        if users_errors:
            stats.setdefault("_errors", []).extend(f"utilisateurs: {e}" for e in users_errors)

        # Bug 2026-05-26 (F2 CRITIQUE) : ``_should_show_admin_onboarding``
        # interroge la BDD pour gérer le cas « user créé avant le déploiement
        # de l'onboarding mais promu admin par la suite » — l'heuristique
        # historique basée uniquement sur ``user.created_at`` ratait ce cas.
        show_onboarding = await _should_show_admin_onboarding(user)
        self.render(
            "dashboard/admin.html",
            user=user,
            stats=stats,
            show_onboarding=show_onboarding,
            recent_searches=recent_searches,
            top_users=top_users,
            recent_errors=recent_errors,
            recent_executions=recent_executions,
            security_stats=security_stats,
            users_overview=users_overview,
            page_title="Dashboard Admin",
        )


class DashboardChartsAPIHandler(BaseHandler):
    """API JSON pour les données des graphiques (``GET /api/dashboard/charts``).

    Contrat de retour (toujours du JSON) :

    .. code-block:: json

        {
            "success": true,
            "charts": {
                "daily_searches": {
                    "labels": ["lun", "mar", "..."],
                    "values": [12, 5, ...],
                    "full_labels": ["lundi 21 avr.", ...]
                },
                "execution_breakdown": {"success": 42, "failed": 3},
                "feedback":  {...},   // admin only
                "overview":  {...}    // admin only
            }
        }

    En erreur : ``{"success": false, "error": <message FR user-friendly>}``
    avec statut HTTP 403 (rôle non supporté) ou 500 (incident technique).
    """

    @authenticated
    async def get(self) -> None:
        user: User = self.current_user
        service = get_stats_service()

        # Trace request_id dans tous les logs pour corréler avec l'access log
        # et permettre à un admin de retrouver l'incident à partir du
        # ``X-Request-ID`` retourné dans la réponse client (cf. BaseHandler.prepare).
        log_extra = {
            "request_id": getattr(self, "request_id", "?"),
            "user_id": getattr(user, "id", None),
            "user_role": getattr(getattr(user, "role", None), "value", str(user.role)),
        }

        try:
            charts_data = await service.build_charts_payload(user)
        except ValueError:
            # Rôle non supporté côté dashboard charts — fail-closed explicite.
            logger.warning(
                "Charts API refusée : rôle non supporté %r",
                user.role,
                extra=log_extra,
            )
            self.write_json(
                {"success": False, "error": "Rôle non autorisé"},
                status=403,
            )
            return
        except SQLAlchemyError:
            logger.error(
                "Erreur SQL chargement charts dashboard",
                exc_info=True,
                extra=log_extra,
            )
            self.write_json(
                {"success": False, "error": _CHARTS_UNAVAILABLE_MESSAGE},
                status=500,
            )
            return
        except Exception:
            # Filet de sécurité : un driver DB qui lève OperationalError bas-niveau,
            # un timeout asyncio, un bug dans build_charts_payload — on renvoie
            # un 500 générique au client plutôt que de laisser Tornado exposer
            # une trace en dev. Le log structuré garde tout le contexte serveur.
            logger.exception(
                "Erreur inattendue chargement charts dashboard",
                extra=log_extra,
            )
            self.write_json(
                {"success": False, "error": _CHARTS_UNAVAILABLE_MESSAGE},
                status=500,
            )
            return

        # Cache privé côté navigateur uniquement (jamais partagé par un proxy).
        # On override le ``Cache-Control: no-store`` par défaut posé par
        # ``SecurityHeadersMiddleware`` et on retire ``Pragma: no-cache`` qui
        # le contredirait — sinon ``Cache-Control: max-age=60`` ET ``Pragma:
        # no-cache`` cohabitent dans la réponse, ambigu pour les proxies HTTP/1.0.
        #
        # ⚠️ ``Vary: Cookie`` (review adversariale finding A2) — sans ce header,
        # le browser keys son cache uniquement par URL. Si user A logout puis
        # user B login dans le même navigateur dans la fenêtre max-age=60, le
        # browser sert à B les charts de A sans nouveau fetch. ``Vary: Cookie``
        # force l'invalidation à chaque changement de cookie de session.
        self.set_header("Cache-Control", _CHARTS_CACHE_CONTROL)
        self.set_header("Vary", "Cookie")
        self.clear_header(_PRAGMA_HEADER_NAME)
        self.write_json({"success": True, "charts": charts_data})



__all__ = [
    "DashboardHandler",
    "DashboardChartsAPIHandler",
]
