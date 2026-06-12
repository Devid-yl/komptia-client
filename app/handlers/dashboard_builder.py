"""Handlers REST pour le Dashboard Builder (style Power BI / Linear).

Architecture
------------
Ce module contient 26 handlers "thin" qui dispatchent vers les services
``DashboardBuilderService``, ``DashboardFilterService``,
``DashboardTemplateService``, ``delivery_service`` et ``widget_planner``.
Les handlers valident la forme des requêtes et formatent les réponses ; toute
la logique métier (ownership, whitelist d'update, validation des modèles)
vit dans la couche service.

Conventions équipe sénior
--------------------------
* **Imports top-level** — plus aucun ``import`` à l'intérieur des méthodes.
  Les services n'importent pas les handlers, donc il n'y a aucun cycle à
  casser. Les imports-en-méthode masquaient la surface de dépendance et
  ralentissaient chaque requête (coût ``importlib`` × N). Voir
  ``GLOBAL_FINDINGS.md`` [DUP] sur le pattern lazy-import mal justifié.
* **Service factories** (``get_dashboard_builder_service`` &co.) — init à la
  demande, swap-ables en test via ``reset_*_services()``. Pas de
  module-singleton figé à l'import, comme ``contacts.py`` peer-session B.
* **Response helpers** — ``_json_error`` / ``_json_success`` / service-500
  centralisent la forme JSON. Shape uniforme : succès =
  ``{"success": true, ...payload}`` ; erreur = ``{"success": false, "error":
  "message FR"}`` + code HTTP sémantique.
* **Rate-limit** — ``RateLimiter`` partagé (``app.utils.rate_limiter``),
  aligné sur ``automations.py`` et ``contacts.py``. Quotas sous forme de
  constantes ``Final[tuple[int, int]]`` typées, re-jouables depuis les tests.
* **Fail-closed** — tout parse d'input (JSON body, JSON query-param,
  ``?filters=``, ``?drill=``) retourne 400 sur erreur plutôt que de
  l'ignorer silencieusement (anti-pattern "silent-truncate / silent-pass"
  signalé en peer-review contacts itér 1).
* **Ownership defense-in-depth** — ``_load_owned_dashboard_or_404_403()``
  factorise la vérification "ce dashboard existe ET appartient au caller"
  utilisée par les handlers de Schedule. Les autres handlers délèguent au
  service (service retourne ``None`` si non-owner = 404) ; le schedule,
  qui écrit dans l'ORM directement, fait le check localement.
* **Sécurité des headers** — ``_sanitize_filename_for_header`` nettoie les
  CR/LF/NUL qui pourraient injecter un header HTTP
  (CWE-93, CVE-2017-9782 style) dans ``Content-Disposition`` avant d'écrire
  un export CSV/Excel.
* **Messages français** — tous les messages visibles par le user sont dans
  :class:`_Msg` (vouvoiement formel, actionnables, pas de stack trace).

Couvre
------
Dashboard CRUD (list/create/get/update/delete/clone), Widgets CRUD +
LLM-planned batch + reorder, Widgets data fetch + export CSV/Excel,
Filtres/Slicers CRUD + reorder + resolve options, Schedule CRUD +
send-now, Templates (built-in + user-saved).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Final

import tornado.web
from sqlalchemy import select as sa_select
from sqlalchemy.exc import SQLAlchemyError

from app.handlers.base import AuthenticatedHandler, require_role
from app.models.dashboard import Dashboard, DashboardSchedule
from app.services.automation.scheduler import get_scheduler
from app.services.dashboard.coherence_checker import check_dashboard_coherence
from app.services.dashboard.dashboard_builder_service import (
    AVAILABLE_METRICS,
    DashboardBuilderService,
)
from app.services.dashboard.filter_service import DashboardFilterService
from app.services.dashboard.template_service import DashboardTemplateService
from app.services.dashboard.widget_planner import (
    WidgetPipelineError,
    plan_widgets_batch,
)
from app.services.dashboard.widget_planner_agent import (
    WidgetPlannerAgentError,
    run_widget_planner_agent,
)
from app.utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


# ── Constantes ────────────────────────────────────────────────────────────

#: Slug de template : a-z, 0-9, tiret. Matche l'allowlist de routes.py.
_TEMPLATE_SLUG_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z0-9-]{1,64}\Z")

#: Taille max d'un ``user_hint`` transmis au pipeline LLM. Au-delà : tronqué.
#: 2000 chars ≈ 500 tokens — largement suffisant pour guider le Composer
#: sans exploser le budget prompt.
_MAX_USER_HINT_LEN: Final[int] = 2000

#: Feature flag — bascule entre l'agent tool-loop (PR 2.4) et le pipeline
#: linéaire 3-shot (Analyst → Composer → Designer) historique.
#:
#: **Activé 2026-05-18** après PR 2.6 (review adversariale finale,
#: 4 HIGH fixés, 224 tests verts). Rollback trivial = remettre ``False``.
#:
#: Le branchement passe par ``_run_widget_planner_with_fallback`` :
#: l'agent en premier (timeout 120s) → en cas d'échec (timeout, erreur,
#: ImportError future-PR), fallback automatique vers ``plan_widgets_batch``
#: (fail-open : on garde la création de widgets même si l'agent down,
#: plutôt que renvoyer 502 à l'utilisateur).
_USE_AGENT_PIPELINE: bool = True

#: Taille max du champ ``message`` d'un ``DashboardSchedule`` (notification
#: email envoyée aux destinataires). Aligné sur le ``validate()`` du modèle ;
#: on REJETTE au-delà plutôt que de tronquer silencieusement (anti-pattern
#: "silent truncate" : le user croit avoir envoyé son texte, on le coupe
#: sans signal — signalé dans peer-review contacts itér 1 sur CSV imports).
_MAX_SCHEDULE_MESSAGE_LEN: Final[int] = 1000

#: Taille max du ``custom_name`` fourni par l'utilisateur lors de la création
#: depuis un template ou la sauvegarde en template.
_MAX_TEMPLATE_NAME_LEN: Final[int] = 200
_MAX_TEMPLATE_DESC_LEN: Final[int] = 1000

#: Bornes de la période (en jours) acceptable pour un override d'export /
#: data-fetch. En-deçà de 1 : rien à rapporter. Au-delà de 365 : on risque
#: un scan BDD complet qui épuise le pool de connexions.
_PERIOD_DAYS_MIN: Final[int] = 1
_PERIOD_DAYS_MAX: Final[int] = 365
_PERIOD_DAYS_DEFAULT: Final[int] = 30

#: Rate-limit pour la création de widgets par l'IA. Chaque appel :
#: (1) exécute du SQL utilisateur sur Sage, (2) profile + obfusque les
#: données, (3) appelle le LLM Composer (payant, ~1500 tokens output),
#: (4) appelle N LLM Designers (1 par widget proposé). Quota agressif.
RATE_LIMIT_LLM_WIDGET_PER_MIN: Final[tuple[int, int]] = (10, 60)
RATE_LIMIT_LLM_WIDGET_PER_HOUR: Final[tuple[int, int]] = (100, 3600)

#: Rate-limit pour l'envoi immédiat d'un dashboard par email (send-now).
#: 20 envois / heure / user, **aligné** sur ``contacts.py::RATE_LIMIT_SEND_EMAIL``
#: (cohérence inter-endpoints anti-drift). Le SMTP de l'organisation est un relais
#: autorisé pour les emails signés ``[Komptia]`` — un user authentifié qui
#: boucle cet endpoint avec ``recipients=[victim@external.com]`` transformerait
#: l'app en spam vector. Quota agressif côté handler ; le SMTP a son propre
#: retry/backoff côté ``SMTPClient``.
RATE_LIMIT_DASHBOARD_SEND: Final[tuple[int, int]] = (20, 3600)

#: Quota anti-emballement (PAS anti-humain) pour ``/api/dashboards/:id/data``
#: (rafraîchissement = N requêtes Sage par appel) et l'export (N requêtes +
#: build fichier). Sans throttle, un client en boucle (bug front, onglet auto-
#: refresh défectueux) ou un insider martèle le serveur Sage PARTAGÉ — axe 20.
#: Les seuils sont volontairement TRÈS larges : aucune interaction humaine
#: (même power-user multi-onglets) n'atteint 600 refresh/min ou 30 exports/min,
#: mais une boucle emballée (1000+/min) est coupée. Aligné sur le pattern
#: ``RATE_LIMIT_DASHBOARD_SEND`` / ``email_history`` (même RateLimiter SSoT).
RATE_LIMIT_DASHBOARD_DATA: Final[tuple[int, int]] = (600, 60)
RATE_LIMIT_DASHBOARD_EXPORT: Final[tuple[int, int]] = (30, 60)

#: Formats d'export autorisés côté handler. Aligné sur ``export_dashboard``
#: du service (validation stricte dans la méthode de routage _export_csv /
#: _export_excel). Pas d'apostrophe / injection / commande shell acceptée.
_ALLOWED_EXPORT_FORMATS: Final[frozenset[str]] = frozenset({"csv", "excel"})

#: Tailles maximales Content-Length pour les endpoints qui prennent du body.
#: Garde-fou DoS avant la désérialisation JSON. Le frontend Power BI envoie
#: rarement plus de 32 KiB (dashboard avec ~50 widgets).
_MAX_BODY_BYTES: Final[int] = 256 * 1024


class _Msg:
    """Messages centralisés (FR, vouvoiement formel, actionnables).

    Centraliser aide (a) l'audit sécurité (zéro drift entre endpoints), (b)
    les tests d'intégration qui peuvent importer ces constantes plutôt que
    les dupliquer en assertion, (c) la future i18n.
    """

    BODY_EMPTY: Final[str] = "Corps de requête vide."
    BODY_TOO_LARGE: Final[str] = "Corps de requête trop volumineux."
    DASHBOARD_NOT_FOUND: Final[str] = "Dashboard introuvable."
    WIDGET_NOT_FOUND: Final[str] = "Widget introuvable."
    FILTER_NOT_FOUND: Final[str] = "Filtre introuvable."
    SCHEDULE_NOT_FOUND: Final[str] = "Planification introuvable."
    TEMPLATE_NOT_FOUND: Final[str] = "Modèle introuvable."
    FORBIDDEN: Final[str] = "Accès non autorisé."
    ACCESS_DENIED: Final[str] = "Accès refusé."
    NAME_REQUIRED: Final[str] = "Le nom est obligatoire."
    SQL_REQUIRED: Final[str] = "La requête SQL est obligatoire."
    INVALID_TEMPLATE_SLUG: Final[str] = "Identifiant de template invalide."
    INVALID_ORDER_LIST: Final[str] = "'order' doit être une liste d'IDs."
    INVALID_WIDGET_IDS: Final[str] = "IDs de widgets invalides."
    INVALID_FILTER_IDS: Final[str] = "IDs de filtres invalides."
    INVALID_EXPORT_FORMAT: Final[str] = "Format invalide. Utilisez 'csv' ou 'excel'."
    INVALID_USER_ID: Final[str] = "user_id (entier) est requis."
    INVALID_FILTERS_JSON: Final[str] = "Paramètre 'filters' : JSON invalide."
    INVALID_DRILL_JSON: Final[str] = "Paramètre 'drill' : JSON invalide."
    MESSAGE_TOO_LONG: Final[str] = f"Le message dépasse {_MAX_SCHEDULE_MESSAGE_LEN} caractères."
    TEMPLATE_NAME_TOO_LONG: Final[str] = (
        f"Le nom du modèle dépasse {_MAX_TEMPLATE_NAME_LEN} caractères."
    )
    AI_NO_WIDGET: Final[str] = "L'IA n'a pas pu composer de widget."
    AI_NO_WIDGET_PERSISTED: Final[str] = "Aucun widget n'a pu être persisté."
    RATE_LIMIT_MINUTE: Final[str] = "Trop de créations IA. Réessayez dans un instant."
    RATE_LIMIT_HOUR: Final[str] = "Quota horaire de créations IA atteint."
    RATE_LIMIT_DASHBOARD_SEND: Final[str] = (
        "Quota d'envois de dashboard atteint. Réessayez plus tard."
    )
    RATE_LIMIT_DASHBOARD_DATA: Final[str] = (
        "Trop de rafraîchissements de données. Patientez un instant."
    )
    RATE_LIMIT_DASHBOARD_EXPORT: Final[str] = (
        "Trop d'exports rapprochés. Patientez un instant avant de réessayer."
    )
    RATE_LIMIT_WORKBOOK_SAVE: Final[str] = "Trop de sauvegardes rapprochées. Patientez un instant."
    WORKBOOK_TOO_LARGE: Final[str] = (
        "Classeur trop volumineux pour être sauvegardé. "
        "Réduisez le nombre de lignes ou contactez votre administrateur."
    )
    TOO_MANY_RECIPIENTS: Final[str] = (
        f"Trop de destinataires (max {DashboardSchedule.MAX_RECIPIENTS})."
    )
    INVALID_RECIPIENTS_TYPE: Final[str] = (
        "Le champ 'recipients' doit être une liste d'adresses email."
    )

    ERROR_FETCH: Final[str] = "Erreur lors de la récupération."
    ERROR_CREATE: Final[str] = "Erreur lors de la création."
    ERROR_UPDATE: Final[str] = "Erreur lors de la mise à jour."
    ERROR_DELETE: Final[str] = "Erreur lors de la suppression."
    ERROR_CLONE: Final[str] = "Erreur lors du clonage."
    ERROR_EXPORT: Final[str] = "Erreur lors de l'export."
    ERROR_SEND: Final[str] = "Erreur lors de l'envoi."
    ERROR_ADD_WIDGET: Final[str] = "Erreur lors de l'ajout du widget."
    ERROR_ADD_WIDGETS: Final[str] = "Erreur lors de l'ajout des widgets."
    ERROR_REORDER: Final[str] = "Erreur lors du réordonnement."
    ERROR_SAVE: Final[str] = "Erreur lors de la sauvegarde."
    ERROR_FILTER_CREATE: Final[str] = "Erreur lors de la création du filtre."


# ── Service factories (anti-singleton) ────────────────────────────────────
#
# Pattern aligné sur ``contacts.py`` (peer-session B). Évite :
#   (a) le module-load qui déclenche un init prématuré ;
#   (b) l'import cycle, car les services n'importent PAS ce module ;
#   (c) l'impossibilité de swap pour les tests (d'où ``reset_*_services``).
#
# On réutilise la même instance de service pour toute la durée du process,
# ce qui est OK car les services de ce module sont stateless (ils lisent
# la session passée en argument, rien de persistant dans ``self``).

_dashboard_builder_service: DashboardBuilderService | None = None
_dashboard_filter_service: DashboardFilterService | None = None
_dashboard_template_service: DashboardTemplateService | None = None


def get_dashboard_builder_service() -> DashboardBuilderService:
    """Retourne l'instance partagée de ``DashboardBuilderService``."""
    global _dashboard_builder_service
    if _dashboard_builder_service is None:
        _dashboard_builder_service = DashboardBuilderService()
    return _dashboard_builder_service


def get_dashboard_filter_service() -> DashboardFilterService:
    """Retourne l'instance partagée de ``DashboardFilterService``."""
    global _dashboard_filter_service
    if _dashboard_filter_service is None:
        _dashboard_filter_service = DashboardFilterService()
    return _dashboard_filter_service


def get_dashboard_template_service() -> DashboardTemplateService:
    """Retourne l'instance partagée de ``DashboardTemplateService``."""
    global _dashboard_template_service
    if _dashboard_template_service is None:
        _dashboard_template_service = DashboardTemplateService()
    return _dashboard_template_service


def reset_dashboard_services() -> None:
    """Vide les singletons — réservé aux tests (isolation entre cas)."""
    global _dashboard_builder_service, _dashboard_filter_service
    global _dashboard_template_service
    _dashboard_builder_service = None
    _dashboard_filter_service = None
    _dashboard_template_service = None


# ── Rate limiters (shared, sliding-window, thread-safe) ───────────────────
#
# Deux instances distinctes pour la fenêtre minute vs heure. Permet de
# surveiller les deux quotas indépendamment et de libérer les timestamps
# de la fenêtre minute plus agressivement (cleanup interne du RateLimiter).
# Chaque instance est thread-safe via un ``threading.Lock`` interne.
_llm_widget_minute_limiter = RateLimiter()
_llm_widget_hour_limiter = RateLimiter()

#: Rate-limiter dédié pour ``DashboardSendNowAPIHandler.post``. Séparé des
#: limiters LLM widget — un user peut consommer son quota d'envois sans
#: bloquer ses créations de widgets et vice-versa. Quota piloté par
#: ``RATE_LIMIT_DASHBOARD_SEND``.
#:
#: ⚠️ **Process-local** : ``RateLimiter`` utilise un ``dict`` + ``threading.Lock``
#: en mémoire. Si Komptia migre vers un déploiement multi-worker (gunicorn,
#: uvicorn ``workers > 1``), le quota effectif devient ``20 × N_workers``,
#: ce qui contourne silencieusement la protection. Aligné sur tout le reste
#: de la codebase (cf. ``contacts.py``, ``automations.py``) — la migration
#: vers Redis ou DB-backed devra être faite GLOBALEMENT, pas ici seulement.
#: Aujourd'hui Komptia tourne en un seul process Tornado, donc OK.
_send_now_limiter = RateLimiter()

#: Limiters dédiés (anti-emballement) pour le rafraîchissement de données et
#: l'export — séparés pour que l'un n'épuise pas le quota de l'autre. Mêmes
#: réserves process-local que ``_send_now_limiter`` (cf. ci-dessus).
_data_refresh_limiter = RateLimiter()
_export_limiter = RateLimiter()

#: Sauvegarde du classeur d'un widget grille (bouton « Enregistrer ») —
#: aligné sur le quota d'upload datastore (20/min) : même nature d'opération
#: (écriture fichier + quota), même protection anti-emballement.
_workbook_save_limiter = RateLimiter()
RATE_LIMIT_WORKBOOK_SAVE: Final[tuple[int, int]] = (20, 60)


# ── Helpers de réponse ────────────────────────────────────────────────────


def _json_error(handler: AuthenticatedHandler, message: str, status: int) -> None:
    """Écrit une réponse JSON d'erreur dans la forme uniforme du projet.

    Forme : ``{"success": false, "error": "<message FR>"}`` + HTTP status
    sémantique. Matche la convention de ``contacts.py`` / ``automations.py``.
    """
    handler.write_json({"success": False, "error": message}, status)


def _json_success(
    handler: AuthenticatedHandler,
    payload: dict[str, Any] | None = None,
    status: int = 200,
) -> None:
    """Écrit une réponse JSON de succès.

    Forme : ``{"success": true, ...payload}`` + HTTP status (typiquement 200
    ou 201). ``payload`` est merge-é dans l'objet racine — les clés déjà
    présentes (``success``) ne sont jamais écrasées par payload par ordre
    d'insertion Python 3.7+ : on assure l'immutabilité du contrat public.
    """
    data: dict[str, Any] = {"success": True}
    if payload:
        # Protège "success" contre un payload mal formé (défensif).
        for key, value in payload.items():
            if key == "success":
                continue
            data[key] = value
    handler.write_json(data, status)


def _log_and_error_500(
    handler: AuthenticatedHandler,
    operation: str,
    client_message: str,
    *,
    context: dict[str, Any] | None = None,
) -> None:
    """Log une erreur technique + renvoie 500 avec message client générique.

    ``operation`` : description courte pour le log serveur ("create
    dashboard", "export dashboard 42"). Jamais exposée au client.
    ``client_message`` : message FR safe pour le user (pas de stack).
    """
    extra = {"operation": operation}
    if context:
        extra.update(context)
    logger.error("Erreur DB : %s", operation, exc_info=True, extra=extra)
    _json_error(handler, client_message, 500)


def _require_body(handler: AuthenticatedHandler) -> dict[str, Any] | None:
    """Valide qu'un body JSON est présent + non-vide + objet.

    Retourne le dict parsé ou ``None`` si la réponse 400 a été émise (le
    caller doit alors ``return``). ``get_json_body`` lève déjà HTTPError(400)
    sur JSON invalide / non-dict — on complète ici pour le cas "body vide"
    (Content-Length: 0 → dict vide après parse : on rejette explicitement).
    """
    content_length_raw = handler.request.headers.get("Content-Length")
    if content_length_raw:
        try:
            if int(content_length_raw) > _MAX_BODY_BYTES:
                _json_error(handler, _Msg.BODY_TOO_LARGE, 413)
                return None
        except ValueError:
            # Header malformé : on laisse le parse standard échouer.
            pass

    body = handler.get_json_body()
    if not body:
        _json_error(handler, _Msg.BODY_EMPTY, 400)
        return None
    return body


def _optional_body(handler: AuthenticatedHandler) -> dict[str, Any]:
    """Retourne le body JSON ou ``{}`` si absent/mal formé.

    Usage : endpoints où le body est optionnel (ex. create-from-template).
    ``get_json_body`` lève 400 sur JSON invalide ; on catche ici pour
    retomber sur dict vide — comportement explicite, aligné avec l'ancien
    ``try/except: body = {}``.
    """
    if not handler.request.body:
        return {}
    try:
        return handler.get_json_body()
    except tornado.web.HTTPError:
        return {}


def _parse_bounded_int(
    raw: str | None,
    minimum: int,
    maximum: int,
    default: int | None = None,
) -> int | None:
    """Parse un entier borné ``[minimum, maximum]``. ``None`` si invalide/absent.

    Si ``default`` est fourni, un raw invalide retombe sur ``default`` plutôt
    que sur ``None``. Utilisé pour ``?period=`` (fallback sur défaut) et
    pour ``body.period_days`` (fallback explicite).
    """
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (ValueError, TypeError):
        return default
    return min(max(value, minimum), maximum)


def _parse_json_dict_or_400(
    handler: AuthenticatedHandler,
    raw: str | None,
    field_name: str,
    error_message: str,
) -> tuple[dict[str, Any] | None, bool]:
    """Parse un paramètre JSON optionnel et retourne ``(value, ok)``.

    Comportement (vs l'ancien silent ``pass`` qui masquait les bugs côté UI) :

    * ``raw`` vide/absent → ``(None, True)`` (OK, filtre non fourni).
    * JSON invalide → émet 400 et retourne ``(None, False)`` — le caller
      doit ``return``.
    * JSON valide mais pas un dict → émet 400 (cohérent : on attend un objet).
    * JSON valide dict → ``(dict, True)``.

    Retourner 400 plutôt que d'ignorer évite le scénario où le user croit
    que son filtre est appliqué alors qu'il a été drop silencieusement
    (bug invisible, debug impossible).
    """
    if not raw:
        return None, True
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        _json_error(handler, error_message, 400)
        return None, False
    if not isinstance(parsed, dict):
        _json_error(handler, error_message, 400)
        return None, False
    return parsed, True


def _parse_int_list_or_400(
    handler: AuthenticatedHandler,
    raw: object,
    error_message: str,
) -> list[int] | None:
    """Cast une liste mixte (JSON array) en ``list[int]`` ou émet 400.

    ``raw`` typiquement ``body.get("order", [])``. Accepte strings
    numériques (``["1", "2"]``) et entiers. Rejette tout autre type.
    Retourne ``None`` si la réponse 400 a été émise (caller doit ``return``).
    """
    if not isinstance(raw, list):
        _json_error(handler, _Msg.INVALID_ORDER_LIST, 400)
        return None
    try:
        return [int(item) for item in raw]
    except (ValueError, TypeError):
        _json_error(handler, error_message, 400)
        return None


#: Regex : tout caractère de contrôle (C0, DEL, C1) qui pourrait casser un
#: header HTTP. CR/LF (``\r\n``) permettent l'injection de header séparé
#: (CWE-93, "HTTP Response Splitting"). NUL, BS, FF idem. On remplace par
#: underscore pour préserver une filename lisible.
_UNSAFE_FILENAME_CHARS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f-\x9f\"\\]")


def _sanitize_filename_for_header(filename: str, fallback: str = "export") -> str:
    """Nettoie un filename avant insertion dans ``Content-Disposition``.

    Protection contre :
    - **CRLF injection** (``filename*=UTF-8''foo\\r\\nX-Injected: yes`` →
      Tornado ``set_header`` ne filtre PAS, contrairement à stdlib
      ``http.client`` qui valide).
    - **Ctrl chars** qui cassent les parseurs Content-Disposition de
      certains navigateurs / proxies (bug → downgrade inline).
    - **Double-quote / backslash** non-escapé dans l'attribut RFC 2183.

    RFC 5987 (``filename*=UTF-8''<percent-encoded>``) exige que tout caractère
    hors ``attr-char`` soit pct-encoded. On préfère ici un nettoyage aval
    (replace par ``_``) car les filenames viennent du service et contiennent
    en général des noms de dashboards saisis par l'utilisateur — l'intention
    est de préserver une filename lisible, pas de la pct-encoder 100%.

    Le caller reste responsable du pct-encoding RFC 5987 pour le ``filename*``
    (accents, espaces) — on ne l'applique pas ici pour ne pas doubler
    l'encodage.
    """
    if not filename:
        return fallback
    cleaned = _UNSAFE_FILENAME_CHARS.sub("_", filename)
    return cleaned or fallback


async def _run_widget_planner_with_fallback(
    *,
    sql: str,
    user_hint: str | None,
    dashboard_id: int,
    user_id: int,
    user: Any = None,
):
    """Route le run vers l'agent tool-loop ou le pipeline 3-shot.

    Source de vérité du choix : :data:`_USE_AGENT_PIPELINE`. Si actif et
    l'agent échoue (provider down, timeout, etc.), on retombe automatiquement
    sur ``plan_widgets_batch`` (fail-open : un user n'a pas à savoir si
    l'agent est dispo ou pas).

    Si :data:`_USE_AGENT_PIPELINE` est ``False``, ce helper est strictement
    équivalent à ``plan_widgets_batch`` direct — overhead 1 if.

    Raises:
        WidgetPipelineError: les deux chemins ont échoué OU le pipeline
            3-shot a échoué (seul chemin). Le handler le map en 502.
    """
    if _USE_AGENT_PIPELINE:
        # Timeout total du run agent (fix HIGH #L1 review adversariale
        # finale 2026-05-18) : sans cela, MAX_TOOL_CALLS=40 × LLM lent
        # (Sonnet ~10-30s/turn avec thinking) = jusqu'à 20 minutes par
        # requête bloquant un worker Tornado. Browser timeout user
        # mais worker continue à brûler tokens.
        # 120s = compromis : 4-6 widgets composés avec exploration
        # confortable, mais cap dur pour éviter denial-of-wallet.
        import asyncio as _asyncio

        try:
            return await _asyncio.wait_for(
                run_widget_planner_agent(
                    sql,
                    user_hint=user_hint,
                    dashboard_id=dashboard_id,
                    user_id=user_id,
                    user=user,
                    # run_id vide pour l'instant : la todo-list LLM n'est
                    # pas encore exposée côté frontend /dashboards/.
                    run_id="",
                ),
                timeout=120.0,
            )
        except _asyncio.TimeoutError:
            logger.warning("widget_planner_agent timeout (>120s) — fallback plan_widgets_batch")
            # Tombe vers le pipeline 3-shot ci-dessous.
        except WidgetPlannerAgentError as exc:
            logger.warning(
                "widget_planner_agent échoué (%s) — fallback plan_widgets_batch",
                exc,
            )
            # Tombe vers le pipeline 3-shot ci-dessous.
        except Exception as exc:  # noqa: BLE001
            # Defense-in-depth fix MEDIUM #3 review adversariale 2026-05-18 :
            # un ImportError (refactor PR future qui casse un import inline
            # dans agent.py) sortirait du except WidgetPlannerAgentError →
            # 500 brut, pas fallback batch → contrat fail-open cassé.
            # On capture tout autre Exception, on logue distinct (pour
            # remonter la régression au monitoring), et on fallback batch.
            logger.exception(
                "widget_planner_agent exception inattendue — fallback batch (%s)",
                type(exc).__name__,
            )
            # Tombe vers le pipeline 3-shot ci-dessous.

        # Fix S3 review globale 2026-05-18 : on consomme un 2e ticket
        # rate-limit AVANT le fallback batch. Cohérent avec le coût LLM
        # réel : agent a déjà brûlé des tokens (peut-être beaucoup), si
        # on enchaîne batch = encore tokens. Sinon 1 attacker authentifié
        # peut multiplier par 2 sa conso LLM en spammant des SQL qui font
        # timeout l'agent → fallback batch.
        # Si le 2e check refuse, on raise WidgetPipelineError (mappée 502
        # par le handler) plutôt que silence : l'user voit le rate-limit.
        allowed_fallback, fallback_msg, _ = _check_llm_widget_rate(user_id)
        if not allowed_fallback:
            logger.warning(
                "widget_planner_agent fallback batch refusé par rate-limit "
                "(user=%s) — agent a déjà consommé un ticket, fallback exigerait un 2e.",
                user_id,
            )
            raise WidgetPipelineError(fallback_msg or "Quota dépassé après échec de l'agent IA.")

    return await plan_widgets_batch(sql, user_hint=user_hint, user_id=user_id, user=user)


def _check_llm_widget_rate(user_id: int) -> tuple[bool, str | None, int | None]:
    """Vérifie le rate-limit pour la création de widgets par l'IA.

    Retourne ``(allowed, error_message, retry_after_s)``. Sur refus,
    ``retry_after_s`` est une approximation (fenêtre du limiter atteinte)
    pour alimenter le header ``Retry-After``.
    """
    key = f"user:{user_id}"

    per_min_max, per_min_window = RATE_LIMIT_LLM_WIDGET_PER_MIN
    if not _llm_widget_minute_limiter.check(
        key, max_requests=per_min_max, window_seconds=per_min_window
    ):
        return False, _Msg.RATE_LIMIT_MINUTE, per_min_window

    per_hour_max, per_hour_window = RATE_LIMIT_LLM_WIDGET_PER_HOUR
    if not _llm_widget_hour_limiter.check(
        key, max_requests=per_hour_max, window_seconds=per_hour_window
    ):
        return False, _Msg.RATE_LIMIT_HOUR, per_hour_window

    return True, None, None


def reset_llm_widget_rate_limiter() -> None:
    """Réinitialise les limiters — réservé aux tests."""
    _llm_widget_minute_limiter.cleanup(max_age_seconds=0)
    _llm_widget_hour_limiter.cleanup(max_age_seconds=0)


def reset_dashboard_send_rate_limiter() -> None:
    """Réinitialise le limiter send-now — réservé aux tests (isolation entre cas)."""
    _send_now_limiter.cleanup(max_age_seconds=0)


async def _load_owned_dashboard_or_response(
    handler: AuthenticatedHandler,
    session: Any,
    dashboard_id: int,
) -> Dashboard | None:
    """Charge le dashboard si le caller en est propriétaire, sinon répond.

    Defense-in-depth pour les handlers Schedule qui écrivent directement
    dans l'ORM (hors ``DashboardBuilderService``). Retourne le
    ``Dashboard`` si accès OK, sinon émet la réponse 404 et retourne
    ``None`` (le caller doit ``return``).

    Fail-closed uniforme avec le reste du module : ne distingue pas un
    dashboard absent d'un dashboard d'un autre user dans la **réponse
    HTTP** — sinon un attaquant pourrait énumérer les IDs en observant
    404 vs 403 (oracle d'existence cross-user, contraire à la promesse
    strict-owner depuis tâche #29).

    **Audit log IDOR (task #104)** : côté serveur, on distingue les deux
    cas pour le SIEM/SOC. Un ``logger.warning`` est émis **uniquement**
    quand le dashboard existe ET appartient à un autre user — c'est un
    signal d'attaque fort (l'ID est valide ET un autre user le possède).
    On ne logge PAS sur "dashboard absent" pour éviter la pollution du
    journal sur scan naturel (404 dans le flow normal d'un user qui
    arrive sur un dashboard supprimé).
    """
    # Capture une fois — ``require_role`` garantit ``current_user`` non-None,
    # mais on capture localement pour (a) la lisibilité, (b) éviter une
    # double-lecture d'un proxy potentiel, (c) un log cohérent même si
    # un futur hook async mute ``handler.request`` pendant le helper.
    attacker_id = handler.current_user.id
    request_path = handler.request.path
    request_method = handler.request.method

    dashboard = await session.get(Dashboard, dashboard_id)
    if dashboard is not None and dashboard.user_id != attacker_id:
        logger.warning(
            "IDOR attempt on dashboard endpoint",
            extra={
                "user_id": attacker_id,
                "target_dashboard_id": dashboard_id,
                "actual_owner_id": dashboard.user_id,
                "endpoint": request_path,
                "method": request_method,
            },
        )
    if not dashboard or dashboard.user_id != attacker_id:
        _json_error(handler, _Msg.DASHBOARD_NOT_FOUND, 404)
        return None
    return dashboard


# ─────────────────────────────────────────────────────────────────────────
# Pages HTML
# ─────────────────────────────────────────────────────────────────────────


#: Préférence (``UserPreference.key``) mémorisant le dernier dashboard
#: CONSULTÉ — l'entrée ``GET /dashboards`` y retourne en priorité au
#: rechargement de la page. L'ancien comportement (« le plus récemment
#: modifié ») reste le fallback si la préférence est absente, corrompue ou
#: pointe un dashboard supprimé.
_LAST_DASHBOARD_PREF_KEY: Final[str] = "last_dashboard_id"


def _pick_landing_dashboard(pref_value: Any, dashboards: list) -> int | None:
    """Choisit le dashboard d'atterrissage depuis la préférence utilisateur.

    Retourne l'id si la préférence est un entier valide ET présent dans
    ``dashboards`` (liste owner-only — la vérification d'appartenance est
    fail-closed contre une valeur périmée/forgée). Sinon ``None`` → le
    caller retombe sur le comportement historique (plus récemment modifié).
    """
    try:
        wanted = int(str(pref_value))
    except (TypeError, ValueError):
        return None
    for d in dashboards or []:
        if isinstance(d, dict) and d.get("id") == wanted:
            return wanted
    return None


async def _get_last_dashboard_pref(session: Any, user_id: int) -> str | None:
    """Lit la valeur brute de la préférence (``None`` si absente)."""
    from app.models.user_preference import UserPreference

    result = await session.execute(
        sa_select(UserPreference).where(
            UserPreference.user_id == user_id,
            UserPreference.key == _LAST_DASHBOARD_PREF_KEY,
        )
    )
    pref = result.scalar_one_or_none()
    return pref.value if pref is not None else None


async def _remember_last_dashboard(session: Any, user_id: int, dashboard_id: int) -> None:
    """Upsert de la préférence (même pattern que ``data_read_consent``).

    Commit laissé au caller (``db_session`` committe à la sortie). No-op si
    la valeur est déjà à jour — pas d'UPDATE parasite à chaque F5 sur le
    même dashboard.
    """
    from app.models.user_preference import UserPreference

    value = str(int(dashboard_id))
    result = await session.execute(
        sa_select(UserPreference).where(
            UserPreference.user_id == user_id,
            UserPreference.key == _LAST_DASHBOARD_PREF_KEY,
        )
    )
    pref = result.scalar_one_or_none()
    if pref is None:
        session.add(
            UserPreference(
                user_id=user_id,
                key=_LAST_DASHBOARD_PREF_KEY,
                value=value,
                category="preference",
            )
        )
    elif pref.value != value:
        pref.value = value


class DashboardBuilderPageHandler(AuthenticatedHandler):
    """Entrée ``GET /dashboards`` : redirige vers le dernier dashboard
    CONSULTÉ par l'utilisateur (préférence persistée serveur — survit au
    rechargement, au changement de navigateur et de poste). Fallback : le
    plus récemment modifié. Si aucun n'existe, en crée un vide pour
    atterrir directement sur ses widgets (plutôt qu'une liste intermédiaire).
    """

    @require_role("admin", "user")
    async def get(self) -> None:
        service = get_dashboard_builder_service()
        async with self.db_session() as session:
            # ``list_dashboards`` est strict owner-only depuis tâche #29 :
            # tous les dashboards retournés appartiennent au user courant.
            # Trié par ``updated_at`` desc → index 0 = le plus récemment édité.
            dashboards = await service.list_dashboards(
                session, self.current_user.id, user=self.current_user
            )

            if dashboards:
                pref_value = await _get_last_dashboard_pref(session, self.current_user.id)
                picked = _pick_landing_dashboard(pref_value, dashboards)
                # ``is not None`` (pas ``or``) : ne jamais confondre un id
                # falsy avec « préférence absente ».
                target_id = picked if picked is not None else dashboards[0]["id"]
            else:
                created = await service.create_dashboard(
                    session,
                    self.current_user.id,
                    name="Mon tableau de bord",
                    description="",
                )
                target_id = created["id"]

        self.redirect(f"/dashboards/{target_id}")


class DashboardBuilderViewHandler(AuthenticatedHandler):
    """Vue d'un dashboard spécifique avec ses widgets et filtres."""

    @require_role("admin", "user")
    async def get(self, dashboard_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        service = get_dashboard_builder_service()

        async with self.db_session() as session:
            dashboard = await service.get_dashboard(
                session, did, self.current_user.id, user=self.current_user
            )
            # Liste complète pour alimenter le switcher en header (même
            # session pour éviter un round-trip supplémentaire).
            all_dashboards = await service.list_dashboards(
                session, self.current_user.id, user=self.current_user
            )

        if not dashboard:
            raise tornado.web.HTTPError(404, _Msg.DASHBOARD_NOT_FOUND)

        # Mémorise le dernier dashboard CONSULTÉ (≠ modifié) — l'entrée
        # /dashboards y retournera au prochain chargement. Session séparée
        # et best-effort : un échec d'écriture (BDD locked → 504 du context
        # manager) ne doit JAMAIS empêcher l'affichage de la page. Posé
        # APRÈS le check 404 : une URL invalide ne doit pas être mémorisée.
        try:
            async with self.db_session() as pref_session:
                await _remember_last_dashboard(pref_session, self.current_user.id, did)
        except Exception:  # noqa: BLE001 — préférence non critique
            logger.warning(
                "Mémorisation du dernier dashboard échouée (non bloquant)", exc_info=True
            )

        self.render(
            "dashboard/builder_view.html",
            dashboard=dashboard,
            all_dashboards=all_dashboards,
            available_metrics=AVAILABLE_METRICS,
        )


# ─────────────────────────────────────────────────────────────────────────
# API REST — Dashboards
# ─────────────────────────────────────────────────────────────────────────


class DashboardAPIHandler(AuthenticatedHandler):
    """CRUD racine des dashboards : GET (list), POST (create)."""

    @require_role("admin", "user")
    async def get(self) -> None:
        service = get_dashboard_builder_service()
        try:
            async with self.db_session() as session:
                dashboards = await service.list_dashboards(
                    session, self.current_user.id, user=self.current_user
                )
            _json_success(self, {"dashboards": dashboards})
        except SQLAlchemyError:
            _log_and_error_500(self, "list dashboards", _Msg.ERROR_FETCH)

    @require_role("admin", "user")
    async def post(self) -> None:
        body = _require_body(self)
        if body is None:
            return

        name = str(body.get("name", "")).strip()
        description = str(body.get("description", "")).strip()

        if not name:
            _json_error(self, _Msg.NAME_REQUIRED, 400)
            return

        service = get_dashboard_builder_service()
        try:
            async with self.db_session() as session:
                dashboard = await service.create_dashboard(
                    session, self.current_user.id, name, description
                )
            _json_success(self, {"dashboard": dashboard}, status=201)
        except ValueError as exc:
            _json_error(self, str(exc), 400)
        except SQLAlchemyError:
            _log_and_error_500(self, "create dashboard", _Msg.ERROR_CREATE)


class DashboardDetailAPIHandler(AuthenticatedHandler):
    """GET / PUT / DELETE d'un dashboard spécifique."""

    @require_role("admin", "user")
    async def get(self, dashboard_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        service = get_dashboard_builder_service()

        try:
            async with self.db_session() as session:
                dashboard = await service.get_dashboard(
                    session, did, self.current_user.id, user=self.current_user
                )
            if not dashboard:
                _json_error(self, _Msg.DASHBOARD_NOT_FOUND, 404)
                return
            _json_success(self, {"dashboard": dashboard})
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"get dashboard {did}",
                _Msg.ERROR_FETCH,
                context={"dashboard_id": did},
            )

    @require_role("admin", "user")
    async def put(self, dashboard_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        body = _require_body(self)
        if body is None:
            return

        service = get_dashboard_builder_service()
        try:
            async with self.db_session() as session:
                # ``update_dashboard`` applique un whitelist interne
                # ``{name, description}`` — protection mass-assignment. Le
                # body brut peut donc être transmis tel quel.
                result = await service.update_dashboard(session, did, self.current_user.id, body)
            if not result:
                _json_error(self, _Msg.DASHBOARD_NOT_FOUND, 404)
                return
            _json_success(self, {"dashboard": result})
        except ValueError as exc:
            _json_error(self, str(exc), 400)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"update dashboard {did}",
                _Msg.ERROR_UPDATE,
                context={"dashboard_id": did},
            )

    @require_role("admin", "user")
    async def delete(self, dashboard_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        service = get_dashboard_builder_service()

        try:
            async with self.db_session() as session:
                deleted = await service.delete_dashboard(session, did, self.current_user.id)
            if not deleted:
                _json_error(self, _Msg.DASHBOARD_NOT_FOUND, 404)
                return
            _json_success(self)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"delete dashboard {did}",
                _Msg.ERROR_DELETE,
                context={"dashboard_id": did},
            )


class DashboardCloneAPIHandler(AuthenticatedHandler):
    """POST ``/api/dashboards/:id/clone`` — clone complet."""

    @require_role("admin", "user")
    async def post(self, dashboard_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        service = get_dashboard_builder_service()

        try:
            async with self.db_session() as session:
                clone = await service.clone_dashboard(session, did, self.current_user.id)
            if not clone:
                _json_error(self, _Msg.DASHBOARD_NOT_FOUND, 404)
                return
            _json_success(self, {"dashboard": clone}, status=201)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"clone dashboard {did}",
                _Msg.ERROR_CLONE,
                context={"dashboard_id": did},
            )


# ─────────────────────────────────────────────────────────────────────────
# API REST — Widgets
# ─────────────────────────────────────────────────────────────────────────


class DashboardWidgetAPIHandler(AuthenticatedHandler):
    """POST ``/api/dashboards/:id/widgets`` — ajouter un widget manuellement."""

    @require_role("admin", "user")
    async def post(self, dashboard_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        body = _require_body(self)
        if body is None:
            return

        service = get_dashboard_builder_service()
        try:
            async with self.db_session() as session:
                widget = await service.add_widget(session, did, self.current_user.id, body)
            if not widget:
                _json_error(self, _Msg.DASHBOARD_NOT_FOUND, 404)
                return
            _json_success(self, {"widget": widget}, status=201)
        except ValueError as exc:
            _json_error(self, str(exc), 400)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"add widget on dashboard {did}",
                _Msg.ERROR_ADD_WIDGET,
                context={"dashboard_id": did},
            )


class DashboardWidgetLLMAPIHandler(AuthenticatedHandler):
    """POST ``/api/dashboards/:id/widgets/llm`` — crée 1..N widgets via pipeline IA.

    Pipeline (``widget_planner.plan_widgets_batch``) :

    1. Exécute le SQL utilisateur (``0 ligne`` → erreur).
    2. Profile programmatique + obfuscation Niveau 2 (voir CLAUDE.md).
    3. LLM Composer : propose 1-6 widgets spécialisés (KPI, chart, trend, table).
    4. Pour chaque proposal : applique la recette en Python sur les VRAIES
       data, puis LLM Designer (titre, sous-titre, format, unit, insight),
       puis restore les tokens anonymisés.
    5. Persiste les N widgets en série (ordre = ordre Composer).

    Réponse : ``{success, widgets:[…], count:N}``. Si une proposal échoue,
    elle est droppée mais le batch continue — **fail-open partiel** pour
    maximiser l'UX (pattern delibéré après review : cf. Phase 5 notes).
    """

    @require_role("admin", "user")
    async def post(self, dashboard_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        body = _require_body(self)
        if body is None:
            return

        sql = str(body.get("sql") or "").strip()
        if not sql:
            _json_error(self, _Msg.SQL_REQUIRED, 400)
            return

        # Rate-limit AVANT tout IO : le pipeline fait 1 exec SQL (coûteux)
        # + 1 Composer + N Designers (payants). On protège aussi bien la
        # BDD Sage que le crédit API LLM.
        allowed, rate_msg, retry_after = _check_llm_widget_rate(self.current_user.id)
        if not allowed:
            if retry_after:
                self.set_header("Retry-After", str(retry_after))
            _json_error(self, rate_msg or _Msg.RATE_LIMIT_MINUTE, 429)
            return

        raw_hint = body.get("user_hint")
        user_hint: str | None = None
        if isinstance(raw_hint, str):
            stripped = raw_hint.strip()[:_MAX_USER_HINT_LEN]
            user_hint = stripped or None

        try:
            # Branche entre l'agent tool-loop (PR 2.4) et le pipeline
            # 3-shot historique selon ``_USE_AGENT_PIPELINE``. En cas
            # d'échec de l'agent, fallback transparent vers le pipeline
            # historique (fail-open : on garde la création de widgets
            # même si l'agent est down, plutôt que 502 utilisateur).
            plans = await _run_widget_planner_with_fallback(
                sql=sql,
                user_hint=user_hint,
                dashboard_id=did,
                user_id=self.current_user.id,
                user=self.current_user,
            )
        except WidgetPipelineError as exc:
            _json_error(self, str(exc), 502)
            return

        if not plans:
            _json_error(self, _Msg.AI_NO_WIDGET, 502)
            return

        service = get_dashboard_builder_service()
        created: list[dict[str, Any]] = []
        try:
            async with self.db_session() as session:
                # Fix LOG2 review globale 2026-05-18 : pré-calcul des
                # position_order côté handler pour réduire la fenêtre de
                # race "2 widgets avec même position_order". Sans ça,
                # ``add_widget`` calculait COUNT(*) + 1 pour chaque widget
                # entre 2 commits — fenêtre 6× plus large que pipeline 3-shot
                # quand l'agent crée 6 widgets en série. Ici on calcule UNE
                # fois MAX(position_order) puis on attribue séquentiellement
                # (resté non-atomique vs autres requêtes, mais batch interne
                # garanti monotone).
                from sqlalchemy import func, select

                from app.models.dashboard import DashboardWidget

                max_order_stmt = select(func.max(DashboardWidget.position_order)).where(
                    DashboardWidget.dashboard_id == did
                )
                max_order_result = await session.execute(max_order_stmt)
                base_order = (max_order_result.scalar() or -1) + 1

                for idx, plan in enumerate(plans):
                    spec = plan.render_spec
                    data_source_config: dict[str, Any] = {
                        "query": sql,
                        "transformation": plan.transformation,
                        "render_spec": spec.to_dict(),
                    }
                    if plan.drill_column:
                        data_source_config["drill_column"] = plan.drill_column

                    widget_data = {
                        "title": spec.title,
                        "widget_type": spec.widget_type,
                        "chart_type": spec.chart_type,
                        "data_source_type": "sql",
                        "data_source_config": data_source_config,
                        "col_span": spec.col_span,
                        # Pré-calcul de position_order (idx séquentiel à
                        # partir du max). add_widget honore cette valeur
                        # s'il est fournie (cf. service.add_widget:336).
                        "position_order": base_order + idx,
                    }
                    try:
                        widget = await service.add_widget(
                            session, did, self.current_user.id, widget_data
                        )
                    except ValueError as validation_error:
                        logger.info(
                            "Widget IA droppé (validation) — intent=%s, err=%s",
                            plan.intent,
                            validation_error,
                        )
                        continue
                    if widget:
                        created.append(widget)

            if not created:
                _json_error(self, _Msg.AI_NO_WIDGET_PERSISTED, 400)
                return

            _json_success(
                self,
                {"widgets": created, "count": len(created)},
                status=201,
            )
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"add widget batch LLM on dashboard {did}",
                _Msg.ERROR_ADD_WIDGETS,
                context={"dashboard_id": did},
            )


class DashboardWidgetDetailAPIHandler(AuthenticatedHandler):
    """PUT / DELETE d'un widget spécifique."""

    @require_role("admin", "user")
    async def put(self, dashboard_id: str, widget_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        wid = self._parse_int_or_400(widget_id, "widget_id")
        body = _require_body(self)
        if body is None:
            return

        service = get_dashboard_builder_service()
        try:
            async with self.db_session() as session:
                widget = await service.update_widget(session, wid, did, self.current_user.id, body)
            if not widget:
                _json_error(self, _Msg.WIDGET_NOT_FOUND, 404)
                return
            _json_success(self, {"widget": widget})
        except ValueError as exc:
            _json_error(self, str(exc), 400)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"update widget {wid}",
                _Msg.ERROR_UPDATE,
                context={"widget_id": wid, "dashboard_id": did},
            )

    @require_role("admin", "user")
    async def delete(self, dashboard_id: str, widget_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        wid = self._parse_int_or_400(widget_id, "widget_id")
        service = get_dashboard_builder_service()

        try:
            async with self.db_session() as session:
                deleted = await service.delete_widget(session, wid, did, self.current_user.id)
            if not deleted:
                _json_error(self, _Msg.WIDGET_NOT_FOUND, 404)
                return
            _json_success(self)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"delete widget {wid}",
                _Msg.ERROR_DELETE,
                context={"widget_id": wid, "dashboard_id": did},
            )


class DashboardWidgetExtraTabsAPIHandler(AuthenticatedHandler):
    """PUT — remplace les feuilles SQL d'un widget grille.

    Deux contrats (read-modify-write côté serveur dans les deux cas — jamais la
    config complète depuis le client → pas de clobber par une copie périmée) :

    - **``{"sheets": [{"query"}, {"label","query"}, ...]}``** (« piloté par les
      feuilles ») : liste ORDONNÉE unique. Feuille 0 = principale → ``query`` ;
      reste → ``extra_tabs``. → ``set_widget_sheets``.
    - **``{"extra_tabs": [{"label","query"}, ...]}``** (legacy) : uniquement les
      onglets additionnels (la requête principale reste inchangée). →
      ``set_widget_extra_tabs``.

    Owner-only (enforcé dans le service via join Dashboard).
    """

    @require_role("admin", "user")
    async def put(self, dashboard_id: str, widget_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        wid = self._parse_int_or_400(widget_id, "widget_id")
        body = _require_body(self)
        if body is None:
            return

        service = get_dashboard_builder_service()
        try:
            async with self.db_session() as session:
                if "sheets" in body:
                    # Contrat « piloté par les feuilles » : feuille 0 = principale
                    # (→ query), feuilles 1..n → extra_tabs.
                    widget = await service.set_widget_sheets(
                        session, wid, did, self.current_user.id, body.get("sheets")
                    )
                else:
                    # Legacy : uniquement les onglets additionnels.
                    widget = await service.set_widget_extra_tabs(
                        session, wid, did, self.current_user.id, body.get("extra_tabs")
                    )
            if not widget:
                _json_error(self, _Msg.WIDGET_NOT_FOUND, 404)
                return
            _json_success(self, {"widget": widget})
        except ValueError as exc:
            _json_error(self, str(exc), 400)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"set widget extra_tabs {wid}",
                _Msg.ERROR_UPDATE,
                context={"widget_id": wid, "dashboard_id": did},
            )


class DashboardWidgetWorkbookAPIHandler(AuthenticatedHandler):
    """PUT ``/api/dashboards/:id/widgets/:wid/workbook`` — sauvegarde MANUELLE
    du classeur d'un widget grille (bouton « Enregistrer » du widget).

    Body : classeur Komptia complet (``GridTabManager.serialize()``), JSON
    brut ou gzippé (magic bytes ``0x1f 0x8b`` — même contrat que l'upload
    datastore). Header ``If-Match`` optionnel (hash du fichier connu côté
    client) → 412 si le classeur a été modifié dans un autre onglet.

    Réponses : 200 ``{success, widget, workbook_hash}`` ; 400 validation ;
    404 widget introuvable/non-propriétaire ; 412 conflit ; 413 quota ou
    payload trop gros ; 429 rate-limit.
    """

    @require_role("admin", "user")
    async def put(self, dashboard_id: str, widget_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        wid = self._parse_int_or_400(widget_id, "widget_id")

        save_max, save_window = RATE_LIMIT_WORKBOOK_SAVE
        if not _workbook_save_limiter.check(
            f"user:{self.current_user.id}",
            max_requests=save_max,
            window_seconds=save_window,
        ):
            self.set_header("Retry-After", str(save_window))
            _json_error(self, _Msg.RATE_LIMIT_WORKBOOK_SAVE, 429)
            return

        raw = self.request.body or b""
        if not raw:
            _json_error(self, _Msg.BODY_EMPTY, 400)
            return
        # Cap de taille (octets COMPRESSÉS reçus) = cap admin d'upload
        # datastore — même source de vérité, même nature d'opération. Le cap
        # de DÉCOMPRESSION (anti zip-bomb) est appliqué plus bas par
        # ``decode_afz_bytes`` (quota stockage admin).
        from app.services.ai.config_service import get_max_upload_size_bytes

        max_bytes = await get_max_upload_size_bytes()
        if isinstance(max_bytes, int) and max_bytes > 0 and len(raw) > max_bytes:
            _json_error(self, _Msg.WORKBOOK_TOO_LARGE, 413)
            return

        expected_hash = self.request.headers.get("If-Match", "").strip().strip('"') or None

        from app.services.dashboard.widget_workbook_store import (
            WorkbookConflictError,
            WorkbookQuotaError,
        )

        service = get_dashboard_builder_service()
        try:
            async with self.db_session() as session:
                result = await service.save_widget_workbook(
                    session,
                    wid,
                    did,
                    self.current_user.id,
                    raw,
                    expected_hash=expected_hash,
                )
            if not result:
                _json_error(self, _Msg.WIDGET_NOT_FOUND, 404)
                return
            _json_success(
                self,
                {"widget": result["widget"], "workbook_hash": result["workbook_hash"]},
            )
        except WorkbookConflictError as exc:
            self.write_json(
                {"success": False, "error": str(exc), "error_code": "ETAG_MISMATCH"}, 412
            )
        except WorkbookQuotaError as exc:
            self.write_json(
                {"success": False, "error": str(exc), "error_code": "QUOTA_EXCEEDED"}, 413
            )
        except ValueError as exc:
            _json_error(self, str(exc), 400)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"save widget workbook {wid}",
                _Msg.ERROR_SAVE,
                context={"widget_id": wid, "dashboard_id": did},
            )


class DashboardWidgetReorderAPIHandler(AuthenticatedHandler):
    """POST ``/api/dashboards/:id/widgets/reorder`` — réordonner les widgets."""

    @require_role("admin", "user")
    async def post(self, dashboard_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        body = _require_body(self)
        if body is None:
            return

        widget_order = _parse_int_list_or_400(self, body.get("order", []), _Msg.INVALID_WIDGET_IDS)
        if widget_order is None:
            return

        service = get_dashboard_builder_service()
        try:
            async with self.db_session() as session:
                success = await service.reorder_widgets(
                    session, did, self.current_user.id, widget_order
                )
            if not success:
                _json_error(self, _Msg.DASHBOARD_NOT_FOUND, 404)
                return
            _json_success(self)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"reorder widgets on dashboard {did}",
                _Msg.ERROR_REORDER,
                context={"dashboard_id": did},
            )


class DashboardDataAPIHandler(AuthenticatedHandler):
    """GET ``/api/dashboards/:id/data`` — données de tous les widgets.

    Query params :
    - ``?period=<int>`` : override de la période (1..365 jours).
    - ``?filters=<json>`` : objet JSON des valeurs de slicers (ex.
      ``{"region": "IDF"}``).
    - ``?drill=<json>`` : filtres drill-down d'un clic sur chart (ex.
      ``{"ville": "Paris"}``).

    Les deux JSON-params renvoient 400 s'ils sont fournis mal formés plutôt
    que d'être ignorés silencieusement — un filtre drop invisible masque
    des bugs (user croit appliquer, ne s'applique pas).
    """

    @require_role("admin", "user")
    async def get(self, dashboard_id: str) -> None:
        # Anti-emballement AVANT tout travail : chaque appel déclenche N
        # requêtes Sage (un widget = une requête). Seuil large (cf.
        # RATE_LIMIT_DASHBOARD_DATA) → ne gêne aucun humain, coupe une boucle.
        # Throttle en PREMIER (≠ send-now qui valide le body d'abord) : ici les
        # params GET sont triviaux et il n'y a pas de body à valider, donc rien
        # à protéger contre la consommation de quota par payload malformé.
        data_max, data_window = RATE_LIMIT_DASHBOARD_DATA
        if not _data_refresh_limiter.check(
            f"user:{self.current_user.id}",
            max_requests=data_max,
            window_seconds=data_window,
        ):
            self.set_header("Retry-After", str(data_window))
            _json_error(self, _Msg.RATE_LIMIT_DASHBOARD_DATA, 429)
            return

        did = self._parse_int_or_400(dashboard_id, "dashboard_id")

        period_override = _parse_bounded_int(
            self.get_argument("period", None), _PERIOD_DAYS_MIN, _PERIOD_DAYS_MAX
        )

        filter_state, ok = _parse_json_dict_or_400(
            self, self.get_argument("filters", None), "filters", _Msg.INVALID_FILTERS_JSON
        )
        if not ok:
            return

        drill_filters, ok = _parse_json_dict_or_400(
            self, self.get_argument("drill", None), "drill", _Msg.INVALID_DRILL_JSON
        )
        if not ok:
            return

        # ``?refresh=1`` → bypass du cache de résultats (bouton « rafraîchir »).
        # Toute autre valeur / absence → cache normal. Lecture tolérante.
        refresh_arg = (self.get_argument("refresh", "") or "").strip().lower()
        force_refresh = refresh_arg in ("1", "true", "yes")

        service = get_dashboard_builder_service()
        try:
            async with self.db_session() as session:
                data = await service.get_all_widget_data(
                    session,
                    did,
                    self.current_user.id,
                    period_override=period_override,
                    filter_state=filter_state,
                    drill_filters=drill_filters,
                    user=self.current_user,
                    force_refresh=force_refresh,
                )
            # JSON ne supporte pas les clés int : on cast en str côté handler.
            # Le client JS reconvertit en number pour lookup via widget.id.
            str_data = {str(k): v for k, v in data.items()}
            _json_success(self, {"data": str_data})
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"get dashboard data {did}",
                _Msg.ERROR_FETCH,
                context={"dashboard_id": did},
            )


class DashboardCoherenceAPIHandler(AuthenticatedHandler):
    """GET ``/api/dashboards/:id/coherence`` — diagnostics de cohérence (T17).

    Renvoie un rapport :class:`CoherenceReport` listant les incohérences
    détectées entre les widgets : périodes filtrées différemment, entités
    filtrées sur des valeurs différentes, agrégats reproduisant un même
    ``SUM(col)`` sur des scopes incompatibles, périodes de métriques
    divergentes, widgets dont le SQL ne parse pas.

    Le rapport est purement informatif — le frontend peut l'afficher sous
    forme de bannière au-dessus du dashboard sans bloquer son rendu. Aucun
    write : ce handler ne mute jamais l'état du dashboard.

    Owner-only. Ne distingue pas "introuvable" et "non-owner" pour ne pas
    leaker l'existence cross-user (fail-closed uniforme avec le reste du
    module — cf. ``_load_owned_dashboard_or_response``).
    """

    @require_role("admin", "user")
    async def get(self, dashboard_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        service = get_dashboard_builder_service()

        try:
            async with self.db_session() as session:
                dashboard = await service.get_dashboard(
                    session, did, self.current_user.id, user=self.current_user
                )
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"get dashboard coherence {did}",
                _Msg.ERROR_FETCH,
                context={"dashboard_id": did},
            )
            return

        if not dashboard:
            _json_error(self, _Msg.DASHBOARD_NOT_FOUND, 404)
            return

        widgets = dashboard.get("widgets") or []
        report = check_dashboard_coherence(widgets)
        _json_success(self, {"report": report.to_dict()})


class DashboardMetricsAPIHandler(AuthenticatedHandler):
    """GET ``/api/dashboards/metrics`` — liste des métriques prédéfinies."""

    @require_role("admin", "user")
    async def get(self) -> None:
        service = get_dashboard_builder_service()
        _json_success(self, {"metrics": service.get_available_metrics()})


# ─────────────────────────────────────────────────────────────────────────
# API REST — Filtres / Slicers (style Power BI)
# ─────────────────────────────────────────────────────────────────────────


class DashboardFilterAPIHandler(AuthenticatedHandler):
    """GET (list) / POST (create) des filtres d'un dashboard."""

    @require_role("admin", "user")
    async def get(self, dashboard_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        service = get_dashboard_filter_service()

        try:
            async with self.db_session() as session:
                filters = await service.list_filters(session, did, self.current_user.id)
            if filters is None:
                _json_error(self, _Msg.DASHBOARD_NOT_FOUND, 404)
                return
            _json_success(self, {"filters": filters})
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"list filters {did}",
                _Msg.ERROR_FETCH,
                context={"dashboard_id": did},
            )

    @require_role("admin", "user")
    async def post(self, dashboard_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        body = _require_body(self)
        if body is None:
            return

        service = get_dashboard_filter_service()
        try:
            async with self.db_session() as session:
                result = await service.create_filter(session, did, self.current_user.id, body)
            if result is None:
                _json_error(self, _Msg.DASHBOARD_NOT_FOUND, 404)
                return
            _json_success(self, {"filter": result}, status=201)
        except ValueError as exc:
            _json_error(self, str(exc), 400)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"create filter on dashboard {did}",
                _Msg.ERROR_FILTER_CREATE,
                context={"dashboard_id": did},
            )


class DashboardFilterDetailAPIHandler(AuthenticatedHandler):
    """PUT / DELETE d'un filtre spécifique."""

    @require_role("admin", "user")
    async def put(self, dashboard_id: str, filter_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        fid = self._parse_int_or_400(filter_id, "filter_id")
        body = _require_body(self)
        if body is None:
            return

        service = get_dashboard_filter_service()
        try:
            async with self.db_session() as session:
                result = await service.update_filter(session, fid, did, self.current_user.id, body)
            if not result:
                _json_error(self, _Msg.FILTER_NOT_FOUND, 404)
                return
            _json_success(self, {"filter": result})
        except ValueError as exc:
            _json_error(self, str(exc), 400)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"update filter {fid}",
                _Msg.ERROR_UPDATE,
                context={"filter_id": fid, "dashboard_id": did},
            )

    @require_role("admin", "user")
    async def delete(self, dashboard_id: str, filter_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        fid = self._parse_int_or_400(filter_id, "filter_id")
        service = get_dashboard_filter_service()

        try:
            async with self.db_session() as session:
                deleted = await service.delete_filter(session, fid, did, self.current_user.id)
            if not deleted:
                _json_error(self, _Msg.FILTER_NOT_FOUND, 404)
                return
            _json_success(self)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"delete filter {fid}",
                _Msg.ERROR_DELETE,
                context={"filter_id": fid, "dashboard_id": did},
            )


class DashboardFilterOptionsAPIHandler(AuthenticatedHandler):
    """GET ``/api/dashboards/:id/filters/options`` — filtres + options résolues."""

    @require_role("admin", "user")
    async def get(self, dashboard_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        service = get_dashboard_filter_service()

        try:
            async with self.db_session() as session:
                filters = await service.get_filters_with_options(
                    session, did, self.current_user.id, user=self.current_user
                )
            if filters is None:
                _json_error(self, _Msg.DASHBOARD_NOT_FOUND, 404)
                return
            _json_success(self, {"filters": filters})
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"filter options {did}",
                _Msg.ERROR_FETCH,
                context={"dashboard_id": did},
            )


class DashboardFilterReorderAPIHandler(AuthenticatedHandler):
    """POST ``/api/dashboards/:id/filters/reorder`` — réordonner les filtres."""

    @require_role("admin", "user")
    async def post(self, dashboard_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")
        body = _require_body(self)
        if body is None:
            return

        filter_order = _parse_int_list_or_400(self, body.get("order", []), _Msg.INVALID_FILTER_IDS)
        if filter_order is None:
            return

        service = get_dashboard_filter_service()
        try:
            async with self.db_session() as session:
                success = await service.reorder_filters(
                    session, did, self.current_user.id, filter_order
                )
            if not success:
                _json_error(self, _Msg.DASHBOARD_NOT_FOUND, 404)
                return
            _json_success(self)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"reorder filters on dashboard {did}",
                _Msg.ERROR_REORDER,
                context={"dashboard_id": did},
            )


# ─────────────────────────────────────────────────────────────────────────
# API REST — Schedule & envoi immédiat
# ─────────────────────────────────────────────────────────────────────────


class DashboardTemplatesAPIHandler(AuthenticatedHandler):
    """GET ``/api/dashboards/templates`` — liste des templates."""

    @require_role("admin", "user")
    async def get(self) -> None:
        service = get_dashboard_template_service()
        templates = service.list_templates()
        _json_success(self, {"templates": templates})


class DashboardTemplateCreateAPIHandler(AuthenticatedHandler):
    """POST ``/api/dashboards/templates/:slug/create`` — créer depuis un template."""

    @require_role("admin", "user")
    async def post(self, slug: str) -> None:
        if not slug or not _TEMPLATE_SLUG_RE.match(slug):
            _json_error(self, _Msg.INVALID_TEMPLATE_SLUG, 400)
            return

        body = _optional_body(self)
        custom_name = str(body.get("name", "")).strip() if isinstance(body, dict) else ""
        if len(custom_name) > _MAX_TEMPLATE_NAME_LEN:
            _json_error(self, _Msg.TEMPLATE_NAME_TOO_LONG, 400)
            return

        service = get_dashboard_template_service()
        try:
            async with self.db_session() as session:
                result = await service.create_from_template(
                    session, self.current_user.id, slug, custom_name
                )
            if result is None:
                _json_error(self, _Msg.TEMPLATE_NOT_FOUND, 404)
                return
            _json_success(self, {"dashboard": result}, status=201)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"create from template {slug}",
                _Msg.ERROR_CREATE,
                context={"template_slug": slug},
            )


class DashboardSaveAsTemplateAPIHandler(AuthenticatedHandler):
    """POST ``/api/dashboards/:id/save-as-template`` — sauvegarder comme template."""

    @require_role("admin", "user")
    async def post(self, dashboard_id: str) -> None:
        did = self._parse_int_or_400(dashboard_id, "dashboard_id")

        body = _optional_body(self)
        template_name = str(body.get("name", "")).strip()
        template_description = str(body.get("description", "")).strip()

        if len(template_name) > _MAX_TEMPLATE_NAME_LEN:
            _json_error(self, _Msg.TEMPLATE_NAME_TOO_LONG, 400)
            return
        if len(template_description) > _MAX_TEMPLATE_DESC_LEN:
            _json_error(
                self,
                f"La description dépasse {_MAX_TEMPLATE_DESC_LEN} caractères.",
                400,
            )
            return

        service = get_dashboard_template_service()
        try:
            async with self.db_session() as session:
                result = await service.save_as_template(
                    session,
                    did,
                    self.current_user.id,
                    template_name,
                    template_description,
                )
            if result is None:
                _json_error(self, _Msg.DASHBOARD_NOT_FOUND, 404)
                return
            _json_success(self, {"template": result}, status=201)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"save as template dashboard {did}",
                _Msg.ERROR_SAVE,
                context={"dashboard_id": did},
            )


class DashboardUserTemplateCreateAPIHandler(AuthenticatedHandler):
    """POST ``/api/dashboards/user-templates/:id/create`` — créer depuis user template."""

    @require_role("admin", "user")
    async def post(self, template_id: str) -> None:
        tid = self._parse_int_or_400(template_id, "template_id")

        body = _optional_body(self)
        custom_name = str(body.get("name", "")).strip()
        if len(custom_name) > _MAX_TEMPLATE_NAME_LEN:
            _json_error(self, _Msg.TEMPLATE_NAME_TOO_LONG, 400)
            return

        service = get_dashboard_template_service()
        try:
            async with self.db_session() as session:
                result = await service.create_from_user_template(
                    session, tid, self.current_user.id, custom_name
                )
            if result is None:
                _json_error(self, _Msg.TEMPLATE_NOT_FOUND, 404)
                return
            _json_success(self, {"dashboard": result}, status=201)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"create from user template {tid}",
                _Msg.ERROR_CREATE,
                context={"template_id": tid},
            )


class DashboardUserTemplateDeleteAPIHandler(AuthenticatedHandler):
    """DELETE ``/api/dashboards/user-templates/:id`` — supprimer un user template."""

    @require_role("admin", "user")
    async def delete(self, template_id: str) -> None:
        tid = self._parse_int_or_400(template_id, "template_id")

        service = get_dashboard_template_service()
        try:
            async with self.db_session() as session:
                deleted = await service.delete_user_template(session, tid, self.current_user.id)
            if not deleted:
                _json_error(self, _Msg.TEMPLATE_NOT_FOUND, 404)
                return
            _json_success(self)
        except SQLAlchemyError:
            _log_and_error_500(
                self,
                f"delete user template {tid}",
                _Msg.ERROR_DELETE,
                context={"template_id": tid},
            )

