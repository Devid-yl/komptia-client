"""Handlers de base Tornado (auth, sessions, JSON, erreurs).

Sommaire
--------
* :class:`BaseHandler` — infrastructure commune : ``prepare`` charge
  ``current_user``, fail-safe, request-id tracé dans les logs, headers de
  sécurité, helpers JSON / DB, ``write_error`` unifié.
* :class:`AuthenticatedHandler` — idem + redirect login si anonyme.
* :func:`authenticated`, :func:`admin_required`, :func:`require_role` —
  décorateurs d'autorisation fail-closed.

Règles de sécurité appliquées (OWASP ASVS 4.0 + Top 10 2025 + Tornado docs)
---------------------------------------------------------------------------
1. **Request-ID sain** — ``X-Request-ID`` reçu en entrée est filtré par un
   allowlist strict (``^[A-Za-z0-9._-]{1,64}$``) avant d'être logué ou
   renvoyé : prévient l'injection CRLF/log (CWE-117) et la pollution de
   traces par un attaquant (long IDs, caractères de contrôle).
2. **Prepare fail-safe** — si la résolution de ``current_user`` explose (BDD
   locked, session corrompue, token invalide), on log en ``warning`` et on
   tombe sur ``current_user = None`` — **jamais** de 500 sur la requête.
3. **Messages d'erreur déterministes** — ``write_error`` ne renvoie JAMAIS
   ``str(exception)`` au client (sauf en mode debug) ; les messages publics
   sont des constantes FR centralisées dans :class:`_Messages`.
4. **Content-negotiation robuste** — réponse JSON vs HTML décidée par le
   path ``/api/``, le header ``X-Requested-With``, **et** l'``Accept`` qui
   privilégie ``application/json``. Un client qui demande JSON reçoit JSON,
   même sur une URL hors ``/api/``.
5. **Décorateurs fail-closed + eager** — ``require_role`` résout ses
   ``UserRole`` une fois à l'import (lève ``ValueError`` si un rôle n'existe
   pas) ; aucune conversion per-request, aucune autorisation ouverte par
   défaut sur rôle inconnu.
6. **Timeouts configurables** — ``slow_request_threshold_s`` et
   ``db_session_timeout_s`` sont des champs de :class:`ServerConfig` —
   plus de magic number.

Conventions d'écriture
----------------------
* ``from __future__ import annotations`` — cohérence typing avec le reste.
* Imports top-level uniquement — plus aucun ``import`` à l'intérieur d'une
  fonction (évite les coûts répétés et rend les dépendances auditables par
  les outils statiques).
* Tous les messages utilisateur sont en français via :class:`_Messages`.
"""

from __future__ import annotations

import asyncio
import functools
import json
import re
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Awaitable, Callable, Final

import tornado.web
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import config
from app.core.database import get_session_factory
from app.middleware.security import SecurityHeadersMiddleware
from app.models.user import User, UserRole
from app.services.auth.session_manager import get_session_manager
from app.services.diagnostics import get_error_watchdog
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ── Constantes ────────────────────────────────────────────────────────────

#: Nom du cookie de session. Unique source de vérité pour tous les handlers
#: (login, logout, iris, settings, base). Éviter la dérive "sessiontoken" vs
#: "session_token" — ce constant est ré-exporté par :mod:`app.handlers.auth`.
SESSION_COOKIE_NAME: Final[str] = "session_token"

#: Taille max d'un ``X-Request-ID`` accepté en entrée (au-delà : ignoré et
#: remplacé par un UUID frais). 64 caractères suffisent pour un UUID hex +
#: marge ; plus long = suspect.
_MAX_REQUEST_ID_LEN: Final[int] = 64

#: Allowlist strict pour ``X-Request-ID``. Seuls alphanum + ``.``, ``_``,
#: ``-`` sont autorisés — bloque les injections CRLF (CWE-93) et les
#: caractères de contrôle qui pourraient casser un parseur de logs.
_REQUEST_ID_PATTERN: Final[re.Pattern[str]] = re.compile(
    rf"\A[A-Za-z0-9._-]{{1,{_MAX_REQUEST_ID_LEN}}}\Z"
)

#: Longueur du UUID hex raccourci généré quand aucun ``X-Request-ID`` valide
#: n'est fourni. 12 car hex = ~48 bits d'entropie, largement suffisant pour
#: corréler sur une fenêtre d'une journée sans polluer les logs.
_REQUEST_ID_LENGTH: Final[int] = 12

#: Valeur retournée par ``_load_theme_mode_preference_safe`` quand l'appel
#: est SKIPPÉ pour un endpoint JSON/API (cf. ADV-S1). On ne tape pas la
#: BDD inutilement ; la valeur n'est de toute façon jamais lue par les
#: handlers JSON. Aligné sur ``_DEFAULT_THEME_MODE`` côté settings (mais
#: sans dépendance d'import circulaire au moment de prepare()).
_DEFAULT_THEME_MODE_FALLBACK: Final[str] = "system"

#: URIs des endpoints SSE long-lived dont le slow-query warning de
#: ``on_finish`` doit être ignoré (la durée mesurée correspond au lifetime
#: du tab client, pas au travail serveur). Match par préfixe pour absorber
#: les éventuels paramètres de query string. Coupler avec le check
#: ``Content-Type: text/event-stream`` côté response (double-règle
#: défensive : ni l'un ni l'autre ne suffit seul).
#:
#: Étendre cette liste explicitement à l'ajout d'un nouvel endpoint SSE.
#: Cf. ``app/handlers/system_events.py`` — implémentation actuelle.
_SSE_URI_ALLOWLIST: Final[tuple[str, ...]] = ("/api/system/events",)


class _Messages:
    """Messages d'erreur client centralisés (français, ton cohérent avec l'UI).

    Garder ces constantes en un seul endroit facilite :

    * l'audit sécurité (pas de drift entre handlers),
    * la future internationalisation,
    * les tests d'intégration qui peuvent importer ces messages plutôt que
      les hardcoder dans les assertions.
    """

    AUTHENTICATION_REQUIRED: Final[str] = "Authentification requise."
    ADMIN_REQUIRED: Final[str] = "Accès réservé aux administrateurs."
    INSUFFICIENT_PERMISSIONS: Final[str] = "Permissions insuffisantes pour cette action."
    INVALID_JSON_BODY: Final[str] = "Le corps de la requête doit être du JSON valide."
    INVALID_PARAMETER: Final[str] = "Paramètre invalide."
    DB_TIMEOUT: Final[str] = "La base de données a mis trop de temps à répondre."
    INTERNAL_ERROR: Final[str] = "Une erreur interne est survenue."
    NOT_FOUND: Final[str] = "Ressource non trouvée."
    FORBIDDEN: Final[str] = "Accès refusé."


# ── Helpers purs (pas de `self`) ──────────────────────────────────────────


def _sanitize_request_id(raw: str | None) -> str:
    """Retourne un request-id sain.

    Règles :

    * ``None`` ou vide → UUID frais (12 car hex).
    * Respecte le pattern allowlist → retourné tel quel.
    * Sinon (trop long, contient ``\\r`` / ``\\n`` / non-ASCII) → UUID frais.

    Cette fonction est pure : pas de log, pas de side-effect. Les handlers
    appellent ``logger.debug`` pour tracer un rejet éventuel.
    """
    if raw and _REQUEST_ID_PATTERN.match(raw):
        return raw
    return uuid.uuid4().hex[:_REQUEST_ID_LENGTH]


def _wants_json(handler: tornado.web.RequestHandler) -> bool:
    """Indique si le client attend une réponse JSON.

    Trois signaux cumulatifs (n'importe lequel suffit) :

    1. Path ``/api/`` (convention Komptia) ;
    2. Le handler est AJAX (``X-Requested-With: XMLHttpRequest``) —
       on lit via ``handler.is_ajax`` pour respecter une éventuelle
       surcharge du sous-classe ;
    3. Header ``Accept`` liste ``application/json`` avant ``text/html``.

    Le troisième signal rend le handler robuste aux appels API hors ``/api/``
    (ex. webhook, intégration tierce) — principe de moindre surprise.
    """
    request = handler.request
    if request.uri and request.uri.startswith("/api/"):
        return True
    if getattr(handler, "is_ajax", False):
        return True

    accept = request.headers.get("Accept", "")
    if not accept:
        return False

    # Parsing Accept minimaliste : on cherche si application/json apparaît
    # avant text/html. ``parse_header`` est overkill ici ; split suffit.
    types = [t.strip().split(";", 1)[0].strip() for t in accept.split(",")]
    for media in types:
        if media == "application/json":
            return True
        if media == "text/html":
            return False
    return False


# ── BaseHandler ───────────────────────────────────────────────────────────


class BaseHandler(tornado.web.RequestHandler):
    # Defaults class-level : Tornado peut appeler ``write_error`` (et donc
    # ``render('error.html')``) AVANT que ``prepare()`` n'ait posé les
    # attributs d'instance — typiquement sur un échec ``check_xsrf_cookie``
    # qui survient AVANT prepare. Ces defaults garantissent que les
    # templates trouvent toujours des valeurs valides.

    #: Nonce CSP — attribut posé par ``SecurityHeadersMiddleware.apply_security_headers``
    #: dans ``prepare``. Vide si prepare() n'a pas tourné — le template
    #: ``error.html`` rend alors un ``<script nonce="">`` qui sera bloqué
    #: par CSP, ce qui est ACCEPTABLE pour une page d'erreur (le bootstrap
    #: thème est non-critique sur la page d'erreur).
    csp_nonce: str = ""

    #: Préférence de thème — aligné sur ``_DEFAULT_THEME_MODE`` côté
    #: settings (``"system"`` = suit prefers-color-scheme).
    theme_mode_preference: str = "system"

    """Handler de base avec fonctionnalités communes.

    Tous les handlers de l'app héritent (directement ou via
    :class:`AuthenticatedHandler`) de cette classe.

    Attributs injectés dans ``prepare`` :

    * ``self.request_id`` (str) — toujours défini, même si ``prepare`` échoue
      partiellement. Utilisé dans tous les logs pour corréler.
    * ``self.current_user`` (User | None) — résolu via
      :class:`SessionManager`. ``None`` si anonyme OU si résolution échoue
      (fail-safe, log warning).
    """

    # ── Cycle de vie Tornado ──────────────────────────────────────────────

    async def prepare(self) -> None:
        """Appelé avant chaque requête.

        Garanties (même en cas d'exception interne) :

        * ``self.request_id`` est défini ;
        * Les headers de sécurité sont posés ;
        * ``self.current_user`` est défini (``None`` si résolution échoue).

        Si une sous-classe overload ``prepare``, elle doit commencer par
        ``await super().prepare()``.
        """
        raw_id = self.request.headers.get("X-Request-ID")
        self.request_id = _sanitize_request_id(raw_id)
        self.set_header("X-Request-ID", self.request_id)

        SecurityHeadersMiddleware.apply_security_headers(self)

        logger.debug(
            "%s %s",
            self.request.method,
            self.request.uri,
            extra={
                "request_id": self.request_id,
                "method": self.request.method,
                "uri": self.request.uri,
                "ip": self.request.remote_ip,
                "user_agent": self.request.headers.get("User-Agent", ""),
            },
        )

        self.current_user = await self._load_current_user_safe()

        # Anti-fuite cross-user (review loop F4) : une fois l'utilisateur
        # résolu, toute page authentifiée par-user est marquée no-store +
        # Vary:Cookie. Les routes /api/* et /admin* le sont déjà par CHEMIN
        # via ``apply_security_headers`` ci-dessus ; ce hook couvre en plus
        # les pages HTML hors /admin (/dashboard, /contacts, /reports,
        # /iris, /settings...) de façon générique (aucune liste à maintenir).
        # Un handler qui cache volontairement réécrit Cache-Control dans son
        # get() (après prepare) et l'emporte.
        SecurityHeadersMiddleware.apply_authenticated_cache_control(self)

        # Propage request_id + user_id via contextvars pour que les
        # services puissent les inclure automatiquement dans leurs logs
        # via ``current_log_extra()`` — pas besoin de plumber le param
        # à travers toutes les signatures.
        # Catch RESTREINT (ImportError + AttributeError) pour ne PAS
        # masquer un bug runtime. Si un dev casse ``request_context.py``,
        # on logue à ERROR pour voir le problème, on ne crash PAS la requête.
        try:
            from app.utils.request_context import set_request_context

            set_request_context(
                request_id=self.request_id,
                user_id=self.current_user.id if self.current_user else None,
            )
        except (ImportError, AttributeError) as exc:
            logger.error(
                "Failed to set request_context — logs will miss request_id",
                exc_info=exc,
                extra={"request_id": self.request_id},
            )

        # Précharge la préférence de thème pour les pages HTML — injectée
        # dans ``base.html`` via Jinja pour que le bootstrap script applique
        # la bonne classe AVANT le rendu CSS (évite le FOUC).
        # Sans ça, après un ``clear localStorage`` (navigation data), toutes
        # les pages fallback sur ``prefers-color-scheme`` (= dark si l'OS
        # est en dark), alors que l'user a peut-être configuré ``light`` en
        # BDD. Seule /settings récupérait la préf (via un fetch async), les
        # autres pages restaient en dark avec une radio "light" cochée.
        self.theme_mode_preference = await self._load_theme_mode_preference_safe()

        # Force l'émission du cookie ``_xsrf`` sur chaque requête. Tornado le
        # génère paresseusement — seulement si ``self.xsrf_token`` est touché
        # par un handler ou un template. Les pages HTML qui ne touchent ni
        # l'un ni l'autre (ex: ``/datastore``) n'émettent jamais le cookie
        # côté navigateur, donc ``getCookie('_xsrf')`` renvoie vide côté JS
        # et les POST protégés par XSRF repartent en 403. Une ligne qui
        # garantit que toute requête qui passe par ``BaseHandler`` dépose le
        # cookie — le coût est négligeable (le token est mis en cache pour
        # la requête en cours par Tornado).
        _ = self.xsrf_token

        # Tracking d'activité utilisateur (T3.1) — alimente ``UserActivitySummary``
        # qui sert aux triggers comportementaux (T3.2) et au dashboard
        # onboarding-metrics (T3.3). Best-effort fail-soft : un échec ne
        # doit JAMAIS casser la requête métier (ex : si la BDD est
        # momentanément locked, l'user n'attend pas son rendu pour une
        # télémétrie). Cf. ``app/services/onboarding/activity_tracker.py``.
        #
        # Throttle in-memory check-and-set EN PREMIER : si le user a déjà
        # été flushé dans les 60 dernières secondes, on saute l'ouverture
        # de session BDD (économise une connexion + une transaction pour
        # rien). À 100 req/s pour 10 users actifs : ~0.17 session/s pour
        # le tracking au lieu de 100.
        #
        # **Fire-and-forget** (fix 2026-05-22 — incident /stats à 31 s) :
        # le UPSERT BDD est lancé en background via
        # :func:`activity_tracker.spawn_upsert_last_seen` au lieu d'être
        # awaité ici. Sans ça, quand la BDD SQLite est lockée par un
        # autre writer (improve-pseudo, AIPerformanceLog),
        # ``db_session()`` attend ``busy_timeout=30s`` + le commit, ce
        # qui ajoute 30 s à la latence de CHAQUE requête authentifiée
        # pendant la contention. Cohérent avec le point 2 du module
        # ``activity_tracker`` : « best-effort, ne casse jamais la
        # requête principale ».
        #
        # Le helper :func:`spawn_upsert_last_seen` gère TOUT le
        # pattern : check throttle SANS set, création de la task avec
        # référence forte (anti-GC Python 3.12+), nom debug, et set du
        # throttle UNIQUEMENT après commit réussi. Le caller n'a qu'à
        # appeler le helper.
        if self.current_user is not None:
            try:
                from app.services.onboarding.activity_tracker import (
                    spawn_upsert_last_seen,
                )

                spawn_upsert_last_seen(self.current_user.id)
            except Exception:  # noqa: BLE001 — fail-soft volontaire
                logger.debug(
                    "activity tracker non-planifié pour user_id=%s — requête non impactée",
                    self.current_user.id,
                    exc_info=True,
                )

    def set_cookie(  # type: ignore[override]
        self,
        name: str,
        value: str,
        domain: str | None = None,
        expires: Any = None,
        path: str = "/",
        expires_days: float | None = None,
        **kwargs: Any,
    ) -> None:
        """Override Tornado pour durcir les flags du cookie ``_xsrf``.

        Par défaut Tornado pose le cookie XSRF via :meth:`xsrf_token`
        sans ``samesite`` ni ``secure``. Résultat curl :
        ``Set-Cookie: _xsrf=...; Path=/`` — vulnérable aux attaques
        cross-site et au transit HTTP en clair.

        On intercepte **toute** émission de cookie passant par Tornado
        (la property ``xsrf_cookie_kwargs`` testée précédemment n'est PAS
        lue par les versions actuelles de Tornado — le fallback set_cookie
        est la voie supportée par tous les overrides documentés). Pour le
        cookie ``_xsrf`` spécifiquement, on injecte :

        * ``samesite=Lax`` — bloque l'envoi cross-site (CSRF mitigation).
        * ``secure`` en production — pas de transit HTTP en clair.
        * **PAS** ``httponly`` — design double-submit cookie : le JS doit
          lire le cookie pour le poser en header ``X-Xsrftoken``.

        Pour les autres cookies (session_token via set_secure_cookie,
        cookies métier), le caller a déjà la maîtrise des flags ; on ne
        touche que ``_xsrf`` pour éviter d'écraser une décision explicite.
        """
        if name == "_xsrf":
            kwargs.setdefault("samesite", "Lax")
            if "secure" not in kwargs:
                kwargs["secure"] = config.is_production()
        super().set_cookie(
            name=name,
            value=value,
            domain=domain,
            expires=expires,
            path=path,
            expires_days=expires_days,
            **kwargs,
        )

    def on_finish(self) -> None:
        """Appelé après chaque requête — log si requête lente, reset contexte.

        Skip explicitement les endpoints **streaming/SSE long-lived** : leur
        durée de vie correspond à la session client, pas à un travail serveur,
        donc le seuil "requête lente" est un faux positif systématique
        (cf. ``/api/system/events`` qui flag à chaque déconnexion EventSource,
        bruit massif dans les logs sans valeur de monitoring).

        La détection se fait sur le ``Content-Type`` réponse (``text/event-stream``)
        — plus robuste qu'un allowlist d'URI hardcodé qui se déphase au
        prochain endpoint SSE ajouté.
        """
        request_time = self.request.request_time()
        threshold = config.server.slow_request_threshold_s
        # Filtrer les SSE : leur ``Content-Type`` est posé par le handler
        # avant le 1ᵉ flush. ``self._headers`` est l'API publique Tornado
        # pour lire les réponses sortantes (cf. RequestHandler.set_header).
        # Triple défense : (1) ``except`` pour le cas où ``_headers`` lève
        # (mock incomplet, etc.), (2) ``isinstance(str)`` pour ne pas
        # accepter un MagicMock truthy, (3) ``startswith`` pour absorber
        # le suffixe ``; charset=utf-8`` que Tornado peut ajouter.
        # **ET** match d'un préfixe d'URI connu : sans cette double-condition
        # un handler arbitraire qui set ``text/event-stream`` (par erreur ou
        # malice) silencerait son propre slow-warning. La double-règle force
        # un dev qui ajoute un nouveau SSE à le déclarer ici → discoverable.
        response_content_type: str = ""
        try:
            ct_value = self._headers.get("Content-Type", "")
            if isinstance(ct_value, str):
                response_content_type = ct_value
        except (AttributeError, TypeError):
            response_content_type = ""
        ct_is_sse = response_content_type.lower().startswith("text/event-stream")
        request_uri = self.request.uri or ""
        # Cf. ``app/handlers/system_events.py`` — seul SSE actuel. Étendre
        # cette liste explicitement quand un nouveau SSE est ajouté.
        uri_is_sse = any(request_uri.startswith(prefix) for prefix in _SSE_URI_ALLOWLIST)
        is_sse_response = ct_is_sse and uri_is_sse
        if request_time > threshold and not is_sse_response:
            logger.warning(
                "Requête lente : %.2fs (seuil %.2fs)",
                request_time,
                threshold,
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "method": self.request.method,
                    "uri": self.request.uri,
                    "status": self.get_status(),
                    "duration_ms": int(request_time * 1000),
                },
            )

        # Reset des ContextVars pour éviter une fuite vers une éventuelle
        # task détachée (``asyncio.create_task``) qui hériterait du contexte
        # courant. Sans ce reset, un job background qui logue plus tard avec
        # ``current_log_extra()`` afficherait l'ancien ``request_id`` /
        # ``user_id`` comme s'il appartenait à la nouvelle requête.
        try:
            from app.utils.request_context import reset_request_context

            reset_request_context()
        except (ImportError, AttributeError) as exc:
            # Erreurs d'import explicites — pas un swallow muet sur ``Exception``
            # qui masquerait des bugs réels (typo, circular import).
            logger.error("Failed to reset request_context", exc_info=exc)

    # ── Authentification ──────────────────────────────────────────────────

    def get_current_user(self) -> User | None:
        """Retourne l'utilisateur connecté, pré-chargé par ``prepare``.

        **Synchrone** — contrat Tornado oblige : la property
        ``self.current_user`` appelle ``get_current_user()`` *sans* ``await``
        (et uniquement tant que ``_current_user`` n'est pas encore défini).
        Une version ``async def`` faisait fuiter une **coroutine non-awaitée**
        dans ``self.current_user`` à chaque accès survenant avant que
        ``prepare`` ait résolu l'utilisateur (``self.current_user = await
        self._load_current_user_safe()``). Cette coroutine atterrissait
        ensuite dans une expression SQLAlchemy puis, au passage du GC, levait
        ``RuntimeWarning: coroutine 'BaseHandler.get_current_user' was never
        awaited`` (trace figée sur ``selectable.py:_from_objects``).

        On lit donc directement le cache ``_current_user`` (rempli par le
        *setter* de la property dans ``prepare``) et on retombe sur ``None``
        si la résolution n'a pas (encore) eu lieu — **jamais** une coroutine.
        La résolution asynchrone réelle reste dans ``_load_current_user`` /
        ``prepare``. NB : ``getattr`` (et non ``self.current_user``) pour
        éviter une récursion infinie via la property quand ``_current_user``
        est absent.
        """
        return getattr(self, "_current_user", None)

    async def _load_current_user_safe(self) -> User | None:
        """Résout l'utilisateur courant sans propager d'exception.

        La doctrine prepare-fail-safe (point 2 du docstring module) impose
        qu'aucune panne en chaîne (DB locked, session manager crashé)
        transforme une requête en HTTP 500. On log en ``warning`` et on
        tombe sur anonyme.
        """
        try:
            return await self._load_current_user()
        except Exception as exc:  # noqa: BLE001 — fail-safe by design
            logger.warning(
                "Échec de résolution de la session : %s",
                exc.__class__.__name__,
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            return None

    async def _load_current_user(self) -> User | None:
        """Charge l'utilisateur connecté depuis le cookie sécurisé.

        Pas de try/except ici — le fail-safe est géré par le wrapper
        ``_load_current_user_safe``. Cette méthode reste simple et testable.
        """
        token = self.get_secure_cookie(SESSION_COOKIE_NAME)
        if not token:
            return None

        try:
            token_str = token.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            logger.warning(
                "Cookie %s corrompu, ignoré",
                SESSION_COOKIE_NAME,
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            return None

        session_manager = get_session_manager()
        return await session_manager.get_user_from_token(token_str)

    def get_login_url(self) -> str:
        """Retourne l'URL de connexion (override Tornado)."""
        return self.reverse_url("login")

    async def _load_theme_mode_preference_safe(self) -> str:
        """Charge la préférence ``theme_mode`` de l'utilisateur courant.

        Retourne toujours une string valide (``"light"``, ``"dark"`` ou
        ``"system"``). Fail-safe : en cas d'erreur DB ou d'absence de
        user, retourne ``_DEFAULT_THEME_MODE`` (=``"system"`` —
        le système OS détermine alors le thème via prefers-color-scheme).
        L'utilisateur peut forcer ``light``/``dark`` via /settings.

        Injecté dans ``base.html`` via ``{{ handler.theme_mode_preference }}``
        pour que le bootstrap script applique immédiatement le bon thème,
        même quand ``localStorage`` a été vidé.

        ADV-S1 : ce SELECT est SKIPPÉ pour les requêtes qui ne servent
        pas du HTML (``/api/*`` ou Accept: application/json) — un
        endpoint JSON n'utilise jamais ``handler.theme_mode_preference``,
        donc payer le SELECT BDD à chaque appel API serait pure perte
        (aggravait le N+1 sur les pages avec 20 widgets en parallèle).
        """
        # Skip le SELECT pour les endpoints JSON / API — ils n'utilisent
        # pas la préférence, le coût BDD est inutile.
        try:
            uri = self.request.uri or ""
            if uri.startswith("/api/"):
                return _DEFAULT_THEME_MODE_FALLBACK
            accept = self.request.headers.get("Accept", "") or ""
            if "application/json" in accept and "text/html" not in accept:
                return _DEFAULT_THEME_MODE_FALLBACK
        except Exception:  # noqa: BLE001 — defensive, ne doit pas casser prepare
            pass

        from app.handlers.settings import (
            PREF_THEME_MODE,
            _DEFAULT_THEME_MODE,
            _THEME_MODE_VALUES,
            _get_pref,
        )

        if not self.current_user:
            return _DEFAULT_THEME_MODE
        try:
            from app.core.database import get_session

            async with get_session() as session:
                pref = await _get_pref(session, self.current_user.id, PREF_THEME_MODE)
            if pref and pref.value in _THEME_MODE_VALUES:
                return pref.value
            return _DEFAULT_THEME_MODE
        except Exception as exc:  # noqa: BLE001 — fail-safe, jamais de 500
            logger.debug(
                "theme_mode preload échoué : %s",
                exc.__class__.__name__,
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            return _DEFAULT_THEME_MODE

    # ── JSON / body parsing ───────────────────────────────────────────────

    def write_json(self, data: Any, status: int = 200) -> None:
        """Écrit une réponse JSON UTF-8."""
        self.set_status(status)
        self.set_header("Content-Type", "application/json; charset=UTF-8")
        self.write(json.dumps(data, ensure_ascii=False, default=str))

    def get_json_body(self) -> dict[str, Any]:
        """Parse le body JSON de la requête.

        Lève ``tornado.web.HTTPError(400)`` sur body invalide. Le caller
        typique est ``body = self.get_json_body() or {}`` — on retourne donc
        toujours un dict et jamais ``None`` ; ``None`` côté caller
        correspondrait à un bug.
        """
        try:
            parsed = json.loads(self.request.body)
        except (json.JSONDecodeError, TypeError) as exc:
            raise tornado.web.HTTPError(400, _Messages.INVALID_JSON_BODY) from exc
        if not isinstance(parsed, dict):
            raise tornado.web.HTTPError(400, _Messages.INVALID_JSON_BODY)
        return parsed

    def load_json_body(self, *, max_bytes: int = 0) -> dict[str, Any]:
        """Variante stricte de ``get_json_body`` qui lève ``ValueError``
        (au lieu de ``HTTPError``) — adaptée aux handlers qui veulent un
        contrôle granulaire (try/except + ``write_json({"success": False})``
        au lieu d'un 400 generique).

        Vérifie la taille AVANT le parsing JSON (defense fail-closed)
        quand ``max_bytes > 0``. ``max_bytes=0`` désactive le check.

        Bug 2026-05-26 (Agent 4 AT-M7) : avant cette méthode, le pattern
        ``_load_json_body`` était dupliqué 2× dans ``ai_admin.py`` avec
        une logique strictement identique. Promu ici comme SSoT pour
        éviter le drift.
        """
        raw = self.request.body or b""
        if max_bytes > 0 and len(raw) > max_bytes:
            raise ValueError("Requête trop volumineuse")
        try:
            decoded = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"JSON invalide : {exc}") from exc
        if not isinstance(decoded, dict):
            raise ValueError("Le corps de la requête doit être un objet JSON")
        return decoded

    # ── Helpers de parsing ────────────────────────────────────────────────

    def _parse_int_or_400(self, value: str, name: str = "paramètre") -> int:
        """Convertit ``value`` en ``int`` ou lève HTTP 400.

        ⚠️ N'applique aucune borne. Pour un paramètre dont la sémantique
        exige un range strict (durée de rétention, page_size, etc.), utiliser
        :meth:`_parse_int_with_bounds_or_400` — sinon le client peut envoyer
        ``-1`` et déclencher un état caché (rapport instantanément expiré,
        token de partage instantanément invalide, …) qui passera à 201/200
        sans signaler la corruption (« données fausses silencieusement »
        — cf. ``rules/consequences.md``).
        """
        try:
            return int(value)
        except (ValueError, TypeError) as exc:
            raise tornado.web.HTTPError(400, f"{name} invalide") from exc

    def _parse_int_with_bounds_or_400(
        self,
        value: str,
        name: str = "paramètre",
        *,
        min_value: int | None = None,
        max_value: int | None = None,
    ) -> int:
        """Convertit ``value`` en ``int`` et vérifie ``min_value <= v <= max_value``.

        Lève ``HTTPError(400)`` si la conversion échoue OU si la valeur est
        hors-bornes. Le message client précise les bornes attendues — l'admin
        d'une organisation cliente doit pouvoir corriger sa requête sans lire
        le code source.

        Args:
            value: La chaîne reçue (query string ou JSON body).
            name: Nom du paramètre (utilisé dans le message d'erreur FR).
            min_value: Borne minimum **inclusive** (``None`` = pas de floor).
            max_value: Borne maximum **inclusive** (``None`` = pas de cap).

        Note design — pourquoi pas étendre ``_parse_int_or_400`` ?
            Ajouter ``min_value``/``max_value`` à ``_parse_int_or_400`` serait
            un changement silencieux : ses ~80 call-sites continueraient à
            marcher sans rejet, ce qui aurait l'air OK mais masquerait les
            futurs gaps. En créant un helper séparé, on force chaque
            caller qui a besoin d'une borne à la déclarer explicitement.
        """
        parsed = self._parse_int_or_400(value, name)
        if min_value is not None and parsed < min_value:
            raise tornado.web.HTTPError(
                400,
                f"{name} doit être >= {min_value} (reçu {parsed})",
            )
        if max_value is not None and parsed > max_value:
            raise tornado.web.HTTPError(
                400,
                f"{name} doit être <= {max_value} (reçu {parsed})",
            )
        return parsed

    @property
    def is_ajax(self) -> bool:
        """``True`` si la requête a ``X-Requested-With: XMLHttpRequest``."""
        return self.request.headers.get("X-Requested-With") == "XMLHttpRequest"

    # ── write_error unifié ────────────────────────────────────────────────

    def write_error(self, status_code: int, **kwargs: Any) -> None:
        """Rend une réponse d'erreur cohérente (JSON ou HTML).

        * En debug : le message client inclut le texte d'origine.
        * En prod : message générique par classe de statut (``401``, ``403``,
          ``404``, ``5xx``). Jamais ``str(exception)`` en clair.
        * Pour ``5xx`` on alimente :class:`ErrorWatchdog` (détection de bugs
          systémiques : N+1, boucle DB, etc.).
        """
        error_message = self._extract_error_message(kwargs)

        if status_code >= 500:
            logger.error(
                "Erreur %d : %s",
                status_code,
                error_message,
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "status": status_code,
                    "uri": self.request.uri,
                    "method": self.request.method,
                },
            )
            try:
                watchdog = get_error_watchdog()
                watchdog.record(
                    f"http_{status_code}",
                    f"{self.request.method} {self.request.uri}: {error_message}",
                )
            except Exception:  # noqa: BLE001 — watchdog ne doit jamais casser write_error
                logger.exception("ErrorWatchdog indisponible")

        client_message = self._client_error_message(status_code, error_message)

        if _wants_json(self):
            self.set_header("Content-Type", "application/json; charset=UTF-8")
            self.finish(
                json.dumps(
                    {
                        "error": True,
                        "status": status_code,
                        "message": client_message,
                        "request_id": getattr(self, "request_id", None),
                    },
                    ensure_ascii=False,
                )
            )
        else:
            self.render(
                "error.html",
                status=status_code,
                message=client_message,
                request_id=getattr(self, "request_id", ""),
            )

    def _is_llm_configured(self) -> bool:
        """Snapshot synchrone : un provider LLM (cloud ou local) est-il
        disponible runtime ?

        Lecture in-memory du :class:`LLMManager` (singleton chargé au boot,
        rafraîchi via ``reinit_providers_from_config`` à chaque save admin).
        Pas d'I/O — safe à appeler à chaque render template sans latence.

        Fail-soft : si le manager ne peut pas être obtenu (boot très early,
        manager corrompu en test), retourne ``False`` (banner s'affiche)
        plutôt que de masquer un état dégradé. Mieux vaut une fausse
        alerte (admin clique sur ``/admin/ai-config`` et trouve tout OK)
        qu'un état dégradé invisible.
        """
        try:
            from app.services.ai.llm_providers import get_llm_manager

            return bool(get_llm_manager().has_any_provider_configured())
        except Exception:  # noqa: BLE001 — fail-soft volontaire
            return False

    def get_template_namespace(self) -> dict[str, Any]:
        """Expose des variables globales à tous les templates.

        Place ici les valeurs qui doivent être accessibles partout sans
        que chaque ``self.render(...)`` ait à les passer manuellement.
        Aujourd'hui :
        - ``app_name`` (``KOMPTIA_APP_NAME`` env-overridable) — évite
          ``"Komptia"`` hardcodé dans 30+ templates.
        - ``llm_configured`` : booléen consommé par
          ``_partials/no_llm_banner.html`` (banner global qui apparaît
          sur toutes les pages auth quand aucun provider n'est configuré).
        """
        ns = super().get_template_namespace()
        ns["app_name"] = config.app_name
        ns["llm_configured"] = self._is_llm_configured()
        # AI-7 (2026-05-26) : SSoT devise pricing — disponible sur TOUS les
        # templates pour qu'on évite de hardcoder ``$`` partout. Import local
        # pour ne pas charger constants_ai au boot des handlers non-IA.
        from app.constants_ai import PRICING_CURRENCY_CODE, PRICING_CURRENCY_SYMBOL

        ns["pricing_currency_code"] = PRICING_CURRENCY_CODE
        ns["pricing_currency_symbol"] = PRICING_CURRENCY_SYMBOL
        return ns

    def _extract_error_message(self, kwargs: dict[str, Any]) -> str:
        """Extrait un message d'erreur sain depuis les kwargs de write_error."""
        exc_info = kwargs.get("exc_info")
        if exc_info:
            exception = exc_info[1]
            log_message = getattr(exception, "log_message", None)
            if log_message:
                return str(log_message)
            reason = getattr(exception, "reason", None)
            if reason:
                return str(reason)
            # Exception non-HTTP : log complet côté serveur, message neutre.
            logger.error(
                "Exception non-HTTP dans write_error",
                exc_info=exc_info,
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            return _Messages.INTERNAL_ERROR
        reason_kw = kwargs.get("reason")
        if reason_kw:
            return str(reason_kw)
        return self._reason

    def _client_error_message(self, status_code: int, server_message: str) -> str:
        """Traduit un message serveur en message client (masque les détails en prod)."""
        if config.server.debug:
            return server_message
        if status_code >= 500:
            return _Messages.INTERNAL_ERROR
        if status_code == 404:
            return _Messages.NOT_FOUND
        if status_code == 403:
            return _Messages.FORBIDDEN
        if status_code == 401:
            return _Messages.AUTHENTICATION_REQUIRED
        return server_message

    # ── Session DB ────────────────────────────────────────────────────────

    @asynccontextmanager
    async def db_session(self, timeout: float | None = None) -> AsyncGenerator[AsyncSession, None]:
        """Context manager pour une session SQLAlchemy async.

        Usage::

            async with self.db_session() as session:
                result = await session.execute(select(User))

        Le ``commit`` final est bornée à ``timeout`` (défaut :
        ``config.server.db_session_timeout_s``) — si SQLite est locked par
        un autre writer, on déroule en HTTP 504 plutôt que de bloquer le
        worker event-loop.
        """
        effective_timeout = timeout if timeout is not None else config.server.db_session_timeout_s
        factory = get_session_factory()
        session = factory()
        try:
            yield session
            await asyncio.wait_for(session.commit(), timeout=effective_timeout)
        except asyncio.TimeoutError as exc:
            await session.rollback()
            raise tornado.web.HTTPError(504, _Messages.DB_TIMEOUT) from exc
        except SQLAlchemyError:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Helpers pour décorateurs ──────────────────────────────────────────────


def _reject_unauthenticated(handler: BaseHandler) -> None:
    """Lève 401 (API) ou redirige vers ``/login`` (HTML) — fail-closed.

    Centralise la logique commune aux trois décorateurs. La méthode wrappée
    n'est jamais appelée : le caller doit ``return`` immédiatement après.
    """
    if _wants_json(handler):
        raise tornado.web.HTTPError(401, _Messages.AUTHENTICATION_REQUIRED)
    handler.redirect(handler.get_login_url())


# ── Décorateurs d'autorisation ────────────────────────────────────────────


_HandlerMethod = Callable[..., Awaitable[Any]]


def authenticated(method: _HandlerMethod) -> _HandlerMethod:
    """Décore une méthode handler : nécessite un utilisateur connecté.

    Comportement sur anonyme :

    * Requête JSON/AJAX/``/api/`` → HTTP 401 JSON.
    * Requête HTML → redirect ``/login``.

    Usage::

        class MyHandler(BaseHandler):
            @authenticated
            async def get(self):
                ...
    """

    @functools.wraps(method)
    async def wrapper(self: BaseHandler, *args: Any, **kwargs: Any) -> Any:
        if not self.current_user:
            _reject_unauthenticated(self)
            return None
        return await method(self, *args, **kwargs)

    return wrapper


def is_admin(user: Any) -> bool:
    """Check booléen ``user.role == admin`` — SSoT pour les checks ad-hoc.

    Utilisable à l'extérieur des décorateurs (handlers qui veulent retourner
    un JSON forbidden custom plutôt que ``HTTPError(403)`` HTML).

    Robuste face aux variantes :
    - ``user.role`` est un ``UserRole`` enum → compare via égalité directe ;
    - ``user.role`` est une string (cas test/mock) → compare via ``.lower()``.
    - ``user`` est None / sans ``role`` → False (fail-closed).

    Bug 2026-05-26 (Agent 1 brainstorm S-9) : avant ce helper, plusieurs
    handlers réimplémentaient leur propre version (cf. ``settings.py::
    _ensure_admin``) avec des comparaisons ad-hoc ``str().lower()``.
    Drift garanti dès qu'un nouveau rôle apparaît.
    """
    if user is None:
        return False
    role = getattr(user, "role", None)
    if role is None:
        return False
    if isinstance(role, UserRole):
        return role == UserRole.ADMIN
    # Fallback string-comparison (tests qui passent un str sans cast enum).
    role_value = getattr(role, "value", role)
    return str(role_value).lower() == "admin"


def admin_required(method: _HandlerMethod) -> _HandlerMethod:
    """Décore une méthode handler : nécessite le rôle ``admin``.

    Anonyme → 401 / redirect login. Connecté mais non-admin → 403 FORBIDDEN.
    """

    @functools.wraps(method)
    async def wrapper(self: BaseHandler, *args: Any, **kwargs: Any) -> Any:
        user = self.current_user
        if not user:
            _reject_unauthenticated(self)
            return None
        if not is_admin(user):
            raise tornado.web.HTTPError(403, _Messages.ADMIN_REQUIRED)
        return await method(self, *args, **kwargs)

    return wrapper


def require_role(*allowed_roles: str) -> Callable[[_HandlerMethod], _HandlerMethod]:
    """Décore une méthode handler : nécessite un des rôles spécifiés.

    La résolution ``str → UserRole`` est **eager** (à l'import) : si un rôle
    inconnu est passé, la levée ``ValueError`` casse l'import — fail-fast,
    pas de silent-ignore qui autoriserait l'accès par défaut à personne
    pendant des semaines en prod.

    Usage::

        class QueryHandler(BaseHandler):
            @require_role("admin", "user")
            async def post(self):
                ...
    """
    if not allowed_roles:
        raise ValueError("require_role() appelé sans rôle — au moins un requis.")

    try:
        resolved_roles: frozenset[UserRole] = frozenset(UserRole(r) for r in allowed_roles)
    except ValueError as exc:
        # Fail-fast à l'import : la trace pointe la ligne du décorateur.
        raise ValueError(
            f"require_role : rôle inconnu dans {allowed_roles!r} — "
            f"valeurs valides : {[r.value for r in UserRole]}"
        ) from exc

    def decorator(method: _HandlerMethod) -> _HandlerMethod:
        @functools.wraps(method)
        async def wrapper(self: BaseHandler, *args: Any, **kwargs: Any) -> Any:
            user = self.current_user
            if not user:
                _reject_unauthenticated(self)
                return None
            if user.role not in resolved_roles:
                raise tornado.web.HTTPError(403, _Messages.INSUFFICIENT_PERMISSIONS)
            return await method(self, *args, **kwargs)

        return wrapper

    return decorator


# ── AuthenticatedHandler ──────────────────────────────────────────────────


class AuthenticatedHandler(BaseHandler):
    """Handler de base pour routes nécessitant une authentification.

    Rejet géré au niveau ``prepare`` : si ``current_user is None`` après
    ``super().prepare()``, la requête est rejetée avant même d'atteindre
    ``get``/``post`` — pas besoin de décorer chaque méthode.
    """

    async def prepare(self) -> None:
        await super().prepare()
        if not self.current_user:
            _reject_unauthenticated(self)
