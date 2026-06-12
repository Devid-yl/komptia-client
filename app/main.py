"""Komptia v2.0 — Point d'entrée principal du serveur Tornado.

Sommaire
--------
* :class:`Application` — application Tornado configurée depuis
  :mod:`app.config` (unique source de vérité pour les settings).
* :class:`AppNotFoundHandler` — ``default_handler_class`` pour les 404.
  Discrimine ``/api/`` (JSON uniforme via :meth:`BaseHandler.write_error`),
  assets statiques (404 silencieux) et pages HTML (redirect ``/``).
* :class:`_ServerLifecycle` — encapsule boot + arrêt gracieux **sans
  globals mutables** (évite les races d'un double signal SIGTERM).
* :func:`make_app`, :func:`shutdown` — surface publique conservée pour la
  rétrocompatibilité stricte avec ``tests/unit/test_server.py`` et
  ``tests/test_smoke.py``.
* :func:`main` — orchestrateur CLI (parse options → init DB → schedulers
  → HTTP server → signal handlers → boucle événementielle).

Garanties senior (OWASP ASVS v5 + Tornado 6.5 docs + CLAUDE.md)
---------------------------------------------------------------
1. **Bootstrap OpenSSL legacy déterministe** — :func:`_bootstrap_openssl_legacy_if_needed`
   active TLS 1.0/1.1 pour les ODBC vieillissants UNIQUEMENT si le fichier
   de config existe ET que ``OPENSSL_CONF`` n'est pas déjà fixé par l'ops
   (respect override environnement, pas de comportement magique caché).
2. **Parse CLI avant logger** — ``tornado.options.parse_command_line()`` est
   appelé **avant** ``AppLogger.setup(...)``. Corrige un bug pré-refactor
   où ``--debug=true`` ne prenait pas effet sur le niveau de log car
   ``options.debug`` lisait encore la valeur par défaut (``config.server.debug``)
   avant parsing.
3. **404 unifiées via BaseHandler.write_error** — :class:`AppNotFoundHandler`
   lève :class:`tornado.web.HTTPError(404)` pour ``/api/`` ; la réponse JSON
   passe par :meth:`BaseHandler.write_error` (shape ``{error, status,
   message, request_id}`` cohérente avec ``settings.py``,
   ``saved_queries.py``, ``templates.py``). Cf. Tornado 6.5 guide : « raise
   HTTPError(404) and override write_error » est le pattern officiel pour
   ``default_handler_class``.
4. **Fire-and-forget tasks strongly referenced (fix GC bug Python 3.12+)** —
   :meth:`_ServerLifecycle.spawn_background` stocke les Task dans un set
   et installe un ``add_done_callback(set.discard)``. Sans cette référence
   forte, la GC peut collecter une Task avant sa terminaison (cf. doc
   ``asyncio.create_task`` Python 3.12/3.13).
5. **Shutdown idempotent, pas de global mutable** — ``_shutting_down`` et
   ``_session_cleanup_cb`` sont des attributs de :class:`_ServerLifecycle`
   (instance unique par process). Deux SIGTERM concurrents ne provoquent
   plus de race : le deuxième est no-op via le re-entry guard.
6. **Cleanup non bloquant** — ``shutdown_scheduler(wait=True)`` et
   ``shutdown_embedding_service()`` sont des API synchrones bloquantes
   (``ThreadPoolExecutor.shutdown(wait=True)``). Elles sont enveloppées
   dans ``asyncio.to_thread`` pour ne pas bloquer l'event-loop pendant le
   drain — sinon les callbacks ``on_connection_close`` ne peuvent pas
   s'exécuter et les requêtes en vol ne finissent jamais proprement.
7. **Logs structurés sans emoji** — les messages de lifecycle sont en
   français pur, le contexte est dans ``extra={...}`` (parsable par les
   pipelines JSON type Datadog/CloudWatch). Les emojis restent dans le
   banner ``print()`` (UX console) mais **jamais** dans un appel
   ``logger.*`` : un parser JSON peut mal traiter des caractères ``\\udXXX``
   et casser l'ingestion.
8. **Port bind error → exit propre** — si ``server.listen`` lève
   :class:`OSError` (port déjà utilisé, permission refusée), on log
   ``critical`` et on ``sys.exit(1)`` au lieu de cracher la stack trace.

Conventions
-----------
* ``from __future__ import annotations`` (PEP 563).
* Imports top-level uniquement (pas de lazy imports dans les fonctions
  sauf pour casser des cycles explicitement documentés).
* Type hints stricts Python 3.10+ (``X | None``, ``dict[str, Any]``, …).
* Messages FR centralisés dans :class:`_Messages`.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from pathlib import Path
from types import FrameType
from typing import Any, Awaitable, Final

# ─── Bootstrap OpenSSL legacy AVANT tout import SSL-touching ──────────────
# (Tornado et SQLAlchemy peuvent charger OpenSSL à l'import selon la version ;
# on fixe OPENSSL_CONF en premier pour ne pas rater la fenêtre.)

_OPENSSL_LEGACY_CONF: Final[Path] = (
    Path(__file__).resolve().parent.parent / "config" / "openssl_legacy.cnf"
)


def _bootstrap_openssl_legacy_if_needed() -> None:
    """Active la config OpenSSL permissive si présente et non déjà fixée.

    OpenSSL 3.x refuse TLS 1.0/1.1 par défaut ; certains SQL Server anciens
    ne supportent pas TLS 1.2+. On pointe ``OPENSSL_CONF`` vers la config
    permissive uniquement si :

    1. Le fichier ``config/openssl_legacy.cnf`` existe (sinon : no-op,
       l'app tourne avec OpenSSL strict) ;
    2. ``OPENSSL_CONF`` n'est pas déjà défini dans l'environnement (respect
       d'une override explicite d'un opérateur).

    Cette fonction est idempotente et sans side-effect si les conditions
    ne sont pas remplies. Exposée (pas préfixée ``__``) pour être testable.
    """
    if "OPENSSL_CONF" in os.environ:
        return
    if _OPENSSL_LEGACY_CONF.is_file():
        os.environ["OPENSSL_CONF"] = str(_OPENSSL_LEGACY_CONF)


_bootstrap_openssl_legacy_if_needed()


# ─── Imports tiers & internes ──────────────────────────────────────────────

import tornado.httpserver  # noqa: E402 — import après bootstrap OpenSSL
import tornado.ioloop  # noqa: E402
import tornado.options  # noqa: E402
import tornado.web  # noqa: E402
from sqlalchemy.exc import OperationalError, SQLAlchemyError  # noqa: E402
from tornado.options import define, options  # noqa: E402

from app.config import config  # noqa: E402
from app.core.database import close_database, init_database  # noqa: E402
from app.handlers.base import BaseHandler  # noqa: E402
from app.routes import get_routes  # noqa: E402
from app.ui_modules import Pagination  # noqa: E402
from app.services.ai.embedding_service import shutdown_embedding_service  # noqa: E402
from app.services.ai.llm_providers import ensure_providers_from_db  # noqa: E402
from app.services.ai.schema_sync_scheduler import (  # noqa: E402
    start_schema_sync_scheduler,
    stop_schema_sync_scheduler,
)
from app.services.auth.session_manager import get_session_manager  # noqa: E402
from app.services.automation import (  # noqa: E402
    load_active_automations,
    shutdown_scheduler,
    start_scheduler,
)
from app.services.automation.scheduler import get_scheduler  # noqa: E402
from app.services.database.sage_connector import init_sage_from_db_config  # noqa: E402
from app.services.diagnostics import startup_check  # noqa: E402
from app.utils.logger import AppLogger, get_logger  # noqa: E402
from app.utils.loop_lag_monitor import (  # noqa: E402
    LoopLagMonitor,
    start_loop_lag_monitor,
)

logger = get_logger(__name__)


# ─── Constantes ────────────────────────────────────────────────────────────

#: Max body size accepté par Tornado AVANT que le handler ne s'exécute.
#: Convention Komptia : aucun cap fichier indépendant — la VRAIE limite est
#: le quota stockage de l'utilisateur (config admin via /admin/performance).
#: On laisse ici une borne très large (4 GiB, max int32 - 1) pour ne pas
#: rejetter un upload au niveau HTTP avant que le handler n'ait pu appliquer
#: la logique de quota. **Note RAM** : Tornado bufferise tout le body en
#: mémoire avant d'invoquer le handler ; un upload simultané de 4 GiB par
#: un user pèse 4 GiB sur le serveur. Mitigation : rate-limit upload +
#: quota user filtre les abus.
_HTTP_MAX_BODY_BYTES: Final[int] = 4 * 1024 * 1024 * 1024 - 1  # 4 GiB - 1

#: Timeout (secondes) pour chaque étape bloquante du démarrage : init DB,
#: init Sage, load_active_automations, schema sync, diagnostic. 30 s laisse
#: le temps à un SQLite migré à froid ou un SQL Server distant lent, tout
#: en plafonnant les démarrages silencieusement accrochés (détection via
#: l'exception ``tornado.util.TimeoutError``).
_STARTUP_STEP_TIMEOUT_S: Final[int] = 14400

#: Période (millisecondes) du cleanup des sessions expirées. 1 h = trade-off
#: entre coût CPU (cleanup très rapide) et latence d'apparition des rows
#: obsolètes. Passé en ms à :class:`tornado.ioloop.PeriodicCallback`.
_SESSION_CLEANUP_PERIOD_MS: Final[int] = 3600 * 1000

#: Délai (secondes) de drain des requêtes en cours lors du SIGTERM/SIGINT.
#: 3 s couvre 99.9 % des handlers JSON (health, login, API). K8s kill hard
#: à 30 s par défaut (``terminationGracePeriodSeconds``) — on reste large.
_SHUTDOWN_DRAIN_DELAY_S: Final[float] = 3.0

#: Paths qui retournent un 404 silencieux (pas de body, pas de redirect).
#: ``frozenset`` pour lookup O(1) + immutabilité (évite toute mutation
#: accidentelle à runtime).
#: ``/.well-known/`` + ``/apple-touch-icon`` : sondes automatiques du
#: navigateur (Chrome DevTools probe ``/.well-known/appspecific/
#: com.chrome.devtools.json`` à chaque ouverture des devtools ; iOS/Safari
#: sonde ``apple-touch-icon``). Sans ces préfixes, ``prepare()`` les
#: redirigeait vers ``/`` (302 vers une page HTML — incorrect pour une sonde)
#: ET loggait un WARNING « Redirection 404 vers / » à chaque fois = bruit de
#: log. On les traite comme des assets → 404 SILENCIEUX, pas de redirect, pas
#: de warning. NB : ``/.well-known/acme-challenge/`` (certbot) est servi par
#: nginx en amont, l'app ne le voit jamais — aucun conflit.
_ASSET_PREFIXES: Final[frozenset[str]] = frozenset(
    (
        "/static/",
        "/favicon",
        "/robots.txt",
        "/manifest.json",
        "/sitemap",
        "/.well-known/",
        "/apple-touch-icon",
    )
)


class _Messages:
    """Messages d'erreur client centralisés (français, ton cohérent UI).

    Cohérent avec :class:`app.handlers.base._Messages`. On centralise ici
    uniquement ceux spécifiques à ``main.py`` : les 404 passent déjà par
    :meth:`BaseHandler.write_error` qui utilise ``_Messages.NOT_FOUND`` de
    ``base.py`` côté client (en prod) — cette classe sert donc surtout de
    source de vérité pour les logs internes et le debug.
    """

    NOT_FOUND_API: Final[str] = "La ressource demandée n'existe pas."
    PORT_BIND_FAILED: Final[str] = "Impossible d'écouter sur le port"
    DB_INIT_FAILED: Final[str] = "Échec de l'initialisation de la base de données"


# ─── CLI options ──────────────────────────────────────────────────────────

define("port", default=config.server.port, help="Port du serveur", type=int)
define("debug", default=config.server.debug, help="Mode debug", type=bool)


# ─── Application ──────────────────────────────────────────────────────────


class _LongCacheStaticFileHandler(tornado.web.StaticFileHandler):
    """Static handler avec cache long-terme pour ``/static/vendor/*``.

    Tornado par défaut sert les fichiers statiques avec un ``Cache-Control``
    qui force la revalidation (ETag + ``If-None-Match`` à chaque requête →
    RTT serveur, ~200 ms en 3G). Pour les libs vendored (Plotly, Bootstrap
    Icons, etc.) qui sont **immutables** dans une version donnée du code,
    on peut servir avec ``max-age=31536000, immutable`` — le navigateur ne
    revalide plus pendant 1 an. Cf. review adversariale R2-A9.

    On scope ce comportement aux fichiers SOUS ``static/vendor/`` : les
    autres assets (CSS Tailwind, JS Komptia) gardent le défaut (revalidation)
    car ils peuvent évoluer entre deux releases sans que le path change.
    Pour les invalidations de cache vendor, il suffit de bump la version
    dans le path (``/static/vendor/plotly@2.36/...`` ou un ``?v=N``).
    """

    def set_extra_headers(self, path: str) -> None:  # type: ignore[override]
        # ``path`` est relatif à ``static_path``. Les fichiers vendored
        # vivent sous ``vendor/...``.
        if path.startswith("vendor" + os.sep) or path.startswith("vendor/"):
            self.set_header("Cache-Control", "public, max-age=31536000, immutable")


class Application(tornado.web.Application):
    """Application Tornado principale.

    Les settings sont lus depuis :mod:`app.config` — unique source de vérité
    (pas de magic strings éparpillés). La version 2026-04 enregistre
    :class:`AppNotFoundHandler` comme ``default_handler_class`` pour que
    toute route inconnue remonte par notre pipeline d'erreur uniformisé.
    """

    def __init__(self) -> None:
        settings: dict[str, Any] = {
            "template_path": str(config.templates_dir),
            "static_path": str(config.static_dir),
            "static_url_prefix": "/static/",
            # Custom handler pour cache long-terme sur ``/static/vendor/``.
            "static_handler_class": _LongCacheStaticFileHandler,
            "cookie_secret": config.security.secret_key,
            "xsrf_cookies": config.security.csrf_enabled,
            "debug": config.server.debug,
            "autoreload": config.server.autoreload,
            "login_url": "/login",
            "default_handler_class": AppNotFoundHandler,
            # UIModules partagés — composants serveur réutilisables appelés via
            # ``{% module X(...) %}``. ``Pagination`` = barre de pagination
            # unifiée (source unique, cf. app/ui_modules.py).
            "ui_modules": {"Pagination": Pagination},
            # ``compress_response`` : active la compression gzip pour les
            # réponses HTTP qui dépassent ~1 KB (seuil interne Tornado).
            # Bénéfice typique : -70 % sur HTML/CSS/JS texte. Sans effet
            # sur les images/binaires (déjà compressés) ni sur WebSocket
            # (qui utilise sa propre extension ``permessage-deflate``).
            #
            # Sécurité (BREACH attack) : safe ici car nos secrets
            # sensibles (token XSRF, cookie de session) sont dans des
            # cookies — JAMAIS dans le body — donc la longueur compressée
            # ne révèle rien d'exploitable. Si un jour on injecte un
            # token user dans un HTML reflété, repenser cette décision.
            "compress_response": True,
        }
        super().__init__(get_routes(), **settings)
        logger.info(
            "Application initialisée",
            extra={"debug": config.server.debug, "environment": config.environment},
        )


# ─── Handler 404 unifié ──────────────────────────────────────────────────


class AppNotFoundHandler(BaseHandler):
    """Handler pour les routes non trouvées (404).

    Branche trois stratégies selon le préfixe du chemin :

    * ``/api/*`` → :class:`tornado.web.HTTPError(404)` → la réponse JSON
      passe par :meth:`BaseHandler.write_error` — shape ``{error, status,
      message, request_id}`` cohérente avec le reste des handlers.
    * Assets (``/static/``, ``/favicon``, ``/robots.txt``, …) → 404 sans
      body (pas de redirect qui polluerait les logs d'un bot qui scanne
      un chemin non existant).
    * Pages HTML → redirect ``/`` (le router client SPA gère l'URL).

    Note sur le nommage : ``AppNotFoundHandler`` plutôt que ``NotFoundHandler``
    pour désambiguïser d'une éventuelle classe Tornado interne. Le suffixe
    ``App`` rappelle que c'est le 404 global de l'application (par opposition
    à un 404 métier qu'un handler spécifique pourrait émettre).
    """

    async def prepare(self) -> None:  # type: ignore[override]
        """Dispatch selon le type de route inconnue.

        ``await super().prepare()`` est **critique** : il charge
        ``self.request_id`` et ``self.current_user`` (fail-safe) que
        :meth:`BaseHandler.write_error` référence pour le JSON de réponse.
        Sans cet appel, on perdrait le ``request_id`` qui corrèle les logs.
        """
        await super().prepare()
        path = self.request.path

        # API : JSON 404 via le pipeline write_error unifié.
        if path.startswith("/api/"):
            raise tornado.web.HTTPError(404, _Messages.NOT_FOUND_API)

        # Assets / fichiers statiques : 404 silencieux.
        if any(path.startswith(prefix) for prefix in _ASSET_PREFIXES):
            self.set_status(404)
            self.finish()
            return

        # Pages HTML inconnues : redirect vers l'accueil (SPA router).
        logger.warning(
            "Redirection 404 vers /",
            extra={
                "request_id": getattr(self, "request_id", "?"),
                "method": self.request.method,
                "path": path,
            },
        )
        self.redirect("/")


def make_app() -> Application:
    """Factory de l'application Tornado (utilisée par tests + :func:`main`)."""
    return Application()


# ─── Lifecycle (encapsule boot + shutdown, évite globals mutables) ────────


class _ServerLifecycle:
    """Encapsule le boot et le shutdown du serveur.

    Remplace les globals ``_shutting_down`` et ``_session_cleanup_cb``.
    Une instance unique est créée dans :func:`main`. Les signal handlers
    ferment la closure sur cette instance, pas sur des variables globales
    — élimine les races d'un double signal (bien que ``signal.signal``
    soit single-threaded, un handler re-entrant peut arriver si la coroutine
    de cleanup attend elle-même un await qui yield).

    Attributes
    ----------
    _shutting_down:
        Re-entry guard pour :meth:`shutdown`.
    _session_cleanup_cb:
        :class:`PeriodicCallback` qui purge les sessions expirées toutes
        les heures. ``None`` tant que :meth:`register_session_cleanup`
        n'a pas été appelé.
    _background_tasks:
        Set de référence forte pour les fire-and-forget tasks (fix du bug
        GC Python 3.12+ documenté dans :mod:`asyncio` — une Task sans ref
        peut être collectée avant complétion).
    """

    def __init__(self) -> None:
        self._shutting_down: bool = False
        self._session_cleanup_cb: tornado.ioloop.PeriodicCallback | None = None
        self._background_tasks: set[asyncio.Task[Any]] = set()
        # Moniteur de latence event-loop (observabilité H1 : détecte le code
        # synchrone qui gèle le loop). ``None`` tant que non démarré / désactivé.
        self._loop_lag_monitor: "LoopLagMonitor | None" = None

    # ── Background tasks helper ──────────────────────────────────────────

    def spawn_background(self, coro: Awaitable[Any]) -> asyncio.Task[Any]:
        """Crée une :class:`asyncio.Task` avec référence forte persistante.

        Sans référence forte, Python 3.12+ peut garbage-collecter la Task
        avant sa terminaison (cf. doc ``asyncio.create_task``). On stocke
        la task dans ``_background_tasks`` et on installe un callback
        ``add_done_callback(self._background_tasks.discard)`` pour libérer
        la référence une fois la task terminée (éviter la fuite mémoire).
        """
        task = asyncio.create_task(coro)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return task

    # ── Session cleanup périodique ───────────────────────────────────────

    def register_session_cleanup(self, io_loop: tornado.ioloop.IOLoop) -> None:
        """Enregistre le :class:`PeriodicCallback` de cleanup des sessions.

        Appelé une fois au démarrage. La task async ``_cleanup_sessions``
        est lancée via :meth:`spawn_background` pour garantir sa survie GC.
        """

        async def _cleanup_sessions() -> None:
            try:
                session_manager = get_session_manager()
                count = await session_manager.cleanup_expired_sessions()
                if count > 0:
                    logger.info("Cleanup périodique sessions", extra={"cleaned": count})
            except (SQLAlchemyError, OperationalError) as exc:
                logger.error("Erreur cleanup sessions (DB)", exc_info=exc)
            except Exception:  # noqa: BLE001 — cleanup ne doit jamais crasher l'IOLoop
                logger.exception("Erreur cleanup sessions (inconnue)")

        def _fire() -> None:
            # Wrappé dans un call synchrone pour éviter qu'un échec
            # d'ordonnancement ne tue le PeriodicCallback. Le spawn_background
            # renvoie la Task (fire-and-forget avec strong ref).
            self.spawn_background(_cleanup_sessions())
            # Purge des rate-limiters en mémoire (clés IP/user expirées).
            # ``RateLimiter.cleanup()`` existait mais n'était jamais schedulé →
            # croissance non bornée du dict ``_requests`` (axe 21). Sync +
            # rapide (pas de task). Ne doit jamais tuer l'IOLoop.
            try:
                from app.utils.rate_limiter import RateLimiter

                # ``max_age`` GÉNÉREUX (24h), volontairement découplé de la
                # cadence : une clé n'est purgée que si son timestamp le plus
                # récent a > 24h — donc bien au-delà de toute fenêtre de
                # rate-limit (la plus longue vaut 1h aujourd'hui). Évite de
                # réinitialiser par erreur un compteur encore actif, ce qui
                # ouvrirait un bypass si un jour une fenêtre > 1h est ajoutée.
                RateLimiter.cleanup_all(max_age_seconds=86_400)
            except Exception:  # noqa: BLE001 — cleanup ne doit jamais crasher l'IOLoop
                logger.exception("Erreur cleanup rate-limiters")
            # Idem pour les gardes d'idempotence (clés d'envoi email expirées).
            try:
                from app.utils.idempotency import IdempotencyGuard

                IdempotencyGuard.cleanup_all()
            except Exception:  # noqa: BLE001 — cleanup ne doit jamais crasher l'IOLoop
                logger.exception("Erreur cleanup idempotency guards")

        self._session_cleanup_cb = tornado.ioloop.PeriodicCallback(
            _fire, _SESSION_CLEANUP_PERIOD_MS
        )
        self._session_cleanup_cb.start()
        logger.info(
            "Nettoyage périodique sessions activé",
            extra={"period_seconds": _SESSION_CLEANUP_PERIOD_MS // 1000},
        )
        # Moniteur de latence event-loop (H1 observabilité) — démarré au boot
        # avec les autres callbacks périodiques. Retourne None si désactivé par env.
        self._loop_lag_monitor = start_loop_lag_monitor(io_loop)
        _ = io_loop  # garde la signature stable si on branche plus tard l'io_loop

    # ── Shutdown ─────────────────────────────────────────────────────────

    def shutdown(
        self,
        server: tornado.httpserver.HTTPServer,
        io_loop: tornado.ioloop.IOLoop,
    ) -> None:
        """Orchestre l'arrêt gracieux. Idempotent (re-entry guard).

        1. Set le flag ``_shutting_down`` (évite les doubles exécutions).
        2. ``server.stop()`` : n'accepte plus de nouvelles connexions.
        3. ``io_loop.add_callback(cleanup)`` : le nettoyage tourne sur
           l'event-loop pour pouvoir faire des ``await`` (DB close,
           scheduler async, etc.).

        La signature ``(server, io_loop)`` est conservée pour la rétrocompat
        avec ``tests/unit/test_server.py::test_graceful_shutdown_logic`` qui
        passe des mocks.
        """
        if self._shutting_down:
            return
        self._shutting_down = True

        logger.info("Arrêt du serveur en cours")
        server.stop()
        io_loop.add_callback(self._run_cleanup, io_loop)

    async def _run_cleanup(self, io_loop: tornado.ioloop.IOLoop) -> None:
        """Coroutine de cleanup : stoppe services, ferme DB, quitte l'IO loop.

        Chaque service est enveloppé d'un try/except ciblé — un service
        HS ne doit pas empêcher les autres d'être arrêtés proprement.
        ``shutdown_scheduler`` et ``shutdown_embedding_service`` sont
        exécutés via ``asyncio.to_thread`` car ce sont des API **synchrones
        bloquantes** (``ThreadPoolExecutor.shutdown(wait=True)`` bloque le
        thread courant). Les exécuter dans le thread event-loop gèlerait
        les callbacks (dont ``on_connection_close``) pendant le drain.
        """
        # Arrêt du PeriodicCallback en premier (sinon il peut enfiler
        # des cleanups pendant qu'on arrête la DB).
        if self._session_cleanup_cb is not None:
            self._session_cleanup_cb.stop()
            self._session_cleanup_cb = None
        # Stoppe la sonde de latence event-loop (idempotent, no-op si désactivée).
        if self._loop_lag_monitor is not None:
            self._loop_lag_monitor.stop()
            self._loop_lag_monitor = None

        # Drain : laisser les requêtes en vol terminer.
        try:
            await asyncio.sleep(_SHUTDOWN_DRAIN_DELAY_S)
        except asyncio.CancelledError:
            logger.warning("Drain interrompu")

        # Scheduler d'automatisations (API sync → asyncio.to_thread).
        try:
            await asyncio.to_thread(shutdown_scheduler, wait=True)
            logger.info("Scheduler automatisations arrêté")
        except RuntimeError as exc:
            logger.error("Erreur arrêt scheduler automatisations", exc_info=exc)

        # Scheduler sync schéma IA (async natif).
        try:
            await stop_schema_sync_scheduler()
            logger.info("Scheduler sync schéma IA arrêté")
        except Exception:  # noqa: BLE001 — best-effort cleanup
            logger.exception("Erreur arrêt scheduler sync schéma IA")

        # Service d'embeddings (ThreadPoolExecutor.shutdown bloquant → to_thread).
        try:
            await asyncio.to_thread(shutdown_embedding_service)
            logger.info("Service embeddings arrêté")
        except Exception:  # noqa: BLE001 — best-effort cleanup
            logger.exception("Erreur arrêt service embeddings")

        # Drain des audits EmailLog fire-and-forget de la BOUCLE PRINCIPALE
        # Tornado encore en vol (#48) — AVANT close_database() (ces tâches
        # écrivent dans la BDD ; les laisser tomber après fermeture = EmailLog
        # perdu). Couvre les envois sur la boucle persistante : /reports,
        # /contacts, Iris, feedback, delivery dashboard. Les audits des
        # AUTOMATISATIONS tournent sur des boucles asyncio.run jetables (threads
        # worker) et sont drainés in-loop par run_then_drain_email_log — PAS ici
        # (drain est loop-scoped, il ne voit que les tâches de la boucle courante).
        try:
            from app.services.email.smtp_client import drain_email_log_tasks

            await drain_email_log_tasks()
        except Exception:  # noqa: BLE001 — best-effort, ne bloque pas l'arrêt
            logger.exception("Erreur drain audits EmailLog au shutdown")

        # Fermeture des connexions BDD.
        try:
            await close_database()
            logger.info("Connexions base de données fermées")
        except (SQLAlchemyError, OperationalError) as exc:
            logger.error("Erreur fermeture DB", exc_info=exc)

        # Annule les tasks background restantes (preload LLM si encore en cours,
        # cleanup sessions déjà stoppé, etc.) — évite les warnings
        # "Task was destroyed but it is pending!" dans les logs.
        for task in list(self._background_tasks):
            if not task.done():
                task.cancel()

        logger.info("Serveur arrêté proprement")
        io_loop.stop()


# ─── Chargement des schedules dashboard ───────────────────────────────────


async def _preload_llm_providers() -> None:
    """Précharge les providers LLM pour éviter le délai au premier usage.

    Lancé en background via :meth:`_ServerLifecycle.spawn_background`.
    Son échec est loggé en ``warning`` — jamais bloquant pour le démarrage.
    Un provider non préchargé sera initialisé paresseusement au premier
    appel (avec une latence visible pour le premier user).
    """
    try:
        await ensure_providers_from_db()
        logger.info("Providers LLM préchargés")
    except (SQLAlchemyError, OperationalError) as exc:
        logger.warning("Échec préchargement providers LLM (DB)", exc_info=exc)
    except Exception:  # noqa: BLE001 — best-effort, ne doit pas masquer un bug ailleurs
        logger.warning("Échec préchargement providers LLM (autre)", exc_info=True)


# ─── Init helpers blocking (découpés pour testabilité) ─────────────────────


def _init_database_blocking(io_loop: tornado.ioloop.IOLoop) -> None:
    """Init DB synchrone. ``sys.exit(1)`` si échec (sans DB, rien à faire)."""
    from app.services.deployment_identity import DeploymentIdentityError

    try:
        io_loop.run_sync(init_database, timeout=_STARTUP_STEP_TIMEOUT_S)
        logger.info("Base de données initialisée")
    except DeploymentIdentityError as exc:
        # Garde d'identité (#8) : BDD locale appartenant à une autre source SQL
        # → refus fail-closed propre (anti-corruption multi-instance). Le message
        # indique l'override KOMPTIA_ALLOW_DEPLOYMENT_REASSIGN pour un changement voulu.
        logger.critical("Refus de boot — garde d'identité de déploiement : %s", exc)
        sys.exit(1)
    except (SQLAlchemyError, OperationalError) as exc:
        logger.critical(_Messages.DB_INIT_FAILED, exc_info=exc)
        sys.exit(1)


def _init_sage_config_blocking(io_loop: tornado.ioloop.IOLoop) -> None:
    """Init config Sage depuis la BDD locale (best-effort, non-bloquant)."""
    try:
        io_loop.run_sync(init_sage_from_db_config, timeout=_STARTUP_STEP_TIMEOUT_S)
    except (SQLAlchemyError, OperationalError) as exc:
        logger.warning("Init config Sage GUI (DB)", exc_info=exc)
    except ImportError as exc:
        logger.warning("Init config Sage GUI (import)", exc_info=exc)


def _start_automation_schedulers(io_loop: tornado.ioloop.IOLoop) -> None:
    """Démarre le scheduler APScheduler + charge automatisations + dashboards.

    Chaque sous-étape est isolée : un échec sur les dashboards ne bloque
    pas le scheduler d'automatisations. Cohérent avec la doctrine
    « fail-closed sur ce qui est critique, best-effort sur le reste ».
    """
    try:
        start_scheduler()
        logger.info("Scheduler automatisations démarré")
        io_loop.run_sync(load_active_automations, timeout=_STARTUP_STEP_TIMEOUT_S)
    except (SQLAlchemyError, OperationalError) as exc:
        logger.error("Erreur démarrage scheduler/automations (DB)", exc_info=exc)
    except Exception:  # noqa: BLE001 — un scheduler HS ne doit pas planter l'app
        logger.exception("Erreur démarrage scheduler/automations")



def _start_schema_sync_blocking(io_loop: tornado.ioloop.IOLoop) -> None:
    """Démarre le scheduler de sync schéma IA (best-effort)."""
    try:
        io_loop.run_sync(start_schema_sync_scheduler, timeout=_STARTUP_STEP_TIMEOUT_S)
        logger.info("Scheduler sync schéma IA démarré")
    except Exception:  # noqa: BLE001 — best-effort
        logger.warning("Scheduler sync schéma IA non démarré", exc_info=True)


def _run_startup_diagnostics_blocking(io_loop: tornado.ioloop.IOLoop) -> None:
    """Exécute le diagnostic de démarrage et log selon la sévérité.

    ``status`` possible : ``ok`` / ``degraded`` / ``critical`` (cf.
    :func:`app.services.diagnostics.startup_check`). Un status inconnu
    est loggé en warning pour détecter un drift d'API côté diag.
    """
    try:
        diag = io_loop.run_sync(startup_check, timeout=_STARTUP_STEP_TIMEOUT_S)
    except Exception:  # noqa: BLE001 — diag ne doit jamais bloquer le démarrage
        logger.warning("Diagnostic démarrage non exécuté", exc_info=True)
        return

    status = diag.get("status") if isinstance(diag, dict) else None
    if status == "ok":
        logger.info("Diagnostic démarrage OK")
        return
    if status == "degraded":
        for warning in diag.get("warnings", []):
            logger.warning("Diagnostic dégradé", extra={"warning": warning})
        for error in diag.get("errors", []):
            logger.error("Diagnostic erreur", extra={"error": error})
        return
    if status == "critical":
        for error in diag.get("errors", []):
            logger.critical("Diagnostic CRITICAL", extra={"error": error})
        return
    logger.warning("Diagnostic : status inconnu", extra={"status": status})


def _create_and_listen(app: Application) -> tornado.httpserver.HTTPServer:
    """Crée le :class:`HTTPServer` et bind le port. ``sys.exit(1)`` si bind HS."""
    # ``xheaders`` : quand l'app est derrière un reverse-proxy de confiance
    # (nginx, port bindé sur 127.0.0.1), Tornado lit ``X-Forwarded-For`` /
    # ``X-Forwarded-Proto`` pour résoudre la vraie IP client et le schéma
    # d'origine (HSTS émis, rate-limiter login per-user, URLs https correctes).
    # Piloté par config (``server.trust_proxy_headers``, fail-safe False) :
    # JAMAIS activé si l'app est joignable en direct, sinon ces en-têtes sont
    # usurpables. Cf. ``ServerConfig.trust_proxy_headers``.
    server = tornado.httpserver.HTTPServer(
        app,
        max_body_size=_HTTP_MAX_BODY_BYTES,
        xheaders=config.server.trust_proxy_headers,
    )
    if config.server.trust_proxy_headers:
        # Signal explicite au boot : la confiance aux en-têtes proxy n'est sûre
        # que si le port applicatif N'EST joignable QUE via le reverse-proxy.
        # On NE peut pas hard-guard sur ``server.host`` : en conteneur l'app
        # bind légitimement 0.0.0.0, c'est le mapping hôte (``127.0.0.1:8888``
        # dans docker-compose, invisible à l'app) qui assure l'isolation.
        # D'où ce rappel de précondition opérateur plutôt qu'un refus aveugle.
        logger.info(
            "trust_proxy_headers ACTIF : X-Forwarded-For/-Proto honorés. "
            "Le port applicatif NE DOIT être exposé QUE via le reverse-proxy "
            "de confiance (docker-compose: 127.0.0.1:8888). Une exposition "
            "directe (0.0.0.0) rendrait ces en-têtes usurpables.",
            extra={"server_host": config.server.host},
        )
    try:
        server.listen(options.port, address=config.server.host)
    except OSError as exc:
        # Port déjà utilisé (EADDRINUSE), permission refusée (EACCES), etc.
        logger.critical(
            _Messages.PORT_BIND_FAILED,
            extra={
                "port": options.port,
                "host": config.server.host,
                "errno": getattr(exc, "errno", None),
                "strerror": getattr(exc, "strerror", None),
            },
        )
        sys.exit(1)
    return server


def _install_signal_handlers(
    io_loop: tornado.ioloop.IOLoop,
    server: tornado.httpserver.HTTPServer,
    lifecycle: _ServerLifecycle,
) -> None:
    """Installe SIGTERM + SIGINT → ``lifecycle.shutdown``.

    On utilise ``signal.signal`` + ``io_loop.add_callback_from_signal``
    plutôt que ``loop.add_signal_handler`` pour deux raisons :

    1. ``add_signal_handler`` n'est pas disponible sur Windows (:func:`signal.signal`
       reste la voie cross-platform supportée par Tornado).
    2. Tornado documente explicitement ``add_callback_from_signal`` comme
       la manière thread-safe de planifier du travail depuis un signal
       handler (qui s'exécute sur le thread main, hors event-loop).
    """

    def _handle(signum: int, _frame: FrameType | None) -> None:
        logger.info("Signal reçu", extra={"signum": signum})
        io_loop.add_callback_from_signal(lifecycle.shutdown, server, io_loop)

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)


def _print_startup_banner() -> None:
    """Affiche le banner console (UX ops — pas dans les logs structurés)."""
    banner = (
        f"\n🚀 Komptia v{config.app_version}\n"
        f"   URL: http://{config.server.host}:{options.port}\n"
        f"   Environment: {config.environment}\n"
        f"   Debug: {options.debug}\n"
        f"\n   Press Ctrl+C to stop\n"
    )
    sys.stdout.write(banner)
    sys.stdout.flush()


# ─── main() ────────────────────────────────────────────────────────────────


def main() -> None:
    """Point d'entrée principal (CLI).

    Ordre critique (à ne pas changer sans tests) :

    1. ``parse_command_line()`` **avant** ``AppLogger.setup`` — sinon le
       flag ``--debug=true`` ne prend pas effet sur le niveau de log.
    2. ``AppLogger.setup`` avant toute log app — sinon les premiers logs
       utilisent le root logger par défaut (perte du formatter JSON).
    3. Init DB avant les schedulers (ils lisent la DB).
    4. Cleanup sessions AVANT le démarrage du serveur HTTP (sinon le
       premier user qui se connecte peut tomber sur une session orpheline).
    """
    # 1. Parse CLI options AVANT init logger (fix bug --debug=true).
    tornado.options.parse_command_line()

    # 2. Init logger avec la valeur effective de --debug.
    AppLogger.setup("DEBUG" if options.debug else "INFO")

    # 3. IOLoop unique (évite la double-récupération pré-refactor).
    io_loop = tornado.ioloop.IOLoop.current()

    # 4. Init DB (bloquant, critique).
    _init_database_blocking(io_loop)

    # 5. Init config Sage (best-effort).
    _init_sage_config_blocking(io_loop)

    # 6. Lifecycle manager (encapsule background tasks, periodic callbacks, shutdown).
    lifecycle = _ServerLifecycle()

    # 7. Schedulers (automations + dashboards + schema sync).
    _start_automation_schedulers(io_loop)
    _start_schema_sync_blocking(io_loop)

    # 8. Cleanup périodique des sessions (avant les tâches background).
    lifecycle.register_session_cleanup(io_loop)

    # 8b. Cleanup .tmp orphelins du datastore (atomic write — write_bytes
    # + os.replace). Si un process Python a été SIGKILL entre les deux
    # étapes, le ``.tmp`` reste sur disque. On le nettoie au boot pour
    # éviter une pollution progressive. Best-effort, fail-safe.
    try:
        from app.handlers.datastore import DATASTORE_DIR, cleanup_orphan_tmp_files

        cleanup_orphan_tmp_files(DATASTORE_DIR)
    except Exception as exc:  # noqa: BLE001 — never block boot on cleanup
        logger.warning("cleanup_orphan_tmp_files au boot a échoué: %s", exc)

    # 8c. Cleanup orphelins outputs/runs/{N} sans row pipeline_runs en BDD
    # (cf. fix #9 review adversariale — race entre flush() et commit() lors
    # d'un crash serveur peut laisser des dossiers sans row BDD).
    try:
        from app.services.ai.pipeline_runner import cleanup_orphan_run_directories

        n_orphans = io_loop.run_sync(
            cleanup_orphan_run_directories, timeout=_STARTUP_STEP_TIMEOUT_S
        )
        if n_orphans:
            logger.info("Pipeline orphan run dirs cleaned: %d", n_orphans)
    except Exception as exc:  # noqa: BLE001 — never block boot on cleanup
        logger.warning("cleanup_orphan_run_directories au boot a échoué: %s", exc)

    # 8d. Réconciliation des runs pipeline ACTIFS orphelins (A6-F2). Le
    # registre des runners est en mémoire (volatil) : après un redémarrage,
    # tout run resté pending/running est un fantôme jamais re-piloté →
    # « en cours » à vie côté UI ET inreprenable (start_resume le refuse).
    # On les marque FAILED ici, AVANT que le serveur n'écoute (étape 11),
    # donc sans race avec un nouveau run. PAUSED est exclu (resume durable).
    try:
        from app.services.ai.pipeline_runner import reconcile_orphan_runs

        n_reconciled = io_loop.run_sync(reconcile_orphan_runs, timeout=_STARTUP_STEP_TIMEOUT_S)
        if n_reconciled:
            logger.info("Pipeline orphan runs reconciled to FAILED: %d", n_reconciled)
    except Exception as exc:  # noqa: BLE001 — never block boot on reconcile
        logger.warning("reconcile_orphan_runs au boot a échoué: %s", exc)

    # 9. Préchargement LLM en background (avec strong ref, fix GC 3.12+).
    io_loop.add_callback(lambda: lifecycle.spawn_background(_preload_llm_providers()))

    # 10. Auto-diagnostic (best-effort, informatif).
    _run_startup_diagnostics_blocking(io_loop)

    # 11. Application + HTTP server.
    app = make_app()
    server = _create_and_listen(app)

    # 12. Banner console + log structuré.
    _print_startup_banner()
    logger.info(
        "Komptia démarré",
        extra={
            "version": config.app_version,
            "url": f"http://{config.server.host}:{options.port}",
            "environment": config.environment,
            "debug": options.debug,
        },
    )

    # 13. Signal handlers (SIGTERM / SIGINT).
    _install_signal_handlers(io_loop, server, lifecycle)

    # 13b. Watchdog de liveness IOLoop — si la boucle gèle (deadlock, appel
    #      synchrone bloquant, famine de ressources), il dumpe les stacks de
    #      tous les threads sur stderr puis fait sortir le process → Docker
    #      `restart: unless-stopped` (ou systemd/k8s) le relance tout seul.
    #      Démarré APRÈS le boot synchrone (les run_sync des steps 8-10 ne font
    #      pas tourner le PeriodicCallback, ce qui fausserait le battement).
    #      Incident prod 2026-06-08 : gel total (même /health muet) que Docker
    #      ne récupérait pas (un conteneur `unhealthy` n'est PAS redémarré, seul
    #      un conteneur qui *sort* l'est). Opt-out : KOMPTIA_WATCHDOG_DISABLE=1.
    from app.core.io_loop_watchdog import start_io_loop_watchdog

    start_io_loop_watchdog(io_loop)

    # 14. Boucle événementielle.
    try:
        io_loop.start()
    except KeyboardInterrupt:
        # Filet de sécurité : si Ctrl-C est pressé pendant que l'IOLoop
        # démarre (avant que les signal handlers soient câblés au niveau
        # OS), on appelle shutdown directement.
        lifecycle.shutdown(server, io_loop)


# ─── Surface publique conservée pour tests + legacy ───────────────────────

#: Instance de lifecycle partagée par :func:`shutdown` (appelée par tests
#: existants qui passent des mocks). Créée paresseusement pour ne pas
#: polluer l'état global tant que :func:`main` n'a pas démarré.
_shared_lifecycle: _ServerLifecycle | None = None


def shutdown(
    server: tornado.httpserver.HTTPServer,
    io_loop: tornado.ioloop.IOLoop,
) -> None:
    """Wrapper module-level pour compat avec ``tests/unit/test_server.py``.

    Le test ``test_graceful_shutdown_logic`` appelle ``shutdown(mock_server,
    mock_io_loop)`` et attend :

    * ``server.stop()`` appelé exactement une fois ;
    * ``io_loop.add_callback`` appelé exactement une fois.

    Le nouveau code doit préférer :meth:`_ServerLifecycle.shutdown` via
    l'instance créée dans :func:`main`.
    """
    global _shared_lifecycle
    if _shared_lifecycle is None:
        _shared_lifecycle = _ServerLifecycle()
    _shared_lifecycle.shutdown(server, io_loop)


if __name__ == "__main__":
    main()
