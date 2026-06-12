"""
Connecteur base source SQL Server
Connexion read-only à la base de données source
"""

import asyncio
import os
import platform
import time as _time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import threading

# Import conditionnel de pyodbc - permet de tester sans le driver installé
# ⚠️ IMPORTANT: pyodbc doit être importé APRÈS la configuration de OPENSSL_CONF
# pour supporter les vieux SQL Server avec TLS 1.0/1.1
try:
    # Import lazy - sera fait au moment de la première connexion
    import pyodbc

    PYODBC_AVAILABLE = True
except ImportError:
    pyodbc = None  # type: ignore
    PYODBC_AVAILABLE = False

import json
import re

from app.utils.sql_scan import strip_all_sql_comments, strip_leading_sql_comments

from app.config import DATA_DIR, config
from app.utils.logger import get_logger
from app.core.exceptions import (
    SageConnectionError,
    SageDriverMissingError,
    QueryError,
    SageQueryCancelledError,
)

logger = get_logger(__name__)

# Pool de threads pour exécuter les requêtes sync dans un contexte async
_executor: Optional[ThreadPoolExecutor] = None
_executor_lock = threading.Lock()

# Throttle : limite le nombre de requêtes SQL concurrentes vers Sage.
# Empêche les rafales (ex: 7 requêtes en <100ms) qui surchargent SQL Server.
# Le singleton get_sage_connector() garantit UNE connexion ; le sémaphore
# garantit que cette connexion n'est pas bombardée de requêtes simultanées.
_SAGE_MAX_CONCURRENT = 5
_query_semaphore: Optional[asyncio.Semaphore] = None


def _get_query_semaphore() -> asyncio.Semaphore:
    """Retourne le sémaphore global de throttling (lazy init, lié à l'event loop courant)."""
    global _query_semaphore
    if _query_semaphore is None:
        _query_semaphore = asyncio.Semaphore(_SAGE_MAX_CONCURRENT)
    return _query_semaphore


# Circuit breaker : après N échecs de connexion consécutifs, fail-fast pendant un cooldown
_CB_MAX_FAILURES = 2  # Nombre d'échecs avant ouverture du circuit
_CB_COOLDOWN_SECONDS = 60  # Durée du cooldown avant nouvelle tentative
_cb_failure_count = 0
_cb_last_failure_time: float = 0.0
_cb_half_open = False  # True = un seul essai autorisé, pas de reset complet
_cb_lock = threading.Lock()


@dataclass
class QueryResult:
    """Résultat d'une requête SQL"""

    columns: List[str]
    rows: List[Tuple[Any, ...]]
    row_count: int
    execution_time_ms: float
    truncated: bool = False  # True si max_rows atteint (il y avait plus de lignes)

    def to_dicts(self) -> List[Dict[str, Any]]:
        """Convertit les résultats en liste de dictionnaires.

        Gère les colonnes dupliquées en ajoutant un suffixe _2, _3, etc.
        """
        unique_cols = self._deduplicate_columns()
        return [dict(zip(unique_cols, row)) for row in self.rows]

    def _deduplicate_columns(self) -> List[str]:
        """Retourne les noms de colonnes avec suffixes pour les doublons."""
        seen: Dict[str, int] = {}
        result: List[str] = []
        for col in self.columns:
            if col in seen:
                seen[col] += 1
                result.append(f"{col}_{seen[col]}")
            else:
                seen[col] = 1
                result.append(col)
        return result

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le premier résultat en dictionnaire"""
        if self.rows:
            return dict(zip(self._deduplicate_columns(), self.rows[0]))
        return {}


# ── Helpers module-level : SOURCE UNIQUE pour la string ODBC ──────────────
#
# Toute l'app (SageConnector pour l'excution relle ET test_connection
# pour le bouton "Tester" sur /admin/database) DOIT passer par ces
# helpers. Sans a, le bouton "Tester" pouvait dire "KO" alors qu'Iris
# excutait avec succs (driver, Encrypt, ApplicationIntent diffrents).
# Une seule source de vrit -> un test fiable -> l'admin a confiance.


def sanitize_odbc_value(value: str) -> str:
    """Echappe une valeur arbitraire pour l'inclusion dans une conn-string ODBC.

    Stratgie dfensive (mme logique partout dans l'app) :

    1. **Refuse les caractres de contrle** (``\\x00``, ``\\r``, ``\\n``)
       qui permettraient une injection CRLF de paramtres ODBC
       supplmentaires (CWE-91). Lve ``ValueError``.
    2. **Encadre TOUJOURS de ``{}``** et **double les ``}`` internes**
       (spec Microsoft ODBC). Defense in depth : mme si la valeur ne
       contient aucun caractre spcial pour l'instant, le wrapping
       systmatique vite tout bug futur si une nouvelle version de
       pyodbc/ODBC parse diffremment.

    Lve ``ValueError`` si caractre de contrle dtect.
    """
    text = str(value)
    if "\x00" in text or "\r" in text or "\n" in text:
        raise ValueError("Caractre de contrle interdit dans les paramtres de connexion.")
    return "{" + text.replace("}", "}}") + "}"


def driver_install_hint() -> str:
    """Conseil d'installation du driver ODBC SQL Server, adapté à l'OS courant.

    Générique : l'OS est détecté dynamiquement (``platform.system()``), aucun
    environnement n'est hardcodé. Évite le piège vécu en prod où le message
    conseillait ``brew install`` (macOS) sur un serveur Linux/Docker, envoyant
    l'admin chercher le problème au mauvais endroit.
    """
    system = platform.system()
    if system == "Darwin":
        return "Sur macOS (poste de dev) : `brew install msodbcsql18`."
    if system == "Linux":
        return (
            "Sur Linux : le paquet `msodbcsql18` (Microsoft ODBC Driver 18 for SQL "
            "Server) doit être installé sur le serveur applicatif (dépôt apt "
            "Microsoft). Si Komptia tourne via l'image Docker officielle, ce paquet "
            "y est embarqué — son absence signale alors une image obsolète à "
            "reconstruire (`docker compose build --no-cache`)."
        )
    if system == "Windows":
        return (
            "Sur Windows : installer « Microsoft ODBC Driver 18 for SQL Server » "
            "depuis le site Microsoft."
        )
    return (
        "Installer le paquet `msodbcsql18` (Microsoft ODBC Driver 18 for SQL "
        "Server) sur le serveur applicatif Komptia."
    )


def discover_sage_odbc_driver() -> tuple[str, str]:
    """Retourne ``(driver_name, encrypt_option)`` pour la conn-string ODBC.

    Driver 17 prfr  Driver 18 :
    Driver 18 + OpenSSL 3.x refuse les TLS anciens (erreur 0A000102
    "unsupported protocol") mme avec ``Encrypt=Optional``, ce qui
    empche la connexion aux serveurs SQL Server anciens (Sage Coala
    notamment) qui ne supportent pas TLS 1.2+.

    Lit pyodbc via ``sys.modules.get`` pour rester mockable par les tests
    (sinon le module-level import au top fige la rfrence).

    Lve :class:`SageConnectionError` si aucun driver SQL Server install.
    """
    import sys as _sys

    pyodbc_mod = _sys.modules.get("pyodbc", pyodbc)
    if pyodbc_mod is None:
        raise SageDriverMissingError(
            "Le module Python pyodbc n'est pas disponible sur le serveur "
            f"applicatif Komptia. {driver_install_hint()}"
        )
    available = pyodbc_mod.drivers()
    if "ODBC Driver 17 for SQL Server" in available:
        return "ODBC Driver 17 for SQL Server", "no"
    if "ODBC Driver 18 for SQL Server" in available:
        return "ODBC Driver 18 for SQL Server", "Optional"
    raise SageDriverMissingError(
        "Aucun driver ODBC SQL Server installé sur le serveur applicatif Komptia. "
        "Ce n'est PAS un problème réseau ni d'identifiants : la base source est "
        "peut-être joignable, mais Komptia n'a aucun pilote pour lui parler. "
        f"{driver_install_hint()}"
    )


def build_sage_connection_string(
    host: str,
    port: int,
    database: str,
    username: str,
    password: str,
    timeout: int,
    connect_timeout: Optional[int] = None,
) -> str:
    """Assemble la conn-string ODBC pour Sage -- SOURCE UNIQUE.

    Utilise par :class:`SageConnector` (excution Iris/datastore) ET par
    ``test_connection`` (bouton "Tester" admin). Garantit que les deux
    chemins parlent EXACTEMENT au mme protocole ODBC :
    mme driver, mme ``Encrypt``, mme ``MARS_Connection``, mme
    ``Lock Timeout``. Si le test passe -> Iris passera ; si le test
    choue -> Iris chouerait identiquement.

    NE contient PAS ``ApplicationIntent=ReadOnly`` (qui exigerait un
    secondary replica AlwaysOn et faisait choir le test sur des Sage
    standalone alors que Iris -- sans ce paramtre -- passait).
    """
    driver, encrypt_opt = discover_sage_odbc_driver()

    # Overrides DSI optionnels (génériques — aucun nom de BDD hardcodé) :
    # permettent de FORCER le chiffrement du transport TDS et la validation du
    # certificat serveur (Encrypt=yes + TrustServerCertificate=no avec CA
    # importée) sur un segment où le trafic comptable ne doit pas circuler en
    # clair / sans authentification du serveur. Défauts = comportement
    # historique (Encrypt auto-détecté selon le driver, TrustServerCertificate
    # =yes). Valeurs invalides ignorées avec warning (fail-safe : on ne casse
    # pas la conn-string sur une env mal saisie).
    _allowed_encrypt = {"yes", "no", "optional", "mandatory", "strict"}
    _env_encrypt = (os.getenv("SAGE_DB_ENCRYPT") or "").strip()
    if _env_encrypt:
        if _env_encrypt.lower() in _allowed_encrypt:
            encrypt_opt = _env_encrypt.lower()
        else:
            logger.warning(
                "SAGE_DB_ENCRYPT=%r invalide (attendu : %s) — ignoré, défaut "
                "auto-détecté %r conservé.",
                _env_encrypt,
                ", ".join(sorted(_allowed_encrypt)),
                encrypt_opt,
            )
    _env_trust = (os.getenv("SAGE_DB_TRUST_SERVER_CERT") or "").strip()
    if _env_trust.lower() in {"yes", "no"}:
        trust_cert = _env_trust.lower()
    else:
        if _env_trust:
            logger.warning(
                "SAGE_DB_TRUST_SERVER_CERT=%r invalide (attendu yes|no) — "
                "défaut 'yes' conservé.",
                _env_trust,
            )
        trust_cert = "yes"

    # ``Connection Timeout`` ODBC = timeout de LOGIN (établissement de la
    # connexion), à NE PAS confondre avec le wall-clock d'exécution de requête
    # (appliqué par ``query_executor``). Si ``connect_timeout`` est fourni, on
    # l'utilise borné à ``timeout`` (inutile que le login dépasse le budget
    # requête) ; sinon fallback ``timeout`` (comportement historique pour les
    # callers qui ne le passent pas). Court → le circuit breaker Sage s'ouvre
    # vite quand le serveur est injoignable au lieu de pendre (prod 2026-06-08).
    login_timeout = max(
        1,
        int(timeout) if connect_timeout is None else min(int(connect_timeout), int(timeout)),
    )

    return (
        f"DRIVER={{{driver}}};"
        f"SERVER={sanitize_odbc_value(f'{host},{port}')};"
        f"DATABASE={sanitize_odbc_value(database)};"
        f"UID={sanitize_odbc_value(username)};"
        f"PWD={sanitize_odbc_value(password)};"
        f"Encrypt={encrypt_opt};"
        f"TrustServerCertificate={trust_cert};"
        f"Connection Timeout={login_timeout};"
        f"Lock Timeout=30;"
        f"MARS_Connection=Yes;"
    )


def _format_pyodbc_error(exc: BaseException) -> str:
    """Sérialise une exception ODBC (pyodbc.Error) ou OS en chaîne lisible.

    Single source of truth pour le formatage des erreurs SQL Server dans tout
    le connecteur Sage. Extrait le SQLSTATE et le(s) message(s) ``[SQL Server]``
    via le même regex utilisé historiquement au site ``execute() / DataError``
    (préserve « UNKNOWN » si la lib ne fournit pas de state).

    Pourquoi : avant 2026-05-26, les ``raise SageConnectionError("...message FR fixe...")``
    masquaient ``str(e)`` ODBC — l'admin/Iris voyait un message générique sans
    SQLSTATE ni cause réelle (login failed vs network vs cert vs DB introuvable).
    Le helper garantit qu'aucun raise n'oublie le détail.
    """
    try:
        if pyodbc is not None and isinstance(exc, pyodbc.Error) and exc.args:
            sql_state = exc.args[0] if exc.args else None
            server_msg = ""
            if len(exc.args) > 1:
                raw = exc.args[1] or ""
                parts = re.findall(r"\[SQL Server\]\s*(.+?)(?:\s*\(\d+\))", raw, re.DOTALL)
                if parts:
                    server_msg = " | ".join(p.strip() for p in parts if p.strip())
                else:
                    match = re.search(r"\[SQL Server\]\s*(.+)", raw, re.DOTALL)
                    if match:
                        server_msg = re.sub(r"\s*\(SQL\w+\)\s*$", "", match.group(1)).strip()
                    else:
                        server_msg = str(raw)[:500]
            if not server_msg:
                server_msg = "détail ODBC indisponible"
            label = sql_state or "UNKNOWN"
            return f"[{label}] {server_msg}"
    except Exception:  # noqa: BLE001 — defensive : ne jamais crasher l'error path
        pass
    fallback = str(exc).strip()
    if not fallback:
        fallback = type(exc).__name__
    return fallback[:500]


class SageConnector:
    """
    Connecteur pour la base de données source SQL Server

    Features:
    - Connexion read-only uniquement
    - Pool de connexions
    - Timeout configurable
    - Retry automatique
    - Async via ThreadPoolExecutor

    Usage:
        connector = SageConnector()
        await connector.connect()
        result = await connector.execute("SELECT * FROM factures WHERE id = ?", (123,))
        await connector.close()
    """

    def __init__(
        self,
        host: str = None,
        port: int = None,
        database: str = None,
        username: str = None,
        password: str = None,
        timeout: int = None,
        connect_timeout: int = None,
        max_rows: int = None,
    ):
        """
        Initialise le connecteur Sage.

        Les paramètres non fournis sont pris depuis la configuration.

        **``max_rows`` (source de vrit unique)** : ce paramtre est
        le PLAFOND GLOBAL appliqu  toutes les requtes via ce
        connecteur, dfini par l'admin sur ``/admin/database`` (colonne
        ``DatabaseConnection.max_rows``). Les callers peuvent demander
        MOINS via ``execute(max_rows=N)``, JAMAIS plus -- ``execute()``
        applique ``min(caller_max, self.max_rows)``. Le fallback
        ``config.sage.max_rows`` (env ``.env``) ne sert que pour les
        instances cres SANS DBConfig (tests, scripts standalone) ;
        en runtime normal, le singleton tire toujours sa valeur de la
        DBConfig active via ``init_sage_from_db_config`` /
        ``_reset_sage_connector``.
        """
        self.host = host or config.sage.host
        self.port = port or config.sage.port
        self.database = database or config.sage.database
        self.username = username or config.sage.username
        self.password = password or config.sage.password
        self.timeout = timeout or config.sage.timeout
        # Login timeout (court) — DISTINCT du wall-clock requête (self.timeout).
        # Cf. SageConfig.connect_timeout / build_sage_connection_string : permet
        # au circuit breaker de s'ouvrir vite quand Sage est injoignable au lieu
        # de pendre 30 s par requête (incident prod 2026-06-08).
        self.connect_timeout = (
            connect_timeout if connect_timeout is not None else config.sage.connect_timeout
        )
        # ``max_rows`` peut tre 0 valide (interdit par le check
        # constraint BDD mais defensif), donc on filtre explicitement
        # ``None`` plutt que de profiter du falsy.
        self.max_rows = max_rows if max_rows is not None else config.sage.max_rows

        # Guard: warn if constructed without credentials (likely a bug —
        # use get_sage_connector() or _get_sage_connector() instead)
        if not self.host and not self.username:
            import traceback

            logger.warning(
                "SageConnector() créé sans host ni username — "
                "les credentials par défaut sont probablement vides. "
                "Utilisez get_sage_connector() ou _get_sage_connector(). "
                "Appelé depuis: %s",
                "".join(traceback.format_stack()[-3:-1]).strip(),
            )

        self._connection: Optional[pyodbc.Connection] = None
        self._connected = False
        # Marqueur instance singleton -- mis a True UNIQUEMENT par
        # ``get_sage_connector()`` apres creation. Le guard
        # ``[CONFIG_MANQUANTE]`` ne s'applique qu'au singleton (les
        # instances cres manuellement par tests/scripts conservent
        # leur propre logique de credentials). Plus robuste que
        # ``self is _sage_connector`` (qui casse au switch SQLite).
        self._is_singleton: bool = False

    @property
    def is_connected(self) -> bool:
        """True si la connexion à Sage est active."""
        return self._connected

    @staticmethod
    def _sanitize_conn_value(value: str) -> str:
        """Échappe les accolades dans une valeur de connection string ODBC.

        Wrapper autour de :func:`sanitize_odbc_value` (module-level). Conserv
        comme staticmethod pour la compat ascendante des tests.
        """
        return sanitize_odbc_value(value)

    @property
    def connection_string(self) -> str:
        """Génère la chaîne de connexion ODBC pour cette instance.

        Dlgue  :func:`build_sage_connection_string` (helper module-level)
        pour qu'il y ait UNE SEULE fonction qui construit cette string dans
        toute l'app -- ainsi le bouton "Tester" sur ``/admin/database`` et
        l'excution relle Iris/datastore utilisent EXACTEMENT la mme
        configuration ODBC. Pas de divergence possible (driver prfr,
        Encrypt, ApplicationIntent, etc.).
        """
        return build_sage_connection_string(
            host=self.host,
            port=self.port,
            database=self.database,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            connect_timeout=self.connect_timeout,
        )

    def _get_executor(self) -> ThreadPoolExecutor:
        """Retourne le pool de threads (lazy init)"""
        global _executor
        if _executor is None:
            with _executor_lock:
                if _executor is None:  # Double-check pattern
                    _executor = ThreadPoolExecutor(max_workers=config.database.pool_size)
        return _executor

    async def connect(self) -> None:
        """
        Établit la connexion à SQL Server avec circuit breaker.

        States:
        - CLOSED: _cb_failure_count < _CB_MAX_FAILURES → connexion normale
        - OPEN: _cb_failure_count >= _CB_MAX_FAILURES et cooldown pas écoulé → fail-fast
        - HALF-OPEN: cooldown écoulé → un seul essai autorisé

        Raises:
            SageConnectionError: Si la connexion échoue ou pyodbc non disponible
        """
        global _cb_failure_count, _cb_last_failure_time, _cb_half_open

        if not PYODBC_AVAILABLE:
            raise SageDriverMissingError(
                "Le module Python pyodbc n'est pas disponible sur le serveur "
                f"applicatif Komptia. {driver_install_hint()}"
            )

        if self._connected:
            return

        # Guard /admin/database : si aucune connexion n'est configurée
        # via la page admin, on refuse net AVANT de toucher au circuit
        # breaker ou à pyodbc. Le check ``self._is_singleton`` restreint
        # le guard au SINGLETON global -- une instance créée manuellement
        # (test, script standalone) avec ses propres creds n'est PAS
        # bloquée. Plus robuste que ``self is _sage_connector`` qui
        # casse pendant les windows de switch SQLite/SQLServer ou si
        # quelqu'un cache une référence à l'ancien singleton.
        if _unconfigured and getattr(self, "_is_singleton", False):
            raise SageConnectionError(
                "[CONFIG_MANQUANTE] Aucune connexion à la base source n'est "
                "configurée. Allez sur /admin/database, créez une connexion "
                "et activez-la pour autoriser l'exécution SQL."
            )

        # Pré-vol driver ODBC : l'absence de pilote SQL Server est une faute de
        # DÉPLOIEMENT (image/serveur applicatif Komptia), PAS une panne réseau.
        # On la détecte AVANT le circuit breaker pour (a) ne pas la masquer
        # derrière « injoignable / patientez » si le breaker est déjà ouvert, et
        # (b) ne pas faire tripper le breaker sur une faute permanente qui ne se
        # rétablira pas seule. Lève SageDriverMissingError → propagée telle quelle
        # (message précis, sans relabel « réseau/auth », sans incrément breaker).
        discover_sage_odbc_driver()

        # Circuit breaker : vérifier l'état avant de tenter la connexion
        with _cb_lock:
            if _cb_failure_count >= _CB_MAX_FAILURES:
                elapsed = _time.monotonic() - _cb_last_failure_time
                if elapsed < _CB_COOLDOWN_SECONDS:
                    remaining = int(_CB_COOLDOWN_SECONDS - elapsed)
                    raise SageConnectionError(
                        f"[CONNEXION_IMPOSSIBLE] Le serveur SQL Server est injoignable "
                        f"(circuit breaker ouvert après {_cb_failure_count} échecs). "
                        f"Prochaine tentative dans {remaining}s. "
                        f"NE PAS reformuler la requête SQL — c'est un problème réseau, "
                        f"pas un problème de requête. Informe l'utilisateur."
                    )
                elif _cb_half_open:
                    # Already in half-open with a probe in flight — block concurrent attempts
                    raise SageConnectionError(
                        "[CONNEXION_IMPOSSIBLE] Tentative de reconnexion en cours "
                        "(circuit breaker half-open). Patientez."
                    )
                else:
                    # Cooldown écoulé → passer en half-open (1 seul essai)
                    _cb_half_open = True
                    logger.info("Circuit breaker Sage: half-open, tentative de reconnexion")

        # Login timeout (court) — borné < au wall-clock requête de query_executor
        # pour que la connexion échoue AVANT l'annulation et ouvre le breaker
        # (incident prod 2026-06-08). MÊME valeur pour le kwarg pyodbc, le
        # ``Connection Timeout`` de la conn-string ET le wait_for asyncio ci-dessous.
        login_timeout = max(1, min(self.connect_timeout, self.timeout))

        def _connect():
            try:
                conn = pyodbc.connect(
                    self.connection_string,
                    # Login timeout (court). PAS ``self.timeout`` (wall-clock requête).
                    timeout=login_timeout,
                    autocommit=True,  # Read-only, pas besoin de transactions
                )
                # Vérifier la connexion
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.close()
                return conn
            except pyodbc.Error as e:
                logger.error("Erreur pyodbc connect: %s", e)
                raise SageConnectionError(
                    f"Impossible de se connecter à Sage — erreur ODBC : "
                    f"{_format_pyodbc_error(e)}"
                ) from e

        try:
            loop = asyncio.get_running_loop()
            # Defense in depth (finding adversarial #1) : on borne le login au
            # niveau asyncio EN PLUS du ``Connection Timeout`` ODBC. Si le driver
            # ignorait son timeout et que le socket TCP pendait (firewall SYN-drop),
            # ce wait_for coupe quand même à ``login_timeout`` → l'échec remonte en
            # TimeoutError COMPTÉ par le breaker (cf. except plus bas), au lieu d'un
            # hang qui ne l'ouvre jamais. Le thread _connect sous-jacent (non
            # cancellable) reste vivant jusqu'au timeout TCP OS, mais le breaker
            # ouvert évite d'en spawner d'autres (× N widgets dashboard).
            self._connection = await asyncio.wait_for(
                loop.run_in_executor(self._get_executor(), _connect),
                timeout=login_timeout,
            )
            self._connected = True
            # Connexion réussie : reset complet du circuit breaker
            with _cb_lock:
                _cb_failure_count = 0
                _cb_half_open = False
            logger.info(
                "✅ Connecté à %s",
                self.database,
                extra={"host": self.host, "database": self.database},
            )
        except SageDriverMissingError:
            # Faute de DÉPLOIEMENT (driver ODBC absent), pas une panne réseau
            # transitoire : NE PAS toucher le circuit breaker et NE PAS clobber
            # le diagnostic précis avec « réseau ou authentification ». Défense en
            # profondeur — le pré-vol ci-dessus l'attrape déjà en temps normal,
            # ce garde couvre tout chemin où le driver disparaîtrait entre le
            # pré-vol et pyodbc.connect (re-discovery dans la conn-string).
            raise
        except asyncio.TimeoutError as e:
            # Login timeout dépassé au niveau asyncio (defense in depth, finding
            # adversarial #1). Échec de connexion RÉEL → incrémenter le breaker
            # pour qu'il s'ouvre (sinon, si le TCP pend au-delà du ``Connection
            # Timeout`` ODBC, le hang reviendrait sans jamais ouvrir le breaker).
            # ⚠️ En Python 3.11+ ``asyncio.TimeoutError`` EST ``TimeoutError``
            # (sous-classe d'``OSError``), donc cette clause DOIT précéder le
            # ``except (..., OSError, ...)`` ci-dessous pour ne pas être masquée ;
            # sur 3.10 c'est une classe distincte, d'où la clause explicite.
            # NB : on ne catch PAS ``asyncio.CancelledError`` (annulation externe,
            # ex. déconnexion navigateur) → pas de faux positif breaker.
            with _cb_lock:
                _cb_failure_count += 1
                _cb_last_failure_time = _time.monotonic()
                _cb_half_open = False
                logger.error(
                    "❌ Timeout de connexion Sage après %ss (%d/%d)",
                    login_timeout,
                    _cb_failure_count,
                    _CB_MAX_FAILURES,
                )
            raise SageConnectionError(
                f"[CONNEXION_IMPOSSIBLE] Délai de connexion au serveur SQL Server "
                f"dépassé ({login_timeout}s). Si la base est joignable mais lente "
                f"(LAN saturé, handshake TLS ancien sur un serveur d'époque), "
                f"augmentez SAGE_DB_CONNECT_TIMEOUT ; sinon la base est injoignable "
                f"(réseau/firewall). NE PAS reformuler la requête SQL — c'est un "
                f"problème de connexion serveur."
            ) from e
        except (pyodbc.Error, OSError, SageConnectionError) as e:
            # Échec : incrémenter le circuit breaker
            with _cb_lock:
                _cb_failure_count += 1
                _cb_last_failure_time = _time.monotonic()
                _cb_half_open = False  # Reset half-open flag
                logger.error(
                    "❌ Erreur connexion Sage (%d/%d)",
                    _cb_failure_count,
                    _CB_MAX_FAILURES,
                    exc_info=True,
                )
            raise SageConnectionError(
                "[CONNEXION_IMPOSSIBLE] Impossible de se connecter au serveur SQL Server. "
                "Erreur réseau ou d'authentification. "
                f"Détail : {_format_pyodbc_error(e)}. "
                "NE PAS reformuler la requête SQL — c'est un problème de connexion serveur. "
                "Informe l'utilisateur que la base source n'est pas accessible."
            ) from e

    async def close(self) -> None:
        """Ferme la connexion"""
        if self._connection:
            try:
                self._connection.close()
            except (pyodbc.Error, OSError) as e:
                # P5.1 (audit 2026-05-26) — Promu DEBUG → WARNING : un close
                # qui échoue laisse une connexion zombie côté SQL Server +
                # un descripteur réseau côté Python. Sans visibilité prod,
                # leak progressif détectable uniquement par sysadmin SQL Server
                # ("trop de connexions ouvertes"). WARNING est le bon niveau :
                # l'app continue (on annule l'état interne ligne suivante),
                # mais l'admin doit savoir.
                logger.warning("Erreur fermeture connexion Sage: %s", e)
            self._connection = None
            self._connected = False
            logger.info("Connexion Sage fermée")

    async def execute(
        self,
        query: str,
        params: Tuple[Any, ...] = None,
        max_rows: int = None,
        bypass_admin_cap: bool = False,
        *,
        cancel_event: Optional["asyncio.Event"] = None,
    ) -> QueryResult:
        """
        Exécute une requête SQL et retourne les résultats.

        Args:
            query: Requête SQL (SELECT uniquement).
            params: Paramètres de la requête (tuple).
            max_rows: Cap demand par le caller. Doit tre ``None`` ou
                un int ``>= 1`` (un ``0`` est rejet par ValueError car
                il signalerait silencieusement "rendez-moi le plafond
                admin", masquant un bug du caller). Le rsultat effectif
                est ``min(max_rows, self.max_rows)`` SAUF si
                ``bypass_admin_cap=True``.
            bypass_admin_cap: ``True`` UNIQUEMENT pour les internals
                non-user-visible (RAG enricher, schema sync, sync de
                valeurs distinctes pour l'index de recherche). Ces
                callers ont un besoin lgitime de tout rcuprer
                indpendamment du plafond UX que l'admin met sur
                /admin/database. Documenter chaque call-site qui passe
                ``True``. Par dfaut ``False`` -- l'admin contrle.
            cancel_event: **Task #9 (2026-05-22)** — si fourni et set
                pendant l'exécution, le cursor pyodbc est cancellé via
                ``cursor.cancel()`` (thread-safe, envoie SQLCancel à
                SQL Server). La requête remonte alors
                :class:`SageQueryCancelledError` au lieu d'un
                ``QueryResult`` — aucun résultat partiel n'est retourné.
                Si l'event fire APRÈS que la requête soit terminée
                (race), le résultat normal est retourné (pas de cancel
                a posteriori — la requête a déjà payé son coût Sage).

        Returns:
            QueryResult avec colonnes, lignes et métadonnées

        Raises:
            ValueError: Si ``max_rows`` est <= 0 (caller bug).
            QueryError: Si la requête échoue.
            SageConnectionError: Si pas connecté ou pas de config admin.
            SageQueryCancelledError: Si ``cancel_event`` fire avant la
                fin de l'exécution (Task #9, 2026-05-22).
        """
        # Validation stricte : un caller qui passe 0 a un bug -- ne pas
        # le masquer en retombant silencieusement sur le plafond admin.
        if max_rows is not None and max_rows < 1:
            raise ValueError(
                f"max_rows doit tre >= 1 (recu : {max_rows}). "
                "Un caller qui veut 0 ligne ne devrait pas appeler execute()."
            )

        if not self._connected:
            await self.connect()

        # Resolution du cap final :
        # - bypass_admin_cap=True (internals) -> on respecte le caller tel quel
        #   (ou ``self.max_rows`` si caller None, ce qui sera de toute faon
        #   une upper bound raisonnable pour les internals)
        # - sinon : ``min(caller, self.max_rows)`` -- /admin/database est
        #   l'UNIQUE source de vrit du plafond global
        if bypass_admin_cap:
            effective_max_rows = max_rows if max_rows is not None else self.max_rows
        elif max_rows is not None:
            effective_max_rows = min(max_rows, self.max_rows)
        else:
            effective_max_rows = self.max_rows
        max_rows = effective_max_rows

        # Defense en profondeur du guard /admin/database :
        # ``connect()`` lve dj ``[CONFIG_MANQUANTE]`` quand le
        # singleton est marqu unconfigured, mais ``execute()`` skip
        # ``connect()`` si ``self._connected`` est dj True (cas :
        # connexion ouverte AVANT que l'admin desactive sa config).
        # On re-check ici pour bloquer la requete quoi qu'il arrive.
        if _unconfigured and getattr(self, "_is_singleton", False):
            raise SageConnectionError(
                "[CONFIG_MANQUANTE] Aucune connexion à la base source n'est "
                "configurée. Allez sur /admin/database, créez une connexion "
                "et activez-la pour autoriser l'exécution SQL."
            )

        # Sécurité: vérifier que c'est bien un SELECT (ou CTE WITH...SELECT)
        query_body = strip_leading_sql_comments(query.strip())
        query_upper = query_body.upper()
        # Exception : les sondes de validation read-only de l'oracle Iris
        # (``SET PARSEONLY ON; <SELECT>; SET PARSEONLY OFF;`` et l'équivalent
        # ``SET FMTONLY``) commencent par SET, pas par SELECT. Sans cette
        # exception, l'oracle de ``validate_for_iris`` se bloquait lui-même →
        # TOUTE requête Iris était faussement rejetée ``SYNTAX_INVALID``
        # (incident log 2026-05-29).
        #
        # SÉCURITÉ — ne PAS supposer que les deux directives sont inertes :
        #   • ``SET PARSEONLY ON`` rend le batch INERTE (SQL Server parse, n'exécute rien).
        #   • ``SET FMTONLY ON`` ne supprime QUE les lignes du résultat — les
        #     effets de bord d'un write S'EXÉCUTERAIENT. Le vrai garde pour la
        #     sonde FMTONLY est donc la boucle ``dangerous_keywords`` ci-dessous
        #     (LOAD-BEARING) : elle scanne tout le batch et bloque write/DDL AVANT
        #     exécution. Elle est tenue alignée sur ``_VALIDATOR_WRITE_PATTERN``.
        # Pour le chemin Iris, le SQL interne a en plus déjà passé les gardes
        # Phase 1 de ``validate_for_iris`` AVANT que l'oracle ne l'enveloppe.
        _is_validation_probe = query_upper.startswith("SET PARSEONLY") or query_upper.startswith(
            "SET FMTONLY"
        )
        if not (
            query_upper.startswith("SELECT")
            or query_upper.startswith("WITH")
            or _is_validation_probe
        ):
            raise QueryError("Seules les requêtes SELECT sont autorisées")

        # Bloquer les requêtes dangereuses (recherche par mots entiers).
        # MIROIR de ``_VALIDATOR_WRITE_PATTERN`` (app/services/ai/sql_validator.py) :
        # ces deux listes DOIVENT rester alignées — le connecteur est le backstop
        # load-bearing des sondes FMTONLY de l'oracle (cf. commentaire SÉCURITÉ
        # ci-dessus). Renforcé 2026-05-29 : ajout MERGE/EXECUTE/BACKUP/RESTORE/
        # GRANT/REVOKE/SHUTDOWN/WAITFOR (review adversariale — drift denylist).
        dangerous_keywords = [
            "INSERT",
            "UPDATE",
            "DELETE",
            "DROP",
            "TRUNCATE",
            "ALTER",
            "CREATE",
            "EXEC",
            "EXECUTE",
            "MERGE",
            "BACKUP",
            "RESTORE",
            "GRANT",
            "REVOKE",
            "SHUTDOWN",
            "WAITFOR",
        ]

        for keyword in dangerous_keywords:
            # Recherche par mot entier (boundaries)
            pattern = r"\b" + re.escape(keyword) + r"\b"
            if re.search(pattern, query_upper):
                raise QueryError(f"Mot-clé interdit détecté: {keyword}")

        # Task #9 (2026-05-22) — cursor holder partagé entre le thread
        # d'exécution et l'asyncio loop. Le thread push le cursor dans
        # ``cursor_holder[0]`` dès création ; si cancel_event fire, l'asyncio
        # loop lit ``cursor_holder[0]`` et appelle ``cursor.cancel()``
        # (pyodbc.Cursor.cancel est documenté thread-safe — envoie SQLCancel).
        # La liste est utilisée comme container mutable cross-thread (GIL
        # protège l'assignation d'attribut int sur list — pas besoin de Lock).
        cursor_holder: List[Optional[Any]] = [None]

        def _execute():
            start_time = _time.perf_counter()
            cursor = self._connection.cursor()
            cursor_holder[0] = cursor

            # Strip ALL SQL comments avant binding paramètres (chantier T6).
            # Certains drivers (pyodbc qmark) parsent les `?` dans les
            # commentaires comme placeholders → bug silencieux observé en
            # log 2026-05-10. Cf. `strip_all_sql_comments` docstring.
            sanitized_query = strip_all_sql_comments(query)

            try:
                if params:
                    cursor.execute(sanitized_query, params)
                else:
                    cursor.execute(sanitized_query)

                # Récupérer les colonnes
                columns = [desc[0] for desc in cursor.description] if cursor.description else []

                # Récupérer les lignes (avec limite)
                rows = cursor.fetchmany(max_rows)

                # Détecter si les résultats ont été tronqués
                # #65 (A8-F1) — Détecter la troncature SANS faux positif.
                # ``len(rows) >= max_rows`` était FAUX quand le résultat fait
                # EXACTEMENT max_rows (complet) : l'user voyait « tronqué » sur un
                # résultat intégral (données fausses silencieuses).
                # ``fetchmany(max_rows)`` ne retourne JAMAIS plus de max_rows :
                #   - len(rows) <  max_rows  ⇒ résultat complet (jamais tronqué)
                #   - len(rows) == max_rows  ⇒ AMBIGU → tranché par le DRAIN
                #     ci-dessous (seul un reste NON VIDE prouve qu'il y avait plus
                #     de lignes au-delà du cap).
                was_truncated = False
                drained_cleanly = False

                # Drainer les résultats restants pour libérer la connexion ET
                # sonder la troncature (cf. #65 ci-dessus).
                # fetchmany(max_rows) ne consomme qu'une partie des résultats ;
                # sans drain, la prochaine requête sur la même connexion échoue
                # avec "Connection is busy with results for another command".
                # MARS_Connection=Yes dans la connection string résout aussi ce
                # problème, mais drainer reste une bonne pratique défensive.
                try:
                    while True:
                        extra = cursor.fetchmany(10000)
                        if not extra:
                            drained_cleanly = True  # fin de résultats atteinte
                            break
                        # ≥1 ligne au-delà du cap → vraiment tronqué.
                        was_truncated = True
                except (pyodbc.Error, pyodbc.ProgrammingError):
                    pass  # Erreur I/O pendant le drain — acceptable

                # #65 — Fail-closed sur l'incertitude : si le drain n'a PAS atteint
                # proprement la fin (erreur I/O avant epuisement) ET qu'on est pile
                # au cap, on ne peut pas PROUVER la complétude → signaler tronqué
                # plutot qu'affirmer a tort « complet » (donnees fausses silencieuses).
                if not drained_cleanly and not was_truncated and len(rows) >= max_rows:
                    was_truncated = True

                execution_time = (_time.perf_counter() - start_time) * 1000

                return QueryResult(
                    columns=columns,
                    rows=rows,
                    row_count=len(rows),
                    execution_time_ms=execution_time,
                    truncated=was_truncated,
                )
            finally:
                # Clear le holder AVANT de close pour qu'un cancel tardif ne
                # voie pas un cursor déjà closed (le check None bypasse le call).
                cursor_holder[0] = None
                cursor.close()

        async def _cancel_watcher():
            """Task #9 — fire cursor.cancel() côté Sage si l'user clique Stop.

            Wait sur ``cancel_event``, puis lit le cursor du holder et
            appelle ``.cancel()``. pyodbc cancel est documenté SQLCancel-safe
            sur la plupart des drivers ODBC (msodbcsql18 OK, autres TODO E2E).
            Si le cursor a été closed entre-temps (race avec finally de
            _execute), le holder vaut None → no-op.

            **Fix BLOCKING #2 adversarial session 18 (2026-05-22)** :
            ``cancel_event`` est partagé entre tool calls séquentiels via
            ``context["_cancel_event"]`` (agent_service.py:4204) → violation
            du contrat « event consumable UNE FOIS » documenté session 12.
            Si l'event est déjà set AVANT le démarrage de cette exec, c'est
            qu'un tool call PRÉCÉDENT (streaming LLM ou autre execute_sql)
            l'a consommé sans clear. On NE doit PAS cancel cette nouvelle
            exec — sinon faux cancel silencieux. Gate pré-exec ci-dessous.
            """
            if cancel_event is None:
                return
            if cancel_event.is_set():
                # Event déjà set avant que cette exec démarre — un tool
                # call précédent a consommé le Stop sans clear. Ne pas
                # cancel cette nouvelle exec.
                logger.warning(
                    "Sage execute: cancel_event déjà set au démarrage (héritage "
                    "d'un tool call précédent qui n'a pas clear()). Ne PAS "
                    "cancel cette exec — faux positif. Le caller devrait "
                    "clear() entre tools séquentiels (cf. agent_service.py:2270)."
                )
                return
            await cancel_event.wait()
            c = cursor_holder[0]
            if c is None:
                # Race : l'exec a fini juste avant le cancel — rien à faire
                logger.debug(
                    "Sage execute: cancel_event fire mais cursor déjà closed (race normale)"
                )
                return
            try:
                c.cancel()
                logger.info(
                    "Sage execute: cancellation forwarded to pyodbc cursor (SQLCancel)"
                )
            except Exception as _cancel_exc:  # noqa: BLE001 — defense in depth
                logger.warning(
                    "Sage execute: cursor.cancel() a levé : %s (cursor peut-être déjà closed)",
                    _cancel_exc,
                )

        # Throttle : le sémaphore global limite les requêtes concurrentes vers Sage.
        # Empêche les rafales (ex: asyncio.gather sur 50 fill_sql) de bombarder SQL Server.
        async with _get_query_semaphore():
            try:
                loop = asyncio.get_running_loop()
                exec_task: asyncio.Future = loop.run_in_executor(
                    self._get_executor(), _execute
                )
                # Task #9 — racer exec vs cancel. Si pas de cancel_event,
                # comportement identique à l'avant-fix (await direct).
                if cancel_event is not None:
                    cancel_task = asyncio.create_task(_cancel_watcher())
                    try:
                        done, _pending = await asyncio.wait(
                            {exec_task, cancel_task},
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        if cancel_task in done and exec_task not in done:
                            # Cancel a fire AVANT que exec ne termine.
                            # cursor.cancel() a déjà été appelé dans le
                            # watcher. Maintenant on attend que exec_task
                            # remonte l'exception pyodbc déclenchée par
                            # SQLCancel (généralement OperationalError),
                            # OU termine normalement si le cancel est arrivé
                            # juste après que fetch ait fini (race rare).
                            #
                            # **Fix BLOCKING #3 adversarial session 18** :
                            # si exec_task termine avec un RÉSULTAT (pas
                            # exception), c'est que le cancel est arrivé
                            # APRÈS la fin réelle de la requête. Le résultat
                            # est COMPLET (pas partiel). On le retourne avec
                            # warning au lieu de le jeter — l'user a payé
                            # le coût Sage, autant rendre la donnée.
                            try:
                                _race_result = await exec_task
                            except (pyodbc.Error, OSError) as _cancel_pyodbc_exc:
                                raise SageQueryCancelledError(
                                    "Requête SQL annulée par l'utilisateur"
                                ) from _cancel_pyodbc_exc
                            else:
                                logger.warning(
                                    "Sage execute: cancel_event fire APRÈS la "
                                    "fin réelle de la requête — résultat COMPLET "
                                    "retourné (rows=%d, time_ms=%.0f). Pas de "
                                    "jet inutile.",
                                    _race_result.row_count,
                                    _race_result.execution_time_ms,
                                )
                                return _race_result
                        else:
                            # Exec a fini avant cancel — cleanup le watcher
                            # et propage le résultat normal.
                            cancel_task.cancel()
                            try:
                                await cancel_task
                            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                                pass
                            result = exec_task.result()
                    except SageQueryCancelledError:
                        # Propager — cleanup automatique du watcher
                        if not cancel_task.done():
                            cancel_task.cancel()
                        raise
                else:
                    result = await exec_task

                logger.debug(
                    "Query executed",
                    extra={
                        "rows": result.row_count,
                        "time_ms": result.execution_time_ms,
                        "query": query[:100],  # Log partiel pour debug
                    },
                )

                return result

            except (pyodbc.DataError, pyodbc.ProgrammingError, pyodbc.IntegrityError) as e:
                # Erreurs SQL (mauvaise requête, type mismatch, violation contrainte)
                # PAS une connexion stale — pas besoin de reconnexion
                logger.warning(
                    "Erreur SQL (requête invalide)",
                    extra={"query": query[:200]},
                    exc_info=True,
                )
                # Extract SQL state code and meaningful SQL Server message.
                # pyodbc: ('SQLSTATE', '[...][SQL Server]Msg1 (N) [...][SQL Server]Msg2 (N) (Driver)')
                # SQL Server often chains multiple messages (e.g. syntax error + "could not be prepared").
                sql_state = e.args[0] if e.args else None
                server_msg = ""
                if len(e.args) > 1:
                    raw = e.args[1]
                    # Extract ALL [SQL Server] messages (may be concatenated or multi-line).
                    parts = re.findall(r"\[SQL Server\]\s*(.+?)(?:\s*\(\d+\))", raw, re.DOTALL)
                    if parts:
                        server_msg = " | ".join(p.strip() for p in parts if p.strip())
                    else:
                        # Fallback: single message without error code
                        m = re.search(r"\[SQL Server\]\s*(.+)", raw, re.DOTALL)
                        if m:
                            msg = re.sub(r"\s*\(SQL\w+\)\s*$", "", m.group(1))
                            server_msg = msg.strip()
                        else:
                            server_msg = raw
                if not server_msg:
                    server_msg = "requête invalide"
                raise QueryError(f"Erreur SQL ({sql_state or 'UNKNOWN'}): {server_msg}")
            except (pyodbc.Error, OSError) as conn_exc:
                if self._connected:
                    # Connexion probablement stale — réinitialiser et réessayer une fois
                    logger.warning("Connexion Sage stale, tentative de reconnexion", exc_info=True)
                    with _cb_lock:
                        self._connected = False
                        self._connection = None
                    try:
                        await self.connect()
                    except SageConnectionError:
                        # connect() a déjà mis à jour le circuit breaker et le message
                        raise  # Propager SageConnectionError directement (pas QueryError)
                    try:
                        result = await loop.run_in_executor(self._get_executor(), _execute)
                        return result
                    except (pyodbc.Error, OSError) as retry_exc:
                        logger.error(
                            "Erreur SQL après reconnexion",
                            extra={"query": query[:200]},
                            exc_info=True,
                        )
                        raise QueryError(
                            f"Erreur d'exécution SQL après reconnexion : "
                            f"{_format_pyodbc_error(retry_exc)}"
                        ) from retry_exc
                logger.error("Erreur SQL", extra={"query": query[:200]}, exc_info=True)
                raise QueryError(
                    f"Erreur de connexion SQL Server : {_format_pyodbc_error(conn_exc)}"
                ) from conn_exc

    async def execute_write(
        self,
        sql: str,
        params: Tuple[Any, ...] = None,
        dry_run: bool = True,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """Exécute une écriture SQL (INSERT/UPDATE/DELETE) en transaction.

        **Pré-condition** : ``sql`` DOIT déjà avoir passé
        ``app.services.database.write_validator.parse_and_validate_write()``.
        Cette méthode ne re-parse pas l'AST (le validateur l'a déjà fait
        et l'a normalisé). En revanche, elle bloque les SELECT pour
        défense en profondeur (pas de confusion avec ``execute()``).

        Args:
            sql: Single statement INSERT/UPDATE/DELETE T-SQL.
            params: Paramètres positionnels (placeholders ``?``).
            dry_run: Si True, exécute en transaction puis ROLLBACK
                (rapporte ``rows_affected`` sans persistance). Utilisé
                pour estimer l'impact AVANT envoi du mail au DBA.
            timeout: Inutilisé pour pyodbc (timeout est sur la connexion).

        Returns:
            Dict :
                - ``rows_affected`` (int) : nombre de lignes touchées
                - ``duration_ms`` (float)
                - ``dry_run`` (bool)
                - ``sql_executed`` (str) : SQL effectivement passé

        Raises:
            SageConnectionError: pas connecté / config manquante.
            QueryError: SQL invalide ou erreur runtime (rollback automatique).
        """
        del timeout  # noqa: ARG002 — pyodbc timeout est connection-level

        if not self._connected:
            await self.connect()

        # Defense en profondeur du guard /admin/database (idem execute())
        if _unconfigured and getattr(self, "_is_singleton", False):
            raise SageConnectionError(
                "[CONFIG_MANQUANTE] Aucune connexion à la base source n'est "
                "configurée. Allez sur /admin/database, créez une connexion "
                "et activez-la pour autoriser l'exécution SQL."
            )

        # Sécurité : refuser tout SELECT (qui doit passer par execute()).
        # Le validateur AST a déjà refusé multi-stmt/DDL/etc., on couvre
        # juste le cas où ce code serait appelé sans validation préalable.
        body = strip_leading_sql_comments(sql.strip()).upper()
        if body.startswith("SELECT") or body.startswith("WITH"):
            raise QueryError("execute_write() refuse les SELECT — utilisez execute().")

        def _execute_write_sync() -> Dict[str, Any]:
            start_time = _time.perf_counter()
            previous_autocommit = self._connection.autocommit
            # autocommit=False force un BEGIN TRANSACTION implicite côté
            # pyodbc/SQL Server. On peut alors commit() ou rollback()
            # explicitement selon dry_run.
            self._connection.autocommit = False
            cursor = self._connection.cursor()
            # Strip ALL SQL comments (chantier T6) — même rationale que
            # execute() : pyodbc qmark interprète `?` dans commentaires.
            sanitized_sql = strip_all_sql_comments(sql)
            try:
                if params:
                    cursor.execute(sanitized_sql, params)
                else:
                    cursor.execute(sanitized_sql)
                rows_affected = int(cursor.rowcount or 0)

                if dry_run:
                    self._connection.rollback()
                else:
                    self._connection.commit()

                return {
                    "rows_affected": rows_affected,
                    "duration_ms": (_time.perf_counter() - start_time) * 1000,
                    "dry_run": dry_run,
                    "sql_executed": sql,
                }
            except Exception:
                # Rollback systématique en cas d'erreur — ne pas laisser
                # de transaction ouverte qui bloquerait les futurs writes.
                try:
                    self._connection.rollback()
                except (pyodbc.Error, OSError) as rollback_exc:
                    # P5.1 (audit 2026-05-26) — Promu silent pass → WARNING :
                    # un rollback raté = transaction zombie côté SQL Server
                    # qui peut verrouiller des rows / bloquer les commits
                    # suivants jusqu'à kill manuel. Très rare mais critique
                    # quand ça arrive — l'admin DOIT savoir.
                    logger.warning(
                        "execute_write rollback() a échoué — transaction "
                        "potentiellement zombie sur le serveur SQL : %s",
                        rollback_exc,
                    )
                raise
            finally:
                # Cleanup robuste : chaque statement du finally doit pouvoir
                # s'exécuter même si le précédent lève (déconnexion réseau,
                # pyodbc.Error, OSError). Sans ces try/except, le drift
                # autocommit reste à False sur le singleton et toutes les
                # requêtes suivantes ouvrent une transaction implicite jamais
                # commitée — symptôme silencieux « Sage devient lent ».
                try:
                    cursor.close()
                except Exception:
                    logger.warning(
                        "execute_write: cursor.close failed during cleanup",
                        exc_info=True,
                    )
                try:
                    self._connection.autocommit = previous_autocommit
                except Exception:
                    # Mark connection stale → force reconnect au prochain
                    # appel via le guard ``if not self._connected: await
                    # self.connect()``. Sans mark-stale, le singleton garde
                    # un état autocommit inconnu côté serveur et toutes les
                    # queries suivantes peuvent ouvrir des transactions
                    # implicites jamais commitées — drift silencieux Sage.
                    # Pattern miroir de ``_explain_sync`` (lignes 984-986
                    # et 1003-1005) qui applique le même contrat fail-closed
                    # + auto-recover.
                    logger.warning(
                        "execute_write: autocommit restore failed during cleanup — "
                        "marking connection stale to force reconnect",
                        exc_info=True,
                    )
                    with _cb_lock:
                        self._connected = False
                        self._connection = None

        async with _get_query_semaphore():
            try:
                loop = asyncio.get_running_loop()
                return await loop.run_in_executor(self._get_executor(), _execute_write_sync)
            except (
                pyodbc.DataError,
                pyodbc.ProgrammingError,
                pyodbc.IntegrityError,
            ) as exc:
                # Erreur SQL côté serveur (mauvaise syntaxe, contrainte FK
                # violée, type incompatible, etc.). Rollback déjà fait dans
                # _execute_write_sync.
                logger.warning(
                    "execute_write SQL error",
                    extra={"sql": sql[:200], "dry_run": dry_run},
                    exc_info=True,
                )
                sql_state = exc.args[0] if exc.args else None
                server_msg = ""
                if len(exc.args) > 1:
                    raw = exc.args[1]
                    parts = re.findall(r"\[SQL Server\]\s*(.+?)(?:\s*\(\d+\))", raw, re.DOTALL)
                    if parts:
                        server_msg = " | ".join(p.strip() for p in parts if p.strip())
                    else:
                        m = re.search(r"\[SQL Server\]\s*(.+)", raw, re.DOTALL)
                        server_msg = (
                            re.sub(r"\s*\(SQL\w+\)\s*$", "", m.group(1)).strip() if m else raw[:500]
                        )
                if not server_msg:
                    server_msg = "requête invalide"
                raise QueryError(f"Erreur SQL ({sql_state or 'UNKNOWN'}): {server_msg}")
            except (pyodbc.Error, OSError) as write_conn_exc:
                logger.error(
                    "execute_write connexion error",
                    extra={"sql": sql[:200]},
                    exc_info=True,
                )
                raise QueryError(
                    f"Erreur de connexion SQL Server lors de l'écriture : "
                    f"{_format_pyodbc_error(write_conn_exc)}"
                ) from write_conn_exc

    async def execute_scalar(self, query: str, params: Tuple[Any, ...] = None) -> Any:
        """
        Exécute une requête et retourne une seule valeur

        Usage:
            count = await connector.execute_scalar("SELECT COUNT(*) FROM factures")
        """
        result = await self.execute(query, params, max_rows=1)
        if result.rows and result.rows[0]:
            return result.rows[0][0]
        return None

    async def explain_plan(
        self,
        sql: str,
        params: Optional[Tuple[Any, ...]] = None,
        *,
        timeout: float = 5.0,
    ) -> Optional[str]:
        """T27 — Récupère le plan d'exécution estimé via ``SHOWPLAN_XML``.

        Demande à SQL Server le plan d'exécution **sans exécuter** la
        requête. ``SET SHOWPLAN_XML ON`` instruit l'optimiseur à
        retourner le plan XML au lieu d'exécuter la query suivante,
        puis ``SET SHOWPLAN_XML OFF`` rétablit l'exécution normale
        (impératif pour ne pas laisser la session dans un état où la
        prochaine query retournerait un plan au lieu de résultats).

        Args:
            sql: requête SELECT à planifier (déjà validée par le caller).
                Ne re-valide pas — c'est un "second canal" hors du
                ``execute()`` normal.
            params: paramètres positionnels ``?`` à binder pour la
                compilation du plan.
            timeout: timeout total de la séquence (défaut 5s).

        Returns:
            XML brut SHOWPLAN_XML (1 colonne, 1 row) OU ``None`` si :
            - non connecté / config manquante
            - permission ``SHOWPLAN`` non accordée (erreur SQL)
            - timeout
            - SQL crash au plan
            - tout autre échec

        **Fail-safe absolu** : ne raise pas. Le caller (T27 plan preview)
        skip silencieusement le warning en cas de ``None``.

        Sécurité :
        - Refuse fast-fail tout SQL qui ne commence pas par ``SELECT`` /
          ``WITH`` (cohérence avec ``execute()``) — ne doit pas servir
          de bypass pour SQL Server commands arbitraires.
        - La séquence ``ON / query / OFF`` est exécutée sous un sémaphore
          exclusif pour ne pas leaker l'état de session sur les requêtes
          parallèles (la connexion est partagée).
        - **State-leak protection** : si la séquence est interrompue après
          que ``SET SHOWPLAN_XML ON`` a réussi côté serveur mais que ``OFF``
          n'a pas pu confirmer (timeout réseau, AttributeError, exception
          imprévue), on force la connexion en état stale (reset au
          prochain execute()). Évite que la prochaine requête retourne du
          XML au lieu de données — "données fausses silencieuses" évitées.

        Generic : aucun nom BDD-spécifique hardcodé.
        """
        # 1. Pré-checks AVANT toute tentative de connect (perf + clarté)
        if _unconfigured and getattr(self, "_is_singleton", False):
            return None

        if not isinstance(sql, str) or not sql.strip():
            return None

        # Refuse les non-SELECT (defense-in-depth — ne doit pas servir
        # de bypass via ce canal pour exécuter du DDL ou autre).
        # Strip parens externes pour accepter ``(SELECT ...)`` wrappé.
        body = strip_leading_sql_comments(sql.strip()).lstrip("(").lstrip().upper()
        if not (body.startswith("SELECT") or body.startswith("WITH")):
            return None

        if not self._connected:
            try:
                await self.connect()
            except SageConnectionError:
                return None

        def _explain_sync() -> Optional[str]:
            cursor = self._connection.cursor()
            xml_text: Optional[str] = None
            # Flag d'audit : ``SET SHOWPLAN_XML ON`` a-t-il été émis côté
            # serveur ? Si oui ET la confirmation OFF n'arrive pas, on
            # force la connexion en stale. C'est la garantie qu'un état
            # SHOWPLAN reste sur cette connexion ne pourra pas pourrir
            # les prochaines queries.
            showplan_on_attempted = False
            showplan_off_confirmed = False
            try:
                # Strip commentaires comme execute() (T6 — éviter `?`
                # interprétés dans les commentaires).
                sanitized_sql = strip_all_sql_comments(sql)
                try:
                    # CRITICAL : SET SHOWPLAN_XML ON DOIT être le seul
                    # statement du batch — ne PAS fusionner avec la
                    # query suivante (SQL Server refuse).
                    showplan_on_attempted = True
                    cursor.execute("SET SHOWPLAN_XML ON")
                    # Drain le row vide du SET (certains drivers en émettent
                    # un, d'autres pas — on consomme défensivement).
                    try:
                        cursor.nextset()
                    except (pyodbc.Error, OSError, AttributeError):
                        pass

                    if params:
                        cursor.execute(sanitized_sql, params)
                    else:
                        cursor.execute(sanitized_sql)

                    row = cursor.fetchone()
                    if row is not None and len(row) >= 1:
                        candidate = row[0]
                        if isinstance(candidate, (bytes, bytearray)):
                            try:
                                xml_text = candidate.decode("utf-8", errors="replace")
                            except (UnicodeDecodeError, AttributeError):
                                xml_text = None
                        elif isinstance(candidate, str):
                            xml_text = candidate
                        else:
                            # Type inattendu (pyodbc.LOB, memoryview, etc.)
                            # → log pour debug, retour None pour fail-safe.
                            logger.info(
                                "explain_plan: unexpected candidate type %s",
                                type(candidate).__name__,
                            )
                    # Drain les rows restantes pour libérer le cursor
                    try:
                        while cursor.fetchmany(10000):
                            pass
                    except (pyodbc.Error, OSError, AttributeError):
                        pass
                finally:
                    # CRITIQUE : SHOWPLAN_XML OFF doit s'exécuter même
                    # en cas d'exception de la query, sinon les prochaines
                    # queries sur cette connexion retourneront des plans
                    # au lieu de résultats.
                    try:
                        cursor.execute("SET SHOWPLAN_XML OFF")
                        try:
                            cursor.nextset()
                        except (pyodbc.Error, OSError, AttributeError):
                            pass
                        showplan_off_confirmed = True
                    except (pyodbc.Error, OSError, AttributeError) as off_exc:
                        # Si OFF échoue, la connexion est probablement
                        # corrompue — on la marque stale pour forcer un
                        # reset au prochain execute().
                        logger.warning(
                            "explain_plan: SHOWPLAN_XML OFF failed, marking conn stale: %s",
                            off_exc,
                        )
                        with _cb_lock:
                            self._connected = False
                            self._connection = None
            except (pyodbc.Error, OSError, AttributeError) as exc:
                logger.info("explain_plan: SHOWPLAN sequence failed: %s", exc)
                xml_text = None
            finally:
                # Defense-in-depth : si ON a été attempté mais OFF n'est
                # PAS confirmé (typique : exception entre les deux qui
                # n'a pas suivi le flow finally), on force stale. Couvre
                # le cas où l'OFF a réussi côté serveur mais a raisé côté
                # client (timeout réseau au retour).
                if showplan_on_attempted and not showplan_off_confirmed:
                    logger.warning(
                        "explain_plan: SHOWPLAN ON attempted without OFF "
                        "confirmation — forcing connection stale"
                    )
                    with _cb_lock:
                        self._connected = False
                        self._connection = None
                try:
                    cursor.close()
                except (pyodbc.Error, OSError, AttributeError):
                    pass
            return xml_text

        # Sémaphore exclusif partagé avec execute() : la séquence
        # SHOWPLAN ON/OFF doit être atomique pour ne pas leaker l'état.
        async with _get_query_semaphore():
            try:
                loop = asyncio.get_running_loop()
                return await asyncio.wait_for(
                    loop.run_in_executor(self._get_executor(), _explain_sync),
                    timeout=float(timeout) + 1.0,  # marge wait_for
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                logger.info("explain_plan: timed out after %.1fs", timeout)
                return None
            except Exception as exc:  # noqa: BLE001 — fail-safe absolu
                logger.info("explain_plan: unexpected error: %s", exc)
                return None

    async def health_check(self) -> bool:
        """
        Vérifie que la connexion est active

        Returns:
            True si la connexion est OK
        """
        try:
            result = await self.execute_scalar("SELECT 1")
            return result == 1
        except (pyodbc.Error, OSError, ConnectionError, QueryError, SageConnectionError):
            return False

    async def get_tables(self, user: Any = None) -> List[str]:
        """
        Liste les tables accessibles

        Args:
            user: optionnel — si fourni avec restrictions, retire les
                tables interdites pour cet user (mode invisible Phase
                α.3). ``user=None`` (défaut) = comportement legacy.
                Pour les flows système (sync schéma, jobs background),
                passer ``user=enforcer.SYSTEM_USER`` court-circuite
                aussi le filtre.

        Returns:
            Liste des noms de tables, filtrée selon ``user`` si fourni.
        """
        query = """
            SELECT TABLE_NAME
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_TYPE = 'BASE TABLE'
            ORDER BY TABLE_NAME
        """
        result = await self.execute(query)
        all_tables = [row[0] for row in result.rows]

        # Phase α.3 — Filtre mode invisible. Comme c'est le live SQL
        # Server, on ne peut pas pré-filtrer côté SQL (les noms autorisés
        # dépendent du user, le query ferait un IN(...) ingrable côté
        # cache). Filtre post-SELECT, en mémoire.
        from app.services.data_access.enforcer import should_filter_for

        if not await should_filter_for(user):
            return all_tables
        try:
            from app.services.data_access.visible_schema import (
                build_user_schema_view,
            )

            view = await build_user_schema_view(user)
            if not view.has_restrictions:
                return all_tables
            return [t for t in all_tables if t and view.can_see_table(t)]
        except Exception as exc:
            # FAIL-CLOSED : retourner liste vide plutôt que la liste
            # complète. Le résultat de get_tables est consommé par des
            # call-sites LLM (Iris, schema_enricher, agent_tools) — un
            # leak silencieux ferait apparaître les noms interdits dans
            # les prompts.
            logger.error(
                "SageConnector.get_tables: filtrage mode invisible "
                "échoué (fail-closed, [] retourné): %s",
                exc,
                exc_info=True,
            )
            return []

    async def get_columns(
        self,
        table_name: str,
        user: Any = None,
    ) -> List[Dict[str, Any]]:
        """
        Liste les colonnes d'une table

        Args:
            table_name: Nom de la table
            user: optionnel — si fourni avec restrictions :
                - Si la table est invisible pour cet user → retourne ``[]``
                  comme si elle n'existait pas (mode invisible : on ne
                  distingue pas « inexistante » et « interdite »).
                - Sinon : filtre les colonnes interdites (denied_columns
                  brutes consultées via ``can_see_column``).

        Returns:
            Liste de dicts avec name, type, nullable (filtrée selon
            ``user`` si fourni).
        """
        # Phase α.3 — Pré-check table visible AVANT la requête SQL pour
        # ne pas révéler dans les logs SQL Server qu'on a interrogé une
        # table interdite.
        from app.services.data_access.enforcer import should_filter_for

        view_for_filter = None
        if await should_filter_for(user):
            try:
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view_for_filter = await build_user_schema_view(user)
                if view_for_filter.has_restrictions and not view_for_filter.can_see_table(
                    table_name
                ):
                    # Table invisible — pas de requête SQL, retour [].
                    return []
            except Exception as exc:
                logger.error(
                    "SageConnector.get_columns: filtrage mode invisible "
                    "échoué (fail-closed, [] retourné): %s",
                    exc,
                    exc_info=True,
                )
                return []

        query = """
            SELECT
            COLUMN_NAME,
            DATA_TYPE,
                IS_NULLABLE,
                CHARACTER_MAXIMUM_LENGTH,
                NUMERIC_PRECISION,
                COLUMN_DEFAULT
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_NAME = ?
            ORDER BY ORDINAL_POSITION
        """
        result = await self.execute(query, (table_name,))

        all_columns = [
            {
                "name": row[0],
                "type": row[1],
                "nullable": row[2] == "YES",
                "max_length": row[3],
                "precision": row[4],
                "default": row[5],
            }
            for row in result.rows
        ]

        # Phase α.3 — Filtre colonnes interdites si view active.
        if view_for_filter is None or not view_for_filter.has_restrictions:
            return all_columns
        return [
            c
            for c in all_columns
            if c.get("name") and view_for_filter.can_see_column(table_name, c["name"])
        ]

    async def get_distinct_values(
        self,
        table_name: str,
        column_name: str,
        max_values: int = 0,
        user: Any = None,
    ) -> List[str]:
        """
        Récupère les valeurs distinctes d'une colonne (pour enrichissement RAG).

        Args:
            table_name: Nom de la table (validé puis bracket-quoted)
            column_name: Nom de la colonne (validé puis bracket-quoted)
            max_values: Nombre max de valeurs. 0 = toutes.
            user: optionnel — Phase α.3 fix BLOCKING #2. Si fourni avec
                restrictions ET table/colonne invisible pour cet user
                → retourne ``[]`` SANS exécuter la requête (ne pas
                leaker les VALEURS PII via cette méthode).

        Returns:
            Liste de valeurs distinctes (chaînes), filtrée selon ``user``.
        """
        # Validation stricte des identifiants (lettres, chiffres, underscores)
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", column_name):
            raise ValueError(f"Nom de colonne invalide: {column_name}")

        # Phase α.3 fix BLOCKING #2 — Pré-check user avant SELECT.
        # Sans ça, un caller LLM pourrait extraire toutes les valeurs
        # d'une colonne PII via cette méthode interne.
        from app.services.data_access.enforcer import should_filter_for

        if await should_filter_for(user):
            try:
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view = await build_user_schema_view(user)
                if view.has_restrictions and (
                    not view.can_see_table(table_name)
                    or not view.can_see_column(table_name, column_name)
                ):
                    return []
            except Exception as exc:
                logger.error(
                    "SageConnector.get_distinct_values: filtrage mode "
                    "invisible échoué (fail-closed, [] retourné): %s",
                    exc,
                    exc_info=True,
                )
                return []

        # Bracket-quoting + identifiants validés
        top_clause = f"TOP {int(max_values)} " if max_values > 0 else ""
        query = (
            f"SELECT DISTINCT {top_clause}[{column_name}] "
            f"FROM [dbo].[{table_name}] "
            f"WHERE [{column_name}] IS NOT NULL"
        )
        # ``bypass_admin_cap=True`` : ce sync est un INTERNAL (alimente
        # l'index de recherche RAG des valeurs distinctes par colonne).
        # Si on respectait le plafond admin (ex: 100 lignes), Iris ne
        # verrait que 100 codes journaux distincts au lieu de tous, et
        # ne pourrait pas matcher des requtes sur les autres -- bug
        # silencieux invisible. Cette query n'est pas user-visible :
        # le plafond admin (UX) ne s'applique pas.
        result = await self.execute(query, max_rows=999_999_999, bypass_admin_cap=True)
        return [str(row[0]) for row in result.rows if row[0] is not None]

    async def get_top_values_with_frequency(
        self,
        table_name: str,
        column_name: str,
        top_n: int = 1000,
        user: Any = None,
    ) -> List[tuple]:
        """Top-N valeurs distinctes triées par fréquence DESC (high-card columns).

        Utilisé par la stratification ``value_mapping`` (T5) — quand une colonne a
        plus de ``MID_CARD_THRESHOLD`` distincts, on n'indexe pas tout : on garde
        les ``top_n`` les plus fréquents (= les plus utiles pour la résolution
        valeur → colonne) + on calcule des agrégats sur la totalité côté serveur.

        Args:
            table_name: Nom de la table (validé strict puis bracket-quoted)
            column_name: Nom de la colonne (validé strict puis bracket-quoted)
            top_n: Nombre maximal de couples (value, count) retournés. ≤ 0 = défaut 1000.

        Returns:
            List[(value:str, count:int)] triée par count DESC. NULL filtrés.
        """
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", column_name):
            raise ValueError(f"Nom de colonne invalide: {column_name}")

        # Phase α.3 fix BLOCKING #2 — Pré-check user (cf. get_distinct_values).
        from app.services.data_access.enforcer import should_filter_for

        if await should_filter_for(user):
            try:
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view = await build_user_schema_view(user)
                if view.has_restrictions and (
                    not view.can_see_table(table_name)
                    or not view.can_see_column(table_name, column_name)
                ):
                    return []
            except Exception as exc:
                logger.error(
                    "SageConnector.get_top_values_with_frequency: filtrage "
                    "mode invisible échoué (fail-closed, [] retourné): %s",
                    exc,
                    exc_info=True,
                )
                return []

        cap = top_n if isinstance(top_n, int) and top_n > 0 else 1000
        query = (
            f"SELECT TOP {cap} [{column_name}] AS v, COUNT(*) AS n "
            f"FROM [dbo].[{table_name}] "
            f"WHERE [{column_name}] IS NOT NULL "
            f"GROUP BY [{column_name}] "
            f"ORDER BY COUNT(*) DESC"
        )
        # bypass_admin_cap : sync interne, même justification que
        # get_distinct_values.
        result = await self.execute(query, max_rows=999_999_999, bypass_admin_cap=True)
        return [(str(row[0]), int(row[1])) for row in result.rows if row[0] is not None]

    async def get_table_row_count(self, table_name: str) -> int:
        """Retourne le nombre de lignes d'une table."""
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")

        query = f"SELECT COUNT(*) FROM [dbo].[{table_name}]"
        result = await self.execute(query, max_rows=1)
        return int(result.rows[0][0]) if result.rows else 0

    async def get_column_stats(
        self, table_name: str, columns: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Collecte les stats par colonne : distinct_count, null_count, null_pct.
        Pour les colonnes numériques : min_val, max_val.

        Returns:
            Dict {col_name: {"distinct": int, "nulls": int, "null_pct": float, ...}}
        """
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", table_name):
            raise ValueError(f"Nom de table invalide: {table_name}")

        stats: Dict[str, Dict[str, Any]] = {}

        # Construire une seule requête qui collecte tout d'un coup
        # pour minimiser les allers-retours réseau
        select_parts = ["COUNT(*) AS _total_rows"]
        col_names = []

        # Types incompatibles avec DISTINCT dans SQL Server
        _incomparable_types = ("ntext", "text", "image", "xml")

        for col_info in columns:
            col_name = col_info["name"] if isinstance(col_info, dict) else col_info
            if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", col_name):
                continue

            col_type = ""
            if isinstance(col_info, dict):
                col_type = (col_info.get("type") or "").lower()

            col_names.append(col_name)
            safe_col = f"[{col_name}]"

            # ntext/text/image/xml ne supportent pas DISTINCT
            if any(t in col_type for t in _incomparable_types):
                select_parts.append(f"0 AS [{col_name}__distinct]")
            else:
                select_parts.append(f"COUNT(DISTINCT {safe_col}) AS [{col_name}__distinct]")
            select_parts.append(
                f"SUM(CASE WHEN {safe_col} IS NULL THEN 1 ELSE 0 END) AS [{col_name}__nulls]"
            )

            # Min/max pour numériques uniquement
            col_type = ""
            if isinstance(col_info, dict):
                col_type = (col_info.get("type") or "").lower()
            if any(t in col_type for t in ("int", "numeric", "decimal", "float", "money")):
                select_parts.append(f"MIN(CAST({safe_col} AS DECIMAL(38,2))) AS [{col_name}__min]")
                select_parts.append(f"MAX(CAST({safe_col} AS DECIMAL(38,2))) AS [{col_name}__max]")

        if not col_names:
            return stats

        # Pas de limite : toutes les colonnes sont incluses dans les stats

        query = f"SELECT {', '.join(select_parts)} FROM [dbo].[{table_name}]"

        try:
            result = await self.execute(query, max_rows=1)
            if not result.rows:
                return stats

            row = result.rows[0]
            total_rows = int(row[0]) if row[0] else 0

            # Parser les résultats par colonne
            col_idx = 1  # Skip _total_rows
            for col_name in col_names:
                col_stats: Dict[str, Any] = {"total_rows": total_rows}
                col_stats["distinct"] = int(row[col_idx]) if row[col_idx] is not None else 0
                col_stats["nulls"] = int(row[col_idx + 1]) if row[col_idx + 1] is not None else 0
                col_stats["null_pct"] = (
                    round(col_stats["nulls"] / total_rows * 100, 1) if total_rows > 0 else 0
                )
                col_idx += 2

                # Min/max si présents
                col_info = next(
                    (c for c in columns if (c["name"] if isinstance(c, dict) else c) == col_name),
                    None,
                )
                col_type = ""
                if isinstance(col_info, dict):
                    col_type = (col_info.get("type") or "").lower()
                if any(t in col_type for t in ("int", "numeric", "decimal", "float", "money")):
                    if col_idx + 1 < len(row):
                        col_stats["min_val"] = row[col_idx]
                        col_stats["max_val"] = row[col_idx + 1]
                        col_idx += 2

                stats[col_name] = col_stats

        except Exception as e:
            # P5.1 (audit 2026-05-26) — Promu DEBUG → WARNING : si la query
            # stats échoue (ex: timeout sur table volumineuse, Arithmetic
            # overflow sur DECIMAL(38,2), permission refusée), le caller
            # voit ``{}`` (stats vides) sans savoir pourquoi. WARNING permet
            # à l'admin de comprendre pourquoi Iris ne reçoit pas de stats
            # enrichies sur cette table.
            logger.warning("get_column_stats(%s) failed: %s", table_name, e)

        return stats

    async def get_schema_context(self) -> Dict[str, Any]:
        """
        Génère le contexte schéma pour l'IA

        Returns:
            Dict avec tables et leurs colonnes
        """
        tables = await self.get_tables()
        tables = tables[:50]  # Limiter à 50 tables

        # Charger toutes les colonnes en parallèle (au lieu de séquentiellement)
        columns_list = await asyncio.gather(*(self.get_columns(table) for table in tables))

        return dict(zip(tables, columns_list))

    # ── Méthodes méta-schéma (interface agnostique partagée avec SqliteSageConnector) ──
    # Côté SQL Server : INFORMATION_SCHEMA + sys.*. Côté SQLite : PRAGMA.
    # Format de retour identique entre les deux pour permettre au code applicatif
    # (ex: agent_tools.introspect_table) d'être agnostique du dialecte.

    async def get_indexes(self, table_name: str) -> List[Dict[str, Any]]:
        """Retourne ``[{"column_name": str, "is_unique": bool}, ...]`` pour la table."""
        query = """
            SELECT
                c.name AS column_name,
                i.is_unique
            FROM sys.indexes i
            JOIN sys.index_columns ic ON i.object_id = ic.object_id
                AND i.index_id = ic.index_id
            JOIN sys.columns c ON ic.object_id = c.object_id
                AND ic.column_id = c.column_id
            WHERE i.object_id = OBJECT_ID(?) AND i.object_id IS NOT NULL
            AND ic.is_included_column = 0
        """
        result = await self.execute(query, (table_name,))
        return [{"column_name": row[0], "is_unique": bool(row[1])} for row in result.rows]

    async def get_identity_columns(self, table_name: str) -> List[str]:
        """Colonnes auto-incrémentées (IDENTITY)."""
        query = """
            SELECT c.name
            FROM sys.identity_columns ic
            JOIN sys.columns c ON ic.object_id = c.object_id
                AND ic.column_id = c.column_id
            WHERE ic.object_id = OBJECT_ID(?) AND ic.object_id IS NOT NULL
        """
        result = await self.execute(query, (table_name,))
        return [row[0] for row in result.rows]

    async def get_primary_keys(self, table_name: str) -> List[str]:
        """PK ordonnées par position (PK composite supportée)."""
        query = """
            SELECT kcu.COLUMN_NAME
            FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
            JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu
                ON tc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME
            WHERE tc.TABLE_NAME = ? AND tc.CONSTRAINT_TYPE = 'PRIMARY KEY'
            ORDER BY kcu.ORDINAL_POSITION
        """
        result = await self.execute(query, (table_name,))
        return [row[0] for row in result.rows]

    async def get_foreign_keys(
        self,
        table_name: str,
        user: Any = None,
    ) -> List[Dict[str, Any]]:
        """FK sortantes : ``[{"column", "references_table", "references_column", "constraint_name"}]``.

        Args:
            table_name: table source.
            user: Phase α.3 fix BLOCKING #3 — filtre les FK qui pointent
                vers une table invisible (sinon leak du nom). Si la
                table source elle-même est invisible → ``[]``.
        """
        # Phase α.3 — Pré-check + filtrage FK vers tables invisibles.
        from app.services.data_access.enforcer import should_filter_for

        view_for_filter = None
        if await should_filter_for(user):
            try:
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view_for_filter = await build_user_schema_view(user)
                if view_for_filter.has_restrictions and not view_for_filter.can_see_table(
                    table_name
                ):
                    return []
            except Exception as exc:
                logger.error(
                    "SageConnector.get_foreign_keys: filtrage mode "
                    "invisible échoué (fail-closed, [] retourné): %s",
                    exc,
                    exc_info=True,
                )
                return []

        query = """
            SELECT
                kcu.COLUMN_NAME,
                ccu.TABLE_NAME AS referenced_table,
                ccu.COLUMN_NAME AS referenced_column,
                tc.CONSTRAINT_NAME
            FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
            JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu
                ON tc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME
            JOIN INFORMATION_SCHEMA.CONSTRAINT_COLUMN_USAGE ccu
                ON tc.CONSTRAINT_NAME = ccu.CONSTRAINT_NAME
            WHERE tc.TABLE_NAME = ? AND tc.CONSTRAINT_TYPE = 'FOREIGN KEY'
        """
        result = await self.execute(query, (table_name,))
        all_fks = [
            {
                "column": row[0],
                "references_table": row[1],
                "references_column": row[2],
                "constraint_name": row[3],
            }
            for row in result.rows
        ]

        # Phase α.3 — Retirer les FK vers tables invisibles.
        if view_for_filter is None or not view_for_filter.has_restrictions:
            return all_fks
        return [
            fk
            for fk in all_fks
            if fk.get("references_table")
            and view_for_filter.can_see_table(fk["references_table"])
            and view_for_filter.can_see_column(table_name, fk.get("column", ""))
        ]

    async def get_referencing_foreign_keys(
        self,
        table_name: str,
        user: Any = None,
    ) -> List[Dict[str, Any]]:
        """FK entrantes : autres tables qui pointent vers ``table_name``.

        Args:
            table_name: table cible.
            user: Phase α.3 — retire les FK depuis des tables invisibles
                (sinon le nom de la table referencing leak). Si la
                table cible est invisible → ``[]``.
        """
        from app.services.data_access.enforcer import should_filter_for

        view_for_filter = None
        if await should_filter_for(user):
            try:
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view_for_filter = await build_user_schema_view(user)
                if view_for_filter.has_restrictions and not view_for_filter.can_see_table(
                    table_name
                ):
                    return []
            except Exception as exc:
                logger.error(
                    "SageConnector.get_referencing_foreign_keys: filtrage "
                    "mode invisible échoué (fail-closed, [] retourné): %s",
                    exc,
                    exc_info=True,
                )
                return []

        query = """
            SELECT
                kcu.TABLE_NAME AS referencing_table,
                kcu.COLUMN_NAME AS referencing_column,
                ccu.COLUMN_NAME AS referenced_column,
                tc.CONSTRAINT_NAME
            FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
            JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu
                ON tc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME
            JOIN INFORMATION_SCHEMA.CONSTRAINT_COLUMN_USAGE ccu
                ON tc.CONSTRAINT_NAME = ccu.CONSTRAINT_NAME
            WHERE ccu.TABLE_NAME = ? AND tc.CONSTRAINT_TYPE = 'FOREIGN KEY'
        """
        result = await self.execute(query, (table_name,))
        all_refs = [
            {
                "referencing_table": row[0],
                "referencing_column": row[1],
                "referenced_column": row[2],
                "constraint_name": row[3],
            }
            for row in result.rows
        ]

        # Phase α.3 — Retirer les FK depuis tables invisibles.
        if view_for_filter is None or not view_for_filter.has_restrictions:
            return all_refs
        return [
            ref
            for ref in all_refs
            if ref.get("referencing_table")
            and view_for_filter.can_see_table(ref["referencing_table"])
        ]

    async def get_check_constraints(self, table_name: str) -> List[Dict[str, Any]]:
        """CHECK constraints : ``[{"constraint_name", "clause"}]`` (filtre le bruit IS NOT NULL)."""
        query = """
            SELECT
                cc.CONSTRAINT_NAME,
                cc.CHECK_CLAUSE
            FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
            JOIN INFORMATION_SCHEMA.CHECK_CONSTRAINTS cc
                ON tc.CONSTRAINT_NAME = cc.CONSTRAINT_NAME
            WHERE tc.TABLE_NAME = ?
                AND tc.CONSTRAINT_TYPE = 'CHECK'
                AND cc.CHECK_CLAUSE NOT LIKE '%IS NOT NULL%'
        """
        result = await self.execute(query, (table_name,))
        return [{"constraint_name": row[0], "clause": row[1]} for row in result.rows]


# Instance globale (singleton)
_sage_connector: Optional[SageConnector] = None
# Override runtime : None = env var, True = SQLite forcé, False = SQL Server forcé
_force_sqlite_mode: Optional[bool] = None

# ── /admin/database == seule source de vérité ──────────────────────────────
#
# ``_unconfigured`` vaut ``True`` quand AUCUNE ``DatabaseConnection`` n'est
# marquée ``is_active`` dans la BDD locale (= rien de configuré sur la page
# ``/admin/database``). Dans ce cas, on REFUSE l'exécution SQL au lieu de
# retomber silencieusement sur les variables ``.env`` / ``localhost`` —
# ainsi la page admin est l'UNIQUE source de vérité pour la connexion BDD
# et l'admin sait toujours d'où vient la config qui tourne.
#
# Le mode SQLite local (``_force_sqlite_mode=True``) est exempté : c'est un
# mode dev/test délibéré qui n'a rien à voir avec la config GUI.
#
# Cycle de vie :
#   - Mis à ``True`` par ``init_sage_from_db_config`` au boot si pas de
#     config active, et par ``_reload_sage_connector(None)`` lors d'une
#     désactivation.
#   - Mis à ``False`` par ``_reset_sage_connector(...)`` (appelé dès
#     qu'une config active est posée).
_unconfigured: bool = False

# Fichier de persistance du mode (survit aux redémarrages). Dérivé de
# DATA_DIR (config) — PAS de ``parent.parent...`` fragile : un DATA_DIR
# redéfini (test/déploiement custom) doit déplacer ce fichier de façon
# cohérente avec le reste de l'app.
_SAGE_MODE_FILE = DATA_DIR / "sage_mode.json"

# SSoT du chemin de la copie SQLite locale (mode offline). db_config.py
# l'importe (au lieu de re-dériver) pour qu'un pré-check ``.exists()`` côté
# handler et le guard côté service ne divergent JAMAIS si DATA_DIR change.
SAGE_SQLITE_COPY_PATH = DATA_DIR / "sage_copy.db"


def _load_persisted_mode() -> Optional[bool]:
    """Charge le mode persisté depuis data/sage_mode.json. Retourne None si absent/invalide."""
    try:
        if _SAGE_MODE_FILE.exists():
            data = json.loads(_SAGE_MODE_FILE.read_text(encoding="utf-8"))
            mode = data.get("mode")
            if mode == "sqlite":
                return True
            elif mode == "sqlserver":
                return False
    except (json.JSONDecodeError, OSError, KeyError):
        pass
    return None


def _persist_mode(use_sqlite: bool) -> None:
    """Persiste le choix de mode dans data/sage_mode.json."""
    try:
        _SAGE_MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _SAGE_MODE_FILE.write_text(
            json.dumps({"mode": "sqlite" if use_sqlite else "sqlserver"}),
            encoding="utf-8",
        )
    except OSError as e:
        logger.warning("Impossible de persister le mode Sage: %s", e)


def _should_use_sqlite() -> bool:
    """Détermine si on doit utiliser SQLite : flag runtime > fichier persisté > env var."""
    if _force_sqlite_mode is not None:
        return _force_sqlite_mode
    persisted = _load_persisted_mode()
    if persisted is not None:
        return persisted
    return os.getenv("USE_SQLITE_COPY", "").lower() in ("true", "1", "yes")


def get_sage_connector() -> "SageConnector":
    """
    Retourne l'instance globale du connecteur Sage.

    Priorité : _force_sqlite_mode (runtime) > sage_mode.json persiste >
    USE_SQLITE_COPY (env var).

    **Detection de mismatch** : si le singleton existant ne correspond
    plus au mode actif (cas connu : le serveur a démarré avant que
    `data/sage_mode.json` soit créé, donc cree un SageConnector
    SQL Server par defaut, puis l'admin a switch SQLite via UI mais le
    fichier persisté n'existait pas au boot → singleton stale), on
    ferme l'ancien et on en cree un du bon type. Sans ce check, le
    runtime continuait a utiliser pyodbc malgre `mode=sqlite` (incident
    auto #9 #3 du 2026-05-08 : timeout 30s sur SQL Server alors que
    sqlite local etait disponible).
    """
    global _sage_connector

    want_sqlite = _should_use_sqlite()

    # Detect stale singleton (mode change non synchronisé après boot).
    if _sage_connector is not None:
        from app.services.database.sqlite_sage_connector import SqliteSageConnector

        is_sqlite_instance = isinstance(_sage_connector, SqliteSageConnector)
        if want_sqlite != is_sqlite_instance:
            logger.warning(
                "🔀 Singleton sage_connector stale (mode=%s, instance=%s) — recreation",
                "sqlite" if want_sqlite else "sqlserver",
                type(_sage_connector).__name__,
            )
            try:
                # Best-effort fermer l'ancien (sync best effort — on ne peut
                # pas await ici, c'est volontaire pour garder l'API sync).
                # L'ancien connecteur sera garbage-collecte.
                _sage_connector = None
            except Exception:
                _sage_connector = None

    if _sage_connector is None:
        if want_sqlite:
            from app.services.database.sqlite_sage_connector import SqliteSageConnector

            logger.info("🔀 Mode SQLite local activé")
            _sage_connector = SqliteSageConnector()  # type: ignore[assignment]
        else:
            _sage_connector = SageConnector()
        # Marquer cette instance comme le singleton -- le guard
        # ``[CONFIG_MANQUANTE]`` dans ``connect()`` ne fire que pour les
        # instances singleton (les tests/scripts qui font
        # ``SageConnector(host=...)`` directement gardent leur autonomie).
        try:
            _sage_connector._is_singleton = True
        except AttributeError:
            # SqliteSageConnector peut ne pas avoir cet attribut -- safe.
            pass
    return _sage_connector


def get_current_sage_mode() -> str:
    """Retourne le mode actif : 'sqlite' ou 'sqlserver'."""
    if _sage_connector is not None:
        from app.services.database.sqlite_sage_connector import SqliteSageConnector

        if isinstance(_sage_connector, SqliteSageConnector):
            return "sqlite"
        return "sqlserver"
    # Pas encore initialisé — retourne ce qui SERAIT utilisé
    return "sqlite" if _should_use_sqlite() else "sqlserver"


async def close_sage_connector() -> None:
    """Ferme le connecteur global et libère le pool de threads"""
    global _sage_connector, _executor, _cb_failure_count, _cb_last_failure_time
    global _cb_half_open, _query_semaphore
    if _sage_connector:
        await _sage_connector.close()
        _sage_connector = None
    if _executor:
        _executor.shutdown(wait=False)
        _executor = None
    # Reset circuit breaker state
    with _cb_lock:
        _cb_failure_count = 0
        _cb_last_failure_time = 0.0
        _cb_half_open = False
    # Reset query semaphore (lié à l'event loop, doit être recréé)
    _query_semaphore = None


def _reset_sage_connector(
    host: str = None,
    port: int = None,
    database: str = None,
    username: str = None,
    password: str = None,
    timeout: int = None,
    max_rows: int = None,
) -> None:
    """
    Recrée le connecteur Sage global avec de nouveaux paramètres.
    Appelé par db_config_service lors de l'activation d'une connexion GUI.

    **Contrat** : si appelé SANS host/username, le connecteur ne sera PAS
    fonctionnel — l'app refusera l'exécution SQL via le flag
    ``_unconfigured`` (cf. ``mark_unconfigured``). C'est volontaire :
    ``/admin/database`` est l'unique source de vérité, le fallback ``.env``
    est désactivé pour qu'aucune connexion ne tourne en sous-marin.

    Respecte le mode SQLite : si _force_sqlite_mode est True, ne fait rien
    (le connecteur SQLite ne dépend pas de ces paramètres SQL Server).
    """
    global _sage_connector, _unconfigured
    if _force_sqlite_mode is True:
        logger.info("⏭️ _reset_sage_connector ignoré — mode SQLite actif")
        return
    _sage_connector = SageConnector(
        host=host,
        port=port,
        database=database,
        username=username,
        password=password,
        timeout=timeout,
        max_rows=max_rows,
    )
    _sage_connector._is_singleton = True  # cf. ``get_sage_connector``
    # Reset inconditionnel du verrou ``_unconfigured`` : ce reset signifie
    # "le caller a explicitement remplace la config courante". S'il n'a
    # pas passe des credentials valides, l'erreur sera leve plus tard
    # avec un message ODBC precis (login failed, host unknown...). Si
    # le caller voulait au contraire signifier "plus aucune config",
    # il appelle ``mark_unconfigured()`` directement, pas ce reset.
    _unconfigured = False


def mark_unconfigured() -> None:
    """Marque le connecteur Sage comme NON configuré.

    Appelée quand aucune ``DatabaseConnection`` ``is_active`` n'existe dans
    la BDD (boot avec /admin/database vide, ou déactivation par l'admin).
    Tant que ce flag est vrai, ``SageConnector.connect()`` refuse de
    tenter une connexion et lève une erreur claire pointant vers
    /admin/database. Pas d'effet si mode SQLite actif (dev).
    """
    global _unconfigured
    if _force_sqlite_mode is True:
        return
    _unconfigured = True


def is_unconfigured() -> bool:
    """``True`` si aucune connexion BDD n'est configurée via /admin/database.

    Lu par les couches UI (admin dashboard, monitoring) pour afficher un
    état "non configuré" différencié de "déconnecté" / "untested".
    """
    if _force_sqlite_mode is True:
        return False
    return _unconfigured


async def switch_sage_mode(use_sqlite: bool) -> dict:
    """
    Switch à chaud entre SQL Server et SQLite (copie locale).
    Ferme proprement l'ancien connecteur, le prochain appel à
    get_sage_connector() créera le bon type.

    Returns:
        dict avec mode, status, et message
    """
    global _force_sqlite_mode, _sage_connector

    if use_sqlite:
        # Vérifier que sage_copy.db existe (chemin SSoT partagé avec db_config).
        db_path = SAGE_SQLITE_COPY_PATH
        if not db_path.exists():
            return {
                "mode": "sqlserver",
                "status": "error",
                "message": "Fichier data/sage_copy.db introuvable. "
                "Lancez d'abord scripts/copy_sage_to_sqlite.py pour créer la copie.",
            }

    # Fermer l'ancien connecteur proprement
    await close_sage_connector()

    # Changer le mode
    _force_sqlite_mode = use_sqlite
    mode = "sqlite" if use_sqlite else "sqlserver"
    logger.info("🔀 Switch mode Sage → %s", mode)

    # Capturer le mode précédent pour rollback
    previous_was_sqlite = not use_sqlite

    # Créer le nouveau connecteur et vérifier qu'il fonctionne
    try:
        connector = get_sage_connector()
        await connector.connect()
        await connector.health_check()
        # Persistance pour survivre aux redémarrages
        _persist_mode(use_sqlite)
        return {"mode": mode, "status": "ok", "message": f"Mode {mode} activé avec succès"}
    except Exception as e:
        # Rollback : revenir au mode précédent
        await close_sage_connector()
        _force_sqlite_mode = previous_was_sqlite
        previous_mode = "sqlite" if previous_was_sqlite else "sqlserver"
        logger.error("❌ Switch vers %s échoué, rollback → %s: %s", mode, previous_mode, e)
        return {
            "mode": previous_mode,
            "status": "error",
            "message": f"Impossible de basculer vers {mode}: {e}",
        }


async def init_sage_from_db_config() -> None:
    """
    Au démarrage de l'app, charge la connexion active depuis la BDD.

    **Contrat** : ``/admin/database`` est l'UNIQUE source de vérité pour
    la connexion BDD source. S'il n'y a pas de connexion ``is_active``
    dans la BDD locale, on marque le connecteur comme ``unconfigured``
    et toute tentative d'exécution SQL est refusée avec un message clair
    pointant vers la page admin -- AUCUN fallback silencieux sur
    ``.env`` ou ``localhost``.

    Le mode SQLite local (``_force_sqlite_mode=True``) est exempté : c'est
    un mode dev/test indépendant de la config GUI.
    """
    if _force_sqlite_mode is True:
        logger.info("⏭️ init_sage_from_db_config ignoré — mode SQLite actif")
        return
    try:
        from app.services.database.db_config_service import (
            get_active_connection,
            decrypt_password,
        )

        active = await get_active_connection()
        if active:
            password = decrypt_password(active.encrypted_password)
            # Force un default explicite si la valeur en BDD est NULL
            # (legacy, migration, raw INSERT) -- on ne doit JAMAIS
            # retomber sur ``config.sage.max_rows`` (env) car ce serait
            # un fallback invisible contradictoire avec la doctrine
            # "DBConfig = unique source de vrit".
            _reset_sage_connector(
                host=active.host,
                port=active.port,
                database=active.database,
                username=active.username,
                password=password,
                timeout=active.timeout or 30,
                max_rows=active.max_rows or 1000,
            )
            logger.info(
                "✅ Config Sage chargée depuis GUI: %s (%s:%s/%s)",
                active.name,
                active.host,
                active.port,
                active.database,
            )
        else:
            # AUCUN fallback .env. /admin/database est la seule source de
            # vérité : tant que rien n'y est activé, on refuse l'exécution
            # SQL pour éviter qu'une config orpheline (variable .env d'un
            # ancien déploiement, valeur par défaut "localhost") ne tourne
            # en sous-marin sans que l'admin le sache.
            mark_unconfigured()
            logger.warning(
                "⚠️ Aucune connexion BDD active. L'exécution SQL est désactivée "
                "tant qu'une connexion n'est pas créée et activée via "
                "/admin/database."
            )
    except Exception:  # noqa: BLE001 -- fail-closed delibere
        # Echec inattendu (BDD locale corrompue, schema en cours de
        # migration, SQLAlchemyError, RuntimeError event-loop, ...) :
        # on marque AUSSI unconfigured. ``except Exception`` est
        # delibere -- la doctrine est "fail-closed" : si on ne peut
        # PAS prouver qu'une config valide existe, on refuse l'execution
        # SQL plutot que de retomber silencieusement sur ``.env`` ou
        # sur un connecteur orphelin (cf. consequences.md "donnees
        # fausses sans erreur visible").
        mark_unconfigured()
        logger.warning(
            "⚠️ Impossible de charger la config Sage depuis la BDD locale — "
            "exécution SQL désactivée. Vérifiez /admin/database.",
            exc_info=True,
        )


@asynccontextmanager
async def sage_connection():
    """
    Context manager pour une connexion Sage (singleton).

    La connexion n'est PAS fermée à la sortie pour permettre la réutilisation.
    En cas d'erreur de connexion pendant l'utilisation, l'état est réinitialisé
    pour forcer une reconnexion au prochain appel.

    Usage:
        async with sage_connection() as connector:
            result = await connector.execute("SELECT ...")
    """
    connector = get_sage_connector()
    await connector.connect()
    try:
        yield connector
    except (pyodbc.Error, OSError):
        # Connexion potentiellement perdue — réinitialiser pour forcer reconnexion
        connector._connected = False
        connector._connection = None
        raise


# Export
__all__ = [
    "SageConnector",
    "QueryResult",
    "get_sage_connector",
    "close_sage_connector",
    "sage_connection",
    "is_unconfigured",
    "mark_unconfigured",
    "build_sage_connection_string",
    "discover_sage_odbc_driver",
    "sanitize_odbc_value",
    "_reset_sage_connector",
    "init_sage_from_db_config",
    "switch_sage_mode",
    "get_current_sage_mode",
]
