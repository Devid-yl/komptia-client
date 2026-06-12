"""
Configuration Komptia v2.0

Charge les paramètres depuis `config.yaml` et les variables d'environnement.

Ordre de priorité (du plus faible au plus fort) :
    1. Valeurs par défaut du dataclass
    2. `config.yaml`
    3. Variables d'environnement (via `.env` ou shell)

Les secrets (`SECRET_KEY`, `SQLCIPHER_KEY`, mots de passe) doivent venir de
l'environnement. Aucun secret ne doit être stocké dans `config.yaml`.
"""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from app.core.clock import resolve_machine_tz_name

load_dotenv()

try:
    import pyodbc  # noqa: F401

    PYODBC_AVAILABLE = True
except ImportError:
    PYODBC_AVAILABLE = False

BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = BASE_DIR / "app"
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"
REPORTS_DIR = DATA_DIR / "reports"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
# Guides d'aide PDF (par rôle) servis dans /settings → section « Aide ».
# Contenu en LECTURE SEULE livré avec l'app (généré par scripts/build_guides.py
# en dev, embarqué dans l'image Docker en prod) — donc PAS dans le volume
# de données runtime et PAS mkdir() dans __post_init__.
GUIDES_DIR = BASE_DIR / "docs" / "guides"

# --- Constantes réseau / sécurité (stables, non configurables) ------------

_MIN_TCP_PORT = 1
_MAX_TCP_PORT = 65535

_DEFAULT_SQL_SERVER_PORT = 1433
_DEFAULT_SMTP_PORT = 587
_DEFAULT_SERVER_PORT = 8888
_DEFAULT_ODBC_DRIVER = "ODBC Driver 17 for SQL Server"

# SQLCipher : clé raw hex, minimum 32 caractères = 128 bits (projet accepte
# déjà cet usage historique ; 64 caractères = 256 bits recommandé pour neuves).
_MIN_SQLCIPHER_KEY_LENGTH = 32

# bcrypt : minimum OWASP Password Storage Cheat Sheet 2024/2025 = 10 ; 12 par défaut.
_MIN_BCRYPT_ROUNDS = 10
_DEFAULT_BCRYPT_ROUNDS = 12

# Sentinel : permet de détecter un secret laissé à la valeur placeholder.
_SECRET_KEY_SENTINEL = "CHANGE_ME_IN_PRODUCTION"

_ENV_DEVELOPMENT = "development"
_ENV_STAGING = "staging"
_ENV_PRODUCTION = "production"

# Caractères spéciaux ODBC (spec Microsoft) nécessitant un encodage par {}.
_ODBC_SPECIAL_CHARS = frozenset(";{}= ")


def _safe_int(value: str | None, default: int, name: str = "env var") -> int:
    """Convertit une chaîne env en int avec fallback prudent.

    Émet un `UserWarning` si la valeur est présente mais non parseable, puis
    retourne `default` — évite un crash au démarrage causé par un `.env` erroné.
    """
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        warnings.warn(
            f"{name}={value!r} n'est pas un entier valide, utilisation de {default}",
            stacklevel=2,
        )
        return default


def _validate_port(port: int, name: str) -> None:
    """Lève `RuntimeError` si le port TCP est hors de la range [1, 65535]."""
    if not (_MIN_TCP_PORT <= port <= _MAX_TCP_PORT):
        raise RuntimeError(
            f"{name}={port} hors range valide [{_MIN_TCP_PORT}, {_MAX_TCP_PORT}]. "
            f"Vérifiez votre configuration."
        )


def _escape_odbc_value(value: str, *, always_brace: bool = False) -> str:
    """Échappe une valeur pour chaîne de connexion ODBC.

    Les valeurs contenant `;`, `{`, `}`, `=` ou un espace doivent être entourées
    d'accolades, avec `}` interne doublé (spec Microsoft ODBC). Prévient
    l'injection de paramètres si un mot de passe contient `;Encrypt=no`.
    """
    if value == "":
        return value
    needs_escape = always_brace or any(c in value for c in _ODBC_SPECIAL_CHARS)
    if not needs_escape:
        return value
    return "{" + value.replace("}", "}}") + "}"


def _get_default_timezone() -> str:
    """Nom IANA de la TZ locale de la **machine hôte** (ex: ``Europe/Paris``,
    ``America/Guadeloupe``, ``UTC``).

    Délègue à la source de vérité unique
    :func:`app.core.clock.resolve_machine_tz_name`. Conservé sous ce nom car il
    sert de ``default_factory`` à ``ServerConfig.timezone`` (et reste importé
    par compat). Toute la logique de résolution OS (tzlocal → /etc/localtime →
    ``time.tzname`` → UTC) vit désormais dans ``app/core/clock.py`` afin qu'il
    n'existe qu'**un seul** endroit qui « lit la TZ de la machine ».
    """
    return resolve_machine_tz_name()


def _read_version_file() -> str:
    """Lit ``BASE_DIR/VERSION`` (stampé au build/export depuis git), ``""`` si absent.

    Permet de dériver la version applicative du build même pour les déploiements
    **non-git** (export ``komptia-client`` où ``git describe`` est indisponible) :
    le fichier est stampé côté appfazia (où git existe) puis embarqué. Priorité
    dans ``app_version`` : ENV ``KOMPTIA_APP_VERSION`` > fichier ``VERSION`` > littéral.
    """
    try:
        version_path = BASE_DIR / "VERSION"
        if version_path.is_file():
            content = version_path.read_text(encoding="utf-8").strip()
            if content:
                return content
    except OSError:
        pass
    return ""


@dataclass
class DatabaseConfig:
    """Configuration BDD locale SQLite (chiffrée via SQLCipher si clé fournie).

    Le ``path`` peut être surchargé par la variable d'environnement
    ``KOMPTIA_DB_PATH`` — utile pour les tests bout-en-bout, le
    déploiement Docker/K8s (volume monté), et la coexistence de
    plusieurs instances locales (dev / staging / prod sur la même
    machine).

    ⚠️  ADV-M10 : la valeur d'env est lue UNE SEULE FOIS au moment de
    l'import du module (``default_factory`` sur dataclass field).
    Définissez ``KOMPTIA_DB_PATH`` *avant* d'importer ``app.config`` —
    typiquement via ``.env`` chargé par votre runner ou export shell
    avant ``python -m app.main``. Un set après l'import est ignoré.
    """

    path: str = field(
        default_factory=lambda: os.getenv("KOMPTIA_DB_PATH") or str(DATA_DIR / "komptia.db")
    )
    # .strip() : un newline/espace de bord (copier-coller dans .env) dériverait
    # une clé hex DIFFÉRENTE et irreproductible → BDD chiffrée non restaurable
    # avec la clé « propre ». On normalise dès la lecture.
    encryption_key: str = field(default_factory=lambda: os.getenv("SQLCIPHER_KEY", "").strip())
    echo: bool = False
    # Concurrence de l'executor de threads de la BDD SOURCE (Sage) — cf.
    # sage_connector / sqlite_sage_connector. NE PAS confondre avec les knobs
    # ``local_*`` ci-dessous (pool du moteur SQLite LOCAL).
    pool_size: int = 5
    # Pool de connexions du moteur SQLite LOCAL async (cf. init_database) : borne
    # la concurrence et réutilise les connexions chaudes. Knobs DÉDIÉS, distincts
    # de ``pool_size`` (Sage) pour éviter toute collision sémantique.
    local_pool_size: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("KOMPTIA_DB_POOL_SIZE"), 10, "KOMPTIA_DB_POOL_SIZE"
        )
    )
    local_max_overflow: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("KOMPTIA_DB_MAX_OVERFLOW"), 20, "KOMPTIA_DB_MAX_OVERFLOW"
        )
    )
    local_pool_timeout: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("KOMPTIA_DB_POOL_TIMEOUT"), 30, "KOMPTIA_DB_POOL_TIMEOUT"
        )
    )

    def __repr__(self) -> str:
        return (
            f"DatabaseConfig(path={self.path!r}, "
            f"encryption_key='***REDACTED***', "
            f"echo={self.echo}, pool_size={self.pool_size}, "
            f"local_pool_size={self.local_pool_size}, "
            f"local_max_overflow={self.local_max_overflow}, "
            f"local_pool_timeout={self.local_pool_timeout})"
        )


@dataclass
class SageConfig:
    """Configuration connexion BDD source (SQL Server).

    Komptia se connecte à n'importe quelle BDD SQL Server ; le nom de base
    doit être fourni via `SAGE_DB_NAME` (ou `config.yaml`). Par défaut vide
    pour rester générique : aucun nom de logiciel tiers codé en dur.
    """

    host: str = field(default_factory=lambda: os.getenv("SAGE_DB_HOST") or "localhost")
    port: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("SAGE_DB_PORT"), _DEFAULT_SQL_SERVER_PORT, "SAGE_DB_PORT"
        )
    )
    database: str = field(default_factory=lambda: os.getenv("SAGE_DB_NAME", ""))
    username: str = field(default_factory=lambda: os.getenv("SAGE_DB_USER", ""))
    password: str = field(default_factory=lambda: os.getenv("SAGE_DB_PASSWORD", ""))
    timeout: int = 30
    # Timeout de LOGIN ODBC (établissement de connexion) en secondes — DISTINCT
    # de ``timeout`` ci-dessus (wall-clock d'EXÉCUTION de requête, appliqué par
    # ``query_executor``). DOIT rester < ``timeout`` : ainsi pyodbc lève une
    # vraie erreur de connexion AVANT que le wall-clock n'annule la coroutine,
    # ce qui permet au circuit breaker Sage de s'OUVRIR (une annulation
    # ``CancelledError`` n'était pas comptée → breaker jamais ouvert → l'app
    # pendait 30 s par requête quand Sage devenait injoignable — incident prod
    # 2026-06-08). Court par défaut : un Sage joignable répond en <1 s ; on veut
    # fail-fast quand il est injoignable (SYN droppé). Override SAGE_DB_CONNECT_TIMEOUT.
    connect_timeout: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("SAGE_DB_CONNECT_TIMEOUT"), 15, "SAGE_DB_CONNECT_TIMEOUT"
        )
    )
    # Défaut relevé 1000→10000 le 2026-05-29 (demande user). Reste configurable
    # par connexion via /admin/database (DatabaseConnection.max_rows) ; aucun
    # hard cap applicatif (cf. no_double_cap). Les gardes anti-DoS (taille SQL,
    # taille réponse LLM) restent actifs — seul le plafond de lignes monte.
    max_rows: int = 10000
    label: str = field(default_factory=lambda: os.getenv("SAGE_DB_LABEL") or "Base SQL Server")
    conventions_notes: str = field(default_factory=lambda: os.getenv("SAGE_DB_CONVENTIONS") or "")
    odbc_driver: str = field(
        default_factory=lambda: os.getenv("SAGE_ODBC_DRIVER") or _DEFAULT_ODBC_DRIVER
    )
    # Schéma source SQL Server à synchroniser. "dbo" par défaut (convention
    # SQL Server standard pour le schéma user) mais override possible via
    # SAGE_DB_SCHEMA pour les BDD avec schéma custom (e.g. "myapp", "ods").
    # Évite l'hardcode TABLE_SCHEMA = 'dbo' dans schema_sync.py (cf. règle
    # GÉNÉRICITÉ de CLAUDE.md).
    source_schema: str = field(default_factory=lambda: os.getenv("SAGE_DB_SCHEMA") or "dbo")

    @property
    def connection_string(self) -> str:
        """Chane de connexion ODBC -- DLGUE  la source unique.

        Avant avril 2026 cette property assemblait sa propre conn-string
        ( part de ``SageConnector``), avec un format diffrent (pas de
        ``Encrypt``, pas de ``MARS``, pas de ``Lock Timeout``). C'tait
        une SECONDE source de vrit qui pouvait diverger silencieusement.
        Maintenant elle dlgue  :func:`build_sage_connection_string`,
        l'unique builder de toute l'app -- ce que le connecteur de prod
        utilise est exactement ce que cette property retourne.
        """
        from app.services.database.sage_connector import build_sage_connection_string

        return build_sage_connection_string(
            host=self.host,
            port=self.port,
            database=self.database,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            connect_timeout=self.connect_timeout,
        )

    def __repr__(self) -> str:
        return (
            f"SageConfig(host={self.host!r}, port={self.port}, "
            f"database={self.database!r}, username={self.username!r}, "
            f"password='***REDACTED***', timeout={self.timeout}, "
            f"max_rows={self.max_rows}, label={self.label!r}, "
            f"odbc_driver={self.odbc_driver!r})"
        )


@dataclass
class SMTPConfig:
    """Configuration SMTP (par défaut : STARTTLS sur port 587)."""

    host: str = field(default_factory=lambda: os.getenv("SMTP_HOST", "localhost"))
    port: int = field(
        default_factory=lambda: _safe_int(os.getenv("SMTP_PORT"), _DEFAULT_SMTP_PORT, "SMTP_PORT")
    )
    username: str = field(default_factory=lambda: os.getenv("SMTP_USER", ""))
    password: str = field(default_factory=lambda: os.getenv("SMTP_PASSWORD", ""))
    use_tls: bool = True
    from_email: str = field(default_factory=lambda: os.getenv("SMTP_FROM", "noreply@localhost"))
    # ``from_name`` est le nom affiché en expéditeur SMTP. Vide par défaut —
    # à la lecture, ``app.services.branding.get_smtp_from_name()`` lit la
    # valeur configurée par l'admin depuis ``smtp_global_config``. Pas de
    # hardcode "Komptia"/"Cabinet X" ici (axe 6 : généricité).
    from_name: str = ""

    def __repr__(self) -> str:
        return (
            f"SMTPConfig(host={self.host!r}, port={self.port}, "
            f"username={self.username!r}, password='***REDACTED***', "
            f"use_tls={self.use_tls}, from_email={self.from_email!r})"
        )


@dataclass
class SecurityConfig:
    """Configuration sécurité (tokens, sessions, hash).

    ``rate_limit_login`` : nombre max de tentatives ratées par fenêtre. Le
    handler ``auth.py`` l'applique **à la fois** par IP et par username (ASVS
    4.0 V2.2.1 + anti-automation). ``rate_limit_login_window_seconds`` : durée
    de la fenêtre glissante. 5 / 900 s reflète l'OWASP Auth Cheat Sheet : un
    humain qui oublie son mot de passe retape 2-3 fois ; un bot testant 5
    combinaisons en 15 min est à bloquer.
    """

    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", _SECRET_KEY_SENTINEL))
    session_timeout_hours: int = 8
    # Durée appliquée quand l'utilisateur coche "Garder ma session ouverte"
    # à la connexion. 168h = 7 jours (default sain pour un SaaS comptable).
    # SSoT côté BDD : colonne ``sessions.remember_me`` Boolean + lecture
    # dans ``Session.refresh()`` pour le glissement, et dans
    # ``SessionManager.create_session(remember_me)`` à la création.
    # Le cookie ``set_secure_cookie`` côté handler aligne ``expires_days``
    # sur la même durée pour éviter cookie-vivant/session-morte.
    session_remember_timeout_hours: int = 168
    csrf_enabled: bool = True
    rate_limit_login: int = 5
    rate_limit_login_window_seconds: int = 900
    bcrypt_rounds: int = _DEFAULT_BCRYPT_ROUNDS
    user_agent_log_max_length: int = 500

    def __repr__(self) -> str:
        return (
            f"SecurityConfig(secret_key='***REDACTED***', "
            f"session_timeout_hours={self.session_timeout_hours}, "
            f"csrf_enabled={self.csrf_enabled}, "
            f"rate_limit_login={self.rate_limit_login}, "
            f"rate_limit_login_window_seconds={self.rate_limit_login_window_seconds}, "
            f"bcrypt_rounds={self.bcrypt_rounds}, "
            f"user_agent_log_max_length={self.user_agent_log_max_length})"
        )


@dataclass
class ServerConfig:
    """Configuration serveur Tornado.

    ``slow_request_threshold_s`` : seuil au-delà duquel ``BaseHandler.on_finish``
    émet un warning "requête lente" avec ``request_id`` pour corréler. 1 s par
    défaut — assez long pour ne pas polluer en dev local, assez court pour
    flagger du code lent en prod.

    ``db_session_timeout_s`` : timeout du ``await session.commit()`` dans
    ``BaseHandler.db_session`` — évite qu'un handler reste bloqué si SQLite
    est locked par un autre writer. 30 s par défaut (aligné sur le timeout de
    connexion Sage).
    """

    host: str = "127.0.0.1"
    port: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("SERVER_PORT"), _DEFAULT_SERVER_PORT, "SERVER_PORT"
        )
    )
    debug: bool = field(default_factory=lambda: os.getenv("DEBUG", "false").lower() == "true")
    autoreload: bool = field(default_factory=lambda: os.getenv("DEBUG", "false").lower() == "true")
    num_processes: int = 1
    slow_request_threshold_s: float = 1.0
    db_session_timeout_s: float = 30.0
    timezone: str = field(default_factory=_get_default_timezone)

    #: Honorer les en-têtes ``X-Forwarded-For`` / ``X-Forwarded-Proto`` /
    #: ``X-Real-IP`` (Tornado ``xheaders``). **fail-safe = False.**
    #: À activer (``trust_proxy_headers: true`` dans ``config.yaml``)
    #: UNIQUEMENT quand l'app tourne derrière un reverse-proxy de confiance
    #: (ex. nginx) ET qu'elle n'est joignable QUE par ce proxy (port bindé sur
    #: ``127.0.0.1`` dans ``docker-compose``). Sinon n'importe quel client en
    #: direct pourrait usurper ces en-têtes (faux ``X-Forwarded-Proto: https``
    #: pour contourner un check HTTPS, fausse IP pour échapper au rate-limiter
    #: ou forger l'audit-trail). Quand activé : l'app voit la vraie IP client
    #: (rate-limiter login per-user au lieu d'un seul bucket proxy), émet HSTS,
    #: et génère des URLs ``https://`` correctes (webhooks/rapports).
    trust_proxy_headers: bool = False


@dataclass
class LimitsConfig:
    """Limites de capacité applicative.

    Note : la taille max d'un fichier uploadé et le nombre max de lignes par
    requête SQL ne vivent PAS ici — ce sont des réglages admin éditables en
    base (source unique de vérité) :

    - taille upload → ``AIConfig.MAX_UPLOAD_SIZE_BYTES`` (/admin/performance),
      lue via ``config_service.get_max_upload_size_bytes()`` ;
    - lignes par requête SQL → ``DatabaseConnection.max_rows`` (/admin/database).

    Les anciens champs ``max_file_size_mb`` / ``max_query_results`` figuraient
    ici mais n'étaient lus par AUCUN code (« costume sans corps ») — retirés le
    2026-05-28 pour éliminer une fausse source de vérité.
    """

    max_users: int = 50
    max_users_warning_at: int = 45
    allow_admin_override: bool = True


@dataclass
class LLMLogConfig:
    """Configuration rotation et rétention de ``llm_log.md``.

    Le fichier accumule tous les échanges LLM (audit + debug). Sans rotation
    il atteint des centaines de Mo en quelques semaines (35 Mo / 498k lignes
    au 2026-05-19 avant cette feature). Trois axes de bornage composables :

    - ``max_size_bytes`` : taille au-delà de laquelle le fichier actif est
      rotaté (rename vers ``llm_log.YYYY-MM-DDTHHMMSS.md``).
    - ``retention_days`` : âge maximum des archives (supprimées par le
      job scheduler quotidien).
    - ``max_archives`` : nombre maximum d'archives conservées (cap dur
      indépendant du TTL — protège contre un burst de rotations dans la
      journée).

    Les trois sont composables : le cap le plus strict gagne. ``llm_logger``
    lit les mêmes variables d'environnement directement pour permettre
    l'usage du module sans dépendance sur ``app.config`` (hot path LLM,
    testabilité). Cette dataclass expose la même configuration pour le
    tooling (admin UI future, diagnostics).

    Env vars (canoniques + alias historiques pour rétro-compat) :
        LLM_LOG_MAX_BYTES (alias : LLM_LOG_MAX_SIZE_BYTES)
        LLM_LOG_RETAIN_DAYS (alias : LLM_LOG_RETENTION_DAYS)
        LLM_LOG_MAX_ARCHIVES
    """

    max_size_bytes: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("LLM_LOG_MAX_BYTES") or os.getenv("LLM_LOG_MAX_SIZE_BYTES"),
            50 * 1024 * 1024,
            "LLM_LOG_MAX_BYTES",
        )
    )
    retention_days: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("LLM_LOG_RETAIN_DAYS") or os.getenv("LLM_LOG_RETENTION_DAYS"),
            14,
            "LLM_LOG_RETAIN_DAYS",
        )
    )
    max_archives: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("LLM_LOG_MAX_ARCHIVES"),
            5,
            "LLM_LOG_MAX_ARCHIVES",
        )
    )


@dataclass
class BackupConfig:
    """Sauvegarde automatique de la BDD locale (SQLite/SQLCipher).

    **Désactivée par défaut** (opt-in fail-safe) : un déploiement ne sauvegarde
    rien tant que l'ops ne l'active pas explicitement (``KOMPTIA_AUTO_BACKUP_ENABLED``).
    Une fois activée, un job scheduler quotidien (cf. ``scheduler.py``, câblage
    sous-étape ultérieure) produit un snapshot cohérent de la BDD dans
    ``config.backups_dir`` et applique une rotation bornée : ``retention_count``
    ET ``retention_days`` sont composables, le plus strict gagne (même logique
    que :class:`LLMLogConfig`).

    NB : ces snapshots vivent dans le volume de données (staging local) ; le
    push **off-site** (règle 3-2-1) est une étape complémentaire configurée
    séparément — un snapshot dans le volume ne protège pas d'une perte du volume.

    Env vars :
        KOMPTIA_AUTO_BACKUP_ENABLED (true/false — défaut false)
        KOMPTIA_AUTO_BACKUP_HOUR (0-23 — défaut 3, AVANT le cleanup TTL de 04:00)
        KOMPTIA_AUTO_BACKUP_RETENTION_COUNT (>=1 — défaut 7)
        KOMPTIA_AUTO_BACKUP_RETENTION_DAYS (>=1 — défaut 30)
    """

    enabled: bool = field(
        default_factory=lambda: os.getenv("KOMPTIA_AUTO_BACKUP_ENABLED", "false").lower() == "true"
    )
    hour: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("KOMPTIA_AUTO_BACKUP_HOUR"), 3, "KOMPTIA_AUTO_BACKUP_HOUR"
        )
    )
    retention_count: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("KOMPTIA_AUTO_BACKUP_RETENTION_COUNT"),
            7,
            "KOMPTIA_AUTO_BACKUP_RETENTION_COUNT",
        )
    )
    retention_days: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("KOMPTIA_AUTO_BACKUP_RETENTION_DAYS"),
            30,
            "KOMPTIA_AUTO_BACKUP_RETENTION_DAYS",
        )
    )
    #: Répertoire off-site (montage NFS/SMB/rclone, USB…) où copier chaque
    #: snapshot après création — règle 3-2-1. Vide = pas d'off-site. DOIT déjà
    #: exister au moment du backup : on ne crée PAS le dossier (un mkdir sur un
    #: montage indisponible produirait un faux off-site local silencieux).
    #: Env : KOMPTIA_AUTO_BACKUP_OFFSITE_DIR.
    offsite_dir: str = field(
        default_factory=lambda: os.getenv("KOMPTIA_AUTO_BACKUP_OFFSITE_DIR", "")
    )


@dataclass
class DiskConfig:
    """Seuils de surveillance de l'espace libre du volume de données.

    ``data_dir`` héberge tout ce qui croît (BDD SQLite, logs, backups, uploads —
    cf. zone 10 review). Sans surveillance, une saturation = crash SQLite
    « disk I/O error » SANS alerte préalable. Ces seuils alimentent le check
    ``diagnostics._check_disk_space`` (boot + runtime) :

    - libre < ``critical_free_mb`` → status error + log CRITICAL ;
    - libre < ``warn_free_mb`` → status warning.

    Env : KOMPTIA_DISK_WARN_FREE_MB (défaut 1024), KOMPTIA_DISK_CRITICAL_FREE_MB (défaut 256).
    """

    warn_free_mb: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("KOMPTIA_DISK_WARN_FREE_MB"), 1024, "KOMPTIA_DISK_WARN_FREE_MB"
        )
    )
    critical_free_mb: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("KOMPTIA_DISK_CRITICAL_FREE_MB"), 256, "KOMPTIA_DISK_CRITICAL_FREE_MB"
        )
    )
    #: Période (heures) du check disque runtime via le scheduler — capte la
    #: saturation PENDANT l'exploitation (le boot-check ne la voit qu'au restart).
    #: <= 0 → check périodique désactivé (le boot-check reste actif).
    #: Env : KOMPTIA_DISK_CHECK_INTERVAL_HOURS (défaut 6).
    check_interval_hours: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("KOMPTIA_DISK_CHECK_INTERVAL_HOURS"), 6, "KOMPTIA_DISK_CHECK_INTERVAL_HOURS"
        )
    )
    #: Fenêtre anti-spam (heures) entre deux alertes mail disque-critique vers
    #: ``support_email``. Une alerte au plus toutes les N heures, même si le check
    #: tourne plus souvent. (L'alerte mail est de toute façon no-op si
    #: ``support_email`` / SMTP ne sont pas configurés.)
    #: Env : KOMPTIA_DISK_ALERT_THROTTLE_HOURS (défaut 24).
    alert_throttle_hours: int = field(
        default_factory=lambda: _safe_int(
            os.getenv("KOMPTIA_DISK_ALERT_THROTTLE_HOURS"), 24, "KOMPTIA_DISK_ALERT_THROTTLE_HOURS"
        )
    )


@dataclass
class AppConfig:
    """Configuration principale Komptia (composition des sous-configs)."""

    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    sage: SageConfig = field(default_factory=SageConfig)
    smtp: SMTPConfig = field(default_factory=SMTPConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    llm_log: LLMLogConfig = field(default_factory=LLMLogConfig)
    backup: BackupConfig = field(default_factory=BackupConfig)
    disk: DiskConfig = field(default_factory=DiskConfig)

    #: Nom du produit affiché dans l'UI (titre, navbar, mails de feedback,
    #: etc.). Override possible par ``KOMPTIA_APP_NAME`` dans ``.env`` —
    #: utile pour un déploiement white-label ou un environnement de
    #: démonstration. Le code reste générique : aucune logique métier ne
    #: dépend de cette valeur.
    app_name: str = field(default_factory=lambda: os.getenv("KOMPTIA_APP_NAME") or "Komptia")
    #: Version applicative exposée sur ``/health/detailed``. Dérivable du build
    #: via ``KOMPTIA_APP_VERSION`` (ENV posé au build, ex. ``git describe`` →
    #: distingue deux déploiements / vérifie qu'un update a landé). Fallback sur
    #: le littéral statique si non posé. Même pattern dynamique que ``app_name``.
    app_version: str = field(
        default_factory=lambda: os.getenv("KOMPTIA_APP_VERSION") or _read_version_file() or "2.0.0"
    )
    environment: str = field(default_factory=lambda: os.getenv("ENVIRONMENT", _ENV_DEVELOPMENT))

    # Email destinataire des rapports d'erreurs/feedback. **Seule source de
    # vérité = ``SMTPGlobalConfig.support_email`` éditable via
    # ``/admin/smtp-config``** (décision user 2026-05-19, aucun hardcode).
    # Si non configuré côté admin, les signalements sont persistés en
    # audit-trail local mais aucun mail n'est envoyé (cf.
    # ``FeedbackService._send_email`` qui retourne False sans recipient).
    # Le champ reste défini ici (avec valeur vide) pour rétro-compat des
    # callers existants — la valeur effective est résolue par
    # ``FeedbackService._resolve_support_email``.
    support_email: str = ""

    base_dir: Path = BASE_DIR
    data_dir: Path = DATA_DIR
    logs_dir: Path = LOGS_DIR
    reports_dir: Path = REPORTS_DIR
    templates_dir: Path = TEMPLATES_DIR
    static_dir: Path = STATIC_DIR
    guides_dir: Path = GUIDES_DIR

    #: Répertoire des snapshots de backup auto. Sous ``data_dir`` par défaut
    #: (dans le volume), override absolu possible via ``KOMPTIA_AUTO_BACKUP_DIR``
    #: (p.ex. un montage off-site/NFS). Créé seulement si ``backup.enabled``.
    backups_dir: Path = field(
        default_factory=lambda: (
            Path(os.environ["KOMPTIA_AUTO_BACKUP_DIR"]).expanduser()
            if os.getenv("KOMPTIA_AUTO_BACKUP_DIR")
            else DATA_DIR / "backups"
        )
    )

    def __post_init__(self) -> None:
        """Crée les répertoires nécessaires et valide la configuration."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        # backups_dir créé uniquement si la sauvegarde auto est activée — pas de
        # répertoire vide parasite sur un déploiement qui n'a pas opté-in.
        if self.backup.enabled:
            self.backups_dir.mkdir(parents=True, exist_ok=True)
        self._validate()

    def _validate(self) -> None:
        """Validation cross-field (appelée après chaque mutation de la config).

        Centralise toutes les règles pour que `from_yaml` puisse re-valider
        après avoir muté les sous-configs via `setattr`.
        """
        _validate_port(self.server.port, "server.port")
        _validate_port(self.sage.port, "sage.port")
        _validate_port(self.smtp.port, "smtp.port")

        # Sauvegarde auto : validation fail-loud UNIQUEMENT si activée (un
        # déploiement opt-out ne doit pas crasher sur des valeurs backup non
        # pertinentes). Pas de clamp silencieux → l'ops voit son erreur.
        if self.backup.enabled:
            if not (0 <= self.backup.hour <= 23):
                raise ValueError(
                    f"backup.hour invalide ({self.backup.hour}) — attendu 0..23 "
                    "(KOMPTIA_AUTO_BACKUP_HOUR)"
                )
            if self.backup.retention_count < 1:
                raise ValueError(
                    f"backup.retention_count invalide ({self.backup.retention_count}) — "
                    "attendu >=1 (KOMPTIA_AUTO_BACKUP_RETENTION_COUNT)"
                )
            if self.backup.retention_days < 1:
                raise ValueError(
                    f"backup.retention_days invalide ({self.backup.retention_days}) — "
                    "attendu >=1 (KOMPTIA_AUTO_BACKUP_RETENTION_DAYS)"
                )

        if self.security.secret_key == _SECRET_KEY_SENTINEL:
            if self.environment != _ENV_DEVELOPMENT:
                raise RuntimeError(
                    "SECRET_KEY non définie. Définissez la variable d'environnement "
                    "SECRET_KEY avec une valeur sécurisée (32 caractères minimum)."
                )
            warnings.warn(
                "SECRET_KEY utilise la valeur par défaut. "
                "Définissez SECRET_KEY dans .env avant tout déploiement.",
                stacklevel=2,
            )

        # Fail-closed : XSRF ne doit JAMAIS être désactivé en production. Un
        # seul flag à False ferait perdre la protection CSRF à TOUTES les
        # mutations (POST/PUT/DELETE). Le défaut est True ; on refuse de
        # démarrer si un override (code ou futur env) le passe à False en prod.
        if self.environment == _ENV_PRODUCTION and not self.security.csrf_enabled:
            raise RuntimeError(
                "csrf_enabled=False en production — protection CSRF désactivée "
                "pour toutes les mutations. Refus de démarrer (fail-closed) ; "
                "réactivez csrf_enabled."
            )

        if self.database.encryption_key:
            if len(self.database.encryption_key) < _MIN_SQLCIPHER_KEY_LENGTH:
                raise RuntimeError(
                    f"SQLCIPHER_KEY trop courte "
                    f"({len(self.database.encryption_key)} caractères). "
                    f"Minimum requis : {_MIN_SQLCIPHER_KEY_LENGTH} caractères."
                )
        elif self.environment == _ENV_PRODUCTION:
            raise RuntimeError(
                "SQLCIPHER_KEY non définie en production — la base de données "
                "ne sera PAS chiffrée. Définissez SQLCIPHER_KEY dans .env."
            )
        elif self.environment != _ENV_DEVELOPMENT:
            warnings.warn(
                "SQLCIPHER_KEY non définie — la base de données ne sera PAS chiffrée. "
                "Définissez SQLCIPHER_KEY dans .env pour activer le chiffrement.",
                stacklevel=2,
            )

        if self.security.bcrypt_rounds < _MIN_BCRYPT_ROUNDS:
            raise RuntimeError(
                f"bcrypt_rounds={self.security.bcrypt_rounds} trop faible. "
                f"Minimum OWASP 2024/2025 : {_MIN_BCRYPT_ROUNDS}."
            )

        if self.security.session_timeout_hours <= 0:
            raise RuntimeError(
                f"session_timeout_hours={self.security.session_timeout_hours} "
                f"doit être strictement positif."
            )

        if self.security.session_remember_timeout_hours <= 0:
            raise RuntimeError(
                f"session_remember_timeout_hours="
                f"{self.security.session_remember_timeout_hours} "
                f"doit être strictement positif (sinon expiration immédiate "
                f"ou dans le passé des sessions « rester connecté »)."
            )

        if self.security.rate_limit_login <= 0:
            raise RuntimeError(
                f"rate_limit_login={self.security.rate_limit_login} doit être strictement positif "
                f"(sinon l'authentification est totalement bloquée)."
            )

        if self.security.rate_limit_login_window_seconds <= 0:
            raise RuntimeError(
                f"rate_limit_login_window_seconds="
                f"{self.security.rate_limit_login_window_seconds} "
                f"doit être strictement positif."
            )

        if self.security.user_agent_log_max_length <= 0:
            raise RuntimeError(
                f"user_agent_log_max_length="
                f"{self.security.user_agent_log_max_length} "
                f"doit être strictement positif."
            )

        if self.server.slow_request_threshold_s <= 0:
            raise RuntimeError(
                f"server.slow_request_threshold_s="
                f"{self.server.slow_request_threshold_s} "
                f"doit être strictement positif."
            )

        if self.server.db_session_timeout_s <= 0:
            raise RuntimeError(
                f"server.db_session_timeout_s="
                f"{self.server.db_session_timeout_s} "
                f"doit être strictement positif."
            )

        if not self.sage.database:
            if self.environment == _ENV_PRODUCTION:
                raise RuntimeError(
                    "SAGE_DB_NAME non définie en production. "
                    "Renseignez le nom de votre base SQL Server dans .env."
                )
            if self.environment != _ENV_DEVELOPMENT:
                warnings.warn(
                    "SAGE_DB_NAME non définie. Renseignez le nom de votre base "
                    "SQL Server dans .env.",
                    stacklevel=2,
                )

    @classmethod
    def from_yaml(cls, config_path: Path | None = None) -> "AppConfig":
        """Charge la configuration en fusionnant defaults + YAML + env vars.

        Pour les sections ayant un préfixe env (SAGE_DB_*, SQLCIPHER_*), les
        valeurs YAML sont ignorées si la variable d'environnement correspondante
        est déjà définie — préserve la précédence env > yaml.
        """
        if config_path is None:
            config_path = BASE_DIR / "config.yaml"

        config = cls()

        if not config_path.exists():
            return config

        # Piège classique du bind-mount Docker : si ``config.yaml`` manque sur
        # l'HÔTE, Docker crée un RÉPERTOIRE vide à l'emplacement monté. ``exists()``
        # est alors vrai mais ``open()`` lèverait ``IsADirectoryError`` (non
        # rattrapé par ``except yaml.YAMLError``) → crash opaque au boot. On
        # échoue FORT et CLAIR (et on ne retombe PAS silencieusement sur les
        # défauts : ça masquerait une config trust_proxy/timezone perdue).
        if not config_path.is_file():
            raise RuntimeError(
                f"{config_path} existe mais n'est PAS un fichier (répertoire ?). "
                "Piège du bind-mount Docker : le fichier config.yaml manque sur "
                "l'hôte → Docker a monté un dossier vide. Créez config.yaml sur "
                "l'hôte (ex: copiez-le depuis le dépôt), puis relancez."
            )

        try:
            with config_path.open("r", encoding="utf-8") as f:
                yaml_config = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise RuntimeError(
                f"config.yaml contient du YAML invalide. "
                f"Vérifiez la syntaxe de {config_path}: {e}"
            ) from e

        if not isinstance(yaml_config, dict):
            raise RuntimeError(
                f"config.yaml doit contenir un mapping YAML (dict), "
                f"pas un {type(yaml_config).__name__}"
            )

        _apply_yaml_section(config.server, yaml_config.get("server"))
        _apply_yaml_section(config.limits, yaml_config.get("limits"))
        _apply_yaml_section(config.database, yaml_config.get("database"), env_prefix="SQLCIPHER_")
        _apply_yaml_section(config.sage, yaml_config.get("sage"), env_prefix="SAGE_DB_")
        # `security:` appliqué de façon DÉFENSIVE : `secret_key` (et tout secret)
        # EXCLU — le secret vient exclusivement de l'env SECRET_KEY ; config.yaml
        # est tracké git et ne doit jamais porter de secret ni écraser l'env.
        # Coercition de type explicite des champs whitelistés (cf. helper).
        _apply_security_yaml(config.security, yaml_config.get("security"))

        # Re-valider après mutations YAML — un yaml peut introduire des valeurs
        # qui violent les invariants vérifiés par __post_init__.
        config._validate()
        return config

    def is_production(self) -> bool:
        return self.environment == _ENV_PRODUCTION

    def is_development(self) -> bool:
        """Vrai uniquement en environnement de développement explicite.

        Symétrique de :meth:`is_production`. Toute autre valeur
        (``staging``, ``production``, ou une valeur ``ENVIRONMENT``
        inattendue) renvoie ``False`` — utile pour gater une UI/outil
        réservé au dev en *fail-closed* (on n'affiche que si c'est
        explicitement le dev, jamais par défaut).
        """
        return self.environment == _ENV_DEVELOPMENT

    def is_debug(self) -> bool:
        return self.server.debug


def _apply_yaml_section(target: Any, section: dict | None, env_prefix: str = "") -> None:
    """Applique les valeurs d'une section YAML sur un dataclass cible.

    Si `env_prefix` est fourni, un champ YAML est ignoré quand
    `os.getenv(env_prefix + KEY)` est défini — garantit la précédence env > yaml.
    """
    if not section:
        return
    for key, value in section.items():
        if not hasattr(target, key):
            continue
        if env_prefix and os.getenv(f"{env_prefix}{key.upper()}"):
            continue
        setattr(target, key, value)


# Champs de ``SecurityConfig`` surchargeables depuis ``config.yaml`` (section
# ``security:``). ``secret_key`` est VOLONTAIREMENT absent : c'est un secret,
# il vient exclusivement de l'env ``SECRET_KEY``.
_SECURITY_YAML_INT_KEYS = frozenset(
    {
        "session_timeout_hours",
        "session_remember_timeout_hours",
        "rate_limit_login",
        "rate_limit_login_window_seconds",
        "bcrypt_rounds",
        "user_agent_log_max_length",
    }
)
_SECURITY_YAML_BOOL_KEYS = frozenset({"csrf_enabled"})


def _apply_security_yaml(target: Any, section: dict | None) -> None:
    """Applique la section ``security:`` du YAML de façon DÉFENSIVE.

    - ``secret_key`` (et toute clé non whitelistée) est **ignorée** : le secret
      vient exclusivement de l'env ``SECRET_KEY``. ``config.yaml`` est tracké
      dans git et ne doit jamais porter de secret ni écraser l'environnement.
    - **Coercition de type explicite** : YAML peut quoter un entier
      (``bcrypt_rounds: "12"``) ou un booléen — sans coercition, ``_validate``
      lèverait un ``TypeError`` opaque au boot, ou une string truthy
      (``csrf_enabled: "false"``) contournerait une garde fail-closed. Une
      valeur non castable est ignorée (le défaut sûr est conservé) + ``warn``.
    """
    if not section:
        return
    for key, value in section.items():
        if key in _SECURITY_YAML_INT_KEYS:
            try:
                setattr(target, key, int(value))
            except (TypeError, ValueError):
                warnings.warn(
                    f"config.yaml security.{key}={value!r} ignoré "
                    f"(entier attendu) — valeur par défaut conservée.",
                    stacklevel=2,
                )
        elif key in _SECURITY_YAML_BOOL_KEYS:
            if isinstance(value, bool):
                setattr(target, key, value)
            elif isinstance(value, str):
                setattr(target, key, value.strip().lower() in ("true", "1", "yes", "on"))
            else:
                setattr(target, key, bool(value))
        # secret_key et clés inconnues : volontairement ignorées.


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """Retourne l'instance singleton de configuration.

    Thread-safe en Python 3.10+ (lru_cache protège la première instanciation).
    Pour forcer un rechargement dans les tests : `get_config.cache_clear()`.
    """
    return AppConfig.from_yaml()


def get_source_db_label() -> str:
    """Retourne le label affichable de la BDD source (ex: 'Base SQL Server')."""
    return get_config().sage.label


# Instance module-level pour import direct (`from app.config import config`).
# Voir note sur les side-effects à l'import dans le docstring du module.
config = get_config()
