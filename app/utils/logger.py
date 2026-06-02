"""
Logging structuré pour Komptia
Format JSON pour faciliter l'analyse des logs
"""

import logging
import logging.handlers
import json
import sys
from typing import Dict, Any

from app.core import clock

from app.config import config


class JSONFormatter(logging.Formatter):
    """Formatter JSON pour logs structurés.

    Récupère DEUX sources de contexte :
    * ``record.extra_data`` (dict) — posé par ``log_with_context``.
    * ``record.<key>`` (champs custom) — posés par ``logger.X("msg", extra={...})``.

    Ce 2ᵉ chemin est essentiel : sans ça, ``logger.info("X", extra={"request_id": "abc"})``
    ne logue PAS le ``request_id`` (bug d'observabilité critique). On
    fait la diff avec les attributs standard ``LogRecord`` pour ne pas
    écraser ``message``/``level``/etc.

    SÉCURITÉ : tout attribut dont le nom évoque un secret est masqué par
    ``[REDACTED]``. Le passthrough automatique simplifie l'usage mais
    introduit un foot-gun : un dev qui logue ``extra={"password": data["pw"]}``
    par inadvertance ne doit pas voir son secret atterrir en clair dans
    ``komptia.log`` + ``errors.log`` (rétention 30 jours). Defense-in-depth
    contre une fuite accidentelle ; ne remplace pas la review de code.
    """

    # Attributs natifs de LogRecord — à exclure du dump pour ne pas
    # masquer les champs déjà sérialisés (level/message/etc.).
    _STANDARD_ATTRS = frozenset(
        {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "extra_data",
            "message",
            "asctime",
            "taskName",
        }
    )

    # Tokens (substring lowercase) qui déclenchent un masquage automatique.
    # Match SUBSTRING insensible à la casse — couvre ``password``, ``api_key``,
    # ``user_password``, ``X-API-Key``, ``private_key``, etc. sans hardcoder
    # toutes les variantes. Les noms d'IDENTIFIANTS publics (``user_id``,
    # ``request_id``, ``contact_id``) restent visibles car ils ne contiennent
    # aucun de ces tokens.
    _SENSITIVE_TOKENS: frozenset[str] = frozenset(
        {
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "cookie",
            "session_token",
            "private_key",
            "credential",
            "encryption",
            "_xsrf",
            "xsrf_token",
        }
    )

    # Borne par valeur loggée — au-delà, troncature avec marqueur. Une stack
    # trace SQL ou un body JSON malicieux ne doivent pas remplir le disque.
    _MAX_VALUE_LENGTH: int = 4096

    @classmethod
    def _is_sensitive_key(cls, key: str) -> bool:
        """Indique si la clé évoque un secret. Match substring insensible à la casse."""
        kl = key.lower()
        return any(token in kl for token in cls._SENSITIVE_TOKENS)

    @classmethod
    def _scrub_value(cls, key: str, value: object) -> object:
        """Renvoie ``[REDACTED]`` si la clé évoque un secret, sinon la valeur
        (éventuellement tronquée si trop longue)."""
        if cls._is_sensitive_key(key):
            return "[REDACTED]"
        if isinstance(value, str) and len(value) > cls._MAX_VALUE_LENGTH:
            return value[: cls._MAX_VALUE_LENGTH] + f"...[truncated {len(value)}]"
        return value

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": clock.now().isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Données via ``log_with_context`` (legacy) — scrubbed également.
        if hasattr(record, "extra_data"):
            data = record.extra_data
            if isinstance(data, dict):
                log_data["data"] = {k: self._scrub_value(k, v) for k, v in data.items()}
            else:
                log_data["data"] = data

        # Données via ``logger.X("msg", extra={"request_id": "abc"})`` :
        # tout attribut de record non-standard est exposé sous sa propre clé.
        # Scrubbing systématique des clés sensibles (cf. _SENSITIVE_TOKENS).
        for key, value in record.__dict__.items():
            if key not in self._STANDARD_ATTRS and not key.startswith("_"):
                log_data[key] = self._scrub_value(key, value)

        return json.dumps(log_data, ensure_ascii=False, default=str)


class ConsoleFormatter(logging.Formatter):
    """Formatter coloré pour la console"""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Vert
        "WARNING": "\033[33m",  # Jaune
        "ERROR": "\033[31m",  # Rouge
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)

        # Format lisible pour console — heure LOCALE de la machine hôte
        timestamp = clock.now_local().strftime("%H:%M:%S")
        message = f"{color}[{timestamp}] {record.levelname:8}{self.RESET} {record.name}: {record.getMessage()}"

        if record.exc_info:
            message += f"\n{self.formatException(record.exc_info)}"

        return message


class AppLogger:
    """
    Logger centralisé pour Komptia

    Usage:
        from app.utils.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Message", extra_data={"user_id": 123})
    """

    _loggers: Dict[str, logging.Logger] = {}
    _initialized = False

    @classmethod
    def setup(cls, log_level: str = "INFO") -> None:
        """Configure le système de logging"""
        if cls._initialized:
            return

        # Créer répertoire logs
        config.logs_dir.mkdir(parents=True, exist_ok=True)

        # Niveau de log
        level = getattr(logging, log_level.upper(), logging.INFO)

        # Logger racine
        root_logger = logging.getLogger("komptia")
        root_logger.setLevel(level)

        # Handler console
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        if config.is_debug():
            console_handler.setFormatter(ConsoleFormatter())
        else:
            console_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(console_handler)

        # Handler fichier (rotation quotidienne)
        file_handler = logging.handlers.TimedRotatingFileHandler(
            config.logs_dir / "komptia.log",
            when="midnight",
            interval=1,
            backupCount=30,  # Garde 30 jours
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(file_handler)

        # Handler erreurs séparé
        error_handler = logging.handlers.RotatingFileHandler(
            config.logs_dir / "errors.log",
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(error_handler)

        cls._initialized = True
        root_logger.info("Logging initialisé", extra={"log_level": log_level})

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """Retourne un logger pour le module spécifié"""
        if not cls._initialized:
            cls.setup("DEBUG" if config.is_debug() else "INFO")

        if name not in cls._loggers:
            # Préfixer avec komptia pour hiérarchie
            logger_name = f"komptia.{name}" if not name.startswith("komptia") else name
            cls._loggers[name] = logging.getLogger(logger_name)

        return cls._loggers[name]


def get_logger(name: str) -> logging.Logger:
    """
    Raccourci pour obtenir un logger

    Usage:
        from app.utils.logger import get_logger
        logger = get_logger(__name__)
    """
    return AppLogger.get_logger(name)


def log_with_context(logger: logging.Logger, level: str, message: str, **context: Any) -> None:
    """
    Log avec contexte additionnel

    Usage:
        log_with_context(logger, "info", "User logged in", user_id=123, ip="1.2.3.4")
    """
    record = logging.LogRecord(
        name=logger.name,
        level=getattr(logging, level.upper()),
        pathname="",
        lineno=0,
        msg=message,
        args=(),
        exc_info=None,
    )
    record.extra_data = context
    logger.handle(record)
