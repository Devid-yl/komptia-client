"""Handlers Tornado pour l'agent Iris.

Routes publiques
----------------
* ``GET /iris`` — :class:`IrisPageHandler` : page HTML + re-hydratation de la
  conversation active.
* ``WS /ws/iris`` — :class:`IrisWebSocketHandler` : streaming temps-réel des
  événements ``agent.run()``.
* ``POST /api/iris/clear`` — :class:`IrisClearAPIHandler` : soft-delete des
  conversations actives de l'utilisateur.
* ``POST /api/iris/feedback`` — :class:`IrisFeedbackAPIHandler` : feedback
  sur le dernier message assistant (``positive``/``adjust``/``negative``).
* ``POST /api/iris/upload`` — :class:`IrisUploadHandler` : upload CSV/Excel
  pour analyse, avec validation défensive (extension, taille, magic bytes,
  path-traversal).

Principes d'ingénierie
----------------------
1. **Handlers minces** — chaque handler délègue aux helpers privés du module ;
   aucun handler ne dépasse 80 lignes.
2. **Messages centralisés** — :class:`_Messages` est la source unique de
   vérité pour les libellés utilisateur (français, ton cohérent).
3. **Rate-limit partagé** — :class:`~app.utils.rate_limiter.RateLimiter`
   (même pattern que ``datastore.py`` / ``contacts.py``) au lieu d'un dict
   global ad-hoc.
4. **Tool-description unique** — :func:`build_tool_description` est la
   source unique : réutilisée à la fois par la ré-hydratation côté handler
   et par le streaming côté ``agent_service``.
5. **Upload fail-closed** — :class:`_UploadValidator` vérifie l'extension,
   la taille, le magic-byte et le path canonique avant d'écrire.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import logging
import os
from contextlib import contextmanager
import re
import uuid
from pathlib import Path
from typing import Any, Callable, Final, Mapping, Optional
from urllib.parse import urlparse

import tornado.web
import tornado.websocket
from sqlalchemy import delete, desc, select, update
from sqlalchemy.exc import SQLAlchemyError

from app.config import config
from app.constants import AUTO_FEEDBACK_OPTIONS
from app.core import clock
from app.core.database import get_session
from app.handlers.base import BaseHandler, admin_required, authenticated
from app.models.conversation import (
    Conversation,
    ConversationMessage,
    ConversationSource,
    MessageRole,
)
from app.models.user import User
from app.services.ai.agent_knowledge import get_agent_knowledge
from app.services.ai.agent_roles import AgentRole, FILE_ATTACHMENT_MARKER
from app.services.ai.agent_service import TOOL_LABELS, get_iris_agent
from app.services.ai.llm_providers import ensure_providers_from_db, get_llm_manager
from app.services.ai.schema_sync import get_sync_service
from app.utils.request_context import request_scope
from app.services.reporting.llm_limits import estimate_tokens, resolve_active_window_snapshot
from app.services.auth.session_manager import get_session_manager
from app.utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


async def _apply_denied_count_update(conv_id: int, denied_in_run: bool) -> None:
    """**Phase 2.5.quinquies (#121)** — Update conversation.consecutive_denied_count.

    Helper module-level (testable sans monter le handler Tornado).
    Incrémente si ``denied_in_run`` est True (au moins un ``tool_result``
    du run portait ``blocked_by="data_access_rule"``) ou reset à 0
    sinon (réponse OK).

    Args:
        conv_id: ID de la conversation à mettre à jour.
        denied_in_run: True si le run a été bloqué par data_access.
    """
    async with get_session() as session:
        if denied_in_run:
            stmt = (
                update(Conversation)
                .where(Conversation.id == conv_id)
                .values(consecutive_denied_count=(Conversation.consecutive_denied_count + 1))
            )
        else:
            stmt = (
                update(Conversation)
                .where(Conversation.id == conv_id)
                .values(consecutive_denied_count=0)
            )
        await session.execute(stmt)
        await session.commit()


# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------


def _int_env(
    name: str,
    default: int,
    *,
    min_: Optional[int] = None,
    max_: Optional[int] = None,
) -> int:
    """Lit une var d'env entière, fallback default si absente ou invalide.

    Clamps optionnels (``min_``, ``max_``) pour protéger contre les valeurs
    aberrantes (ex: ``IRIS_WS_RATE_LIMIT_MESSAGES=0`` figerait toutes les WS).
    Si la valeur env dépasse les bornes, on clamp + log warning explicite
    pour que l'admin sache que sa config a été ajustée.

    Pattern Komptia : config runtime via env vars (cohérent avec
    ``IRIS_DISABLE_EG_FOR_SQL_PATH``). Évite l'ajout d'une AIConfigKey
    + migration BDD + UI admin pour des valeurs d'ops.
    """
    try:
        raw = os.environ.get(name)
        if raw is None or not raw.strip():
            return default
        value = int(raw)
    except (ValueError, TypeError):
        return default
    if min_ is not None and value < min_:
        logger.warning("env var %s=%d below safe min %d — clamped to %d", name, value, min_, min_)
        return min_
    if max_ is not None and value > max_:
        logger.warning("env var %s=%d above safe max %d — clamped to %d", name, value, max_, max_)
        return max_
    return value


def _float_env(
    name: str,
    default: float,
    *,
    min_: Optional[float] = None,
    max_: Optional[float] = None,
) -> float:
    """Variante float pour les timeouts, avec clamps optionnels."""
    try:
        raw = os.environ.get(name)
        if raw is None or not raw.strip():
            return default
        value = float(raw)
    except (ValueError, TypeError):
        return default
    if min_ is not None and value < min_:
        logger.warning("env var %s=%g below safe min %g — clamped to %g", name, value, min_, min_)
        return min_
    if max_ is not None and value > max_:
        logger.warning("env var %s=%g above safe max %g — clamped to %g", name, value, max_, max_)
        return max_
    return value


#: Nombre max de messages WebSocket par utilisateur dans la fenêtre glissante.
#: Préserve l'API publique attendue par ``tests/unit/test_iris_handlers.py``.
#: Ajustable via env ``IRIS_WS_RATE_LIMIT_MESSAGES`` (default 20, clamp [1, 10000]).
_RATE_LIMIT_MESSAGES: Final[int] = _int_env("IRIS_WS_RATE_LIMIT_MESSAGES", 20, min_=1, max_=10000)

#: Largeur de la fenêtre glissante du rate-limiter (secondes).
#: Ajustable via env ``IRIS_WS_RATE_LIMIT_WINDOW_S`` (default 60, clamp [1, 86400]).
_RATE_LIMIT_WINDOW: Final[int] = _int_env("IRIS_WS_RATE_LIMIT_WINDOW_S", 60, min_=1, max_=86400)

#: Timeout per-event sur ``async for event in agent.run(...)``. Sans
#: timeout, un LLM hung ou un appel SQL Sage qui ne renvoie jamais tient
#: la WS du user et le lock conversation indéfiniment. 300 s couvre les
#: events les plus longs observés (pipeline NL→SQL Phase 4 sur schéma
#: large + LLM Sonnet : 60-180 s).
#: Ajustable via env ``IRIS_AGENT_EVENT_TIMEOUT_S`` (default 300, clamp [5, 3600]).
_AGENT_EVENT_TIMEOUT_SECONDS: Final[float] = _float_env(
    "IRIS_AGENT_EVENT_TIMEOUT_S", 300.0, min_=5.0, max_=3600.0
)

#: Cap **wall-clock** total d'un run agent. Sans ce cap, un agent
#: malveillant ou un bug d'agent qui yield ``{"type":"progress"}`` toutes
#: les 290 s peut rester actif indéfiniment (le timeout per-event est
#: reset à chaque event). 30 min couvre les rapports les plus longs
#: (multi-SQL + PDF), au-delà = certaine pathologie.
#: Ajustable via env ``IRIS_AGENT_TOTAL_TIMEOUT_S`` (default 1800, clamp [30, 86400]).
_AGENT_RUN_TOTAL_TIMEOUT_SECONDS: Final[float] = _float_env(
    "IRIS_AGENT_TOTAL_TIMEOUT_S", 1800.0, min_=30.0, max_=86400.0
)

#: Timeout sur ``agent_gen.aclose()`` lui-même. Si l'agent est bloqué
#: dans un ``await provider.stream(...)`` sans checkpoint cancel, le
#: ``GeneratorExit`` injecté par ``aclose()`` ne réveille rien tant que
#: l'await ne retourne pas. Sans timeout, on rebloque sur ``aclose()``
#: et on retient les ressources qu'on essaie justement de libérer.
#: 10 s est généreux pour un cleanup normal, court pour un déblocage
#: d'urgence.
_AGENT_ACLOSE_TIMEOUT_SECONDS: Final[float] = 10.0

#: Cap dur pour le paramètre ``?prompt=`` — pré-remplit l'input Iris depuis
#: un deep-link (dashboards, emails, etc.). 1500 caractères suffisent pour
#: une question utilisateur tout en restant sous les limites de proxy/browser
#: (typiquement 8 Ko d'URL totale) et hors de portée d'un payload DoS.
_MAX_PROMPT_PREFILL_CHARS: Final[int] = 1500

#: Fallback de dernier recours pour la taille max d'un fichier uploadé Iris
#: (octets). La SOURCE UNIQUE de vérité runtime est
#: ``config_service.get_max_upload_size_bytes()`` (réglage admin
#: ``/admin/performance``, défaut 50 Mo) : ``IrisUploadHandler`` la résout et
#: la passe au validateur ainsi qu'au bridge ``uploadConfig`` du template.
#: Cette constante ne sert que si le SSoT est indisponible (valeur par défaut
#: du validateur et de ``_upload_config_for_template``). Alignée sur le défaut
#: du registre AIConfig pour rester cohérente. (Le commentaire historique
#: référençait ``make_file_size_bytes()`` / ``config.limits.max_file_size_mb``
#: qui n'ont jamais existé / n'étaient jamais lus.)
_MAX_UPLOAD_SIZE: Final[int] = 50 * 1024 * 1024

#: Extensions autorisées pour l'upload Iris. Whitelist explicite — JAMAIS
#: de blacklist : on refuse tout ce qui n'est pas listé ici. Le contenu est
#: ensuite validé par :class:`_UploadValidator` (magic-bytes, décodage texte).
#:
#: **SSoT — Task #11**. Cette frozenset est l'UNIQUE source de vérité pour
#: les extensions Iris. Le template ``iris.html`` (attribut ``accept``) et
#: le JS ``iris.js`` (filtrage datastore picker) consomment cette liste
#: via le bridge ``IRIS_CONFIG.uploadConfig`` injecté par
#: :class:`IrisPageHandler` au render. Tout code qui hardcode la liste
#: ailleurs (string ou array) est une régression — voir le test de garde
#: ``tests/unit/test_iris_upload_config_ssot.py``.
_ALLOWED_EXTENSIONS: Final[frozenset[str]] = frozenset({".csv", ".xlsx", ".xls", ".json", ".txt"})


def _upload_config_for_template(max_size_bytes: int = _MAX_UPLOAD_SIZE) -> dict[str, Any]:
    """Construit le dict de configuration upload exposé au frontend via
    ``window.IRIS_CONFIG.uploadConfig``.

    Les extensions dérivent à 100% de :data:`_ALLOWED_EXTENSIONS`. La taille
    max (``max_size_bytes``) est la SSoT runtime résolue par le handler via
    ``config_service.get_max_upload_size_bytes()`` et passée en argument ;
    :data:`_MAX_UPLOAD_SIZE` ne sert que de fallback. Modifier ces sources
    propage automatiquement aux call-sites HTML (attribut ``accept``) et JS
    (filtrage datastore picker, validation pré-upload).

    Args:
        max_size_bytes: limite de taille à exposer au frontend (octets).
            Défaut : ``_MAX_UPLOAD_SIZE`` (fallback). En production, le handler
            passe la valeur du registre AIConfig (``/admin/performance``).

    Returns:
        dict avec :
        - ``extensions`` : liste triée des extensions (ex.
          ``['.csv', '.json', '.txt', '.xls', '.xlsx']``)
        - ``accept_attribute`` : string formattée pour l'attribut HTML
          ``accept`` (ex. ``'.csv,.json,.txt,.xls,.xlsx'``)
        - ``max_size_bytes`` : limite stricte en octets
        - ``max_size_mb`` : limite arrondie en Mo pour affichage user
    """
    sorted_exts = sorted(_ALLOWED_EXTENSIONS)
    return {
        "extensions": sorted_exts,
        "accept_attribute": ",".join(sorted_exts),
        "max_size_bytes": max_size_bytes,
        "max_size_mb": max_size_bytes // (1024 * 1024),
    }


#: Magic-bytes pour les formats binaires (défense en profondeur au-delà de
#: l'extension). Les formats textuels (``csv``/``json``/``txt``) sont validés
#: par un décodage UTF-8 du prologue — cf. :class:`_UploadValidator`.
_MAGIC_BYTES: Final[Mapping[str, bytes]] = {
    "xlsx": b"PK",  # ZIP archive (Office Open XML)
    "xls": b"\xd0\xcf\x11\xe0",  # OLE2 compound document
}

#: Taille max du prologue décodé pour les fichiers textuels (octets).
_TEXT_SNIFF_BYTES: Final[int] = 4096

#: Pattern de sanitisation pour les noms de fichier journalisés (anti log-
#: injection CWE-117). On neutralise tout ce qui n'est pas imprimable ASCII
#: ou usuel Unicode ; les retours chariot et contrôles sont particulièrement
#: bannis pour ne pas polluer les parseurs de logs.
_LOG_UNSAFE_CHARS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

#: Nombre max de rôles que peut prendre un message de rehydratation (borne
#: défensive pour éviter qu'une corruption côté BDD n'entre dans le template).
_MAX_TOOL_DESCRIPTION_CHARS: Final[int] = 240

#: Mode d'exécution par défaut si le client envoie une valeur inconnue.
_DEFAULT_MODE: Final[str] = "execution"

#: Modes d'exécution acceptés par l'agent.
_ALLOWED_MODES: Final[frozenset[str]] = frozenset({"execution", "explanation"})

#: Feedback values acceptés par :class:`IrisFeedbackAPIHandler`.
_ALLOWED_FEEDBACKS: Final[frozenset[str]] = frozenset({"positive", "adjust", "negative"})

#: Base directory pour les uploads Iris. Dérivé de ``config.data_dir`` —
#: zéro chemin absolu hardcodé, portable par déploiement.
_UPLOAD_DIR: Final[Path] = config.data_dir / "uploads"

#: Codes de fermeture WebSocket (RFC 6455 section 7.4.2, range applicatif
#: 4000-4999). On centralise pour que les clients puissent reconnaître un
#: code précis sans introspection de la raison textuelle.
_WS_CLOSE_AUTH_REQUIRED: Final[int] = 4001
_WS_CLOSE_XSRF_FAILED: Final[int] = 4003


# ---------------------------------------------------------------------------
# Messages utilisateur centralisés
# ---------------------------------------------------------------------------


class _Messages:
    """Libellés FR exposés aux clients Iris.

    Garder ces constantes en un seul endroit évite la dérive entre handlers
    et facilite un futur audit de messages ou une i18n.
    """

    INVALID_JSON: Final[str] = "Message JSON invalide."
    UNKNOWN_ACTION: Final[str] = "Action inconnue."
    AGENT_RUNNING: Final[str] = (
        "L'agent est déjà en cours d'exécution. Attendez la fin ou arrêtez-le d'abord."
    )
    MESSAGE_EMPTY: Final[str] = "Le message ne peut pas être vide."
    SESSION_EXPIRED: Final[str] = (
        "Votre session a expiré ou votre compte a été désactivé. " "Veuillez vous reconnecter."
    )
    CLARIFICATION_EMPTY: Final[str] = "La réponse de clarification ne peut pas être vide."
    CONVERSATION_ID_REQUIRED: Final[str] = (
        "conversation_id requis pour une réponse de clarification."
    )
    CONVERSATION_ID_INVALID: Final[str] = "conversation_id invalide."
    CONVERSATION_NOT_FOUND: Final[str] = "Conversation introuvable."
    NO_ASSISTANT_MESSAGE: Final[str] = "Aucun message assistant trouvé."
    RATE_LIMITED: Final[str] = (
        f"Trop de messages envoyés (limite : {_RATE_LIMIT_MESSAGES} "
        f"par {_RATE_LIMIT_WINDOW} secondes). Patientez quelques secondes "
        f"puis réessayez."
    )
    INTERNAL_ERROR: Final[str] = "Une erreur interne est survenue. Réessayez."
    CLEAR_FAILED: Final[str] = "Erreur lors de l'effacement."
    FEEDBACK_FAILED: Final[str] = "Erreur lors de l'enregistrement."
    FEEDBACK_INVALID: Final[str] = "conversation_id et feedback (positive/adjust/negative) requis."
    FEEDBACK_JSON_INVALID: Final[str] = "JSON invalide."
    NO_FILE: Final[str] = "Aucun fichier envoyé."
    PATH_INVALID: Final[str] = "Chemin de fichier invalide."
    DISK_FULL: Final[str] = "Espace disque insuffisant pour sauvegarder le fichier."
    DISK_DENIED: Final[str] = (
        "Permission refusée pour écrire le fichier. Contactez l'administrateur."
    )
    DISK_ERROR: Final[str] = "Impossible de sauvegarder le fichier."
    LLM_SETUP_ADMIN: Final[str] = (
        "Aucun fournisseur IA n'est configuré. "
        "Rendez-vous dans <a href='/admin/ai-config'>Intelligence Artificielle &gt; "
        "Configuration IA</a> pour ajouter votre clé API."
    )
    LLM_SETUP_USER: Final[str] = (
        "Iris n'est pas encore configurée. Demandez à votre administrateur "
        "de configurer la clé API dans les paramètres de l'application."
    )
    LLM_SETUP_UNKNOWN: Final[str] = (
        "Impossible de vérifier la configuration IA. Contactez votre administrateur."
    )

    @staticmethod
    def extension_not_supported(ext: str) -> str:
        # Liste dérivée dynamiquement de la SSoT ``_ALLOWED_EXTENSIONS``.
        # Ajouter une extension à la frozenset propage automatiquement au
        # message utilisateur — pas de duplication hardcodée à maintenir.
        allowed = ", ".join(sorted(_ALLOWED_EXTENSIONS))
        return f"Extension '{ext}' non supportée. Utilisez {allowed}."

    @staticmethod
    def magic_bytes_mismatch(ext_key: str) -> str:
        return f"Le contenu du fichier ne correspond pas au format .{ext_key}"

    @staticmethod
    def text_decode_failed(ext_key: str) -> str:
        return f"Le fichier .{ext_key} contient des données binaires invalides."

    @staticmethod
    def file_too_large(max_bytes: int) -> str:
        # Message dérivé de la VRAIE limite effective (SSoT runtime), pas d'un
        # chiffre codé en dur — ne ment jamais même si l'admin change la valeur.
        return f"Fichier trop volumineux (max {max_bytes // (1024 * 1024)} Mo)."


# ---------------------------------------------------------------------------
# Agent error classification
# ---------------------------------------------------------------------------


_AgentErrorMatcher = tuple[tuple[type[Exception], ...], tuple[str, ...], str]


#: Règles de classification d'erreur agent → message utilisateur FR. Les règles
#: sont ordonnées : la première qui matche gagne. Une règle = (types d'exception
#: reconnus, mots-clés dans le message, texte utilisateur).
_AGENT_ERROR_RULES: Final[tuple[_AgentErrorMatcher, ...]] = (
    (
        (ConnectionError, TimeoutError, OSError),
        (
            "connection",
            "timeout",
            "refused",
            "unreachable",
            "network",
            "tcp/ip",
            "odbc",
            "pyodbc",
            "login failed",
        ),
        (
            "Impossible de se connecter au serveur de base de données. "
            "Vérifiez que vous êtes sur le bon réseau et que le serveur est accessible."
        ),
    ),
    (
        (),
        ("rate limit", "429", "too many requests"),
        "Le service IA est temporairement surchargé. Réessayez dans quelques secondes.",
    ),
    (
        (),
        ("401", "403", "unauthorized", "forbidden", "api key"),
        (
            "Erreur d'authentification avec le service IA. "
            "Vérifiez la clé API dans la configuration."
        ),
    ),
    (
        (),
        ("overloaded", "529", "503", "service unavailable"),
        "Le service IA est temporairement indisponible. Réessayez dans quelques instants.",
    ),
    (
        # HTTP 413 = payload too large (tier provider à TPM bas, ou contexte
        # qui dépasse la context window du modèle). Pas un transient : retry
        # mécanique re-échoue. Message actionnable plutôt que "réessayez".
        (),
        ("413", "payload too large", "request too large", "tokens per minute"),
        (
            "Le provider a refusé la requête (payload trop gros). "
            "Démarrez une nouvelle conversation, changez de modèle, "
            "ou demandez à un administrateur de passer sur un tier supérieur."
        ),
    ),
)


def _classify_agent_error(exc: Exception) -> str:
    """Convertit une exception agent en message utilisateur FR actionnable.

    L'ordre des règles reflète la probabilité par déploiement : problèmes
    réseau → rate-limit API → auth → service down → SQL (QueryError /
    SageConnectionError, depuis P1.1 contiennent ``[SQLSTATE] message ODBC``
    propagés tels quels) → erreur SQL générique heuristique → fallback avec
    type d'exception (utile pour diagnostic tickets).

    **P2.2 (audit 2026-05-26)** : pour les call-sites async, préférer
    :func:`_classify_agent_error_for_user` qui passe par
    ``sanitize_sql_for_client`` (catégorisation + sanitization PII mode
    invisible). Cette version sync reste utilisable mais expose le
    ``str(exc)`` brut pour les erreurs SQL (acceptable : depuis P1.1, ce
    raw contient le SQLSTATE actionnable, et la fonction est appelée
    uniquement par des call-sites qui ne peuvent pas await).
    """
    # P2.2 — QueryError/SageConnectionError : str(exc) contient déjà
    # ``[SQLSTATE] message ODBC`` depuis P1.1. Propager directement.
    try:
        from app.core.exceptions import QueryError, SageConnectionError

        if isinstance(exc, (QueryError, SageConnectionError)):
            raw = str(exc).strip()
            return raw if raw else f"Erreur SQL ({type(exc).__name__})."
    except ImportError:  # pragma: no cover — defensive si module renommé
        pass

    exc_msg = str(exc).lower()
    for types, keywords, message in _AGENT_ERROR_RULES:
        if types and isinstance(exc, types):
            return message
        if any(keyword in exc_msg for keyword in keywords):
            return message

    if "sql" in exc_msg and any(kw in exc_msg for kw in ("syntax", "invalid", "column")):
        return (
            "La requête SQL générée contient une erreur. "
            "Essayez de reformuler votre demande différemment."
        )

    return f"Une erreur inattendue est survenue ({type(exc).__name__}). Réessayez."


async def _classify_agent_error_for_user(exc: Exception, user: Any) -> str:
    """Variant async : utilise :func:`sanitize_sql_for_client` pour les
    erreurs SQL (catégorisation FR actionnable + sanitization PII mode
    invisible). Pour le reste, délègue à :func:`_classify_agent_error` sync.

    **P2.2 (audit 2026-05-26)** : preferred over la version sync pour les
    call-sites async (WS handler, async generators). Bénéficie :

    - Hint catégoriel FR adapté (referential / timeout / permission / etc.)
    - Sanitization "Invalid object name 'F_X'" → message générique mode-invisible
    - Détail court inclus pour les erreurs actionnables (referential/type/syntax)

    Args:
        exc: l'exception remontée par l'agent.
        user: l'utilisateur courant (pour décider de la sanitization PII).
    """
    try:
        from app.core.exceptions import QueryError, SageConnectionError

        if isinstance(exc, (QueryError, SageConnectionError)):
            from app.services.data_access.error_messages import sanitize_sql_for_client

            payload = await sanitize_sql_for_client(exc, user, audience="user")
            return payload["message"]
    except ImportError:  # pragma: no cover — defensive
        pass
    except Exception:  # noqa: BLE001 — fail-safe : ne jamais casser le path d'erreur
        logger.warning(
            "_classify_agent_error_for_user: sanitize_sql_for_client a crashé — " "fallback sync",
            exc_info=True,
        )
    return _classify_agent_error(exc)


# ---------------------------------------------------------------------------
# Model display name — re-export depuis le module central
# ---------------------------------------------------------------------------
# Le helper vit dans ``app.services.ai.model_display`` (neutre, sans dépendance
# Tornado). On le ré-exporte ici sous l'ancien nom ``_model_display_name`` pour
# rétrocompat (tests + appels existants). Toute nouvelle utilisation devrait
# importer ``model_display_name`` depuis le module service directement.

from app.services.ai.model_display import (  # noqa: E402,F401  -- ré-export pour rétrocompat tests
    model_display_name as _model_display_name,
)

# ---------------------------------------------------------------------------
# Prompt prefill
# ---------------------------------------------------------------------------


def _parse_prompt_prefill(raw: object) -> str:
    """Normalise le paramètre ``?prompt=`` passé en query-string.

    - Tout type non-``str`` → chaîne vide (robuste aux types inattendus).
    - Trim whitespace.
    - Cap à :data:`_MAX_PROMPT_PREFILL_CHARS`.
    """
    if not isinstance(raw, str):
        return ""
    return raw.strip()[:_MAX_PROMPT_PREFILL_CHARS]


# ---------------------------------------------------------------------------
# Tool description registry
# ---------------------------------------------------------------------------


def _truncate(text: str, max_len: int = _MAX_TOOL_DESCRIPTION_CHARS) -> str:
    """Tronque proprement une description avec marqueur ``…``."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def _describe_keywords(tool_input: Mapping[str, Any], key: str = "keywords") -> str:
    keywords = tool_input.get(key) or []
    if isinstance(keywords, list):
        return ", ".join(str(k) for k in keywords[:5])
    return ""


def _describe_fk_path(tool_input: Mapping[str, Any]) -> str:
    frm = tool_input.get("from_table", "")
    to = tool_input.get("to_table", "")
    return f"{frm} → {to}" if frm and to else ""


def _describe_join_compat(tool_input: Mapping[str, Any]) -> str:
    ta = tool_input.get("table_a", "")
    ca = tool_input.get("column_a", "")
    tb = tool_input.get("table_b", "")
    cb = tool_input.get("column_b", "")
    if ta and tb:
        return f"{ta}.{ca} ↔ {tb}.{cb}"
    return ""


def _describe_resolved_value(tool_input: Mapping[str, Any]) -> str:
    term = tool_input.get("term", "")
    tbl = tool_input.get("table_name", "")
    col = tool_input.get("column_name", "")
    if term or tbl or col:
        return f"'{term}' dans {tbl}.{col}"
    return ""


def _describe_batch_tables(tool_input: Mapping[str, Any]) -> str:
    tables = tool_input.get("table_names", [])
    if not isinstance(tables, list) or not tables:
        return ""
    head = ", ".join(str(t) for t in tables[:5])
    extra = len(tables) - 5
    return head + (f" (+{extra})" if extra > 0 else "")


def _describe_variant_compare(tool_input: Mapping[str, Any]) -> str:
    variants = tool_input.get("variants", [])
    if not isinstance(variants, list) or not variants:
        return ""
    labels = [str(v.get("label", "?")) for v in variants if isinstance(v, dict)]
    return " vs ".join(labels[:3])


def _describe_question(tool_input: Mapping[str, Any], key: str = "user_question") -> str:
    q = tool_input.get(key, "")
    if not isinstance(q, str) or not q.strip():
        return ""
    return _truncate(q, 80)


def _describe_subject(tool_input: Mapping[str, Any]) -> str:
    return str(tool_input.get("subject", ""))


def _describe_action_name(tool_input: Mapping[str, Any]) -> str:
    action = tool_input.get("action", "")
    name = tool_input.get("name", "")
    return f"{action} — {name}" if name else str(action)


_ToolDescriber = Callable[[Mapping[str, Any]], str]

#: Registry tool_name → builder de description. Centralise la logique
#: dupliquée historiquement entre ``iris.py`` (rehydratation) et
#: ``agent_service._get_tool_display`` (streaming).
_TOOL_DESCRIPTION_BUILDERS: Final[Mapping[str, _ToolDescriber]] = {
    "execute_sql": lambda ti: _truncate(str(ti.get("sql", ""))),
    "test_sql": lambda ti: _truncate(str(ti.get("sql", ""))),
    "diagnose_zero_rows": lambda ti: _truncate(str(ti.get("sql", ""))),
    "introspect_table": lambda ti: str(ti.get("table_name", "")),
    "peek_table_data": lambda ti: str(ti.get("table_name", "")),
    "get_database_schema": _describe_keywords,
    "search_schema": _describe_keywords,
    "search_documentation": lambda ti: str(ti.get("query", "")),
    "send_email": _describe_subject,
    "manage_automations": _describe_action_name,
    "get_fk_path": _describe_fk_path,
    "explore_join_alternatives": _describe_fk_path,
    "check_join_compatibility": _describe_join_compat,
    "get_resolved_values": _describe_resolved_value,
    "introspect_tables_batch": _describe_batch_tables,
    "compare_query_variants": _describe_variant_compare,
    "match_analytical_pattern": _describe_question,
    "align_request": lambda _ti: "Alignement requête ↔ BDD",
}


def build_tool_description(tool_name: str, tool_input: Mapping[str, Any] | None) -> str:
    """Construit la description affichable d'un appel d'outil.

    Utilisée aussi bien par la rehydratation (iris.py) que par le streaming
    (agent_service) — une seule source de vérité, pas de drift possible.

    Un ``tool_input`` absent ou vide est toléré : certains outils produisent
    une description statique (``align_request``) et ne doivent pas dépendre
    d'un champ de payload.
    """
    if tool_input is not None and not isinstance(tool_input, Mapping):
        return ""
    builder = _TOOL_DESCRIPTION_BUILDERS.get(tool_name)
    if builder is None:
        return ""
    try:
        return builder(tool_input or {})
    except (TypeError, ValueError, KeyError):
        logger.debug("Tool description builder failed for %s", tool_name)
        return ""


def _build_clarification_payload(tool_input: Mapping[str, Any]) -> dict[str, Any] | None:
    """Extrait {question, options} pour le tool ``ask_user_clarification``."""
    question = tool_input.get("question", "")
    options = tool_input.get("options", [])
    if not question:
        return None
    return {"question": question, "options": options if isinstance(options, list) else []}


# ---------------------------------------------------------------------------
# Conversation message rehydration
# ---------------------------------------------------------------------------


#: Tags [SUGGESTIONS]/[THINKING] orphelins (streaming interrompu) à nettoyer.
_ORPHAN_TAG_PATTERN: Final[re.Pattern[str]] = re.compile(r"\[(?:SUGGESTIONS|THINKING)\][\s\S]*$")


def _safe_json_loads(raw: str | None) -> Any:
    """JSON loads tolérant : renvoie ``None`` plutôt que lever."""
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _extract_text_blocks(content: str) -> str:
    """Extrait les parties texte d'un tableau JSON de content-blocks Anthropic.

    Un message assistant peut être stocké en JSON quand il contient des
    ``tool_use`` blocks. Le front n'a besoin que des parties ``type == "text"``.
    """
    stripped = content.rstrip()
    if not (content.startswith("[") and stripped.endswith("]")):
        return content
    blocks = _safe_json_loads(content)
    if not isinstance(blocks, list):
        return content
    texts = [b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"]
    return "\n".join(t for t in texts if t.strip())


async def _scrub(text: Any, user: Any) -> Any:
    """**P0 (#124)** — Wrapper safe pour ``scrub_text_for_user``.

    Court-circuite si ``text`` n'est pas un string (préserve dict/list/None).
    Fail-safe : si le scrub crash (BDD down etc.), retourne le texte
    original — mieux qu'un rendu cassé. Le scrub lui-même fait déjà
    no-op pour user=None / admin / sans restrictions.
    """
    if not isinstance(text, str) or not text:
        return text
    if user is None:
        return text
    try:
        from app.services.data_access.error_messages import scrub_text_for_user

        return await scrub_text_for_user(text, user, context_label="iris_rehydration")
    except Exception:  # noqa: BLE001 — best-effort, on n'écrase pas le rendu
        logger.warning(
            "iris rehydration: scrub_text_for_user a crashé (best-effort skip)",
            exc_info=True,
        )
        return text


async def _scrub_tool_input_for_user(tool_input: Mapping[str, Any], user: Any) -> dict[str, Any]:
    """**P0 (#124)** — Scrub les champs texte d'un ``tool_input`` dict.

    Cible les champs typiques : ``sql``, ``query``, ``table_name``,
    ``description``, ``title``, ``content`` — tout ce qui peut contenir
    un nom denied. Ignore les nombres/booléens/listes structurées.
    """
    scrubbed: dict[str, Any] = {}
    for k, v in tool_input.items():
        if isinstance(v, str):
            scrubbed[k] = await _scrub(v, user)
        else:
            scrubbed[k] = v
    return scrubbed


async def _render_tool_message(msg: ConversationMessage, user: Any) -> dict[str, Any]:
    """Sérialise un message ``TOOL`` pour le template (icon/label/description).

    **P0 (#124)** — Scrubbe les champs texte avant rendu (anti-fuite
    rehydratation page Iris pour les conversations antérieures à la pose
    d'une règle deny).
    """
    tool_name = msg.tool_name or "outil"
    label_info = TOOL_LABELS.get(tool_name, {"icon": "🔧", "label": tool_name})
    payload: dict[str, Any] = {
        "role": "tool",
        "tool_name": tool_name,
        "icon": label_info["icon"],
        "label": label_info["label"],
    }

    tool_input = _safe_json_loads(msg.tool_input)
    if isinstance(tool_input, Mapping):
        # **P0 (#124)** — Scrubbe les champs texte du tool_input AVANT
        # de les passer aux builders (description, clarification).
        scrubbed_input = await _scrub_tool_input_for_user(tool_input, user)
        if tool_name == "ask_user_clarification":
            clarification = _build_clarification_payload(scrubbed_input)
            if clarification is not None:
                payload["clarification"] = clarification
        description = build_tool_description(tool_name, scrubbed_input)
        if description:
            # Defense-in-depth : re-scrub la description (build peut
            # produire un texte qui mélange plusieurs champs).
            payload["description"] = await _scrub(description, user)

    # Statut succès/échec du tool — propagé au rehydrate pour que les
    # clients (page + widget) puissent rendre un état visuel différent
    # (chip ``done`` vs ``error``). Sans ce champ, le widget marquait
    # tous les tools comme « ✓ done » même pour les échecs SQL —
    # exactement le type de « donnée fausse silencieuse » interdit par
    # la règle ``rules/consequences.md`` (MOYEN-3 adversarial 2026-05-26).
    # Default ``True`` pour les conversations legacy d'avant la pose
    # du flag — le pire scénario reste une fausse confirmation sur
    # un outil très ancien (rare ; pas pire qu'avant).
    parsed_tool_result = _safe_json_loads(msg.tool_result)
    if isinstance(parsed_tool_result, Mapping):
        success_value = parsed_tool_result.get("success")
        # ``None``/manquant → on assume succès (rétrocompat legacy).
        # Booléen explicite → on respecte (False = echec affiché en error).
        if isinstance(success_value, bool):
            payload["success"] = success_value
        else:
            payload["success"] = True
    else:
        payload["success"] = True

    if tool_name == "execute_sql":
        tool_result = parsed_tool_result
        if isinstance(tool_result, Mapping):
            restore = tool_result.get("_restore_data")
            if (
                isinstance(restore, Mapping)
                and isinstance(restore.get("columns"), list)
                and restore["columns"]
            ):
                # **P0 (#124)** — Scrubbe les noms de colonnes ET le SQL
                # stocké pour _restore_data. Les rows (valeurs) ne sont
                # PAS scrubbées car ce sont des cellules de données, pas
                # des noms de tables/colonnes (philosophie scrub).
                scrubbed_restore = dict(restore)
                if isinstance(restore.get("sql"), str):
                    scrubbed_restore["sql"] = await _scrub(restore["sql"], user)
                scrubbed_restore["columns"] = [
                    await _scrub(c, user) if isinstance(c, str) else c for c in restore["columns"]
                ]
                payload["sql_data"] = scrubbed_restore

    return payload


async def _render_user_or_assistant(msg: ConversationMessage, user: Any) -> dict[str, Any] | None:
    """Sérialise un message USER/ASSISTANT, ``None`` si rien à rendre.

    **P0 (#124)** — Scrubbe le content texte avant rendu.
    """
    content = msg.content or ""
    if msg.role == MessageRole.ASSISTANT:
        content = _extract_text_blocks(content)
    content = _ORPHAN_TAG_PATTERN.sub("", content).strip()
    if not content:
        return None
    # Scrub APRÈS extraction des blocs texte mais AVANT injection
    # dans le payload Tornado — c'est le dernier rempart avant le navigateur.
    content = await _scrub(content, user)

    rendered: dict[str, Any] = {"role": msg.role.value, "content": content}
    if msg.role == MessageRole.ASSISTANT:
        if msg.feedback:
            rendered["feedback"] = msg.feedback
        if msg.turn_events:
            events = _safe_json_loads(msg.turn_events)
            if events is not None:
                rendered["turn_events"] = events
    return rendered


async def _render_conversation_messages(
    messages: list[ConversationMessage],
    user: Any,
) -> list[dict[str, Any]]:
    """Pipeline complet de rehydratation — utilisé par :class:`IrisPageHandler`.

    **P0 (#124)** — ``user`` propagé à chaque renderer pour scrubber
    les noms denied à la rehydratation page (anti-fuite historique).
    """
    rendered: list[dict[str, Any]] = []
    for msg in messages:
        if msg.role == MessageRole.TOOL:
            rendered.append(await _render_tool_message(msg, user))
            continue
        if msg.role not in (MessageRole.USER, MessageRole.ASSISTANT):
            continue
        payload = await _render_user_or_assistant(msg, user)
        if payload is not None:
            rendered.append(payload)
    return rendered


#: Timeout (secondes) sur les SELECT du helper. Sans ce cap, une
#: contention SQLite (improve-pseudo, audit_logs, AIPerformanceLog —
#: cf. mémoire ``project_db_locked_followup_2026_05_22.md``) ferait
#: attendre l'endpoint le ``busy_timeout`` complet (~30s) — multiplié
#: par N onglets ouverts. 5s : assez pour absorber une rotation WAL,
#: assez court pour ne pas bloquer la navigation.
_LOAD_CONVERSATION_TIMEOUT_S: Final[float] = 5.0
# A5-F6 : borne la réhydratation conversation (affichage page/widget) aux N
# messages les plus récents. Un user avec des milliers de messages chargeait
# TOUT au refresh (latence + mémoire non bornées). Le contexte AGENT est chargé
# séparément (couche D1) → borner l'AFFICHAGE n'ampute pas la mémoire agent.
_CONVERSATION_REPLAY_LIMIT: Final[int] = 200


async def _load_active_conversation(user: User, source: str) -> tuple[
    Optional[int],
    Optional[int],
    list[ConversationMessage],
    list[dict[str, Any]],
]:
    """SSOT de lecture d'une conversation active — réutilisé par la page
    et par le widget (rehydratation overlay).

    Retourne ``(conversation_id, last_input_tokens, raw_messages,
    rendered_messages)`` :

    * ``conversation_id`` : id de la conv (``None`` si aucune active).
    * ``last_input_tokens`` : dernière valeur LLM-effective persistée
      (utilisée par la page pour l'indicateur context-window au boot ;
      le widget l'ignore). ``None`` si NULL ou conv legacy.
    * ``raw_messages`` : objets ORM bruts (la page les utilise pour
      ``_estimate_history_tokens`` qui lit les champs ``tool_input``/
      ``tool_result``/``turn_events`` avant le rendu UI qui drop ces
      payloads).
    * ``rendered_messages`` : format UI (scrubbé + tool icons +
      sql_data) — directement injectable côté template Tornado ou
      réponse JSON API.

    Tous les retours sont **détachés de session** (id + scalaires
    extraits AVANT la sortie du ``async with``) — pas de lazy-load
    hors session (cf. CLAUDE.md règle 6 "ORM async safe").

    * Filtre ``agent_role`` : aligné sur le SSOT de création
      (``conversation_lifecycle.get_or_create_active_conversation``).
    * Filtre ``source`` (page vs widget) : empêche le widget de servir
      la conv page et inversement (cf. bug 2026-05-21 / enum
      :class:`ConversationSource`).
    * **Timeout** : ``_LOAD_CONVERSATION_TIMEOUT_S`` cap chaque SELECT —
      sinon SQLite locked = stall navigation (CRITIQUE-2 adversarial
      2026-05-26).
    * Fail-safe : ``(None, None, [], [])`` si erreur SQL ou timeout.
    """
    try:
        async with get_session() as session:
            conv_result = await asyncio.wait_for(
                session.execute(
                    select(Conversation)
                    .where(
                        Conversation.user_id == user.id,
                        Conversation.is_active.is_(True),
                        Conversation.agent_role == AgentRole.IRIS.value,
                        Conversation.source == source,
                    )
                    .order_by(Conversation.updated_at.desc())
                    .limit(1)
                ),
                timeout=_LOAD_CONVERSATION_TIMEOUT_S,
            )
            conversation = conv_result.scalar_one_or_none()
            if conversation is None:
                return None, None, [], []

            # Capture des scalaires AVANT la sortie de session (évite
            # tout lazy-load implicite quand un caller relit l'objet).
            conv_id = conversation.id
            last_input_tokens = conversation.last_input_tokens

            msgs_result = await asyncio.wait_for(
                session.execute(
                    select(ConversationMessage)
                    .where(ConversationMessage.conversation_id == conv_id)
                    # A5-F6 : les N PLUS RÉCENTS (DESC + LIMIT) au lieu de TOUT.
                    .order_by(ConversationMessage.id.desc())
                    .limit(_CONVERSATION_REPLAY_LIMIT)
                ),
                timeout=_LOAD_CONVERSATION_TIMEOUT_S,
            )
            # Récupérés DESC (N plus récents) → on rétablit l'ordre chronologique
            # (ASC) attendu par le replay d'affichage.
            messages = list(reversed(msgs_result.scalars().all()))
            rendered = await _render_conversation_messages(messages, user)
            return conv_id, last_input_tokens, messages, rendered
    except asyncio.TimeoutError:
        logger.warning(
            "Timeout (>%ss) sur _load_active_conversation source=%s "
            "user=%s — SQLite probablement lockée. Renvoi conv vide.",
            _LOAD_CONVERSATION_TIMEOUT_S,
            source,
            getattr(user, "id", "?"),
        )
        return None, None, [], []
    except SQLAlchemyError as exc:
        logger.error("Erreur chargement conversation (source=%s): %s", source, exc, exc_info=True)
        return None, None, [], []


def _estimate_history_tokens(messages: list[ConversationMessage]) -> int:
    """Estimation grossière de la taille en tokens d'une conversation rechargée.

    Lit les champs **bruts** du modèle (``content``, ``tool_input``,
    ``tool_result``, ``turn_events``) — sans dépendre de la sortie de
    :func:`_render_conversation_messages` qui drop certains payloads pour le
    rendu UI. Le but est de rendre l'indicateur initial plausible **avant**
    le premier ``done`` event (qui corrigera avec la valeur exacte). Heuristique
    via :func:`estimate_tokens` (~4 chars/token).
    """
    total = 0
    for msg in messages:
        if msg.content:
            total += estimate_tokens(msg.content)
        if getattr(msg, "tool_input", None):
            total += estimate_tokens(msg.tool_input)
        if getattr(msg, "tool_result", None):
            total += estimate_tokens(msg.tool_result)
        if getattr(msg, "turn_events", None):
            # ``turn_events`` peut peser plusieurs k tokens (thinking blocks,
            # exploration timeline, tool segments). Sans ça l'estimation
            # sous-évalue de ~10× pour les conversations exploratoires.
            total += estimate_tokens(msg.turn_events)
    return total


# ---------------------------------------------------------------------------
# Upload validation
# ---------------------------------------------------------------------------


class _UploadValidator:
    """Validations défense-en-profondeur pour les uploads Iris.

    Chaque méthode retourne ``None`` si OK, sinon un message FR prêt à être
    renvoyé au client. Séparer validations et renvoi HTTP permet de tester
    chaque règle isolément sans mocker un handler.
    """

    def __init__(
        self,
        *,
        allowed_extensions: frozenset[str] = _ALLOWED_EXTENSIONS,
        max_size: int = _MAX_UPLOAD_SIZE,
        magic_bytes: Mapping[str, bytes] = _MAGIC_BYTES,
    ) -> None:
        self._allowed_extensions = allowed_extensions
        self._max_size = max_size
        self._magic_bytes = magic_bytes

    def validate(
        self, filename: str, body: bytes, max_size: int | None = None
    ) -> tuple[str, str] | None:
        """Valide extension + taille + contenu.

        Args:
            max_size: limite de taille effective (octets). Si ``None``, retombe
                sur ``self._max_size`` (fallback). Le handler passe la SSoT
                résolue via ``get_max_upload_size_bytes()``.

        Retour :
            ``None`` si OK, sinon ``(error_message, ext_key)`` où ``ext_key``
            sert au handler pour construire le file_type final.
        """
        ext_error, ext_key = self._validate_extension(filename)
        if ext_error is not None:
            return ext_error, ""
        size_error = self._validate_size(body, max_size)
        if size_error is not None:
            return size_error, ext_key
        content_error = self._validate_content(body, ext_key)
        if content_error is not None:
            return content_error, ext_key
        return None

    def _validate_extension(self, filename: str) -> tuple[str | None, str]:
        _, ext = os.path.splitext(filename.lower())
        if ext not in self._allowed_extensions:
            return _Messages.extension_not_supported(ext), ""
        return None, ext[1:]

    def _validate_size(self, body: bytes, max_size: int | None = None) -> str | None:
        effective = max_size if max_size is not None else self._max_size
        if len(body) > effective:
            return _Messages.file_too_large(effective)
        return None

    def _validate_content(self, body: bytes, ext_key: str) -> str | None:
        expected = self._magic_bytes.get(ext_key)
        if expected is not None:
            if not body.startswith(expected):
                return _Messages.magic_bytes_mismatch(ext_key)
            return None
        # Fichiers textuels : doivent être décodables en UTF-8 sur le prologue
        if ext_key in {"csv", "json", "txt"}:
            try:
                body[:_TEXT_SNIFF_BYTES].decode("utf-8")
            except UnicodeDecodeError:
                return _Messages.text_decode_failed(ext_key)
        return None


#: Singleton module-level — la classe est stateless, mais la garder instancée
#: permet de surcharger la config via un simple assignment en test.
_upload_validator: Final[_UploadValidator] = _UploadValidator()


def _safe_log_filename(filename: str) -> str:
    """Sanitise un nom de fichier avant log (anti CWE-117).

    Tronque à 256 chars et supprime les contrôles / CR / LF.
    """
    clean = _LOG_UNSAFE_CHARS.sub("?", filename)
    return clean[:256]


# ---------------------------------------------------------------------------
# WebSocket rate limiter
# ---------------------------------------------------------------------------


#: Rate-limiter WebSocket partagé entre toutes les connexions.
#: Remplace l'ancien ``_user_message_times`` / ``_rate_limit_check_counter``.
_ws_rate_limiter: Final[RateLimiter] = RateLimiter()

#: Rate-limiter dédié à la persistance pref iris-consent via WS — bloque
#: un script qui spam ``data_read_consent_response`` avec ``dont_ask_again=true``
#: pour saturer les writes BDD (DoS write-amp). 5/min est cohérent avec
#: ``_PASSWORD_RATE_MAX`` et le fait qu'un humain change ce setting
#: moins d'une fois par session.
_iris_consent_ws_rate_limiter: Final[RateLimiter] = RateLimiter()
_IRIS_CONSENT_WS_RATE_MAX: Final[int] = 5
_IRIS_CONSENT_WS_RATE_WINDOW_S: Final[int] = 60


def _reset_ws_rate_limiter() -> None:
    """Helper exclusivement utilisé par les tests pour réinitialiser le state."""
    _ws_rate_limiter._requests.clear()  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


class IrisPageHandler(BaseHandler):
    """Page principale de l'agent Iris (conversation unique par utilisateur).

    La méthode :meth:`get` est volontairement courte : elle orchestre des
    helpers privés pour (1) rehydrater la conversation, (2) détecter l'état
    du provider LLM, (3) générer les suggestions d'accueil, (4) normaliser le
    deep-link ``?prompt=``. Aucune logique métier n'est inline.
    """

    @authenticated
    async def get(self) -> None:
        user = self.current_user
        assert user is not None  # @authenticated garantit que user n'est pas None

        # Anti-bfcache : sans ces headers, le retour-arrière du navigateur
        # restaure le DOM figé d'une session précédente (potentiellement
        # une *autre* conversation, par ex. un ancien rôle ``sql_expert``).
        # Cf. incident 2026-05-10 : David a vu un run "expert comptable"
        # alors que la conv active en BDD était la rentabilité par dossier.
        # ``no-store`` bloque aussi le disk cache HTTP. ``Vary: Cookie``
        # est défense-en-profondeur pour les CDN/proxies intermédiaires.
        self.set_header("Cache-Control", "no-store, no-cache, must-revalidate, private")
        self.set_header("Pragma", "no-cache")
        self.set_header("Vary", "Cookie")

        conversation_id, conversation_messages, history_token_estimate = (
            await self._rehydrate_conversation(user)
        )
        # Charger les events bruts pour le replay DOM-IDENTIQUE au refresh.
        # (Solution B APEX 2026-05-09). Si vide → conversation legacy ou
        # nouvelle → frontend tombera automatiquement sur le path restore
        # legacy basé sur ``conversation_messages``.
        conversation_events: list[dict[str, Any]] = []
        if conversation_id is not None:
            from app.services.ai.conversation_event_persister import (
                get_events_for_conversation,
            )

            try:
                conversation_events = await get_events_for_conversation(conversation_id)
            except SQLAlchemyError as exc:
                logger.warning(
                    "Erreur chargement conversation_events (conv=%s): %s",
                    conversation_id,
                    exc,
                )
                conversation_events = []
        # Snapshot du modèle actif (id + context_window + libellé) — single
        # source of truth = ``/admin/ai-config`` via le helper centralisé.
        snapshot = await resolve_active_window_snapshot()
        # Si la fenêtre est connue, on cap l'estimation initiale à cette
        # capacité (sinon une rehydratation aberrante ferait apparaître un
        # bar saturé sans raison utile au user).
        cw = snapshot.get("context_window")
        if cw and history_token_estimate > cw:
            history_token_estimate = cw
        model_display = snapshot.get("model_display") or "IA"
        llm_ready, llm_setup_hint = await self._check_llm_ready(user)
        welcome_suggestions = await self._fetch_welcome_suggestions(user)
        prompt_prefill = _parse_prompt_prefill(self.get_argument("prompt", ""))

        # SSOT-4 — tooltips du toggle de mode dérivés de la même source que
        # le runtime (``EXPLANATION_MODE_ALLOWED_CLASSES``). Le tooltip ne
        # peut plus mentir si l'allowlist change.
        from app.services.ai.agent_tools import derive_iris_mode_tooltips

        mode_tooltips = derive_iris_mode_tooltips()

        # SSoT — Task #11 : la configuration upload (extensions + taille
        # max) est dérivée du backend et exposée au template / JS via un
        # bridge unique. Les extensions viennent de ``_ALLOWED_EXTENSIONS`` ;
        # la taille max est la SSoT admin (``/admin/performance``) résolue via
        # ``get_max_upload_size_bytes()``. Modifier ces sources propage
        # automatiquement à l'attribut ``accept`` HTML et au filtrage JS.
        from app.services.ai.config_service import get_max_upload_size_bytes

        upload_config = _upload_config_for_template(await get_max_upload_size_bytes())

        self.render(
            "iris.html",
            user=user,
            conversation_id=conversation_id,
            conversation_messages=_json_for_template(conversation_messages),
            conversation_events=_json_for_template(conversation_events),
            model_display=model_display,
            model_name=snapshot.get("model_name"),
            context_window=cw,
            initial_context_tokens=history_token_estimate,
            welcome_suggestions=_json_for_template(welcome_suggestions),
            llm_ready=llm_ready,
            llm_setup_hint=llm_setup_hint,
            prompt_prefill=prompt_prefill,
            mode_execution_tooltip=mode_tooltips["execution"],
            mode_explanation_tooltip=mode_tooltips["explanation"],
            upload_config=upload_config,
            upload_accept_attribute=upload_config["accept_attribute"],
            auto_feedback_options=AUTO_FEEDBACK_OPTIONS,
        )

    async def _rehydrate_conversation(
        self, user: User
    ) -> tuple[Optional[int], list[dict[str, Any]], int]:
        """Charge la conversation active page + estimation tokens.

        Retourne ``(conversation_id, rendered_messages, estimated_history_tokens)``.
        Le SELECT + render est délégué à :func:`_load_active_conversation`
        (SSOT partagé avec le widget). Cette méthode ajoute uniquement
        l'estimation tokens spécifique à la page (utilisée par l'indicateur
        context-window).

        * Filtre ``source == "page"`` : la page ``/iris`` ne doit
          JAMAIS rehydrater une conv créée depuis le floating widget
          (cf. bug 2026-05-21 — sans ce filtre les messages
          du widget apparaissaient dans le chat page). Le widget a sa
          propre route ``GET /api/iris/widget/conversation``.
        * **P0 (#124)** : scrub historique appliqué via
          ``_load_active_conversation`` → ``_render_conversation_messages``.
        * L'estimation lit les champs RAW (``content``, ``tool_input``,
          ``tool_result``, ``turn_events``) AVANT le rendu UI — sinon
          les ``tool_result`` sont droppés par le renderer et
          l'estimation sous-compte massivement les conversations
          exploratoires.

        Sur erreur SQL : ``_load_active_conversation`` renvoie déjà
        ``(None, None, [], [])`` (caller-friendly), estimation 0.
        """
        conv_id, persisted_last_input, raw_messages, rendered = await _load_active_conversation(
            user, ConversationSource.PAGE.value
        )
        if conv_id is None:
            return None, [], 0

        # Source de vérité pour l'indicateur context-window au
        # reload : la dernière valeur réelle persistée par l'agent
        # (incluant system prompt + tools + RAG + cache, mesurée
        # par l'API LLM). Si NULL (conversation legacy d'avant la
        # migration ou run qui n'a jamais émis de done LLM-effectif),
        # on retombe sur l'estimation heuristique qui couvre au moins
        # le poids des messages stockés.
        #
        # ⚠️ Le check ``> 0`` est une **defense en profondeur** —
        # le persister (cf. ``agent_service.py``) refuse déjà
        # d'écrire 0. Le check ici protège contre : (a) un edit
        # SQL manuel `UPDATE conversations SET last_input_tokens=0`
        # (test/debug), (b) un futur writer qui poserait 0 par
        # erreur, (c) une row corrompue par restore d'un dump.
        # Dans ces cas pathologiques, on retombe sur l'estimation
        # plutôt que d'afficher "0 tokens" trompeur à l'écran.
        if persisted_last_input is not None and persisted_last_input > 0:
            estimate = persisted_last_input
        else:
            estimate = _estimate_history_tokens(raw_messages)
        return conv_id, rendered, estimate

    async def _check_llm_ready(self, user: User) -> tuple[bool, str]:
        """État du provider LLM + hint de setup selon le rôle utilisateur."""
        try:
            await ensure_providers_from_db()
            manager = get_llm_manager()
        except (RuntimeError, SQLAlchemyError) as exc:
            logger.warning("Provider check failed: %s", exc)
            return False, _Messages.LLM_SETUP_UNKNOWN
        if manager.available_providers:
            return True, ""
        hint = _Messages.LLM_SETUP_ADMIN if user.is_admin else _Messages.LLM_SETUP_USER
        return False, hint

    async def _fetch_welcome_suggestions(self, user: User) -> list[Any]:
        """Suggestions d'accueil contextualisées (fail-safe liste vide)."""
        try:
            sync_svc = get_sync_service()
            return await sync_svc.generate_welcome_suggestions(user_id=user.id)
        except (RuntimeError, SQLAlchemyError) as exc:
            logger.debug("Suggestions d'accueil non disponibles: %s", exc)
            return []


def _json_safe_default(obj: Any) -> Any:
    """Default-encoder JSON qui ne PRODUIT PAS le repr Python des ``bytes``.

    Bug observé David 2026-05-19 : ``json.dumps(value, default=str)``
    appelait ``str(b'\\xc1\\xe3\\xaf...')`` pour les colonnes
    ``varbinary``/``rowversion`` retournées par pyodbc, produisant la
    string littérale ``"b'\\\\xc1\\\\xe3\\\\xaf...'"`` (avec backslash
    LITTÉRAL). Cette string traversait le WebSocket vers le frontend,
    était scannée par ``_anonExtractTerms``, et finissait en BDD via
    PUT panneau comme terme ``source="manual"``. 686 termes parasites
    observés dans la BDD prod.

    Encoder qui couvre les cas non-JSON-natifs SANS produire de repr :
    - ``bytes``/``bytearray``/``memoryview`` → ``None`` (vide JSON,
      l'utilisateur voit "—" dans la grille pour ces colonnes
      techniques — plus utile qu'une suite de chars cryptiques)
    - ``uuid.UUID`` → ``str(uuid)`` (format GUID 36 chars, déjà filtré
      par le tokenizer côté JS via ``GUID_FULL_RE``)
    - ``datetime.datetime``/``date`` → ``isoformat()``
    - ``decimal.Decimal`` → ``str()`` (préserve la précision)
    - Autre → ``str()`` fallback (comportement précédent pour les
      types métier inattendus, mais log debug).
    """
    import datetime as _dt
    import decimal as _dec
    import uuid as _uuid

    if isinstance(obj, (bytes, bytearray, memoryview)):
        return None
    if isinstance(obj, _uuid.UUID):
        return str(obj)
    if isinstance(obj, (_dt.datetime, _dt.date)):
        return obj.isoformat()
    if isinstance(obj, _dec.Decimal):
        return str(obj)
    return str(obj)


def _json_for_template(value: Any) -> str:
    """Sérialise un objet en JSON sûr pour injection dans ``<script>``.

    Le ``replace("</", "<\\/")`` neutralise la sortie d'un tag ``</script>``
    injecté via le contenu — cf. OWASP A03 (XSS). Jinja2 auto-escape ne suffit
    pas dans un contexte JS.

    Utilise ``_json_safe_default`` qui filtre les ``bytes`` (cf. docstring)
    pour empêcher la fuite de leur repr Python dans le frontend.
    """
    return json.dumps(value, default=_json_safe_default, ensure_ascii=False).replace("</", "<\\/")


# ---------------------------------------------------------------------------
# WebSocket handler
# ---------------------------------------------------------------------------


class IrisWebSocketHandler(tornado.websocket.WebSocketHandler):
    """WebSocket temps-réel pour le streaming des événements ``agent.run()``.

    Protocole entrant (JSON) :
        - ``{"action": "send_message", "message": "...", "conversation_id": ?}``
        - ``{"action": "clarification_response", "conversation_id": int, "response": "..."}``
        - ``{"action": "cancel"}`` (jamais rate-limité — mécanisme de sécurité)

    Protocole sortant — événements produits par :func:`IrisAgent.run`.
    """

    #: Attributs initialisés dans :meth:`open`. Déclarés ici pour que les
    #: tests unitaires puissent les introspecter même sur un ``MagicMock(spec=...)``.
    current_user: Optional[User]
    _last_mode: str
    _cancel_event: asyncio.Event
    _agent_task: Optional[asyncio.Task[None]]
    _write_lock: asyncio.Lock

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def check_origin(self, origin: str) -> bool:
        """Accepte uniquement les origines dont le ``netloc`` matche ``Host``.

        Tornado exige un opt-in explicite sur toute origine cross-site (même
        authentification cookie est vulnérable au XSRF WebSocket sans cette
        restriction). On applique la contrainte minimale + :meth:`open`
        vérifie en plus le token XSRF.
        """
        parsed = urlparse(origin)
        request_host = self.request.headers.get("Host", "")
        return bool(parsed.netloc) and parsed.netloc == request_host

    async def open(self) -> None:
        """Authentifie le user via cookie et valide XSRF avant d'accepter la WS."""
        user = await self._load_current_user()
        if user is None:
            logger.warning("WebSocket Iris: connexion sans utilisateur authentifié")
            self.close(_WS_CLOSE_AUTH_REQUIRED, "Authentication required")
            return

        try:
            self.check_xsrf_cookie()
        except Exception:  # noqa: BLE001 — Tornado peut lever HTTPError ou SuspiciousOperation
            logger.warning(
                "WebSocket Iris: XSRF validation failed for user_id=%s",
                user.id,
            )
            self.close(_WS_CLOSE_XSRF_FAILED, "XSRF validation failed")
            return

        self.current_user = user
        self._last_mode = _DEFAULT_MODE
        self._cancel_event = asyncio.Event()
        self._agent_task = None
        self._write_lock = asyncio.Lock()
        # Strong-ref pour les tasks fire-and-forget (send_error, consent
        # response, pipeline ask_user response). Sans cette référence,
        # Python 3.12+ peut GC une task avant sa terminaison. Pattern
        # repris de ``app/main.py:_ServerLifecycle._background_tasks``.
        # Cf. mémoire ``feedback_asyncio_create_task_strong_ref.md``.
        self._background_tasks: set[asyncio.Task[Any]] = set()
        logger.info(
            "WebSocket Iris ouvert: user_id=%s, ip=%s",
            user.id,
            self.request.remote_ip,
        )

    def on_close(self) -> None:
        user_id = getattr(getattr(self, "current_user", None), "id", "?")
        cancel_event = getattr(self, "_cancel_event", None)
        if cancel_event is not None:
            cancel_event.set()
        logger.info(
            "WebSocket Iris fermé: user_id=%s, code=%s, reason=%s",
            user_id,
            self.close_code,
            self.close_reason,
        )

    def _spawn_background(self, coro: Any) -> asyncio.Task[Any]:
        """Crée une task fire-and-forget avec référence forte persistante.

        Sans cette référence, Python 3.12+ peut garbage-collecter la task
        avant sa terminaison (cf. doc ``asyncio.create_task``). On stocke
        la task dans ``self._background_tasks`` et on installe un callback
        ``add_done_callback(self._background_tasks.discard)`` pour libérer
        la référence une fois la task terminée.

        Le ``self._background_tasks.discard`` bound-method capture une
        référence à ``self`` qui maintient le handler en vie tant qu'au
        moins une task est pending — sécurise les coros qui doivent finir
        leur écriture WS même si ``on_close()`` arrive entre-temps.
        """
        task = asyncio.ensure_future(coro)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return task

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _rate_limit_key(self) -> str | None:
        user_id = getattr(getattr(self, "current_user", None), "id", None)
        if not isinstance(user_id, int):
            return None
        return f"iris-ws:{user_id}"

    def _check_rate_limit(self) -> bool:
        """Retourne ``True`` si l'utilisateur est rate-limité.

        Fail-closed : pas d'``user_id`` → considéré limité (la connexion a
        pourtant dû authentifier, mais un mock ou un user sans id ne doit
        jamais contourner).
        """
        key = self._rate_limit_key()
        if key is None:
            return True
        allowed = _ws_rate_limiter.check(key, _RATE_LIMIT_MESSAGES, _RATE_LIMIT_WINDOW)
        return not allowed

    # ------------------------------------------------------------------
    # Incoming messages
    # ------------------------------------------------------------------

    def on_message(self, raw_message: str) -> None:
        """Dispatche une frame WebSocket entrante.

        Méthode *synchrone* volontairement : Tornado n'attendrait pas le
        retour d'une coroutine ``on_message`` pour lire le frame suivant, donc
        conserver cette méthode sync garantit qu'un ``cancel`` reçu pendant
        l'exécution d'un ``send_message`` est traité immédiatement.
        """
        payload = _safe_json_loads(raw_message)
        if not isinstance(payload, Mapping):
            self._spawn_background(self._send_error(_Messages.INVALID_JSON))
            return

        action = payload.get("action", "send_message")

        # Cancel — jamais rate-limité (mécanisme de sécurité).
        if action == "cancel":
            self._cancel_event.set()
            logger.info(
                "Cancel requested by user_id=%s",
                getattr(self.current_user, "id", "?"),
            )
            return

        # Heartbeat applicatif émis par le widget flottant (cf.
        # ``static/js/iris-widget.js`` ``_startHeartbeat``). Jamais
        # rate-limité : sinon un onglet idle qui ping toutes les 30s
        # consommerait son bucket et l'user serait throttle au prochain
        # vrai message (adversarial #2 sur fix #7). No-op côté serveur :
        # ``ws.onmessage`` du widget ignore les pongs absents.
        if action == "ping":
            return

        if self._check_rate_limit():
            self._spawn_background(self._send_error(_Messages.RATE_LIMITED))
            return

        if action == "send_message":
            self._schedule_agent(self._handle_send_message(dict(payload)))
        elif action == "clarification_response":
            self._schedule_agent(self._handle_clarification_response(dict(payload)))
        elif action == "data_read_consent_response":
            # Réponse au modal de consentement lecture résultats SQL. Le
            # gate dans ``agent_service`` est en train d'``await`` la
            # résolution du Future — pas besoin de scheduler un nouvel
            # agent task (qui crasherait sur le guard anti-concurrence
            # car ``_agent_task`` est déjà running). Résolution directe
            # via fire-and-forget : ``resolve_consent`` est synchrone et
            # rapide (set_result sur un Future), sans I/O ni LLM.
            self._spawn_background(self._handle_data_read_consent_response(dict(payload)))
        elif action == "pipeline_ask_user_response":
            # Réponse à une question posée par la pipeline elle-même
            # (cf. ``AskUserBridge.ask()`` côté Phase 4). Le run pipeline
            # est en cours d'``await future`` sur la réponse — résoudre
            # via ``submit_response`` libère la coroutine ``ask()`` et
            # la phase reprend. Fire-and-forget : pas de scheduler agent
            # (la pipeline tourne dans un task séparé, géré par
            # ``PipelineRunner._task``). Cf. fix 2026-05-20 architecture
            # pipeline-driven Q/A.
            self._spawn_background(self._handle_pipeline_ask_user_response(dict(payload)))
        else:
            self._spawn_background(self._send_error(_Messages.UNKNOWN_ACTION))

    def _schedule_agent(self, coro: Any) -> None:
        """Lance une coroutine agent en tâche de fond, avec guard anti-concurrence."""
        if self._agent_task and not self._agent_task.done():
            coro.close()  # Don't leak the coroutine object
            self._spawn_background(self._send_error(_Messages.AGENT_RUNNING))
            return
        self._agent_task = asyncio.ensure_future(coro)
        self._agent_task.add_done_callback(self._on_agent_task_done)

    def _on_agent_task_done(self, task: asyncio.Task[Any]) -> None:
        """Capture les exceptions qui échapperaient au ``try/except`` interne."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc is None:
            return
        logger.error(
            "Agent task crashed (user_id=%s): %s",
            getattr(self.current_user, "id", "?"),
            exc,
            exc_info=exc,
        )
        self._spawn_background(self._send_error(_Messages.INTERNAL_ERROR))

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    async def _handle_send_message(self, payload: Mapping[str, Any]) -> None:
        """Délègue à :meth:`IrisAgent.run` et stream les événements."""
        message = (payload.get("message") or "").strip()
        if not message:
            await self._send_error(_Messages.MESSAGE_EMPTY)
            return

        # M3 : re-vérification session avant exécution (helper SSoT — envoie un
        # message clair AVANT de close pour que le frontend explique au user
        # pourquoi sa session se ferme).
        if await self._reject_if_session_invalid():
            return

        conversation_id = _coerce_optional_int(payload.get("conversation_id"))
        file_id = payload.get("file_id")
        # Task #42b (cycle #30) — mode éphémère : si le payload contient
        # ``attachment_stats`` au lieu de ``file_id``, le frontend a déjà
        # calculé les stats agrégées localement (via IrisStatsAggregator
        # #42a). On formate le message pour que le LLM voie les stats
        # sans avoir à lire le fichier disque. Backward-compat : si
        # ``file_id`` est aussi présent, il a priorité (le frontend
        # client n'a pas encore migré). La validation + le formatage
        # passent par ``_format_attachment_stats_into_message`` (SSoT).
        attachment_stats = payload.get("attachment_stats")
        if file_id is None and isinstance(attachment_stats, Mapping) and isinstance(message, str):
            try:
                message = await _format_attachment_stats_into_message(
                    message,
                    attachment_stats,
                    user_id=getattr(self.current_user, "id", None),
                )
            except Exception:  # noqa: BLE001 — fail-soft
                logger.warning(
                    "Format attachment_stats KO — fallback message sans stats",
                    exc_info=True,
                )

        # Task #43b (cycle #32) — logger structuré d'usage mode.
        # Permet à David de monitorer la proportion legacy/éphémère
        # AVANT de décider de tirer le rideau sur le handler legacy
        # (#43d/#43e). Le log a un nom explicite ``iris_upload_mode_used``
        # facilement grep-able dans ``llm_log.md`` et les logs JSON.
        # Pas de PII : juste le mode + user_id + booléens présence.
        _attached_mode = _classify_attachment_mode(file_id, attachment_stats)
        if _attached_mode != "none":
            logger.info(
                "iris_upload_mode_used",
                extra={
                    "iris_upload_mode": _attached_mode,
                    "user_id": getattr(self.current_user, "id", None),
                    "has_file_id": file_id is not None,
                    "has_attachment_stats": isinstance(attachment_stats, Mapping),
                },
            )
            # Task #43c (cycle #33) — incrémente le compteur in-process
            # consommé par IrisModeUsageStatsHandler (/api/admin/iris-mode-usage).
            # Fail-soft : un échec du compteur ne casse pas la conversation.
            try:
                from app.services.ai.iris_mode_stats import record_mode

                record_mode(_attached_mode)
            except Exception:  # noqa: BLE001
                logger.debug("iris_mode_stats.record_mode KO", exc_info=True)
        mode = payload.get("mode", _DEFAULT_MODE)
        if mode not in _ALLOWED_MODES:
            mode = _DEFAULT_MODE
        self._last_mode = mode
        # Entry point d'origine — par défaut ``page`` (rétrocompat clients qui
        # n'envoient pas le champ). Le widget envoie ``source="widget"``.
        source = _coerce_source(payload.get("source"))
        self._last_source = source

        await self._run_agent(
            message=message,
            conversation_id=conversation_id,
            mode=mode,
            file_id=file_id if isinstance(file_id, str) else None,
            role=None,
            source=source,
        )

        # Tracking T3.1 — incrémente ``total_iris_queries`` + maj
        # ``last_iris_query_at`` côté ``UserActivitySummary``. Best-effort :
        # un échec ne doit jamais casser la conversation Iris (l'user a
        # déjà reçu sa réponse via ``_run_agent``).
        try:
            from app.core.database import get_session
            from app.services.onboarding import track_iris_query

            if self.current_user is not None:
                async with get_session() as session:
                    await track_iris_query(session, self.current_user.id)
                    await session.commit()
        except Exception:  # noqa: BLE001 — fail-soft, télémétrie best-effort
            logger.debug("track_iris_query non écrit", exc_info=True)

    async def _handle_clarification_response(self, payload: Mapping[str, Any]) -> None:
        """Envoie la réponse de clarification comme un nouveau tour."""
        if await self._reject_if_session_invalid():
            return
        response = (payload.get("response") or "").strip()
        if not response:
            await self._send_error(_Messages.CLARIFICATION_EMPTY)
            return

        conversation_raw = payload.get("conversation_id")
        if conversation_raw is None:
            await self._send_error(_Messages.CONVERSATION_ID_REQUIRED)
            return
        conversation_id = _coerce_optional_int(conversation_raw)
        if conversation_id is None:
            await self._send_error(_Messages.CONVERSATION_ID_INVALID)
            return
        # Source du payload ; fallback sur le ``_last_source`` mémorisé au
        # dernier send_message (utile si le client ne renvoie pas le champ
        # à chaque réponse de clarification).
        source = _coerce_source(payload.get("source") or getattr(self, "_last_source", None))

        await self._run_agent(
            message=response,
            conversation_id=conversation_id,
            mode=getattr(self, "_last_mode", _DEFAULT_MODE),
            file_id=None,
            role=None,
            source=source,
        )

    async def _handle_data_read_consent_response(self, payload: Mapping[str, Any]) -> None:
        """Résout le Future en attente dans ``agent_service._gate_data_read_consent``.

        Payload attendu (envoyé depuis ``static/js/iris.js``) ::

            {
                "action": "data_read_consent_response",
                "conversation_id": <int>,
                "approved": <bool>,
                "abandoned": <bool>,           # optionnel — défaut False
                "dont_ask_again": <bool>,      # optionnel — défaut False
            }

        Cas d'usage de chaque flag :

        - ``approved=True`` : utilisateur a cliqué OUI (directement OU
          après configuration via le panneau Confidentialité détaché).
          Iris reprend, les éventuels nouveaux termes pseudo s'appliqueront
          au prochain anonymize.
        - ``approved=False, abandoned=False`` : utilisateur a cliqué
          "Configurer" / NON → le frontend doit ouvrir le panneau pour
          configurer les termes, PUIS renvoyer une réponse finale (OK ou
          abandon). Cette réponse intermédiaire ne devrait pas remonter
          ici — mais on est défensif si elle arrive : on ne résout pas.
        - ``approved=False, abandoned=True`` : utilisateur a fermé tout
          le flow (Esc/X). Iris reçoit "lecture refusée" au tool_result.

        Si ``dont_ask_again=True``, persiste la pref user :
        - ``approved=True`` → ``always_allow``.
        - ``approved=False`` → ``always_show_panel``.
        """
        if await self._reject_if_session_invalid():
            return
        approved = bool(payload.get("approved"))
        abandoned = bool(payload.get("abandoned", False))
        dont_ask_again = bool(payload.get("dont_ask_again", False))

        conversation_raw = payload.get("conversation_id")
        conversation_id = _coerce_optional_int(conversation_raw)
        if conversation_id is None:
            await self._send_error(_Messages.CONVERSATION_ID_INVALID)
            return

        logger.info(
            "data_read_consent_response: payload reçu user_id=%s conv_id=%s "
            "approved=%s abandoned=%s dont_ask_again=%s",
            getattr(self.current_user, "id", None),
            conversation_id,
            approved,
            abandoned,
            dont_ask_again,
        )

        # Defense-in-depth ownership check : un user authentifié ne doit
        # pas pouvoir débloquer le gate de consentement d'un autre user
        # en devinant son conversation_id (séquentiel = prédictible).
        # Réutilise le helper déjà appliqué à ``_run_agent`` (cf.
        # adversarial review CRITICAL #7 mai 2026).
        user = self.current_user
        if user is None:
            await self._send_error(_Messages.INTERNAL_ERROR)
            return
        try:
            # SSOT du helper : ``conversation_lifecycle`` (cf. l'autre call-site
            # plus bas dans ``open`` qui importe depuis le bon module). Régression
            # 2026-05-19 : import incorrect depuis ``agent_session_memory`` qui
            # n'expose pas ce symbole → ImportError silencieux → owned=False →
            # consent payload droppé. Tout consent user passait à la trappe.
            from app.services.ai.conversation_lifecycle import (
                assert_conversation_owned_by_user,
            )

            owned = await assert_conversation_owned_by_user(conversation_id, user.id)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "data_read_consent_response: ownership check crashed " "(conv=%s user=%s) : %s",
                conversation_id,
                getattr(user, "id", "?"),
                exc,
            )
            owned = False
        if not owned:
            logger.warning(
                "data_read_consent_response: ownership check failed "
                "(conv=%s user=%s) — dropping payload",
                conversation_id,
                getattr(user, "id", "?"),
            )
            await self._send_error("Conversation introuvable ou non autorisée.")
            return

        # Réponse intermédiaire (refus = ouvrir panel) : pas une réponse
        # finale — le frontend rappellera avec approved=true (après
        # config) ou abandoned=true. On no-op silencieusement plutôt
        # que de résoudre le Future prématurément.
        if not approved and not abandoned:
            logger.debug(
                "data_read_consent_response: intermediate refusal "
                "(conv=%s) — awaiting final response",
                conversation_id,
            )
            return

        # Si "ne plus me redemander" coché : persiste la pref AVANT de
        # résoudre le Future, pour que les prochains tools de cette
        # conversation voient la pref à jour (race : si on résout
        # d'abord et que l'agent loop check_pref avant le commit, la
        # pref serait encore stale).
        if dont_ask_again:
            # Rate-limit anti-spam pref-write : un user authentifié ne
            # doit pas pouvoir bombarder la WS pour saturer les writes
            # UserPreference. 5/min suffit largement à un humain qui
            # change d'avis sur ce setting.
            if not _iris_consent_ws_rate_limiter.check(
                f"iris_consent_ws:{user.id}",
                _IRIS_CONSENT_WS_RATE_MAX,
                _IRIS_CONSENT_WS_RATE_WINDOW_S,
            ):
                logger.info(
                    "data_read_consent: WS pref-write rate-limit hit "
                    "(user=%s) — flag ignoré, résolution Future continue",
                    user.id,
                )
                # On NE bloque PAS la résolution du Future : l'utilisateur
                # a quand même cliqué OUI/NON, son intention immédiate
                # doit aboutir. Seul le ``dont_ask_again`` est dropé.
            else:
                new_pref = "always_allow" if approved else "always_show_panel"
                try:
                    from app.core.database import get_session
                    from app.services.ai.data_read_consent import (
                        set_user_consent_pref,
                    )

                    async with get_session() as session:
                        await set_user_consent_pref(session, user.id, new_pref)
                        await session.commit()
                    logger.info(
                        "data_read_consent: pref updated via WS " "(user=%s, pref=%s)",
                        user.id,
                        new_pref,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "data_read_consent_response: persist pref échoué "
                        "(user=%s, pref=%s) : %s",
                        user.id,
                        new_pref,
                        exc,
                    )

        # Résolution du Future. Idempotent : un double-clic ou un envoi
        # concurrent depuis un autre onglet ne crashe pas.
        try:
            from app.services.ai.data_read_consent import (
                ConsentResponse,
                resolve_consent,
            )

            resolve_consent(
                user.id,
                conversation_id,
                ConsentResponse(
                    approved=approved,
                    abandoned=abandoned,
                    dont_ask_again=dont_ask_again,
                ),
            )
        except Exception as exc:  # noqa: BLE001 — defense-in-depth
            logger.error(
                "data_read_consent_response: resolve_consent crashed " "(conv=%s) : %s",
                conversation_id,
                exc,
                exc_info=exc,
            )
            await self._send_error(_Messages.INTERNAL_ERROR)

    # Cap longueur réponse user → AskUserBridge (2 KB, idem
    # ``iris_pipeline_ws.IrisPipelineWebSocketHandler._ASK_RESPONSE_MAX_CHARS``).
    # Une réponse à une question pipeline (sélection d'option / précision)
    # est typiquement < 100 chars. Au-delà = bug client ou abus.
    _PIPELINE_ASK_RESPONSE_MAX_CHARS = 2048

    async def _handle_pipeline_ask_user_response(self, payload: Mapping[str, Any]) -> None:
        """Résout une question posée par la pipeline elle-même via
        ``AskUserBridge.ask()``.

        La pipeline (Phase 4 typiquement, mais générique) a appelé
        ``bridge.ask(question, ...)`` qui ``await future``. Le bus a publié
        un event ``pipeline_ask_user`` que ``_stream_pipeline_run_to_chat``
        propage au frontend (cf. fix 2026-05-20 — câblage pipeline-driven
        Q/A). Le frontend a affiché la question, l'user a répondu, et
        envoie cette action sur le WS Iris.

        Payload attendu ::

            {
                "action": "pipeline_ask_user_response",
                "run_id": <int>,
                "ask_id": "<str hex 12 chars>",
                "response": "<str réponse user>",
            }

        Sécurité : ownership check via ``get_runner(run_id, user.id)`` —
        un user ne peut pas répondre à une question d'un autre user en
        devinant son ``run_id`` (séquentiel = prédictible). Cap longueur
        2 KB (idem WS pipeline-dédié). En cas d'erreur (run inactif,
        ask_id inconnu, BDD KO), on log et on no-op silencieusement —
        la pipeline timeout sur son ``await future`` après PHASE4_ASK_TIMEOUT
        et fallback en degraded (cf. ``_phase4_ask_user_safely``).
        """
        if await self._reject_if_session_invalid():
            return
        run_id = _coerce_optional_int(payload.get("run_id"))
        ask_id = str(payload.get("ask_id") or "").strip()
        response = payload.get("response")
        if not isinstance(run_id, int) or not ask_id or response is None:
            await self._send_error("Paramètres requis : run_id (int), ask_id (str), response.")
            return

        response_str = str(response)
        if len(response_str) > self._PIPELINE_ASK_RESPONSE_MAX_CHARS:
            await self._send_error(
                f"Réponse trop longue (max {self._PIPELINE_ASK_RESPONSE_MAX_CHARS} chars)."
            )
            return

        user = self.current_user
        if user is None:
            await self._send_error(_Messages.INTERNAL_ERROR)
            return

        try:
            from app.services.ai.pipeline_runner import get_runner

            runner = await get_runner(run_id, user.id)
        except Exception as exc:  # noqa: BLE001 — defense-in-depth
            logger.exception(
                "pipeline_ask_user_response: get_runner crashed " "(user=%s run=%s ask=%s) : %s",
                user.id,
                run_id,
                ask_id,
                exc,
            )
            await self._send_error(_Messages.INTERNAL_ERROR)
            return

        if runner is None:
            # Run inconnu OU pas owner. Anti-leak existence = même message
            # que les autres handlers pipeline.
            logger.info(
                "pipeline_ask_user_response: runner introuvable " "(user=%s run=%s ask=%s)",
                user.id,
                run_id,
                ask_id,
            )
            await self._send_error(
                "Pipeline #" + str(run_id) + " non active sur ce serveur "
                "(peut-être terminée entre temps). Réponse ignorée."
            )
            return

        try:
            ok = await runner.ask_user_bridge.submit_response(ask_id, response_str)
        except Exception as exc:  # noqa: BLE001 — defense-in-depth
            logger.exception(
                "pipeline_ask_user_response: submit_response crashed "
                "(user=%s run=%s ask=%s) : %s",
                user.id,
                run_id,
                ask_id,
                exc,
            )
            await self._send_error(_Messages.INTERNAL_ERROR)
            return

        if not ok:
            # ask_id inconnu / déjà résolu / timeout côté pipeline.
            # Pas une erreur fatale — l'user a peut-être cliqué après
            # le timeout, ou refresh + reclick. On informe sans drama.
            logger.info(
                "pipeline_ask_user_response: ask_id non pendant "
                "(user=%s run=%s ask=%s — déjà résolu ou expiré)",
                user.id,
                run_id,
                ask_id,
            )

    async def _run_agent(
        self,
        *,
        message: str,
        conversation_id: Optional[int],
        mode: str,
        file_id: Optional[str],
        role: Optional[AgentRole],
        source: str = ConversationSource.PAGE.value,
    ) -> None:
        """Pipe agent events → WebSocket, avec gestion d'erreur centralisée.

        Pose le ``request_scope`` (user_id + request_id) avant tout appel
        LLM. Sans ce scope, le hook ``llm_call_tracker`` voit
        ``current_user_id() == None`` car ``IrisWebSocketHandler`` étend
        directement ``tornado.websocket.WebSocketHandler`` (pas
        ``BaseHandler``) → ``BaseHandler.prepare()`` ne tourne jamais
        pour les WS, et le ``set_request_context()`` qui s'y trouve
        n'est pas appelé. Conséquence : tous les ``AIPerformanceLog``
        d'Iris auraient ``user_id=NULL`` → breakdown ``Par utilisateur``
        agglomère tout sous "Système" au lieu de distinguer chaque user.
        """
        agent = get_iris_agent()
        self._cancel_event.clear()
        # Un request_id par tour (≈ par message envoyé) pour pouvoir
        # corréler les rows AIPerformanceLog de la même demande utilisateur.
        # ``conversation_id`` reste posé séparément par ``llm_call_context``
        # à l'intérieur de l'agent.
        scope_user_id = getattr(self.current_user, "id", None)
        scope_request_id = f"iris-ws-{uuid.uuid4().hex[:12]}"

        # ── Persistance event-par-event pour replay au refresh ─────────────
        # Source de vérité unique pour la lifecycle Conversation :
        # ``app/services/ai/conversation_lifecycle.py``. Réutilise l'active
        # existante OU en crée une (cf. review BLOCKING #4 : avant on créait
        # TOUJOURS une nouvelle → orphelins). Defense-in-depth ownership
        # check via ``assert_conversation_owned_by_user`` (review BLOCKING #6).
        from app.services.ai.conversation_event_persister import (
            SequentialEventPersister,
            TRANSIENT_EVENT_TYPES,
            get_max_turn_index_for_conversation,
        )
        from app.services.ai.conversation_lifecycle import (
            get_or_create_active_conversation,
            assert_conversation_owned_by_user,
        )

        _resolved_conv_id: Optional[int] = conversation_id

        # Defense-in-depth : si le client a fourni un conv_id, vérifier
        # l'ownership AVANT toute lecture/écriture. L'agent vérifie aussi
        # en aval mais reposer 100% sur l'aval = brèche silencieuse au
        # prochain refactor.
        #
        # TOCTOU acté (cf. adversarial review 2026-05-10 CRITICAL #5) :
        # entre cet ownership check et le WAL persist plus bas, un autre
        # handler (clear, soft-delete) peut modifier ``is_active`` ou
        # transférer la conv. Risque accepté car (a) SQLite WAL-mode +
        # mono-tenant local = fenêtre microseconde, (b) le pire cas est
        # un row WAL orphelin sur conv ``is_active=False`` (récupérable
        # par cleanup), (c) corriger nécessiterait ``SELECT FOR UPDATE``
        # qui n'existe pas en SQLite. Trade-off à revisiter si Komptia
        # passe sur Postgres multi-tenant.
        if _resolved_conv_id is not None and scope_user_id is not None:
            # ``expected_source=source`` empêche un client widget d'écrire
            # dans la conv ``page`` de l'user (et inversement). Sans ce
            # check, le fix #22 (séparation widget/page) était contournable
            # en envoyant un conversation_id cross-source — cf. adversarial
            # #4 du 2026-05-21.
            owned = await assert_conversation_owned_by_user(
                _resolved_conv_id, scope_user_id, expected_source=source
            )
            if not owned:
                logger.warning(
                    "Conversation ownership check failed " "(conv=%s user=%s expected_source=%s)",
                    _resolved_conv_id,
                    scope_user_id,
                    source,
                )
                await self._send_error("Conversation introuvable ou non autorisée.")
                return

        # Si pas de conv_id fourni : réutiliser l'active OU en créer une
        # via le SSOT (qui maintient l'invariant 1 active par
        # (user, agent_role, source)). Le filtre ``source`` est CRITIQUE :
        # sans lui, le widget polluait la conv de la page ``/iris`` (bug
        # 2026-05-21).
        if _resolved_conv_id is None and scope_user_id is not None:
            _resolved_conv_id = await get_or_create_active_conversation(
                scope_user_id, agent_role="iris", source=source
            )

        # C2-followup BLOCKING (review post-Phase 1 session 11) — Acquérir
        # le lock conversation AVANT le ``SequentialEventPersister.open``
        # qui calcule ``max_turn + 1``. Sans ce lock, 2 WS du même user
        # qui démarrent un run simultanément lisent le même ``max_turn``
        # et créent 2 events au même ``turn_index`` → corruption replay.
        # Le lock dans ``agent.run()`` (Phase 1) ne ferme PAS cette race
        # car il est acquis APRÈS le persister init.
        #
        # SSOT-7 (session 15) — On utilise le context manager
        # ``agent.conversation_lock(conv_id)`` qui peuple automatiquement
        # ``_currently_locked_conversations`` ; ``agent.run()`` détecte
        # l'état via le set au lieu d'un flag boolean passé en arg
        # (qui dépendait d'une promesse du caller, fragile).
        #
        # On entre/sort manuellement le context manager (``__aenter__``/
        # ``__aexit__``) plutôt qu'un ``async with`` global pour éviter
        # de re-indenter 120 lignes — trade-off ergonomique vs risque
        # de corruption sur re-indent massif d'un code complexe (try/
        # except imbriqués).
        #
        # Trade-off résiduel : risque d'orphan lock si une exception se
        # produit entre cet ``__aenter__`` et le ``try:`` ci-dessous —
        # probabilité < 0.01% (juste BDD read/write courte), impact = 1
        # lock orphelin jusqu'au prochain restart.
        _conv_lock_cm = None
        if _resolved_conv_id is not None:
            _conv_lock_cm = agent.conversation_lock(_resolved_conv_id)
            await _conv_lock_cm.__aenter__()

        _persister: Optional[SequentialEventPersister] = None
        if _resolved_conv_id is not None:
            try:
                max_turn = await get_max_turn_index_for_conversation(_resolved_conv_id)
                _persister = await SequentialEventPersister.open(_resolved_conv_id, max_turn + 1)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Persister init failed (conv=%s): %s", _resolved_conv_id, exc)
                _persister = None

        # ── WAL user_message UNIQUEMENT côté events (replay UI) ────────────
        # POURQUOI ÉVITER ``ConversationMessage`` ICI :
        # L'agent (``agent_service.py:_load_conversation_history``) charge
        # les ``ConversationMessage`` USER pour reconstruire son contexte
        # LLM puis ré-ajoute le ``message`` du turn courant en queue. Si on
        # WAL-persistait aussi un ``ConversationMessage(role=USER)``, l'agent
        # verrait le user message DEUX fois consécutivement → Anthropic 400
        # « roles must alternate » ou réponse polluée par la duplication
        # (cf. adversarial review 2026-05-10 BLOCKING #1).
        #
        # Le WAL côté ``ConversationEvent`` SUFFIT pour le besoin originel :
        # garantir qu'au reload (page refresh, retour-arrière, crash WS),
        # l'utilisateur revoit son message dans la conversation grâce au
        # case ``user_message`` du dispatcher frontend. Le ``_save_turn``
        # classique se charge de persister le ``ConversationMessage`` à la
        # fin du turn réussi.
        #
        # Trade-off accepté : si le tool loop crashe AVANT ``_save_turn``,
        # le ``ConversationMessage`` USER n'est pas créé en BDD, mais
        # l'event existe (donc replay UI OK) et le bandeau "interrompu"
        # signale à l'utilisateur de relancer. Le pire = recommencer le
        # turn — pas de fausse réponse silencieuse.
        # ⚠️ WAL fire-and-forget — distinct du flow event-loop ci-dessous.
        # ``user_message`` n'est PAS dans ``TRANSIENT_EVENT_TYPES`` (donc persistable).
        # Le retour de ``persist()`` est ignoré volontairement : pas d'envoi WS à
        # gater à ce stade (l'event n'est PAS yieldé par l'agent — il est écrit
        # par le handler avant le tool loop). Ne PAS introduire un check
        # ``persisted_ok`` ici sans réaliser que la sémantique diffère du loop.
        if _resolved_conv_id is not None and _persister is not None:
            try:
                await _persister.persist(
                    {
                        "type": "user_message",
                        "content": message,
                        "mode": mode,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "user_message WAL event persist failed (conv=%s): %s",
                    _resolved_conv_id,
                    exc,
                )

        # **Phase 2.5.quinquies (#121)** — Tracking des refus data_access.
        # Si pendant ce run on observe au moins un ``tool_result`` avec
        # ``blocked_by="data_access_rule"``, on incrémente
        # ``conversation.consecutive_denied_count`` à la fin du run.
        # Sinon (réponse OK), on reset le compteur à 0. Branche le
        # compteur posé en #98 (colonne ``Conversation`` + migration BDD).
        denied_in_run = False
        try:
            with request_scope(
                request_id=scope_request_id,
                user_id=scope_user_id,
            ):
                # La logique de timeout + aclosing est extraite dans
                # ``agent_drain.drain_agent_events`` pour testabilité
                # (cf. ``tests/unit/test_agent_drain.py``). On reste
                # ici sur la responsabilité du handler : tracking
                # denied, persistance, send WS.
                import contextlib as _ctxlib

                from app.services.ai.agent_drain import (
                    AgentEventTimeout,
                    AgentRunWallClockTimeout,
                    drain_agent_events,
                )

                _agent_gen = agent.run(
                    message=message,
                    conversation_id=_resolved_conv_id,
                    user=self.current_user,
                    role=role,
                    mode=mode,
                    cancel_event=self._cancel_event,
                    file_id=file_id,
                    # ``source`` propagé pour le fallback SSOT interne à
                    # l'agent (cf. ``_get_or_create_conversation``) — sans
                    # cela, si l'agent retombe sur le SSOT (BDD lente,
                    # conv_id non résolu en amont), il crée une conv
                    # ``page`` même côté widget.
                    source=source,
                    # SSOT-7 : le caller a acquis le lock via
                    # ``agent.conversation_lock(conv_id)`` ci-dessus, qui peuple
                    # ``_currently_locked_conversations``. ``agent.run()`` détecte
                    # via le set et skip son propre acquire (évite deadlock).
                    # Plus besoin du flag legacy.
                )
                # Double aclosing : (a) ``drain_agent_events`` wrap
                # ``_agent_gen`` dans son propre ``aclosing`` interne ;
                # (b) le caller (ici) wrap ``drain_agent_events`` lui-
                # même dans un ``aclosing`` externe pour garantir un
                # cleanup synchrone si on ``break`` ou si une exception
                # propage à travers la boucle ``async for``. Sans le
                # wrapper externe, Python n'appelle ``aclose`` sur le
                # helper qu'à la finalisation event-loop (potentiellement
                # secondes/minutes plus tard) — leak transitoire en
                # multi-user.
                try:
                    async with _ctxlib.aclosing(
                        drain_agent_events(
                            _agent_gen,
                            per_event_timeout_s=_AGENT_EVENT_TIMEOUT_SECONDS,
                            total_timeout_s=_AGENT_RUN_TOTAL_TIMEOUT_SECONDS,
                        )
                    ) as _drained:
                        async for event in _drained:
                            # Tracking refus data_access : un seul ``tool_result``
                            # avec ce marker suffit à classer le run comme "denied".
                            if event.get("type") == "tool_result":
                                _result_payload = event.get("result")
                                if (
                                    isinstance(_result_payload, dict)
                                    and _result_payload.get("blocked_by") == "data_access_rule"
                                ):
                                    denied_in_run = True

                            # Persist AVANT envoi WS pour garantir atomicité BDD↔client.
                            # Si la persistance échoue (BDD down), on N'envoie PAS
                            # l'event au client : sinon il verra un event que la
                            # BDD n'a pas → divergence garantie au refresh.
                            # Cf. adversarial review CRITICAL #12.
                            if _persister is not None:
                                try:
                                    persisted_ok = await _persister.persist(event)
                                except Exception as exc:  # noqa: BLE001
                                    logger.warning(
                                        "ConversationEvent persist failed (conv=%s): %s",
                                        _resolved_conv_id,
                                        exc,
                                    )
                                    persisted_ok = False
                                # SSoT : ``persist_event`` retourne ``False`` pour 2 cas
                                # distincts — (a) skip volontaire d'un type dans
                                # ``TRANSIENT_EVENT_TYPES`` (cf. docstring du persister)
                                # et (b) échec BDD réel. Cette garde ne skip-WS QUE pour
                                # (b) — sinon les modals consent / la barre context ne
                                # s'affichent jamais. NE PAS hardcoder une whitelist
                                # locale (régression 2026-05-22 → 2026-05-26).
                                if (
                                    not persisted_ok
                                    and event.get("type") not in TRANSIENT_EVENT_TYPES
                                ):
                                    # Skip silencieux côté logger pour ne pas spammer
                                    # — mais NE PAS envoyer au client. La conv reste
                                    # cohérente (le client verra le tour comme s'il
                                    # n'avait pas eu lieu, sans drift au refresh).
                                    logger.debug(
                                        "Event not sent to client (persist failed) " "type=%s",
                                        event.get("type"),
                                    )
                                    continue

                            await self._safe_write(json.dumps(event, default=_json_safe_default))
                except AgentEventTimeout as _timeout_exc:
                    logger.warning(
                        "Agent.run event timeout après %.0fs " "(user_id=%s conv=%s)",
                        _timeout_exc.timeout_s,
                        scope_user_id,
                        _resolved_conv_id,
                    )
                    # ``cancel_event.set()`` signale l'agent ; il le
                    # reverra à son prochain checkpoint cancel. Le
                    # ``aclose()`` est garanti par ``drain_agent_events``
                    # via ``contextlib.aclosing``. Le ``finally`` global
                    # reset ``_cancel_event`` (cf. plus bas).
                    self._cancel_event.set()
                    await self._send_error(
                        "La requête a dépassé le délai maximum autorisé. "
                        "Reformulez en plus simple ou découpez en étapes."
                    )
                except AgentRunWallClockTimeout as _wall_exc:
                    logger.warning(
                        "Agent.run wall-clock timeout après %.0fs "
                        "(user_id=%s conv=%s, elapsed=%.0fs)",
                        _wall_exc.timeout_s,
                        scope_user_id,
                        _resolved_conv_id,
                        _wall_exc.elapsed_s,
                    )
                    self._cancel_event.set()
                    await self._send_error(
                        "La requête a dépassé le délai global autorisé. "
                        "Réessayez en découpant en étapes plus simples."
                    )
        except tornado.websocket.WebSocketClosedError:
            logger.info(
                "WebSocket fermé pendant le streaming (user_id=%s)",
                getattr(self.current_user, "id", "?"),
            )
        except Exception as exc:  # noqa: BLE001 — on veut classifier puis remonter
            logger.error("Erreur inattendue agent.run: %s", exc, exc_info=True)
            # P2.2 — pour QueryError/SageConnectionError, helper async qui
            # catégorise + sanitize PII via sanitize_sql_for_client.
            await self._send_error(await _classify_agent_error_for_user(exc, self.current_user))
        finally:
            # Reset ``_cancel_event`` (adversarial CRIT #1) — sans ce
            # reset, après un timeout serveur le ``_cancel_event`` reste
            # en état ``set``. Les actions WS suivantes du même user qui
            # ne re-clear PAS l'event (``clarification_response``,
            # ``data_read_consent_response``) appelleraient ``agent.run``
            # avec un ``cancel_event`` déjà ``set`` → cancel immédiat
            # silencieux. ``send_message`` clear au début (ligne 1657)
            # donc serait OK seul, mais defense-in-depth : on clear ici
            # pour TOUTE sortie de ``_run_agent``. Idempotent (no-op si
            # déjà clear).
            self._cancel_event.clear()
            # C2-followup — Release le lock conversation EN PREMIER avant les
            # autres cleanup. Garantit qu'un autre WS en attente peut démarrer
            # même si update_consecutive_denied_count échoue. Defensive : try
            # /except RuntimeError pour le cas pathologique où le lock aurait
            # déjà été release ailleurs (ne devrait pas arriver mais pas grave).
            # SSOT-7 — Sortie du context manager. ``__aexit__`` release le
            # lock ET retire conv_id de ``_currently_locked_conversations``.
            # ``None, None, None`` car on n'a pas d'exception à propager
            # (le finally s'exécute APRÈS qu'une éventuelle exception soit
            # déjà gérée plus haut par le try/except imbriqué du run).
            if _conv_lock_cm is not None:
                try:
                    await _conv_lock_cm.__aexit__(None, None, None)
                    logger.debug(
                        "C2 SSOT-7: lock handler libéré conv=%s",
                        _resolved_conv_id,
                    )
                except RuntimeError as _rel_exc:  # pragma: no cover — defensive
                    logger.warning(
                        "C2 SSOT-7: release lock handler conv=%s a raise: %s",
                        _resolved_conv_id,
                        _rel_exc,
                    )
            # Update conversation.consecutive_denied_count (#121).
            # Best-effort fail-soft : si la BDD est down, on logue et on
            # continue (un compteur imparfait vaut mieux que casser le
            # streaming par un check). N'agit que si ``_resolved_conv_id``
            # est défini (sinon pas de conversation à update).
            if _resolved_conv_id:
                try:
                    await self._update_consecutive_denied_count(_resolved_conv_id, denied_in_run)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "consecutive_denied_count update failed " "(conv=%s denied=%s): %s",
                        _resolved_conv_id,
                        denied_in_run,
                        exc,
                    )

    # ------------------------------------------------------------------
    # Helpers WS
    # ------------------------------------------------------------------

    async def _update_consecutive_denied_count(self, conv_id: int, denied_in_run: bool) -> None:
        """**Phase 2.5.quinquies (#121)** — Branche le compteur posé en #98.

        Délègue au helper module-level :func:`_apply_denied_count_update`
        pour la testabilité unitaire (le handler Tornado est lourd à
        monter en test).
        """
        await _apply_denied_count_update(conv_id, denied_in_run)

    async def _safe_write(self, payload: str) -> None:
        """Écrit sur la WS sous ``_write_lock`` — sérialise les messages sortants."""
        lock = getattr(self, "_write_lock", None)
        if lock is not None:
            async with lock:
                await self.write_message(payload)
        else:
            await self.write_message(payload)

    async def _send_error(self, message: str) -> None:
        """Envoie un événement ``{"type": "error", ...}`` — swallow sur WS fermée."""
        try:
            await self._safe_write(json.dumps({"type": "error", "message": message}))
        except tornado.websocket.WebSocketClosedError:
            pass

    async def _load_current_user(self) -> Optional[User]:
        """Charge l'utilisateur via cookie sécurisé (miroir :class:`BaseHandler`)."""
        try:
            token_bytes = self.get_secure_cookie("session_token")
            if not token_bytes:
                return None
            token_str = token_bytes.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            logger.warning("WebSocket Iris: cookie session_token corrompu")
            return None
        try:
            session_manager = get_session_manager()
            return await session_manager.get_user_from_token(token_str)
        except Exception as exc:  # noqa: BLE001 — fail-safe : anonymous
            logger.warning("Erreur chargement utilisateur WebSocket: %s", exc)
            return None

    async def _is_session_still_valid(self) -> bool:
        """Re-vérifie que la session est encore valide à chaque action utilisateur.

        Sans ce check, une WS ouverte conserve indéfiniment ``self.current_user``
        figé depuis ``open()`` — un user désactivé par l'admin ou dont le token
        a expiré peut continuer à requêter Iris jusqu'à fermeture WS (souvent
        plusieurs heures). Cf. finding M3 audit /iris 2026-05-20.

        Retourne ``False`` si : pas de current_user, cookie invalide, token
        expiré, user désactivé en BDD, ou changement d'identité (sécurité —
        un cookie pivotant ne doit pas re-router une WS existante).

        Fail-soft sur exception transitoire BDD : retourne ``True`` (ne pas
        casser la conversation pour un hiccup réseau).
        """
        if self.current_user is None:
            return False
        try:
            current = await self._load_current_user()
        except Exception:  # noqa: BLE001 — fail-soft transitoire
            logger.warning(
                "Re-vérification session échouée (fail-soft), on garde la session active"
            )
            return True
        if current is None:
            return False
        if current.id != self.current_user.id:
            return False
        if not getattr(current, "is_active", True):
            return False
        return True

    async def _reject_if_session_invalid(self) -> bool:
        """Garde SSoT pour les handlers WS qui pilotent l'agent ou débloquent
        un gate : re-vérifie la session via :meth:`_is_session_still_valid`.

        Si invalide : envoie ``SESSION_EXPIRED``, ferme la WS
        (``_WS_CLOSE_AUTH_REQUIRED``) et retourne ``True`` (le caller DOIT
        ``return``). Sinon ``False``. Sans cette garde sur TOUTES les entrées
        (pas seulement send_message), un user désactivé/expiré mid-conversation
        continue de piloter l'agent + les tools SQL via une réponse de
        clarification, un consentement, ou une réponse pipeline.
        """
        if await self._is_session_still_valid():
            return False
        await self._send_error(_Messages.SESSION_EXPIRED)
        self.close(_WS_CLOSE_AUTH_REQUIRED, "Session expired")
        return True


# ---------------------------------------------------------------------------
# API handlers
# ---------------------------------------------------------------------------


def _coerce_optional_int(value: object) -> Optional[int]:
    """Coerce ``value`` en ``int`` — ``None`` si impossible."""
    if value is None:
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


_VALID_SOURCES = frozenset(s.value for s in ConversationSource)


def _coerce_source(value: object) -> str:
    """Coerce ``value`` en ``ConversationSource`` valide.

    Tout payload absent, vide, ou non reconnu est traité comme ``page``.
    Fail-safe : on n'accepte JAMAIS un ``source`` arbitraire venu du
    client (l'enum est le contrat). Sans cette validation, un client
    malicieux pourrait poser ``source="../etc"`` et créer des conv
    isolées hors-scope du SSOT (déni de service par fragmentation).
    """
    if isinstance(value, str) and value in _VALID_SOURCES:
        return value
    return ConversationSource.PAGE.value


# ── Task #43d (cycle #33) — soft disable du mode legacy ─────────────


def _legacy_upload_disabled() -> bool:
    """Retourne True si le mode legacy (file_id + lecture disque) doit
    être désactivé soft (handlers retournent 410 Gone).

    Lu via env var ``IRIS_LEGACY_UPLOAD_DISABLED`` (pattern Komptia env
    pour les flags d'ops, cf. ``IRIS_DISABLE_EG_FOR_SQL_PATH``).

    **Comment l'activer** : ``export IRIS_LEGACY_UPLOAD_DISABLED=true``
    puis restart Tornado. Toutes les routes upload legacy (``POST
    /api/iris/upload``, ``POST /api/iris/upload/cancel``, ``POST
    /api/iris/parse-attachment``) retournent 410 Gone avec un message
    FR clair invitant à utiliser le mode éphémère.

    **Quand l'activer** : quand ``/api/admin/iris-mode-usage`` montre
    ``decision_hint = "all_ephemeral"`` ou ``"mostly_ephemeral"``
    stable depuis plusieurs jours. C'est l'étape AVANT la suppression
    définitive du code (#43e).

    **Rollback** : ``unset IRIS_LEGACY_UPLOAD_DISABLED`` + restart →
    le mode legacy se réactive immédiatement.
    """
    raw = os.environ.get("IRIS_LEGACY_UPLOAD_DISABLED", "")
    return raw.strip().lower() in ("1", "true", "yes", "on")


_LEGACY_DISABLED_MESSAGE: Final[str] = (
    "Mode upload legacy désactivé. Komptia est passé en mode éphémère "
    "(stats agrégées navigateur). Recharge la page — ton navigateur "
    "calculera automatiquement les stats au prochain upload."
)


# ── Task #43b (cycle #32) — classifieur d'usage mode upload ─────────


def _classify_attachment_mode(file_id: Any, attachment_stats: Any) -> str:
    """Retourne le mode d'attachement utilisé par un payload WS.

    Valeurs :
    - ``"legacy"`` : ``file_id`` présent (le serveur va lire le fichier)
    - ``"ephemeral"`` : ``attachment_stats`` présent SANS ``file_id``
    - ``"both"`` : les deux présents (transition — ``file_id`` gagne)
    - ``"none"`` : aucun (message sans pièce jointe)

    Pure (pas d'I/O). Utilisé pour le logger structuré #43b.
    """
    has_file_id = isinstance(file_id, str) and bool(file_id)
    has_stats = isinstance(attachment_stats, Mapping) and bool(attachment_stats)
    if has_file_id and has_stats:
        return "both"
    if has_file_id:
        return "legacy"
    if has_stats:
        return "ephemeral"
    return "none"


# ── Task #42b (cycle #30) — formatage stats agrégées → message LLM ──


# Caps anti-payload-énorme (défense côté serveur même si le frontend
# IrisStatsAggregator a déjà cappé). Si un attaquant forge un payload
# WS avec 10000 colonnes, on tronque pour ne pas saturer le prompt.
_STATS_MAX_COLUMNS_INJECTED: Final[int] = 50
_STATS_MAX_TOP_VALUES_INJECTED: Final[int] = 5


def _format_stats_payload_to_text(stats: Mapping[str, Any], filename: str) -> str:
    """Convertit un payload stats agrégées (shape ``IrisStatsAggregator``)
    en un bloc texte FR compact pour injection LLM.

    Format aligné sur la doctrine du marker ``FILE_ATTACHMENT_MARKER``
    (cf. agent_roles.py — reconnu par ``FILE_ATTACHMENT_GUIDANCE``).
    Le LLM voit :

        📎 Fichier joint (mode éphémère — stats agrégées) : <name>
        - 100 lignes × 3 colonnes
        - Colonnes :
          - client (str, 0 null, 3 distincts) — top: ACME×2, FOO×1, BAR×1
          - montant (numeric, 1 null) — min=50 max=250 mean=133.3 (n=3)
          - statut (str, 0 null, 2 distincts) — top: paid×3, pending×1
    """
    if not isinstance(stats, Mapping):
        return ""

    row_count = stats.get("row_count")
    col_count = stats.get("column_count")
    columns = stats.get("column_stats", [])
    if not isinstance(columns, list):
        columns = []

    lines: list[str] = [
        f"{FILE_ATTACHMENT_MARKER} (mode éphémère — stats agrégées uniquement) : `{filename}`",
        f"- {row_count} ligne(s) × {col_count} colonne(s)",
        "- Colonnes :",
    ]

    for col in columns[:_STATS_MAX_COLUMNS_INJECTED]:
        if not isinstance(col, Mapping):
            continue
        name = col.get("name", "?")
        type_hint = col.get("type_hint", "unknown")
        null_count = col.get("null_count", 0)
        distinct = col.get("distinct_count_capped", 0)
        overflow = col.get("distinct_overflow", False)

        line = f"  - `{name}` ({type_hint}, {null_count} null"
        if distinct:
            line += f", {distinct} distincts"
            if overflow:
                line += "+"  # signale cap atteint
        line += ")"

        numeric = col.get("numeric_stats")
        if isinstance(numeric, Mapping):
            mn = numeric.get("min")
            mx = numeric.get("max")
            mean = numeric.get("mean")
            n = numeric.get("count")
            if all(v is not None for v in (mn, mx, mean, n)):
                line += f" — min={mn} max={mx} mean={mean:.4g} (n={n})"

        top_values = col.get("top_values", [])
        if isinstance(top_values, list) and top_values:
            tops_formatted = []
            for tv in top_values[:_STATS_MAX_TOP_VALUES_INJECTED]:
                if isinstance(tv, Mapping):
                    val = tv.get("value", "?")
                    cnt = tv.get("count", 0)
                    # Tronque les valeurs longues (anti-saturation)
                    val_str = str(val)[:40]
                    tops_formatted.append(f"{val_str}×{cnt}")
            if tops_formatted:
                line += " — top: " + ", ".join(tops_formatted)

        lines.append(line)

    if len(columns) > _STATS_MAX_COLUMNS_INJECTED:
        omitted = len(columns) - _STATS_MAX_COLUMNS_INJECTED
        lines.append(f"  - … ({omitted} colonnes supplémentaires omises)")

    return "\n".join(lines)


async def _format_attachment_stats_into_message(
    message: str,
    attachment_stats: Mapping[str, Any],
    user_id: Optional[int],
) -> str:
    """Injecte les stats agrégées dans le message user, avec
    anonymisation systématique avant retour au LLM (CRIT-3 doctrine
    2026-05-26).

    Args:
        message: message original de l'user (texte libre).
        attachment_stats: payload shape ``IrisStatsAggregator.aggregate``
            transmis via WebSocket (``payload["attachment_stats"]``).
            Doit contenir au moins ``row_count``, ``column_count``,
            ``column_stats``. Tout autre champ est ignoré.
        user_id: id du user authentifié (pour pseudonymizer scope).

    Returns:
        Message enrichi (anonymisé) prêt à passer à ``IrisAgent.run``.
        Format :
            <message original>

            📎 Fichier joint (mode éphémère — stats agrégées) : ...

    Fail-safe :
        - Si ``attachment_stats`` est malformé → retourne le message
          original sans crash.
        - Si l'anonymisation lève → retourne le message original
          (fail-closed : pas de stats brutes leakées au LLM si on ne
          peut pas les anonymiser).
    """
    if not isinstance(attachment_stats, Mapping):
        return message

    filename = attachment_stats.get("filename", "fichier_joint")
    if not isinstance(filename, str):
        filename = "fichier_joint"

    try:
        stats_text = _format_stats_payload_to_text(attachment_stats, filename)
    except Exception:  # noqa: BLE001
        logger.warning("Format stats payload KO", exc_info=True)
        return message

    if not stats_text:
        return message

    # CRIT-3 doctrine — anonymisation systématique avant LLM
    try:
        from app.services.anonymization import anonymize_for_llm

        full_message = f"{message}\n\n{stats_text}"
        anonymized, _restore = await anonymize_for_llm(user_id, full_message, "IRIS_CHAT")
        if isinstance(anonymized, str):
            return anonymized
        return message
    except Exception:  # noqa: BLE001
        # Fail-closed : si on ne peut pas anonymiser, on retourne le
        # message ORIGINAL sans les stats. Plutôt perdre la feature
        # que leaker des stats en clair.
        logger.warning(
            "Anonymisation stats KO — fail-closed (message sans stats)",
            exc_info=True,
        )
        return message


class IrisClearAPIHandler(BaseHandler):
    """POST ``/api/iris/clear`` — supprime physiquement les conversations
    actives de l'user (et leurs messages via cascade ``all, delete-orphan`` +
    FK ``ON DELETE CASCADE`` sur ``conversation_messages.conversation_id``).

    Auparavant : soft-delete via ``is_active=False``. La BDD grossissait
    indéfiniment même quand l'user cliquait "Effacer". Décision 2026-05-15 :
    hard-delete, pour que le clic respecte la promesse implicite "ça dégage".

    Le champ ``Conversation.is_active`` n'est plus muté ici, mais reste en
    place pour compatibilité avec la query liste (cf. ``iris.py:808``). À
    retirer dans une migration ultérieure si plus aucun usage.

    **Scope par ``source`` (2026-05-21)** : le clic « Effacer » côté
    widget ne doit PAS détruire la conv de la page ``/iris`` (et
    inversement). Le body JSON accepte un champ ``source`` :

    - ``"page"`` (défaut) — clear la conv page seulement
    - ``"widget"`` — clear la conv widget seulement

    Toute autre valeur (y compris absente) est traitée comme ``"page"``
    (fail-safe ; cohérent avec le client historique qui n'envoyait rien
    et était toujours la page). Pas de mode ``"all"`` exposé au client :
    un éventuel besoin admin futur passera par un endpoint dédié avec
    contrôle de rôle (cf. adversarial #5 du 2026-05-21).
    """

    @authenticated
    async def post(self) -> None:
        user = self.current_user
        assert user is not None

        # Parse body — best-effort, défaut "page" (cohérent avec le client
        # historique qui n'envoyait rien et était toujours la page).
        body_raw = self.request.body or b""
        body = _safe_json_loads(body_raw.decode("utf-8", errors="replace"))
        raw_source = body.get("source") if isinstance(body, Mapping) else None
        source_filter = _coerce_source(raw_source)

        try:
            async with get_session() as session:
                # DELETE direct : la cascade SQLAlchemy (``cascade=all,
                # delete-orphan`` sur Conversation.messages) + la FK BDD
                # (``ondelete=CASCADE`` sur conversation_messages) virent
                # les messages associés sans qu'on les liste explicitement.
                # Scope par source obligatoire — un user qui clique « Effacer »
                # côté widget ne doit JAMAIS détruire la conv de la page.
                await session.execute(
                    delete(Conversation).where(
                        Conversation.user_id == user.id,
                        Conversation.is_active.is_(True),
                        Conversation.source == source_filter,
                    )
                )
                await session.commit()
            logger.info(
                "Conversations supprimées (hard): user_id=%d source=%s",
                user.id,
                source_filter,
            )
            self.write_json({"success": True})
        except SQLAlchemyError as exc:
            logger.error("Erreur effacement conversations: %s", exc, exc_info=True)
            self.write_json(
                {"success": False, "error": _Messages.CLEAR_FAILED},
                status=500,
            )


# ──────────────────────────────────────────────────────────────────────
# Rehydratation overlay widget — 2026-05-26
# ──────────────────────────────────────────────────────────────────────


class IrisWidgetConversationAPIHandler(BaseHandler):
    """``GET /api/iris/widget/conversation`` — rehydrate la conv widget
    de l'utilisateur authentifié (chat overlay flottant).

    Pendant côté API du ``_rehydrate_conversation`` que :class:`IrisPageHandler`
    exécute en SSR pour la page ``/iris``. Le widget n'a pas de SSR — il
    appelle cet endpoint au boot (ou à la première ouverture du panel)
    pour récupérer l'historique persisté en BDD.

    **Sans cet endpoint** (état avant 2026-05-26), le widget réinitialisait
    son ``conversationId`` à ``null`` au refresh et perdait tout l'historique
    affiché. Les conversations étaient bien en BDD (le backend persistait
    chaque tour via ``ConversationEvent`` + ``ConversationMessage`` au sein
    de ``_save_turn``), mais le frontend n'avait aucun mécanisme pour les
    relire. Le SSOT de création (``get_or_create_active_conversation``) faisait
    déjà SELECT-first, donc envoyer ``conversation_id: null`` après refresh
    ne créait PAS de doublon — il continuait silencieusement la même conv,
    mais sans afficher les messages antérieurs.

    Scope strict :

    * ``user_id == current_user.id`` (auth requise + ownership implicite).
    * ``source == "widget"`` (jamais une conv ``page`` même si elle existe ;
      cf. enum :class:`ConversationSource` et bug 2026-05-21).
    * ``agent_role == "iris"`` (cohérent avec SSOT + rehydrate page).

    Réponse JSON ::

        {
            "conversation_id": 99 | null,
            "messages": [
                {"role": "user", "content": "..."},
                {"role": "assistant", "content": "...", ...},
                {"role": "tool", "tool_name": "execute_sql", "sql_data": {...}, ...},
                ...
            ]
        }

    Les ``messages`` passent par :func:`_render_conversation_messages` :
    P0 (#124) scrub data_access denied + tool icons + sql_data inline.

    Cache : ``no-store, private`` + ``Vary: Cookie`` (anti-bfcache, anti-CDN ;
    même pattern qu':class:`IrisPageHandler.get`).
    """

    @authenticated
    async def get(self) -> None:
        user = self.current_user
        if user is None:
            # Defense-in-depth : ``@authenticated`` garantit déjà non-None
            # mais ``python -O`` strip les ``assert``. On retourne 401
            # propre au lieu d'un 500 sur AttributeError.
            self.write_json({"success": False, "error": "Non authentifié."}, status=401)
            return

        # Anti-bfcache + anti-CDN : même doctrine que IrisPageHandler.get.
        # Sans ces headers, le retour-arrière du navigateur restaure le
        # JSON figé d'une session précédente (potentiellement d'un autre
        # user sur poste partagé), et le widget hydrate avec des messages
        # qui ne lui appartiennent pas.
        self.set_header("Cache-Control", "no-store, no-cache, must-revalidate, private")
        self.set_header("Pragma", "no-cache")
        self.set_header("Vary", "Cookie")

        conv_id, _last_input_tokens, _raw_messages, rendered = await _load_active_conversation(
            user, ConversationSource.WIDGET.value
        )
        # ``_load_active_conversation`` est déjà fail-safe (renvoie
        # ``(None, None, [], [])`` sur erreur SQL). Le widget recevra
        # ``{conversation_id: null, messages: []}`` et affichera son
        # welcome — exactement comme un premier usage du widget.
        self.write_json(
            {
                "success": True,
                "conversation_id": conv_id,
                "messages": rendered,
            }
        )


# ──────────────────────────────────────────────────────────────────────
# Mémoire Iris user-scoped — 2026-05-22 (parité ``copilot_memory``)
# ──────────────────────────────────────────────────────────────────────


class IrisUserMemoryAPIHandler(BaseHandler):
    """CRUD ``/api/iris/user-memory`` — gestion de ``User.iris_memory``.

    Mémoire fixe consolidée par utilisateur, injectée dans le system prompt
    de toutes les conversations Iris de ce user. Cf.
    ``app/services/ai/iris_user_memory.py``.

    * ``GET``    : retourne le contenu actuel + métadonnées (longueur, cap).
    * ``PUT``    : remplace le contenu (sanitize + cap appliqués côté serveur).
    * ``DELETE`` : reset à ``NULL`` (l'user choisit de tout oublier).

    Scope strict ``current_user`` — pas de path param ``user_id`` exposé
    (defense-in-depth contre la confusion de scope). Un admin qui veut
    inspecter la mémoire d'un autre user passera par un endpoint
    ``/api/admin/...`` dédié à créer plus tard (pas dans ce ticket).
    """

    # F7 review adversariale 2026-05-22 — Les ``assert user is not None``
    # initiaux sont strippés en ``python -O``. On utilise une garde
    # explicite qui retourne 401 propre au lieu de crasher en 500.
    def _require_user(self):
        user = self.current_user
        if user is None:
            self.write_json(
                {"success": False, "error": "Non authentifié."},
                status=401,
            )
            return None
        return user

    @authenticated
    async def get(self) -> None:
        user = self._require_user()
        if user is None:
            return
        try:
            from app.services.ai.iris_user_memory import IRIS_USER_MEMORY_MAX_CHARS

            # F6 review adversariale 2026-05-22 — on retourne le contenu
            # BRUT stocké en BDD (pas la version sanitizée à la volée).
            # Le sanitize est déjà appliqué à TOUTES les écritures (PUT
            # endpoint + fusion fin-de-run + helper _save_user_iris_memory),
            # donc ce qui est en BDD est déjà safe. Le ré-appliquer en
            # lecture créait un GET→affiche-version-tronquée→user-sauve-
            # tronqué → écrasement silencieux du raw original.
            # Defense in depth : on relit fresh depuis la BDD au cas où la
            # mémoire ait été modifiée par une fusion fin-de-run récente
            # (cohérent avec F3 côté agent_service).
            async with get_session() as session:
                stmt = select(User.iris_memory).where(User.id == user.id)
                result = await session.execute(stmt)
                stored = result.scalar_one_or_none() or ""
            self.write_json(
                {
                    "success": True,
                    "memory": stored,
                    "char_count": len(stored),
                    "max_chars": IRIS_USER_MEMORY_MAX_CHARS,
                }
            )
        except SQLAlchemyError as exc:
            logger.error("Lecture user_memory échouée: %s", exc, exc_info=True)
            self.write_json(
                {"success": False, "error": "Lecture de la mémoire impossible."},
                status=500,
            )

    @authenticated
    async def put(self) -> None:
        user = self._require_user()
        if user is None:
            return
        from app.services.ai.iris_user_memory import (
            IRIS_USER_MEMORY_MAX_CHARS,
            sanitize_iris_user_memory,
        )

        # F8 review adversariale 2026-05-22 — Garde DoS sur la taille du
        # body avant tout décodage/sanitize. Tornado a un cap global
        # ``max_body_size``, mais une garde dédiée évite de dépenser CPU
        # sur UTF-8 + JSON parse + NFKC normalize pour un payload qu'on
        # va tronquer à 2000 chars de toute façon. Facteur 4 = marge UTF-8
        # multi-byte + JSON wrapping.
        raw_body = self.request.body or b""
        if len(raw_body) > IRIS_USER_MEMORY_MAX_CHARS * 4:
            self.write_json(
                {
                    "success": False,
                    "error": f"Payload trop volumineux (max ~{IRIS_USER_MEMORY_MAX_CHARS} caractères).",
                },
                status=413,
            )
            return

        body = _safe_json_loads(raw_body.decode("utf-8", errors="replace") if raw_body else "")
        if not isinstance(body, Mapping):
            self.write_json(
                {"success": False, "error": "JSON body invalide."},
                status=400,
            )
            return
        raw_memory = body.get("memory")
        if raw_memory is not None and not isinstance(raw_memory, str):
            self.write_json(
                {"success": False, "error": "Le champ 'memory' doit être une chaîne."},
                status=400,
            )
            return
        try:
            cleaned = sanitize_iris_user_memory(raw_memory)
            # Une mémoire vide après sanitize équivaut à un reset → on
            # accepte (alignement DELETE comportement).
            async with get_session() as session:
                stmt = select(User).where(User.id == user.id)
                result = await session.execute(stmt)
                u_row = result.scalar_one_or_none()
                if u_row is None:
                    self.write_json(
                        {"success": False, "error": "Utilisateur introuvable."},
                        status=404,
                    )
                    return
                u_row.iris_memory = cleaned or None
                await session.commit()
            self.write_json(
                {
                    "success": True,
                    "memory": cleaned,
                    "char_count": len(cleaned),
                    "max_chars": IRIS_USER_MEMORY_MAX_CHARS,
                }
            )
        except SQLAlchemyError as exc:
            logger.error("Écriture user_memory échouée: %s", exc, exc_info=True)
            self.write_json(
                {"success": False, "error": "Sauvegarde impossible."},
                status=500,
            )

    @authenticated
    async def delete(self) -> None:
        user = self._require_user()
        if user is None:
            return
        try:
            async with get_session() as session:
                stmt = select(User).where(User.id == user.id)
                result = await session.execute(stmt)
                u_row = result.scalar_one_or_none()
                if u_row is None:
                    self.write_json(
                        {"success": False, "error": "Utilisateur introuvable."},
                        status=404,
                    )
                    return
                u_row.iris_memory = None
                await session.commit()
            logger.info("user_memory reset par user=%d", user.id)
            self.write_json({"success": True, "memory": "", "char_count": 0})
        except SQLAlchemyError as exc:
            logger.error("Reset user_memory échoué: %s", exc, exc_info=True)
            self.write_json(
                {"success": False, "error": "Réinitialisation impossible."},
                status=500,
            )


class IrisFeedbackAPIHandler(BaseHandler):
    """POST ``/api/iris/feedback`` — enregistre un feedback sur le dernier
    message assistant d'une conversation."""

    @authenticated
    async def post(self) -> None:
        body = _safe_json_loads(self.request.body.decode("utf-8", errors="replace"))
        if not isinstance(body, Mapping):
            self.write_json(
                {"success": False, "error": _Messages.FEEDBACK_JSON_INVALID},
                status=400,
            )
            return

        feedback = body.get("feedback")
        conversation_id = _coerce_optional_int(body.get("conversation_id"))
        if conversation_id is None or feedback not in _ALLOWED_FEEDBACKS:
            self.write_json(
                {"success": False, "error": _Messages.FEEDBACK_INVALID},
                status=400,
            )
            return

        user = self.current_user
        assert user is not None

        try:
            last_msg = await self._store_feedback(
                conversation_id=conversation_id,
                feedback=str(feedback),
                user_id=user.id,
            )
        except SQLAlchemyError as exc:
            logger.error("Erreur feedback: %s", exc, exc_info=True)
            self.write_json(
                {"success": False, "error": _Messages.FEEDBACK_FAILED},
                status=500,
            )
            return

        if last_msg is None:
            # Résultat déjà écrit par _store_feedback via l'appelant ;
            # ici on distingue les cas ``None`` = conversation / assistant absent.
            return

        logger.info(
            "Feedback enregistré: conversation_id=%d, feedback=%s, user_id=%d",
            conversation_id,
            feedback,
            user.id,
        )
        # Apprentissage continu — ne jamais bloquer la réponse si ça casse.
        try:
            knowledge = get_agent_knowledge()
            # is_admin → modération : un 👍 d'admin auto-approuve la paire Q/SQL,
            # un 👍 de non-admin part en attente d'approbation (axe 14 + promesse
            # onboarding /admin/ai-training). ``user`` est garanti non-None ici.
            await knowledge.learn_from_conversation_feedback(
                conversation_id, str(feedback), is_admin=user.is_admin
            )
        except Exception as learn_exc:  # noqa: BLE001 — best-effort enrichment
            logger.warning("Learning from feedback failed: %s", learn_exc)

        self.write_json({"success": True})

    async def _store_feedback(
        self,
        *,
        conversation_id: int,
        feedback: str,
        user_id: int,
    ) -> Optional[ConversationMessage]:
        """Met à jour le feedback du dernier message assistant. Écrit la réponse
        d'erreur directement sur le handler si conversation / message introuvable ;
        retourne le message persisté sinon.
        """
        async with get_session() as session:
            # Defense-in-depth : ownership + is_active + agent_role. Sans le
            # filtre ``is_active``, un user peut feedback un message d'une
            # conv archivée (typiquement plus accessible en UI). Sans le
            # filtre ``agent_role``, un crafted POST avec l'``id`` d'une
            # conv copilot/autre agent pourrait écrire un feedback Iris sur
            # le mauvais agent → biais qualité dans les agrégats.
            conv = await session.execute(
                select(Conversation).where(
                    Conversation.id == conversation_id,
                    Conversation.user_id == user_id,
                    Conversation.is_active.is_(True),
                    Conversation.agent_role == AgentRole.IRIS.value,
                )
            )
            if conv.scalar_one_or_none() is None:
                self.write_json(
                    {"success": False, "error": _Messages.CONVERSATION_NOT_FOUND},
                    status=404,
                )
                return None

            result = await session.execute(
                select(ConversationMessage)
                .where(
                    ConversationMessage.conversation_id == conversation_id,
                    ConversationMessage.role == MessageRole.ASSISTANT,
                )
                .order_by(desc(ConversationMessage.created_at))
                .limit(1)
            )
            msg = result.scalar_one_or_none()
            if msg is None:
                self.write_json(
                    {"success": False, "error": _Messages.NO_ASSISTANT_MESSAGE},
                    status=404,
                )
                return None

            msg.feedback = feedback
            await session.commit()
            return msg


class IrisWelcomeSuggestionsAPIHandler(BaseHandler):
    """GET ``/api/iris/welcome-suggestions`` — suggestions d'accueil
    dynamiques pour l'utilisateur courant.

    **SSOT** : réutilise ``get_sync_service().generate_welcome_suggestions(user_id)``
    — exactement le même service utilisé par ``IrisPageHandler`` au render
    template (cf. ``_fetch_welcome_suggestions``). Pas de duplication, pas
    de hardcoded : les suggestions viennent du cache LLM peuplé par le sync.

    Permet au floating widget (chargé sur toutes les pages sauf ``/iris``)
    d'afficher les mêmes suggestions personnalisées que la page complète
    sans dupliquer le service ni hardcoder une liste statique côté JS.

    Retour : ``{"suggestions": [{"label": "...", "prompt": "..."}, ...]}``.
    Liste vide si pas de cache (premier boot, sync pas encore tourné) —
    fail-safe : le widget masque simplement la section chips.
    """

    # Caps anti-prompt-injection / anti-layout-cassé. Si le cache LLM est
    # un jour compromis (LLM hijack ou édition BDD), un ``label`` ou
    # ``prompt`` excessivement long arrive borné côté front (adversarial #3
    # fix P1).
    _MAX_LABEL_CHARS: Final[int] = 80
    _MAX_PROMPT_CHARS: Final[int] = 500
    _MAX_SUGGESTIONS: Final[int] = 4

    @authenticated
    async def get(self) -> None:
        user = self.current_user
        assert user is not None
        try:
            sync_svc = get_sync_service()
            raw = await sync_svc.generate_welcome_suggestions(user_id=user.id)
        except (RuntimeError, SQLAlchemyError) as exc:
            logger.debug("welcome_suggestions API: fail-safe vide (%s)", exc)
            raw = []
        # Sanitization : cap nombre + cap chars + strip control chars +
        # filtre les entrées invalides. Defense-in-depth contre un cache
        # LLM compromis (adversarial #3).
        sanitized: list[dict[str, str]] = []
        for item in (raw or [])[: self._MAX_SUGGESTIONS]:
            if not isinstance(item, Mapping):
                continue
            label = item.get("label") or ""
            prompt = item.get("prompt") or label
            if not isinstance(label, str) or not isinstance(prompt, str):
                continue
            label = label.strip()[: self._MAX_LABEL_CHARS]
            prompt = prompt.strip()[: self._MAX_PROMPT_CHARS]
            if not label:
                continue
            sanitized.append({"label": label, "prompt": prompt})
        # A5-F5 : ``no-store`` (cohérent avec la doctrine page authentifiée
        # par-user, cf. A1-F4) — les suggestions peuvent être personnalisées et
        # un ``max-age=300`` privé laissait un résidu cross-session sur poste
        # partagé (l'user suivant voyait 5 min les suggestions du précédent). Le
        # middleware pose déjà no-store sur /api/* ; on ne le ré-écrase plus.
        self.set_header("Cache-Control", "no-store")
        self.write_json({"suggestions": sanitized})


class IrisUsageStatsAPIHandler(BaseHandler):
    """GET ``/api/admin/iris-usage-stats`` — instrumentation de l'usage
    relatif du floating widget Iris vs la page ``/iris`` complète.

    **Pourquoi** (task #17) : avant d'investir des jours sur les P1/P2
    widget (sanitize + a11y + persistence conv + suggestions contextuelles
    + extract iris-common.js + ...), on veut savoir si l'usage justifie
    cet investissement. Si <5 % des messages Iris viennent du widget,
    on peut envisager de le supprimer (vue contrarian de la review
    brainstorm initiale — cf. task #16).

    **Méthode** : agrégat SQL sur la colonne ``Conversation.source``
    (ajoutée par fix #22 du 2026-05-21, valeurs `'page'`/`'widget'`).
    Pas de nouvelle colonne ni de nouveau tracking — on réutilise la
    discrimination déjà en place.

    **Paramètres query** :
    - ``days`` (int, défaut 7, max 90) — fenêtre temporelle remontée
      depuis maintenant. Au-delà de 90 jours la requête devient lente
      (table grandit sans rotation).

    **Réponse JSON** :
    ```
    {
      "period_days": 7,
      "since": "2026-05-14T...",
      "total_conversations": N,
      "by_source": {
        "page":   {"conversations": N_p, "messages": M_p, "users": U_p},
        "widget": {"conversations": N_w, "messages": M_w, "users": U_w}
      },
      "widget_share_messages": 0.12,   // 0..1
      "widget_share_conversations": 0.08,
      "decision_hint": "below_5pct" | "5_to_20pct" | "above_20pct"
    }
    ```

    Le ``decision_hint`` est aligné sur les seuils définis dans la
    description de task #16 — il oriente la décision garder/supprimer
    sans la prendre à la place de l'admin.

    Endpoint **admin-only** (les chiffres révèlent l'activité Iris
    agrégée — pas sensibles techniquement, mais pas d'intérêt user).
    """

    _MAX_DAYS = 90

    @admin_required
    async def get(self) -> None:
        from datetime import timedelta

        from sqlalchemy import func as sa_func
        from sqlalchemy import select as sa_select

        from app.services.ai.agent_roles import AgentRole

        raw_days = self.get_argument("days", "7")
        try:
            days = max(1, min(self._MAX_DAYS, int(raw_days)))
        except (TypeError, ValueError):
            days = 7

        # ``Conversation.created_at`` est ``DateTime`` SANS timezone, rempli
        # par ``func.now()`` côté DB (cf. ``app/models/base.py:42``). Pour
        # comparer correctement, on construit une borne NAIVE en UTC : aware
        # vs naive donne soit ``TypeError`` (SQL Server), soit du drift
        # silencieux (SQLite en heure locale) selon le driver. Aligné sur
        # le storage existant — adversarial #1 BLOCKING fix #17.
        since = (clock.now() - timedelta(days=days)).replace(tzinfo=None)

        # Agrégats par source — 1 query GROUP BY + 1 query pour le total
        # ``unique_users`` global. On joint ``ConversationMessage`` pour
        # compter les messages de manière AUTORITATIVE (cf. adversarial #5
        # BLOCKING fix #17 : le dénormalisé ``Conversation.message_count``
        # peut diverger si un incrémenteur foire ou en cas de hard-delete
        # de messages sans update). Coût : LEFT JOIN + GROUP BY indexable.
        by_source: dict[str, dict[str, int]] = {
            ConversationSource.PAGE.value: {
                "conversations": 0,
                "messages": 0,
                "users_in_source": 0,
            },
            ConversationSource.WIDGET.value: {
                "conversations": 0,
                "messages": 0,
                "users_in_source": 0,
            },
        }
        try:
            async with get_session() as session:
                stmt = (
                    sa_select(
                        Conversation.source,
                        sa_func.count(sa_func.distinct(Conversation.id)).label("conv_count"),
                        sa_func.count(ConversationMessage.id).label("msg_count"),
                        sa_func.count(sa_func.distinct(Conversation.user_id)).label("user_count"),
                    )
                    .outerjoin(
                        ConversationMessage,
                        ConversationMessage.conversation_id == Conversation.id,
                    )
                    .where(Conversation.created_at >= since)
                    .where(Conversation.agent_role == AgentRole.IRIS.value)
                    .group_by(Conversation.source)
                )
                result = await session.execute(stmt)
                for row in result.all():
                    src = str(row.source or ConversationSource.PAGE.value)
                    if src in by_source:
                        by_source[src] = {
                            "conversations": int(row.conv_count or 0),
                            "messages": int(row.msg_count or 0),
                            "users_in_source": int(row.user_count or 0),
                        }
                # ``unique_users_global`` : un user qui a 1 conv page + 1 conv
                # widget compte 1, pas 2 (contrairement à ``users_in_source``).
                # Réponse à l'adversarial #6 BLOCKING fix #17 : sans ce chiffre,
                # l'admin ne peut pas répondre à « combien de users distincts
                # touchent Iris ? » sans risquer un double-comptage.
                unique_users_stmt = (
                    sa_select(sa_func.count(sa_func.distinct(Conversation.user_id)))
                    .where(Conversation.created_at >= since)
                    .where(Conversation.agent_role == AgentRole.IRIS.value)
                )
                unique_users_global = int((await session.execute(unique_users_stmt)).scalar() or 0)
        except SQLAlchemyError as exc:
            logger.error("iris_usage_stats: query failed: %s", exc, exc_info=True)
            self.write_json(
                {"success": False, "error": "Erreur de lecture des statistiques."},
                status=500,
            )
            return

        total_conv = sum(s["conversations"] for s in by_source.values())
        total_msg = sum(s["messages"] for s in by_source.values())
        widget_msg = by_source[ConversationSource.WIDGET.value]["messages"]
        widget_conv = by_source[ConversationSource.WIDGET.value]["conversations"]

        # Ratios — float [0,1]. Évite ZeroDivisionError sur table vide.
        widget_share_messages = (widget_msg / total_msg) if total_msg else 0.0
        widget_share_conversations = (widget_conv / total_conv) if total_conv else 0.0

        # Hint de décision aligné sur les seuils de task #16.
        if widget_share_messages < 0.05:
            decision_hint = "below_5pct"
        elif widget_share_messages < 0.20:
            decision_hint = "5_to_20pct"
        else:
            decision_hint = "above_20pct"

        self.write_json(
            {
                "period_days": days,
                "since": since.isoformat(),
                "total_conversations": total_conv,
                "unique_users_global": unique_users_global,
                "by_source": by_source,
                "widget_share_messages": round(widget_share_messages, 4),
                "widget_share_conversations": round(widget_share_conversations, 4),
                "decision_hint": decision_hint,
            }
        )


class IrisModeUsageStatsHandler(BaseHandler):
    """GET ``/api/admin/iris-mode-usage`` — snapshot des compteurs in-process
    d'usage des modes ``legacy`` vs ``ephemeral`` des uploads Iris.

    Task #43c (cycle #33) — endpoint admin de monitoring pour préparer
    la décision « tirer le rideau sur le mode legacy » (#43d/#43e).

    **État data-driven** : David peut consulter cet endpoint pour voir
    le ratio d'usage du mode éphémère. Quand ce ratio approche 100%
    (et stabilise), on peut activer le soft-disable (#43d) puis
    supprimer le code legacy (#43e) en toute sécurité.

    **Caractère in-process** : les compteurs sont remis à 0 à chaque
    reboot. Acceptable pour le monitoring de transition (observable
    sur plusieurs heures/jours). Pas d'audit RGPD ni de retention.

    **Réponse JSON** :
    ```
    {
      "counters": {"legacy": N, "ephemeral": M, "both": K},
      "total": N + M + K,
      "ephemeral_ratio": M / (N+M+K),   // 0..1, null si total=0
      "uptime_seconds": <float ou null si jamais incrémenté>,
      "decision_hint": "all_legacy" | "transitioning" | "mostly_ephemeral"
                       | "all_ephemeral" | "no_data"
    }
    ```

    Le ``decision_hint`` oriente la décision sans la prendre :
    - ``all_legacy`` : ratio == 0 → ne pas désactiver le legacy
    - ``transitioning`` : 0 < ratio < 0.95 → encore des users legacy
    - ``mostly_ephemeral`` : 0.95 ≤ ratio < 1 → quelques outliers
    - ``all_ephemeral`` : ratio == 1 → safe à désactiver
    - ``no_data`` : aucun upload depuis le boot → attendre
    """

    @admin_required
    async def get(self) -> None:
        from app.services.ai.iris_mode_stats import get_snapshot

        snap = get_snapshot()
        ratio = snap.get("ephemeral_ratio")
        total = snap.get("total", 0)

        if total == 0:
            hint = "no_data"
        elif ratio is None:
            hint = "no_data"
        elif ratio == 0:
            hint = "all_legacy"
        elif ratio < 0.95:
            hint = "transitioning"
        elif ratio < 1:
            hint = "mostly_ephemeral"
        else:
            hint = "all_ephemeral"

        out = dict(snap)
        out["decision_hint"] = hint
        self.write_json(out)


class IrisParseAttachmentHandler(BaseHandler):
    """POST ``/api/iris/parse-attachment`` — parse un fichier uploadé via
    pandas et retourne ``tabs/columns/rows`` pour affichage en grille
    ``iris-sql-card`` inline (Task #34 / #8 Phase 2).

    Alternative à SheetJS côté navigateur (~500 KB binaire). On réutilise
    l'infra pandas déjà chargée côté backend pour parser les CSV (avec
    fallback multi-encoding utf-8/cp1252/latin-1) et les Excel
    multi-feuilles natifs.

    Format de retour :

    .. code-block:: json

        {
          "success": true,
          "total_tabs": 3,
          "tabs": [
            {"name": "Feuille1", "columns": ["A", "B"], "rows": [["1","2"]],
             "row_count": 1, "truncated_rows": false, "truncated_cols": false},
            ...
          ]
        }

    Limites visuelles (anti-saturation client) :
    - ``_MAX_ROWS_PER_TAB`` lignes max par onglet
    - ``_MAX_COLS_PER_TAB`` colonnes max par onglet
    Flags ``truncated_rows`` / ``truncated_cols`` indiquent si on a coupé
    pour que l'UI puisse afficher un message « Aperçu — onglet plus grand ».
    """

    #: Limites de payload — au-delà le navigateur lagge sur le rendu
    #: et le payload JSON dépasse 1-2 Mo. 1000 lignes × 50 colonnes
    #: couvre 95% des fichiers comptables typiques.
    _MAX_ROWS_PER_TAB: Final[int] = 1000
    _MAX_COLS_PER_TAB: Final[int] = 50

    @authenticated
    async def post(self) -> None:
        """Parse un fichier uploadé pour affichage en grille côté frontend.

        Sécurité (CRIT-4 adversarial fix 2026-05-26) :

        - Le ``file_id`` est validé UUID strict (anti path traversal)
        - Le scope user est *exclusivement* ``self.current_user.id`` —
          ne JAMAIS lire ``user_id`` depuis le body / query string /
          header. Cette règle est exprimée par un check fail-closed
          explicite (``user is None or user.id is None → 401``) en plus
          de ``@authenticated``. Avant : un simple ``assert user is not
          None`` désactivable via ``python -O``. Si demain quelqu'un
          ajoute un query param ``?user_id=`` pour debug admin, le
          fail-closed le bloque par défaut.
        - Defense in depth : re-vérification ``_is_within_dir`` après
          resolution du path (anti symlink escape).
        """
        # Task #43d (cycle #33) — soft disable mode legacy via env var
        if _legacy_upload_disabled():
            self.write_json(
                {"success": False, "error": _LEGACY_DISABLED_MESSAGE},
                status=410,
            )
            return
        body = _safe_json_loads(self.request.body.decode("utf-8", errors="replace"))
        if not isinstance(body, Mapping):
            self.write_json({"success": False, "error": "Body JSON invalide"}, status=400)
            return

        file_id = body.get("file_id")
        # Validation UUID stricte — anti path traversal via file_id
        if not isinstance(file_id, str) or not re.match(r"^[0-9a-f-]{36}$", file_id):
            self.write_json({"success": False, "error": "file_id invalide"}, status=400)
            return

        user = self.current_user
        # Fail-closed explicite — ne pas se reposer sur assert
        # (désactivable via python -O). CRIT-4 adversarial fix 2026-05-26.
        user_id = getattr(user, "id", None) if user is not None else None
        if user_id is None:
            logger.warning("parse-attachment refusé : current_user ou user.id manquant")
            self.write_json({"success": False, "error": "Authentication requise"}, status=401)
            return
        user_dir = _UPLOAD_DIR / str(user_id)

        # Cherche le fichier (extension peut varier : csv, xlsx, xls, json, txt)
        target: Optional[Path] = None
        if user_dir.is_dir():
            for entry in user_dir.iterdir():
                if entry.is_file() and entry.name.startswith(file_id + "."):
                    target = entry
                    break
        if target is None:
            self.write_json({"success": False, "error": "Fichier introuvable"}, status=404)
            return

        # Defense in depth — re-vérifier path traversal après resolution
        if not _is_within_dir(target, _UPLOAD_DIR):
            logger.error(
                "Path traversal attempt parse-attachment user_id=%d file_id=%s",
                user_id,
                file_id,
            )
            self.write_json({"success": False, "error": _Messages.PATH_INVALID}, status=400)
            return

        ext = target.suffix.lower().lstrip(".")
        try:
            tabs = await self._parse_file_to_tabs(target, ext)
        except Exception as exc:
            logger.warning(
                "parse-attachment échec file_id=%s ext=%s: %s",
                file_id,
                ext,
                exc,
                exc_info=True,
            )
            self.write_json(
                {"success": False, "error": f"Parsing échoué : {exc}"},
                status=400,
            )
            return

        if not tabs:
            self.write_json(
                {"success": False, "error": "Aucun onglet analysable dans le fichier"},
                status=400,
            )
            return

        self.write_json(
            {
                "success": True,
                "tabs": tabs,
                "total_tabs": len(tabs),
            }
        )

    async def _parse_file_to_tabs(self, path: Path, ext: str) -> list[dict[str, Any]]:
        """Parse pandas dans un executor pour ne pas bloquer l'event loop
        sur les gros fichiers. Pandas n'est PAS async-friendly nativement."""
        import asyncio

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._parse_sync, path, ext)

    def _parse_sync(self, path: Path, ext: str) -> list[dict[str, Any]]:
        import io  # noqa: F401 — peut servir pour bytes IO

        try:
            import pandas as pd  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "pandas n'est pas installé — impossible de parser le fichier."
            ) from exc

        if ext in ("csv", "txt"):
            # Multi-encoding fallback (réutilise le pattern de
            # _build_tabs_context_from_upload dans agent_tools.py)
            df = None
            last_err: Optional[Exception] = None
            for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
                try:
                    df = pd.read_csv(path, encoding=encoding)
                    break
                except UnicodeDecodeError as e:
                    last_err = e
                    continue
            if df is None:
                raise RuntimeError(
                    f"CSV illisible (encodings testés : utf-8, utf-8-sig, "
                    f"cp1252, latin-1). Dernier détail : {last_err}"
                )
            return [self._df_to_tab(path.stem, df)]

        if ext in ("xlsx", "xls"):
            sheets = pd.read_excel(path, sheet_name=None)
            result = []
            for name, df in sheets.items():
                if df is not None:
                    result.append(self._df_to_tab(str(name), df))
            return result

        if ext == "json":
            try:
                df = pd.read_json(path)
                return [self._df_to_tab(path.stem, df)]
            except Exception as exc:
                raise RuntimeError(
                    "JSON non parseable comme tableau (pas un array d'objets "
                    "ou autre format pandas-compatible)."
                ) from exc

        raise RuntimeError(f"Format non supporté pour parsing en grille : .{ext}")

    def _df_to_tab(self, name: str, df: Any) -> dict[str, Any]:
        """Convertit un DataFrame pandas en dict ``{name, columns, rows, ...}``
        avec limites anti-saturation client. Gère NaN/None proprement
        (None Python pour les valeurs manquantes, sinon str pour les
        objets non-JSON-serializable nativement)."""
        max_r = self._MAX_ROWS_PER_TAB
        max_c = self._MAX_COLS_PER_TAB
        total_rows = int(len(df))
        total_cols = int(len(df.columns))
        truncated_rows = total_rows > max_r
        truncated_cols = total_cols > max_c
        view = df.iloc[:max_r, :max_c]
        columns = [str(c) for c in view.columns]
        rows: list[list[Any]] = []
        for _, row in view.iterrows():
            row_cells: list[Any] = []
            for v in row.tolist():
                if v is None:
                    row_cells.append(None)
                # NaN test pour les floats pandas (NaN != NaN)
                elif isinstance(v, float) and v != v:
                    row_cells.append(None)
                elif isinstance(v, (int, float, bool)):
                    row_cells.append(v)
                else:
                    # Datetime / Timestamp / autres → str
                    row_cells.append(str(v))
            rows.append(row_cells)
        return {
            "name": str(name),
            "columns": columns,
            "rows": rows,
            "row_count": total_rows,
            "truncated_rows": truncated_rows,
            "truncated_cols": truncated_cols,
        }


class IrisUploadCancelHandler(BaseHandler):
    """POST ``/api/iris/upload/cancel`` — supprime un fichier uploadé que
    l'utilisateur a retiré via la croix avant d'envoyer son message.

    MED-8 adversarial fix 2026-05-26 — sans ce endpoint, un fichier
    abandonné restait sur disque jusqu'au TTL 30j (Task #40). Pour un
    user qui hésite sur plusieurs fichiers c'est plusieurs Mo gâchés.

    Sécurité :
    - ``@authenticated`` requis
    - Validation UUID stricte sur le ``file_id`` (anti path traversal)
    - Scoping fail-closed via ``self.current_user.id`` (jamais input
      externe — cf. CRIT-4 doctrine)
    - Defense-in-depth ``_is_within_dir`` après resolution
    - Best-effort : 200 même si fichier déjà absent (idempotent)
    """

    @authenticated
    async def post(self) -> None:
        # Task #43d (cycle #33) — soft disable mode legacy via env var
        if _legacy_upload_disabled():
            self.write_json(
                {"success": False, "error": _LEGACY_DISABLED_MESSAGE},
                status=410,
            )
            return
        body = _safe_json_loads(self.request.body.decode("utf-8", errors="replace"))
        if not isinstance(body, Mapping):
            self.write_json({"success": False, "error": "Body JSON invalide"}, status=400)
            return

        file_id = body.get("file_id")
        if not isinstance(file_id, str) or not re.match(r"^[0-9a-f-]{36}$", file_id):
            self.write_json({"success": False, "error": "file_id invalide"}, status=400)
            return

        user = self.current_user
        user_id = getattr(user, "id", None) if user is not None else None
        if user_id is None:
            self.write_json({"success": False, "error": "Authentication requise"}, status=401)
            return

        user_dir = _UPLOAD_DIR / str(user_id)
        if not user_dir.is_dir():
            # Idempotent — file_id déjà nettoyé ou n'a jamais existé
            self.write_json({"success": True, "removed": 0})
            return

        removed = 0
        for entry in user_dir.iterdir():
            if not entry.is_file():
                continue
            if not entry.name.startswith(file_id + "."):
                continue
            if not _is_within_dir(entry, _UPLOAD_DIR):
                logger.error(
                    "Path traversal upload/cancel user_id=%d file_id=%s",
                    user_id,
                    file_id,
                )
                self.write_json(
                    {"success": False, "error": _Messages.PATH_INVALID},
                    status=400,
                )
                return
            try:
                entry.unlink()
                removed += 1
            except OSError as exc:
                logger.warning(
                    "upload/cancel échec unlink user_id=%d file_id=%s: %s",
                    user_id,
                    file_id,
                    exc,
                )

        # Retire l'entry du .dedup.json (sinon dédup ferait pointer un
        # futur upload identique vers ce file_id supprimé).
        if removed > 0:
            try:
                with _dedup_locked(user_dir):
                    idx_path = _dedup_index_path(user_dir)
                    if idx_path.is_file():
                        try:
                            with idx_path.open("r", encoding="utf-8") as f:
                                data = json.load(f)
                            if isinstance(data, dict):
                                new_data = {
                                    sha: entry
                                    for sha, entry in data.items()
                                    if not (
                                        isinstance(entry, dict) and entry.get("file_id") == file_id
                                    )
                                }
                                if len(new_data) < len(data):
                                    tmp_path = idx_path.with_suffix(".json.tmp")
                                    with tmp_path.open("w", encoding="utf-8") as f:
                                        json.dump(new_data, f)
                                    os.replace(str(tmp_path), str(idx_path))
                        except (OSError, json.JSONDecodeError):
                            pass
            except Exception:  # noqa: BLE001
                logger.warning(
                    "upload/cancel : prune dédup index a échoué (continue) " "user_id=%d",
                    user_id,
                )

        self.write_json({"success": True, "removed": removed})


class IrisUploadHandler(BaseHandler):
    """POST ``/api/iris/upload`` — upload CSV/Excel pour analyse par Iris.

    Valide extension + taille + magic-bytes, écrit dans un dossier per-user
    sous :data:`_UPLOAD_DIR` avec un nom canonique ``{uuid}.{ext}`` — le nom
    d'origine n'est jamais écrit sur le disque.
    """

    @authenticated
    async def post(self) -> None:
        # Task #43d (cycle #33) — soft disable mode legacy via env var
        if _legacy_upload_disabled():
            self.write_json(
                {"success": False, "error": _LEGACY_DISABLED_MESSAGE},
                status=410,  # HTTP 410 Gone — la ressource n'est plus disponible
            )
            return
        if "file" not in self.request.files:
            self.write_json({"success": False, "error": _Messages.NO_FILE}, status=400)
            return

        file_info = self.request.files["file"][0]
        filename = file_info.get("filename", "") or ""
        body = file_info.get("body", b"") or b""

        # Taille max = SSoT admin (/admin/performance), résolue au runtime.
        from app.services.ai.config_service import get_max_upload_size_bytes

        max_upload = await get_max_upload_size_bytes()
        validation = _upload_validator.validate(filename, body, max_size=max_upload)
        if validation is not None:
            error_message, _ = validation
            self.write_json({"success": False, "error": error_message}, status=400)
            return

        ext_key = os.path.splitext(filename.lower())[1][1:]  # "csv", "xlsx", ...
        user = self.current_user
        assert user is not None

        user_dir = _UPLOAD_DIR / str(user.id)

        # Task #17 — Déduplication par SHA256.
        #
        # Avant ce fix (F10 du brainstorm), chaque upload du MÊME
        # fichier (re-upload PC ou copie datastore→iris du même blob)
        # créait une nouvelle copie disque avec un nouvel UUID. Pour
        # un user qui clique 5 fois « Depuis le datastore » sur la
        # même feuille de paie, on stockait 5 fois ~5 Mo = 25 Mo de
        # gâché.
        #
        # Maintenant : avant d'écrire, on calcule le SHA256 du body
        # et on consulte un index ``.dedup.json`` par user qui mappe
        # ``{sha256: (file_id, ext)}``. Si match ET fichier disque
        # encore présent (résistant aux cleanups manuels), on REUSE
        # le file_id existant — aucune écriture disque, aucun nouveau
        # file_id. Le client reçoit le file_id partagé.
        body_sha256 = hashlib.sha256(body).hexdigest()
        existing_file_id, existing_ext = _dedup_lookup(user_dir, body_sha256)
        if existing_file_id is not None and existing_ext is not None:
            existing_safe_filename = f"{existing_file_id}.{existing_ext}"
            existing_path = user_dir / existing_safe_filename
            # Defense in depth — vérifier que le fichier référencé
            # existe encore (un cleanup manuel ou TTL futur pourrait
            # avoir supprimé le fichier sans nettoyer l'index).
            if existing_path.is_file() and _is_within_dir(existing_path, _UPLOAD_DIR):
                file_type = "csv" if existing_ext == "csv" else existing_ext
                logger.info(
                    "Fichier dédupliqué : file_id=%s réutilisé pour "
                    "filename=%s (sha256=%s, user_id=%d, %d octets économisés)",
                    existing_file_id,
                    _safe_log_filename(filename),
                    body_sha256[:16],
                    user.id,
                    len(body),
                )
                self.write_json(
                    {
                        "success": True,
                        "file_id": existing_file_id,
                        "filename": filename,
                        "size": len(body),
                        "type": file_type,
                        "deduplicated": True,
                    }
                )
                return
            # Sinon : l'index pointe vers un fichier disparu → on
            # créera un nouveau (et l'index sera mis à jour ci-dessous).

        file_id = str(uuid.uuid4())
        safe_filename = f"{file_id}.{ext_key}"
        file_path = user_dir / safe_filename

        if not _is_within_dir(file_path, _UPLOAD_DIR):
            logger.error(
                "Path traversal attempt user_id=%s filename=%s",
                user.id,
                _safe_log_filename(filename),
            )
            self.write_json({"success": False, "error": _Messages.PATH_INVALID}, status=400)
            return

        user_dir.mkdir(parents=True, exist_ok=True)
        try:
            file_path.write_bytes(body)
        except OSError as exc:
            logger.error("Erreur sauvegarde upload user_id=%s: %s", user.id, exc, exc_info=True)
            self.write_json(
                {"success": False, "error": _disk_error_message(exc)},
                status=500,
            )
            return

        # Task #17 — Enregistre le mapping sha256 → file_id dans l'index
        # de dédup. Best-effort : si l'écriture échoue (disque plein,
        # permission denied), on log juste un warning et on continue —
        # le upload est déjà committé sur disque, pas la peine de
        # rollback. L'effet visible : la prochaine fois que l'user
        # uploade le même fichier, il ne sera pas dédupliqué (mais
        # aucune corruption).
        try:
            _dedup_record(user_dir, body_sha256, file_id, ext_key)
        except Exception as dedup_err:
            logger.warning(
                "Échec enregistrement dédup user_id=%d sha256=%s: %s",
                user.id,
                body_sha256[:16],
                dedup_err,
            )

        file_type = "csv" if ext_key == "csv" else ext_key
        logger.info(
            "Fichier uploadé: file_id=%s, filename=%s, size=%d, user_id=%d",
            file_id,
            _safe_log_filename(filename),
            len(body),
            user.id,
        )
        self.write_json(
            {
                "success": True,
                "file_id": file_id,
                "filename": filename,
                "size": len(body),
                "type": file_type,
            }
        )


# ── Task #17 — Index de déduplication par user ──────────────────────


def _dedup_index_path(user_dir: Path) -> Path:
    """Chemin du fichier d'index dédup pour le user (sidecar dans son
    dossier d'uploads). Préfixé par ``.`` pour qu'il n'apparaisse pas
    dans les listings utilisateur s'ils utilisent un autre outil."""
    return user_dir / ".dedup.json"


def _dedup_lock_path(user_dir: Path) -> Path:
    """Chemin du fichier de lock dédup (séparé de ``.dedup.json`` pour
    ne pas tenir le lock pendant le rename atomique)."""
    return user_dir / ".dedup.lock"


@contextmanager
def _dedup_locked(user_dir: Path):
    """Context manager — acquiert un lock exclusif sur le fichier
    ``.dedup.lock`` du user_dir avant la séquence read-modify-write
    de ``.dedup.json``.

    CRIT-2 adversarial fix 2026-05-26 :

    Avant ce fix, ``_dedup_record`` (iris.py) et ``_prune_dedup_index``
    (db_retention.py) lisaient puis écrivaient ``.dedup.json``
    indépendamment, sans lock. Race possible :

    1. Upload concurrent A lit l'index (10 entries) → ajoute entry X → écrit (11 entries)
    2. Cleanup TTL lit l'index ENTRE temps (10 entries) → ne voit pas X → réécrit (9 entries, X perdu)

    Le helper acquiert un lock ``fcntl.flock(LOCK_EX)`` sur
    ``.dedup.lock``. Plateforme : Unix/Mac seulement (Komptia prod
    tourne Linux). Sur Windows : no-op (le lock degrade vers le
    comportement antérieur — risque race mais pas crash).

    Le lock est best-effort — si la création du fichier de lock
    échoue (FS read-only / quota), on log et continue sans lock (le
    risque race est préférable à un cleanup qui crash).
    """
    user_dir.mkdir(parents=True, exist_ok=True)
    lock_path = _dedup_lock_path(user_dir)
    lock_fd = None
    try:
        try:
            lock_fd = open(str(lock_path), "a+")
        except OSError as exc:
            logger.warning(
                "Impossible de créer le fichier de lock dédup (%s) — " "continue sans lock : %s",
                lock_path,
                exc,
            )
            yield
            return
        try:
            import fcntl

            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
        except (ImportError, OSError) as exc:
            # Windows ou flock indisponible — pas de lock mais on
            # continue (régression de comportement antérieur, pas crash)
            logger.debug("fcntl.flock indisponible — continue sans lock : %s", exc)
        yield
    finally:
        if lock_fd is not None:
            try:
                import fcntl

                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass
            try:
                lock_fd.close()
            except OSError:
                pass


def _dedup_lookup(user_dir: Path, sha256_hex: str) -> tuple[str | None, str | None]:
    """Cherche ``sha256_hex`` dans l'index de dédup du user.

    Retourne ``(file_id, ext_key)`` si trouvé, ``(None, None)`` sinon.
    Robuste aux index corrompus / inexistants : si le JSON ne parse
    pas ou si la structure est inattendue, on traite comme « pas trouvé »
    (et le caller créera un nouveau file_id, ce qui RECONSTRUIT l'index
    sain au prochain ``_dedup_record``).
    """
    idx_path = _dedup_index_path(user_dir)
    if not idx_path.is_file():
        return None, None
    try:
        with idx_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    entry = data.get(sha256_hex)
    if not isinstance(entry, dict):
        return None, None
    file_id = entry.get("file_id")
    ext = entry.get("ext")
    if not isinstance(file_id, str) or not isinstance(ext, str):
        return None, None
    # Validation défensive : file_id doit être UUID-like (32 hex + 4
    # tirets = 36 chars total) pour éviter qu'un index corrompu
    # injecte un path traversal via file_id.
    if not re.match(r"^[0-9a-f-]{36}$", file_id):
        return None, None
    # Validation ext : whitelist littérale (cohérent _ALLOWED_EXTENSIONS
    # sans le point initial)
    if ext not in {"csv", "xlsx", "xls", "json", "txt"}:
        return None, None
    return file_id, ext


def _dedup_record(user_dir: Path, sha256_hex: str, file_id: str, ext_key: str) -> None:
    """Ajoute (ou met à jour) l'entrée ``sha256 → (file_id, ext)`` dans
    l'index dédup du user.

    Écriture atomique via ``write-tmp + rename`` pour éviter qu'un crash
    en plein milieu laisse un JSON tronqué.

    CRIT-2 adversarial fix 2026-05-26 — la séquence read-modify-write
    est protégée par ``_dedup_locked`` (lock ``fcntl`` Unix). Avant ce
    fix, ``_prune_dedup_index`` du cleanup TTL pouvait écraser une
    entry ajoutée concurremment (le cleanup avait lu l'index AVANT
    notre add → ré-écriture sans notre entry). Maintenant les deux
    chemins acquièrent le même lock.
    """
    idx_path = _dedup_index_path(user_dir)
    with _dedup_locked(user_dir):
        # Lit le state actuel (ou repart de zéro si corrompu)
        data: dict[str, Any] = {}
        if idx_path.is_file():
            try:
                with idx_path.open("r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    data = loaded
            except (OSError, json.JSONDecodeError):
                data = {}
        data[sha256_hex] = {"file_id": file_id, "ext": ext_key}
        # Écriture atomique : tmp puis rename (rename est atomique sur même FS)
        tmp_path = idx_path.with_suffix(".json.tmp")
        with tmp_path.open("w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(str(tmp_path), str(idx_path))


def _is_within_dir(target: Path, root: Path) -> bool:
    """Vérifie que ``target`` résolu reste sous ``root`` résolu."""
    target_resolved = os.path.realpath(str(target))
    root_resolved = os.path.realpath(str(root))
    return target_resolved.startswith(root_resolved + os.sep) or target_resolved == root_resolved


def _disk_error_message(exc: OSError) -> str:
    """Traduit une ``OSError`` en message FR — pas de détail sensible leaké."""
    if exc.errno == errno.ENOSPC:
        return _Messages.DISK_FULL
    if exc.errno == errno.EACCES:
        return _Messages.DISK_DENIED
    return _Messages.DISK_ERROR
