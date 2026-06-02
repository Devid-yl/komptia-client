"""Service métier de feedback utilisateur (rapports d'erreurs / suggestions).

Responsabilités
---------------
1. Recevoir un payload validé (:class:`FeedbackPayload`) depuis
   :class:`app.handlers.feedback.FeedbackReportHandler`.
2. Construire un email HTML/texte en utilisant la configuration SMTP
   globale (:class:`SMTPGlobalConfig` via :func:`build_smtp_client_from_db`).
3. Envoyer l'email à ``config.support_email`` (ou ne PAS l'envoyer si
   ``force_no_send=True`` — quota global anonyme saturé).
4. **Audit-trail** : écrire le rapport dans
   ``data/logs/feedback_audit_YYYY-MM-DD.jsonl`` (rotation par jour,
   cap 50 MB par fichier, ancien renommé ``.old`` au-delà). Toujours
   persisté pour audit, MÊME si le mail a été envoyé. Renommé
   "audit" (vs ancien "unsent") pour refléter la sémantique réelle.

Robustesse
----------
* Aucune exception SMTP/IO ne remonte au caller — le service retourne
  toujours ``{"sent": bool, "stored": bool}``.
* Lectures ``config.app_name`` / ``config.support_email`` faites à
  CHAQUE appel (pas figées au singleton init) — un changement runtime
  est pris en compte sans reset_feedback_service().
* ``json.dumps`` peut lever : on log + retourne ``stored=False``. Le
  caller (handler) traite alors comme erreur 500 (vs faux SUCCESS).
* Écriture fichier : ``flush()`` + ``os.fsync()`` pour garantir
  durabilité même sur disque saturé (sinon ligne JSONL tronquée =
  fichier non parseable au rejeu).
"""

from __future__ import annotations

import asyncio
import html as html_module
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final, Mapping, Optional

from app.core import clock

logger = logging.getLogger(__name__)


# ── Limites défensives ───────────────────────────────────────────────────

_MAX_MESSAGE_LENGTH: Final[int] = 4000
_MAX_USER_AGENT_LENGTH: Final[int] = 500
_MAX_PAGE_LENGTH: Final[int] = 500
_MAX_CONSOLE_ENTRIES: Final[int] = 100
_MAX_CONSOLE_ENTRY_LENGTH: Final[int] = 2000
_MAX_STACK_TRACE_LENGTH: Final[int] = 8000
_MAX_BROWSER_VERSION_LENGTH: Final[int] = 200

# Payload enrichi 2026-05-19 (V « plus d'infos au support ») — caps anti-DoS.
_MAX_NETWORK_ENTRIES: Final[int] = 50  # cap miroir du buffer côté JS (30) + marge.
_MAX_NETWORK_URL_LENGTH: Final[int] = 500
_MAX_PERFORMANCE_KEYS: Final[int] = 30  # navigation timing + ~10 slow resources.
_MAX_APP_STATE_KEYS: Final[int] = 20
_MAX_APP_STATE_VALUE_LENGTH: Final[int] = 500
_MAX_LOCALSTORAGE_ENTRIES: Final[int] = 30
_MAX_LOCALSTORAGE_VALUE_LENGTH: Final[int] = 500

# Anti-leak credential : tout clé localStorage dont le NOM contient un de ces
# fragments est filtré côté serveur (defense in depth — le frontend filtre
# déjà mais on ne fait pas confiance aveuglément).
_LOCALSTORAGE_SENSITIVE_FRAGMENTS: Final[frozenset[str]] = frozenset(
    {
        "token",
        "xsrf",
        "session",
        "auth",
        "password",
        "secret",
        "cookie",
        "credential",
        "private",
        "jwt",
        "api_key",
        "apikey",
    }
)

# Lecture logs serveur (corrélation par request_id) — caps stricts.
_SERVER_LOGS_MAX_LINES: Final[int] = 100
_SERVER_LOGS_MAX_FILE_BYTES_TO_TAIL: Final[int] = 10 * 1024 * 1024  # 10 MB tail.

#: Préfixe du fichier audit-trail. Suffixe = date YYYY-MM-DD pour
#: rotation quotidienne automatique. Au-delà de _AUDIT_FILE_MAX_BYTES
#: dans la même journée, on renomme en ``.old`` et on rouvre.
_AUDIT_FILENAME_PREFIX: Final[str] = "feedback_audit_"
_AUDIT_FILE_MAX_BYTES: Final[int] = 50 * 1024 * 1024  # 50 MB

_CONTROL_CHARS_REGEX: Final[re.Pattern[str]] = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]")


# ────────────────────────────────────────────────────────────────────────


@dataclass(slots=True)
class FeedbackPayload:
    """Données validées d'un rapport de feedback.

    L'instanciation se fait uniquement par
    :meth:`FeedbackPayload.from_handler_input` qui applique sanitize +
    troncature défensive. ``client_captured_at`` est l'heure ISO de la
    capture côté navigateur (donnée par le client, optionnelle) —
    ``received_at`` est posée côté serveur à la réception.
    """

    message: str
    page: str
    user_agent: str
    browser_version: str
    stack_trace: str
    console_entries: list[str]
    extras: dict[str, Any] = field(default_factory=dict)

    # Payload enrichi 2026-05-19 (« plus d'infos au support »).
    network_requests: list[dict[str, Any]] = field(default_factory=list)
    """Liste des derniers fetches navigateur capturés par le wrapper côté JS.
    Chaque entrée : ``{url, method, status, duration_ms, error}``. URL et
    body NE SONT PAS envoyés (anti-leak PII)."""

    performance_timing: dict[str, Any] = field(default_factory=dict)
    """Snapshot ``performance.getEntriesByType('navigation')[0]`` + slow
    resources > 1s. Valeurs numériques uniquement."""

    app_state: dict[str, Any] = field(default_factory=dict)
    """Snapshot léger : ``url``, ``hash``, ``body_classes``, ``modal_open``,
    ``title``. Pour reproduire le contexte de l'erreur."""

    localstorage_debug: dict[str, str] = field(default_factory=dict)
    """Sélection des clés ``komptia_*`` non sensibles. Le frontend filtre
    déjà ``token|xsrf|session|auth|password|secret|cookie|credential|jwt``,
    on re-filtre côté serveur (defense in depth)."""

    server_logs: list[str] = field(default_factory=list)
    """Lignes de log serveur corrélées au ``request_id`` (lecture
    paresseuse côté service au moment de l'envoi, pas dans le payload
    initial). Peuplé par ``FeedbackService._collect_server_logs``."""

    request_id: str = ""
    client_ip: str = ""
    user_id: Optional[int] = None
    username: Optional[str] = None
    received_at: datetime = field(default_factory=clock.now)
    client_captured_at: Optional[str] = None  # ISO du navigateur, peut être absent

    @classmethod
    def from_handler_input(
        cls,
        *,
        message: str,
        page: Optional[str],
        user_agent: Optional[str],
        browser_version: Optional[str],
        stack_trace: Optional[str],
        console_entries: Optional[list[Any]],
        extras: Optional[Mapping[str, Any]] = None,
        client_captured_at: Optional[str] = None,
        request_id: str = "",
        client_ip: str = "",
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        # Payload enrichi 2026-05-19.
        network_requests: Optional[list[Any]] = None,
        performance_timing: Optional[Mapping[str, Any]] = None,
        app_state: Optional[Mapping[str, Any]] = None,
        localstorage_debug: Optional[Mapping[str, Any]] = None,
    ) -> FeedbackPayload:
        message_clean = _sanitize_text(message, _MAX_MESSAGE_LENGTH)
        if not message_clean:
            raise ValueError("Le message ne peut pas être vide.")

        # C4-F1 : ``page`` arrive en ``pathname + search`` (cf. feedback-reporter.js)
        # → on retire la query (potentiellement confidentielle) avant envoi support.
        page_clean = _sanitize_text(_strip_url_query(page or ""), _MAX_PAGE_LENGTH)
        ua_clean = _sanitize_text(user_agent or "", _MAX_USER_AGENT_LENGTH)
        browser_clean = _sanitize_text(browser_version or "", _MAX_BROWSER_VERSION_LENGTH)
        # C4-F2 (#70) : stack_trace et console_entries sont du TEXTE LIBRE qui
        # peut contenir des URLs avec query confidentielle (ex un message
        # « fetch /api/x?token=… » loggué). ``page`` et ``app_state.url`` étaient
        # déjà strippés (C4-F1) ; ces deux champs ne l'étaient PAS (résidu). On
        # applique la même policy anti-leak URL-par-URL avant l'envoi support.
        stack_clean = _sanitize_text(
            _strip_url_queries_in_text(stack_trace or ""), _MAX_STACK_TRACE_LENGTH
        )

        clean_console: list[str] = []
        for entry in (console_entries or [])[:_MAX_CONSOLE_ENTRIES]:
            if entry is None:
                continue
            clean_console.append(
                _sanitize_text(
                    _strip_url_queries_in_text(str(entry)), _MAX_CONSOLE_ENTRY_LENGTH
                )
            )

        clean_extras: dict[str, Any] = {}
        if extras:
            for key, value in list(extras.items())[:20]:
                if not isinstance(key, str):
                    continue
                clean_key = _sanitize_text(key, 80)
                if not clean_key:
                    continue
                # ADV-C3 : filtrer None explicitement (sinon str(None)="None"
                # créait un faux signalement noyé dans le contenu). Logger
                # un warning pour signaler l'usage anormal côté client.
                if value is None:
                    clean_extras[clean_key] = ""
                    continue
                if not isinstance(value, (str, int, float, bool)):
                    logger.warning(
                        "FeedbackPayload: valeur extras non-primitive coercée str()",
                        extra={"key": clean_key, "type": type(value).__name__},
                    )
                clean_extras[clean_key] = _sanitize_text(str(value), 500)

        # ADV-S16 : captured_at client préféré (heure réelle de l'erreur),
        # fallback sur received_at serveur si absent.
        captured_clean: Optional[str] = None
        if client_captured_at:
            captured_clean = _sanitize_text(str(client_captured_at), 64)

        # Network requests : liste de dicts {url, method, status, duration_ms, error}.
        # Fix #2 (review 2026-05-19) — anti-leak PII via query string :
        # une URL ``/api/users?email=jean@example.org`` contiendrait l'email
        # en clair dans le mail support (Gmail = stockage hors-EU). On strip
        # systématiquement la query string et on remonte juste le COMPTE de
        # paramètres en metadata (le support voit "il y avait 3 params" sans
        # voir leurs valeurs). Defense in depth : le JS strip aussi côté
        # client (au moment du wrap fetch), on re-filtre côté serveur.
        clean_network: list[dict[str, Any]] = []
        for entry in (network_requests or [])[:_MAX_NETWORK_ENTRIES]:
            if not isinstance(entry, dict):
                continue
            raw_url = str(entry.get("url", ""))
            base_url, _sep, query = raw_url.partition("?")
            query_param_count = len([p for p in query.split("&") if p]) if query else 0
            clean_network.append(
                {
                    "url": _sanitize_text(base_url, _MAX_NETWORK_URL_LENGTH),
                    "method": _sanitize_text(str(entry.get("method", "")), 20),
                    "status": (
                        int(entry.get("status") or 0)
                        if isinstance(entry.get("status"), (int, float))
                        else 0
                    ),
                    "duration_ms": (
                        int(entry.get("duration_ms") or 0)
                        if isinstance(entry.get("duration_ms"), (int, float))
                        else 0
                    ),
                    "error": _sanitize_text(str(entry.get("error", "")), 200),
                    "query_param_count": query_param_count,
                }
            )

        # Performance timing : dict {key: numeric}.
        clean_performance: dict[str, Any] = {}
        if performance_timing:
            for key, value in list(performance_timing.items())[:_MAX_PERFORMANCE_KEYS]:
                if not isinstance(key, str):
                    continue
                clean_key = _sanitize_text(key, 80)
                if not clean_key:
                    continue
                # Numérique uniquement (anti-leak : un objet entier serait str()
                # avec leak potentiel d'attributs sensibles).
                if isinstance(value, (int, float)):
                    clean_performance[clean_key] = value
                else:
                    # C4-F2 (#70) : ``slow_resource_N`` porte l'URL COMPLÈTE de
                    # la ressource lente (cf. feedback-reporter.js ``r.name``),
                    # query incluse (ex un asset signé ``?sig=…``). Même strip
                    # anti-leak que stack/console avant envoi support.
                    clean_performance[clean_key] = _sanitize_text(
                        _strip_url_queries_in_text(str(value)), 200
                    )

        # App state : snapshot léger (URL, body classes, modal ouvert, titre).
        clean_app_state: dict[str, Any] = {}
        if app_state:
            for key, value in list(app_state.items())[:_MAX_APP_STATE_KEYS]:
                if not isinstance(key, str):
                    continue
                clean_key = _sanitize_text(key, 80)
                if not clean_key:
                    continue
                raw_value = str(value) if value is not None else ""
                # C4-F1 : la clé ``url`` d'``app_state`` porte le href COMPLET du
                # navigateur (cf. feedback-reporter.js ``location.href``) → on retire
                # la query/fragment comme pour ``page`` et les network_requests. NB :
                # ``hash`` est un fragment de navigation pur (``#tab-2``, non sensible
                # en Komptia qui n'utilise pas d'OAuth implicit-flow) → laissé tel quel.
                if clean_key == "url":
                    raw_value = _strip_url_query(raw_value)
                clean_app_state[clean_key] = _sanitize_text(
                    raw_value,
                    _MAX_APP_STATE_VALUE_LENGTH,
                )

        # localStorage debug-safe : filtre les clés sensibles côté serveur.
        # Le frontend filtre déjà mais defense in depth ici (un client
        # malveillant pourrait envoyer un payload crafted).
        clean_localstorage: dict[str, str] = {}
        if localstorage_debug:
            for key, value in list(localstorage_debug.items())[:_MAX_LOCALSTORAGE_ENTRIES]:
                if not isinstance(key, str):
                    continue
                clean_key = _sanitize_text(key, 80)
                if not clean_key:
                    continue
                # Anti-leak : si le NOM de la clé contient un fragment sensible,
                # on skip (jamais en mail au support).
                lowered = clean_key.lower()
                if any(frag in lowered for frag in _LOCALSTORAGE_SENSITIVE_FRAGMENTS):
                    logger.info(
                        "FeedbackPayload: clé localStorage sensible filtrée: %s",
                        clean_key[:40],
                    )
                    continue
                clean_localstorage[clean_key] = _sanitize_text(
                    str(value) if value is not None else "",
                    _MAX_LOCALSTORAGE_VALUE_LENGTH,
                )

        return cls(
            message=message_clean,
            page=page_clean,
            user_agent=ua_clean,
            browser_version=browser_clean,
            stack_trace=stack_clean,
            console_entries=clean_console,
            extras=clean_extras,
            client_captured_at=captured_clean,
            request_id=request_id,
            client_ip=client_ip,
            user_id=user_id,
            username=username,
            network_requests=clean_network,
            performance_timing=clean_performance,
            app_state=clean_app_state,
            localstorage_debug=clean_localstorage,
        )

    def to_log_dict(self) -> dict[str, Any]:
        """Sérialise pour l'audit JSONL (sans HTML)."""
        return {
            "received_at": self.received_at.isoformat(),
            "client_captured_at": self.client_captured_at,
            "request_id": self.request_id,
            "client_ip": self.client_ip,
            "user_id": self.user_id,
            "username": self.username,
            "page": self.page,
            "user_agent": self.user_agent,
            "browser_version": self.browser_version,
            "message": self.message,
            "stack_trace": self.stack_trace,
            "console_entries": self.console_entries,
            "extras": self.extras,
            "network_requests": self.network_requests,
            "performance_timing": self.performance_timing,
            "app_state": self.app_state,
            "localstorage_debug": self.localstorage_debug,
            # Fix #9 review 2026-05-19 — ``server_logs`` SKIP audit JSONL :
            # déjà dispo dans komptia.log/errors.log/rotated, dédup inutile
            # qui ferait exploser le 50 MB de rotation audit (100 lignes × 2
            # KB × N feedback/h = jusqu'à 12 MB/h juste pour les logs serveur
            # dupliqués). Le mail support reste self-contained car il les
            # inclut directement. L'audit JSONL ne tracke que le contexte
            # client + ID corrélation pour retrouver les logs source.
            "server_logs_lines_count": len(self.server_logs),
        }


def _sanitize_text(value: str, max_length: int) -> str:
    """Strip + retire les caractères de contrôle dangereux + tronque."""
    if not isinstance(value, str):
        value = str(value)
    cleaned = _CONTROL_CHARS_REGEX.sub("", value).strip()
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + "…[tronqué]"
    return cleaned


def _strip_url_query(value: Any) -> str:
    """Retire la query-string (``?...``) d'une URL, en préservant path + fragment.

    C4-F1 (anti-leak) : une URL de page peut porter dans son ``?...`` des valeurs
    confidentielles (terme de recherche ``?q=SOFIGEC``, filtre, identifiant de
    dossier, voire un token). Le rapport « Signaler » part vers un Gmail externe
    (destinataire support) — on applique aux champs ``page`` / ``app_state.url``
    la MÊME policy que les ``network_requests`` (qui ne gardent que ``base_url``).

    Le FRAGMENT (``#...``) est en revanche CONSERVÉ : en Komptia il porte un état
    de navigation non sensible (``#tab-2``, ``#filter=all``) et n'expose pas de
    token (pas d'OAuth implicit-flow). On strippe donc la query mais on réattache
    le fragment au path.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    before_frag, frag_sep, frag = value.partition("#")
    path_only = before_frag.partition("?")[0]
    return path_only + (frag_sep + frag if frag_sep else "")


# C4-F2 (#70) — URLs embarquées dans du TEXTE LIBRE (stack_trace, console).
# ``_strip_url_query`` ci-dessus ne gère qu'UNE url isolée (le champ ``page``) :
# il coupe tout après le 1er ``?``, ce qui DÉTRUIRAIT un texte multi-ligne. Ici
# les URLs sont noyées dans du texte (« Failed to fetch
# https://api/x?token=SECRET 500 ») et peuvent être multiples. On applique la
# MÊME policy anti-leak que ``page`` / ``network_requests`` (garder le base_url,
# retirer la query) mais URL-par-URL, in-place. Le rapport « Signaler » part
# vers un Gmail externe (hors-EU) — un ``?token=`` / ``?email=`` ne doit jamais
# y figurer, même cité dans une stack ou un log console.
#
# La query est bornée par les délimiteurs d'URL-en-texte (espace, guillemets,
# parenthèses/crochets fermants, ``#``) et doit contenir au moins un ``=`` (vrai
# paramètre) — ``and/or?maybe`` (sans ``=``) n'est donc PAS matché (anti faux
# positif sur du texte courant). Base = URL absolue ``http(s)://…`` ou chemin
# relatif ``/…`` (les logs fetch citent souvent l'URL relative).
# Compromis assumé : une URL de stack portant à la fois ``?cachebuster`` ET
# ``:ligne:col`` perdrait son ``:ligne:col`` — cas rare, la confidentialité
# prime sur le numéro de ligne exact.
_URL_QUERY_IN_TEXT_REGEX = re.compile(
    r"""(?P<base>(?:https?://|/)[^\s"'<>)\]}?#]+)\?[^\s"'<>)\]}#]*=[^\s"'<>)\]}#]*"""
)


def _strip_url_queries_in_text(value: Any) -> str:
    """Retire les query-strings de TOUTES les URLs embarquées dans un texte.

    Préserve le texte autour ; remplace ``base?clé=valeur…`` par
    ``base?[redacted]`` (marqueur explicite plutôt que disparition silencieuse,
    pour que le support sache qu'une query a été retirée). Voir le bloc de
    commentaire ci-dessus pour la policy et les compromis.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return _URL_QUERY_IN_TEXT_REGEX.sub(lambda m: m.group("base") + "?[redacted]", value)


# ────────────────────────────────────────────────────────────────────────


async def resolve_support_email() -> Optional[str]:
    """SSoT du destinataire des signalements **et** des approbations support.

    Lit ``SMTPGlobalConfig.support_email`` (admin via ``/admin/smtp-config``).
    **Seule source de vérité = la BDD** (décision user 2026-05-19, aucun
    hardcode d'adresse ailleurs). Retourne ``None`` si la valeur admin est
    vide ou que la table est inaccessible — le caller décide quoi faire de
    l'absence (le bug-reporter saute l'envoi mail et persiste l'audit local ;
    la casquette Iris-DBA-write refuse fail-closed la proposition d'écriture).

    ``ORDER BY id DESC LIMIT 1`` pour le cas d'incohérence singleton (purge
    échouée, INSERT manuel) — cohérent avec ``_get_latest_config`` du handler
    admin_smtp.
    """
    try:
        from app.core.database import get_session
        from app.models.smtp_global_config import SMTPGlobalConfig
        from sqlalchemy import select
        from sqlalchemy.exc import SQLAlchemyError

        async with get_session() as session:
            row = (
                await session.scalars(
                    select(SMTPGlobalConfig).order_by(SMTPGlobalConfig.id.desc()).limit(1)
                )
            ).one_or_none()
            if row and row.support_email and row.support_email.strip():
                return row.support_email.strip()
    except (SQLAlchemyError, OSError, ImportError, RuntimeError, asyncio.TimeoutError) as exc:
        # Best-effort : panne transitoire BDD, BDD non initialisée (tests/boot)
        # ou BDD verrouillée (TimeoutError) → destinataire support introuvable.
        # Fail-closed propre (None) plutôt qu'une 500 qui remonterait au caller.
        logger.warning(
            "resolve_support_email: lecture support_email BDD échouée (%s)",
            exc.__class__.__name__,
        )
    return None


class FeedbackService:
    """Service singleton — envoi mail + audit-trail JSONL.

    Les valeurs ``app_name`` / ``support_email`` sont lues à CHAQUE
    appel via ``config`` (pas figées au singleton init) — un changement
    runtime ou via env est pris en compte sans reset_feedback_service().
    """

    def __init__(self, *, fallback_dir: Optional[Path] = None) -> None:
        from app.config import config

        if fallback_dir is None:
            fallback_dir = config.logs_dir
        self._fallback_dir = fallback_dir

    async def _resolve_support_email(self) -> Optional[str]:
        """Délègue au resolver module-level :func:`resolve_support_email`
        (SSoT partagé avec la casquette Iris-DBA-write). Conservé comme
        méthode d'instance pour la compat des tests qui patchent
        ``FeedbackService``.
        """
        return await resolve_support_email()

    @property
    def app_name(self) -> str:
        from app.config import config

        return config.app_name

    async def submit(
        self, payload: FeedbackPayload, *, force_no_send: bool = False
    ) -> dict[str, Any]:
        """Envoie le rapport. Retourne ``{sent: bool, stored: bool}``.

        Args:
            payload: Rapport validé.
            force_no_send: Si True, n'envoie pas le mail (quota global
                anonyme saturé) mais persiste en audit-trail. L'utilisateur
                voit alors le message ``SUCCESS_STORED_ONLY``.
        """
        # 2026-05-19 — Enrichir avec les logs serveur corrélés au request_id
        # AVANT la persistance audit ET avant l'envoi mail. Le support reçoit
        # ainsi un mail self-contained sans avoir à grep le serveur lui-même.
        # Non-bloquant : si la lecture log échoue, on continue avec server_logs
        # vide (best-effort).
        try:
            payload.server_logs = await self._collect_server_logs(payload.request_id)
        except Exception:  # noqa: BLE001
            logger.warning(
                "FeedbackService: lecture logs serveur échouée",
                exc_info=True,
                extra={"request_id": payload.request_id},
            )

        # Persister AVANT envoi : c'est le filet de sécurité ultime.
        stored = await self._persist_audit(payload)

        sent = False
        if not force_no_send:
            try:
                sent = await self._send_email(payload)
            except Exception:  # noqa: BLE001
                logger.warning(
                    "FeedbackService: envoi mail échoué — voir détail dans les logs",
                    exc_info=True,
                    extra={"request_id": payload.request_id},
                )

        return {"sent": sent, "stored": stored}

    # ── Logs serveur corrélés au request_id (2026-05-19) ────────────────

    async def _collect_server_logs(self, request_id: str) -> list[str]:
        """Lit les ~100 dernières lignes des logs serveur corrélées au
        ``request_id``. Permet au support de recevoir le contexte serveur
        sans devoir grep manuellement.

        Sources lues (dans l'ordre, fusion best-effort) :
        1. ``komptia.log`` (logs courants)
        2. ``errors.log`` (erreurs/critical — fix #8 review 2026-05-19)
        3. Dernier fichier rotaté ``komptia.log.YYYY-MM-DD`` si le request_id
           date d'avant minuit UTC (fix #8).

        Contraintes :

        - **Match exact JSON** : ``f'"request_id": "{rid}"'`` pour éviter
          les faux positifs substring (fix #1 review — le request_id ne
          fait que 12 hex chars, le substring naïf pourrait matcher des
          IDs d'autres requêtes ou fragments hex aléatoires).
        - Cap fichier : tail des ``_SERVER_LOGS_MAX_FILE_BYTES_TO_TAIL``
          derniers octets par fichier (anti-OOM).
        - Cap output total : ``_SERVER_LOGS_MAX_LINES`` (toutes sources
          confondues, dédupliquées).
        - Best-effort : un fichier absent ou illisible est skippé sans
          erreur, l'autre source prend le relai.
        - Timeout : 2s global via ``asyncio.wait_for`` côté caller.
        """
        if not request_id:
            return []

        # Fix #1 — Match exact dans le format JSON des logs structurés
        # (logger Komptia écrit ``"request_id": "abcdef123456"``).
        exact_marker = f'"request_id": "{request_id}"'

        # Construire la liste des fichiers à lire (dans l'ordre).
        candidates: list[Path] = [
            self._fallback_dir / "komptia.log",
            self._fallback_dir / "errors.log",
        ]
        # Fix #8 — Fichier rotaté du jour précédent si on est tôt après
        # minuit UTC (risque de bug signalé juste après rotation 00:00).
        yesterday = clock.now().date() - timedelta(days=1)
        candidates.append(self._fallback_dir / f"komptia.log.{yesterday.isoformat()}")

        def _read_tail_and_filter(log_path: Path) -> list[str]:
            if not log_path.exists():
                return []
            try:
                size = log_path.stat().st_size
            except OSError:
                return []
            offset = max(0, size - _SERVER_LOGS_MAX_FILE_BYTES_TO_TAIL)
            try:
                with log_path.open("r", encoding="utf-8", errors="replace") as f:
                    if offset > 0:
                        f.seek(offset)
                        f.readline()  # jeter la ligne potentiellement coupée
                    raw_lines = f.readlines()
            except OSError:
                return []
            # C4-F2 (#70) — defense-in-depth : une ligne de log peut contenir
            # une URL avec query (un log applicatif ad-hoc « fetch failed
            # /api/x?token=… » ; Komptia logge le path seul mais rien ne
            # l'impose partout) et part au support externe (Gmail). On strippe
            # la query comme pour stack_trace / console_entries.
            return [
                _strip_url_queries_in_text(line.rstrip("\n")[:2000])
                for line in raw_lines
                if exact_marker in line
            ]

        def _read_all_sources() -> list[str]:
            all_matched: list[str] = []
            for path in candidates:
                all_matched.extend(_read_tail_and_filter(path))
            # Dédup en préservant l'ordre.
            seen: set[str] = set()
            deduped: list[str] = []
            for line in all_matched:
                if line not in seen:
                    seen.add(line)
                    deduped.append(line)
            return deduped[-_SERVER_LOGS_MAX_LINES:]

        try:
            return await asyncio.wait_for(
                asyncio.to_thread(_read_all_sources),
                timeout=2.0,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "FeedbackService: lecture logs timeout (2s) — fichiers "
                "probablement géants. Retour vide.",
                extra={"request_id": request_id},
            )
            return []

    # ── Audit-trail JSONL avec rotation quotidienne + cap 50 MB ─────────

    def _audit_path_for_today(self) -> Path:
        date_str = clock.now().strftime("%Y-%m-%d")
        return self._fallback_dir / f"{_AUDIT_FILENAME_PREFIX}{date_str}.jsonl"

    def _rotate_if_needed(self, path: Path) -> Path:
        """Si le fichier dépasse _AUDIT_FILE_MAX_BYTES, le renomme en
        ``.old`` (un seul niveau) et retourne le path fresh à utiliser.
        Si ``.old`` existe déjà, il est écrasé — on garde 2 fichiers
        actifs max par jour pour borner l'occupation disque (50 MB
        × 2 = 100 MB par jour worst case)."""
        try:
            if path.exists() and path.stat().st_size >= _AUDIT_FILE_MAX_BYTES:
                old_path = path.with_suffix(path.suffix + ".old")
                if old_path.exists():
                    old_path.unlink()
                path.rename(old_path)
                logger.warning(
                    "FeedbackService: rotation audit-trail (>= %d MB)",
                    _AUDIT_FILE_MAX_BYTES // (1024 * 1024),
                    extra={"rotated_to": str(old_path)},
                )
        except OSError:
            logger.exception("FeedbackService: rotation audit-trail échouée")
        return path

    async def _persist_audit(self, payload: FeedbackPayload) -> bool:
        """Append le payload dans l'audit-trail du jour. Retourne True
        si écriture confirmée (durabilité fsync), False sinon."""
        try:
            line = json.dumps(payload.to_log_dict(), ensure_ascii=False)
        except (TypeError, ValueError):
            logger.exception("FeedbackService: payload non sérialisable")
            return False

        target = self._rotate_if_needed(self._audit_path_for_today())

        def _write() -> bool:
            target.parent.mkdir(parents=True, exist_ok=True)
            # ``with open(..., "a")`` + flush + fsync : garantit durabilité.
            # Sans fsync, sur disque saturé/crash kernel, la ligne peut
            # être tronquée → JSONL invalide au rejeu.
            with open(target, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    # fsync peut lever sur certains FS (NFS, tmpfs) — on
                    # accepte, l'écriture flushée vaut mieux que rien.
                    pass
            return True

        try:
            return await asyncio.to_thread(_write)
        except OSError:
            logger.exception("FeedbackService: échec écriture audit-trail")
            return False

    # ── Envoi mail ──────────────────────────────────────────────────────

    async def _send_email(self, payload: FeedbackPayload) -> bool:
        """Envoie le mail via SMTP global config. ``False`` si SMTP HS."""
        from app.services.email.smtp_factory import build_smtp_client_from_db

        client = await build_smtp_client_from_db(fallback_from_name=self.app_name)
        if client is None:
            logger.info(
                "FeedbackService: SMTP non configuré, rapport persisté localement",
                extra={"request_id": payload.request_id},
            )
            return False

        subject = f"[{self.app_name}] Signalement utilisateur — {self._short_summary(payload)}"
        # Destinataire = SMTPGlobalConfig.support_email (admin via
        # /admin/smtp-config). Si vide → l'admin n'a pas configuré, on ne
        # peut PAS envoyer. L'audit-trail local persiste quand même le
        # signalement (filet de sécurité ultime — un user ne perd jamais
        # son rapport, même si l'admin a oublié de configurer l'email).
        recipient = await self._resolve_support_email()
        if not recipient:
            logger.info(
                "FeedbackService: support_email non configuré (/admin/"
                "smtp-config) — rapport persisté localement, pas d'envoi mail",
                extra={"request_id": payload.request_id},
            )
            return False
        from app.services.email.template_names import EmailTemplate

        result = await client.send_email(
            to_emails=recipient,
            subject=subject,
            body_html=self._render_html(payload),
            body_text=self._render_text(payload),
            sent_by_user_id=payload.user_id,
            template_name=EmailTemplate.FEEDBACK_REPORT.value,
        )
        return bool(result.get("success"))

    @staticmethod
    def _short_summary(payload: FeedbackPayload) -> str:
        first_line = payload.message.splitlines()[0] if payload.message else "(message vide)"
        return first_line[:80]

    def _render_text(self, payload: FeedbackPayload) -> str:
        captured = payload.client_captured_at or "(non transmis)"
        lines = [
            f"Application : {self.app_name}",
            f"Reçu (UTC)  : {payload.received_at.isoformat()}",
            f"Capturé client : {captured}",
            f"Request-ID  : {payload.request_id or '(aucun)'}",
            f"IP client   : {payload.client_ip or '(inconnue)'}",
            f"Utilisateur : {payload.username or '(anonyme)'} (id={payload.user_id})",
            f"Page        : {payload.page or '(inconnue)'}",
            f"Navigateur  : {payload.browser_version or '(inconnu)'}",
            "",
            "─── Message ──────────────────────────────────────────────",
            payload.message or "(message vide)",
        ]
        if payload.stack_trace:
            lines += [
                "",
                "─── Stack trace JS ───────────────────────────────────────",
                payload.stack_trace,
            ]
        if payload.console_entries:
            lines += [
                "",
                f"─── Console ({len(payload.console_entries)} entrée(s)) ──────────────",
                *payload.console_entries,
            ]
        if payload.extras:
            lines += [
                "",
                "─── Extras ───────────────────────────────────────────────",
                *(f"{k} = {v}" for k, v in payload.extras.items()),
            ]
        # Payload enrichi 2026-05-19 — sections rajoutées.
        if payload.network_requests:
            lines += [
                "",
                f"─── Network ({len(payload.network_requests)} requête(s)) ──────────",
                *(
                    f"{r.get('method', '?')} {r.get('url', '')} → "
                    f"{r.get('status', 0)} ({r.get('duration_ms', 0)}ms)"
                    + (f" — ERR: {r['error']}" if r.get("error") else "")
                    for r in payload.network_requests
                ),
            ]
        if payload.performance_timing:
            lines += [
                "",
                "─── Performance ──────────────────────────────────────────",
                *(f"{k} = {v}" for k, v in payload.performance_timing.items()),
            ]
        if payload.app_state:
            lines += [
                "",
                "─── État application ─────────────────────────────────────",
                *(f"{k} = {v}" for k, v in payload.app_state.items()),
            ]
        if payload.localstorage_debug:
            lines += [
                "",
                "─── localStorage (clés debug non sensibles) ──────────────",
                *(f"{k} = {v}" for k, v in payload.localstorage_debug.items()),
            ]
        if payload.server_logs:
            lines += [
                "",
                f"─── Logs serveur ({len(payload.server_logs)} ligne(s) filtrées par request_id) ──",
                *payload.server_logs,
            ]
        lines += [
            "",
            "─── User-Agent ───────────────────────────────────────────",
            payload.user_agent or "(non transmis)",
        ]
        return "\n".join(lines)

    def _render_html(self, payload: FeedbackPayload) -> str:
        esc = html_module.escape

        def block(label: str, content: str) -> str:
            return (
                f"<tr><th align='left' style='padding:6px 12px;background:#f3f4f6;"
                f"font-weight:600;width:160px;'>{esc(label)}</th>"
                f"<td style='padding:6px 12px;'>{esc(content) or '<em>(aucun)</em>'}</td></tr>"
            )

        rows = [
            block("Application", self.app_name),
            block("Reçu (UTC)", payload.received_at.isoformat()),
            block("Capturé client", payload.client_captured_at or ""),
            block("Request-ID", payload.request_id),
            block("IP client", payload.client_ip),
            block("Utilisateur", f"{payload.username or 'anonyme'} (id={payload.user_id})"),
            block("Page", payload.page),
            block("Navigateur", payload.browser_version),
            block("User-Agent", payload.user_agent),
        ]

        message_html = esc(payload.message).replace("\n", "<br>")
        stack_html = (
            f"<h3 style='margin-top:24px;'>Stack trace JS</h3>"
            f"<pre style='background:#0f172a;color:#fafafa;padding:12px;border-radius:6px;"
            f"overflow:auto;font-size:12px;'>{esc(payload.stack_trace)}</pre>"
            if payload.stack_trace
            else ""
        )
        console_html = ""
        if payload.console_entries:
            entries = "".join(f"<li>{esc(e)}</li>" for e in payload.console_entries)
            console_html = (
                f"<h3 style='margin-top:24px;'>Console "
                f"({len(payload.console_entries)} entrée(s))</h3>"
                f"<ol style='font-family:monospace;font-size:12px;'>{entries}</ol>"
            )
        extras_html = ""
        if payload.extras:
            items = "".join(
                f"<li><strong>{esc(k)}</strong> = {esc(str(v))}</li>"
                for k, v in payload.extras.items()
            )
            extras_html = f"<h3 style='margin-top:24px;'>Extras</h3><ul>{items}</ul>"

        # Payload enrichi 2026-05-19 — sections rajoutées en HTML.
        network_html = ""
        if payload.network_requests:
            rows_net = "".join(
                "<tr>"
                f"<td style='padding:4px 8px;font-family:monospace;'>{esc(str(r.get('method', '?')))}</td>"
                f"<td style='padding:4px 8px;font-family:monospace;word-break:break-all;'>{esc(str(r.get('url', '')))}</td>"
                f"<td style='padding:4px 8px;text-align:right;color:{'#16a34a' if 200 <= int(r.get('status', 0)) < 300 else '#dc2626'};'>{esc(str(r.get('status', 0)))}</td>"
                f"<td style='padding:4px 8px;text-align:right;'>{esc(str(r.get('duration_ms', 0)))}ms</td>"
                f"<td style='padding:4px 8px;color:#dc2626;'>{esc(str(r.get('error', '')))}</td>"
                "</tr>"
                for r in payload.network_requests
            )
            network_html = (
                f"<h3 style='margin-top:24px;'>Network "
                f"({len(payload.network_requests)} requête(s))</h3>"
                "<table style='width:100%;border-collapse:collapse;font-size:12px;border:1px solid #e5e7eb;'>"
                "<thead><tr style='background:#f3f4f6;'>"
                "<th align='left' style='padding:6px 8px;'>Méthode</th>"
                "<th align='left' style='padding:6px 8px;'>URL</th>"
                "<th align='right' style='padding:6px 8px;'>Statut</th>"
                "<th align='right' style='padding:6px 8px;'>Durée</th>"
                "<th align='left' style='padding:6px 8px;'>Erreur</th>"
                "</tr></thead>"
                f"<tbody>{rows_net}</tbody></table>"
            )
        performance_html = ""
        if payload.performance_timing:
            items_perf = "".join(
                f"<li><strong>{esc(k)}</strong> = {esc(str(v))}</li>"
                for k, v in payload.performance_timing.items()
            )
            performance_html = f"<h3 style='margin-top:24px;'>Performance</h3><ul style='font-family:monospace;font-size:12px;'>{items_perf}</ul>"
        app_state_html = ""
        if payload.app_state:
            items_st = "".join(
                f"<li><strong>{esc(k)}</strong> = {esc(str(v))}</li>"
                for k, v in payload.app_state.items()
            )
            app_state_html = f"<h3 style='margin-top:24px;'>État application</h3><ul style='font-family:monospace;font-size:12px;'>{items_st}</ul>"
        localstorage_html = ""
        if payload.localstorage_debug:
            items_ls = "".join(
                f"<li><strong>{esc(k)}</strong> = {esc(str(v))}</li>"
                for k, v in payload.localstorage_debug.items()
            )
            localstorage_html = (
                f"<h3 style='margin-top:24px;'>localStorage (debug non sensible)</h3>"
                f"<ul style='font-family:monospace;font-size:12px;'>{items_ls}</ul>"
            )
        server_logs_html = ""
        if payload.server_logs:
            log_lines = "".join(f"<li>{esc(line)}</li>" for line in payload.server_logs)
            server_logs_html = (
                f"<h3 style='margin-top:24px;'>Logs serveur "
                f"({len(payload.server_logs)} ligne(s) corrélées par request_id)</h3>"
                f"<ol style='font-family:monospace;font-size:11px;background:#0f172a;color:#fafafa;padding:12px;border-radius:6px;overflow:auto;'>{log_lines}</ol>"
            )

        return (
            "<html><body style='font-family:-apple-system,Segoe UI,sans-serif;color:#111;"
            "max-width:800px;margin:0 auto;padding:24px;'>"
            f"<h2 style='color:#C44133;margin-top:0;'>Signalement utilisateur — {esc(self.app_name)}</h2>"
            "<table cellspacing='0' cellpadding='0' style='width:100%;border-collapse:collapse;"
            "border:1px solid #e5e7eb;'>"
            f"{''.join(rows)}"
            "</table>"
            "<h3 style='margin-top:24px;'>Message</h3>"
            f"<div style='background:#f9fafb;border-left:3px solid #C44133;padding:12px 16px;"
            f"white-space:pre-wrap;'>{message_html}</div>"
            f"{stack_html}{console_html}{extras_html}"
            f"{network_html}{performance_html}{app_state_html}"
            f"{localstorage_html}{server_logs_html}"
            "</body></html>"
        )


# ── Singleton ───────────────────────────────────────────────────────────

_service: Optional[FeedbackService] = None


def get_feedback_service() -> FeedbackService:
    global _service
    if _service is None:
        _service = FeedbackService()
    return _service


def reset_feedback_service() -> None:
    """Force la recréation (utilisé en tests pour appliquer monkeypatch
    sur ``config.logs_dir`` ou ``support_email``)."""
    global _service
    _service = None
