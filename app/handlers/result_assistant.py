"""Handlers HTTP du *copilote de résultat* SQL (IA sur la grille).

Endpoints
---------
* ``POST /api/iris/result-modify`` — modifie/construit un résultat SQL à
  partir d'une instruction utilisateur en langue naturelle (tool-loop
  :func:`app.services.ai.copilot_agent.run_copilot_agent`) ou, pour
  l'auto-fill « ghost », l'appel one-shot :func:`modify_result`.
* ``POST /api/iris/cell-suggest`` — propose des valeurs pour remplir une
  cellule (détermination programmatique si possible, sinon LLM).

Garanties senior appliquées (OWASP Top 10 2025 + API Sec Top 10 2023)
---------------------------------------------------------------------
1. **A01 Broken Access Control** — décorateur local ``_copilot_authorized``
   fail-closed : pas d'utilisateur → 401, rôle hors ``ADMIN``/``USER`` →
   403. Équivalent fonctionnel de :func:`app.handlers.base.require_role`
   mais conserve le contrat de réponse ``{"error": "..."}`` (string)
   attendu par ``static/js/iris-grid.js`` (4 appelants, lignes 2607, 2695,
   3220, 3592). Migrer vers ``@require_role`` exigerait de mettre à jour
   le frontend pour lire ``data.message`` — tracké par
   ``EPIC:LLM-COST-GUARDRAILS``.
2. **API4 Unrestricted Resource Consumption** — les deux endpoints sont
   coûteux (appels LLM = $ + latence + tours). Rate-limit par user + par
   endpoint : :data:`_COPILOT_RATE_MAX`/:data:`_COPILOT_RATE_WINDOW_S` et
   :data:`_SUGGEST_RATE_MAX`/:data:`_SUGGEST_RATE_WINDOW_S`.
3. **API3 Broken Object Property Level Authorization** — le body JSON est
   validé en forme (dict) + toutes les sous-structures sont
   ``isinstance``-guard (pas de ``AttributeError`` en prod) via les
   helpers ``_coerce_*``.
4. **Taille bornée** (défense-in-depth — uniquement le body brut) :

   * Pré-check ``Content-Length`` → 413 avant désérialisation
     (:data:`_BODY_MAX_BYTES` = 50 MiB, anti-DoS event-loop ; les
     classeurs Komptia légitimes peuvent peser plusieurs MiB) ;
   * Instruction cappée à :data:`_INSTR_MAX_LEN` (4 000 char) — bloque
     le prompt injection par bombardement de texte + LLM cost ;
   * ``tabs_context`` / ``sheet_content`` / ``columns`` ne sont **plus
     cappés en nombre d'entrées** — le copilot doit pouvoir traiter
     n'importe quelle taille de classeur que l'app peut stocker. Le
     cap technique reste le ``_BODY_MAX_BYTES`` ci-dessus.
5. **Pas de leak d'exception** — doctrine :class:`app.handlers.base.
   BaseHandler` : jamais ``str(exc)`` au client. Tous les messages
   utilisateur sont dans :class:`_Messages`. Stack trace + type d'erreur
   sont loggés côté serveur avec ``request_id``.
6. **Codes HTTP sémantiques** — 400 (body invalide), 401 (anonyme),
   403 (rôle refusé), 413 (body trop gros), 422 (contexte insuffisant),
   429 (rate limit), 503 (LLM upstream surchargé), 500 (bug).
7. **Pas de fallback silencieux** — si ``run_copilot_agent`` plante ou
   épuise ses tours, on remonte l'erreur brute à l'utilisateur. L'ancien
   fallback vers ``modify_result`` one-shot masquait la cause réelle ET
   retombait sur un chemin qui n'a PAS les tools du copilot_agent
   (``ask_iris``, ``patch_tab``, ``rename_tab``, ``delete_tab``) — donc
   résultat dégradé trompeur. ``modify_result`` reste utilisé uniquement
   pour ``is_auto_fill=True`` (suggestions ghost).
"""

from __future__ import annotations

import asyncio
import functools
import json
import re
from typing import Any, Awaitable, Callable, Dict, Final, TypedDict

import tornado.ioloop
import tornado.web

from app.handlers.base import BaseHandler
from app.models.user import UserRole
from app.services.ai.copilot_agent import run_copilot_agent
from app.services.result_assistant import modify_result, suggest_cell_values
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter

logger = get_logger(__name__)

# Format accepté pour les run_id copilot (clé du progress store, jamais
# interprété en SQL/chemin/HTML — defense-in-depth charset, tâche #25).
# Couvre les deux générateurs frontend : ``crypto.randomUUID()``
# (hex + tirets) et le fallback ``run_<base36>_<base36>``.
_RUN_ID_RE: Final = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


# ── Constantes ────────────────────────────────────────────────────────────

#: Instruction trop courte = bruit (`"abc"` ou `"ok"`), l'agent hallucine du
#: SQL vide. 10 caractères suffisent pour exiger un verbe + objet (« trier
#: par », « filtrer », « somme de »).
_INSTR_MIN_LEN: Final[int] = 10

#: Cap haut : une instruction de plus de 4 000 caractères n'est plus une
#: instruction mais un déversoir de contexte qui fait grimper le coût LLM
#: et ouvre la porte au prompt injection par dilution. Aligné sur
#: :data:`app.handlers.reports._MAX_USER_PROMPT_LEN`.
_INSTR_MAX_LEN: Final[int] = 4_000

#: Taille max du body JSON. Garde-fou TECHNIQUE anti-DoS event-loop
#: (Tornado parse synchrone). Volontairement large : les classeurs Komptia
#: peuvent peser plusieurs MiB (.afz.json observés jusqu'à 15 MiB), et le
#: copilot doit pouvoir traiter ce volume comme contexte d'entrée. 50 MiB
#: = 3× la plus grosse charge observée + marge pour les futurs classeurs ;
#: au-delà on suspecte un envoi pathologique (debug dump, copier-coller
#: binaire). Le rate-limit ``_COPILOT_RATE_MAX`` (5/min/user) borne les
#: abus en complément.
_BODY_MAX_BYTES: Final[int] = 50 * 1024 * 1024

#: Rate-limit copilote tool-loop : l'agent brûle jusqu'à 40 tours Opus,
#: soit ~$0.50–1.00 par appel dans le pire cas. 5 appels/minute/user
#: couvre un usage actif (itérer sur une requête) tout en bloquant un
#: script qui spam — un user malveillant plafonne à 7 200 appels/jour/user
#: soit ~$3 600/jour, encore trop haut donc :data:`_COPILOT_RATE_WINDOW_S`
#: reste court (minute) pour un feedback UX immédiat + l'EPIC
#: LLM-COST-GUARDRAILS ajoutera un budget $ quotidien transverse.
_COPILOT_RATE_MAX: Final[int] = 5
_COPILOT_RATE_WINDOW_S: Final[int] = 60

#: Rate-limit suggestion cellule : plus léger (1 appel LLM, pas 40), mais
#: un auto-fill en boucle sur 50 cellules en 2 secondes reste coûteux.
#: 20/min/user = 1 200/h max, cohérent avec un edit manuel humain.
_SUGGEST_RATE_MAX: Final[int] = 20
_SUGGEST_RATE_WINDOW_S: Final[int] = 60

#: Rôles autorisés à appeler les endpoints copilot. ``READER`` (si ajouté
#: un jour) est exclu : ce sont des actions transformant des données.
_ALLOWED_ROLES: Final[frozenset[UserRole]] = frozenset({UserRole.ADMIN, UserRole.USER})


# ── Messages client centralisés ───────────────────────────────────────────


class _Messages:
    """Libellés FR exposés au client copilot (iris-grid.js).

    Centraliser ces constantes : audit sécurité (pas de drift), tests
    d'intégration (import au lieu de hardcode en assertion), future i18n.
    """

    AUTH_REQUIRED: Final[str] = "Authentification requise."
    FORBIDDEN: Final[str] = "Accès refusé."
    INVALID_JSON: Final[str] = "Corps de requête JSON invalide."
    #: La limite affichée DOIT être dérivée de ``_BODY_MAX_BYTES`` (SSoT) —
    #: sinon le message ment au client. Bug 2026-05-31 : ce libellé était
    #: figé à « 2 Mo » alors que le cap réel est 50 MiB → un user dont le
    #: classeur (légitimement plusieurs MiB) est rejeté lit une limite 25×
    #: trop basse. Voir ``_parse_body_or_error`` (seul call-site, HTTP 413).
    BODY_TOO_LARGE: Final[str] = (
        f"Corps de requête trop volumineux (limite : {_BODY_MAX_BYTES // (1024 * 1024)} Mo)."
    )
    INSTRUCTION_REQUIRED: Final[str] = "Instruction requise."
    INSTRUCTION_TOO_SHORT: Final[str] = (
        "Instruction trop courte. Décrivez plus précisément ce que vous souhaitez."
    )
    INSTRUCTION_TOO_LONG: Final[str] = (
        "Instruction trop longue (limite : 4 000 caractères). " "Synthétisez votre demande."
    )
    NO_SHEET_CONTEXT: Final[str] = "Contexte insuffisant (aucune donnée de feuille)."
    NO_SQL_CONTEXT: Final[str] = "Aucun contexte disponible (pas de SQL dans les onglets)."
    ANON_STATE_INVALID: Final[str] = (
        "État d'anonymisation invalide. Ouvrez le panneau de confidentialité " "pour le corriger."
    )
    RATE_LIMITED_COPILOT: Final[str] = (
        f"Trop de requêtes au copilote (limite : {_COPILOT_RATE_MAX} "
        f"par {_COPILOT_RATE_WINDOW_S} secondes). Patientez avant de réessayer."
    )
    RATE_LIMITED_SUGGEST: Final[str] = (
        f"Trop de suggestions demandées (limite : {_SUGGEST_RATE_MAX} "
        f"par {_SUGGEST_RATE_WINDOW_S} secondes). Patientez un instant."
    )
    INTERNAL_ERROR: Final[str] = (
        "Une erreur interne est survenue. Réessayez ; "
        "si le problème persiste, contactez un administrateur."
    )
    #: Quand aucun provider LLM (ni cloud ni local) n'est configuré dans
    #: ``/admin/ai-config``. Le service ``modify_result`` / ``suggest_cell_values``
    #: retourne ``{reason: "not_configured", message: ...}`` que ce handler mappe
    #: vers HTTP 503 + ce message FR. Cohérent avec le banner UI global qui
    #: affiche un message équivalent. Le ``str(exc)`` du service contient déjà
    #: ``_MSG_NOT_CONFIGURED`` de :mod:`llm_runtime` — on garde ici une
    #: constante pour les cas où le service ne renvoie pas de ``message``
    #: explicite (défense en profondeur).
    LLM_NOT_CONFIGURED: Final[str] = (
        "L'IA n'est pas configurée sur cette instance. Un administrateur "
        "doit configurer la clé API ou activer le LLM local dans "
        "/admin/ai-config pour utiliser cette fonctionnalité."
    )


# ── Rate limiters partagés ────────────────────────────────────────────────

_copilot_rate_limiter: Final[RateLimiter] = RateLimiter()
_suggest_rate_limiter: Final[RateLimiter] = RateLimiter()


# ── Typage body (documentation + outils statiques) ────────────────────────


class _ModifyRequest(TypedDict, total=False):
    """Shape attendue du body JSON pour ``/api/iris/result-modify``.

    ``total=False`` : tous les champs sont optionnels côté wire (le front
    n'envoie pas toujours tout selon le flux — auto-fill vs copilot
    explicite). Le handler applique des defaults safe via les helpers
    ``_coerce_*``.
    """

    sql: str
    instruction: str
    is_auto_fill: bool
    columns: list[str]
    display_state: dict[str, Any]
    tabs_context: list[dict[str, Any]]
    sheet_content: list[dict[str, Any]]
    sheet_context: dict[str, Any]
    #: État d'anonymisation pilotée utilisateur (format ``anon_terms`` v1).
    #: Si absent, traité comme state neuf → gate probable
    #: (``ANON_PENDING_REVIEW``) dès qu'un terme est détecté dans le classeur.
    anonymization_state: dict[str, Any]
    #: Cellules sélectionnées par l'utilisateur au moment du Send (coords
    #: 0-based ``{r, c}``). Sert d'indication contextuelle au copilot : "voici
    #: ce sur quoi je voulais agir". Capé à 200 entries côté front.
    selected_cells: list[dict[str, int]]


class _SuggestRequest(TypedDict, total=False):
    """Shape attendue du body JSON pour ``/api/iris/cell-suggest``."""

    column_name: str
    cell_position: dict[str, Any]
    columns: list[str]
    tabs_context: list[dict[str, Any]]
    sheet_content: list[dict[str, Any]]


# ── Helpers purs (testables sans handler) ─────────────────────────────────


def _coerce_str(value: Any, max_len: int = _INSTR_MAX_LEN) -> str:
    """Retourne une string nettoyée + tronquée à ``max_len`` caractères.

    Non-string → string vide (jamais ``None``) : le caller traite la chaîne
    vide selon sa sémantique (``instruction`` vide → 400, ``sql`` vide →
    recherche dans ``tabs_context``).
    """
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_len]


def _coerce_list(value: Any, max_items: int | None = None) -> list[Any] | None:
    """Retourne une list bornée ou ``None`` si non-list.

    ``None`` (pas ``[]``) pour distinguer « absent » de « vide » — les
    services ``modify_result`` / ``suggest_cell_values`` interprètent
    différemment les deux cas.
    """
    if not isinstance(value, list):
        return None
    if max_items is not None and len(value) > max_items:
        return value[:max_items]
    return value


def _coerce_dict(value: Any) -> dict[str, Any] | None:
    """Retourne un dict ou ``None`` si non-dict."""
    return value if isinstance(value, dict) else None


def _has_any_sql(sql: str, tabs_context: list[dict[str, Any]] | None) -> bool:
    """``True`` si au moins un SQL est présent (directement ou via onglets).

    Guard fail-closed : le copilot ne peut pas interpréter une instruction
    sans source SQL (il hallucinerait). On refuse avant l'appel LLM pour
    économiser le coût *et* donner un feedback utile au user.
    """
    if sql:
        return True
    if not tabs_context:
        return False
    return any(isinstance(t, dict) and t.get("sql") for t in tabs_context)


def _classify_service_error(error_text: str) -> int:
    """Mappe un message d'erreur service → code HTTP sémantique.

    * « surchargé », « overloaded », « 529 » → 503 Service Unavailable
      (upstream LLM, retryable côté user) ;
    * « rate limit », « 429 » → 429 Too Many Requests (upstream) ;
    * « limite de … tours » / « budget épuisé » → 504 Gateway Timeout
      (ressource agent épuisée côté serveur, pas un body invalide) ;
    * tout le reste → 422 Unprocessable Entity (erreur applicative
      exploitable par le user : clarification, contexte manquant).

    422 (et pas 400) : le body est bien formé, c'est la logique qui
    refuse. Source : RFC 4918 §11.2.
    """
    low = error_text.lower()
    if "surchargé" in low or "overloaded" in low or "529" in low:
        return 503
    if "rate limit" in low or "429" in low or "quota" in low:
        return 429
    # Budget agent épuisé côté serveur — deux formulations acceptées :
    #  - legacy : "Limite de N tours atteinte sans résultat."
    #  - actuelle (2026-04-21) : "Budget de raisonnement épuisé sans résultat."
    if (
        ("tours atteinte" in low)
        or ("raisonnement épuisé" in low)
        or ("limite de" in low and "tours" in low)
        or ("budget" in low and "épuisé" in low)
    ):
        return 504
    return 422


#: Classification PRIMAIRE par ``error_kind`` machine-readable (fix
#: 2026-06-11) : les retours d'erreur de ``run_copilot_agent`` portent un
#: kind explicite — fini les décisions machine prises sur des substrings de
#: messages français destinés aux humains (source du bug « cancel → 422 »
#: et de l'incohérence 504/500 du fail-closed max_turns).
#: ``_classify_service_error`` reste le fallback legacy pour les retours
#: non encore tagués.
_ERROR_KIND_TO_STATUS: Dict[str, int] = {
    "overloaded": 503,
    "rate_limit": 429,
    "llm_truncated": 422,
    "no_terminal": 422,
    "abandon": 422,
    "budget_exhausted": 504,
    "internal": 500,
}


def _status_for_service_error(result: Dict[str, Any], error_text: str) -> int:
    """Code HTTP d'un résultat d'erreur service — kind d'abord, legacy ensuite."""
    kind = result.get("error_kind")
    if isinstance(kind, str) and kind in _ERROR_KIND_TO_STATUS:
        return _ERROR_KIND_TO_STATUS[kind]
    if error_text == _Messages.INTERNAL_ERROR:
        # Bug serveur (exception inattendue) — 500 pour les métriques 5xx.
        return 500
    return _classify_service_error(error_text)


# ── Décorateur local d'autorisation ───────────────────────────────────────


def _copilot_authorized(
    method: Callable[..., Awaitable[Any]],
) -> Callable[..., Awaitable[Any]]:
    """Décorateur : exige un user connecté avec rôle ``admin`` ou ``user``.

    Diffère de :func:`app.handlers.base.require_role` parce qu'il émet
    ``{"error": "..."}`` (string) au lieu de
    ``{"error": true, "message": "..."}`` — nécessaire pour que
    ``iris-grid.js`` affiche le message utilisateur tel quel (``data.error``
    est lu comme string dans 4 call-sites).

    Fail-closed :

    * ``current_user is None`` → 401
    * ``role not in {ADMIN, USER}`` → 403
    * Future ``READER`` (ex : ajout du rôle) → 403 automatique (allowlist
      :data:`_ALLOWED_ROLES`).
    """

    @functools.wraps(method)
    async def wrapper(self: BaseHandler, *args: Any, **kwargs: Any) -> Any:
        user = self.current_user
        if not user:
            self.write_json({"error": _Messages.AUTH_REQUIRED}, 401)
            return None
        if user.role not in _ALLOWED_ROLES:
            logger.warning(
                "Tentative d'accès copilot par rôle non autorisé",
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "user_id": user.id,
                    "role": user.role.value if hasattr(user.role, "value") else str(user.role),
                },
            )
            self.write_json({"error": _Messages.FORBIDDEN}, 403)
            return None
        return await method(self, *args, **kwargs)

    return wrapper


# ── Parsing body partagé ──────────────────────────────────────────────────


def _parse_body_or_error(handler: BaseHandler) -> dict[str, Any] | None:
    """Parse le body JSON ; émet la réponse 400/413 et retourne ``None`` si invalide.

    Pré-check ``Content-Length`` avant désérialisation : économise une copie
    RAM + bloquage event-loop sur un body pathologique. Un header malformé
    (non-numérique) ne fait pas planter — on laisse ``json.loads`` trancher.

    Le shape attendu est un ``dict`` au top-level. Un tableau top-level (ex:
    ``[1, 2, 3]``) est rejeté — le code aval fait ``body.get(...)`` et
    crasherait en ``AttributeError``.
    """
    content_length_raw = handler.request.headers.get("Content-Length")
    if content_length_raw:
        try:
            if int(content_length_raw) > _BODY_MAX_BYTES:
                handler.write_json({"error": _Messages.BODY_TOO_LARGE}, 413)
                return None
        except ValueError:
            # Header malformé : laisser la garde autoritative ci-dessous trancher.
            pass

    # Garde AUTORITATIVE sur le body réellement reçu : ``Content-Length`` est
    # absent en ``Transfer-Encoding: chunked`` → le pré-check ci-dessus est
    # alors sauté et ``json.loads`` recevrait jusqu'à ``max_body_size`` (4 GiB).
    # ``len`` sur bytes est O(1), sans copie.
    if len(handler.request.body) > _BODY_MAX_BYTES:
        handler.write_json({"error": _Messages.BODY_TOO_LARGE}, 413)
        return None

    try:
        parsed = json.loads(handler.request.body)
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError, ValueError) as exc:
        logger.info(
            "Body JSON invalide",
            extra={
                "request_id": getattr(handler, "request_id", "?"),
                "err_class": exc.__class__.__name__,
            },
        )
        handler.write_json({"error": _Messages.INVALID_JSON}, 400)
        return None

    if not isinstance(parsed, dict):
        handler.write_json({"error": _Messages.INVALID_JSON}, 400)
        return None

    return parsed


def _rate_limit_key(handler: BaseHandler, prefix: str) -> str:
    """Construit la clé rate-limit : ``<prefix>:<user_id>`` ou fallback IP.

    Fail-closed : si ni user ni IP (tests unitaires, requête forgée), on
    retourne ``<prefix>:anonymous`` qui partage un seul bucket → rate-limit
    strict pour les cas exotiques.
    """
    user = getattr(handler, "current_user", None)
    user_id = getattr(user, "id", None) if user else None
    if user_id is not None:
        return f"{prefix}:{user_id}"
    ip = handler.request.remote_ip or "anonymous"
    return f"{prefix}:ip:{ip}"


# ── Handler : modification de résultat SQL ───────────────────────────────


class ResultModifyHandler(BaseHandler):
    """Modifie un résultat SQL selon une instruction en langage naturel.

    Deux flux internes distincts (pas de bascule silencieuse entre eux) :

    * ``is_auto_fill=True`` → chemin one-shot (``modify_result``) : plus
      rapide, pas de tool-loop, pour les suggestions « ghost » sur cellule
      vide.
    * ``is_auto_fill=False`` → agent tool-loop
      (``run_copilot_agent``) : MAX_TURNS tours max, peut manipuler le
      classeur via ``emit_tab``/``patch_tab``/``ask_iris``/etc.

    Si ``run_copilot_agent`` échoue (crash ou tours épuisés), l'erreur
    remonte brute à l'utilisateur — elle n'est pas masquée par un repli
    sur ``modify_result`` qui ne saurait pas utiliser les tools du
    copilot_agent.

    Cancellation : si le client ferme l'onglet pendant un run long,
    ``on_connection_close`` propage un ``task.cancel()`` au runtime
    copilot via le store. Sans ça, le serveur continue à brûler les
    tokens LLM (40 tours × $0.50–1.00) jusqu'à terminal naturel.
    """

    def initialize(self) -> None:
        # Stocke (run_id, user_id) du run en cours pour que
        # ``on_connection_close`` (sync, appelé par Tornado quand le client
        # ferme) sache quel task canceller. Vide tant que post() n'a pas
        # avancé jusqu'à l'appel _run_agent.
        self._copilot_run_id: str = ""
        self._copilot_user_id: Any = None
        # Capture l'IOLoop courant au moment où Tornado instancie le handler
        # (donc dans le contexte de la coroutine HTTP). ``on_connection_close``
        # peut être appelé hors de ce contexte (notamment lors de la
        # fermeture côté serveur via threadpool) où ``IOLoop.current()``
        # retournerait un loop différent — voire lèverait. On garde la
        # référence stable ici.
        try:
            self._copilot_ioloop = tornado.ioloop.IOLoop.current()
        except Exception:  # noqa: BLE001
            self._copilot_ioloop = None
        super_init = getattr(super(), "initialize", None)
        if callable(super_init):
            super_init()

    def on_connection_close(self) -> None:
        """Tornado appelle ça (sync) quand le client raccroche en plein run.

        On schedule un ``cancel_task`` async via l'IOLoop mémorisé dans
        ``initialize`` — on ne peut pas await ici. Le runtime copilot
        lèvera ``CancelledError`` à sa prochaine ``await`` (typiquement
        le call_llm_with_tools du tour suivant). Idempotent si run_id
        absent (post() n'a pas démarré le run, rien à canceller).
        """
        run_id = self._copilot_run_id
        user_id = self._copilot_user_id
        ioloop = getattr(self, "_copilot_ioloop", None)
        if run_id and user_id is not None and ioloop is not None:
            try:
                from app.services.ai.copilot_progress_store import cancel_task

                ioloop.add_callback(cancel_task, user_id, run_id)
            except Exception:  # noqa: BLE001 — on_connection_close ne doit jamais throw
                logger.debug(
                    "on_connection_close: cancel_task scheduling échoué",
                    exc_info=True,
                )
        super().on_connection_close()

    @_copilot_authorized
    async def post(self) -> None:
        body = _parse_body_or_error(self)
        if body is None:
            return

        # gap2 — l'auto-fill « ghost » (``is_auto_fill=True`` : one-shot
        # ``modify_result``, 1 appel LLM léger) et le copilot EXPLICITE
        # (``is_auto_fill=False`` : agent tool-loop ~40 appels, coûteux) ont des
        # coûts TRÈS différents et NE doivent PAS partager le même bucket : sinon un
        # auto-fill en rafale (ex. 50 cellules) épuise le quota copilot explicite de
        # l'user (5/min) → l'action chère qu'on voulait protéger est bloquée par
        # l'action légère (et inversement). On route le rate-limit PAR MODE, en
        # réutilisant les SSoT déjà définies :
        #   • explicite → ``_copilot_rate_limiter`` (5/min, cher) ;
        #   • auto-fill → ``_suggest_rate_limiter`` (20/min, léger — la doc de
        #     ``_SUGGEST_RATE_MAX`` dimensionne précisément l'auto-fill), clé
        #     « autofill » DISTINCTE de l'endpoint /suggest (pas de nouvelle
        #     interférence). ``is_auto_fill`` remonté AVANT le gate.
        is_auto_fill = bool(body.get("is_auto_fill"))
        if is_auto_fill:
            if not _suggest_rate_limiter.check(
                _rate_limit_key(self, "autofill"),
                _SUGGEST_RATE_MAX,
                _SUGGEST_RATE_WINDOW_S,
            ):
                self.write_json({"error": _Messages.RATE_LIMITED_SUGGEST}, 429)
                return
        elif not _copilot_rate_limiter.check(
            _rate_limit_key(self, "copilot"),
            _COPILOT_RATE_MAX,
            _COPILOT_RATE_WINDOW_S,
        ):
            self.write_json({"error": _Messages.RATE_LIMITED_COPILOT}, 429)
            return

        sql = _coerce_str(body.get("sql"))
        instruction_raw = body.get("instruction")

        # Validation instruction : auto-fill peut être sans instruction
        # (le service devine depuis le contexte), sinon on exige un texte
        # utile et borné.
        if not is_auto_fill:
            if not isinstance(instruction_raw, str) or not instruction_raw.strip():
                self.write_json({"error": _Messages.INSTRUCTION_REQUIRED}, 400)
                return
            if len(instruction_raw) > _INSTR_MAX_LEN:
                self.write_json({"error": _Messages.INSTRUCTION_TOO_LONG}, 400)
                return
            instruction = instruction_raw.strip()
            if len(instruction) < _INSTR_MIN_LEN:
                self.write_json({"error": _Messages.INSTRUCTION_TOO_SHORT}, 400)
                return
        else:
            instruction = _coerce_str(instruction_raw)

        columns = _coerce_list(body.get("columns")) or []
        display_state = _coerce_dict(body.get("display_state")) or {}
        tabs_context = _coerce_list(body.get("tabs_context"))
        sheet_content = _coerce_list(body.get("sheet_content"))
        sheet_context = _coerce_dict(body.get("sheet_context"))

        # Mode "workbook by reference" : le frontend envoie ``workbook_path``
        # (rel_path dans son datastore) au lieu d'envoyer ``tabs_context`` /
        # ``sheet_content`` inline. On lit le ``.afz.json`` côté backend et
        # on reconstruit le contexte via le loader dédié — pas de cap réseau,
        # ce qui permet de gérer des classeurs gigantesques (Excel-Online-like).
        # Si à la fois ``workbook_path`` ET ``tabs_context`` inline sont
        # fournis, ``workbook_path`` prime (le storage est la source de
        # vérité, l'inline était un fallback legacy).
        workbook_path_raw = body.get("workbook_path")
        if isinstance(workbook_path_raw, str) and workbook_path_raw.strip():
            from app.services.ai.copilot_workbook_loader import (
                load_workbook_for_copilot,
            )

            user_id = getattr(self.current_user, "id", None)
            if user_id is None:
                # ``_copilot_authorized`` garantit ``current_user`` ; mais on
                # vérifie defensively pour éviter un crash sur un mock test.
                self.write_json(
                    {"error": "Utilisateur non identifié."},
                    401,
                )
                return
            # **Hors event loop** (fix 2026-06-11, sweep Moyen confirmé) : la
            # lecture + décompression gzip + parse JSON + conversion d'un
            # gros .afz.json (plusieurs Mo, gzippé ~20×) est synchrone — la
            # laisser dans la coroutine gelait tout Tornado le temps du load.
            # La fonction est PURE (path scoped user → listes fraîches, aucun
            # état partagé) → thread-safe. Pool par défaut adapté (IO court,
            # même pattern que datastore.py).
            loaded = await asyncio.to_thread(
                load_workbook_for_copilot, user_id, workbook_path_raw.strip()
            )
            if loaded is None:
                self.write_json(
                    {
                        "error": (
                            "workbook_path invalide ou inaccessible "
                            "(chemin hors datastore, fichier absent, ou "
                            "format non-supporté)."
                        ),
                        "error_code": "WORKBOOK_PATH_INVALID",
                    },
                    400,
                )
                return
            loaded_tabs, loaded_sheet, _active_idx, raw_workbook = loaded
            tabs_context = loaded_tabs
            sheet_content = loaded_sheet
            # Récupère ``copilot_memory`` depuis le ``.afz.json`` si présent —
            # le frontend n'a plus à le re-poster.
            if not body.get("copilot_memory"):
                mem = raw_workbook.get("copilot_memory") if isinstance(raw_workbook, dict) else None
                if isinstance(mem, str):
                    body["copilot_memory"] = mem[:5000]
        # Le body peut transporter un ``anonymization_state`` mais la source
        # de vérité prod est la BDD (``anonymization_terms``). Quand
        # ``user_id`` est connu (toujours vrai ici grâce au décorateur auth),
        # on IGNORE le champ body et on lit la BDD en aval — ``run_copilot_agent``
        # s'en occupe. On GARDE la validation de shape au cas où le client
        # enverrait quand même, pour remonter un 400 actionable plutôt que
        # de laisser passer silencieusement un état malformé.
        anonymization_state = _coerce_dict(body.get("anonymization_state"))
        if anonymization_state is not None:
            from app.services.anonymization import extract as _anon_terms

            state_errors = _anon_terms.validate_state(anonymization_state)
            if state_errors:
                # Sanitize au lieu de rejeter (cohérent avec le PUT handler).
                # Un terme corrompu (pseudo invalide, type mismatch) est
                # stripé plutôt que de bloquer le copilot send. Les erreurs
                # sont logguées pour audit ; le caller peut tjrs corriger
                # via le panneau s'il veut un état différent.
                logger.warning(
                    "anonymization_state invalide — %d erreurs sanitizées",
                    len(state_errors),
                    extra={
                        "request_id": getattr(self, "request_id", "?"),
                        "error_count": len(state_errors),
                    },
                )
                anonymization_state = _anon_terms.sanitize_state(anonymization_state)

        # ── Gate d'anonymisation AVANT branching is_auto_fill ──
        # Le chemin auto-fill (``modify_result``) n'applique PAS le
        # pseudonymizer aujourd'hui. Pour éviter une fuite cleartext vers
        # le LLM en contournant le opt-in utilisateur, on refuse l'auto-fill
        # dès qu'un terme avec ``enabled=True`` existe en BDD. Le copilot
        # tool-loop (run_copilot_agent) applique l'anonymisation correctement,
        # donc il n'est pas impacté par ce check.
        if is_auto_fill:
            try:
                from app.services.anonymization import repository as _anon_repo
                from app.services.anonymization import extract as _anon_terms

                user_id = self.current_user.id
                async with self.db_session() as session:
                    stored_state = await _anon_repo.get_state_for_user(session, user_id)
                any_enabled = any(
                    entry.get("enabled", False)
                    for entry in (stored_state.get("terms") or {}).values()
                    if isinstance(entry, dict)
                )
                any_pending = _anon_terms.has_pending_review(stored_state)
                if any_enabled or any_pending:
                    # On refuse l'auto-fill plutôt que de leaker. L'utilisateur
                    # peut soit utiliser la barre copilot explicite (qui applique
                    # l'anonymisation), soit désactiver ses termes via le
                    # panneau de confidentialité s'il accepte le leak.
                    self.write_json(
                        {
                            "error": (
                                "Auto-fill désactivé car des termes sont "
                                "configurés pour être anonymisés. Utilisez la "
                                "barre copilot pour bénéficier de "
                                "l'anonymisation."
                            ),
                            "error_code": "ANON_BLOCKS_AUTOFILL",
                        },
                        409,
                    )
                    return
            except Exception:  # noqa: BLE001
                # Fail-closed : si on ne peut pas vérifier le state, on
                # refuse l'auto-fill (mieux vaut dégrader la feature que
                # leaker).
                logger.exception(
                    "anonymization gate auto-fill : lecture state échouée, "
                    "refuse l'auto-fill par défaut"
                )
                self.write_json(
                    {
                        "error": "Impossible de vérifier l'état de confidentialité.",
                        "error_code": "ANON_GATE_ERROR",
                    },
                    503,
                )
                return

        # run_id : identifiant du run copilot pour le polling de progress
        # (todo-list). Généré côté frontend (crypto.randomUUID() ou fallback).
        # Facultatif : si absent ou mal formé, le run tourne normalement mais
        # le store de progress ne sera pas synchronisé (polling retournera
        # null, frontend affichera juste "Modification en cours…").
        run_id_raw = body.get("run_id")
        if isinstance(run_id_raw, str) and _RUN_ID_RE.match(run_id_raw):
            run_id = run_id_raw
        else:
            run_id = ""

        # copilot_memory : résumé factuel laissé par un run copilot PRÉCÉDENT
        # sur le même classeur (persisté par le frontend dans la racine du
        # ``.afz.json``, relu et renvoyé dans chaque POST). Facultatif — un
        # classeur neuf n'en a pas. Validation stricte : on le coerce en
        # str, on cap à 5000 chars (2.5× le cap interne ``_MEMORY_MAX_OUTPUT_CHARS``
        # pour tolérer une marge sans accepter un blob DoS). Le service va
        # re-sanitize à l'injection (strip markdown / accolades / délimiteurs).
        copilot_memory_raw = body.get("copilot_memory")
        if isinstance(copilot_memory_raw, str):
            copilot_memory = copilot_memory_raw[:5000]
        else:
            copilot_memory = ""

        # selected_cells : cellules sélectionnées par l'user au clic Send.
        # Coords 0-based, capées à 200 côté front, on re-cap ici (defense-
        # in-depth) et on filtre les entrées malformées. Format normalisé :
        # list[{r: int, c: int}] avec r,c >= 0.
        selected_cells: list[dict[str, int]] = []
        raw_selected = body.get("selected_cells")
        # #18f (triage caps 2026-06-10) — au-delà de 200 cellules, la
        # sélection est COUPÉE : sans log, le copilot transforme une partie
        # de la sélection et l'utilisateur croit l'opération complète.
        if isinstance(raw_selected, list) and len(raw_selected) > 200:
            logger.warning(
                "selected_cells tronquées : %d reçues, 200 transmises au "
                "copilot — transformation potentiellement partielle",
                len(raw_selected),
                extra={"request_id": getattr(self, "request_id", "?")},
            )
        if isinstance(raw_selected, list):
            for item in raw_selected[:200]:
                if not isinstance(item, dict):
                    continue
                r_val = item.get("r")
                c_val = item.get("c")
                if not isinstance(r_val, int) or isinstance(r_val, bool):
                    continue
                if not isinstance(c_val, int) or isinstance(c_val, bool):
                    continue
                if r_val < 0 or c_val < 0:
                    continue
                selected_cells.append({"r": r_val, "c": c_val})

        # Guard B4 : rejet « ghost/init » — le front peut émettre un POST
        # avant que la grille soit hydratée. Ces appels coûtent un aller-
        # retour LLM pour zéro résultat utilisable → refus strict.
        if not sheet_content and not tabs_context:
            logger.debug(
                "Rejet B4: ni sheet_content ni tabs_context",
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            self.write_json({"error": _Messages.NO_SHEET_CONTEXT}, 422)
            return

        if not _has_any_sql(sql, tabs_context):
            self.write_json({"error": _Messages.NO_SQL_CONTEXT}, 422)
            return

        if is_auto_fill:
            result = await self._run_one_shot(
                sql=sql,
                instruction=instruction,
                columns=columns,
                display_state=display_state,
                tabs_context=tabs_context,
                sheet_content=sheet_content,
                sheet_context=sheet_context,
                is_auto_fill=True,
                user_id=self.current_user.id,
            )
        else:
            # ``workbook_ref`` : si le frontend a envoyé ``workbook_path``,
            # on tag les nouveaux termes auto-détectés avec source="workbook"
            # + ce ref pour le grouping par provenance dans /data/privacy.
            # Sinon (mode legacy inline tabs), pas de ref → upsert garde le
            # default ``"manual"`` côté repository.
            workbook_ref = (
                workbook_path_raw.strip()
                if isinstance(workbook_path_raw, str) and workbook_path_raw.strip()
                else None
            )
            # Mémorise (run_id, user_id) pour que on_connection_close puisse
            # canceller le bon task si le client ferme l'onglet en cours.
            self._copilot_run_id = run_id
            self._copilot_user_id = self.current_user.id
            result = await self._run_agent(
                sql=sql,
                instruction=instruction,
                columns=columns,
                display_state=display_state,
                tabs_context=tabs_context,
                sheet_content=sheet_content,
                sheet_context=sheet_context,
                run_id=run_id,
                user_id=self.current_user.id,
                anonymization_state=anonymization_state,
                copilot_memory=copilot_memory,
                workbook_ref=workbook_ref,
                selected_cells=selected_cells if selected_cells else None,
                user=self.current_user,
            )

        if not isinstance(result, dict):
            logger.error(
                "Service a renvoyé un non-dict",
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "result_type": type(result).__name__,
                },
            )
            self.write_json({"error": _Messages.INTERNAL_ERROR}, 500)
            return

        # Gate d'anonymisation : le service refuse l'appel LLM tant que des
        # termes ne sont pas confirmés par l'utilisateur. On mappe vers 409
        # Conflict (le state client a besoin d'être synchronisé avant de
        # rejouer) avec le shape structuré intact pour que le frontend
        # ouvre le panneau sur les pending_terms.
        if result.get("error_code") == "ANON_PENDING_REVIEW":
            self.write_json(result, 409)
            return

        # Aucun provider LLM configuré (cloud + local tous deux absents) :
        # 503 Service Unavailable + payload structuré que ``iris-grid.js``
        # détecte (``reason="not_configured"``) pour afficher un toast
        # ciblé au lieu de l'erreur générique "Erreur interne".
        # Position : AVANT le check ``type`` plus bas, car ce shape n'a
        # volontairement pas de ``type`` (skipped=True).
        if result.get("reason") == "not_configured":
            payload = {
                "error": result.get("message") or _Messages.LLM_NOT_CONFIGURED,
                "reason": "not_configured",
                "skipped": True,
            }
            self.write_json(payload, 503)
            return

        # **Cancel utilisateur → 200** (fix 2026-06-11) : ``{"type":
        # "cancelled", "error": "Run annulé."}`` passait dans la
        # classification d'erreur (le check ``error`` précédait le check
        # ``type``) → 422 pour une annulation VOLONTAIRE, métriques 4xx
        # polluées. L'UX front lisait déjà ``type`` en premier — seul le
        # code HTTP était faux. Court-circuit AVANT la branche erreur.
        if result.get("type") == "cancelled":
            self.write_json(result, 200)
            return

        error_text = result.get("error")
        # Une string non vide → erreur métier classifiée (kind machine-readable
        # d'abord, substring legacy en fallback — cf. _status_for_service_error).
        if isinstance(error_text, str) and error_text:
            status = _status_for_service_error(result, error_text)
            self.write_json(result, status)
            return

        # Réponse "success" : le contrat avec iris-grid.js exige que le dict
        # porte un champ ``type`` (sql / fill / fill_sql / display /
        # clone_sheet / emit_tab / patch_tab / rename_tab / delete_tab).
        # Un dict vide ``{}`` ou un dict qui contient uniquement ``error=""``
        # passerait 200 silencieusement côté handler mais le front ne
        # dispatcherait rien → toast "Modification appliquée" trompeur.
        # On traite ce cas comme un bug interne (pas une erreur utilisateur).
        if not is_auto_fill and not isinstance(result.get("type"), str):
            logger.error(
                "Service a renvoyé un dict sans `type` ni `error` — bug interne",
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "result_keys": list(result.keys()),
                },
            )
            self.write_json({"error": _Messages.INTERNAL_ERROR}, 500)
            return

        self.write_json(result, 200)

    async def _run_agent(
        self,
        *,
        sql: str,
        instruction: str,
        columns: list[str],
        display_state: dict[str, Any],
        tabs_context: list[dict[str, Any]] | None,
        sheet_content: list[dict[str, Any]] | None,
        sheet_context: dict[str, Any] | None,
        run_id: str,
        user_id: Any,
        anonymization_state: dict[str, Any] | None = None,
        copilot_memory: str = "",
        workbook_ref: str | None = None,
        selected_cells: list[dict[str, int]] | None = None,
        user: Any = None,
    ) -> dict[str, Any]:
        """Lance ``run_copilot_agent``. En cas de crash, retourne une erreur
        brute ; l'utilisateur voit la vraie cause au lieu d'un résultat dégradé
        par un fallback muet.

        Le ``run_id`` (optionnel) indexe le store de progress pour permettre
        au frontend de poller la todo-list du LLM pendant le run. Couplé à
        ``user_id`` pour empêcher un leak cross-user. Cleanup systématique
        en finally pour éviter une fuite mémoire si le run crash avant
        d'atteindre sa fin normale.

        Cancellation : si l'utilisateur clique Stop OU ferme l'onglet,
        ``cancel_task(user_id, run_id)`` est appelé (via POST /result-cancel
        OU ``on_connection_close``). Le ``asyncio.CancelledError`` remonte
        ici et on retourne un résultat ``type=cancelled`` plutôt qu'une
        exception — le client a déjà raccroché, mais c'est un signal propre
        pour les logs + cas où on voudrait audit-trail la cancellation.
        """
        from app.services.ai.copilot_progress_store import (
            claim_run,
            finalize_run,
            register_task,
        )

        # IDEMPOTENCE : si un POST arrive avec un (user_id, run_id) déjà
        # en cours (double-clic Send, retry réseau client), on await le
        # résultat du 1er appel au lieu de relancer un appel LLM payant.
        # ``claim_run`` retourne (is_owner, future) :
        #  - is_owner=True : on est le 1er, on fait le boulot
        #  - is_owner=False : un autre POST a déjà claim, on await
        # Sans run_id ou user_id valide, claim_run retourne is_owner=True
        # avec une Future locale → comportement legacy (pas de dedup).
        is_owner, inflight_future = await claim_run(user_id, run_id)
        if not is_owner:
            logger.info(
                "Idempotence : POST doublon sur (user=%s, run=%s) — "
                "await du résultat du 1er appel.",
                user_id,
                run_id,
            )
            # Filet de sécurité : si le 1er appel reste bloqué (crash sans
            # release_run, lock saturé), on ne veut pas que les doublons
            # restent suspendus 30min jusqu'au TTL serveur. Timeout 5min
            # = bien au-delà de la durée max d'un run normal (40 tours ×
            # ~30s) mais nettement sous le TTL inflight (30min).
            try:
                return await asyncio.wait_for(inflight_future, timeout=300)
            except asyncio.TimeoutError:
                logger.warning(
                    "Idempotence : timeout 300s sur Future (user=%s, run=%s) "
                    "— le 1er appel est resté bloqué.",
                    user_id,
                    run_id,
                )
                return {"error": _Messages.INTERNAL_ERROR, "error_kind": "internal"}
            except asyncio.CancelledError:
                # NB : depuis le fix adversarial, l'owner passe un dict
                # `{type:cancelled}` via set_result, pas set_exception.
                # CancelledError ici signifie que NOTRE coro a été cancellée
                # (ex: notre client a raccroché aussi). Propager.
                raise
            except Exception:  # noqa: BLE001
                logger.debug(
                    "Idempotence : 1er appel a levé, propagation au doublon",
                    exc_info=True,
                )
                return {"error": _Messages.INTERNAL_ERROR, "error_kind": "internal"}

        # Variables pour partage entre try et finally (résultat à
        # release_run pour les doublons en attente). Default sain en cas
        # de crash très précoce (avant l'assignation effective).
        result_for_release: Any = {"error": _Messages.INTERNAL_ERROR, "error_kind": "internal"}
        registered_task: Any = None
        try:
            # Register le Task courant DANS le try pour que le finally
            # release_run s'exécute même si register_task lève. Sans ça,
            # un crash entre claim et register laissait les awaiters
            # bloqués 30min (TTL inflight).
            if run_id and user_id is not None:
                registered_task = asyncio.current_task()
                if registered_task is not None:
                    await register_task(user_id, run_id, registered_task)

            result_for_release = await run_copilot_agent(
                sql=sql,
                instruction=instruction,
                columns=columns,
                display_state=display_state,
                tabs_context=tabs_context,
                sheet_content=sheet_content,
                sheet_context=sheet_context,
                is_auto_fill=False,
                run_id=run_id,
                user_id=user_id,
                anonymization_state=anonymization_state,
                copilot_memory=copilot_memory,
                workbook_ref=workbook_ref,
                selected_cells=selected_cells,
                user=user,
            )
            return result_for_release
        except asyncio.CancelledError:
            logger.info(
                "Copilot run %s cancellé (user_id=%s)",
                run_id or "?",
                user_id if user_id is not None else "?",
            )
            # NE PAS re-raise : le client a raccroché ou demandé Stop.
            # **Pas d'exception aux awaiters** : on leur passe le dict
            # cancelled via set_result. Une CancelledError propagée à
            # un awaiter annulerait sa propre coro (BaseException).
            result_for_release = {"type": "cancelled", "error": "Run annulé."}
            return result_for_release
        except Exception:  # noqa: BLE001 — jamais de leak au client
            logger.exception(
                "run_copilot_agent a crashé",
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            result_for_release = {"error": _Messages.INTERNAL_ERROR, "error_kind": "internal"}
            return result_for_release
        finally:
            # Cleanup de fin de run en UNE Task INDÉPENDANTE (fix
            # 2026-06-11, tâche #14). L'ancien pattern (3 awaits shieldés
            # successifs, chacun avec ``except CancelledError: raise``)
            # avait un trou : une cancellation ré-entrante (2e clic Stop
            # PENDANT le finally) levait au 1er await et SAUTAIT les
            # cleanups suivants — la fuite ``_tasks``/``_store`` que les
            # shields prétendaient empêcher. ``create_task`` détache la
            # séquence de cleanup de NOTRE cancellation : elle va au bout
            # dans tous les cas (release → unregister → clear, chaque
            # étape isolée dans finalize_run). Le shield ne sert qu'à
            # attendre poliment ; si on est re-cancellé, la Task continue
            # en arrière-plan et la CancelledError se propage.
            if run_id and user_id is not None:
                cleanup_task = asyncio.create_task(
                    finalize_run(
                        user_id,
                        run_id,
                        result=result_for_release,
                        task=registered_task,
                    )
                )
                # Consomme l'exception éventuelle de la Task détachée
                # (review #14) : si on est re-cancellé pendant le shield,
                # plus personne ne l'await — sans ce callback, une
                # BaseException résiduelle deviendrait un warning asyncio
                # « Task exception was never retrieved ».
                cleanup_task.add_done_callback(
                    lambda t: t.exception() if not t.cancelled() else None
                )
                try:
                    await asyncio.shield(cleanup_task)
                except asyncio.CancelledError:
                    raise  # cleanup_task indépendante — elle finira seule
                except Exception:
                    logger.debug(
                        "finalize_run non critique a levé",
                        exc_info=True,
                    )

    async def _run_one_shot(
        self,
        *,
        sql: str,
        instruction: str,
        columns: list[str],
        display_state: dict[str, Any],
        tabs_context: list[dict[str, Any]] | None,
        sheet_content: list[dict[str, Any]] | None,
        sheet_context: dict[str, Any] | None,
        is_auto_fill: bool,
        user_id: Any = None,
    ) -> dict[str, Any]:
        """Appel direct ``modify_result`` (auto-fill ghost). Try/except propre."""
        try:
            return await modify_result(
                sql=sql,
                instruction=instruction,
                columns=columns,
                display_state=display_state,
                tabs_context=tabs_context,
                sheet_content=sheet_content,
                is_auto_fill=is_auto_fill,
                sheet_context=sheet_context,
                user_id=user_id,
            )
        except Exception:  # noqa: BLE001 — fail-safe user-visible
            logger.exception(
                "modify_result one-shot a crashé",
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            return {"error": _Messages.INTERNAL_ERROR, "error_kind": "internal"}


# ── Handler : suggestions de remplissage de cellule ──────────────────────


class CellSuggestHandler(BaseHandler):
    """Génère des suggestions pour remplir une cellule.

    Si le sheet analyzer détermine programmatiquement la cellule avec
    confiance, retourne 1 seule suggestion (pas d'appel LLM). Sinon,
    fallback vers ~6 suggestions via LLM — le service gère la bascule.
    """

    @_copilot_authorized
    async def post(self) -> None:
        body = _parse_body_or_error(self)
        if body is None:
            return

        if not _suggest_rate_limiter.check(
            _rate_limit_key(self, "suggest"),
            _SUGGEST_RATE_MAX,
            _SUGGEST_RATE_WINDOW_S,
        ):
            self.write_json({"error": _Messages.RATE_LIMITED_SUGGEST}, 429)
            return

        column_name = _coerce_str(body.get("column_name"), max_len=_INSTR_MAX_LEN)
        cell_position = _coerce_dict(body.get("cell_position"))
        columns = _coerce_list(body.get("columns"))
        tabs_context = _coerce_list(body.get("tabs_context"))
        sheet_content = _coerce_list(body.get("sheet_content"))

        try:
            result = await suggest_cell_values(
                column_name=column_name,
                cell_position=cell_position,
                columns=columns,
                sheet_content=sheet_content,
                tabs_context=tabs_context,
                user_id=self.current_user.id,
            )
        except Exception:  # noqa: BLE001 — fail-safe user-visible
            logger.exception(
                "suggest_cell_values a crashé",
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            self.write_json({"error": _Messages.INTERNAL_ERROR}, 500)
            return

        if not isinstance(result, dict):
            logger.error(
                "suggest_cell_values a renvoyé un non-dict",
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "result_type": type(result).__name__,
                },
            )
            self.write_json({"error": _Messages.INTERNAL_ERROR}, 500)
            return

        # Aucun provider LLM configuré : 503 + payload structuré (cf.
        # ResultModifyHandler pour le rationale détaillé).
        if result.get("reason") == "not_configured":
            payload = {
                "error": result.get("message") or _Messages.LLM_NOT_CONFIGURED,
                "reason": "not_configured",
                "skipped": True,
                "suggestions": [],
            }
            self.write_json(payload, 503)
            return

        error_text = result.get("error")
        if isinstance(error_text, str) and error_text:
            if error_text == _Messages.INTERNAL_ERROR:
                status = 500
            else:
                status = _classify_service_error(error_text)
            self.write_json(result, status)
            return

        self.write_json(result, 200)


# ── Handler : progress polling (todo-list du copilot en cours) ───────────

#: Outils du copilote qui ne représentent **pas** une action concrète
#: utilisateur — leur affichage dans le bandeau de progress polluerait l'UX
#: sans apporter d'info utile ("Mise à jour du plan…", "Fin du tour…").
#:
#: SSOT pour le test de garde
#: :func:`tests.unit.test_result_assistant.test_every_user_facing_copilot_tool_has_label`
#: qui contraint :data:`CopilotTaskProgressHandler._TOOL_LABELS` à couvrir
#: ``COPILOT_TOOLS \ _META_COPILOT_TOOLS``.
#:
#: Régression évitée : 2026-05-22 — ``modify_tab_sql`` (action principale d'un
#: run "modifier ce SQL") manquait silencieusement → l'utilisateur voyait
#: "Modification en cours…" pendant 25-30s sans signal de progrès.
_META_COPILOT_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "abandon",
        "done",
        "plan_add",
        "plan_update",
        "plan_list",
        "explain_substitution",
    }
)


class CopilotTaskProgressHandler(BaseHandler):
    """Retourne l'état courant de la todo-list du run copilot identifié par
    ``run_id``. Polled par le frontend toutes les 1s pendant un run pour
    afficher la task `in_progress` dans le bandeau de la grille.

    Contrat :
        GET /api/iris/task-progress?run_id=<uuid>

    Réponse (toujours 200, jamais 404 — pas de bruit côté frontend) :
        {
          "task_in_progress": {"id": int, "subject": str} | null,
          "plan_size": int,  # nombre total de tasks (tous statuts)
        }

    - ``task_in_progress == null`` : aucune task en status `in_progress`, OU
      run inconnu/terminé. Le frontend retombe sur le texte défaut.
    - ``plan_size == 0`` : le LLM n'a posé aucune task. Pas d'erreur.
    """

    # Mapping technical tool name → label utilisateur français. Centralisé
    # ici (pas côté store) pour faciliter l'évolution sans coupler le runtime.
    # Les tools internes listés dans :data:`_META_COPILOT_TOOLS` ne sont PAS
    # mappés → ne s'affichent pas côté frontend (bruit inutile pour l'user).
    _TOOL_LABELS: Final[dict[str, str]] = {
        "list_tabs": "Liste des onglets",
        "read_tab_rows": "Lecture onglet",
        "count_rows": "Comptage",
        "aggregate": "Agrégation",
        "search_workbook": "Recherche dans le classeur",
        "ask_iris": "Génération SQL via Iris",
        "modify_tab_sql": "Modification du SQL via Iris",
        "run_python": "Exécution Python",
        "preview_emit_tab": "Aperçu de l'onglet",
        "emit_tab": "Création de l'onglet",
        "emit_via_code": "Création de l'onglet (via code)",
        "patch_tab": "Mise à jour de cellules",
        "rename_tab": "Renommage onglet",
        "delete_tab": "Suppression onglet",
        # cf. :data:`_META_COPILOT_TOOLS` pour la liste des tools meta
        # intentionnellement absents (plan_*, explain_*, done, abandon).
    }

    @_copilot_authorized
    async def get(self) -> None:
        run_id = self.get_argument("run_id", default="")
        if not isinstance(run_id, str) or not _RUN_ID_RE.match(run_id):
            # Fail-loud sur input mal formé ; mais le frontend n'est pas
            # censé envoyer un mauvais run_id sauf bug.
            self.write_json({"error": "run_id manquant ou invalide"}, 400)
            return

        from app.services.ai.copilot_progress_store import (
            get_progress,
            get_tool_in_use,
        )

        # Scope user strict : (user_id, run_id) est la clé. Un user qui
        # devine le run_id d'un autre ne peut pas lire son plan — la clé
        # ne matche pas.
        #
        # Les deux lectures prennent le lock du store SÉPARÉMENT : entre les
        # deux awaits, le run peut finir/expirer → paire plan/tool
        # momentanément incohérente. Toléré par construction : les deux
        # combinaisons (plan sans tool, tool sans plan — cf. branche
        # ``plan is None`` plus bas) sont gérées, et le polling 1s du
        # frontend s'auto-corrige au tick suivant (verdict tâche #25 :
        # pas de snapshot atomique nécessaire).
        plan = await get_progress(self.current_user.id, run_id)
        raw_tool = await get_tool_in_use(self.current_user.id, run_id)
        tool_label = self._TOOL_LABELS.get(raw_tool) if raw_tool else None
        # Garde-fou : si un nouvel outil est ajouté côté copilot_tools.py
        # sans mapping français ici, on logue (mais on n'affiche rien
        # plutôt que le raw name technique). Permet de détecter la dérive
        # via les logs serveur sans casser l'UX (review adv Medium #5).
        if raw_tool and tool_label is None:
            logger.warning(
                "CopilotTaskProgressHandler: tool '%s' absent de _TOOL_LABELS "
                "— affichage masqué côté frontend. Ajouter le mapping FR.",
                raw_tool,
            )
        if plan is None:
            # Run inconnu/terminé/expiré — signal neutre au frontend.
            # tool_label peut être présent si set_tool_in_use a écrit avant
            # set_progress (cas du run qui vient de démarrer sans plan).
            self.write_json(
                {
                    "task_in_progress": None,
                    "tool_in_use": tool_label,
                    "plan_size": 0,
                },
                200,
            )
            return

        # Choisit la task in_progress la plus RÉCEMMENT ACTIVÉE — via
        # ``updated_at`` (ajouté par plan_add/update), pas juste l'ordre
        # d'insertion. Sans ça, une task ressuscitée (plan_update d'une
        # vieille task) ne remonterait pas, alors qu'elle reflète l'attention
        # courante du LLM.
        in_progress_candidates = [t for t in plan if t.get("status") == "in_progress"]
        in_progress_task = None
        if in_progress_candidates:
            in_progress_task = max(
                in_progress_candidates,
                key=lambda t: t.get("updated_at", 0),
            )
        if in_progress_task is None:
            self.write_json(
                {
                    "task_in_progress": None,
                    "tool_in_use": tool_label,
                    "plan_size": len(plan),
                },
                200,
            )
            return

        self.write_json(
            {
                "task_in_progress": {
                    "id": in_progress_task.get("id"),
                    "subject": in_progress_task.get("subject", ""),
                },
                "tool_in_use": tool_label,
                "plan_size": len(plan),
            },
            200,
        )


# ── Handler : cancel d'un run copilot en cours ──────────────────────────


class CopilotCancelHandler(BaseHandler):
    """Cancel le run copilot identifié par ``run_id``. Appelé par le
    frontend quand l'utilisateur clique Stop dans la copilot-bar.

    Contrat :
        POST /api/iris/result-cancel
        Body: {"run_id": "<uuid>"}

    Réponse 200 idempotente :
        {"cancelled": true}   si un run vivant a été cancellé
        {"cancelled": false}  si aucun run trouvé (déjà fini, expiré,
                              run_id inconnu, ou appartient à un autre user)

    Le 200 idempotent évite les "false errors" côté frontend si l'user
    double-clic Stop ou si le run finit naturellement entre le Stop et
    le POST. Le scope user (clé composite ``(user_id, run_id)`` dans le
    store) empêche un user de canceller le run d'un autre, même s'il
    devine le run_id.
    """

    @_copilot_authorized
    async def post(self) -> None:
        body = _parse_body_or_error(self)
        if body is None:
            return

        run_id_raw = body.get("run_id")
        if not isinstance(run_id_raw, str) or not _RUN_ID_RE.match(run_id_raw):
            self.write_json({"error": "run_id manquant ou invalide"}, 400)
            return

        from app.services.ai.copilot_progress_store import cancel_task

        ok = await cancel_task(self.current_user.id, run_id_raw)
        self.write_json({"cancelled": bool(ok)}, 200)


__all__ = [
    "ResultModifyHandler",
    "CellSuggestHandler",
    "CopilotTaskProgressHandler",
    "CopilotCancelHandler",
]
