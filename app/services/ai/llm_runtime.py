"""Couche unifiée pour les call sites LLM de Komptia.

**Source de vérité unique** : 1 ``CallProfile`` par caller, 3 fonctions
publiques (``call_llm``, ``call_llm_with_tools``, ``stream_llm_with_tools``).

Encapsule ce qui était auparavant dupliqué dans 26 endroits :

* résolution dynamique du modèle selon ``ModelKind`` (PRIMARY / UTILITY / LOCAL)
* clamp ``max_tokens`` au cap du modèle réel via :func:`clamped_max_tokens`
* pose de ``llm_call_context(caller=...)`` pour le tracking ``AIPerformanceLog``
* retry exponentiel sur erreurs transitoires (429 / 5xx / network)
* mapping exception → message utilisateur en français (jamais de fuite de
  détails internes : URL, clé API, traceback)
* timeout (via :func:`asyncio.wait_for` si ``timeout_seconds`` est posé)
* validation soft de ``caller ∈ KNOWN_CALLERS`` (warning, jamais hard fail)

**Hors scope** : le caching ``cache_control`` Anthropic est posé
automatiquement par :class:`AnthropicProvider` sur tous les calls (system
prompt + tools + messages cross-turn). Le marker ``CACHE_BREAKPOINT`` reste
à la charge des callers qui veulent un split stable/variable précis dans
leur system prompt (cf. ``agent_service.py`` qui l'insère explicitement).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, AsyncIterator, Optional

import httpx

from app.constants_ai import (
    clamped_max_tokens,
    get_max_tokens_for_model,
    get_utility_model,
)
from app.services.ai.config_service import get_ai_config_service
from app.services.ai.llm_providers import (
    LLMRequest,
    LLMResponse,
    RateLimitError,
    _sanitize_for_log,
    ensure_providers_from_db,
    get_llm_manager,
)
from app.utils.request_context import llm_call_context

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums — choix de modèle et politique de retry
# ---------------------------------------------------------------------------


class ModelKind(Enum):
    """Choix du modèle, résolu dynamiquement à chaque appel.

    PRIMARY : ``LLMManager.default_model_name`` — modèle choisi par l'admin
              dans ``/admin/ai-config``. Utilisé pour les tâches qui
              demandent la meilleure qualité (Iris, copilot, planners).

    UTILITY : :func:`get_utility_model` — modèle économique du provider
              actif (Haiku-équivalent). Utilisé pour les tâches simples
              déterministes (détection de rôle, extraction concepts,
              enrichissement schéma, résumé mémoire).

    LOCAL   : :meth:`LLMManager.get_local_fallback` — Ollama configuré via
              ``/admin/ai-config → Anonymisation locale``. Utilisé pour
              l'auto-classification PII (zéro fuite cloud).
    """

    PRIMARY = "primary"
    UTILITY = "utility"
    LOCAL = "local"


class RetryPolicy(Enum):
    """Politique de retry sur erreurs transitoires (429 / 5xx / network).

    Seules ``NONE`` et ``STANDARD`` sont définies — chaque valeur ajoutée
    DOIT avoir au moins un caller applicatif réel (règle « pas de costume
    sans corps », CLAUDE.md). Si un caller a besoin de plus de tentatives,
    ajouter une valeur ici en même temps que le caller qui l'utilise.
    """

    NONE = "none"  # 1 tentative — pour probe, boucles tool-use,
    #   et callers qui pilotent leur propre retry.
    STANDARD = "standard"  # 3 tentatives, backoff exp 2 / 4 / 8 s.
    #   Défaut pour les single-shot LLM calls
    #   (planners, suggesters, classifiers).


class FallbackPolicy(Enum):
    """Politique de fallback vers le LLM local (Ollama) quand le primary
    cloud lève une erreur transitoire (rate-limit, 5xx, réseau).

    Doctrine Komptia : les chiffres sont sacrés (cf. ``CLAUDE.md`` règle
    "Iris ne génère JAMAIS de SQL à l'aveugle"). Un fallback Ollama 3B
    sans tool calling natif renverra du texte hallucinant un tool_use
    → SQL faux silencieux. Pour les callers critiques (Iris, copilot
    SQL), il vaut mieux fail-fast que produire des données fausses.

    GRACEFUL est le défaut : comportement historique (test eligible_error
    + garde-fou tool_use de P0 #1). NONE désactive toute tentative de
    fallback — utilisé sur les callers où l'utilisateur prend des
    décisions financières basées sur la réponse.
    """

    NONE = "none"
    """Pas de fallback, fail-fast. Pour Iris (chat NL→SQL), copilot_cell_*
    (génération SQL ad-hoc), iris_oneshot_load_all_cols. La responsable
    financière préfère "Indisponible 5 min" à un SQL faux silencieux."""

    GRACEFUL = "graceful"
    """Comportement par défaut (historique). Tente le fallback uniquement
    si capabilities matchent (tool_use guard) ET erreur eligible. Pour
    les callers où une réponse dégradée mais correcte est préférable à
    une indisponibilité (résumés, classifications, suggestions)."""


# Status HTTP retriables. 529 = Anthropic « overloaded ». Aligné avec
# les helpers retry existants (llm_report_planner._RETRIABLE_STATUS_CODES,
# widget_planner/_llm_common._RETRIABLE_STATUS_CODES) qu'on supprime
# après migration de leurs callers.
_RETRIABLE_HTTP_CODES: frozenset[int] = frozenset({429, 502, 503, 504, 529})


# ---------------------------------------------------------------------------
# Erreur unifiée
# ---------------------------------------------------------------------------


class LLMCallError(Exception):
    """Erreur unifiée pour tous les call sites LLM.

    Le message est en français et **safe à renvoyer à l'utilisateur**
    (pas de fuite de détails internes : URL, clé API, traceback). Le
    champ ``kind`` permet aux callers de discriminer pour des UI plus
    fines (badge ``rate_limit`` vs ``overloaded``, par exemple).

    L'exception cause originale est conservée dans ``__cause__`` (et
    aussi dans ``cause`` pour faciliter l'inspection).
    """

    def __init__(
        self,
        message: str,
        *,
        kind: str = "generic",
        cause: Optional[BaseException] = None,
    ):
        super().__init__(message)
        self.kind = kind  # "overloaded" | "rate_limit" | "network" | "unreachable" | "generic"
        self.cause = cause


# ---------------------------------------------------------------------------
# CallProfile — la dataclass que tous les call sites consomment
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CallProfile:
    """Source de vérité unique pour les paramètres d'un call site LLM.

    Remplace la combinaison auparavant éparpillée de :

    * ``get_llm_manager()`` + ``LLMRequest(model=..., max_tokens=clamped...)``
    * ``llm_call_context(caller=...)``
    * ``try`` / ``except`` overloaded / rate_limit / network avec messages FR
    * retry exponentiel custom (auparavant 2 implémentations dupliquées dans
      ``llm_report_planner`` et ``widget_planner/_llm_common``)

    Champs :

    caller : nom sémantique. Devrait figurer dans
             :data:`app.services.ai.llm_call_tracker.KNOWN_CALLERS` pour
             que le dashboard ``/admin/ai-performance`` filtre proprement.
             Un caller absent loggue un ``warning`` (pas un hard fail —
             règle CLAUDE.md fail-loud-not-fail-closed pour l'observabilité).

    model_kind : PRIMARY (admin choice), UTILITY (Haiku-eq), LOCAL (Ollama).

    temperature : 0.0–1.0. Défaut 0.2.

    max_tokens_soft : plafond souhaité côté caller. Sera **clampé au cap
                      du modèle réel** via :func:`clamped_max_tokens`. ``None``
                      = laisser le provider choisir (cap modèle complet).

    timeout_seconds : timeout asyncio. ``None`` = pas de wrap ``wait_for``
                      (le provider applique son timeout HTTP natif).

    retry : :class:`RetryPolicy`. STANDARD par défaut.

    provider_name_override : pour LOCAL ou multi-provider explicite. ``None``
                             = laisser le ``LLMManager`` router au default.
    """

    caller: str
    model_kind: ModelKind = ModelKind.PRIMARY
    temperature: float = 0.2
    max_tokens_soft: Optional[int] = None
    timeout_seconds: Optional[float] = None
    retry: RetryPolicy = RetryPolicy.STANDARD
    provider_name_override: Optional[str] = None
    fallback_policy: FallbackPolicy = FallbackPolicy.GRACEFUL
    """Politique de fallback Ollama. Default = GRACEFUL = comportement
    historique (backward-compat). Mettre ``FallbackPolicy.NONE`` pour
    les callers critiques où une donnée fausse silencieuse serait pire
    qu'une indisponibilité explicite (Iris, copilot SQL — chiffres sacrés)."""

    def __post_init__(self) -> None:
        if not self.caller:
            raise ValueError("CallProfile.caller cannot be empty")

        # Validation soft contre KNOWN_CALLERS — log warning, pas hard fail.
        # Rationale : on ne veut pas casser la prod si quelqu'un ajoute un
        # caller sans mettre à jour le set. Mais on veut le savoir dans les
        # logs pour pouvoir l'ajouter et que le dashboard reste cohérent.
        try:
            from app.services.ai.llm_call_tracker import KNOWN_CALLERS

            if self.caller not in KNOWN_CALLERS:
                logger.warning(
                    "CallProfile: caller '%s' absent de KNOWN_CALLERS — "
                    "le dashboard /admin/ai-performance ne le reconnaîtra pas. "
                    "Ajoute-le à app.services.ai.llm_call_tracker.KNOWN_CALLERS "
                    "si c'est un nouveau caller légitime.",
                    self.caller,
                )
        except Exception:  # noqa: BLE001 — import circulaire ou tracker indisponible
            pass


# ---------------------------------------------------------------------------
# Helpers internes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ResolvedModel:
    """Résultat de :func:`_resolve_model`. Couple ``(model_name, provider_name)``."""

    model_name: str
    provider_name: Optional[str]


def _resolve_model(profile: CallProfile, manager: Any) -> _ResolvedModel:
    """Résout ``(model_name, provider_name)`` selon ``profile.model_kind``.

    PRIMARY → ``("", default_provider_name)`` — le provider lit son
              ``default_model_name`` (chemin lazy, qui peut être overridé
              par un ``model`` explicite dans la ``LLMRequest`` du caller).

    UTILITY → ``(get_utility_model(provider), provider)`` — Haiku-eq.

    LOCAL   → ``(get_local_fallback_model(), local.provider_name)`` —
              Ollama. Lève ``RuntimeError`` si non configuré.
    """
    if profile.model_kind is ModelKind.LOCAL:
        local = manager.get_local_fallback()
        if local is None:
            raise LLMCallError(
                "LLM local non configuré (/admin/ai-config → Anonymisation locale).",
                kind="generic",
            )
        return _ResolvedModel(
            model_name=manager.get_local_fallback_model() or "",
            provider_name=getattr(local, "provider_name", None),
        )

    provider_name = profile.provider_name_override or manager.default_provider_name

    if profile.model_kind is ModelKind.UTILITY:
        return _ResolvedModel(
            model_name=get_utility_model(provider_name),
            provider_name=provider_name,
        )

    # PRIMARY : laisser le provider lire son default_model_name (model="")
    return _ResolvedModel(
        model_name="",
        provider_name=provider_name,
    )


def _build_llm_request(
    profile: CallProfile,
    user_request: LLMRequest,
    resolved: _ResolvedModel,
) -> LLMRequest:
    """Compose le ``LLMRequest`` final à partir du profile + request user.

    **Précédence explicite > implicite** :

    * ``model`` : si ``user_request.model`` est non vide, on le respecte.
      Sinon ``resolved.model_name`` (qui peut être vide pour PRIMARY → le
      provider choisira son default).
    * ``max_tokens`` : si ``user_request.max_tokens`` est posé, on le
      respecte. Sinon ``profile.max_tokens_soft`` clampé au cap modèle.
      Sinon ``None`` (le provider applique son cap complet).
    * ``temperature`` : ``user_request.temperature`` toujours (la dataclass
      a une valeur par défaut). Le ``profile.temperature`` n'est utilisé
      que si le caller construit son ``LLMRequest`` à partir du profile.

    Tous les autres champs (``prompt``, ``system``, ``options``,
    ``prompt_cache_prefix``) sont préservés tels quels.
    """
    if user_request.max_tokens is not None:
        max_tokens = user_request.max_tokens
    elif profile.max_tokens_soft is not None:
        max_tokens = clamped_max_tokens(
            profile.max_tokens_soft,
            model_name=(resolved.model_name or None),
        )
    else:
        max_tokens = None

    model = user_request.model if user_request.model else resolved.model_name

    return LLMRequest(
        prompt=user_request.prompt,
        system=user_request.system,
        model=model,
        temperature=user_request.temperature,
        max_tokens=max_tokens,
        options=dict(user_request.options) if user_request.options else {},
        prompt_cache_prefix=user_request.prompt_cache_prefix,
        # #19a (triage anonymisation 2026-06-10) — ce rebuild DROPPAIT
        # user_id : la couche 2 provider (pseudonymizer /data-privacy,
        # appliquée par generate() ssi request.user_id) était neutralisée
        # pour TOUT caller passant par call_llm, notamment le
        # prompt_cache_prefix de result_assistant (valeurs réelles).
        user_id=user_request.user_id,
    )


async def _resolve_effective_fallback_policy(
    profile: CallProfile,  # noqa: ARG001
    *,
    is_stream: bool = False,  # noqa: ARG001
) -> FallbackPolicy:
    """Politique de fallback runtime — toujours GRACEFUL.

    Décision admin assumée (2026-05-20) : le LLM local Ollama doit servir
    de filet de sécurité sur **tous les call-sites**, y compris ceux que
    le caller a déclaré ``FallbackPolicy.NONE`` (Iris SQL, copilot,
    result_assistant). L'admin préfère la continuité de service à
    l'application stricte de la doctrine "chiffres sacrés".

    Conséquence acceptée : quand le cloud lève une erreur transitoire
    (rate-limit, 5xx, réseau) sur un caller critique, Ollama prend le
    relais et peut produire un SQL hallucinant un tool_use → résultat
    faux silencieux. C'est le trade-off explicitement choisi par l'admin
    en échange de la continuité de service.

    Le champ ``profile.fallback_policy`` est conservé dans le modèle
    (utile si une future décision admin réintroduit une distinction par
    caller), mais ignoré par la résolution actuelle. Idem pour
    ``is_stream`` — gardé pour stabilité de signature.
    """
    return FallbackPolicy.GRACEFUL


def _retry_attempts(policy: RetryPolicy) -> int:
    return {
        RetryPolicy.NONE: 1,
        RetryPolicy.STANDARD: 3,
    }[policy]


def _retry_delay(policy: RetryPolicy, attempt: int) -> float:
    """Backoff exponentiel : ``2^(attempt+1)`` secondes, cap à 30 s."""
    if policy is RetryPolicy.NONE:
        return 0.0
    return min(2.0 * (2**attempt), 30.0)


def _is_retriable_exception(exc: BaseException) -> bool:
    """Détermine si une exception justifie un retry **au niveau runtime**.

    **Coordination avec le retry du provider** : :class:`AnthropicProvider` et
    :class:`OpenAIProvider` retry déjà en interne sur HTTP 429/5xx/network
    (cf. ``_should_retry_http`` / ``_should_retry_exception`` dans
    ``llm_providers``). Quand une de ces exceptions remonte au runtime, le
    provider a **déjà épuisé ses tries** — re-retry n'aiderait pas et
    doublerait l'attente utilisateur (potentiellement ~50s sur 9 tentatives
    cumulées).

    Le runtime ne retry donc QUE sur :

    * :class:`RateLimitError` — notre exception domain qui signale qu'un
      provider compatible (sans retry interne sur ce code) a vu un 429.
      Le runtime peut absorber le pic transitoire ici.

    Tout autre transient (HTTP/network) qui remonte indique que le provider
    a déjà tenté son maximum — on ne re-retry pas. Le caller voit alors
    immédiatement le ``LLMCallError`` mappé.
    """
    return isinstance(exc, RateLimitError)


def _map_error_to_user_message(exc: BaseException) -> LLMCallError:
    """Mappe une exception runtime vers un :class:`LLMCallError` avec un
    message en français adapté au contexte.

    Ne **jamais** inclure ``str(exc)`` dans le message renvoyé : peut leaker
    URL, clé API, headers. Le détail technique reste côté serveur (logs).
    """
    # Defense-in-depth : ``asyncio.CancelledError`` est un signal de contrôle
    # asyncio, **pas** une erreur LLM. Le mapper vers ``LLMCallError`` casse
    # la sémantique structurée de cancellation (PEP 654 / Python 3.8+) et
    # remonte au user un message générique « Erreur interne du service LLM »
    # alors que le bon flow est : handler caller (ex: result_assistant)
    # catch ``CancelledError`` et renvoie ``{"type":"cancelled"}``.
    # Les call sites (call_llm / call_llm_with_tools / stream_llm_with_tools)
    # doivent déjà re-raise avant d'arriver ici — cette garde protège contre
    # un futur caller qui réintroduirait le bug par accident.
    if isinstance(exc, asyncio.CancelledError):
        raise exc

    exc_str = str(exc).lower()

    if isinstance(exc, RateLimitError):
        return LLMCallError(
            "⏳ Quota LLM dépassé (rate limit). Réessaie dans quelques minutes.",
            kind="rate_limit",
            cause=exc,
        )

    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 429:
            return LLMCallError(
                "⏳ Quota LLM dépassé (rate limit). Réessaie dans quelques minutes.",
                kind="rate_limit",
                cause=exc,
            )
        if status == 413:
            # Spécifique au cas « payload trop gros ». Ne PAS dire "réessaie
            # dans un instant" : tant que le payload reste de la même taille,
            # le retry échouera pareil. Deux sous-cas pratiques :
            #   1. Tier provider à TPM bas (ex : Groq free = 8000 TPM) qui
            #      refuse une requête Iris standard (~20k tokens). L'admin
            #      doit upgrader ou changer de modèle/provider.
            #   2. Payload > context window du modèle (ex : 250k envoyés à
            #      un modèle 128k). L'utilisateur doit réduire le contexte
            #      (nouvelle conversation, demande plus courte).
            # Message volontairement actionnable côté admin ET côté user.
            return LLMCallError(
                "⚠️ Le provider a refusé la requête : payload trop volumineux "
                "(HTTP 413). Causes possibles : tier provider à quota bas "
                "(Groq free, Mistral gratuit, etc.) ou contexte qui dépasse "
                "la limite du modèle. Démarrez une nouvelle conversation, "
                "changez de modèle, ou contactez un administrateur pour "
                "passer sur un tier supérieur.",
                kind="payload_too_large",
                cause=exc,
            )
        if status == 529:
            return LLMCallError(
                "⏳ Service LLM temporairement surchargé. Ce n'est pas un bug "
                "de la demande — réessaie dans 1-2 minutes.",
                kind="overloaded",
                cause=exc,
            )
        return LLMCallError(
            f"IA indisponible (HTTP {status}). Réessaie dans un instant.",
            kind="generic",
            cause=exc,
        )

    if isinstance(exc, (httpx.TimeoutException, asyncio.TimeoutError)):
        return LLMCallError(
            "Timeout sur l'appel LLM. Réessaie ou simplifie ta demande.",
            kind="network",
            cause=exc,
        )

    # Connexion REFUSÉE / endpoint injoignable (≠ timeout) : le service LLM
    # n'est pas là (typiquement Ollama local arrêté). Kind distinct
    # ``"unreachable"`` pour que les callers (improve_pseudo, auto_classify)
    # FAIL-FAST au lieu de réduire le chunk / retenter — réduire la taille ne
    # fait pas réapparaître un service éteint (c'était 28 s de grind inutile).
    # ⚠️ ``httpx.ConnectError`` ⊂ ``httpx.NetworkError`` et
    # ``ConnectionRefusedError`` ⊂ ``ConnectionError`` ⊂ ``OSError`` : cette
    # branche DOIT précéder le catch réseau générique ci-dessous, sinon elle
    # ne serait jamais atteinte. On ne range ici QUE le « refus de connexion »
    # (service down) ; un reset/abort mid-flux reste ``"network"`` (transitoire).
    if isinstance(exc, (httpx.ConnectError, ConnectionRefusedError)):
        return LLMCallError(
            "Service LLM injoignable (connexion refusée). Vérifie qu'il est démarré.",
            kind="unreachable",
            cause=exc,
        )

    if isinstance(exc, (httpx.NetworkError, ConnectionError, OSError)):
        return LLMCallError(
            "Erreur réseau lors de l'appel LLM. Vérifie ta connexion et réessaie.",
            kind="network",
            cause=exc,
        )

    # Filet de sécurité : si la garde :func:`_ensure_llm_runtime_ready`
    # est court-circuitée (un caller construit son ``LLMCallError`` sans
    # passer par les helpers, ou un test contourne la garde via mock du
    # manager), on reconnaît ici les ``ValueError`` historiques qu'on
    # rencontrait avant la garde et on les remappe vers ``not_configured``
    # — pour que l'UX reste cohérente (même message, même kind).
    #
    # Les chaînes reconnues correspondent aux ``raise ValueError(...)``
    # de :mod:`app.services.ai.llm_providers` (cf. ``get_provider``,
    # ``set_default``, ``AnthropicProvider.__init__``, etc.).
    if isinstance(exc, ValueError):
        not_configured_markers = (
            "Provider LLM non trouvé",
            "Provider non enregistré",
            "ANTHROPIC_API_KEY non configurée",
            "Clé API non configurée",
        )
        if any(marker in str(exc) for marker in not_configured_markers):
            return LLMCallError(_MSG_NOT_CONFIGURED, kind="not_configured", cause=exc)

    # Fallback : inspecter le message pour les providers qui propagent
    # l'erreur en RuntimeError/ValueError plutôt qu'en httpx.HTTPStatusError.
    if "overloaded" in exc_str or "529" in exc_str:
        return LLMCallError(
            "⏳ Service LLM temporairement surchargé. Réessaie dans 1-2 minutes.",
            kind="overloaded",
            cause=exc,
        )
    if "rate limit" in exc_str or "429" in exc_str:
        return LLMCallError(
            "⏳ Quota LLM dépassé (rate limit). Réessaie dans quelques minutes.",
            kind="rate_limit",
            cause=exc,
        )

    return LLMCallError(
        "Erreur interne du service LLM. Réessaie la demande.",
        kind="generic",
        cause=exc,
    )


# ---------------------------------------------------------------------------
# Message FR pour le cas « aucun provider LLM configuré »
# ---------------------------------------------------------------------------

# Source unique du message « pas de provider ». Référencée par :
# - :func:`_ensure_llm_runtime_ready` (garde fail-fast avant HTTP)
# - :func:`_map_error_to_user_message` (filet de sécurité si une
#   ``ValueError("Provider LLM non trouvé"...)`` remonte malgré la garde)
# - Tests d'assertion (``test_llm_no_provider_guard.py``)
#
# Ton volontairement neutre : ne pointe pas vers ``/admin/ai-config`` directement
# dans le message API (un user non-admin ne peut pas y aller). Le banner UI
# global gère le diff admin/user et l'URL cliquable.
_MSG_NOT_CONFIGURED: str = (
    "IA non configurée. Un administrateur doit configurer la clé API "
    "(ou activer le LLM local) avant que cette fonctionnalité ne fonctionne."
)


async def _ensure_llm_runtime_ready(caller: Optional[str] = None) -> None:
    """Garde fail-fast : raise :class:`LLMCallError` si aucun provider n'est
    utilisable runtime (cloud OU local).

    **Pourquoi** : sans cette garde, un appel transitait jusqu'à
    :meth:`LLMManager.get_provider` qui levait ``ValueError("Provider LLM
    non trouvé: None")``. Cette ``ValueError`` était ensuite mappée vers
    le message générique « Erreur interne du service LLM. Réessaie. » —
    inactionnable, et qui mentait (réessayer ne change rien).

    **Pourquoi côté runtime** : un seul point d'enforcement. Tous les call
    sites métier (Iris, copilot, automations, widget_planner, etc.)
    traversent ``call_llm`` / ``call_llm_with_tools`` / ``stream_llm_with_tools``.
    Donc on bloque ici, message uniforme, zéro duplication.

    Appel à :func:`ensure_providers_from_db` AVANT le check pour absorber
    la course-condition au boot (le 1er request peut arriver avant que
    l'auto-sync background ait fini — cf. commit 078f74f). Idempotent
    après la 1ère exécution (flag ``_providers_initialized_from_db``).

    **Observabilité** : la garde tire AVANT ``llm_call_context`` (qui pose
    le tracking ``AIPerformanceLog``). Sans ce log explicite, l'admin
    n'a aucun signal dans ``/admin/ai-performance`` qu'une garde a tiré
    — il ne peut pas diagnostiquer un incident en cours. Le ``WARNING``
    avec ``caller`` permet à l'admin de grep ``komptia.log`` pour
    « not_configured ». Pas de ``record_llm_call_async`` ici (pas de
    réponse, pas de provider à attribuer) ; un counter dédié type
    ``llm_guard_blocked_total`` est tracé comme dette pour P2.
    """
    await ensure_providers_from_db()
    manager = get_llm_manager()
    if not manager.has_any_provider_configured():
        logger.warning(
            "LLM guard: aucun provider configuré — bloque caller=%s (admin doit "
            "configurer /admin/ai-config ou activer le LLM local)",
            _sanitize_for_log(caller or "<unknown>", max_len=64),
        )
        raise LLMCallError(_MSG_NOT_CONFIGURED, kind="not_configured", cause=None)


# ---------------------------------------------------------------------------
# API publique
# ---------------------------------------------------------------------------


async def resolve_active_model() -> tuple[str, str]:
    """Retourne ``(provider_name, model_name)`` du modèle LLM actif.

    **Source de vérité unique** pour la résolution pre-flight du couple
    (provider, modèle) — extraite du pattern auparavant dupliqué dans
    ``llm_report_planner.py``, ``widget_planner/_llm_common.py`` et
    ``report_analyzer.py``.

    Combine :

    1. Check disponibilité via :meth:`LLMManager.has_any_provider_configured`
       (couvre env vars ``ANTHROPIC_API_KEY`` ET config admin BDD)
    2. Lecture ``primary_provider`` / ``primary_model`` depuis
       :class:`AIConfigService` (choix admin explicite, source de vérité)
    3. Fallback vers ``manager.default_provider_name`` / ``default_model_name``
       (valeurs propagées depuis la config au boot via ``set_default``)

    Cette résolution est complémentaire de :func:`_resolve_model` :

    * :func:`_resolve_model` est appelée **dans** :func:`call_llm` au moment
      du build de la ``LLMRequest`` finale (build-time, peut retourner ``""``
      pour que le provider lazy-résolve).
    * :func:`resolve_active_model` est appelée **avant** :func:`call_llm`
      par les call sites qui ont besoin du nom du modèle réel (UI, budget
      tokens, sélection conditionnelle de prompts).

    Returns:
        ``(provider_name, model_name)`` — tous deux non vides garantis.

    Raises:
        :class:`LLMCallError` avec ``kind="not_configured"`` si :

        * aucun provider n'est utilisable (ni env var ni config BDD), OU
        * config BDD vide ET ``manager.default_*`` vides (cas paradoxal
          provider chargé mais aucun modèle déterminable)

        Les callers wrappent dans leur exception domaine (``ReportPlanError``,
        ``ValueError`` selon le contexte).
    """
    manager = get_llm_manager()
    if not manager.has_any_provider_configured():
        raise LLMCallError(_MSG_NOT_CONFIGURED, kind="not_configured")

    # ``get_all()`` peut lever ``SQLAlchemyError`` (DB locked, OperationalError)
    # — aucun caller ne catche cette classe nativement. On re-raise en
    # ``LLMCallError(kind="config_unavailable")`` qui EST attrapée par tous
    # les call sites métier (analyst/composer/designer/report_*). Sans ça,
    # une BDD locale lockée crashe la génération PDF en 500 au lieu de
    # tomber proprement en fallback dégradé.
    try:
        config = await get_ai_config_service().get_all()
    except Exception as exc:  # noqa: BLE001 — wrap toute erreur DB/IO en kind="config_unavailable"
        raise LLMCallError(_MSG_NOT_CONFIGURED, kind="config_unavailable", cause=exc) from exc

    provider_name = config.get("primary_provider") or manager.default_provider_name
    config_model = config.get("primary_model")

    # **Garde anti-incohérence** : ``manager.default_model_name`` n'est
    # un fallback valide QUE si on est sur le même provider — sinon on
    # enverrait p.ex. un nom de modèle Claude à un endpoint OpenAI (400
    # silencieux côté SDK). En pratique, ``ensure_providers_from_db()``
    # garde les deux alignés via ``set_default()`` au boot, mais protégeons
    # contre une fenêtre de race (admin change la config et appelle
    # immédiatement le helper avant que le manager soit re-synchronisé).
    if config_model:
        model_name = config_model
    elif provider_name == manager.default_provider_name:
        model_name = manager.default_model_name
    else:
        model_name = ""

    if not provider_name or not model_name:
        raise LLMCallError(_MSG_NOT_CONFIGURED, kind="not_configured")

    return provider_name, model_name


def _concat_prompt_for_gate(
    request: LLMRequest,
    messages: Optional[list[dict]] = None,
) -> str:
    """**Phase 3.4 (#65) helper** — concatène les blocs texte d'une
    ``LLMRequest`` + ``messages`` pour le check ``assert_safe_llm_prompt``.

    Defense-in-depth uniquement : on assemble un string représentatif
    pour la détection de noms denied. Pas besoin de fidélité parfaite à
    ce qui part au provider — un best-effort sur les blocs texte
    suffit pour qu'un nom denied éventuel apparaisse au scan.
    """
    parts: list[str] = []
    if request.system:
        parts.append(request.system)
    if request.prompt_cache_prefix:
        parts.append(request.prompt_cache_prefix)
    if request.prompt:
        parts.append(request.prompt)
    if messages:
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                # Anthropic content blocks : [{type, text|input, ...}]
                for blk in content:
                    if not isinstance(blk, dict):
                        continue
                    btype = blk.get("type")
                    if btype in ("text", "thinking"):
                        text = blk.get("text")
                        if isinstance(text, str):
                            parts.append(text)
                    elif btype == "tool_use":
                        # Sérialiser l'input du tool — un nom denied peut
                        # apparaître dans un argument (sql_query, etc.).
                        try:
                            import json as _json

                            parts.append(
                                _json.dumps(
                                    blk.get("input"),
                                    ensure_ascii=False,
                                    default=str,
                                )
                            )
                        except Exception:  # noqa: BLE001 — best-effort
                            pass
    return "\n".join(p for p in parts if p)


async def call_llm(
    profile: CallProfile,
    request: LLMRequest,
    *,
    conversation_id: Optional[str] = None,
    user: Optional[Any] = None,
) -> LLMResponse:
    """Single-shot LLM call. **Source de vérité unique** pour tout call
    site qui utilise :meth:`LLMManager.generate` aujourd'hui.

    Gère :

    * résolution model selon ``profile.model_kind``
    * clamp ``max_tokens`` au cap du modèle réel
    * pose de ``llm_call_context(caller=profile.caller, conversation_id=...)``
      pour le tracking dashboard
    * retry exponentiel selon ``profile.retry`` sur erreurs transitoires
    * timeout via :func:`asyncio.wait_for` si ``profile.timeout_seconds > 0``
    * mapping exception → :class:`LLMCallError` (message FR user-safe)

    **Phase 3.4/3.5 (#65/#66) defense-in-depth** : si ``user`` est fourni,
    le prompt est scanné via :func:`assert_safe_llm_prompt` AVANT envoi.
    Si un nom denied est détecté (bug de filtrage amont), lève
    :class:`InvisibleLeakError`. Le param est **optionnel** — les call-sites
    SYSTEM / scripts admin laissent ``None``, les call-sites user-facing
    peuvent l'opter pour ce filet de secours.

    Lève :class:`LLMCallError` sur échec — le caller catch et formate son
    retour utilisateur. La cause originale est dans ``__cause__``.
    """
    await _ensure_llm_runtime_ready(caller=profile.caller)
    manager = get_llm_manager()
    resolved = _resolve_model(profile, manager)
    final_request = _build_llm_request(profile, request, resolved)

    # **#65 defense-in-depth gate** : opt-in via ``user=``. Si fourni,
    # vérifie que le prompt n'expose pas un nom denied (bug amont).
    if user is not None:
        from app.services.data_access.error_messages import (
            assert_safe_llm_prompt,
        )

        _prompt_for_check = _concat_prompt_for_gate(final_request)
        if _prompt_for_check:
            await assert_safe_llm_prompt(
                _prompt_for_check,
                user,
                context_label=profile.caller,
            )

    # Résolu UNE FOIS hors de la boucle retry. Si l'admin save un nouveau
    # scope au milieu de nos retries, les tentatives restantes garderont
    # la valeur initiale — cohérent avec un single call_llm logique.
    effective_policy = await _resolve_effective_fallback_policy(profile)

    last_exc: Optional[BaseException] = None
    attempts = _retry_attempts(profile.retry)

    for attempt in range(attempts):
        try:
            with llm_call_context(caller=profile.caller, conversation_id=conversation_id):
                coro = manager.generate(
                    final_request,
                    provider_name=resolved.provider_name,
                    fallback_policy=effective_policy.value,
                )
                if profile.timeout_seconds is not None and profile.timeout_seconds > 0:
                    return await asyncio.wait_for(coro, timeout=profile.timeout_seconds)
                return await coro
        except LLMCallError:
            raise
        except asyncio.CancelledError:
            # Cancellation = signal asyncio (l'user a cliqué « Stop », ou le
            # client a fermé la connexion, ou un parent task a annulé).
            # Doit propager intacte pour que le handler caller traite proprement
            # (cf. result_assistant._run_agent: ``except asyncio.CancelledError``
            # → renvoie ``{"type":"cancelled"}`` et libère les awaiters).
            raise
        except BaseException as exc:
            last_exc = exc
            if attempt < attempts - 1 and _is_retriable_exception(exc):
                delay = _retry_delay(profile.retry, attempt)
                logger.warning(
                    "call_llm[%s] attempt %d/%d failed (%s) — retry in %.1fs",
                    profile.caller,
                    attempt + 1,
                    attempts,
                    type(exc).__name__,
                    delay,
                )
                await asyncio.sleep(delay)
                continue
            break

    assert last_exc is not None
    # Inclure ``str(last_exc)`` sanitizé : sans ça, le diagnostic prod est
    # aveugle (on voyait juste « ValueError » sans savoir POURQUOI). Le
    # ``_sanitize_for_log`` retire les caractères de contrôle (anti-CRLF
    # injection) et cap à 300 chars (évite log-flood). Pour les
    # ``httpx.HTTPStatusError`` qui contiennent l'URL provider, le tronc
    # à 300 chars limite l'exposition mais ne supprime pas — accepter
    # car (a) les logs admin sont en BDD protégée par SQLCipher, (b) un
    # admin a déjà accès à la config provider via /admin/ai-config.
    logger.error(
        "call_llm[%s] failed after %d attempt(s): %s: %s",
        profile.caller,
        attempts,
        type(last_exc).__name__,
        _sanitize_for_log(str(last_exc), max_len=300),
    )
    raise _map_error_to_user_message(last_exc)


async def call_llm_with_tools(
    profile: CallProfile,
    request: LLMRequest,
    tools: list[dict],
    messages: list[dict],
    *,
    thinking_budget: int = 0,
    conversation_id: Optional[str] = None,
    user_id: Optional[int] = None,
    user: Optional[Any] = None,
) -> dict:
    """Single-shot LLM call avec tool-use. **Source de vérité unique** pour
    tout call site qui utilise :meth:`LLMManager.generate_with_tools`
    aujourd'hui.

    ``thinking_budget`` : si > 0, active extended thinking sur Anthropic
    Sonnet/Opus 4.x+. Ignoré silencieusement sur Haiku, OpenAI, etc.

    ``user_id`` : identifiant user pour activer la couche pseudonymizer
    user-scoped (§…§) en plus de la couche PII regex. Tout caller servant
    un utilisateur final doit le passer (iris_main, _explore_llm, etc.).
    ``None`` = scripts admin / sync sans contexte user (couche 1 PII regex
    seulement).

    ``user`` (objet, distinct de ``user_id``) : **Phase 3.4/3.5 (#65/#66)**
    defense-in-depth. Si fourni, le prompt + tools + messages sont scannés
    via :func:`assert_safe_llm_prompt` AVANT envoi pour détecter un nom
    denied (bug de filtrage amont). Lève :class:`InvisibleLeakError` si
    fuite. ``None`` = pas de gate (legacy / SYSTEM).

    Retourne le dict brut de la réponse (``content``, ``stop_reason``,
    ``usage``…). Le caller parse selon son besoin.
    """
    await _ensure_llm_runtime_ready(caller=profile.caller)
    manager = get_llm_manager()
    resolved = _resolve_model(profile, manager)
    final_request = _build_llm_request(profile, request, resolved)

    # **#65 defense-in-depth gate** : opt-in via ``user=``.
    if user is not None:
        from app.services.data_access.error_messages import (
            assert_safe_llm_prompt,
        )

        _prompt_for_check = _concat_prompt_for_gate(final_request, messages)
        if _prompt_for_check:
            await assert_safe_llm_prompt(
                _prompt_for_check,
                user,
                context_label=profile.caller,
            )

    # Résolu UNE FOIS hors de la boucle retry. Cf. ``call_llm`` ci-dessus
    # pour la rationale (cohérence sur la durée d'un seul call logique).
    effective_policy = await _resolve_effective_fallback_policy(profile)

    last_exc: Optional[BaseException] = None
    attempts = _retry_attempts(profile.retry)

    for attempt in range(attempts):
        try:
            with llm_call_context(caller=profile.caller, conversation_id=conversation_id):
                coro = manager.generate_with_tools(
                    final_request,
                    tools,
                    messages,
                    provider_name=resolved.provider_name,
                    thinking_budget=thinking_budget,
                    user_id=user_id,
                    fallback_policy=effective_policy.value,
                )
                if profile.timeout_seconds is not None and profile.timeout_seconds > 0:
                    return await asyncio.wait_for(coro, timeout=profile.timeout_seconds)
                return await coro
        except LLMCallError:
            raise
        except asyncio.CancelledError:
            # Cf. ``call_llm`` ci-dessus pour le détail : cancellation propage
            # intacte, pas un faux « Erreur interne du service LLM ».
            raise
        except BaseException as exc:
            last_exc = exc
            if attempt < attempts - 1 and _is_retriable_exception(exc):
                delay = _retry_delay(profile.retry, attempt)
                logger.warning(
                    "call_llm_with_tools[%s] attempt %d/%d failed (%s) — retry in %.1fs",
                    profile.caller,
                    attempt + 1,
                    attempts,
                    type(exc).__name__,
                    delay,
                )
                await asyncio.sleep(delay)
                continue
            break

    assert last_exc is not None
    logger.error(
        "call_llm_with_tools[%s] failed after %d attempt(s): %s: %s",
        profile.caller,
        attempts,
        type(last_exc).__name__,
        _sanitize_for_log(str(last_exc), max_len=300),
    )
    raise _map_error_to_user_message(last_exc)


async def stream_llm_with_tools(
    profile: CallProfile,
    request: LLMRequest,
    tools: list[dict],
    messages: list[dict],
    *,
    thinking_budget: int = 0,
    conversation_id: Optional[str] = None,
    user_id: Optional[int] = None,
) -> AsyncIterator[dict]:
    """Variante streaming. Yield les events SSE bruts du provider.

    ``user_id`` : voir :func:`call_llm_with_tools` — active la couche
    pseudonymizer user-scoped à l'INPUT. Note : le restore output est
    aujourd'hui PII-only sur le stream (dette documentée).

    **Pas de retry sur stream** : un retry casserait l'ordre des events
    déjà yieldés au caller. Si une exception survient au milieu d'un
    stream, on la mappe vers :class:`LLMCallError` et on raise — c'est au
    caller de décider quoi faire (souvent : renvoyer un event ``error``
    final au client).
    """
    await _ensure_llm_runtime_ready(caller=profile.caller)
    manager = get_llm_manager()
    resolved = _resolve_model(profile, manager)
    final_request = _build_llm_request(profile, request, resolved)

    # Résolu UNE FOIS avant l'ouverture du stream — un swap admin au milieu
    # du stream n'affecte pas les events déjà en cours d'émission.
    # ``is_stream=True`` : trace historique pour le resolver. Dette P1 #15
    # SOLDÉE le 2026-06-10 — ``manager.stream_with_tools`` bascule désormais
    # sur le fallback local via le flux simulé quand le primary échoue AVANT
    # le premier event (après, on propage : re-streamer dupliquerait le
    # contenu déjà parti au client). Cf. test_stream_fallback_local.py.
    effective_policy = await _resolve_effective_fallback_policy(profile, is_stream=True)

    try:
        with llm_call_context(caller=profile.caller, conversation_id=conversation_id):
            async for event in manager.stream_with_tools(
                final_request,
                tools,
                messages,
                provider_name=resolved.provider_name,
                thinking_budget=thinking_budget,
                user_id=user_id,
                fallback_policy=effective_policy.value,
            ):
                yield event
    except LLMCallError:
        raise
    except asyncio.CancelledError:
        # Cf. ``call_llm`` pour le détail : cancellation propage intacte.
        # Particulièrement critique sur le stream Iris : l'user qui stoppe
        # un message en plein milieu doit voir un état « annulé » propre,
        # pas un faux « Erreur interne du service LLM ».
        raise
    except BaseException as exc:
        logger.error(
            "stream_llm_with_tools[%s] failed: %s: %s",
            profile.caller,
            type(exc).__name__,
            _sanitize_for_log(str(exc), max_len=300),
        )
        raise _map_error_to_user_message(exc)


# ---------------------------------------------------------------------------
# Helpers pour les boucles tool-use (effort + max_tokens detection)
# ---------------------------------------------------------------------------


# Réserve par défaut entre ``thinking.budget_tokens`` et ``max_tokens`` (Anthropic
# refuse l'appel si ``budget >= max_tokens`` — on garde une marge pour la vraie
# génération de tokens : tool_use + text).
_DEFAULT_THINKING_RESERVE_TOKENS = 8000

# Fallback si le modèle est inconnu de constants_ai (provider sans registre BDD).
_DEFAULT_MAX_TOKENS_FALLBACK = 32000

# Plancher Anthropic pour ``thinking.budget_tokens`` (cf. doc officielle +
# ``AnthropicProvider._ANTHROPIC_THINKING_MIN_BUDGET``). En dessous, l'API
# rejette la requête. Source de vérité partagée avec le provider.
_ANTHROPIC_THINKING_MIN_BUDGET = 1024

# Marge minimale réservée pour la vraie génération de tokens (tool_use args
# + texte) quand on active extended thinking. Un tool_use Anthropic typique
# consomme 200-500 tokens rien que pour le JSON ``input`` d'un seul outil ;
# une réponse SQL/texte d'un agent type Iris fait régulièrement 1500-3000
# tokens (cf. tool_use ``execute_sql`` / ``emit_via_code`` qui retournent
# du SQL généré + commentaire). À 256, l'appel « réussit » mais retourne
# un tool_use tronqué (``stop_reason=max_tokens``) — coût LLM payé pour
# rien. À 4096, on couvre la borne haute observée (3000) avec une marge
# pour le tool_use + text final. Désactiver thinking quand on n'a pas
# cette marge est plus productif qu'un appel qui rate à mi-course.
_MIN_RESPONSE_TOKENS_WITH_THINKING = 4096


def compute_effort_params(
    manager: Any,
    *,
    hard_cap_max_tokens: Optional[int] = None,
    thinking_reserve_tokens: int = _DEFAULT_THINKING_RESERVE_TOKENS,
) -> dict:
    """Calcule ``{max_tokens, thinking_budget}`` au max des capacités du
    provider+modèle actuellement actifs dans le ``LLMManager``.

    **Stratégie Anthropic Sonnet/Opus 4.x+** :
        * ``max_tokens`` = cap réel du modèle (via :func:`get_max_tokens_for_model`,
          source de vérité unique — ne PAS hardcoder).
        * ``thinking_budget`` = ``cap - thinking_reserve_tokens`` (plancher 1024,
          seuil API Anthropic). La marge garantit la contrainte API
          ``budget_tokens < max_tokens``.

    **Stratégie Haiku Anthropic / OpenAI / autres** :
        * ``thinking_budget`` = 0 (Haiku ne supporte pas l'extended thinking,
          OpenAI / autres l'ignorent natively).
        * ``max_tokens`` = cap modèle si disponible, sinon fallback raisonnable.

    **Fallback safe** : si provider/model indéterminé (mocks tests, manager
    corrompu), valeurs sûres (pas de thinking, max_tokens raisonnable). Le
    pipeline continue sans crash.

    Args:
        manager: ``LLMManager`` actif (lit ``default_provider_name`` /
                 ``default_model_name`` à chaque appel — permet le switch
                 provider mid-session sans relancer).
        hard_cap_max_tokens: plafond local optionnel. Utile pour les callers
                             qui veulent réserver du budget input pour des
                             runs agentic longs (ex: copilot_workspace cap à
                             50K pour garder ~150K input dispo). ``None`` =
                             pas de cap supplémentaire (cap modèle réel utilisé).
        thinking_reserve_tokens: marge entre ``thinking_budget`` et ``max_tokens``.
                                 Défaut 8000 (suffisant pour la plupart des
                                 réponses tool_use + text).

    Returns:
        ``{"max_tokens": int, "thinking_budget": int}``. Toujours valide
        (jamais ``None``), prêt à passer à :func:`call_llm_with_tools`.

    Raises:
        ValueError: si ``hard_cap_max_tokens <= 0`` ou
                    ``thinking_reserve_tokens < 0``. Fail-fast plutôt
                    que de produire des paramètres « zéro silencieux »
                    qui feraient échouer l'appel LLM côté provider avec
                    un message obscur.

    Note (race condition transient) :
        L'appel lit ``manager.default_provider_name`` puis
        ``manager.default_model_name`` en deux temps. Si l'admin switch
        de modèle via ``/admin/ai-config`` exactement entre les deux
        accès (~ms), on peut obtenir un couple incohérent. Le provider
        clampe automatiquement ``max_tokens`` au cap réel du modèle
        cible (``llm_providers.py``), donc l'appel ne crashe pas — mais
        ``thinking_budget`` peut être sous-optimal pour le modèle B.
        Acceptable en pratique : la fenêtre est minuscule et l'admin ne
        switch pas pendant un run actif.
    """
    if hard_cap_max_tokens is not None and hard_cap_max_tokens <= 0:
        raise ValueError(
            f"compute_effort_params: hard_cap_max_tokens={hard_cap_max_tokens} "
            "doit être > 0 (ou None pour utiliser le cap modèle complet)."
        )
    if thinking_reserve_tokens < 0:
        raise ValueError(
            f"compute_effort_params: thinking_reserve_tokens="
            f"{thinking_reserve_tokens} doit être >= 0."
        )

    try:
        provider = manager.get_provider() if manager else None
    except Exception as exc:  # noqa: BLE001 — fallback safe
        logger.debug(
            "compute_effort_params: get_provider échoué (%s) — fallback conservateur",
            exc,
        )
        provider = None

    provider_name = ""
    model_name = ""
    if provider is not None:
        provider_name = str(getattr(provider, "provider_name", "") or "").lower()
    if manager is not None:
        try:
            model_name = str(getattr(manager, "default_model_name", "") or "")
        except Exception:  # noqa: BLE001
            model_name = ""

    model_cap = get_max_tokens_for_model(model_name) if model_name else _DEFAULT_MAX_TOKENS_FALLBACK
    cap = min(model_cap, hard_cap_max_tokens) if hard_cap_max_tokens else model_cap

    # Reasoning si supporté par le MODÈLE (lecture registre BDD — pas de
    # comparaison ``provider_name``). Deux formats équivalents en intention :
    # - ``extended_thinking`` (Anthropic) : tokens explicites
    # - ``reasoning_effort`` (OpenAI o-series, GPT-5) : niveaux discrets
    # On calcule ``thinking_budget`` (format Anthropic-pivot) si l'un OU
    # l'autre est supporté. Les providers downstream traduisent :
    # AnthropicProvider envoie ``thinking_budget`` directement, OpenAIProvider
    # le convertit en ``reasoning_effort`` via
    # ``_reasoning_effort_from_thinking_budget``.
    #
    # Note : on appelle ``supports_feature`` même si ``provider is None``
    # (manager.get_provider a levé). Le registre LLM (qui répond à la
    # question capability) ne dépend pas du provider en vie — il lit la
    # BDD. Couplage retiré pour éviter la dégradation silencieuse de
    # thinking quand le primary est temporairement down (rate-limit total,
    # clé révoquée). Le ``try/except`` couvre les exceptions runtime du
    # manager corrompu.
    from app.constants_ai import supports_capability_for_model as _supports_cap

    supports_thinking = False
    if manager is not None:
        try:
            supports_thinking = bool(
                manager.supports_feature(
                    "extended_thinking",
                    model=model_name,
                    provider_name=provider_name,
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "compute_effort_params: supports_feature(extended_thinking) "
                "échoué (%s) — fallback sans thinking",
                exc,
            )
            supports_thinking = False

    # Si le modèle ne supporte pas extended_thinking, vérifie le format
    # alternatif reasoning_effort (OpenAI o-series). Lecture directe du
    # registre LlmModel.supports_reasoning_effort.
    if not supports_thinking and model_name:
        supports_reasoning = _supports_cap(model_name, "reasoning_effort")
        if supports_reasoning is True:
            supports_thinking = True

    if not supports_thinking:
        # Modèle sans reasoning (OpenAI standard, Mistral, Groq, Gemini
        # non-thinking, Haiku, ou inconnu). ``thinking_budget=0`` =
        # format Anthropic neutre.
        return {"thinking_budget": 0, "max_tokens": cap}

    # Garde-fou : si ``cap`` est trop petit pour respecter à la fois
    # le plancher thinking (1024) ET la marge tokens utiles (4096),
    # désactiver thinking. Sinon l'API rejette (``budget >= max_tokens``)
    # ou le modèle ne peut produire aucune sortie utile.
    # Cas pratique : caller passe ``hard_cap_max_tokens=500`` à tort,
    # ou modèle inconnu avec un petit cap résolu.
    min_cap_for_thinking = _ANTHROPIC_THINKING_MIN_BUDGET + _MIN_RESPONSE_TOKENS_WITH_THINKING
    if cap < min_cap_for_thinking:
        logger.warning(
            "compute_effort_params: cap=%d < min=%d pour activer thinking — "
            "extended thinking désactivé pour cet appel.",
            cap,
            min_cap_for_thinking,
        )
        return {"thinking_budget": 0, "max_tokens": cap}

    # Calcul du budget thinking :
    # 1. ``cap - thinking_reserve_tokens`` est l'idéal (laisse la marge demandée)
    # 2. ``_ANTHROPIC_THINKING_MIN_BUDGET`` est le plancher API
    # 3. ``cap - _MIN_RESPONSE_TOKENS_WITH_THINKING`` est le PLAFOND admissible :
    #    au-delà, on n'aurait plus assez de tokens utiles pour la réponse.
    # Garde-fou critique : si ``thinking_reserve_tokens=0``, l'idéal serait
    # ``cap`` lui-même, ce qui violerait ``budget < max_tokens``. On clamp
    # au plafond admissible pour respecter l'invariant API.
    thinking_ideal = max(_ANTHROPIC_THINKING_MIN_BUDGET, cap - thinking_reserve_tokens)
    thinking_max_admissible = cap - _MIN_RESPONSE_TOKENS_WITH_THINKING
    thinking = min(thinking_ideal, thinking_max_admissible)
    return {"thinking_budget": thinking, "max_tokens": cap}


def is_response_truncated(response: dict) -> bool:
    """Détecte la troncature à ``max_tokens`` sur une réponse ``generate_with_tools``.

    **Pourquoi c'est critique** : si le LLM atteint ``max_tokens`` au milieu
    d'un ``tool_use``, le bloc est **partiel** (pas de JSON valide). Renvoyer
    ce bloc tel quel au turn suivant déclenche un 400 Anthropic
    (``invalid_request_error: tool_use.input is not valid JSON``).

    **Usage recommandé** dans les boucles tool-use :

    .. code-block:: python

        response = await call_llm_with_tools(profile, request, tools, messages)
        if is_response_truncated(response):
            return {"error": "Le LLM a atteint la limite max_tokens — "
                             "découpe la tâche ou simplifie la demande."}
        # ... continuer la boucle normalement
    """
    return response.get("stop_reason") == "max_tokens"


__all__ = [
    "CallProfile",
    "LLMCallError",
    "ModelKind",
    "RetryPolicy",
    "call_llm",
    "call_llm_with_tools",
    "compute_effort_params",
    "is_response_truncated",
    "stream_llm_with_tools",
]
