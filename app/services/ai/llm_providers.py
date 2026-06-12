"""
Abstraction multi-modèle LLM pour Komptia.

Inspiré de Vanna.ai: interface commune pour OpenAI, Anthropic.
Permet de changer de modèle sans modifier le code métier.
"""

import asyncio
import json
import logging
import os
import re
import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import AsyncGenerator, Callable, Final, Optional, Dict, Any, List
from dataclasses import dataclass, field
from uuid import uuid4

import httpx

from app.core import clock
from app.services.anonymization.patterns import get_anonymizer
from app.services.ai.llm_logger import log_llm_exchange
from app.constants_ai import (
    OPENAI_API_URL,
    OPENAI_TIMEOUT,
    OPENAI_DEFAULT_MODEL,
    ANTHROPIC_API_URL,
    ANTHROPIC_API_VERSION,
    ANTHROPIC_TIMEOUT,
    ANTHROPIC_DEFAULT_MODEL,
    ANTHROPIC_AVAILABLE_MODELS,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TEMPERATURE,
    get_max_tokens_for_model,
    get_context_window_for_model,
    supports_capability_for_model,
    CONTEXT_WINDOW_WARNING_THRESHOLD,
)

logger = logging.getLogger(__name__)


# Regex des caractères de contrôle qu'un attaquant pourrait injecter dans
# un nom de modèle (via config BDD ou requête mal filtrée) pour corrompre
# la lecture des logs (insertion de fausses lignes dans llm_log.md).
_LOG_SANITIZE_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _sanitize_for_log(value: Optional[str], max_len: int = 120) -> str:
    """Nettoie une valeur user-controlled avant de l'interpoler dans un log.

    Remplace les caractères de contrôle (``\\n``, ``\\r``, ``\\x00``, etc.)
    par ``?`` et tronque à ``max_len`` pour éviter le log-flood. Utiliser
    dès qu'on interpole un ``model``, ``provider_name`` ou autre valeur qui
    peut traverser la config/BDD sans validation.
    """
    if value is None:
        return "None"
    s = str(value)
    s = _LOG_SANITIZE_RE.sub("?", s)
    if len(s) > max_len:
        s = s[:max_len] + "…"
    return s


def _sanitize_api_key(key: str) -> str:
    """Nettoie une clé API : supprime les caractères invisibles non-ASCII.

    Les clés API copiées-collées depuis des pages web ou des emails
    peuvent contenir des caractères Unicode invisibles (LINE SEPARATOR \u2028,
    ZERO-WIDTH SPACE \u200b, etc.) qui cassent httpx (encode en ASCII).
    """
    if not key:
        return key
    # Garder uniquement les caractères ASCII imprimables (0x20-0x7E)
    # sauf strip des espaces en début/fin
    return re.sub(r"[^\x20-\x7E]", "", key).strip()


def _normalize_provider_base_url(base_url: Optional[str], default_url: str) -> str:
    """Renvoie une ``base_url`` toujours utilisable par httpx.

    Cas traités :
    - ``None`` / ``""`` / whitespace → ``default_url`` (constante provider).
    - Sentinelle string ``'None'`` / ``'null'`` / ``'undefined'`` → idem.
      Arrive quand un form admin a stringifié une valeur nulle et l'a persisté
      dans la BDD. Sans ce guard, on produirait ``https://None`` et httpx
      lèverait ``[Errno 8] nodename nor servname provided``.
    - URL sans protocole (``api.anthropic.com/v1``) → préfixe ``https://``.
      Bug classique : un admin copie-colle l'URL depuis la barre d'adresse
      d'un navigateur sans le ``https://``, httpx lève ensuite « Request URL
      is missing an 'http://' or 'https://' protocol. ».
    - URL normale (``https://…``) → strip trailing slash et retourne.

    ``http://`` est accepté tel quel (proxy interne HTTP non-TLS autorisé ;
    on ne force pas https car ça casserait un setup volontaire).
    """
    if base_url is None:
        return default_url.rstrip("/")
    cleaned = str(base_url).strip()
    if not cleaned or cleaned.lower() in {"none", "null", "undefined"}:
        return default_url.rstrip("/")
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned.lstrip("/")
    return cleaned.rstrip("/")


# Mapping host → nom canonique du provider OpenAI-compat. Permet de
# distinguer Mistral, Groq, DeepSeek, etc. quand l'admin colle juste la
# clé API et le base_url. Sans cette détection, tous tombent sous "openai"
# et le dashboard de coût les agrège (impossibilité de tracker par provider).
_OPENAI_COMPAT_HOST_TO_PROVIDER: Final[dict[str, str]] = {
    "api.openai.com": "openai",
    "api.mistral.ai": "mistral",
    "api.groq.com": "groq",
    "api.deepseek.com": "deepseek",
    "api.together.xyz": "together",
    "api.together.ai": "together",
    "api.perplexity.ai": "perplexity",
    "api.x.ai": "xai",
    "generativelanguage.googleapis.com": "gemini",
}


def _extract_error_message(payload: Any) -> str:
    """LOT 8.2 — Extrait un message d'erreur depuis une réponse provider.

    Tolérant aux variations de schema :
    - Anthropic/OpenAI : ``{"error": {"message": "..."}}``
    - Mistral parfois : ``{"detail": "..."}`` ou ``{"message": "..."}``
    - Groq : ``{"error": {"failed_generation": "...", "message": "..."}}``
    - Fallback : ``str(payload)`` tronqué
    """
    if not isinstance(payload, dict):
        try:
            return str(payload)[:200] if payload is not None else "unknown"
        except Exception:  # noqa: BLE001
            return "unknown"
    err = payload.get("error")
    if isinstance(err, dict):
        for key in ("message", "failed_generation"):
            v = err.get(key)
            if isinstance(v, str) and v:
                return v
    if isinstance(err, str) and err:
        return err
    for key in ("detail", "message"):
        v = payload.get(key)
        if isinstance(v, str) and v:
            return v
    try:
        return str(payload)[:200]
    except Exception:  # noqa: BLE001
        return "unknown"


def _count_cache_control_breakpoints(payload: Any) -> int:
    """Compte les ``cache_control`` posés dans un payload Anthropic.

    LOT 8.8 — Anthropic limite à 4 breakpoints par requête. Au-delà,
    l'API rejette avec 400. Helper récursif pour audit/garde-fou.
    """
    if isinstance(payload, dict):
        n = 1 if "cache_control" in payload else 0
        for v in payload.values():
            n += _count_cache_control_breakpoints(v)
        return n
    if isinstance(payload, list):
        return sum(_count_cache_control_breakpoints(item) for item in payload)
    return 0


_ANTHROPIC_MAX_CACHE_BREAKPOINTS = 4


# ── Toggle prompt-caching admin (SSoT BDD via AIConfigKey.USE_CACHE) ──
# Cache 60s pour ne pas hammer la BDD à chaque appel LLM. Invalidé
# explicitement par ``invalidate_use_cache_runtime()`` quand l'admin
# save la config via ``/admin/ai-config``.
#
# Doctrine ``feedback_no_double_cap`` : un seul cap admin, pas de
# hard-cap applicatif. Quand désactivé, retire tous les ``cache_control``
# du payload Anthropic AVANT envoi — pas de prompt caching côté provider.
# Effet : tokens recomputés intégralement à chaque appel (coût +30 %
# typique mais utile pour debug ou pour économiser les breakpoints
# Anthropic limités à 4).
_USE_CACHE_TTL = 60.0
_use_cache_cache: Optional[bool] = None
_use_cache_loaded_at: float = 0.0


async def _get_use_cache_runtime() -> bool:
    """Lit ``AIConfigKey.USE_CACHE`` (SSoT BDD admin). Cache 60s.

    Fallback ``True`` si la BDD est inaccessible (préserve le comportement
    historique : prompt caching activé par défaut).
    """
    import time as _t

    global _use_cache_cache, _use_cache_loaded_at

    if _use_cache_cache is not None and (_t.time() - _use_cache_loaded_at) < _USE_CACHE_TTL:
        return _use_cache_cache
    try:
        from app.services.ai.config_service import get_ai_config_service

        cs = get_ai_config_service()
        raw = await cs.get("use_cache")
        if isinstance(raw, bool):
            value = raw
        elif isinstance(raw, str):
            value = raw.strip().lower() in ("true", "1", "yes", "on")
        elif raw is None:
            value = True  # fallback historique
        else:
            value = bool(raw)
        _use_cache_cache = value
        _use_cache_loaded_at = _t.time()
    except Exception as exc:  # noqa: BLE001 — fail-soft, garde le default
        logger.debug("use_cache runtime config load failed: %s", exc)
        _use_cache_cache = True
        _use_cache_loaded_at = _t.time()
    return _use_cache_cache


def invalidate_use_cache_runtime() -> None:
    """Appelé par ``app/handlers/ai_config.py`` quand l'admin save la
    valeur ``use_cache`` pour forcer un reload BDD à la prochaine requête.
    """
    global _use_cache_cache, _use_cache_loaded_at
    _use_cache_cache = None
    _use_cache_loaded_at = 0.0


def _strip_all_cache_control(payload: Any) -> Any:
    """Retire RÉCURSIVEMENT tous les ``cache_control`` d'un payload Anthropic.

    Utilisé quand ``AIConfigKey.USE_CACHE`` est désactivé : le payload part
    sans aucun breakpoint, donc l'API Anthropic ne caches rien (tous les
    tokens sont input tokens "neufs" facturés au tarif plein).

    Mutation in-place pour cohérence avec ``_enforce_cache_breakpoint_limit``
    (le payload est juste avant envoi HTTP, pas de raison de copier).
    """
    if isinstance(payload, dict):
        payload.pop("cache_control", None)
        for v in payload.values():
            _strip_all_cache_control(v)
    elif isinstance(payload, list):
        for item in payload:
            _strip_all_cache_control(item)
    return payload


async def _apply_cache_policy(payload: dict) -> dict:
    """Applique la politique cache admin (SSoT BDD) puis le garde-fou
    breakpoint Anthropic (max 4). Appelé juste avant l'envoi HTTP.

    Si ``use_cache=False`` (admin a désactivé), retire tous les
    ``cache_control`` du payload. Sinon, comportement historique.
    """
    if not await _get_use_cache_runtime():
        payload = _strip_all_cache_control(payload)
    return _enforce_cache_breakpoint_limit(payload)


def _enforce_cache_breakpoint_limit(payload: dict) -> dict:
    """LOT 8.8 — Garde-fou : si le payload dépasse 4 ``cache_control``,
    retire les breakpoints en EXCÈS sur les **messages les plus anciens**
    (priorité au caching récent qui amortit mieux). Ne touche jamais les
    breakpoints sur ``system``, ``tools`` (rarement plusieurs) — uniquement
    les messages historiques.

    Logue un warning visible — atteindre 5+ signale une régression à
    investiguer.
    """
    n = _count_cache_control_breakpoints(payload)
    if n <= _ANTHROPIC_MAX_CACHE_BREAKPOINTS:
        return payload
    logger.warning(
        "Anthropic cache_control: %d breakpoints détectés (max=%d). "
        "Retrait des plus anciens dans messages[].",
        n,
        _ANTHROPIC_MAX_CACHE_BREAKPOINTS,
    )
    excess = n - _ANTHROPIC_MAX_CACHE_BREAKPOINTS
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return payload
    # Retire en partant du début (anciens). Mute le payload (acceptable
    # car on est juste avant l'envoi HTTP).
    for msg in messages:
        if excess <= 0:
            break
        content = msg.get("content")
        if isinstance(content, list):
            for block in content:
                if excess <= 0:
                    break
                if isinstance(block, dict) and "cache_control" in block:
                    block.pop("cache_control", None)
                    excess -= 1
        elif isinstance(content, dict) and "cache_control" in content:
            content.pop("cache_control", None)
            excess -= 1
    return payload


def _harden_schema_strict_mode(schema: Any) -> Any:
    """LOT 3.1+3.2 — Durcit un JSON Schema pour le mode strict OpenAI/Mistral.

    Récursivement :
    - ``type:"object"`` sans ``additionalProperties`` → ajoute ``False``
    - ``type:"array"`` avec ``items`` → harden les items
    - ``properties`` dict → harden chaque sub-schema
    - ``oneOf``/``anyOf``/``allOf`` → harden chaque branche

    Ne **MODIFIE PAS** un schéma qui pose explicitement
    ``additionalProperties`` (l'admin/dev a un avis). N'enlève rien.
    Sûr à appliquer aveuglément à tous les outils.
    """
    if not isinstance(schema, dict):
        return schema
    out = dict(schema)
    schema_type = out.get("type")
    if schema_type == "object":
        if "additionalProperties" not in out:
            out["additionalProperties"] = False
        props = out.get("properties")
        if isinstance(props, dict):
            out["properties"] = {k: _harden_schema_strict_mode(v) for k, v in props.items()}
    if schema_type == "array":
        items = out.get("items")
        if items is not None:
            out["items"] = _harden_schema_strict_mode(items)
    for key in ("oneOf", "anyOf", "allOf"):
        if key in out and isinstance(out[key], list):
            out[key] = [_harden_schema_strict_mode(s) for s in out[key]]
    return out


def _merge_consecutive_same_role(messages: list[dict]) -> list[dict]:
    """Merge les messages user/assistant consécutifs (LOT 2.4).

    Préserve l'ordre, concatène le ``content`` (string). Pour les assistants
    avec ``tool_calls``, concatène les listes. Les ``tool``-roles (résultats
    d'outils) ne sont jamais mergés entre eux car chacun référence un
    ``tool_call_id`` distinct.
    """
    if not messages:
        return messages
    merged: list[dict] = []
    for msg in messages:
        role = msg.get("role")
        if merged and role in ("user", "assistant") and merged[-1].get("role") == role:
            prev = merged[-1]
            # Concat content (les deux peuvent être "" — toujours OK)
            prev_content = prev.get("content", "") or ""
            curr_content = msg.get("content", "") or ""
            if prev_content and curr_content:
                prev["content"] = prev_content + "\n" + curr_content
            elif curr_content:
                prev["content"] = curr_content
            # Concat tool_calls (assistant avec parallel calls)
            if msg.get("tool_calls"):
                prev_tcs = prev.get("tool_calls") or []
                prev["tool_calls"] = prev_tcs + msg["tool_calls"]
        else:
            merged.append(dict(msg))
    return merged


def _resolve_timeout_for_model(model_name: str, default_timeout: float) -> float:
    """LOT 8.12 — Lit ``LlmModel.timeout_seconds`` depuis le registre BDD.

    Use-cases : Groq très rapide (10s pour fail-fast), Ollama local lent
    (1800s sur GPU faible), Mistral Large lent (900s). Override admin via
    ``/admin/ai-models``. Fallback ``default_timeout`` du provider si
    absent ou registre indisponible.
    """
    if not model_name:
        return default_timeout
    try:
        from app.constants_ai import _registry_cache_lookup

        val = _registry_cache_lookup(model_name, "timeout_seconds")
        if val is not None:
            return float(val)
    except Exception:  # noqa: BLE001
        pass
    return default_timeout


def _check_model_not_deprecated(model_name: str) -> None:
    """LOT 1.4 — Garde-fou : refuse un modèle marqué ``deprecated_at`` en BDD.

    Permet à l'admin de retirer progressivement un modèle (ex: Sonnet 4 quand
    Sonnet 4.7 sort) sans risque d'utilisation accidentelle. Mieux vaut
    fail-fast avec un message clair que de laisser le provider rejeter avec
    un 404 opaque le jour où Anthropic retire vraiment le modèle.

    Fail-soft : si le registre n'est pas chargé (tests minimaux, init en cours),
    on passe — le runtime continue à fonctionner avec le static.
    """
    if not model_name:
        return
    try:
        from app.services.ai.llm_model_registry import LlmModelRegistry

        instance = LlmModelRegistry._instance
        if instance is None:
            return
        deprecated_at = instance.get_field_sync(model_name, "deprecated_at")
        if deprecated_at:
            raise ValueError(
                f"Le modèle '{model_name}' est marqué deprecated dans "
                f"/admin/ai-models (depuis {deprecated_at}). Choisir un autre "
                f"modèle actif dans la configuration admin."
            )
    except ValueError:
        raise
    except Exception:  # noqa: BLE001
        # Registre absent / corrompu → fail-soft (pas de blocage)
        return


def _detect_openai_compat_provider_from_url(base_url: str) -> Optional[str]:
    """Inférence du provider depuis le hostname de ``base_url``.

    Retourne le nom canonique (``"mistral"``, ``"groq"``, etc.) si reconnu,
    sinon ``None`` (le caller utilise le défaut ``"openai"``). Best-effort —
    une URL inconnue (ex: proxy enterprise, Ollama local) reste génériquement
    "openai", mais l'admin peut forcer un nom via ``OpenAIProvider(name=...)``.
    """
    if not base_url:
        return None
    try:
        from urllib.parse import urlparse

        host = urlparse(base_url).hostname or ""
        return _OPENAI_COMPAT_HOST_TO_PROVIDER.get(host.lower())
    except (ValueError, TypeError):
        return None


# Message injecté dans le system prompt quand des messages sont tronqués
_TRUNCATION_WARNING_TEMPLATE = (
    "\n\n⚠️ AVERTISSEMENT CONTEXTE : {count} message(s) ancien(s) "
    "de cette conversation ont été supprimés pour respecter la fenêtre de contexte. "
    "Si l'utilisateur fait référence à des éléments précédents que tu ne vois plus, "
    "dis-le clairement et demande-lui de reformuler."
)


@dataclass
class LLMRequest:
    """Requête vers un LLM."""

    prompt: str
    system: Optional[str] = None
    model: str = ""
    # ``None`` = utiliser le default admin (``/admin/ai-config``) résolu
    # au moment de l'appel via ``_temperature_for_request``. Un caller qui
    # veut une température explicite passe une valeur (ex: 0.0 pour determin
    # tasks, 0.7 pour creative). Single source of truth quand non spécifié.
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    options: Dict[str, Any] = field(default_factory=dict)
    # Préfixe stable du prompt (onglets SQL, etc.) — caché via prompt caching Anthropic.
    # Si défini, le message user est structuré en 2 blocs : [cache_prefix | prompt].
    prompt_cache_prefix: Optional[str] = None
    # Couche 2 — pseudonymizer user-scoped (/data-privacy). Si défini, le
    # chemin generate() applique les termes manuels (§…§) configurés par
    # l'admin AVANT envoi cloud, EN PLUS de la couche 1 PII. ``None`` =
    # couche 1 seule (fallback légitime : tâches utilitaires sans contexte
    # utilisateur / LLM local). Symétrique du param ``user_id`` de
    # generate_with_tools / stream_with_tools.
    user_id: Optional[int] = None


@dataclass
class LLMResponse:
    """Réponse d'un LLM."""

    content: str
    model: str
    provider: str
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    cache_creation_tokens: Optional[int] = None
    cache_read_tokens: Optional[int] = None
    # Extended thinking : nombre de tokens consommés par le raisonnement
    # interne du modèle (facturé). Présent uniquement sur Anthropic quand
    # le champ `thinking` est activé. Utile pour le suivi denial-of-wallet.
    thinking_tokens: Optional[int] = None
    duration_seconds: float = 0.0
    raw_response: Optional[Dict[str, Any]] = None

    @property
    def estimated_cost_usd(self) -> float:
        """LOT 8.7 — Coût estimé en USD pour cet appel LLM.

        Délègue à ``llm_call_tracker._compute_cost_snapshot`` (SOURCE UNIQUE de
        vérité du calcul de coût — D1-F4) : pricing registre BDD prioritaire,
        prise en compte du cache_read / cache_creation, et surtout distinction
        ``None`` (modèle non-tarifé → warning fail-loud ``[BILLING]`` + cap NON
        comptabilisé) vs ``0.0`` (modèle explicitement gratuit enregistré).

        Avant D1-F4, cette property dupliquait la formule de coût en moins bon
        (elle ratait le cas pricing placeholder ``0.0/0.0`` pré-sync → coût 0
        silencieux → cap ``max_llm_cost_eur`` jamais déclenché = denial-of-wallet
        masqué). La délégation supprime la duplication ET hérite du warning.

        Permet à ``dag_executor.cumulative_llm_cost_eur`` de cumuler les coûts de
        TOUS les call-sites LLM d'une automation pour appliquer le cap
        ``max_llm_cost_eur``. Retourne 0.0 quand le coût est inconnu (le warning
        du snapshot rend le masquage VISIBLE) ou réellement nul. Ne lève jamais.
        """
        try:
            from app.services.ai.llm_call_tracker import _compute_cost_snapshot

            cost = _compute_cost_snapshot(
                self.model or "",
                self.prompt_tokens,
                self.completion_tokens,
                self.cache_read_tokens,
                self.thinking_tokens,
                self.cache_creation_tokens,
            )
            return float(cost) if cost is not None else 0.0
        except Exception:  # noqa: BLE001 — le calcul de coût ne doit jamais casser un tour
            return 0.0

    @property
    def estimated_cost_eur(self) -> float:
        """Conversion USD→EUR à taux conservateur (1 USD = 0.95 EUR au
        2026-04). Utilise pour comparer à ``automation.max_llm_cost_eur``."""
        return self.estimated_cost_usd * 0.95


class RateLimitError(Exception):
    """Levée quand l'API retourne 429 et que les retries sont épuisées."""

    def __init__(self, retry_after: float, message: str = ""):
        self.retry_after = max(1.0, float(retry_after))
        super().__init__(message or f"Rate limited, retry after {self.retry_after:.0f}s")


class LLMFeature(str, Enum):
    """Features LLM connues que ``LLMProvider.supports_feature`` peut interroger.

    Hérite de ``str`` pour que la comparaison ``feature == "prompt_caching"``
    continue de marcher (zero breaking change côté callers qui passent un
    literal string). Ajouter une feature = 1 entrée ici ET une entrée dans
    ``_CAPABILITIES`` de chaque provider concerné (les autres providers
    hériteront du ``False`` par défaut via la base class).

    Un nom de feature inconnu passé à ``supports_feature`` loggue un
    ``warning`` (fail-loud pour détecter les typos) mais retourne ``False``
    (fail-safe pour ne jamais bloquer un tour sur une question capacitaire).
    """

    PROMPT_CACHING = "prompt_caching"
    INTERLEAVED_THINKING = "interleaved_thinking"
    EXTENDED_THINKING = "extended_thinking"
    API_COMPACTION = "api_compaction"
    TOOL_SEARCH_TOOL = "tool_search_tool"


# Set de lookup rapide pour la validation — extrait de l'Enum.
_KNOWN_FEATURE_VALUES: frozenset[str] = frozenset(f.value for f in LLMFeature)


# Type d'un handler de capability : prend le modèle cible et retourne bool.
# Permet aux sous-classes d'exposer leur logique via un dict (Open/Closed).
CapabilityHandler = Callable[[Optional[str]], bool]


class LLMProvider(ABC):
    """
    Interface abstraite pour les fournisseurs LLM.

    Inspiré de Vanna.ai LlmService:
    chaque provider implémente generate() et list_models().
    """

    provider_name: str = "base"

    @abstractmethod
    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Génère une réponse à partir d'un prompt."""

    @abstractmethod
    async def list_models(self) -> List[Dict[str, Any]]:
        """Liste les modèles disponibles."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Vérifie la disponibilité du provider."""

    async def close(self):
        """Ferme les ressources."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    def _resolve_request_model(self, request_model: Optional[str], fallback: str) -> str:
        """Résout le modèle effectif pour un appel provider.

        **Priorité** :
        1. ``request.model`` explicite (le caller a choisi).
        2. ``LLMManager.default_model_name`` — choix admin via
           ``/admin/ai-config``. Garantit que les call-sites qui bypassent
           le manager (``copilot_memory``, ``llm_report_planner``,
           ``vanna_enhanced_generator``) respectent quand même la config admin.
        3. ``fallback`` — constante du provider (``ANTHROPIC_DEFAULT_MODEL`` /
           ``OPENAI_DEFAULT_MODEL``). Filet de sécurité dernier recours pour
           que le provider puisse fonctionner même si le manager n'est pas
           initialisé (tests unitaires, scripts standalone).

        **Garde-fou deprecated_at** : si le modèle résolu est marqué
        ``deprecated_at`` non-null dans le registre BDD, lève une
        ``ValueError`` claire pour l'admin. Mieux vaut un échec immédiat
        et explicite (« choisir un autre modèle dans /admin/ai-models »)
        qu'un crash 404 opaque côté provider quand celui-ci finit par
        retirer effectivement le modèle.
        """
        if request_model:
            resolved = request_model
        else:
            try:
                mgr = get_llm_manager()
                chosen = mgr.default_model_name
                if chosen:
                    resolved = chosen
                else:
                    resolved = fallback
            except Exception:  # noqa: BLE001
                resolved = fallback
        # Garde-fou deprecated_at — applicable à tous les chemins
        _check_model_not_deprecated(resolved)
        return resolved

    def _capability_map(self) -> dict[str, CapabilityHandler]:
        """Retourne la map feature→handler pour CE provider.

        Pattern Open/Closed : une sous-classe déclare ici les features qu'elle
        supporte via un dict `{feature_value: handler(model) -> bool}`. Les
        features absentes du dict héritent automatiquement du fallback
        ``False`` côté base class.

        Par défaut : dict vide (la base class ne supporte rien).
        """
        return {}

    def supports_feature(
        self,
        feature: str,
        *,
        model: Optional[str] = None,
    ) -> bool:
        """Indique si ce provider (et optionnellement ce modèle) supporte une feature.

        Voir :class:`LLMFeature` pour la liste des features connues :
        ``prompt_caching``, ``interleaved_thinking``, ``extended_thinking``,
        ``api_compaction``, ``tool_search_tool``.

        Contrat :
            - ``feature`` non-string → retourne False (fail-safe).
            - ``feature`` inconnue → log warning + retourne False (fail-loud).
            - ``feature`` connue mais non mappée par ce provider → False.
            - ``feature`` connue et mappée → délègue au handler (qui peut
              dépendre du ``model`` passé en keyword-only).

        Args:
            feature: Nom de la feature (valeur d'un :class:`LLMFeature`).
            model: Keyword-only. Certaines features (extended_thinking) ne
                marchent que sur un sous-ensemble des modèles du provider.

        Returns:
            True si supporté, False sinon (jamais de crash).
        """
        # Fail-safe : type invalide = pas de support.
        if not isinstance(feature, str):
            return False
        # Fail-loud : si le caller a une typo (ex: "prompt-caching" avec tiret),
        # on veut le voir en logs plutôt que dégrader silencieusement.
        if feature not in _KNOWN_FEATURE_VALUES:
            logger.warning(
                "supports_feature('%s') : feature inconnue. "
                "Features connues: %s. Retourne False par défaut.",
                feature,
                sorted(_KNOWN_FEATURE_VALUES),
            )
            return False
        # Délégation : si la sous-classe déclare cette feature dans son dict,
        # on appelle son handler ; sinon False.
        handler = self._capability_map().get(feature)
        if handler is None:
            return False
        return handler(model)


# ── Compact LLM-assisté ──────────────────────────────────────
#
# Quand une conversation agentic devient longue (10+ turns avec tool_results
# verbeux), on approche ou dépasse la context window. Le comportement
# historique était une TRONCATURE brute (jeter les N premiers messages),
# qui perdait toute information utile. Le compact la remplace quand
# possible : un appel LLM léger résume les vieux messages en un seul bloc
# texte qui prend en charge la logique de décision et les découvertes
# factuelles, puis on conserve les derniers messages intacts. Gain typique :
# 40-80K tokens libérés selon la densité.
#
# Déclenchement : `estimated_tokens > budget_input * _COMPACT_TRIGGER_RATIO`.
# Cible : ramener le payload sous `budget_input * _COMPACT_TARGET_RATIO`.
# Queue préservée : `_COMPACT_KEEP_TAIL` derniers messages conservés pour
# que la continuité immédiate reste intacte (le dernier tool_result, la
# question en cours…).
#
# Re-entrance : après un compact, si la conversation re-grossit, un 2ème
# compact se déclenchera et résumera le précédent résumé + les nouveaux
# messages. Aucune limite sur le nombre de compacts successifs.
#
# Fail : si aucun provider Anthropic n'est disponible pour appeler Haiku,
# ou si l'appel de résumé lève, on retombe sur la troncature classique
# (déjà corrigée pour respecter l'invariant tool_use/tool_result). Pas
# de fallback qui masque : le log expose clairement ce qui s'est passé.
_COMPACT_TRIGGER_RATIO = 0.85
_COMPACT_TARGET_RATIO = 0.50
# Ratio de la conversation conservé en queue (non compacté). On garde ~30%
# des messages les plus récents ; les ~70% plus anciens sont résumés. Le
# choix 30% est un équilibre : assez pour que le LLM voie ses dernières
# décisions et les tool_results directement consultés récemment, mais
# assez court pour que la libération de contexte soit substantielle sur
# une conversation longue.
_COMPACT_KEEP_RATIO = 0.30
# Plancher et plafond absolus pour éviter les cas pathologiques : sur une
# conversation courte, on garde au moins 4 messages (soit 2 paires
# user/assistant, soit le dernier tool_use et son result). Sur une
# conversation très longue (>33 messages), on plafonne la queue à 10
# pour que le compact libère toujours quelque chose d'utile.
_COMPACT_KEEP_TAIL_MIN = 4
_COMPACT_KEEP_TAIL_MAX = 10
_COMPACT_MAX_SUMMARY_TOKENS = 4000
# Ratio "chars / tokens" utilisé pour les approximations rapides (4 chars/token
# est l'estimation Anthropic standard pour le français/anglais). Sert ici à
# convertir le ``context_window`` en chars pour le cap du compactage.
_CHARS_PER_TOKEN = 4
# Fraction du ``context_window`` qu'on accepte d'envoyer au summarizer.
# Au-delà, on abandonne le compact et on laisse la troncature classique
# prendre le relais (évite qu'un run pathologique envoie une chaîne plus
# grosse que la context window du summarizer lui-même).
_COMPACT_MAX_CONVERSATION_RATIO = 0.75


def _compact_max_conversation_chars(model_name: str) -> int:
    """Cap dynamique sur la chaîne sérialisée envoyée au summarizer,
    proportionnel au ``context_window`` du modèle actif.

    Évite de hardcoder un seuil absolu qui devient soit trop bas (modèle
    1M tokens : on compacte trop tôt), soit trop haut (modèle 32K tokens :
    on satureait le summarizer). Lookup au runtime depuis le registre
    central — passer Sonnet 4.6 de 200K à 1M relève automatiquement le
    cap (de ~600K à ~3M chars).
    """
    from app.constants_ai import get_context_window_for_model

    cw = get_context_window_for_model(model_name) if model_name else 200_000
    return int(cw * _CHARS_PER_TOKEN * _COMPACT_MAX_CONVERSATION_RATIO)


def _resolve_keep_tail(n_messages: int) -> int:
    """Nombre de messages de queue à conserver non-compactés, selon la
    taille de la conversation. Borné entre ``_COMPACT_KEEP_TAIL_MIN`` et
    ``_COMPACT_KEEP_TAIL_MAX``. Cible ``_COMPACT_KEEP_RATIO`` de la
    conversation totale.
    """
    target = int(n_messages * _COMPACT_KEEP_RATIO)
    return max(_COMPACT_KEEP_TAIL_MIN, min(_COMPACT_KEEP_TAIL_MAX, target))


_COMPACT_SUMMARY_PROMPT = """\
Tu es un résumeur de conversation agent-IA. Voici la PARTIE LA PLUS ANCIENNE (en général ~70%) d'une conversation entre un agent qui manipule des données et ses outils. Cette portion doit être résumée pour libérer de la context window, tandis que les derniers tours (~30%) seront conservés tels quels pour que l'agent puisse continuer. Les tours conservés peuvent référencer des informations découvertes dans la partie que tu résumes — d'où l'importance de préserver tout ce qui peut encore servir.

**Objectif du résumé** : préserver TOUT ce qui permet — ou permettrait — à l'agent de répondre à la demande INITIALE de l'utilisateur (qui est le premier message de la conversation). Tout ce qui a été découvert, décidé, ou constaté et qui peut être encore nécessaire pour finir la tâche doit rester dans le résumé, même si l'agent ne semble pas s'en resservir dans l'instant. Le critère est : « si je supprime cette information, est-ce que l'agent risque d'être obligé de re-explorer ou de passer à côté d'un élément utile à la demande utilisateur ? ». Si oui, garde-la.

**À préserver systématiquement** :
- Découvertes factuelles : valeurs chiffrées, comptes, structures, schémas de données, sources identifiées, labels et codes rencontrés, col_distinct vus.
- Décisions prises : substitutions sémantiques validées et leur raison, hypothèses confirmées ou infirmées, sources écartées et pourquoi, chemins abandonnés et pourquoi.
- Progrès vs. demande utilisateur : ce qui est fait, ce qui reste à couvrir pour satisfaire la demande initiale, obstacles encore ouverts.
- Références techniques : index d'onglets, noms de colonnes, identifiants, tokens opaques (§...§) qui seront ré-utilisés en aval. Préserve ces tokens exactement tels quels — ce sont des références opaques que l'agent consommera.

**À ne pas conserver** : les tentatives abandonnées sans aucune information tirée (purement exploratoires et stériles), les répétitions, l'enrobage textuel.

**Règle d'or** : mieux vaut un résumé un peu plus long qui garde une donnée qui se révélera utile, qu'un résumé trop aggressif qui force l'agent à re-explorer ou à livrer un résultat incomplet. Si tu hésites sur une information, GARDE-LA.

**Format** : texte dense en paragraphes et/ou puces, pas de préambule du type « Voici le résumé… », pas de conclusion meta. Retourne directement le contenu du résumé, que l'agent pourra lire comme un rappel de ce qu'il a déjà fait.

**Demande initiale de l'utilisateur** (à garder comme cap du résumé) :
---
{initial_user_request}
---

**Portion de la conversation à résumer** (de l'ancien vers le récent) :
---
{conversation_text}
---
"""


def _messages_to_text(messages: list) -> str:
    """Sérialise une liste de messages (assistant + user tool_results) en texte
    dense pour le prompt du compact. Préserve la structure (rôle, tool calls,
    tool results) sans les blocs binaires/schémas lourds.
    """
    lines: List[str] = []
    for i, msg in enumerate(messages):
        role = msg.get("role", "?")
        content = msg.get("content", "")
        if isinstance(content, str):
            lines.append(f"[msg {i} — {role}]\n{content}")
        elif isinstance(content, list):
            parts: List[str] = []
            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type")
                if btype == "text":
                    parts.append(block.get("text", ""))
                elif btype == "thinking":
                    # On ne garde PAS le thinking opaque (signature) dans le résumé
                    # — c'est du bruit pour Haiku. Garder juste un marqueur.
                    pass
                elif btype == "tool_use":
                    name = block.get("name", "?")
                    inp = block.get("input", {})
                    parts.append(
                        f"[appel outil: {name}({json.dumps(inp, ensure_ascii=False)[:500]})]"
                    )
                elif btype == "tool_result":
                    raw = block.get("content", "")
                    if isinstance(raw, list):
                        raw = json.dumps(raw, ensure_ascii=False)
                    elif not isinstance(raw, str):
                        raw = str(raw)
                    # Cap chaque tool_result à 2KB dans le résumé : au-delà
                    # c'est du détail brut (rows, col_distinct complets) que
                    # Haiku va de toute façon condenser.
                    if len(raw) > 2048:
                        raw = raw[:2048] + f"… (+{len(raw) - 2048} chars tronqués)"
                    parts.append(f"[résultat outil]: {raw}")
            if parts:
                lines.append(f"[msg {i} — {role}]\n" + "\n".join(parts))
    return "\n\n".join(lines)


def _extract_tool_use_ids_in_message(msg: dict) -> set:
    """Extrait les tool_use_id ÉMIS par un message assistant.

    Couvre les deux formats provider :
    - **Anthropic** : ``content`` = liste de blocks, type ``tool_use`` avec ``id``
    - **OpenAI compat** (Mistral, Groq, DeepSeek, OpenAI, …) : ``tool_calls``
      array sur le message assistant, chaque entrée a ``id``

    Indispensable pour valider l'invariant cross-provider à la troncature
    (LLM_PROVIDERS_DYN switching = même fonction tourne quel que soit le
    provider actif).
    """
    ids: set = set()
    # Format Anthropic (content blocks)
    content = msg.get("content", "")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                tid = block.get("id")
                if isinstance(tid, str):
                    ids.add(tid)
    # Format OpenAI compat (tool_calls array sur l'assistant)
    if msg.get("role") == "assistant":
        tcs = msg.get("tool_calls")
        if isinstance(tcs, list):
            for tc in tcs:
                if isinstance(tc, dict):
                    tid = tc.get("id")
                    if isinstance(tid, str):
                        ids.add(tid)
    return ids


def _extract_tool_result_refs_in_message(msg: dict) -> set:
    """Extrait les tool_use_id RÉFÉRENCÉS par un message tool_result.

    Couvre les deux formats provider :
    - **Anthropic** : message ``role=user`` avec block ``tool_result`` qui
      porte ``tool_use_id``
    - **OpenAI compat** : message ``role=tool`` avec ``tool_call_id``
    """
    refs: set = set()
    # Format OpenAI compat (role=tool dédié)
    if msg.get("role") == "tool":
        tid = msg.get("tool_call_id")
        if isinstance(tid, str):
            refs.add(tid)
    # Format Anthropic (tool_result block dans content user)
    content = msg.get("content", "")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                tid = block.get("tool_use_id")
                if isinstance(tid, str):
                    refs.add(tid)
    return refs


def _find_safe_compact_boundary(messages: list, desired_keep_start: int) -> int:
    """Détermine un `keep_start` qui respecte l'invariant tool_use/tool_result
    à la coupure : TOUS les tool_use_id référencés par des tool_result dans
    messages[keep_start:] doivent avoir leur assistant-émetteur AUSSI dans
    messages[keep_start:] (pas dans la zone compactée).

    Stratégie : on part de `desired_keep_start`, on collecte tous les
    tool_use_id référencés dans la queue, puis on recule keep_start tant
    que des tool_use_id manquent (= leur émetteur est dans la zone
    compactée). On s'arrête dès que toutes les refs sont couvertes, ou
    on abandonne si on descend sous 1 (messages[0] doit rester intact).

    Retourne `keep_start` valide, ou 0 si impossible (caller abandonne compact).
    """
    keep_start = max(1, desired_keep_start)
    # Évite la boucle infinie si les messages sont mal formés.
    for _ in range(len(messages) + 1):
        queue = messages[keep_start:]
        # Tous les tool_use_id RÉFÉRENCÉS dans la queue (par des tool_result)
        refs_needed: set = set()
        for m in queue:
            refs_needed |= _extract_tool_result_refs_in_message(m)
        if not refs_needed:
            return keep_start
        # Tous les tool_use_id ÉMIS dans la queue (par des assistant tool_use)
        emitted: set = set()
        for m in queue:
            emitted |= _extract_tool_use_ids_in_message(m)
        missing = refs_needed - emitted
        if not missing:
            return keep_start
        # Il reste des tool_result dont l'émetteur est dans la zone compactée.
        # Recule d'un cran pour inclure cet émetteur.
        if keep_start <= 1:
            # Pas assez de place pour reculer sans toucher messages[0]. Abandonne.
            return 0
        keep_start -= 1
    return 0


def _resolve_compact_summarizer_model(provider: Any, fallback_model: str) -> str:
    """Résout le modèle à utiliser pour le résumé compact.

    **LOT 8.4** — Stratégie :
    1. Si l'admin a configuré un ``utility_model`` distinct dans le
       registre BDD (champ futur), l'utiliser (cheap : Haiku/gpt-4o-mini).
    2. Sinon : utiliser ``manager.default_model_name`` (= modèle primary).
       Cohérent mais cher si admin a Opus configuré.
    3. Fallback ultime : ``fallback_model`` (modèle de la tâche actuelle).

    L'option (1) permet à un admin avec Opus 4.7 ($15/$75 le Mtok) de
    rediriger les compactages vers Haiku 4.5 ($1/$5) → ×15 d'économie.
    """
    # 1. utility_model BDD (registre éditable admin) — DU MÊME PROVIDER que
    # l'appel parent : le résumé part via ``mgr.generate(provider_name=
    # provider.provider_name)`` (cf. plus bas), donc un utility d'un AUTRE
    # provider est garanti 404. Incident 2026-06-12 : sans ce filtre,
    # ``phi3:mini`` (ollama, is_utility=1 en base) partait sur l'API
    # Anthropic → 404 → « falling back to truncation » à CHAQUE compaction,
    # en silence. Accès via l'API publique du registre — l'itération directe
    # de ``_cache_by_name`` est un anti-pattern (cf. CLAUDE.md).
    try:
        from app.services.ai.llm_model_registry import get_llm_model_registry

        utility = get_llm_model_registry().find_utility_model_sync(
            getattr(provider, "provider_name", None)
        )
        if utility:
            return utility
    except Exception:  # noqa: BLE001
        pass
    # 2. Manager default model
    try:
        mgr = get_llm_manager()
        if mgr.default_model_name:
            return mgr.default_model_name
    except Exception:  # noqa: BLE001
        pass
    # 3. Fallback final : modèle courant ou attribut provider
    for attr in ("default_model_name", "model", "_default_model"):
        candidate = getattr(provider, attr, None)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return fallback_model


async def _maybe_compact_messages(
    *,
    provider: Any,
    messages: list,
    system: Optional[str],
    tools: Optional[list],
    max_tokens: int,
    model: str,
) -> tuple[list, int]:
    """Tente de compacter les messages anciens via un appel LLM léger si le
    payload dépasse le seuil de déclenchement. Retourne (messages_compactés,
    compacted_count). Si le compact est impossible ou échoue, retourne
    (messages, 0) — le caller se rabattra sur la troncature classique.

    Le compact **ne lève jamais** : toute erreur provider/réseau est logguée
    et on retourne les messages originaux. Best-effort qui dégrade proprement.
    """
    keep_tail = _resolve_keep_tail(len(messages)) if messages else 0
    if not messages or len(messages) <= keep_tail + 2:
        return messages, 0

    context_window = get_context_window_for_model(model)
    budget_input = context_window - max_tokens
    if budget_input <= 0:
        return messages, 0

    total_chars = 0
    if system:
        total_chars += len(system)
    if tools:
        total_chars += len(json.dumps(tools, ensure_ascii=False))
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            total_chars += len(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    total_chars += len(json.dumps(block, ensure_ascii=False))

    estimated_tokens = total_chars // 3
    trigger_threshold = int(budget_input * _COMPACT_TRIGGER_RATIO)
    if estimated_tokens <= trigger_threshold:
        return messages, 0

    # Trouve un keep_start qui préserve l'invariant tool_use/tool_result.
    # Robuste aux cas de tool_use batchés (N tool_uses dans un seul content
    # assistant) et aux référencements croisés.
    desired_keep_start = max(1, len(messages) - keep_tail)
    keep_start = _find_safe_compact_boundary(messages, desired_keep_start)
    if keep_start <= 0:
        return messages, 0

    to_compact = messages[1:keep_start]
    if not to_compact:
        return messages, 0

    conversation_text = _messages_to_text(to_compact)
    # Cap dynamique : proportionnel au context_window du modèle actif.
    # Sur Sonnet 4.6 GA 1M, ce cap est ~3M chars (75% × 1M tokens × 4 chars).
    # Sur un modèle 32K legacy, ~96K chars. Évite le hardcoded 150K qui
    # devenait soit trop bas (1M models : compact prématuré) soit trop
    # haut (small models : summarizer saturé).
    compact_cap = _compact_max_conversation_chars(model)
    if len(conversation_text) > compact_cap:
        logger.warning(
            "Compact abandonné : conversation_text %d chars > cap %d (modèle %s) ; "
            "fallback troncature.",
            len(conversation_text),
            compact_cap,
            model,
        )
        return messages, 0

    # Extrait la demande initiale utilisateur pour ancrer le résumé.
    initial_request = ""
    initial_content = messages[0].get("content", "")
    if isinstance(initial_content, str):
        initial_request = initial_content
    elif isinstance(initial_content, list):
        for block in initial_content:
            if isinstance(block, dict) and block.get("type") == "text":
                initial_request += block.get("text", "")
    initial_request = initial_request.strip()[:4000]  # cap défensif

    prompt = _COMPACT_SUMMARY_PROMPT.replace(
        "{initial_user_request}", initial_request or "(demande initiale non extraite)"
    ).replace("{conversation_text}", conversation_text)

    summarizer_model = _resolve_compact_summarizer_model(provider, model)
    try:
        req = LLMRequest(
            prompt=prompt,
            system="",
            model=summarizer_model,
            temperature=0.0,
            max_tokens=_COMPACT_MAX_SUMMARY_TOKENS,
        )
        # Route via manager.generate si le singleton est initialisé : ça
        # passe par ``llm_call_tracker`` et logue les tokens consommés
        # par le compact dans ``ai_performance_logs`` → visibles dans
        # ``/admin/ai-config`` Consommation API. Sans ça, les tokens du
        # compact (jusqu'à ~_COMPACT_MAX_SUMMARY_TOKENS par déclenchement)
        # sont invisibles dans le tracking → écart silencieux entre la
        # facture provider et le KPI Komptia (review adversariale 2026-05-15
        # P4 #25).
        #
        # **Caller** : on pose explicitement ``iris_compress_history``
        # (déjà déclaré dans ``KNOWN_CALLERS`` mais jamais posé jusqu'ici).
        # Sans ce context, le compact hériterait du caller parent
        # (``iris_main``, ``copilot_workspace``, ...) et polluerait son
        # compteur — l'admin verrait "iris_main 200 calls" au lieu de
        # "iris_main 100 + iris_compress_history 100" et accuserait Iris
        # à tort de gaspillage. Cette catégorie séparée permet de mesurer
        # le coût des compacts pour décider de leur seuil.
        #
        # **provider_name** explicit pour rester sur le MÊME provider que
        # l'appel parent (sinon manager.generate utiliserait le default qui
        # peut différer du provider qui a déclenché le compact). Si le
        # manager est désynchronisé (admin vient de désactiver le provider
        # via /admin/ai-config en plein run), ``mgr.get_provider`` raise
        # ValueError → fallback explicit sur la réf locale ``provider``
        # (sinon perte du compact alors que provider.generate marcherait).
        #
        # Fallback : si manager non init (cas standalone tests, scripts CLI
        # comme ``scripts/pipeline.py``), appel provider direct sans
        # tracker → backward-compat documentée et acceptée.
        from app.utils.request_context import llm_call_context

        mgr = _llm_manager
        if mgr is not None:
            with llm_call_context(caller="iris_compress_history"):
                try:
                    resp = await mgr.generate(req, provider_name=provider.provider_name)
                except ValueError as ve:
                    # Provider désynchronisé (rare : admin reload providers
                    # en plein run). Fallback direct sans perdre le compact.
                    logger.warning(
                        "Manager désynchronisé pour provider=%s (%s) — "
                        "fallback compact en direct sans tracker.",
                        provider.provider_name,
                        ve,
                    )
                    resp = await provider.generate(req)
        else:
            resp = await provider.generate(req)
    except Exception as exc:
        logger.warning(
            "Compact LLM call failed (%s); falling back to truncation.",
            _sanitize_for_log(str(exc), max_len=200),
        )
        return messages, 0

    summary = (resp.content or "").strip()
    if not summary:
        logger.warning("Compact LLM returned empty summary; falling back to truncation.")
        return messages, 0

    # Fusionne le résumé DANS le message initial au lieu d'ajouter un second
    # message user — évite 2 users consécutifs qui dégradent le cache.
    # L'agent voit : [instruction initiale + rappel de ce qui a été fait] + queue.
    # Préserve le premier message dans son type original (string ou list).
    compact_marker = (
        "\n\n---\n"
        "[CONTEXTE COMPACTÉ — les premiers tours de cette conversation ont "
        "été résumés pour libérer la context window. Le résumé ci-dessous "
        "préserve les découvertes, décisions et progrès nécessaires à ta "
        "tâche ; les détails bruts sont supprimés.]\n\n" + summary
    )
    original_content = messages[0].get("content", "")
    if isinstance(original_content, str):
        fused_content = original_content + compact_marker
    elif isinstance(original_content, list):
        # Copie la liste et append un text block avec le résumé.
        fused_content = list(original_content) + [{"type": "text", "text": compact_marker}]
    else:
        fused_content = str(original_content) + compact_marker

    fused_first_msg = {"role": "user", "content": fused_content}
    new_messages = [fused_first_msg] + messages[keep_start:]
    compacted_count = len(to_compact)
    logger.info(
        "Context compact : %d message(s) résumés via %s "
        "(~%d tokens estimés avant compact, queue conservée: %d).",
        compacted_count,
        summarizer_model,
        estimated_tokens,
        len(messages) - keep_start,
    )
    return new_messages, compacted_count


def _check_context_window(
    model: str,
    messages: list,
    system: Optional[str] = None,
    tools: Optional[list] = None,
    max_tokens: int = 0,
) -> tuple[list, int]:
    """
    Estime la taille du payload en tokens et tronque les messages si nécessaire.

    Fonction partagée entre AnthropicProvider et OpenAIProvider.
    Retourne (messages, removed_count).
    """
    context_window = get_context_window_for_model(model)
    budget_input = context_window - max_tokens

    total_chars = 0
    if system:
        total_chars += len(system)
    if tools:
        total_chars += len(json.dumps(tools, ensure_ascii=False))
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            total_chars += len(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    total_chars += len(json.dumps(block, ensure_ascii=False))

    # JSON-heavy payloads (tool_use/tool_result) are ~3 chars/token, not 4
    estimated_tokens = total_chars // 3
    warning_threshold = int(budget_input * CONTEXT_WINDOW_WARNING_THRESHOLD)

    if estimated_tokens > budget_input and len(messages) > 2:
        target_tokens = int(budget_input * 0.70)
        tokens_to_remove = estimated_tokens - target_tokens

        removed_chars = 0
        keep_from = 1
        i = 1
        while i < len(messages) - 2 and removed_chars // 4 < tokens_to_remove:
            msg = messages[i]
            content = msg.get("content", "")
            if isinstance(content, list):
                removed_chars += len(json.dumps(content, ensure_ascii=False))
            elif isinstance(content, str):
                removed_chars += len(content)
            i += 1
            keep_from = i

        # CRITIQUE : invariants providers à la troncature.
        #
        # Le payload final est ``[messages[0]] + messages[keep_from:]``.
        # ``messages[0]`` est le préambule user (instruction initiale).
        # Pour qu'Anthropic comme OpenAI compat (Mistral, Groq, …) acceptent
        # le payload, ``messages[keep_from]`` DOIT respecter deux invariants :
        #
        # 1. **Alternance de rôles** (Anthropic strict, OpenAI tolérant) :
        #    le premier message conservé après ``messages[0]=user`` doit
        #    être ``assistant``. Sinon : Anthropic merge deux users
        #    consécutifs, et tout ``tool_result`` du 2ème user devient
        #    orphelin de ``messages[0]`` (erreur 400 :
        #    ``messages.0.content.1: unexpected tool_use_id``).
        #
        # 2. **Intégrité tool_use ↔ tool_result** : tout ``tool_result``
        #    (Anthropic) ou message ``role=tool`` (OpenAI) dans la queue
        #    conservée doit référencer un ``tool_use``/``tool_call`` ÉMIS
        #    par un assistant ÉGALEMENT dans la queue. Les helpers
        #    ``_extract_tool_use_ids_in_message`` et
        #    ``_extract_tool_result_refs_in_message`` couvrent les deux
        #    formats — DRY cross-provider.
        #
        # Stratégie : on **recule** ``keep_from`` (pas en avant) jusqu'à
        # tomber sur un assistant qui satisfait les deux invariants. Reculer
        # préserve plus de contexte ET trouve toujours un assistant valide
        # tant qu'il y en a un dans la conversation (puisque les tours
        # alternent assistant↔user). Si on atterrit à ``keep_from=1`` sans
        # rien trouver de valide, on n'effectue PAS de troncature : mieux
        # vaut un payload over-budget (l'API peut compresser ou rejeter
        # avec un message clair) qu'un orphan tool_result silencieux.
        while keep_from > 1:
            m = messages[keep_from]
            role = m.get("role")
            if role == "assistant":
                queue = messages[keep_from:]
                refs_needed: set = set()
                emitted: set = set()
                for q in queue:
                    refs_needed |= _extract_tool_result_refs_in_message(q)
                    emitted |= _extract_tool_use_ids_in_message(q)
                if not (refs_needed - emitted):
                    break  # frontière valide
            keep_from -= 1

        # Si on a reculé jusqu'à 1, aucune coupe valide n'a été trouvée :
        # on annule la troncature plutôt que de produire un payload invalide.
        if keep_from <= 1:
            logger.warning(
                "Context window %s: ~%d/%d tokens estimés mais aucune frontière "
                "de troncature ne préserve l'invariant tool_use/tool_result + "
                "alternance. Troncature annulée — payload conservé tel quel "
                "(l'API peut compresser/rejeter, mais pas de 400 silencieux).",
                model,
                estimated_tokens,
                budget_input,
            )
            return messages, 0

        truncated = [messages[0]] + messages[keep_from:]
        removed_count = keep_from - 1
        if removed_count > 0:
            logger.warning(
                "Context window %s: ~%d/%d tokens estimés. "
                "Troncature de %d message(s) ancien(s) "
                "(paires tool_use/tool_result préservées).",
                model,
                estimated_tokens,
                budget_input,
                removed_count,
            )
        return truncated, removed_count

    if estimated_tokens > warning_threshold:
        pct = int(estimated_tokens / budget_input * 100)
        logger.warning(
            "Context window %s: ~%d/%d tokens estimés (%d%% du budget input). "
            "Proche de la limite.",
            model,
            estimated_tokens,
            budget_input,
            pct,
        )

    return messages, 0


# ══════════════════════════════════════════════════════════════════════
# Retry centralisé — erreurs HTTP et réseau transitoires
# ══════════════════════════════════════════════════════════════════════
# Tous les providers (Anthropic, OpenAI, futurs) utilisent ces utilitaires
# pour décider quand retry. Cela garantit un comportement uniforme face à
# une surcharge API (429/529), une erreur serveur transitoire (5xx), un
# timeout ou une panne réseau ponctuelle.
#
# Sans helper centralisé, chaque méthode a sa propre liste de codes et
# finit par diverger : c'est exactement ce qui est arrivé avec
# AnthropicProvider.generate() qui retryait 429 mais pas 529, provoquant
# des échecs silencieux lors des pics de charge Anthropic.
#
# Philosophie : TOUS les codes HTTP listés ici sont transitoires par
# définition (RFC 7231 + recommandations Anthropic/OpenAI). Les erreurs
# non-retriables (auth, payload, not found) lèvent directement.

# Codes HTTP transitoires à retry :
#   408 Request Timeout, 429 Too Many Requests, 500 Internal Server Error,
#   502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout,
#   529 Overloaded (spécifique Anthropic)
_RETRIABLE_HTTP_CODES = frozenset({408, 429, 500, 502, 503, 504, 529})

# Exceptions réseau transitoires. httpx.TimeoutException couvre les timeouts
# de connexion, lecture et pool. httpx.NetworkError couvre les erreurs de
# socket (connection reset, refused, etc.).
_RETRIABLE_NETWORK_EXC: tuple[type[BaseException], ...] = (
    httpx.TimeoutException,
    httpx.NetworkError,
)

_RETRY_AFTER_RE = re.compile(r"^\d+(\.\d+)?$")


def _parse_retry_after(header_value: Optional[str], fallback: float) -> float:
    """Parse le header Retry-After en secondes. Cap à 60s, fallback si invalide.

    LOT 8.3 — Tolère 3 formats :
    - Entier/float : secondes (Anthropic, OpenAI standard).
    - HTTP-date RFC 7231 (``Wed, 21 Oct 2026 07:28:00 GMT``) : Mistral l'utilise
      souvent — on calcule le delta vs maintenant.
    - Vide / invalide → ``fallback``.
    """
    if not header_value:
        return fallback
    raw = header_value.strip()
    # 1. Format numérique (secondes)
    try:
        val = float(raw)
        return min(val, 60.0) if val > 0 else fallback
    except (ValueError, TypeError):
        pass
    # 2. Format HTTP-date
    try:
        from email.utils import parsedate_to_datetime

        target = parsedate_to_datetime(raw)
        if target is not None:
            from datetime import timezone

            now = clock.now()
            if target.tzinfo is None:
                target = target.replace(tzinfo=timezone.utc)
            delta = (target - now).total_seconds()
            return min(max(delta, 0.0), 60.0) if delta > 0 else fallback
    except (ValueError, TypeError, AttributeError):
        pass
    return fallback


def _resolve_retry_after_from_headers(headers: dict | Any) -> Optional[str]:
    """LOT 8.3 — Lit le header de retry depuis plusieurs noms possibles.

    Anthropic/OpenAI : ``Retry-After``. Groq : ``x-ratelimit-reset-requests``
    et ``x-ratelimit-reset-tokens`` (en secondes flottantes type ``"3.5s"``).
    Retourne le 1er header présent et non-vide.
    """
    for header_name in (
        "retry-after",
        "x-ratelimit-reset-requests",
        "x-ratelimit-reset-tokens",
        "x-ratelimit-reset",
    ):
        try:
            val = headers.get(header_name)
        except (AttributeError, TypeError):
            continue
        if val:
            # Strip suffix "s" éventuel (Groq : "3.5s")
            return str(val).rstrip("sS").strip() or None
    return None


def _format_retry_info(header_value: Optional[str]) -> str:
    """Format Retry-After info pour les logs, sanitized contre log injection."""
    if not header_value:
        return ""
    if _RETRY_AFTER_RE.match(header_value):
        return f" (Retry-After: {header_value}s)"
    return f" (Retry-After: [MALFORMED, {len(header_value)} chars])"


def _should_retry_http(status_code: int) -> bool:
    """True si le code HTTP est transitoire (à retry)."""
    return status_code in _RETRIABLE_HTTP_CODES


def _should_retry_exception(exc: BaseException) -> bool:
    """True si l'exception réseau appartient à la catégorie « transitoire ».

    NB : ce classifieur reste vrai pour un ``ConnectError`` (c'EST une erreur
    réseau). La DÉCISION de ne pas retry un refus de connexion est une politique
    prise dans les boucles de retry via :func:`_is_connection_refused` (fail-fast
    UX), pas une propriété de l'exception — on garde les deux notions séparées.
    """
    return isinstance(exc, _RETRIABLE_NETWORK_EXC)


def _is_connection_refused(exc: BaseException) -> bool:
    """True si l'exception est un REFUS de connexion / endpoint injoignable
    (service down, DNS introuvable, no route) — distinct d'un timeout ou d'un
    reset transitoire.

    On NE retry PAS ces erreurs : « All connection attempts failed » se
    reproduit à l'identique en 1-2-4 s (Ollama arrêté, API injoignable). Retry
    = 7 s gaspillés AVANT que le caller / le fallback runtime ne réagisse.
    Fix prod 2026-06-09 : improve-pseudo restait bloqué 7 s sur un LLM local
    arrêté à cause des 3 retries provider, alors même que le caller avait
    demandé un fail-fast.
    """
    return isinstance(exc, (httpx.ConnectError, ConnectionRefusedError))


def _compute_backoff(
    attempt: int,
    retry_after_header: Optional[str],
    *,
    base: float = 1.0,
    max_delay: float = 60.0,
) -> float:
    """Calcule le délai avant le prochain retry.

    Exponentiel `base * 2^attempt`, borné à `max_delay`. Si le serveur
    fournit un Retry-After valide, il prend le pas (également borné à 60s
    pour éviter un DoS lent).
    """
    backoff = min(base * (2**attempt), max_delay)
    return _parse_retry_after(retry_after_header, backoff)


# Paramètres susceptibles d'être rejetés comme "deprecated" par certains modèles récents
# (ex: Opus 4.7 rejette `temperature`). Ordre : le plus "optionnel" d'abord.
_DEPRECATABLE_PARAMS = ("temperature", "top_p", "top_k")


def _usage_int(value: Any) -> int:
    """Coerce un compteur de tokens provider en ``int`` >= 0.

    Les providers OpenAI-compat exotiques peuvent renvoyer les tokens en
    string (``"1000"``) ou float. L'arithmétique de normalisation cache
    (``prompt - cached``) lèverait alors un ``TypeError`` — au MILIEU du stream
    (après livraison du contenu à l'user) ou dans la conversion non-stream.
    On dégrade ce token vers ``0`` plutôt que de crasher toute la requête
    (règle « conséquences » : input malformé géré gracieusement). ``0`` est
    sûr : il SOUS-compte ce champ précis mais ne fabrique JAMAIS un nombre
    faux plausible. Le ``logger.warning`` rend le dégradé VISIBLE (doctrine
    "jamais 0 silencieux" — un coût sous-estimé doit laisser une trace).
    """
    if value is None:
        return 0
    try:
        n = int(value)
    except (TypeError, ValueError):
        logger.warning("Compteur de tokens provider non numérique (%r) → traité comme 0", value)
        return 0
    return n if n > 0 else 0


def _strip_deprecated_params_from_msg(payload: dict, err_msg: str) -> list[str]:
    """Variante bas-niveau : prend directement le message d'erreur.

    Utile pour le streaming où le body a déjà été lu via ``resp.aread()`` —
    on ne peut pas appeler ``response.json()`` une seconde fois sans rejouer
    le stream. Retourne la liste des params stripés.
    """
    if not err_msg:
        return []
    low = err_msg.lower()
    stripped: list[str] = []
    if "deprecated" in low:
        for param in _DEPRECATABLE_PARAMS:
            if param in err_msg and param in payload:
                payload.pop(param, None)
                stripped.append(param)
    # ``stream_options.include_usage`` (#115) : param standard mais quelques
    # providers OpenAI-compat exotiques le rejettent ("unknown/unsupported
    # parameter"). On le retire pour ne JAMAIS casser tout le streaming à
    # cause d'un param de comptabilité — le coût retombe au dégradé connu $0
    # plutôt que de faire échouer la requête. Générique : déclenché par la
    # mention du param dans l'erreur, jamais par un nom de provider. Gated sur
    # ``"stream_options" in payload`` → no-op pour le path non-stream.
    if "stream_options" in payload and ("stream_options" in low or "include_usage" in low):
        payload.pop("stream_options", None)
        stripped.append("stream_options")
    return stripped


def _strip_deprecated_params(payload: dict, response: "httpx.Response") -> list[str]:
    """Si la réponse 400 mentionne qu'un param du payload est déprécié, le retirer.

    Retourne la liste des params retirés (vide si rien à faire).
    Mutation du payload en place. Sûr : ne retire que les clés présentes dans
    _DEPRECATABLE_PARAMS, jamais une clé obligatoire.
    """
    try:
        body = response.json()
        err_msg = _extract_error_message(body) if isinstance(body, dict) else ""
    except Exception:
        return []
    return _strip_deprecated_params_from_msg(payload, err_msg)


# Sentinel d'event SSE qui transporte le ``pii_mapping`` accumulé pendant
# ``stream_with_tools`` jusqu'au caller. Yieldé une seule fois en fin de
# stream, AVANT le retour de la coroutine. Le caller assemble la réponse
# complète puis applique :func:`_pii_restore_recursive` avec ce mapping
# pour récupérer les valeurs cleartext. Caller qui n'en consomme pas reste
# fonctionnel — UX dégradée : placeholders ``[TYPE_N]`` visibles côté user
# pendant les chunks live, jusqu'à la restauration de fin si elle a lieu.
PII_MAPPING_EVENT_TYPE: Final[str] = "_pii_mapping"

#: Event yieldé par ``stream_with_tools`` à la fin du stream pour exposer
#: au caller le mapping ``{token: cleartext}`` du pseudonymizer user-scoped.
#: Symétrique à :data:`PII_MAPPING_EVENT_TYPE` mais pour la couche §…§.
#: Le caller assemble la réponse depuis les content_block_delta puis
#: applique ce mapping via ``str.replace`` (les tokens sont des chaînes
#: opaques bornées par § et n'overlap pas avec les placeholders [TYPE_N]).
#: ⚠️ **NE JAMAIS forwarder cet event au front** — il contient les valeurs
#: cleartext de l'utilisateur, le restore doit rester serveur-side.
PSEUDO_MAPPING_EVENT_TYPE: Final[str] = "_pseudo_token_mapping"


async def _anonymize_with_tools_payload(
    messages: list[dict],
    system: Optional[str],
    user_id: Optional[int] = None,
) -> tuple[list[dict], str, dict[str, str], Any]:
    """Anonymise un payload tool-use : couche PII regex + couche user-scoped (§…§).

    Walker récursif partagé entre les 4 méthodes ``generate_with_tools`` /
    ``stream_with_tools`` (OpenAI + Anthropic). Mirroring de la couche
    appliquée par :meth:`OpenAIProvider.generate` /
    :meth:`AnthropicProvider.generate` — defense-in-depth pour empêcher
    qu'un caller métier oublié n'envoie du cleartext au LLM cloud.

    **Couches appliquées (dans l'ordre)** :

    1. **PII regex built-in** (EMAIL, SIRET, IBAN, etc.) — placeholders
       ``[TYPE_N]`` indépendants du user.
    2. **Pseudonymizer user-scoped** (si ``user_id`` fourni et l'user a
       des termes ``enabled=True``) — placeholders ``§…§`` pour les
       termes manuels (DUPONT → §CLIENT_A§, codes métier, etc.).

    Sans ``user_id``, seule la couche 1 s'applique — fallback historique
    pour les call-sites sans contexte user (scripts admin, sync). Tout
    call-site servant un utilisateur final DOIT passer ``user_id``.

    **Couverture** :

    - ``messages[].content`` (str ou list de blocks).
    - Blocks ``text`` (champ ``text``), ``tool_use`` (champ ``input``,
      dict potentiellement imbriqué), ``tool_result`` (champ ``content``),
      ``thinking`` (champ ``thinking``) — le walker récursif touche
      tous les strings imbriqués.
    - ``system`` (str).
    - Les **clés** de dict ne sont PAS modifiées (cohérent avec le contrat
      :func:`_pii_anonymize_recursive`).

    **Idempotence** : un payload déjà tokenisé en amont (ex: caller
    ``iris_one_shot`` qui anonymise via ``apply_builtin_pii`` cumulatif)
    n'est PAS re-tokenisé : les placeholders ``[TYPE_N]`` ne matchent
    aucune regex PII built-in (la regex EMAIL exige un ``@``, etc.) et
    les sentinelles ``§…§`` du pseudonymizer ne se chevauchent pas avec
    ``[…]``.

    **Mapping local par-call** : pas cumulatif inter-tours d'agent loop.
    Pour iris_main qui boucle 30+ tours, chaque tour réalloue son mapping —
    un email apparaissant aux tours 1 et 5 obtient des tokens DIFFÉRENTS
    en interne (numérotation indépendante), mais c'est invisible côté
    LLM (chaque tour est un appel HTTP indépendant) et le restore se fait
    au sein du même appel. Le pseudonymizer user-scoped, lui, est stable
    (même DUPONT → même §CLIENT_A§ pour ce user à chaque tour). Si un
    caller veut un mapping PII cumulatif, il doit anonymiser AVANT
    (pattern iris_one_shot) — le provider sera alors no-op par idempotence.

    **Fail-closed** : si :func:`_load_user_pseudonymizer` raise (perte de
    termes en collision), l'exception remonte au caller — pas de
    fall-back qui enverrait du cleartext au LLM.

    Args:
        messages: liste de messages au format Anthropic
            (``[{"role": str, "content": str | list[dict]}]``).
        system: system prompt brut, ou ``None``.
        user_id: identifiant user pour la couche pseudonymizer
            user-scoped. ``None`` = pas de couche 2 (fallback légitime
            uniquement pour scripts admin / sync sans user).

    Returns:
        Tuple ``(anon_messages, anon_system, pii_mapping, pseudo)``.
        ``anon_system`` est ``""`` si ``system`` était ``None``/vide.
        ``pii_mapping`` est un dict ``{token: original}`` à utiliser pour
        le restore PII (vide si rien n'a été anonymisé). ``pseudo`` est
        soit un :class:`Pseudonymizer` à utiliser pour le restore §…§,
        soit ``None`` (couche 2 skipped).
    """
    from app.services.anonymization.proxy import (
        _load_user_pseudonymizer,
        _pii_anonymize_recursive,
    )

    pii_mapping: dict[str, str] = {}
    pii_counters: dict[str, int] = {}
    anon_messages = _pii_anonymize_recursive(messages, pii_mapping, pii_counters)
    if system:
        anon_system = _pii_anonymize_recursive(system, pii_mapping, pii_counters)
    else:
        anon_system = ""

    pseudo = None
    if user_id is not None:
        pseudo = await _load_user_pseudonymizer(user_id)
        if pseudo is not None and len(pseudo) > 0:
            anon_messages = pseudo.anonymize(anon_messages)
            if anon_system:
                anon_system = pseudo.anonymize(anon_system)

    return anon_messages, anon_system, pii_mapping, pseudo


class OpenAIProvider(LLMProvider):
    """
    Provider OpenAI-compatible (GPT, Mistral, Groq, DeepSeek, Together, etc.).

    Fonctionne avec TOUTE API compatible OpenAI chat/completions.
    Le provider_name et base_url sont configurables.
    """

    provider_name = "openai"

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = OPENAI_API_URL,
        timeout: float = OPENAI_TIMEOUT,
        name: Optional[str] = None,
    ):
        """Initialise le provider OpenAI-compatible.

        Args:
            name: Nom explicite du provider (ex: "mistral", "groq"). Prime
                sur la détection auto-base_url. Si None ET base_url pointe
                vers un provider OpenAI-compat connu, le provider_name est
                inféré (Mistral, Groq, DeepSeek, Gemini, Together,
                Perplexity). Sinon défaut "openai".
        """
        self.api_key = _sanitize_api_key(api_key or "")
        self.base_url = _normalize_provider_base_url(base_url, OPENAI_API_URL)
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        # Resolution du provider_name : explicit > détection base_url > "openai"
        if name:
            self.provider_name = name
        else:
            detected = _detect_openai_compat_provider_from_url(self.base_url)
            if detected:
                self.provider_name = detected
            # Sinon le défaut "openai" du class attribute reste actif

    async def _get_client(self) -> httpx.AsyncClient:
        """Obtient ou crée le client HTTP avec headers d'auth."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def close(self):
        """Ferme le client HTTP."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    # OpenAI a activé le prompt caching automatique en nov. 2024. Aucun flag
    # applicatif à poser — l'API cache les préfixes stables toute seule. Les
    # autres APIs "OpenAI-compatibles" (Mistral, Groq, DeepSeek) n'ont pas
    # cette capacité de façon uniforme ; on reste conservatif en ne l'annonçant
    # que pour le provider_name == "openai" strict.
    _AUTO_CACHING_PROVIDERS = frozenset({"openai"})

    def _capability_map(self) -> dict[str, CapabilityHandler]:
        """Features supportées par OpenAI strict / compat layer.

        Ajouter une feature ici quand l'écosystème OpenAI la supporte —
        les autres restent False par défaut (fallback côté base class).
        """
        return {
            LLMFeature.PROMPT_CACHING.value: self._supports_auto_caching,
        }

    def _supports_auto_caching(self, model: Optional[str]) -> bool:
        """Auto-caching côté OpenAI strict uniquement.

        Mistral/Groq/DeepSeek partagent l'interface HTTP mais pas le cache
        automatique ; on reste conservatif — le caller basculera sur un
        fallback maison s'il en veut un.
        """
        return self.provider_name in self._AUTO_CACHING_PROVIDERS

    async def health_check(self) -> bool:
        """Vérifie la disponibilité de l'API OpenAI."""
        if not self.api_key:
            return False
        try:
            client = await self._get_client()
            response = await client.get(f"{self.base_url}/models")
            return response.status_code == 200
        except (ConnectionError, asyncio.TimeoutError, OSError, httpx.ConnectError):
            return False

    async def list_models(self) -> List[Dict[str, Any]]:
        """Liste les modèles GPT disponibles."""
        if not self.api_key:
            return []
        try:
            client = await self._get_client()
            response = await client.get(f"{self.base_url}/models")
            response.raise_for_status()
            result = response.json()
            models = []
            for m in result.get("data", []):
                name = m.get("id", "")
                if "gpt" in name:
                    models.append(
                        {
                            "name": name,
                            "provider": "openai",
                        }
                    )
            return models
        except (ConnectionError, asyncio.TimeoutError, OSError, httpx.ConnectError) as e:
            # Provider injoignable (réseau, service local down, base_url
            # erronée) = condition transitoire ATTENDUE, pas une erreur interne.
            # WARNING (pas ERROR) pour ne pas polluer les logs / déclencher des
            # alertes : on dégrade proprement en liste vide. Cohérent avec le
            # fallback Anthropic list_models et le path local Ollama down.
            logger.warning(
                "Provider OpenAI injoignable au listing des modèles (%s) — " "fallback liste vide",
                type(e).__name__,
            )
            return []

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Génère une réponse via l'API OpenAI (avec anonymisation PII).

        **Skip anonymization for local LLMs** (fix 2026-05-19) : quand
        ``provider_name == 'local'`` (= LLM local Ollama/LM Studio/TGI
        configuré via :meth:`LLMManager.register_local_fallback`), on
        BYPASS l'anonymisation PII cloud. Raisons :

        1. **Privacy** : un LLM local tourne sur la machine de l'utilisateur,
           pas dans le cloud — pas de raison de masquer les PII.
        2. **Correctness** : pour les usages d'enrichissement sémantique
           (``improve_pseudos_chunk`` qui demande au LLM local de proposer
           un LABEL pour CHAQUE terme), anonymiser les termes côté provider
           CASSE la sémantique. Le LLM reçoit ``[EMAIL_1]`` au lieu de
           ``jean@example.org`` → propose un label pour ``[EMAIL_1]`` → le
           parser cherche ce token dans la liste de candidats (qui contient
           ``jean@example.org``, pas ``[EMAIL_1]``) → 0 termes améliorés.
           Avant ce fix : ``improve_pseudos_chunk`` retournait
           silencieusement 0 résultats avec ``JSON invalide`` dans les logs.
        """
        if not self.api_key:
            raise ValueError("Clé API non configurée")

        # OpenAI n'a pas de cache_control — concaténer le prefix dans le prompt
        anonymizer = get_anonymizer()
        full_prompt = request.prompt
        if request.prompt_cache_prefix:
            full_prompt = request.prompt_cache_prefix + "\n\n" + request.prompt

        is_local = self.provider_name == "local"
        pseudo = None  # couche 2 (pseudonymizer user-scoped) — restore en fin
        if is_local:
            # Bypass total : on envoie le prompt brut au LLM local. Pas de
            # mapping à conserver pour le dé-anonymise → l'output sera
            # utilisé tel quel par le caller.
            anon_prompt = full_prompt
            anon_system = request.system or ""
            pii_mapping: dict = {}
        else:
            anon_prompt, prompt_mapping = anonymizer.anonymize(full_prompt)
            anon_system, system_mapping = (
                anonymizer.anonymize(request.system) if request.system else ("", {})
            )
            pii_mapping = {**prompt_mapping, **system_mapping}
            if pii_mapping:
                logger.warning("OpenAI: %s PII anonymisées avant envoi", len(pii_mapping))
            # Couche 2 — pseudonymizer user-scoped (§…§) : termes manuels
            # (/data-privacy). Symétrique de _anonymize_with_tools_payload.
            # Fail-closed : si un terme configuré manque, _load_user_pseudonymizer
            # raise → l'appel échoue plutôt que de fuiter la valeur en clair.
            if request.user_id is not None:
                from app.services.anonymization.proxy import _load_user_pseudonymizer

                pseudo = await _load_user_pseudonymizer(request.user_id)
                if pseudo is not None and len(pseudo) > 0:
                    anon_prompt = pseudo.anonymize(anon_prompt)
                    if anon_system:
                        anon_system = pseudo.anonymize(anon_system)
                else:
                    pseudo = None

        client = await self._get_client()
        messages = []
        if request.system:
            messages.append({"role": "system", "content": anon_system})
        messages.append({"role": "user", "content": anon_prompt})

        resolved_model = self._resolve_request_model(request.model, OPENAI_DEFAULT_MODEL)
        payload = {
            "model": resolved_model,
            "messages": messages,
            "temperature": _temperature_for_request(request),
        }
        # Clamper max_tokens au max connu pour ce modèle (évite 400 sur modèles
        # avec une limite inférieure à ce qu'on demande).
        if request.max_tokens:
            model_cap = get_max_tokens_for_model(resolved_model)
            payload["max_tokens"] = min(request.max_tokens, model_cap)

        # Plan dynamicité 2026-05-14 (review L3 CRIT 1) : reasoning_effort
        # branché aussi sur le path generate() simple, pas seulement
        # generate_with_tools/stream_with_tools. Un caller utility qui veut
        # activer le reasoning passe ``options={"thinking_budget": N}`` dans
        # son ``LLMRequest`` ; sinon le mapping retourne None et le payload
        # reste inchangé (no-op safe).
        _thinking_budget = int(request.options.get("thinking_budget", 0) or 0)
        self._maybe_inject_reasoning_effort(payload, resolved_model, _thinking_budget)

        # ``response_format`` (2026-05-20) — OpenAI compat « JSON mode » :
        # un caller qui passe ``options={"response_format": {"type": "json_object"}}``
        # force le LLM à produire du JSON strict (vs texte libre).
        # Ollama et LM Studio supportent cette directive via leur endpoint
        # OpenAI-compat. Crucial pour les classifieurs structurés
        # (``improve_pseudos_chunk``) où parser un format libre est fragile.
        _resp_fmt = request.options.get("response_format")
        if isinstance(_resp_fmt, dict) and _resp_fmt.get("type"):
            payload["response_format"] = _resp_fmt

        # Retry centralisé (429/529/5xx + erreurs réseau transitoires).
        # Auparavant : aucun retry — un 429 faisait crash immédiat.
        max_retries = _resolve_max_retries()
        response: Optional[httpx.Response] = None
        duration = 0.0

        for attempt in range(max_retries + 1):
            try:
                start = time.time()
                response = await client.post(f"{self.base_url}/chat/completions", json=payload)
                duration = time.time() - start
            except _RETRIABLE_NETWORK_EXC as exc:
                # Refus de connexion (endpoint injoignable) → PAS de retry :
                # « All connection attempts failed » se reproduit à l'identique
                # en 1+2+4 s. Échec immédiat (fix prod 2026-06-09 : improve-pseudo
                # restait bloqué 7 s sur un Ollama arrêté).
                if not _is_connection_refused(exc) and attempt < max_retries:
                    delay = _compute_backoff(attempt, None)
                    logger.warning(
                        "OpenAI generate %s, retry %d/%d in %.0fs",
                        type(exc).__name__,
                        attempt + 1,
                        max_retries,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                if _is_connection_refused(exc):
                    logger.warning(
                        "OpenAI generate: endpoint injoignable (%s) — pas de retry.",
                        type(exc).__name__,
                    )
                else:
                    logger.error("OpenAI generate network error après retries: %s", exc)
                raise

            if _should_retry_http(response.status_code) and attempt < max_retries:
                retry_after_raw = _resolve_retry_after_from_headers(response.headers)
                delay = _compute_backoff(attempt, retry_after_raw)
                logger.warning(
                    "OpenAI generate HTTP %s, retry %d/%d in %.0fs%s",
                    response.status_code,
                    attempt + 1,
                    max_retries,
                    delay,
                    _format_retry_info(retry_after_raw),
                )
                await asyncio.sleep(delay)
                continue

            # 400 "X is deprecated for this model" → retirer le param et 1 retry.
            # Certains modèles récents (ex: Claude Opus 4.7 via proxy OpenAI-compat,
            # reasoning models GPT) refusent temperature/top_p/top_k.
            if response.status_code == 400:
                stripped = _strip_deprecated_params(payload, response)
                if stripped:
                    logger.warning(
                        "OpenAI: param(s) déprécié(s) pour %s : %s. Retry sans.",
                        payload.get("model"),
                        ", ".join(stripped),
                    )
                    try:
                        response = await client.post(
                            f"{self.base_url}/chat/completions", json=payload
                        )
                    except _RETRIABLE_NETWORK_EXC as exc:
                        logger.error("OpenAI retry après strip: %s", exc)
                        raise
            break

        if response is None:
            raise RuntimeError("OpenAI generate: aucune réponse après retries")

        if response.status_code != 200:
            try:
                err_msg = _extract_error_message(response.json())
            except Exception:
                err_msg = "HTTP %s" % response.status_code
            logger.error("OpenAI API error %s: %s", response.status_code, err_msg)
            if response.status_code in _RETRIABLE_HTTP_CODES:
                retry_after_raw = _resolve_retry_after_from_headers(response.headers)
                retry_after = _parse_retry_after(retry_after_raw, 60.0)
                raise RateLimitError(retry_after, err_msg)
            response.raise_for_status()

        result = response.json()

        usage = result.get("usage", {})

        choices = result.get("choices")
        if not choices or not isinstance(choices, list):
            raise ValueError("Réponse LLM invalide: champ 'choices' manquant ou vide")
        content = choices[0].get("message", {}).get("content", "")

        # Dé-anonymiser en ordre LIFO inverse de l'anonymisation : couche 2
        # pseudonymizer (§…§) PUIS couche 1 PII ([TYPE_N]) — aligné sur le SSoT
        # restore_fn du proxy. Sentinelles disjointes (§…§ vs [TYPE_N]).
        if pseudo is not None:
            content = pseudo.deanonymize(content)
        if pii_mapping:
            content = anonymizer.deanonymize(content, pii_mapping)

        # LOT 5.2 — OpenAI auto-cache (depuis nov 2024) expose
        # ``prompt_tokens_details.cached_tokens``. o1/o3 exposent
        # ``completion_tokens_details.reasoning_tokens`` (5×–50× output
        # tokens facturés). Sans ces champs, le dashboard de coût et le
        # monitoring denial-of-wallet sont aveugles côté OpenAI.
        prompt_details = usage.get("prompt_tokens_details") or {}
        completion_details = usage.get("completion_tokens_details") or {}
        cached_tokens = (
            prompt_details.get("cached_tokens") if isinstance(prompt_details, dict) else None
        )
        reasoning_tokens = (
            completion_details.get("reasoning_tokens")
            if isinstance(completion_details, dict)
            else None
        )

        # D1-F5 (#74) — Normalisation sémantique tokens vers la convention
        # Anthropic (single source of truth du calcul de coût) :
        #   * OpenAI : ``prompt_tokens`` = input TOTAL, ``cached_tokens`` en est
        #     un SOUS-ENSEMBLE (``prompt_tokens_details.cached_tokens``).
        #   * Anthropic : ``input_tokens`` = NON-caché, ``cache_read_input_tokens``
        #     compté À PART (additif).
        # Le calcul de coût (``llm_call_tracker._compute_cost`` :
        # ``prompt_tokens*input + cache_read*cache_read_price``) suppose la
        # convention Anthropic. Sans cette normalisation, le cached OpenAI est
        # facturé DEUX FOIS (à input_price DANS prompt_tokens + à cache_read_price).
        # On retranche donc le cached de ``prompt_tokens`` ET de ``total_tokens``
        # (parité : total = input_non_caché + output, cache tracké à part).
        # ``max(0, …)`` : garde anti-incohérence API (cached ⊆ prompt garanti par
        # OpenAI, mais on ne fait jamais confiance à l'aveugle — cf. règle conséquences).
        _raw_prompt = usage.get("prompt_tokens")
        _raw_total = usage.get("total_tokens")
        _cached = cached_tokens or 0
        _prompt_uncached = max(0, _raw_prompt - _cached) if _raw_prompt is not None else None
        _total_uncached = max(0, _raw_total - _cached) if _raw_total is not None else None

        return LLMResponse(
            content=content,
            model=resolved_model,
            provider=self.provider_name,
            prompt_tokens=_prompt_uncached,
            completion_tokens=usage.get("completion_tokens"),
            total_tokens=_total_uncached,
            cache_read_tokens=cached_tokens,
            thinking_tokens=reasoning_tokens,
            duration_seconds=duration,
            raw_response=result,
        )

    @staticmethod
    def _reasoning_effort_from_thinking_budget(thinking_budget: int) -> Optional[str]:
        """Mappe un ``thinking_budget`` (format Anthropic, en tokens) à un
        ``reasoning_effort`` (format OpenAI o-series, niveau discret).

        **Sémantique** : les deux features visent à donner plus de tokens
        à la réflexion interne du modèle. Anthropic exprime en tokens
        explicites (1024 plancher, jusqu'à ~50k), OpenAI en niveaux
        discrets ``"low"``/``"medium"``/``"high"``. Cette traduction permet
        à ``compute_effort_params`` (qui produit un format Anthropic-pivot)
        de driver les deux familles de modèles via le même paramètre
        downstream. Cf. plan dynamicité 2026-05-14.

        Seuils choisis pragmatiquement :
        - ``< 4096`` → ``"low"`` (tâche simple, modèle pense brièvement)
        - ``< 16384`` → ``"medium"`` (tâche complexe usuelle)
        - ``>= 16384`` → ``"high"`` (raisonnement long, multi-étapes)

        Retourne ``None`` si ``thinking_budget=0`` (pas de reasoning demandé).
        """
        if thinking_budget <= 0:
            return None
        if thinking_budget < 4096:
            return "low"
        if thinking_budget < 16384:
            return "medium"
        return "high"

    def _maybe_inject_reasoning_effort(
        self, payload: dict, model: str, thinking_budget: int
    ) -> None:
        """Si le registre ``LlmModel.supports_reasoning_effort`` retourne
        ``True`` pour ``model``, traduit ``thinking_budget`` en
        ``reasoning_effort`` et l'ajoute au payload OpenAI.

        Pas-op si le modèle ne supporte pas (``None`` ou ``False`` du
        registre) — OpenAI standard ignorerait ce param de toute façon,
        mais on évite la pollution du payload et des logs. Cohérent avec
        la doctrine "adaptation, pas force" du plan dynamicité 2026-05-14.

        Idempotent : si ``thinking_budget=0``, n'ajoute rien (pas de
        reasoning demandé). Si ``reasoning_effort`` est déjà dans
        ``payload`` (caller explicite), on ne l'écrase pas.
        """
        from app.constants_ai import supports_capability_for_model

        if supports_capability_for_model(model, "reasoning_effort") is not True:
            return
        if "reasoning_effort" in payload:
            return  # caller a forcé explicitement
        effort = self._reasoning_effort_from_thinking_budget(thinking_budget)
        if effort is not None:
            payload["reasoning_effort"] = effort

    @staticmethod
    def _convert_anthropic_tools_to_openai(tools: list[dict]) -> list[dict]:
        """Convertit les outils du format Anthropic au format OpenAI.

        **LOT 3.1 (strict mode compat)** : injecte ``additionalProperties:
        false`` récursivement sur tous les ``type:"object"`` qui n'en ont pas.
        Anthropic accepte les schémas lâches ; OpenAI strict mode, Mistral
        récent, Groq les rejettent (400 ``parameters do not match schema``).
        Le code applicatif (70 outils dans agent_tools/copilot_tools/
        orchestrator_tools) reste inchangé — la couche provider durcit
        automatiquement.
        """
        openai_tools = []
        for tool in tools:
            params = tool.get("input_schema", {}) or {}
            params_strict = _harden_schema_strict_mode(dict(params))
            openai_tool = {
                "type": "function",
                "function": {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "parameters": params_strict,
                },
            }
            openai_tools.append(openai_tool)
        return openai_tools

    @staticmethod
    def _convert_anthropic_messages_to_openai(messages: list[dict]) -> list[dict]:
        """Convertit les messages du format Anthropic au format OpenAI."""
        openai_messages = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content")

            if role == "user":
                # Vérifier les tool_result AVANT le texte (Anthropic met
                # les tool_result dans des messages role="user")
                if isinstance(content, list) and any(
                    isinstance(b, dict) and b.get("type") == "tool_result" for b in content
                ):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "tool_result":
                            # Extraire le contenu texte du tool_result
                            tr_content = block.get("content", "")
                            if isinstance(tr_content, list):
                                tr_content = "\n".join(
                                    b.get("text", "")
                                    for b in tr_content
                                    if isinstance(b, dict) and b.get("type") == "text"
                                ) or json.dumps(tr_content)
                            elif not isinstance(tr_content, str):
                                tr_content = json.dumps(tr_content)
                            openai_messages.append(
                                {
                                    "role": "tool",
                                    "tool_call_id": block.get("tool_use_id", ""),
                                    "content": tr_content,
                                }
                            )
                elif isinstance(content, str):
                    openai_messages.append({"role": "user", "content": content})
                elif isinstance(content, list):
                    text_parts = []
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            text_parts.append(block.get("text", ""))
                    if text_parts:
                        openai_messages.append({"role": "user", "content": "\n".join(text_parts)})
            elif role == "assistant":
                if isinstance(content, str):
                    openai_messages.append({"role": "assistant", "content": content})
                elif isinstance(content, list):
                    text_parts = []
                    tool_calls = []
                    for block in content:
                        if isinstance(block, dict):
                            if block.get("type") == "text":
                                text_parts.append(block.get("text", ""))
                            elif block.get("type") == "tool_use":
                                tool_calls.append(
                                    {
                                        "id": block.get("id", f"call_{uuid4().hex[:24]}"),
                                        "type": "function",
                                        "function": {
                                            "name": block.get("name", ""),
                                            "arguments": json.dumps(block.get("input", {})),
                                        },
                                    }
                                )
                    msg_dict: dict = {"role": "assistant"}
                    # ``content=""`` (et non ``None``) si tool_use seul.
                    # Mistral, Groq, Gemini OpenAI-compat rejettent
                    # ``content: null`` quand ``tool_calls`` est présent
                    # avec un 400 « content must be string ». OpenAI officiel
                    # tolère, donc on uniformise sur la valeur compatible.
                    msg_dict["content"] = "\n".join(text_parts) if text_parts else ""
                    if tool_calls:
                        msg_dict["tool_calls"] = tool_calls
                    if msg_dict.get("content") or tool_calls:
                        openai_messages.append(msg_dict)

        # LOT 2.4 — Merge des messages consécutifs de même rôle. Anthropic
        # accepte 2 user/assistant successifs ; Mistral/Groq exigent l'
        # alternance stricte. Un agent loop qui replay l'historique peut
        # produire 2 assistants successifs (text-only + tool_use ajouté
        # plus tard). On les merge plutôt que de laisser le provider
        # rejeter avec « roles must alternate ».
        return _merge_consecutive_same_role(openai_messages)

    @staticmethod
    def _convert_openai_response_to_anthropic(openai_response: dict) -> dict:
        """Convertit la réponse OpenAI au format Anthropic."""
        choices = openai_response.get("choices", [])
        if not choices:
            return {
                "content": [],
                "stop_reason": "end_turn",
                "usage": openai_response.get("usage", {}),
            }

        choice = choices[0]
        message = choice.get("message", {})
        choice.get("finish_reason", "stop")

        anthropic_content = []
        content = message.get("content")
        if content:
            if isinstance(content, str):
                anthropic_content.append({"type": "text", "text": content})
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        anthropic_content.append({"type": "text", "text": block.get("text", "")})

        tool_calls = message.get("tool_calls", [])
        for tool_call in tool_calls:
            tool_id = tool_call.get("id", f"call_{uuid4().hex[:24]}")
            func = tool_call.get("function", {})
            try:
                input_data = json.loads(func.get("arguments", "{}"))
            except (json.JSONDecodeError, TypeError):
                input_data = {}

            anthropic_content.append(
                {
                    "type": "tool_use",
                    "id": tool_id,
                    "name": func.get("name", ""),
                    "input": input_data,
                }
            )

        # Si des tool_calls sont présents, c'est un tool_use — peu importe le finish_reason
        # (certains modèles OpenAI retournent "stop" même avec des tool_calls)
        stop_reason = "tool_use" if tool_calls else "end_turn"

        # D1-F5b (#114) — Normalisation tokens cachés OpenAI vers la convention
        # Anthropic (parité avec le chemin ``generate`` non-tools). OpenAI :
        # ``prompt_tokens`` = input TOTAL, cached = sous-ensemble
        # (``prompt_tokens_details.cached_tokens``). On émet donc
        # ``input_tokens`` NON-caché + ``cache_read_input_tokens`` à part, pour
        # que le calcul de coût (qui suppose la convention Anthropic) applique
        # le PRIX CACHE_READ au cached au lieu du prix INPUT plein (sinon
        # sur-facturation silencieuse). INVARIANT pour le gate de contexte de
        # l'agent (``input_tokens + cache_read`` = full, cf. agent_service.py).
        _usage = openai_response.get("usage", {}) or {}
        _prompt = _usage_int(_usage.get("prompt_tokens"))
        _details = _usage.get("prompt_tokens_details") or {}
        _cached = _usage_int(_details.get("cached_tokens")) if isinstance(_details, dict) else 0

        return {
            "content": anthropic_content,
            "stop_reason": stop_reason,
            "usage": {
                "input_tokens": max(0, _prompt - _cached),
                "output_tokens": _usage_int(_usage.get("completion_tokens")),
                "cache_read_input_tokens": _cached,
            },
        }

    async def generate_with_tools(
        self,
        request: LLMRequest,
        tools: list[dict],
        messages: list[dict],
        thinking_budget: int = 0,
        user_id: Optional[int] = None,
    ) -> dict:
        """
        Appelle POST /v1/chat/completions avec tool_use (format OpenAI).

        Accepte thinking_budget mais l'ignore (OpenAI ne supporte pas extended thinking).

        **Anonymisation 2 couches inline** (defense-in-depth) — les ``messages``
        et le ``system`` sont passés par :func:`_anonymize_with_tools_payload`
        AVANT d'être envoyés au LLM cloud :
        couche 1 = PII regex (EMAIL, SIRET, IBAN, etc.),
        couche 2 = pseudonymizer user-scoped (§…§) si ``user_id`` fourni.
        La réponse est restaurée AVANT d'être retournée. Idempotent vs un
        caller qui aurait déjà tokenisé.

        ``user_id`` doit être passé par tout caller servant un utilisateur
        final — sans ça, la couche 2 (termes manuels DUPONT, codes métier)
        est skippée et seule la couche 1 protège.

        Retourne un dict au format Anthropic (content, stop_reason, usage) pour
        compatibilité avec agent_service.py.
        """
        if not self.api_key:
            raise ValueError("Clé API non configurée")

        if thinking_budget > 0:
            logger.info(
                "OpenAI: extended thinking (budget=%d) non supporté — "
                "le modèle répondra sans raisonnement interne",
                thinking_budget,
            )

        client = await self._get_client()
        model = self._resolve_request_model(request.model, OPENAI_DEFAULT_MODEL)
        _model_cap_for_clamp = get_max_tokens_for_model(model)
        resolved_max_tokens = min(request.max_tokens or _model_cap_for_clamp, _model_cap_for_clamp)

        # Defense-in-depth : anonymisation 2 couches AVANT compact + troncature
        # + envoi HTTP. Le compact (Haiku via ``provider.generate``) verra ainsi
        # une version déjà tokenisée — pas de double-anonymisation au compact
        # car ``apply_builtin_pii`` est idempotent par dédup. Le ``pii_mapping``
        # et ``pseudo`` sont locaux à cet appel ; le restore est appliqué à la
        # réponse avant le ``return``.
        messages, anon_system_raw, pii_mapping, pseudo = await _anonymize_with_tools_payload(
            messages, request.system, user_id=user_id
        )

        # LOT 8.5 — Compact LLM-assisté EN PREMIER (idem Anthropic). Sur
        # Mistral 32K / Groq Llama-3-8B 8K, sans compact on tronquerait
        # brutalement les conversations longues → perte de contexte
        # critique. Avec compact, le LLM résume les anciens tours et
        # préserve l'information.
        compacted_messages, compacted_count = await _maybe_compact_messages(
            provider=self,
            messages=messages,
            system=anon_system_raw,
            tools=tools,
            max_tokens=resolved_max_tokens,
            model=model,
        )

        # Puis vérification context window + troncature classique
        # (partagé avec Anthropic)
        checked_messages, removed_count = _check_context_window(
            model=model,
            messages=compacted_messages,
            system=anon_system_raw,
            tools=tools,
            max_tokens=resolved_max_tokens,
        )

        effective_system = anon_system_raw
        if removed_count > 0:
            effective_system += _TRUNCATION_WARNING_TEMPLATE.format(count=removed_count)
        # Le marker de cache_control est Anthropic-only. Côté OpenAI on le
        # strippe pour ne pas polluer le prompt réel envoyé au modèle.
        effective_system = effective_system.replace(AnthropicProvider.CACHE_BREAKPOINT, "")

        openai_tools = self._convert_anthropic_tools_to_openai(tools)
        openai_messages = self._convert_anthropic_messages_to_openai(checked_messages)

        messages_to_send = []
        if effective_system:
            messages_to_send.append({"role": "system", "content": effective_system})
        messages_to_send.extend(openai_messages)

        payload = {
            "model": model,
            "messages": messages_to_send,
            "temperature": _temperature_for_request(request),
            "max_tokens": resolved_max_tokens,
        }
        if openai_tools:
            payload["tools"] = openai_tools

        # Plan dynamicité 2026-05-14 : si le modèle supporte
        # ``reasoning_effort`` (OpenAI o-series, GPT-5), traduire le
        # ``thinking_budget`` reçu (format Anthropic-pivot) en niveau
        # discret OpenAI. Pas-op si le modèle ne supporte pas.
        self._maybe_inject_reasoning_effort(payload, model, thinking_budget)

        log_llm_exchange("request", payload)

        max_retries = _resolve_max_retries()
        for attempt in range(max_retries + 1):
            try:
                start = time.time()
                response = await client.post(f"{self.base_url}/chat/completions", json=payload)
                duration = time.time() - start
            except _RETRIABLE_NETWORK_EXC as exc:
                if attempt < max_retries:
                    delay = _compute_backoff(attempt, None)
                    logger.warning(
                        "OpenAI generate_with_tools %s, retry %d/%d in %.0fs",
                        type(exc).__name__,
                        attempt + 1,
                        max_retries,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                logger.error("OpenAI generate_with_tools network error après retries: %s", exc)
                raise

            if _should_retry_http(response.status_code) and attempt < max_retries:
                retry_after_raw = _resolve_retry_after_from_headers(response.headers)
                delay = _compute_backoff(attempt, retry_after_raw)
                logger.warning(
                    "OpenAI generate_with_tools HTTP %s, retry %d/%d in %.0fs%s",
                    response.status_code,
                    attempt + 1,
                    max_retries,
                    delay,
                    _format_retry_info(retry_after_raw),
                )
                await asyncio.sleep(delay)
                continue

            if response.status_code != 200:
                try:
                    err_msg = _extract_error_message(response.json())
                except Exception:
                    err_msg = "HTTP %s" % response.status_code
                logger.error(
                    "OpenAI generate_with_tools error %s: %s",
                    response.status_code,
                    err_msg,
                )
                if response.status_code == 400:
                    stripped = _strip_deprecated_params(payload, response)
                    if stripped:
                        logger.warning(
                            "OpenAI generate_with_tools: param(s) déprécié(s) pour %s : %s. Retry sans.",
                            payload.get("model"),
                            ", ".join(stripped),
                        )
                        try:
                            response = await client.post(
                                f"{self.base_url}/chat/completions",
                                json=payload,
                            )
                        except _RETRIABLE_NETWORK_EXC as exc:
                            logger.error("OpenAI generate_with_tools retry après strip: %s", exc)
                            raise
                        if response.status_code != 200:
                            response.raise_for_status()
                    else:
                        response.raise_for_status()
                elif response.status_code in _RETRIABLE_HTTP_CODES:
                    retry_after_raw = _resolve_retry_after_from_headers(response.headers)
                    retry_after = _parse_retry_after(retry_after_raw, 60.0)
                    raise RateLimitError(retry_after, err_msg)
                else:
                    response.raise_for_status()

            result = response.json()
            log_llm_exchange("response", result)
            anthropic_result = self._convert_openai_response_to_anthropic(result)
            # Restore 2 couches : pseudo d'abord (sentinelles ``§…§``), puis
            # PII (placeholders ``[TYPE_N]``). Pas de chevauchement entre les
            # deux formats. Best-effort : un échec restore n'est pas critique
            # (le LLM cloud n'a JAMAIS vu de cleartext, defense-in-depth core
            # préservé) ; on log + retourne le payload partiellement restauré.
            if pseudo is not None and len(pseudo) > 0:
                try:
                    anthropic_result = pseudo.deanonymize(anthropic_result)
                except Exception as restore_exc:  # noqa: BLE001
                    logger.warning(
                        "OpenAI generate_with_tools: restore pseudonymizer échoué : %s",
                        restore_exc,
                    )
            if pii_mapping:
                try:
                    from app.services.anonymization.proxy import _pii_restore_recursive

                    anthropic_result = _pii_restore_recursive(anthropic_result, pii_mapping)
                except Exception as restore_exc:  # noqa: BLE001
                    logger.warning(
                        "OpenAI generate_with_tools: restore PII échoué : %s",
                        restore_exc,
                    )
            logger.debug(
                "OpenAI generate_with_tools: stop_reason=%s, duration=%.2fs",
                anthropic_result.get("stop_reason"),
                duration,
            )
            return anthropic_result

        raise RuntimeError("OpenAI generate_with_tools: max retries exceeded")

    async def stream_with_tools(
        self,
        request: LLMRequest,
        tools: list[dict],
        messages: list[dict],
        thinking_budget: int = 0,
        user_id: Optional[int] = None,
    ) -> AsyncGenerator[dict, None]:
        """
        Appelle POST /v1/chat/completions avec stream=True et tool_use.

        **Anonymisation 2 couches** des ``messages`` + ``system`` AVANT envoi
        (defense-in-depth) : couche 1 PII regex + couche 2 pseudonymizer
        user-scoped si ``user_id`` fourni. Les events SSE sont yieldés bruts
        (pas de restauration live — un placeholder coupé entre 2 chunks
        casserait le restore). À la fin du stream, un event spécial
        ``{"type": "_pii_mapping", "mapping": {...}}`` est yieldé si au
        moins une PII a été tokenisée. Le caller assemble la réponse
        complète puis applique :func:`_pii_restore_recursive` avec ce
        mapping pour récupérer le cleartext. Caller qui ignore l'event
        reste fonctionnel — UX dégradée : placeholders ``[TYPE_N]``
        visibles côté user.

        Yield des événements au format Anthropic SSE pour compatibilité.
        """
        if not self.api_key:
            raise ValueError("Clé API non configurée")

        if thinking_budget > 0:
            logger.info(
                "OpenAI stream: extended thinking (budget=%d) non supporté — "
                "le modèle répondra sans raisonnement interne",
                thinking_budget,
            )

        client = await self._get_client()
        model = self._resolve_request_model(request.model, OPENAI_DEFAULT_MODEL)
        _model_cap_for_clamp = get_max_tokens_for_model(model)
        resolved_max_tokens = min(request.max_tokens or _model_cap_for_clamp, _model_cap_for_clamp)

        # Defense-in-depth : anonymisation 2 couches avant compact + troncature
        # + envoi SSE. Idempotent vs caller pré-tokenisé. Cf. docstring
        # :func:`_anonymize_with_tools_payload` pour les invariants détaillés.
        messages, anon_system_raw, pii_mapping, pseudo = await _anonymize_with_tools_payload(
            messages, request.system, user_id=user_id
        )

        # LOT 8.5 — Compact LLM-assisté pour streaming aussi (parité Anthropic)
        compacted_messages, compacted_count = await _maybe_compact_messages(
            provider=self,
            messages=messages,
            system=anon_system_raw,
            tools=tools,
            max_tokens=resolved_max_tokens,
            model=model,
        )

        # Puis troncature de sécurité
        checked_messages, removed_count = _check_context_window(
            model=model,
            messages=compacted_messages,
            system=anon_system_raw,
            tools=tools,
            max_tokens=resolved_max_tokens,
        )

        effective_system = anon_system_raw
        if removed_count > 0:
            effective_system += _TRUNCATION_WARNING_TEMPLATE.format(count=removed_count)
        # Cache marker Anthropic-only → on le strippe côté OpenAI streaming.
        effective_system = effective_system.replace(AnthropicProvider.CACHE_BREAKPOINT, "")

        openai_tools = self._convert_anthropic_tools_to_openai(tools)
        openai_messages = self._convert_anthropic_messages_to_openai(checked_messages)

        messages_to_send = []
        if effective_system:
            messages_to_send.append({"role": "system", "content": effective_system})
        messages_to_send.extend(openai_messages)

        payload = {
            "model": model,
            "messages": messages_to_send,
            "temperature": _temperature_for_request(request),
            "stream": True,
            # ``include_usage`` → OpenAI/Mistral/Groq/DeepSeek/Together émettent
            # un chunk FINAL portant ``usage`` (input/cached/output). SANS lui,
            # le stream ne reporte AUCUN token → coût $0 silencieux = denial-of-
            # wallet aveugle (cf. #115 / D1-F5c, interdit par la doctrine
            # "jamais 0 silencieux"). Le contrat consommateur
            # (``StreamAccountingWrapper.observe``) l'attend déjà. Si un
            # provider exotique le rejette en 400, il est strippé + retenté
            # (``_strip_deprecated_params_from_msg``) → dégradé connu, pas crash.
            "stream_options": {"include_usage": True},
            "max_tokens": resolved_max_tokens,
        }
        if openai_tools:
            payload["tools"] = openai_tools

        # Plan dynamicité 2026-05-14 : reasoning_effort si le modèle le
        # supporte (lecture registre). Aligne le streaming sur le path
        # non-stream pour cohérence.
        self._maybe_inject_reasoning_effort(payload, model, thinking_budget)

        log_llm_exchange("request", {**payload, "stream": True})

        max_retries = _resolve_max_retries()
        for attempt in range(max_retries + 1):
            # Garde contre la duplication sur retry : une fois qu'on a yieldé
            # un event au caller, on ne peut pas retry (le caller a déjà vu du
            # content partiel, un retry enverrait le stream complet par-dessus).
            stream_yielded_any = False
            try:
                collected_content: list[dict] = []
                # Indexé par ``index`` numérique (spec OpenAI/Mistral/Groq) :
                # le 1er chunk porte l'``id`` du tool_call et son nom, les
                # chunks suivants peuvent avoir ``id=null`` mais conservent
                # toujours ``index``. Sans dispatch par index, parallel
                # tool calling est cassé : args du 2e tool s'empilent dans
                # le 1er → JSON invalide → 400 au tour suivant.
                collected_tool_calls_by_index: dict[int, dict] = {}
                message_usage: dict[str, int] = {}

                async with client.stream(
                    "POST", f"{self.base_url}/chat/completions", json=payload
                ) as resp:
                    if _should_retry_http(resp.status_code) and attempt < max_retries:
                        retry_after_raw = _resolve_retry_after_from_headers(resp.headers)
                        delay = _compute_backoff(attempt, retry_after_raw)
                        logger.warning(
                            "OpenAI stream_with_tools HTTP %s, retry %d/%d in %.0fs%s",
                            resp.status_code,
                            attempt + 1,
                            max_retries,
                            delay,
                            _format_retry_info(retry_after_raw),
                        )
                        await asyncio.sleep(delay)
                        continue

                    if resp.status_code != 200:
                        body = await resp.aread()
                        try:
                            err_msg = _extract_error_message(json.loads(body))
                        except Exception:
                            err_msg = "HTTP %s" % resp.status_code
                        logger.error(
                            "OpenAI stream_with_tools error %s: %s",
                            resp.status_code,
                            err_msg,
                        )
                        if resp.status_code == 400 and not stream_yielded_any:
                            stripped = _strip_deprecated_params_from_msg(payload, err_msg)
                            if stripped:
                                logger.warning(
                                    "OpenAI stream_with_tools: param(s) déprécié(s) pour %s : %s. Retry sans.",
                                    payload.get("model"),
                                    ", ".join(stripped),
                                )
                                # Sortir du context async with et retenter
                                continue
                        if resp.status_code in _RETRIABLE_HTTP_CODES:
                            retry_after_raw = _resolve_retry_after_from_headers(resp.headers)
                            retry_after = _parse_retry_after(retry_after_raw, 60.0)
                            raise RateLimitError(retry_after, err_msg)
                        resp.raise_for_status()

                    async for line in resp.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        data_str = line[len("data:") :].strip()
                        if not data_str or data_str == "[DONE]":
                            continue

                        try:
                            chunk = json.loads(data_str)
                        except json.JSONDecodeError as e:
                            logger.warning("OpenAI SSE parse error: %s — line: %r", e, line)
                            continue

                        # ``stream_options.include_usage`` → un chunk FINAL
                        # porte ``usage`` AVEC ``choices: []``. On capte donc
                        # l'usage AVANT le guard ``if not choices`` ci-dessous
                        # (sinon ce chunk est ``continue``-skippé et le coût
                        # retombe à $0 — cf. #115 / D1-F5c). Capté à chaque
                        # chunk : on garde la dernière valeur non-vide (les
                        # providers qui l'envoient cumulativement marchent
                        # aussi).
                        _chunk_usage = chunk.get("usage")
                        if isinstance(_chunk_usage, dict) and _chunk_usage:
                            message_usage = _chunk_usage

                        choices = chunk.get("choices", [])
                        if not choices:
                            continue

                        choice = choices[0]
                        delta = choice.get("delta", {})
                        finish_reason = choice.get("finish_reason")

                        yield_event: Optional[dict] = None

                        if "content" in delta:
                            content_text = delta.get("content", "")
                            if content_text:
                                yield_event = {
                                    "type": "content_block_delta",
                                    "index": 0,
                                    "delta": {"type": "text_delta", "text": content_text},
                                }

                        if "tool_calls" in delta:
                            for tc in delta["tool_calls"]:
                                # Spec OpenAI : ``index`` numérique
                                # OBLIGATOIRE pour distinguer les tool_calls
                                # parallèles. Si manquant (provider mal
                                # implémenté), on suppose 0 (pas idéal mais
                                # compatible mono-call).
                                idx = tc.get("index")
                                if idx is None:
                                    idx = 0
                                tc_id = tc.get("id")
                                tc_func = tc.get("function", {})
                                # Initialise l'entrée pour cet index si neuve
                                if idx not in collected_tool_calls_by_index:
                                    collected_tool_calls_by_index[idx] = {
                                        "type": "tool_use",
                                        "id": tc_id or "",
                                        "name": tc_func.get("name", ""),
                                        "_raw_args": "",
                                    }
                                else:
                                    # Compléter ``id`` / ``name`` si arrive plus tard
                                    entry = collected_tool_calls_by_index[idx]
                                    if tc_id and not entry["id"]:
                                        entry["id"] = tc_id
                                    if tc_func.get("name") and not entry["name"]:
                                        entry["name"] = tc_func["name"]
                                # Accumuler les arguments
                                if "arguments" in tc_func:
                                    collected_tool_calls_by_index[idx]["_raw_args"] += tc_func[
                                        "arguments"
                                    ]

                        # Fin du streaming — émettre les tool_use blocks
                        has_tools = bool(collected_tool_calls_by_index)
                        if finish_reason and has_tools:
                            # Itère par index croissant (ordre déterministe)
                            for _idx_sorted in sorted(collected_tool_calls_by_index.keys()):
                                tc_data = collected_tool_calls_by_index[_idx_sorted]
                                # Parser le JSON complet accumulé
                                raw = tc_data.pop("_raw_args", "")
                                try:
                                    tc_data["input"] = json.loads(raw) if raw else {}
                                except (json.JSONDecodeError, TypeError):
                                    logger.warning(
                                        "OpenAI stream: invalid tool args JSON: %.200s", raw
                                    )
                                    tc_data["input"] = {}
                                idx = len(collected_content)
                                stream_yielded_any = True
                                yield {
                                    "type": "content_block_start",
                                    "index": idx,
                                    "content_block": tc_data,
                                }
                                yield {
                                    "type": "content_block_delta",
                                    "index": idx,
                                    "delta": {
                                        "type": "input_json_delta",
                                        "partial_json": json.dumps(tc_data.get("input", {})),
                                    },
                                }
                                collected_content.append(tc_data)

                        if yield_event:
                            stream_yielded_any = True
                            yield yield_event

                        if finish_reason:
                            stop_reason = "tool_use" if has_tools else "end_turn"
                            stream_yielded_any = True
                            for i, block in enumerate(collected_content):
                                if block.get("type") == "tool_use":
                                    yield {"type": "content_block_stop", "index": i}
                            yield {
                                "type": "message_delta",
                                "delta": {"stop_reason": stop_reason},
                            }

                log_llm_exchange("response", {"stream_events": collected_content})
                # #115 / D1-F5c — émettre l'usage capté via include_usage sous
                # forme d'un ``message_delta`` (shape attendue par
                # ``StreamAccountingWrapper.observe`` ET le consommateur
                # ``agent_service``). Normalisation cache IDENTIQUE au path
                # non-stream (#74/#114) : OpenAI ``prompt_tokens`` INCLUT le
                # cached → ``input_tokens = prompt - cached``, cached tracké à
                # part (``cache_read_input_tokens``) pour appliquer le discount.
                # Sans cette émission, le coût du stream OpenAI serait $0.
                if message_usage:
                    _raw_prompt = _usage_int(message_usage.get("prompt_tokens"))
                    _details = message_usage.get("prompt_tokens_details") or {}
                    _cached = (
                        _usage_int(_details.get("cached_tokens"))
                        if isinstance(_details, dict)
                        else 0
                    )
                    _completion = _usage_int(message_usage.get("completion_tokens"))
                    yield {
                        "type": "message_delta",
                        "delta": {},
                        "usage": {
                            "input_tokens": max(0, _raw_prompt - _cached),
                            "output_tokens": _completion,
                            "cache_read_input_tokens": _cached,
                        },
                    }
                # Yield le mapping PII en fin de stream pour permettre au caller
                # de restaurer la réponse agrégée. Émis APRÈS ``message_delta``
                # / ``content_block_stop`` finaux pour que les callers naïfs
                # (qui ignorent l'event) ne soient pas perturbés. No-op si
                # rien n'a été tokenisé.
                if pii_mapping:
                    yield {"type": PII_MAPPING_EVENT_TYPE, "mapping": pii_mapping}
                # Symétrique : mapping pseudonymizer user-scoped (§…§).
                # Permet au caller de remplacer les tokens dans la réponse
                # streamée agrégée. ⚠️ contient du cleartext, à ne JAMAIS
                # forwarder au front (filtre côté handler WS Iris).
                if pseudo is not None and len(pseudo) > 0:
                    yield {
                        "type": PSEUDO_MAPPING_EVENT_TYPE,
                        "mapping": pseudo.export_token_mapping(),
                    }
                return

            except _RETRIABLE_NETWORK_EXC as exc:
                # Pas de retry possible après avoir yieldé au caller : on
                # enverrait un stream complet par-dessus un stream partiel
                # (duplication de texte et d'args tool).
                if stream_yielded_any:
                    logger.error(
                        "OpenAI stream_with_tools network error mid-stream "
                        "(already yielded), cannot retry: %s",
                        exc,
                    )
                    raise
                if attempt < max_retries:
                    delay = _compute_backoff(attempt, None)
                    logger.warning(
                        "OpenAI stream_with_tools %s, retry %d/%d in %.0fs",
                        type(exc).__name__,
                        attempt + 1,
                        max_retries,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                logger.error("OpenAI stream_with_tools network error après retries: %s", exc)
                raise
            except httpx.HTTPStatusError as e:
                logger.error("OpenAI stream_with_tools HTTP error: %s", e)
                raise

        raise RateLimitError(60.0, "OpenAI stream rate limited: max retries exceeded")


class AnthropicProvider(LLMProvider):
    """
    Provider Anthropic (Claude 3/4).

    Nécessite ANTHROPIC_API_KEY dans l'environnement.
    """

    provider_name = "anthropic"

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = ANTHROPIC_TIMEOUT,
        *,
        base_url: Optional[str] = None,
    ):
        """Initialise le provider Anthropic/Claude.

        ``base_url`` permet de cibler un endpoint Anthropic-compatible
        (Vertex AI, proxy custom). Par défaut = ``ANTHROPIC_API_URL``.
        Keyword-only pour éviter les ambiguïtés avec ``timeout``.
        """
        self.api_key = _sanitize_api_key(api_key or os.getenv("ANTHROPIC_API_KEY", ""))
        self.base_url = _normalize_provider_base_url(base_url, ANTHROPIC_API_URL)
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Obtient ou crée le client HTTP avec headers Anthropic."""
        if self._client is None or self._client.is_closed:
            headers: dict[str, str] = {
                "anthropic-version": ANTHROPIC_API_VERSION,
                "Content-Type": "application/json",
            }
            if self.api_key:
                headers["x-api-key"] = self.api_key
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(self.timeout), headers=headers)
        return self._client

    async def close(self):
        """Ferme le client HTTP."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    # ── Capability detection ──────────────────────────────────────────
    # Extended thinking est supporté par Sonnet/Opus à partir de la génération 4.
    # On matche avec un regex anchored qui capture (famille, version) et compare
    # la version à un minimum. Avantages vs liste statique substring :
    #
    # 1. Futur-proof : Sonnet 5, Opus 5+ passent automatiquement (pas de
    #    régression silencieuse quand Anthropic publie la prochaine génération).
    # 2. Pas de false positive : `opus-40` ou `sonnet-4xmini` ne matchent pas
    #    — on exige que ce qui suit la version soit un séparateur ou une fin
    #    de chaîne (ex: `-5-20260101`, `-6`, fin de string).
    # 3. Haiku reste exclu (pas dans (sonnet|opus)).
    #
    # Le modèle minimal attendu : Claude 4. Les modèles plus anciens (Claude
    # 3.5, 3.7) ne supportent pas extended_thinking tel que l'API le définit
    # aujourd'hui.
    _EXTENDED_THINKING_MIN_GENERATION = 4
    # Regex anchored avec:
    # - préfixe `claude-` optionnel (présent dans tous les IDs réels
    #   2024-2026, mais certains tests/mocks utilisent juste `sonnet-4-6`)
    # - famille = sonnet|opus (haiku et Claude 3.x non supportés)
    # - version = UN seul digit (1-9) avec negative lookahead `(?!\d)` pour
    #   bloquer les faux positifs style "opus-40-*" (où `40` serait interprété
    #   comme gen 40). Si Anthropic publie une gen 10+, cette constante
    #   devra évoluer — volontairement limité pour éviter le risque de
    #   force-enable thinking sur des modèles mal nommés.
    # - après la version : séparateur (- ou . ou _) ou fin de string, garanti
    #   par `(?!\d)` qui refuse un digit immédiatement après.
    _EXTENDED_THINKING_MODEL_RE = re.compile(
        r"^(?:claude[-_])?(sonnet|opus)-(\d)(?!\d)",
        re.IGNORECASE,
    )

    def _supports_extended_thinking_for_model(self, model: Optional[str]) -> bool:
        """True si `model` supporte extended thinking.

        **Priorité** :
        1. Registre BDD (``LlmModel.supports_extended_thinking``) — admin
           override via UI ``/admin/ai-models``. Source de vérité runtime.
        2. Regex hardcodée Sonnet/Opus ≥ gen 4 — fallback quand le modèle
           n'est pas dans le registre (modèle nouveau pas encore synced,
           BDD vide en test, etc.).

        Garde-fou : la regex reste utilisée pour les modèles inconnus du
        registre — un futur Sonnet 5 résolu par regex passe sans intervention
        admin. Si l'admin a un avis (registre BDD), il prime.
        """
        if not model:
            return False
        # 1. Registre BDD prime
        from app.constants_ai import supports_capability_for_model

        from_registry = supports_capability_for_model(model, "extended_thinking")
        if from_registry is not None:
            return from_registry
        # 2. Fallback regex
        match = self._EXTENDED_THINKING_MODEL_RE.search(model)
        if not match:
            return False
        try:
            version = int(match.group(2))
        except (TypeError, ValueError):
            return False
        return version >= self._EXTENDED_THINKING_MIN_GENERATION

    @staticmethod
    def _supports_prompt_caching_for_model(model: Optional[str]) -> bool:
        """True si `model` supporte prompt caching.

        Priorité registre BDD → fallback ``True`` (tous les Claude récents
        2024-2026 supportent prompt caching ; si futur modèle ne le
        supporte pas, l'admin décoche le flag dans le registre).
        """
        if not model:
            return True
        from app.constants_ai import supports_capability_for_model

        from_registry = supports_capability_for_model(model, "prompt_caching")
        if from_registry is not None:
            return from_registry
        return True

    def _capability_map(self) -> dict[str, CapabilityHandler]:
        """Features supportées par Anthropic.

        ``interleaved_thinking`` et ``extended_thinking`` pointent sur le
        MÊME handler car ils sont techniquement couplés (même beta header
        ``interleaved-thinking-2025-05-14``, même whitelist modèle). Ajouter
        ``api_compaction`` ou ``tool_search_tool`` ici quand on les active.

        **Toutes les capabilities consultent le registre BDD en priorité** —
        l'admin peut désactiver une feature pour un modèle spécifique via
        ``PATCH /api/admin/llm/models/{name}`` (flag ``supports_*``).
        """
        return {
            LLMFeature.PROMPT_CACHING.value: self._supports_prompt_caching_for_model,
            LLMFeature.INTERLEAVED_THINKING.value: self._supports_extended_thinking_for_model,
            LLMFeature.EXTENDED_THINKING.value: self._supports_extended_thinking_for_model,
        }

    # Seuil minimal Anthropic pour le champ `thinking.budget_tokens` (doc
    # officielle). En dessous : l'API rejette ou ignore. On normalise le
    # comportement côté client : on skip ET on log un warning pour que les
    # misconfigurations (ex: AGENT_THINKING_BUDGET = 512) soient visibles.
    _ANTHROPIC_THINKING_MIN_BUDGET = 1024

    # Modèles qui supportent / préfèrent l'API adaptive thinking
    # (`thinking.type.adaptive` + `output_config.effort`). Doc Anthropic 2026 :
    #   - Opus 4.7 : adaptive UNIQUEMENT (`enabled` rejeté avec 400 Bad Request)
    #   - Opus 4.6 : adaptive recommandé, `enabled` deprecated mais accepté
    #   - Sonnet 4.6 : adaptive recommandé, `enabled` deprecated mais accepté
    #   - Claude Mythos Preview : adaptive par défaut
    #   - Opus 4.5 et antérieurs : manual seul (`enabled` + `budget_tokens`)
    #
    # Pattern regex :
    #   - `mythos` (toute variante)
    #   - `(sonnet|opus)-4-[6-9]` : gen 4 sous-version ≥ 6 (4.6, 4.7, 4.8, 4.9)
    #   - `(sonnet|opus)-[5-9]`   : gen 5-9 (future Opus 5, Sonnet 5, …)
    #   - lookahead `(?!\d)` pour rejeter `sonnet-40` ou `opus-4-60`.
    #
    # Si Anthropic publie une génération hors range, la regex devra évoluer —
    # préfère un skip (ancien chemin `enabled`) à un force-adaptive mal typé.
    _ADAPTIVE_THINKING_MODEL_RE = re.compile(
        r"^(?:claude[-_])?" r"(?:mythos(?:[-_]|$)|(?:sonnet|opus)-(?:[5-9](?!\d)|4-[6-9](?!\d)))",
        re.IGNORECASE,
    )

    # Niveau d'effort adaptive = `medium`. Doc Anthropic 2026 pour Sonnet 4.6 :
    # "Medium effort (recommended default): Best balance of speed, cost, and
    # performance for most applications. Suitable for agentic coding,
    # tool-heavy workflows, and code generation."
    # `max` consomme ~7 min de thinking par turn lourd sur 64K cap → timeout
    # pytest à 20 min sans achever la tâche. `medium` reste qualitatif sur
    # Sonnet 4.6 / Opus 4.6 / Opus 4.7 / Mythos tout en étant 3-5× plus rapide.
    _ADAPTIVE_DEFAULT_EFFORT = "medium"

    def _model_should_use_adaptive_thinking(self, model: Optional[str]) -> bool:
        """True si `model` supporte / préfère l'API adaptive thinking.

        Routage :
        - True  → payload `thinking.type.adaptive` + `output_config.effort`
          (forcé pour Opus 4.7 / Mythos ; recommandé pour Sonnet 4.6, Opus 4.6)
        - False → ancien payload `thinking.type.enabled` + `budget_tokens`
          (Opus 4.5 et antérieurs)
        """
        if not model:
            return False
        return bool(self._ADAPTIVE_THINKING_MODEL_RE.search(model))

    def _build_thinking_payload(
        self,
        payload: dict,
        resolved_model: str,
        thinking_budget: int,
    ) -> dict[str, str]:
        """Active extended + interleaved thinking sur ``payload`` si applicable.

        Source unique de vérité pour le couple ``thinking`` + beta header,
        partagée entre ``generate_with_tools`` et ``stream_with_tools``.

        Mute ``payload`` in-place (ajout du champ ``thinking``, retrait de
        ``temperature`` quand thinking est actif — exigence API) et retourne
        les headers additionnels à poser sur la requête.

        Deux chemins selon le modèle (détecté par ``_model_should_use_adaptive_thinking``) :

        - **Adaptive** (Sonnet 4.6, Opus 4.6, Opus 4.7, Mythos) :
          ``thinking.type.adaptive`` + ``output_config.effort``. Aucun header
          beta. ``thinking_budget`` ignoré (obsolète pour ces modèles).

        - **Manual / legacy** (Opus 4.5 et antérieurs) :
          ``thinking.type.enabled`` + ``budget_tokens``. Header beta
          ``interleaved-thinking-2025-05-14``.

        Le routage s'applique de manière transparente à TOUS les agents de
        Komptia qui utilisent ce provider (copilot_agent, Iris, auto-fill).

        Returns:
            Dict d'extra headers (vide si adaptive ou thinking non activé).
        """
        if thinking_budget <= 0:
            return {}

        # Chemin ADAPTIVE — Sonnet 4.6+, Opus 4.6+, Mythos. Vérifié AVANT le
        # gate `extended_thinking` car Mythos ne matche pas la whitelist
        # sonnet/opus mais supporte adaptive.
        # Plus de `budget_tokens` : le modèle scale son thinking selon la
        # difficulté de la tâche, `output_config.effort` est le dial qualité.
        # Pas de beta header (adaptive est GA).
        if self._model_should_use_adaptive_thinking(resolved_model):
            payload["thinking"] = {"type": "adaptive"}
            output_config = payload.get("output_config")
            if not isinstance(output_config, dict):
                output_config = {}
                payload["output_config"] = output_config
            output_config.setdefault("effort", self._ADAPTIVE_DEFAULT_EFFORT)
            # API rejette `temperature` quand thinking est actif — cohérence
            # avec le chemin `enabled`.
            payload.pop("temperature", None)
            logger.info(
                "Adaptive thinking enabled (effort=%s, model=%s).",
                output_config.get("effort"),
                _sanitize_for_log(resolved_model),
            )
            return {}

        # Chemin MANUAL — gate par feature extended_thinking (Sonnet/Opus gen 4).
        if not self.supports_feature("extended_thinking", model=resolved_model):
            logger.info(
                "Extended thinking skipped : modèle %s ne matche pas la whitelist "
                "(Sonnet/Opus ≥ génération %d). Requête envoyée sans `thinking`.",
                _sanitize_for_log(resolved_model),
                self._EXTENDED_THINKING_MIN_GENERATION,
            )
            return {}

        # Chemin MANUAL / LEGACY — Opus 4.5 et antérieurs. `budget_tokens`
        # requis avec seuil minimum 1024 (API rejette en dessous).
        if thinking_budget < self._ANTHROPIC_THINKING_MIN_BUDGET:
            logger.warning(
                "thinking_budget=%d sous le seuil Anthropic (%d) — ignoré. "
                "Fixer la config à 0 ou ≥%d.",
                thinking_budget,
                self._ANTHROPIC_THINKING_MIN_BUDGET,
                self._ANTHROPIC_THINKING_MIN_BUDGET,
            )
            return {}

        # Contrainte API Anthropic : `thinking.budget_tokens < max_tokens`
        # strictement. Si le caller passe budget >= max_tokens, on clampe
        # juste en dessous pour éviter un 400 invisible. La marge de 1024
        # réserve un minimum de tokens pour la vraie génération. Si
        # max_tokens - 1024 descend sous MIN_BUDGET, on skip proprement.
        effective_budget = thinking_budget
        current_max = payload.get("max_tokens")
        if isinstance(current_max, int) and effective_budget >= current_max:
            candidate = current_max - 1024
            if candidate < self._ANTHROPIC_THINKING_MIN_BUDGET:
                logger.warning(
                    "Extended thinking skipped : max_tokens=%d trop petit pour "
                    "accueillir thinking_budget (min %d + buffer 1024 réservé "
                    "à la vraie réponse).",
                    current_max,
                    self._ANTHROPIC_THINKING_MIN_BUDGET,
                )
                return {}
            effective_budget = candidate
            logger.info(
                "thinking_budget clampé de %d à %d (max_tokens=%d, contrainte API).",
                thinking_budget,
                effective_budget,
                current_max,
            )

        payload["thinking"] = {
            "type": "enabled",
            "budget_tokens": effective_budget,
        }
        payload.pop("temperature", None)
        logger.info(
            "Extended thinking enabled: budget=%d tokens, model=%s",
            effective_budget,
            _sanitize_for_log(resolved_model),
        )
        return {"anthropic-beta": "interleaved-thinking-2025-05-14"}

    # NOTE 2026-05-05 : pas de header ``context-1m-2025-08-07`` ici.
    # Anthropic a retiré ce beta header le 2026-04-30 ; le 1M tokens est
    # désormais GA sur Opus 4.6+, Opus 4.7 et Sonnet 4.6. Aucun header
    # spécial n'est requis pour bénéficier des grandes fenêtres : il
    # suffit que ``context_window`` en BDD reflète la valeur du modèle
    # (le sync LiteLLM s'en charge). Référence : retirement notice
    # Anthropic 2026-04-30.

    # ── Prompt caching ──────────────────────────────────────────────
    # ``_CACHE_CONTROL`` = TTL par défaut Anthropic (5 min). Conservé comme
    # constante pour rétrocompat (tests qui asserent dessus). Pour les
    # tool-loops longs (15-20 min typique), on préfère le TTL ``"1h"`` —
    # sélection par :meth:`_cache_control_for` en fonction de l'endpoint.
    #
    # IMPORTANT : ces dicts sont partagés entre tous les appels (même
    # référence retournée par ``_cache_control_for``). Les callers ne
    # DOIVENT PAS les muter — si une évolution future nécessite de les
    # modifier, il faut cloner (``dict(cc)``) avant.
    _CACHE_CONTROL: dict = {"type": "ephemeral"}
    _CACHE_CONTROL_LONG: dict = {"type": "ephemeral", "ttl": "1h"}

    # Opt-out : ``KOMPTIA_ANTHROPIC_CACHE_LONG_TTL=0`` (ou ``false``, ``no``,
    # ``off``, vide) force le TTL 5 min — rollback instantané sans modif
    # code si un provider/proxy rejette ``ttl: "1h"``. Casing insensible.
    # Lu au chargement du module — changer l'env var nécessite un restart
    # du process Python (acceptable : c'est un switch infra, pas user).
    _LONG_TTL_ENABLED: bool = os.getenv(
        "KOMPTIA_ANTHROPIC_CACHE_LONG_TTL", "1"
    ).strip().lower() not in ("0", "false", "no", "off", "n", "")

    # Types de blocs ``content`` de message Anthropic qui ne doivent JAMAIS
    # recevoir ``cache_control`` — contenu volatile qui change à chaque
    # appel (le raisonnement interne du modèle). Cacher ces blocs
    # invaliderait le préfixe du tour suivant et ruinerait le cache rate.
    _UNCACHEABLE_BLOCK_TYPES: frozenset = frozenset({"thinking", "redacted_thinking"})

    # Marqueur inséré par les callers pour séparer la partie STABLE
    # (rôle + règles + tools + schema BDD) de la partie VARIABLE du
    # system prompt (memory, deja_vu SQL, query_analysis, etc.).
    # Voir :meth:`_make_cacheable_system`. Valeur volontairement verbeuse
    # pour qu'elle ne risque jamais d'apparaître dans du contenu utilisateur.
    CACHE_BREAKPOINT = "<!--KOMPTIA:CACHE_BREAKPOINT-->"

    @staticmethod
    def _long_ttl_eligible(base_url: Optional[str]) -> bool:
        """Retourne ``True`` si l'endpoint supporte ``cache_control.ttl="1h"``.

        Officiellement supporté par ``api.anthropic.com`` et Vertex AI
        (``aiplatform.googleapis.com``). Les proxies Anthropic-compatibles
        (TogetherAI, Fireworks, Bedrock anciens) peuvent rejeter le flag
        ou l'ignorer silencieusement → on retombe prudemment sur le TTL
        5 min pour eux (qui reste bénéfique dans les tool-loops courts).

        ``base_url=None`` / vide → considéré comme ``api.anthropic.com``
        par défaut (c'est la valeur de ``ANTHROPIC_API_URL`` quand la
        config admin n'a rien overridé).
        """
        if not base_url:
            return True
        try:
            from urllib.parse import urlparse

            hostname = urlparse(base_url).hostname or ""
        except (TypeError, ValueError):
            return False
        # Trim optional trailing dot (DNS canonical form :
        # ``api.anthropic.com.`` doit être accepté comme équivalent).
        if hostname.endswith("."):
            hostname = hostname[:-1]
        if hostname == "api.anthropic.com":
            return True
        # Vertex AI : 3 formes officielles Google. On utilise une regex
        # stricte sur le label région pour éviter les faux positifs genre
        # ``fake-aiplatform.googleapis.com`` ou ``xxx-aiplatform.googleapis.com``.
        # Les régions Google Cloud suivent le format ``<area><digits>`` :
        # ``us-central1``, ``europe-west4``, ``asia-northeast1``, etc.
        # Pattern accepté : [a-z]{2,}(?:-[a-z0-9]+)*(?:-\d+)?
        _VERTEX_PATTERN = re.compile(r"^(?:[a-z]+-[a-z]+[0-9]+-)?aiplatform\.googleapis\.com$")
        if _VERTEX_PATTERN.match(hostname):
            return True
        return False

    @classmethod
    def _cache_control_for(cls, base_url: Optional[str]) -> dict:
        """Retourne le dict ``cache_control`` à utiliser pour un endpoint.

        - Endpoint éligible ``ttl: "1h"`` + feature flag ON → TTL 1h
        - Sinon → TTL 5 min (constante ``_CACHE_CONTROL``).

        Le dict retourné ne doit PAS être muté par les callers (la même
        référence est partagée entre tous les blocs d'un payload pour
        minimiser l'allocation).
        """
        if cls._LONG_TTL_ENABLED and cls._long_ttl_eligible(base_url):
            return cls._CACHE_CONTROL_LONG
        return cls._CACHE_CONTROL

    @staticmethod
    def _resolve_supports_caching(model_name: str) -> bool:
        """Lit le registre ``LlmModel.supports_prompt_caching`` pour le
        modèle cible. Retourne ``True`` si non renseigné (default safe pour
        ``AnthropicProvider`` qui supporte historiquement le caching).
        Seul un ``False`` EXPLICITE dans le registre déclenche le strip
        de ``cache_control`` — cas d'un proxy Anthropic-compat (Bedrock
        vieux, etc.) où l'admin a coché ``supports_prompt_caching=False``
        via ``/admin/ai-models``. Cf. plan dynamicité 2026-05-14.
        """
        from app.constants_ai import supports_capability_for_model

        # ``None`` = registre n'a pas d'avis → garder le default Anthropic
        # (caching activé). Seul ``False`` explicite désactive.
        val = supports_capability_for_model(model_name, "prompt_caching")
        return val is not False

    @staticmethod
    def _make_cacheable_system(
        system_text: str,
        *,
        cache_control: Optional[dict] = None,
        supports_caching: bool = True,
    ) -> list[dict]:
        """Convertit un system prompt string en bloc(s) Anthropic.

        Si ``system_text`` contient :data:`CACHE_BREAKPOINT`, on split en 2
        blocs : le préfixe (stable entre conversations, cacheable) et le
        suffixe (spécifique au tour, non cacheable). Ça évite de payer le
        cache_creation à chaque conversation si seulement la partie
        variable diffère.

        Sans marker → tout le text est cacheable (comportement legacy).

        ``cache_control`` : dict à utiliser ; si ``None``, fallback sur
        ``_CACHE_CONTROL`` (5 min) — défaut prudent pour les appelants
        qui n'ont pas encore été migrés.

        ``supports_caching`` : si ``False`` (modèle sans prompt caching,
        ex : OpenAI standard, Mistral, Groq), aucun ``cache_control`` n'est
        injecté — le payload reste compatible avec le provider downstream
        (qui ignorerait silencieusement le marker, mais on évite le bruit
        dans les payloads/logs). Le split sur ``CACHE_BREAKPOINT`` reste
        appliqué pour préserver la structure (2 blocs si marker présent),
        mais sans le ``cache_control``. Cf. plan dynamicité 2026-05-14.
        """
        marker = AnthropicProvider.CACHE_BREAKPOINT
        if not supports_caching:
            # Pas de caching : aucun ``cache_control`` injecté, mais on
            # préserve le split si le marker est présent (cohérent avec
            # la sémantique : "ce qui était stable reste un bloc distinct").
            if marker in system_text:
                stable, _, variable = system_text.partition(marker)
                blocks_nc: list[dict] = [{"type": "text", "text": stable}]
                if variable.strip():
                    blocks_nc.append({"type": "text", "text": variable})
                return blocks_nc
            return [{"type": "text", "text": system_text}]

        cc = cache_control if cache_control is not None else AnthropicProvider._CACHE_CONTROL
        if marker in system_text:
            stable, _, variable = system_text.partition(marker)
            blocks: list[dict] = [
                {
                    "type": "text",
                    "text": stable,
                    "cache_control": cc,
                }
            ]
            # Si la partie variable est vide (marker en fin) on n'ajoute
            # pas de bloc vide (Anthropic refuse).
            if variable.strip():
                blocks.append({"type": "text", "text": variable})
            return blocks
        return [
            {
                "type": "text",
                "text": system_text,
                "cache_control": cc,
            }
        ]

    @staticmethod
    def _add_cache_to_tools(
        tools: list[dict],
        *,
        cache_control: Optional[dict] = None,
        supports_caching: bool = True,
    ) -> list[dict]:
        """Ajoute cache_control au dernier outil (Anthropic cache tout le préfixe).

        Si ``supports_caching=False`` (modèle Anthropic-compat sans caching,
        ex : un proxy/Bedrock vieux), retourne ``tools`` inchangés —
        cohérent avec ``_make_cacheable_system``. Cf. plan dynamicité 2026-05-14.
        """
        if not tools or not supports_caching:
            return tools
        cc = cache_control if cache_control is not None else AnthropicProvider._CACHE_CONTROL
        tools = [*tools]  # copie pour ne pas muter l'original
        tools[-1] = {**tools[-1], "cache_control": cc}
        return tools

    @staticmethod
    def _add_cache_to_messages(
        messages: list[dict],
        *,
        cache_control: Optional[dict] = None,
        supports_caching: bool = True,
    ) -> list[dict]:
        """Ajoute un cache breakpoint sur l'avant-dernier message.

        Anthropic cache tout le préfixe jusqu'au breakpoint. Entre deux tours
        d'agent, seul le dernier message change (nouveau tool_result ou user msg).
        Tout l'historique avant est identique → caché → pas re-facturé.

        Le breakpoint est posé sur le DERNIER block non-``thinking`` du
        message cible. Les blocs ``thinking`` / ``redacted_thinking``
        représentent le raisonnement interne du modèle et changent à
        chaque appel : les cacher invaliderait le préfixe au tour
        suivant (miss systématique). En pratique Anthropic place toujours
        ``thinking`` en premier, mais cette garde défend contre des
        orderings non-standard (providers compatibles, futurs formats).
        """
        if len(messages) < 2 or not supports_caching:
            return messages
        cc = cache_control if cache_control is not None else AnthropicProvider._CACHE_CONTROL
        messages = [*messages]  # copie shallow
        target_idx = len(messages) - 2  # avant-dernier message
        target = messages[target_idx]
        content = target.get("content")

        if isinstance(content, str):
            # Convertir en format block pour pouvoir ajouter cache_control
            messages[target_idx] = {
                **target,
                "content": [
                    {
                        "type": "text",
                        "text": content,
                        "cache_control": cc,
                    }
                ],
            }
        elif isinstance(content, list) and content:
            # Trouver le DERNIER block cacheable (= dict ET non-thinking) en
            # remontant depuis la fin. Deux gardes :
            # 1. ``isinstance(block, dict)`` — un content list avec éléments
            #    non-dict (str brut, int) casserait le merge ``{**block, ...}``
            #    avec TypeError.
            # 2. ``type not in _UNCACHEABLE_BLOCK_TYPES`` — les blocs
            #    ``thinking`` / ``redacted_thinking`` représentent le
            #    raisonnement interne qui change à chaque appel, les cacher
            #    invaliderait le préfixe au tour suivant.
            # Si aucun block cacheable trouvé (tout thinking OU tout
            # non-dict), on ne pose pas de breakpoint — le cache cross-turn
            # reste sur system+tools+message-avant.
            content = [*content]
            cacheable_idx: Optional[int] = None
            for i in range(len(content) - 1, -1, -1):
                block = content[i]
                if not isinstance(block, dict):
                    continue
                block_type = block.get("type")
                if block_type in AnthropicProvider._UNCACHEABLE_BLOCK_TYPES:
                    continue
                cacheable_idx = i
                break
            if cacheable_idx is not None:
                content[cacheable_idx] = {**content[cacheable_idx], "cache_control": cc}
                messages[target_idx] = {**target, "content": content}

        return messages

    @staticmethod
    def _extract_thinking_tokens(usage: dict) -> int:
        """Extrait le nombre de tokens consommés par extended_thinking.

        Anthropic expose l'info soit à ``usage.thinking_tokens`` (variantes
        récentes) soit imbriqué dans ``usage.output_tokens_details.thinking_tokens``
        selon la version de l'API. On tente les 2 chemins connus.
        """
        direct = usage.get("thinking_tokens")
        if isinstance(direct, int) and direct >= 0:
            return direct
        details = usage.get("output_tokens_details") or usage.get("output_token_details")
        if isinstance(details, dict):
            val = details.get("thinking_tokens") or details.get("reasoning_tokens")
            if isinstance(val, int) and val >= 0:
                return val
        return 0

    @staticmethod
    def _log_cache_usage(usage: dict) -> None:
        """Log les métriques de cache + thinking_tokens si présentes.

        Rend visible la consommation d'extended_thinking (denial-of-wallet
        monitoring S3) : chaque ligne "thinking=N tokens" permet à l'admin
        de corréler via ``grep`` dans les logs quels users/sessions consomment
        le plus, sans nécessiter une migration de schéma DB.
        """
        cache_write = usage.get("cache_creation_input_tokens", 0)
        cache_read = usage.get("cache_read_input_tokens", 0)
        thinking = AnthropicProvider._extract_thinking_tokens(usage)

        if cache_write or cache_read:
            logger.info(
                "Anthropic cache: write=%d read=%d tokens (économie %.0f%%)",
                cache_write,
                cache_read,
                (cache_read / max(cache_read + usage.get("input_tokens", 1), 1)) * 100,
            )
        if thinking > 0:
            logger.info("Anthropic thinking consumed: %d tokens", thinking)

    # Wrappers conservés pour rétrocompat (tests + callers externes).
    # La logique réelle vit au module-level (_parse_retry_after / _format_retry_info)
    # pour être partagée avec OpenAIProvider sans dépendance cross-class.
    _RETRY_AFTER_RE = _RETRY_AFTER_RE

    @staticmethod
    def _parse_retry_after(header_value: Optional[str], fallback: float) -> float:
        """Parse Retry-After header safely. Returns delay capped at 60s."""
        return _parse_retry_after(header_value, fallback)

    @staticmethod
    def _format_retry_info(header_value: Optional[str]) -> str:
        """Format Retry-After info for log, sanitized against log injection."""
        return _format_retry_info(header_value)

    # _check_context_window extraite en fonction module-level (partagée Anthropic/OpenAI)

    async def health_check(self) -> bool:
        """Vérifie la disponibilité de l'API Anthropic via un vrai ping réseau.

        LOT 8.1 — Avant : ``return bool(self.api_key)`` (false-positive si la
        clé est révoquée ou si la connexion réseau est down). Maintenant on
        fait un ``GET /v1/models`` (low-cost, valide la clé + le réseau).
        """
        if not self.api_key:
            return False
        try:
            client = await self._get_client()
            response = await client.get(f"{self.base_url}/models")
            return response.status_code == 200
        except (ConnectionError, asyncio.TimeoutError, OSError, httpx.ConnectError):
            return False

    async def list_models(self) -> List[Dict[str, Any]]:
        """Liste les modèles disponibles via l'API Anthropic /v1/models."""
        if not self.api_key:
            return []

        try:
            client = await self._get_client()
            response = await client.get(f"{self.base_url}/models", params={"limit": 100})

            if response.status_code == 200:
                data = response.json()
                models = []
                for m in data.get("data", []):
                    models.append(
                        {
                            "name": m.get("id", ""),
                            "provider": "anthropic",
                            "display_name": m.get("display_name", m.get("id", "")),
                            "created_at": m.get("created_at"),
                        }
                    )
                if models:
                    logger.info("Anthropic: %s modèles récupérés via API", len(models))
                    return models

            logger.warning(
                "Anthropic API /models status %s, fallback sur liste statique", response.status_code
            )
        except Exception as e:
            logger.warning("Anthropic list_models API error: %s, fallback sur liste statique", e)

        return ANTHROPIC_AVAILABLE_MODELS

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Génère une réponse via l'API Anthropic (avec anonymisation PII)."""
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY non configurée")

        # Anonymiser les données avant envoi au provider externe
        anonymizer = get_anonymizer()
        anon_prompt, prompt_mapping = anonymizer.anonymize(request.prompt)
        anon_system, system_mapping = (
            anonymizer.anonymize(request.system) if request.system else ("", {})
        )
        pii_mapping = {**prompt_mapping, **system_mapping}

        if pii_mapping:
            logger.warning("Anthropic: %s PII anonymisées avant envoi", len(pii_mapping))

        # Couche 2 — pseudonymizer user-scoped (§…§), symétrique du chemin
        # generate_with_tools. Fail-closed si un terme configuré manque.
        pseudo = None
        if request.user_id is not None:
            from app.services.anonymization.proxy import _load_user_pseudonymizer

            pseudo = await _load_user_pseudonymizer(request.user_id)
            if pseudo is not None and len(pseudo) > 0:
                anon_prompt = pseudo.anonymize(anon_prompt)
                if anon_system:
                    anon_system = pseudo.anonymize(anon_system)
            else:
                pseudo = None

        client = await self._get_client()

        resolved_model = self._resolve_request_model(request.model, ANTHROPIC_DEFAULT_MODEL)
        # TTL 1h si endpoint éligible + feature flag ON, sinon TTL 5 min.
        cache_control = self._cache_control_for(self.base_url)
        # Structurer le message user avec prompt caching si un préfixe stable est fourni
        if request.prompt_cache_prefix:
            anon_prefix, prefix_mapping = anonymizer.anonymize(request.prompt_cache_prefix)
            pii_mapping.update(prefix_mapping)
            if pseudo is not None:
                anon_prefix = pseudo.anonymize(anon_prefix)
            user_content = [
                {"type": "text", "text": anon_prefix, "cache_control": cache_control},
                {"type": "text", "text": anon_prompt},
            ]
        else:
            user_content = anon_prompt

        # Clamper max_tokens au max réel du modèle — un appel avec
        # max_tokens=16384 sur Haiku (cap=8192) échouerait sinon.
        model_cap = get_max_tokens_for_model(resolved_model)
        requested_max = request.max_tokens or model_cap
        payload = {
            "model": resolved_model,
            "max_tokens": min(requested_max, model_cap),
            "temperature": _temperature_for_request(request),
            "messages": [{"role": "user", "content": user_content}],
        }
        # Lecture registre : caching activé pour ce modèle ?
        # Couvre le cas admin coche ``supports_prompt_caching=False`` sur
        # un modèle Anthropic-compat exotic (Bedrock vieux, proxy custom).
        _caching_enabled = self._resolve_supports_caching(resolved_model)
        if request.system:
            payload["system"] = self._make_cacheable_system(
                anon_system,
                cache_control=cache_control,
                supports_caching=_caching_enabled,
            )

        log_llm_exchange("request", payload)

        # Retry centralisé (429/529/5xx + erreurs réseau transitoires).
        # Auparavant : seuls les 429 étaient retry — un 529 "Overloaded"
        # faisait échouer silencieusement l'exploration Iris.
        max_retries = _resolve_max_retries()
        response: Optional[httpx.Response] = None
        duration = 0.0

        for attempt in range(max_retries + 1):
            try:
                start = time.time()
                payload = await _apply_cache_policy(payload)
                response = await client.post(f"{self.base_url}/messages", json=payload)
                duration = time.time() - start
            except _RETRIABLE_NETWORK_EXC as exc:
                if attempt < max_retries:
                    delay = _compute_backoff(attempt, None)
                    logger.warning(
                        "Anthropic generate %s, retry %d/%d in %.0fs",
                        type(exc).__name__,
                        attempt + 1,
                        max_retries,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                logger.error("Anthropic generate network error après retries: %s", exc)
                raise

            if _should_retry_http(response.status_code) and attempt < max_retries:
                retry_after_raw = _resolve_retry_after_from_headers(response.headers)
                delay = _compute_backoff(attempt, retry_after_raw)
                # Diagnostic 429/529 : dump les headers anthropic-ratelimit-* pour
                # voir EXACTEMENT pourquoi on est throttle (TPM saturé ? RPM ?
                # output cap ?). Sans ces données, impossible de distinguer
                # rate-limit org-level vs surcharge transient API globale.
                if response.status_code in (429, 529):
                    rl_headers = {
                        k: v
                        for k, v in response.headers.items()
                        if k.lower().startswith("anthropic-ratelimit") or k.lower() == "retry-after"
                    }
                    logger.warning(
                        "Anthropic %s rate-limit headers : %s",
                        response.status_code,
                        rl_headers or "(aucun header anthropic-ratelimit-*)",
                    )
                logger.warning(
                    "Anthropic generate HTTP %s, retry %d/%d in %.0fs%s",
                    response.status_code,
                    attempt + 1,
                    max_retries,
                    delay,
                    _format_retry_info(retry_after_raw),
                )
                await asyncio.sleep(delay)
                continue

            # 400 "X is deprecated for this model" → retirer le param et 1 retry
            if response.status_code == 400:
                stripped = _strip_deprecated_params(payload, response)
                if stripped:
                    logger.warning(
                        "Anthropic: param(s) déprécié(s) pour %s : %s. Retry sans.",
                        resolved_model,
                        ", ".join(stripped),
                    )
                    # Un seul retry après strip — évite les boucles si le message
                    # liste plusieurs params et qu'on en corrige un à la fois
                    try:
                        payload = await _apply_cache_policy(payload)
                        response = await client.post(f"{self.base_url}/messages", json=payload)
                    except _RETRIABLE_NETWORK_EXC as exc:
                        logger.error("Anthropic retry après strip: %s", exc)
                        raise
            break

        if response is None:  # défensif : boucle sortie sans response assignée
            raise RuntimeError("Anthropic generate: aucune réponse après retries")

        if response.status_code != 200:
            try:
                err_msg = _extract_error_message(response.json())
            except Exception:
                err_msg = "HTTP %s" % response.status_code
            logger.error("Anthropic API error %s: %s", response.status_code, err_msg)
            if response.status_code in _RETRIABLE_HTTP_CODES:
                retry_after_raw = _resolve_retry_after_from_headers(response.headers)
                retry_after = _parse_retry_after(retry_after_raw, 60.0)
                raise RateLimitError(retry_after, err_msg)
            response.raise_for_status()

        result = response.json()
        log_llm_exchange("response", result)

        usage = result.get("usage", {})
        self._log_cache_usage(usage)
        content_blocks = result.get("content")
        if not content_blocks or not isinstance(content_blocks, list):
            raise ValueError("Réponse Anthropic invalide: champ 'content' manquant ou vide")
        content = content_blocks[0].get("text", "")

        # Dé-anonymiser en ordre LIFO inverse de l'anonymisation : couche 2
        # pseudonymizer (§…§) PUIS couche 1 PII ([TYPE_N]) — aligné sur le SSoT
        # restore_fn du proxy. Sentinelles disjointes (§…§ vs [TYPE_N]).
        if pseudo is not None:
            content = pseudo.deanonymize(content)
        if pii_mapping:
            content = anonymizer.deanonymize(content, pii_mapping)

        return LLMResponse(
            content=content,
            model=resolved_model,
            provider=self.provider_name,
            prompt_tokens=usage.get("input_tokens"),
            completion_tokens=usage.get("output_tokens"),
            total_tokens=((usage.get("input_tokens") or 0) + (usage.get("output_tokens") or 0))
            or None,
            cache_creation_tokens=usage.get("cache_creation_input_tokens"),
            cache_read_tokens=usage.get("cache_read_input_tokens"),
            thinking_tokens=self._extract_thinking_tokens(usage) or None,
            duration_seconds=duration,
            raw_response=result,
        )

    async def generate_with_tools(
        self,
        request: LLMRequest,
        tools: list[dict],
        messages: list[dict],
        thinking_budget: int = 0,
        tool_choice: dict | None = None,
        user_id: Optional[int] = None,
    ) -> dict:
        """
        Appelle POST /v1/messages avec tool_use.

        **Anonymisation 2 couches inline** (defense-in-depth) — les
        ``messages`` (incluant blocks ``text``, ``tool_use.input``,
        ``tool_result``, ``thinking``) et le ``system`` sont passés par
        :func:`_anonymize_with_tools_payload` AVANT compact + envoi HTTP :
        couche 1 = PII regex, couche 2 = pseudonymizer user-scoped (§…§)
        si ``user_id`` fourni. La réponse est restaurée AVANT d'être
        retournée. Idempotent vs un caller qui aurait déjà tokenisé en
        amont (cf. ``iris_one_shot``).

        ``user_id`` doit être passé par tout caller servant un utilisateur
        final pour activer la couche 2 (termes manuels DUPONT, codes métier).

        Args:
            thinking_budget: Si > 0, active extended thinking avec ce budget de tokens.
                Le modèle réfléchit en interne avant chaque action (comme Claude Code).
                Les thinking blocks sont inclus dans la réponse et doivent être
                préservés dans l'historique de conversation.
            tool_choice: Optionnel — force le LLM à appeler un tool spécifique.
                Format Anthropic : ``{"type": "tool", "name": "<tool_name>"}`` ou
                ``{"type": "any"}`` (n'importe quel tool) ou ``{"type": "auto"}``
                (laisser le LLM décider). Par défaut None = pas de contrainte
                (≡ ``"auto"`` côté Anthropic). Utilisé par Phase 4 IR pour
                empêcher le LLM de répondre en text-only quand on attend un IR.

        Retourne le dict brut de la réponse Anthropic pour que l'agent loop
        puisse inspecter stop_reason et les content blocks (tool_use, text, thinking).
        """
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY non configurée")

        client = await self._get_client()

        resolved_model = self._resolve_request_model(request.model, ANTHROPIC_DEFAULT_MODEL)
        _model_cap_for_clamp = get_max_tokens_for_model(resolved_model)
        resolved_max_tokens = min(request.max_tokens or _model_cap_for_clamp, _model_cap_for_clamp)

        # Defense-in-depth : anonymisation 2 couches avant compact +
        # troncature + envoi HTTP. Couches idempotentes — un caller pré-tokenisé
        # (iris_one_shot.py via apply_builtin_pii cumulatif) reste safe car
        # les placeholders [TYPE_N] ne matchent aucune regex PII built-in et
        # les sentinelles §…§ ne se chevauchent pas avec [...]. Le ``pii_mapping``
        # et ``pseudo`` sont locaux à cet appel ; restore appliqué à la
        # réponse avant return.
        messages, anon_system_raw, pii_mapping, pseudo = await _anonymize_with_tools_payload(
            messages, request.system, user_id=user_id
        )

        # 1) Compact LLM-assisté en PREMIER — si le payload dépasse le seuil
        # de déclenchement, résume les messages anciens via Haiku et laisse
        # les derniers intacts. Préserve l'information (pas de jet brut) et
        # bénéficie aux runs agentic longs. Best-effort : en cas d'échec
        # (Haiku indispo, erreur réseau), retourne messages inchangés et on
        # retombe sur la troncature classique ci-dessous.
        compacted_messages, compacted_count = await _maybe_compact_messages(
            provider=self,
            messages=messages,
            system=anon_system_raw,
            tools=tools,
            max_tokens=resolved_max_tokens,
            model=resolved_model,
        )

        # 2) Troncature classique en filet de sécurité — déclenchée seulement
        # si le compact n'a pas suffi (ou n'a pas pu tourner). Respecte
        # l'invariant tool_use/tool_result depuis le fix 2026-04-22.
        checked_messages, removed_count = _check_context_window(
            model=resolved_model,
            messages=compacted_messages,
            system=anon_system_raw,
            tools=tools,
            max_tokens=resolved_max_tokens,
        )

        # Si des messages ont été tronqués/compactés, enrichir le system prompt
        # pour que l'agent sache qu'il a perdu du contexte
        effective_system = anon_system_raw
        if compacted_count > 0:
            logger.info(
                "Compact appliqué : %d message(s) résumés via Haiku avant appel principal.",
                compacted_count,
            )
        if removed_count > 0:
            effective_system += _TRUNCATION_WARNING_TEMPLATE.format(count=removed_count)
            logger.info(
                "Avertissement troncature injecté dans le system prompt (%d messages supprimés)",
                removed_count,
            )

        # TTL 1h si endpoint éligible (api.anthropic.com, Vertex AI) et
        # feature flag ON — sinon TTL 5 min par défaut. Un appel alloue le
        # dict une fois et le partage entre tous les breakpoints (system,
        # tools, messages) pour minimiser l'allocation et garder l'égalité
        # référentielle attendue par certains tests.
        cache_control = self._cache_control_for(self.base_url)
        # Lecture registre : caching activé pour ce modèle ?
        # Applique à system + tools + messages pour cohérence : si caching
        # est OFF, aucun ``cache_control`` n'est injecté dans le payload.
        _caching_enabled = self._resolve_supports_caching(resolved_model)
        cached_tools = self._add_cache_to_tools(
            tools, cache_control=cache_control, supports_caching=_caching_enabled
        )
        cached_messages = self._add_cache_to_messages(
            checked_messages, cache_control=cache_control, supports_caching=_caching_enabled
        )
        payload: dict = {
            "model": resolved_model,
            "max_tokens": resolved_max_tokens,
            "temperature": _temperature_for_request(request),
            "tools": cached_tools,
            "messages": cached_messages,
        }
        if effective_system:
            payload["system"] = self._make_cacheable_system(
                effective_system,
                cache_control=cache_control,
                supports_caching=_caching_enabled,
            )
        if tool_choice is not None:
            # Force ou contraint l'usage d'un tool. Cf. docstring du paramètre
            # `tool_choice`. Anthropic rejette côté serveur si le format est
            # invalide — on n'ajoute pas de validation cliente (laisse le
            # SDK gérer les erreurs).
            payload["tool_choice"] = tool_choice

        # Extended thinking via helper DRY (partagé avec stream_with_tools).
        # Pour les modèles adaptive, `_build_thinking_payload` fixe
        # `output_config.effort = max` par défaut (constante de classe).
        _extra_headers = self._build_thinking_payload(payload, resolved_model, thinking_budget)

        log_llm_exchange("request", payload)

        max_retries = _resolve_max_retries()
        for attempt in range(max_retries + 1):
            try:
                start = time.time()
                payload = await _apply_cache_policy(payload)
                response = await client.post(
                    f"{self.base_url}/messages",
                    json=payload,
                    headers=_extra_headers if _extra_headers else None,
                )
                duration = time.time() - start

                if _should_retry_http(response.status_code) and attempt < max_retries:
                    retry_after_raw = _resolve_retry_after_from_headers(response.headers)
                    delay = _compute_backoff(attempt, retry_after_raw)
                    logger.warning(
                        "Anthropic generate_with_tools HTTP %s, retry %d/%d in %.0fs%s",
                        response.status_code,
                        attempt + 1,
                        max_retries,
                        delay,
                        _format_retry_info(retry_after_raw),
                    )
                    await asyncio.sleep(delay)
                    continue

                if response.status_code != 200:
                    try:
                        err_msg = _extract_error_message(response.json())
                    except Exception:
                        err_msg = "HTTP %s" % response.status_code
                    logger.error(
                        "Anthropic generate_with_tools error %s: %s",
                        response.status_code,
                        err_msg,
                    )
                    # 400 "X is deprecated for this model" → retirer le param et
                    # retenter. Même pattern que dans generate() ligne 636.
                    if response.status_code == 400:
                        stripped = _strip_deprecated_params(payload, response)
                        if stripped:
                            logger.warning(
                                "Anthropic generate_with_tools: param(s) déprécié(s) "
                                "pour %s : %s. Retry sans.",
                                payload.get("model"),
                                ", ".join(stripped),
                            )
                            try:
                                response = await client.post(
                                    f"{self.base_url}/messages",
                                    json=payload,
                                    headers=_extra_headers if _extra_headers else None,
                                )
                            except _RETRIABLE_NETWORK_EXC as exc:
                                logger.error(
                                    "Anthropic generate_with_tools retry après strip: %s",
                                    exc,
                                )
                                raise
                            if response.status_code != 200:
                                try:
                                    err_msg = (
                                        response.json().get("error", {}).get("message", "unknown")
                                    )
                                except Exception:
                                    err_msg = "HTTP %s" % response.status_code
                                logger.error(
                                    "Anthropic generate_with_tools après strip: %s — %s",
                                    response.status_code,
                                    err_msg,
                                )
                                response.raise_for_status()
                        else:
                            response.raise_for_status()
                    elif response.status_code in _RETRIABLE_HTTP_CODES:
                        retry_after_raw = _resolve_retry_after_from_headers(response.headers)
                        retry_after = _parse_retry_after(retry_after_raw, 60.0)
                        raise RateLimitError(retry_after, err_msg)
                    else:
                        response.raise_for_status()

                result: dict = response.json()
                log_llm_exchange("response", result)
                self._log_cache_usage(result.get("usage", {}))
                # Restore 2 couches : pseudonymizer d'abord (sentinelles ``§…§``),
                # puis PII (placeholders ``[TYPE_N]``). Les 2 formats ne se
                # chevauchent pas. Best-effort : un échec retourne le payload
                # partiellement restauré (UX dégradée mais pas de crash ;
                # defense-in-depth core préservé puisque le LLM cloud n'a
                # JAMAIS vu de cleartext).
                if pseudo is not None and len(pseudo) > 0:
                    try:
                        result = pseudo.deanonymize(result)
                    except Exception as restore_exc:  # noqa: BLE001
                        logger.warning(
                            "Anthropic generate_with_tools: restore pseudonymizer échoué : %s",
                            restore_exc,
                        )
                if pii_mapping:
                    try:
                        from app.services.anonymization.proxy import _pii_restore_recursive

                        result = _pii_restore_recursive(result, pii_mapping)
                    except Exception as restore_exc:  # noqa: BLE001
                        logger.warning(
                            "Anthropic generate_with_tools: restore PII échoué : %s",
                            restore_exc,
                        )
                logger.debug(
                    "Anthropic generate_with_tools: stop_reason=%s, duration=%.2fs",
                    result.get("stop_reason"),
                    duration,
                )
                return result

            except _RETRIABLE_NETWORK_EXC as exc:
                if attempt < max_retries:
                    delay = _compute_backoff(attempt, None)
                    logger.warning(
                        "Anthropic generate_with_tools %s, retry %d/%d in %.0fs",
                        type(exc).__name__,
                        attempt + 1,
                        max_retries,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                logger.error("Anthropic generate_with_tools network error après retries: %s", exc)
                raise
            except httpx.HTTPStatusError as e:
                logger.error("Anthropic generate_with_tools HTTP error: %s", e)
                raise

        raise RuntimeError("Anthropic generate_with_tools: max retries exceeded")

    async def stream_with_tools(
        self,
        request: LLMRequest,
        tools: list[dict],
        messages: list[dict],
        thinking_budget: int = 0,
        user_id: Optional[int] = None,
    ) -> AsyncGenerator[dict, None]:
        """
        Appelle POST /v1/messages avec stream=True et tool_use.

        **Anonymisation 2 couches** des ``messages`` + ``system`` AVANT envoi
        (defense-in-depth) : couche 1 PII regex + couche 2 pseudonymizer
        user-scoped si ``user_id`` fourni. Les events SSE sont yieldés bruts
        — un placeholder coupé entre 2 chunks ``content_block_delta`` est
        une faille de restore live. À la fin du stream, un event spécial
        ``{"type": "_pii_mapping", "mapping": {...}}`` est yieldé si au
        moins une PII a été tokenisée. Le caller assemble la réponse
        complète puis applique :func:`_pii_restore_recursive` avec ce
        mapping pour restaurer le cleartext PII. Caller qui ignore l'event
        reste fonctionnel — UX dégradée : placeholders ``[TYPE_N]``
        visibles côté user pendant les chunks live et après.

        ⚠️ **Dette streaming pseudo-restore** : la couche 2 (§…§) est
        appliquée à l'INPUT mais le restore output stream n'est pas
        encore implémenté. Le caller verra des ``§CLIENT_A§`` dans les
        chunks live. Les valeurs réelles ne quittent JAMAIS le serveur
        (sécurité OK), mais l'UX est dégradée. Fix prévu via un nouvel
        event ``{"type": "_pseudo_token_mapping"}`` consommé par le
        caller pour restorer la réponse agrégée.

        Args:
            thinking_budget: Si > 0, active extended thinking (interleaved).

        Yield chaque événement SSE parsé en dict (content_block_delta, message_delta, etc.).
        Les thinking deltas ont type=content_block_delta avec delta.type=thinking_delta.
        """
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY non configurée")

        client = await self._get_client()

        resolved_model = self._resolve_request_model(request.model, ANTHROPIC_DEFAULT_MODEL)
        _model_cap_for_clamp = get_max_tokens_for_model(resolved_model)
        resolved_max_tokens = min(request.max_tokens or _model_cap_for_clamp, _model_cap_for_clamp)

        # Defense-in-depth : anonymisation 2 couches avant troncature et envoi.
        # Idempotent vs caller pré-tokenisé. Cf. ``_anonymize_with_tools_payload``.
        # ``pseudo`` est capturé pour pouvoir yielder son mapping en fin de
        # stream (event ``PSEUDO_MAPPING_EVENT_TYPE``) — le caller peut alors
        # restaurer la réponse agrégée et afficher ``DUPONT`` au lieu de
        # ``§CLIENT_A§`` à l'utilisateur.
        messages, anon_system_raw, pii_mapping, pseudo = await _anonymize_with_tools_payload(
            messages, request.system, user_id=user_id
        )

        # Vérifier le context window et tronquer si nécessaire
        checked_messages, removed_count = _check_context_window(
            model=resolved_model,
            messages=messages,
            system=anon_system_raw,
            tools=tools,
            max_tokens=resolved_max_tokens,
        )

        # Même logique de warning troncature que generate_with_tools
        effective_system = anon_system_raw
        if removed_count > 0:
            effective_system += _TRUNCATION_WARNING_TEMPLATE.format(count=removed_count)

        cache_control = self._cache_control_for(self.base_url)
        _caching_enabled = self._resolve_supports_caching(resolved_model)
        cached_tools = self._add_cache_to_tools(
            tools, cache_control=cache_control, supports_caching=_caching_enabled
        )
        cached_messages = self._add_cache_to_messages(
            checked_messages, cache_control=cache_control, supports_caching=_caching_enabled
        )
        payload: dict = {
            "model": resolved_model,
            "max_tokens": resolved_max_tokens,
            "temperature": _temperature_for_request(request),
            "tools": cached_tools,
            "messages": cached_messages,
            "stream": True,
        }
        if effective_system:
            payload["system"] = self._make_cacheable_system(
                effective_system,
                cache_control=cache_control,
                supports_caching=_caching_enabled,
            )

        # Extended thinking en streaming (même helper DRY).
        _extra_headers = self._build_thinking_payload(payload, resolved_model, thinking_budget)

        max_retries = _resolve_max_retries()
        for attempt in range(max_retries + 1):
            # Garde contre la duplication sur retry : une fois qu'on a yieldé
            # un event au caller, un retry réenverrait le stream complet
            # par-dessus (texte et thinking dupliqués).
            stream_yielded_any = False
            try:
                payload = await _apply_cache_policy(payload)
                log_llm_exchange("request", {**payload, "stream": True})
                collected_events: list[dict] = []

                async with client.stream(
                    "POST",
                    f"{self.base_url}/messages",
                    json=payload,
                    headers=_extra_headers if _extra_headers else None,
                ) as resp:
                    if _should_retry_http(resp.status_code) and attempt < max_retries:
                        retry_after_raw = _resolve_retry_after_from_headers(resp.headers)
                        delay = _compute_backoff(attempt, retry_after_raw)
                        logger.warning(
                            "Anthropic stream_with_tools HTTP %s, retry %d/%d in %.0fs%s",
                            resp.status_code,
                            attempt + 1,
                            max_retries,
                            delay,
                            _format_retry_info(retry_after_raw),
                        )
                        await asyncio.sleep(delay)
                        continue

                    if resp.status_code != 200:
                        body = await resp.aread()
                        try:
                            err_msg = _extract_error_message(json.loads(body))
                        except Exception:
                            err_msg = "HTTP %s" % resp.status_code
                        logger.error(
                            "Anthropic stream_with_tools error %s: %s",
                            resp.status_code,
                            err_msg,
                        )
                        if resp.status_code == 400 and not stream_yielded_any:
                            stripped = _strip_deprecated_params_from_msg(payload, err_msg)
                            if stripped:
                                logger.warning(
                                    "Anthropic stream_with_tools: param(s) déprécié(s) pour %s : %s. Retry sans.",
                                    payload.get("model"),
                                    ", ".join(stripped),
                                )
                                continue
                        if resp.status_code in _RETRIABLE_HTTP_CODES:
                            retry_after_raw = _resolve_retry_after_from_headers(resp.headers)
                            retry_after = _parse_retry_after(retry_after_raw, 60.0)
                            raise RateLimitError(retry_after, err_msg)
                        resp.raise_for_status()

                    async for line in resp.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        data_str = line[len("data:") :].strip()
                        if not data_str or data_str == "[DONE]":
                            continue
                        try:
                            event = json.loads(data_str)
                            collected_events.append(event)
                            stream_yielded_any = True
                            yield event
                        except json.JSONDecodeError as e:
                            logger.warning("Anthropic SSE parse error: %s — line: %r", e, line)

                log_llm_exchange("response", {"stream_events": collected_events})
                # Cache metrics from message_start event
                for ev in collected_events:
                    if ev.get("type") == "message_start":
                        self._log_cache_usage(ev.get("message", {}).get("usage", {}))
                        break
                # Yield le mapping PII en fin de stream pour permettre au caller
                # de restaurer la réponse agrégée. Émis APRÈS les events SSE
                # natifs ; un caller naïf qui s'arrête sur ``message_stop``
                # ne le voit jamais (no-op de son point de vue).
                if pii_mapping:
                    yield {"type": PII_MAPPING_EVENT_TYPE, "mapping": pii_mapping}
                # Symétrique : mapping pseudonymizer user-scoped (§…§).
                # Permet au caller de remplacer les tokens dans la réponse
                # streamée agrégée. ⚠️ contient du cleartext, à ne JAMAIS
                # forwarder au front (filtre côté handler WS Iris).
                if pseudo is not None and len(pseudo) > 0:
                    yield {
                        "type": PSEUDO_MAPPING_EVENT_TYPE,
                        "mapping": pseudo.export_token_mapping(),
                    }
                return  # Stream terminé avec succès, sortir de la boucle retry

            except _RETRIABLE_NETWORK_EXC as exc:
                # Pas de retry si des events sont déjà partis vers le caller
                # (duplication de texte/thinking garantie sinon).
                if stream_yielded_any:
                    logger.error(
                        "Anthropic stream_with_tools network error mid-stream "
                        "(already yielded), cannot retry: %s",
                        exc,
                    )
                    raise
                if attempt < max_retries:
                    delay = _compute_backoff(attempt, None)
                    logger.warning(
                        "Anthropic stream_with_tools %s, retry %d/%d in %.0fs",
                        type(exc).__name__,
                        attempt + 1,
                        max_retries,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                logger.error("Anthropic stream_with_tools network error après retries: %s", exc)
                raise
            except httpx.HTTPStatusError as e:
                logger.error("Anthropic stream_with_tools HTTP error: %s", e)
                raise

        raise RateLimitError(60.0, "Anthropic stream rate limited: max retries exceeded")


class LLMManager:
    """
    Gestionnaire de providers LLM.

    Gère plusieurs providers et permet de basculer facilement entre eux.
    Inspiré de l'approche multi-LLM de Vanna.ai mais avec DI propre.
    """

    HEALTH_CACHE_TTL = 300  # 5 minutes

    def __init__(self):
        """Initialise le gestionnaire de providers."""
        self._providers: Dict[str, LLMProvider] = {}
        self._default_provider: Optional[str] = None
        self._default_model: Optional[str] = None
        self._health_cache: Optional[Dict[str, bool]] = None
        self._health_cache_time: float = 0.0
        # LLM local de fallback (séparé du registre principal pour qu'il ne
        # soit pas accidentellement choisi comme primary). Utilisé :
        # 1) Comme provider d'anonymisation (auto-extraction termes sensibles
        #    avant envoi cloud) — cf. ``auto_classify.py``.
        # 2) Comme fallback runtime quand le primary lève
        #    ``RateLimitError``/``httpx.NetworkError``/HTTP 5xx — préserve la
        #    continuité de service quand l'API cloud est indisponible.
        self._local_fallback: Optional[LLMProvider] = None
        self._local_fallback_model: Optional[str] = None
        # Defaults runtime hydratés depuis ``/admin/ai-config`` au boot et
        # rafraîchis à chaque save admin (cf. ``hydrate_defaults_from_config``).
        # Source unique de vérité : si ``None``, les call sites retombent sur
        # les constantes statiques ``DEFAULT_TEMPERATURE`` / ``DEFAULT_MAX_RETRIES``.
        # Cloud + local ont des defaults distincts (l'admin peut tuner Ollama
        # différemment du cloud).
        self._default_temperature: Optional[float] = None
        self._default_max_retries: Optional[int] = None
        self._default_timeout_seconds: Optional[float] = None
        self._local_default_temperature: Optional[float] = None
        self._local_default_max_retries: Optional[int] = None

    @property
    def default_temperature(self) -> Optional[float]:
        return self._default_temperature

    @property
    def default_max_retries(self) -> Optional[int]:
        return self._default_max_retries

    @property
    def default_timeout_seconds(self) -> Optional[float]:
        return self._default_timeout_seconds

    @property
    def local_default_temperature(self) -> Optional[float]:
        return self._local_default_temperature

    @property
    def local_default_max_retries(self) -> Optional[int]:
        return self._local_default_max_retries

    async def hydrate_defaults_from_config(self, config_service) -> None:
        """Lit ``temperature`` / ``max_retries`` / ``timeout_seconds`` (cloud)
        et leurs équivalents ``local_llm_*`` depuis la config admin et les
        stocke comme defaults runtime. Appelé au boot puis à chaque save
        admin (via ``reinit_providers_from_config``). Bornes anti-aberration
        appliquées (un admin qui saisit temperature=10 ne casse pas tout).
        """

        def _safe_float(raw: Any, lo: float, hi: float) -> Optional[float]:
            try:
                v = float(raw)
            except (TypeError, ValueError):
                return None
            if v < lo or v > hi:
                return None
            return v

        def _safe_int(raw: Any, lo: int, hi: int) -> Optional[int]:
            try:
                v = int(raw)
            except (TypeError, ValueError):
                return None
            if v < lo or v > hi:
                return None
            return v

        try:
            self._default_temperature = _safe_float(
                await config_service.get("temperature"), 0.0, 2.0
            )
            self._default_max_retries = _safe_int(await config_service.get("max_retries"), 0, 10)
            self._default_timeout_seconds = _safe_float(
                await config_service.get("timeout_seconds"), 5.0, 1800.0
            )
            self._local_default_temperature = _safe_float(
                await config_service.get("local_llm_temperature"), 0.0, 2.0
            )
            self._local_default_max_retries = _safe_int(
                await config_service.get("local_llm_max_retries"), 0, 10
            )
        except Exception as exc:  # noqa: BLE001 — fail-soft, on garde les Nones
            logger.warning("hydrate_defaults_from_config échoué : %s", exc)

    def register_provider(self, provider: LLMProvider, is_default: bool = False):
        """Enregistre un provider LLM."""
        self._providers[provider.provider_name] = provider
        if is_default or len(self._providers) == 1:
            self._default_provider = provider.provider_name
        logger.info("Provider LLM enregistré: %s", provider.provider_name)

    def register_local_fallback(
        self, provider: LLMProvider, model_name: Optional[str] = None
    ) -> None:
        """Enregistre un LLM local (Ollama, LM Studio, TGI…) comme :
        - source d'anonymisation auto (extraction PII via prompt court),
        - fallback runtime quand le primary lève rate limit / réseau / 5xx.

        Le local n'est JAMAIS utilisé comme primary par défaut — l'admin
        doit le choisir explicitement via ``primary_provider`` s'il veut
        que toutes les requêtes y passent.

        **Lookup dual** (fix 2026-05-19) : le local est aussi ajouté à
        :data:`_providers` (sans toucher ``_default_provider``) pour que
        :func:`call_llm` avec ``ModelKind.LOCAL`` puisse l'atteindre via
        ``get_provider(local.provider_name)``. Sans cela : ``_resolve_model``
        renvoie ``provider_name="local"`` mais ``manager.generate(provider_name="local")``
        appelle ``get_provider("local")`` → ``ValueError: Provider LLM non
        trouvé: local`` car le local vivait UNIQUEMENT dans ``_local_fallback``.

        **Flag ``_is_local_kind``** (fix B2 review adversariale 2026-05-22) :
        marque cette instance comme "local-kind" pour que la garde
        anti-double-trip de :meth:`generate` / :meth:`generate_with_tools`
        détecte le local indépendamment d'un check d'identity sensible
        au swap admin atomique. Si l'admin remplace X (ancien local) par
        Y (nouveau local), une requête déjà en vol sur X conserve son
        flag — pas de retry futile sur Y.
        """
        self._local_fallback = provider
        self._local_fallback_model = model_name
        # Marqueur "local-kind" — utilisé par la garde anti-double-trip.
        # Posé sur l'instance, pas une classe → résilient au swap atomique.
        # ``setattr`` évite l'erreur sur les providers qui ont ``__slots__``
        # (cas hypothétique — nos providers actuels n'en ont pas).
        try:
            setattr(provider, "_is_local_kind", True)
        except AttributeError:
            # Provider avec __slots__ stricts : on tolère silencieusement,
            # la garde repliera sur l'identity check (qui marche tant qu'il
            # n'y a pas de swap).
            pass
        # Ajout aussi dans le dict providers (sans changer _default_provider).
        # ``get_provider(provider.provider_name)`` doit pouvoir trouver le
        # local sans connaître sa nature spéciale. Si un autre provider est
        # déjà enregistré sous le même nom (ne devrait pas arriver — le
        # local utilise ``provider_name="local"``), on l'écrase
        # silencieusement : le local fallback prend la priorité runtime.
        self._providers[provider.provider_name] = provider
        # Invalider le cache health_check : sinon le dashboard montre
        # l'état du PRÉCÉDENT fallback pendant 5 min après le swap, ce
        # qui ment à l'admin (review adversariale 2026-05-15).
        self.invalidate_health_cache()
        logger.info(
            "LLM local fallback enregistré: %s (model=%s)",
            provider.provider_name,
            model_name or "<auto>",
        )

    def get_local_fallback(self) -> Optional[LLMProvider]:
        """Retourne le LLM local fallback s'il est configuré, sinon None."""
        return self._local_fallback

    def get_local_fallback_model(self) -> Optional[str]:
        return self._local_fallback_model

    def get_local_provider_name(self) -> str:
        """Nom du provider local fallback (= ``provider_name``).

        Permet aux callers (ex: ``stats_service.get_dashboard_metrics`` pour
        compter les rows fallback) de filtrer SANS hardcoder ``"local"``.
        Si l'admin renomme le provider via ``register_local_fallback(..., name="X")``,
        le compteur suit dynamiquement.

        Bug 2026-05-26 (Agent 3 AI-1) : avant, ``stats_service`` hardcodait
        ``model_provider == "local"`` ce qui castait silencieusement le
        compteur si le provider changeait de nom.

        Fallback : ``"local"`` quand aucun fallback n'est enregistré
        (rétro-compat — les rows historiques écrites avec ``"local"``
        restent comptées par les queries qui utilisent ce helper).
        """
        if self._local_fallback is None:
            return "local"
        return getattr(self._local_fallback, "provider_name", None) or "local"

    def get_provider(self, name: Optional[str] = None) -> LLMProvider:
        """Récupère un provider par nom (ou le défaut)."""
        provider_name = name or self._default_provider
        if not provider_name or provider_name not in self._providers:
            raise ValueError(f"Provider LLM non trouvé: {provider_name}")
        return self._providers[provider_name]

    def has_any_provider_configured(self) -> bool:
        """Vrai si AU MOINS un provider (cloud OU local) est utilisable runtime.

        **Source de vérité unique** : reflète l'état du manager après
        ``_init_default_providers`` (env vars) + ``ensure_providers_from_db``
        (admin config BDD). Couvre les 2 chemins d'enregistrement sans
        re-lire la BDD à chaque check.

        Utilisé par :
        - :func:`app.services.ai.llm_runtime._ensure_llm_runtime_ready`
          pour fail-fast avant tout HTTP quand aucun provider n'est
          enregistré (clé API vide en BDD ET pas d'env var, et local LLM
          désactivé).
        - :class:`app.handlers.base.BaseHandler` pour injecter
          ``llm_configured`` dans le contexte template (banner global UI).
        - Refactor DRY des checks ad-hoc dans
          ``widget_planner/_llm_common`` et ``llm_report_planner``.

        Cloud requis : ``_providers`` non vide ET ``_default_provider`` set
        (un provider register sans default ne sert à rien, c'est un état
        transitoire bug). Local requis : ``_local_fallback`` non None
        (l'admin a activé Ollama + saisi un modèle local).
        """
        has_cloud = bool(self._providers) and bool(self._default_provider)
        has_local = self._local_fallback is not None
        return has_cloud or has_local

    def supports_feature(
        self,
        feature: str,
        *,
        model: Optional[str] = None,
        provider_name: Optional[str] = None,
    ) -> bool:
        """Pass-through vers :meth:`LLMProvider.supports_feature` du provider ciblé.

        Permet au code applicatif (ex: ``agent_service``) de décider sans
        connaître quel provider est actif. Fail-safe total : si aucun
        provider n'est enregistré OU si un provider custom lève une
        exception dans son ``supports_feature``, retourne False (jamais
        bloquer le tour utilisateur sur une question capacitaire).

        ``model`` et ``provider_name`` sont keyword-only pour rendre l'API
        auto-documentée et stable (pas de dépendance à l'ordre positionnel).
        """
        try:
            provider = self.get_provider(provider_name)
        except ValueError:
            return False
        try:
            return provider.supports_feature(feature, model=model)
        except Exception as exc:  # noqa: BLE001 — fail-safe by design
            logger.warning(
                "supports_feature(%s) a levé une exception sur %s: %s — "
                "réponse False par défaut.",
                _sanitize_for_log(feature),
                _sanitize_for_log(provider.provider_name),
                _sanitize_for_log(str(exc), max_len=200),
            )
            return False

    def set_default(self, provider_name: str, model_name: Optional[str] = None):
        """Définit le provider et modèle par défaut."""
        if provider_name not in self._providers:
            raise ValueError(f"Provider non enregistré: {provider_name}")
        self._default_provider = provider_name
        self._default_model = model_name

    @property
    def default_provider_name(self) -> Optional[str]:
        return self._default_provider

    @property
    def default_model_name(self) -> Optional[str]:
        return self._default_model

    def _is_fallback_eligible_error(self, exc: BaseException) -> bool:
        """Détermine si une erreur primary doit déclencher le fallback local.

        Eligible :
        - rate limit (RateLimitError, HTTP 429)
        - réseau down, timeout (``_RETRIABLE_NETWORK_EXC``)
        - HTTP 5xx provider
        - HTTP 413 (payload trop gros) — typiquement un tier free à TPM bas
          (Groq 8k TPM refuse un payload Iris standard de ~20k). Conceptuellement
          équivalent à un rate-limit côté tokens : le cloud refuse, le local
          (sans quota) peut servir. Si le local a une context window plus
          petite et échoue lui aussi, ``_try_local_fallback_or_reraise``
          re-raise l'erreur primary (cf. ligne 3970) — donc inclure 413 ici
          ne dégrade JAMAIS le pire cas, ça améliore juste le cas Ollama
          configuré.
        - ``RuntimeError("...max retries exceeded...")`` : le provider a
          épuisé sa boucle de retry interne (3 tentatives par défaut)
          sur un transient (typiquement réseau ou rate-limit). Sans cette
          ligne, on rate le fallback ALORS QUE c'est précisément le cas
          où on en a besoin (review adversariale 2026-05-15 → P4 #26).

        NON eligible : autres 4xx (auth invalide, modèle deprecated, etc. →
        fail-fast voulu, l'admin doit corriger), ValueError.
        """
        if isinstance(exc, RateLimitError):
            return True
        if isinstance(exc, _RETRIABLE_NETWORK_EXC):
            return True
        status_code = getattr(getattr(exc, "response", None), "status_code", None)
        if isinstance(status_code, int):
            if 500 <= status_code < 600:
                return True
            if status_code in (413, 429):
                return True
        # RuntimeError "max retries exceeded" : provider a déjà retenté en
        # interne (cf. _resolve_max_retries) sur un transient, sans succès.
        # Le fallback local n'a PAS le même problème (réseau différent /
        # quota différent), donc ça vaut le coup de tenter.
        if isinstance(exc, RuntimeError) and "max retries" in str(exc).lower():
            return True
        return False

    async def _try_local_fallback_or_reraise(
        self,
        method_name: str,
        primary_exc: BaseException,
        *args,
        **kwargs,
    ) -> Any:
        """Tente d'appeler ``method_name`` sur le LLM local fallback.

        Utilisé quand le primary lève une erreur transitoire (rate limit,
        réseau, 5xx). Retourne le résultat de l'appel local OU re-raise
        l'exception ``primary_exc`` si le local n'est pas configuré ou
        s'il échoue lui aussi.

        Le model du request est rebasculé vers ``_local_fallback_model``
        (le local n'expose pas les mêmes IDs que l'API cloud — Ollama
        utilise des noms type ``phi3:mini``).

        **Garde-fou tool_use (fail-CLOSED)** : si on tente un
        ``generate_with_tools`` ET que ``tools`` est non-vide, on refuse
        le fallback SAUF si le registre BDD déclare explicitement
        ``supports_tool_use=True`` pour le modèle local. Raison : un
        modèle 3B sans tool calling natif (phi3:mini, llama3.2:3b)
        renverra du texte hallucinant un tool_use → SQL faux silencieux
        côté Iris. La doctrine Komptia interdit les résultats faux
        silencieux (cf. ``consequences.md`` Q5).

        Cas refusés (fail-CLOSED) :
        - ``_local_fallback_model`` non configuré (None ou "")
        - registre BDD retourne ``False`` (capability explicit absente)
        - registre BDD retourne ``None`` (modèle inconnu / pas d'avis)

        Cas autorisé : registre BDD retourne ``True`` explicit pour
        ``supports_tool_use``.
        """
        from app.constants_ai import supports_capability_for_model
        from app.utils.request_context import current_caller, current_user_id

        # Capture refs locales pour éviter race avec swap concurrent
        # (admin désactive Ollama / change le modèle local pendant qu'un
        # fallback est en cours d'exécution).
        local_fb = self._local_fallback
        local_fb_model = self._local_fallback_model
        if local_fb is None:
            raise primary_exc
        local_method = getattr(local_fb, method_name, None)
        if local_method is None:
            raise primary_exc

        # Capture du contexte (1 appel chacun, pas 2 — évite double lookup
        # ContextVar sur le hot path log).
        caller_name = current_caller() or "<none>"
        user_id = current_user_id()
        user_label = str(user_id) if user_id is not None else "<none>"

        # Garde-fou tool_use FAIL-CLOSED : si tools demandés et modèle
        # local ne déclare PAS True explicit pour tool_use → refuse.
        if method_name == "generate_with_tools":
            tools_arg = args[1] if len(args) >= 2 else kwargs.get("tools")
            if tools_arg:
                if not local_fb_model:
                    logger.warning(
                        "[AUDIT] LLM fallback REFUSÉ : aucun modèle local configuré "
                        "(``local_llm_model`` vide) — impossible de garantir le support "
                        "tool_use. Re-raise erreur primary. caller=%s user=%s primary_exc=%s",
                        caller_name,
                        user_label,
                        type(primary_exc).__name__,
                    )
                    raise primary_exc
                supports_tools = supports_capability_for_model(local_fb_model, "supports_tool_use")
                if supports_tools is not True:
                    logger.warning(
                        "[AUDIT] LLM fallback REFUSÉ : modèle local %s ne déclare "
                        "PAS supports_tool_use=True dans le registre BDD (valeur=%r). "
                        "Re-raise erreur primary pour éviter résultats faux silencieux. "
                        "caller=%s user=%s primary_exc=%s",
                        local_fb_model,
                        supports_tools,
                        caller_name,
                        user_label,
                        type(primary_exc).__name__,
                    )
                    raise primary_exc

        request = args[0] if args else kwargs.get("request")
        if request is not None and local_fb_model:
            request.model = local_fb_model
        logger.warning(
            "[AUDIT] LLM fallback engagé : primary indisponible (%s) → local=%s "
            "model=%s caller=%s user=%s",
            type(primary_exc).__name__,
            local_fb.provider_name,
            local_fb_model or "<auto>",
            caller_name,
            user_label,
        )
        token = _in_local_fallback.set(True)
        try:
            return await local_method(*args, **kwargs)
        except Exception as local_exc:  # noqa: BLE001
            logger.error(
                "LLM local fallback a aussi échoué : %s. Re-raise erreur primary.",
                local_exc,
            )
            raise primary_exc
        finally:
            _in_local_fallback.reset(token)

    async def generate(
        self,
        request: LLMRequest,
        provider_name: Optional[str] = None,
        fallback_policy: Optional[str] = None,
    ) -> LLMResponse:
        """Génère avec le provider spécifié ou le défaut.

        **Fallback local** : si le primary lève rate limit / réseau / 5xx
        ET qu'un LLM local est enregistré (``register_local_fallback``),
        on retente sur le local pour préserver la continuité de service.

        ``fallback_policy`` (string, None = comportement par défaut
        "graceful") :
        - ``"none"`` : désactive le fallback Ollama. Re-raise direct
          l'exception primary. Utilisé pour les callers critiques où une
          donnée fausse silencieuse serait pire qu'une indisponibilité
          (Iris, copilot SQL — chiffres sacrés Komptia). Cf. P1 #14.
        - ``"graceful"`` (défaut) : tente le fallback si capabilities
          matchent (garde-fou tool_use de P0 #1) ET erreur eligible.

        **Tracking unifié** : chaque appel logue automatiquement une ligne
        dans ``AIPerformanceLog`` via ``llm_call_tracker``. Cf. CLAUDE.md
        section "Architecture LLM dynamique" — toute la consommation API
        passe par ici, donc le dashboard reflète la facture réelle.
        """
        from app.services.ai.llm_call_tracker import record_llm_call_async

        provider = self.get_provider(provider_name)
        if not request.model and self._default_model:
            request.model = self._default_model
        # **Garde anti double-trip local→local** (fix 2026-05-22 +
        # review adversariale findings B1/B2) : si le caller a
        # explicitement demandé le LLM local (``ModelKind.LOCAL`` →
        # provider résolu = self._local_fallback), un échec de ce
        # provider ne doit PAS engager ``_try_local_fallback_or_reraise``
        # qui retape le MÊME provider local. Sans cette garde, le log
        # AUDIT « primary indisponible → local » devenait trompeur (la
        # "primary" était en fait le local) et on payait ~7 s de retries
        # internes inutiles.
        #
        # **Triple check** pour robustesse au swap admin atomique :
        # 1. flag ``_is_local_kind`` posé par :meth:`register_local_fallback`
        #    (résilient au swap — chaque instance garde son marqueur)
        # 2. snapshot ``local_fb_snapshot`` du local_fallback courant
        # 3. identity ``provider is local_fb_snapshot`` (back-compat avec
        #    les providers sans flag — futurs callers custom)
        # Le flag prime sur l'identity car il survit au cycle de vie de
        # ``_local_fallback`` (un ancien local remplacé garde son flag,
        # donc un retry sur lui-même n'engagera pas le fallback Ollama
        # courant — comportement défensif voulu).
        local_fb_snapshot = self._local_fallback
        # ``is True`` (pas ``bool()``) — un ``MagicMock`` ou objet exotique
        # retournerait truthy via ``getattr`` même sans flag set ; on veut
        # uniquement le bool ``True`` posé explicitement par
        # :meth:`register_local_fallback`.
        _is_already_local = getattr(provider, "_is_local_kind", False) is True or (
            local_fb_snapshot is not None and provider is local_fb_snapshot
        )
        start_ts = time.time()
        try:
            response = await provider.generate(request)
        except Exception as exc:
            # FallbackPolicy.NONE OU déjà sur le local → fail-fast direct
            # (pas de tentative Ollama qui retaperait le même provider).
            if fallback_policy == "none" or _is_already_local:
                await record_llm_call_async(
                    request=request,
                    response=None,
                    provider_name=provider.provider_name,
                    duration_seconds=time.time() - start_ts,
                    error=exc,
                )
                raise
            if self._is_fallback_eligible_error(exc):
                # Le fallback retente — on logue le succès du fallback OU
                # la nouvelle exception qu'il lève. Pas de double logging
                # de l'erreur primaire (elle est interne au fallback).
                try:
                    fallback_resp = await self._try_local_fallback_or_reraise(
                        "generate", exc, request
                    )
                except Exception as fexc:
                    await record_llm_call_async(
                        request=request,
                        response=None,
                        provider_name=provider.provider_name,
                        duration_seconds=time.time() - start_ts,
                        error=fexc,
                    )
                    raise
                await record_llm_call_async(
                    request=request,
                    response=fallback_resp,
                    provider_name=getattr(fallback_resp, "provider", provider.provider_name),
                    duration_seconds=time.time() - start_ts,
                )
                return fallback_resp
            await record_llm_call_async(
                request=request,
                response=None,
                provider_name=provider.provider_name,
                duration_seconds=time.time() - start_ts,
                error=exc,
            )
            raise
        await record_llm_call_async(
            request=request,
            response=response,
            provider_name=getattr(response, "provider", provider.provider_name),
            duration_seconds=time.time() - start_ts,
        )
        return response

    async def generate_with_tools(
        self,
        request: LLMRequest,
        tools: list[dict],
        messages: list[dict],
        provider_name: Optional[str] = None,
        thinking_budget: int = 0,
        user_id: Optional[int] = None,
        fallback_policy: Optional[str] = None,
    ) -> dict:
        """
        Délègue au provider résolu (Anthropic, OpenAI, ou tout provider compatible).

        Args:
            thinking_budget: Si > 0, active extended thinking (Anthropic uniquement).
            user_id: Identifiant user pour la couche pseudonymizer
                user-scoped (§…§). Tout caller servant un utilisateur final
                doit le passer — sans, seule la couche PII regex protège
                (les termes manuels DUPONT/codes métier passent en cleartext).
            fallback_policy: ``"none"`` désactive le fallback Ollama
                (fail-fast, chiffres sacrés). ``None`` ou ``"graceful"`` =
                comportement historique (garde-fou tool_use + eligible_error).
                Cf. P1 #14.

        Lève ValueError si le provider ne supporte pas generate_with_tools.

        **Tracking unifié** — cf. ``generate`` ci-dessus.
        """
        from app.services.ai.llm_call_tracker import record_llm_call_async

        provider = self.get_provider(provider_name)
        if not hasattr(provider, "generate_with_tools"):
            raise ValueError(
                f"Le provider {provider.provider_name!r} ne supporte pas generate_with_tools"
            )
        if not request.model and self._default_model:
            request.model = self._default_model
        # **Garde anti double-trip local→local** (fix 2026-05-22 +
        # review adversariale findings B1/B2) — cf. ``generate``
        # ci-dessus pour la rationale détaillée. Triple check :
        # flag _is_local_kind ∨ identity sur snapshot atomique.
        local_fb_snapshot = self._local_fallback
        # ``is True`` (pas ``bool()``) — un ``MagicMock`` ou objet exotique
        # retournerait truthy via ``getattr`` même sans flag set ; on veut
        # uniquement le bool ``True`` posé explicitement par
        # :meth:`register_local_fallback`.
        _is_already_local = getattr(provider, "_is_local_kind", False) is True or (
            local_fb_snapshot is not None and provider is local_fb_snapshot
        )
        start_ts = time.time()
        try:
            result = await provider.generate_with_tools(
                request,
                tools,
                messages,
                thinking_budget=thinking_budget,
                user_id=user_id,
            )
        except Exception as exc:
            # FallbackPolicy.NONE OU déjà sur le local : fail-fast (chiffres
            # sacrés, doctrine Komptia "Iris ne génère JAMAIS de SQL à
            # l'aveugle"). Cf. P1 #14 + fix double-trip 2026-05-22.
            if fallback_policy == "none" or _is_already_local:
                await record_llm_call_async(
                    request=request,
                    response=None,
                    provider_name=provider.provider_name,
                    duration_seconds=time.time() - start_ts,
                    error=exc,
                )
                raise
            if self._is_fallback_eligible_error(exc):
                try:
                    fallback_result = await self._try_local_fallback_or_reraise(
                        "generate_with_tools",
                        exc,
                        request,
                        tools,
                        messages,
                        thinking_budget=thinking_budget,
                        user_id=user_id,
                    )
                except Exception as fexc:
                    await record_llm_call_async(
                        request=request,
                        response=None,
                        provider_name=provider.provider_name,
                        duration_seconds=time.time() - start_ts,
                        error=fexc,
                    )
                    raise
                # Tracking : refléter le provider RÉEL qui a servi (le
                # fallback local), pas le primary qui a échoué. Aligne le
                # comportement sur la branche fallback de ``self.generate``
                # ci-dessus — sans ça, le dashboard ``/admin/ai-config``
                # montre des calls "anthropic" qui sont en fait sur Ollama,
                # et la métrique "fallback déclenché N fois" est faussée.
                # Capture ref locale (self._local_fallback peut swap entre
                # le call et le tracking en cas de désactivation admin).
                local_fb_for_tracking = self._local_fallback
                await record_llm_call_async(
                    request=request,
                    response=fallback_result,
                    provider_name=(
                        local_fb_for_tracking.provider_name
                        if local_fb_for_tracking is not None
                        else provider.provider_name
                    ),
                    duration_seconds=time.time() - start_ts,
                )
                return fallback_result
            await record_llm_call_async(
                request=request,
                response=None,
                provider_name=provider.provider_name,
                duration_seconds=time.time() - start_ts,
                error=exc,
            )
            raise
        await record_llm_call_async(
            request=request,
            response=result,
            provider_name=provider.provider_name,
            duration_seconds=time.time() - start_ts,
        )
        return result

    async def stream_with_tools(
        self,
        request: LLMRequest,
        tools: list[dict],
        messages: list[dict],
        provider_name: Optional[str] = None,
        thinking_budget: int = 0,
        user_id: Optional[int] = None,
        fallback_policy: Optional[str] = None,
    ) -> AsyncGenerator[dict, None]:
        """Délègue au provider résolu pour le streaming avec tools.

        Args:
            user_id: Identifiant user pour la couche pseudonymizer
                user-scoped (§…§). Tout caller servant un utilisateur final
                doit le passer.
            fallback_policy: ``"none"`` désactive le fallback Ollama
                sur les erreurs streaming. ``None`` ou ``"graceful"`` =
                comportement actuel (PAS de fallback wiré sur stream
                aujourd'hui, mais le param est accepté pour cohérence
                avec ``generate``/``generate_with_tools`` et pour
                préparer P1 #15 enrichissement futur). Cf. P1 #14 — le
                vrai bénéfice maintenant est que la doctrine "NONE"
                est portée jusqu'au stream pour les callers critiques
                qui passeront par generate_with_tools fallback (via
                ``self.generate_with_tools(fallback_policy="none")``).
                Cf. aussi commentaire sur ``except Exception`` plus bas.

        **Tracking unifié** : les events SSE sont interceptés au passage
        par ``StreamAccountingWrapper``, qui aggrège les tokens (input
        au ``message_start``, output cumulatif au ``message_delta``) et
        flush en BDD à la sortie du stream — y compris en cas
        d'exception ou d'annulation par le caller (``CancelledError``).

        **Dégradation gracieuse** (plan dynamicité 2026-05-14) : si le
        modèle cible déclare ``supports_streaming=False`` dans le registre
        ``LlmModel``, on appelle ``generate_with_tools`` (non-stream) et
        on émet une séquence d'events Anthropic-format avec UN seul cycle
        ``message_start → content_block_* → message_delta → message_stop``.
        Le caller (StreamAccountingWrapper, Iris) reçoit du contenu valide
        sans modification — juste sans flux progressif. Aucune fabrication
        de feature : on utilise uniquement ce que le modèle propose
        (``generate_with_tools``).
        """
        from app.services.ai.llm_call_tracker import StreamAccountingWrapper

        provider = self.get_provider(provider_name)
        if not hasattr(provider, "stream_with_tools"):
            raise ValueError(
                f"Le provider {provider.provider_name!r} ne supporte pas stream_with_tools"
            )
        if not request.model and self._default_model:
            request.model = self._default_model

        # Lecture registre : streaming activable pour ce call ?
        # Le primary ET le fallback enregistré (si présent) doivent supporter
        # le streaming. Si l'un des deux déclare ``supports_streaming=False``
        # explicit dans le registre BDD, on dégrade préventivement en
        # ``_simulate_stream_from_non_stream`` (mode non-stream avec events
        # Anthropic-format simulés). Raison : la branche dégradée passe par
        # ``manager.generate_with_tools`` qui wire le fallback Ollama — sans
        # dégradation préventive, un crash primary en plein stream laisserait
        # l'utilisateur sans réponse (le stream du provider Anthropic n'a
        # pas de retry vers Ollama wiré, cf. dette historique P1 #15).
        #
        # ``None`` du registre = pas d'avis explicite → on assume True (défaut
        # ``LlmModel.supports_streaming``). Seul ``False`` explicite déclenche
        # la dégradation. "Jusqu'à rétablissement" : le check est ré-évalué à
        # chaque call ; dès que l'admin met ``supports_streaming=True`` sur le
        # modèle fautif dans ``/admin/ai-models``, le prochain call repart
        # en vrai stream sans redéploiement.
        primary_model = request.model or ""
        # Capture atomique (review adversariale 2026-05-20) : éviter
        # qu'un swap admin entre les 2 lectures laisse fallback_model
        # référencer un modèle dont le provider a été close().
        local_fb_snapshot = self._local_fallback
        fallback_model = self._local_fallback_model if local_fb_snapshot is not None else None
        skip_reason = _stream_degradation_reason(
            primary_model,
            fallback_model,
            tools_present=bool(tools),
        )
        if skip_reason is not None:
            logger.info(
                "stream_with_tools: dégradation streaming — %s. Bascule vers "
                "generate_with_tools (events Anthropic-format simulés + fallback "
                "Ollama wiré). Admin peut rétablir via /admin/ai-models en "
                "passant supports_streaming=True sur le modèle fautif.",
                skip_reason,
            )
            # Pas de StreamAccountingWrapper sur la branche dégradée :
            # ``_simulate_stream_from_non_stream`` passe maintenant par
            # ``self.generate_with_tools`` (manager), qui enregistre déjà
            # l'appel via ``record_llm_call_async``. Wrap = double-record.
            try:
                async for event in self._simulate_stream_from_non_stream(
                    request,
                    tools,
                    messages,
                    provider_name=provider_name,
                    thinking_budget=thinking_budget,
                    user_id=user_id,
                ):
                    yield event
            except asyncio.CancelledError:
                raise
            except (httpx.CloseError, RuntimeError) as exc:
                # Symétrie avec le path streaming normal (MAJ10 review
                # adversariale 2026-05-14) : si l'admin clear pendant
                # la dégradation aussi, émet un event propre au lieu
                # d'une 500.
                if not self._is_provider_client_closed(provider):
                    raise
                logger.warning(
                    "stream_with_tools (dégradé) interrompu (%s) — "
                    "émission provider_reset_during_stream propre.",
                    type(exc).__name__,
                )
                yield {
                    "type": "error",
                    "error": {
                        "type": "provider_reset_during_stream",
                        "message": (
                            "La configuration du provider a été "
                            "modifiée pendant que la réponse était "
                            "générée. Réessayez votre demande."
                        ),
                    },
                }
            return

        wrapper = StreamAccountingWrapper(
            provider_name=provider.provider_name,
            request=request,
        )
        # M5 / dette P1#15 (2026-06-10) — fallback Ollama sur le chemin
        # STREAMING, promesse CLAUDE.md « fallback runtime quand le primary
        # cloud est indisponible ». Frontière de sécurité : le fallback ne
        # s'engage QUE si l'échec survient AVANT le premier event yielé —
        # après, des deltas sont déjà partis au client et re-streamer depuis
        # le local dupliquerait le contenu (on propage alors, comme avant).
        # Mécanique : on délègue à ``_simulate_stream_from_non_stream`` qui
        # passe par ``self.generate_with_tools`` (manager) — lequel wire DÉJÀ
        # le fallback ``_try_local_fallback_or_reraise`` + accounting. Le
        # primary y est retenté une fois (un 429/réseau transitoire peut se
        # résorber sans Ollama) avant la bascule locale.
        _stream_fallback_exc: Optional[BaseException] = None
        _yielded_any = False
        try:
            async with wrapper:
                try:
                    async for event in provider.stream_with_tools(
                        request,
                        tools,
                        messages,
                        thinking_budget=thinking_budget,
                        user_id=user_id,
                    ):
                        wrapper.observe(event)
                        _yielded_any = True
                        yield event
                except asyncio.CancelledError:
                    # Cancel légitime (WebSocket fermé, user a quitté l'onglet).
                    # Pas une erreur — laisser le wrapper flush et re-raise pour
                    # signaler propre à la couche caller (qui gère via finally).
                    raise
                except (httpx.CloseError, RuntimeError) as exc:
                    # Crash provoqué par un ``_reinit_after_config_change``
                    # exécuté pendant que le stream tournait (admin a cliqué
                    # "Effacer la connexion" ou switch modèle). L'``AsyncClient``
                    # httpx en cours d'utilisation a été fermé sous nos pieds.
                    # Plutôt que de remonter une exception opaque qui ferait
                    # crasher la WebSocket Iris avec une 500, on émet un event
                    # d'erreur explicite. Cf. review adversariale 2026-05-14
                    # CRIT2 : on ne se fie PAS au message string (fragile aux
                    # changements Python/httpx) mais à l'état réel du client
                    # via ``_is_provider_client_closed`` (helper avec fallback
                    # safe). Si le client n'est PAS fermé, c'est un vrai bug
                    # → on re-raise pour ne pas masquer.
                    if not self._is_provider_client_closed(provider):
                        # Revue adv. 2026-06-10 (CRITIQUE) : un RuntimeError
                        # « max retries exceeded » est ÉLIGIBLE au fallback
                        # (cas P4#26, rate-limit post-retries) mais cette
                        # branche l'intercepte AVANT le ``except Exception``
                        # du fallback — sans ce bloc, le fix ratait
                        # précisément sa cible principale.
                        if (
                            not _yielded_any
                            and fallback_policy != "none"
                            and self._local_fallback is not None
                            and self._is_fallback_eligible_error(exc)
                        ):
                            _stream_fallback_exc = exc
                        raise
                    logger.warning(
                        "stream_with_tools interrompu (%s) alors que le client "
                        "httpx est fermé — émission d'un event provider_reset "
                        "propre au caller (au lieu d'une 500 opaque).",
                        type(exc).__name__,
                    )
                    # Format aligné avec la convention agent_service.run() :
                    # ``{"type": "error", "message": "..."}`` — le client iris.js
                    # (case 'error' à iris.js:3194) lit ``event.message`` direct.
                    # ``error_kind`` séparé pour traçabilité / dashboard sans
                    # casser la convention.
                    yield {
                        "type": "error",
                        "message": (
                            "La configuration du provider a été modifiée "
                            "pendant que la réponse était générée. Réessayez "
                            "votre demande."
                        ),
                        "error_kind": "provider_reset_during_stream",
                    }
                except Exception as exc:
                    if (
                        not _yielded_any
                        and fallback_policy != "none"
                        and self._local_fallback is not None
                        and self._is_fallback_eligible_error(exc)
                    ):
                        # Mémorise puis RE-RAISE : le wrapper (__aexit__ avec
                        # exception) enregistre l'échec du PRIMARY — métrique
                        # fidèle. Le try externe absorbe et lance le fallback.
                        _stream_fallback_exc = exc
                    raise
        except BaseException as outer_exc:
            # Revue adv. 2026-06-10 (Moyen) : test d'IDENTITÉ, pas seulement
            # de présence — ``wrapper.__aexit__`` fait un ``await flush()``
            # (écriture BDD) qui peut lever/être annulé et REMPLACER
            # l'exception du corps. Sans ce check, une CancelledError du
            # flush serait absorbée (fallback parasite alors que le caller
            # a annulé) et la cause réelle masquée.
            if _stream_fallback_exc is None or outer_exc is not _stream_fallback_exc:
                raise
            # Échec primary éligible avant le 1er event : absorbé — le flux
            # simulé (avec fallback Ollama wiré) prend le relais ci-dessous.
        if _stream_fallback_exc is not None:
            logger.warning(
                "stream_with_tools: primary KO avant le 1er event (%s: %s) — "
                "bascule vers le flux simulé generate_with_tools (fallback "
                "local wiré).",
                type(_stream_fallback_exc).__name__,
                _stream_fallback_exc,
            )
            async for event in self._simulate_stream_from_non_stream(
                request,
                tools,
                messages,
                provider_name=provider_name,
                thinking_budget=thinking_budget,
                user_id=user_id,
            ):
                yield event

    @staticmethod
    def _is_provider_client_closed(provider: Any) -> bool:
        """Détecte si le client HTTP interne du provider est fermé.

        Pattern stable : on vérifie l'attribut ``_client.is_closed`` sur
        les providers httpx-based (Anthropic, OpenAI). Si l'attribut
        n'existe pas (provider custom, mock), retourne ``False`` (= ne
        masque pas le bug, on re-raise l'exception originale). Cf. review
        adversariale 2026-05-14 — remplacement de l'heuristique string
        ``"closed" in msg.lower()`` qui était fragile aux changements de
        message d'erreur Python/httpx.
        """
        try:
            client = getattr(provider, "_client", None)
            if client is None:
                return False
            return bool(getattr(client, "is_closed", False))
        except Exception:  # noqa: BLE001 — fail-safe
            return False

    async def _simulate_stream_from_non_stream(
        self,
        request: LLMRequest,
        tools: list[dict],
        messages: list[dict],
        *,
        provider_name: Optional[str] = None,
        thinking_budget: int = 0,
        user_id: Optional[int] = None,
    ) -> AsyncGenerator[dict, None]:
        """Construit un faux stream Anthropic-format depuis une réponse
        non-streamée. Utilisé par ``stream_with_tools`` quand le modèle
        cible déclare ``supports_streaming=False``.

        Émet exactement la séquence d'events qu'un caller attend :

        - ``message_start`` (avec usage input + cache_read + cache_creation)
        - pour chaque block content : ``content_block_start`` →
          ``content_block_delta`` (texte d'un coup OU tool_use d'un coup) →
          ``content_block_stop``
        - ``message_delta`` (avec stop_reason + usage output_tokens)
        - ``message_stop``

        **Tracking unifié + fallback wiré** : passe par
        ``self.generate_with_tools`` (manager, pas ``provider.generate_with_tools``
        raw). Ce changement (2026-05-20) active le fallback Ollama runtime sur
        la branche dégradée : si le primary cloud lève une erreur transitoire,
        ``_try_local_fallback_or_reraise`` bascule sur le LLM local sans que
        le caller ne s'en aperçoive (la séquence d'events Anthropic-format
        reste identique). Sans ce wiring, dégrader pour ``supports_streaming
        =False`` ne servirait à rien si le but est la continuité de service.

        Conséquence tracking : ``manager.generate_with_tools`` fait déjà son
        ``record_llm_call_async``. Le caller ``stream_with_tools`` n'enroule
        donc PAS de ``StreamAccountingWrapper`` autour de cette simulation —
        sinon double enregistrement BDD.

        ``fallback_policy="graceful"`` : le fallback Ollama est autorisé sur
        cette branche dégradée (l'utilisateur préfère un résultat dégradé à
        une indisponibilité, cohérent avec la doctrine retenue 2026-05-20).

        Pas de fabrication : la réponse vient réellement du provider (ou du
        fallback local en cas de bascule). La simulation ne fait que
        re-découper la réponse en séquence d'events SSE Anthropic-format.
        """
        if not request.model and self._default_model:
            request.model = self._default_model
        response = await self.generate_with_tools(
            request,
            tools,
            messages,
            provider_name=provider_name,
            thinking_budget=thinking_budget,
            user_id=user_id,
            fallback_policy="graceful",
        )
        usage = response.get("usage", {}) or {}
        input_tokens = int(usage.get("input_tokens", 0) or 0)
        output_tokens = int(usage.get("output_tokens", 0) or 0)
        # Cache tokens spécifiques Anthropic — propagés pour que le tracking
        # côté caller reflète la vraie facture (cf. review adversariale
        # finding MINEUR 9, 2026-05-14).
        cache_read_tokens = int(usage.get("cache_read_input_tokens", 0) or 0)
        cache_creation_tokens = int(usage.get("cache_creation_input_tokens", 0) or 0)
        stop_reason = response.get("stop_reason", "end_turn")
        content_blocks = response.get("content", []) or []

        # 1. message_start
        message_usage: dict = {"input_tokens": input_tokens, "output_tokens": 0}
        if cache_read_tokens:
            message_usage["cache_read_input_tokens"] = cache_read_tokens
        if cache_creation_tokens:
            message_usage["cache_creation_input_tokens"] = cache_creation_tokens
        yield {
            "type": "message_start",
            "message": {"usage": message_usage},
        }

        # 2. Chaque block content en 3 events
        for idx, block in enumerate(content_blocks):
            block_type = block.get("type", "text")
            if block_type == "text":
                yield {
                    "type": "content_block_start",
                    "index": idx,
                    "content_block": {"type": "text", "text": ""},
                }
                yield {
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": {"type": "text_delta", "text": block.get("text", "")},
                }
                yield {"type": "content_block_stop", "index": idx}
            elif block_type == "tool_use":
                yield {
                    "type": "content_block_start",
                    "index": idx,
                    "content_block": {
                        "type": "tool_use",
                        "id": block.get("id", ""),
                        "name": block.get("name", ""),
                        "input": {},
                    },
                }
                # Emit le JSON input en un seul delta pour ne pas avoir à
                # reconstituer un parsing partiel (qui poserait des soucis
                # avec le bug LiteLLM-like index=0 sur les autres providers).
                # ``ensure_ascii=False`` préserve les accents UTF-8 ; ``or {}``
                # évite ``json.dumps(None) == "null"`` qui ferait JSON.parse
                # → null → tool_use crash côté caller.
                yield {
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": {
                        "type": "input_json_delta",
                        "partial_json": json.dumps(block.get("input") or {}, ensure_ascii=False),
                    },
                }
                yield {"type": "content_block_stop", "index": idx}
            elif block_type == "thinking":
                # Modèle qui ne stream pas mais qui aurait extended thinking ?
                # Cas hypothétique mais on préserve le block pour le caller.
                yield {
                    "type": "content_block_start",
                    "index": idx,
                    "content_block": {"type": "thinking", "thinking": ""},
                }
                yield {
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": {
                        "type": "thinking_delta",
                        "thinking": block.get("thinking", ""),
                    },
                }
                yield {"type": "content_block_stop", "index": idx}

        # 3. message_delta (stop_reason + usage output)
        yield {
            "type": "message_delta",
            "delta": {"stop_reason": stop_reason},
            "usage": {"output_tokens": output_tokens},
        }

        # 4. message_stop
        yield {"type": "message_stop"}

    async def list_all_models(self) -> Dict[str, List[Dict[str, Any]]]:
        """Liste tous les modèles de tous les providers."""
        all_models = {}
        for name, provider in self._providers.items():
            try:
                models = await provider.list_models()
                all_models[name] = models
            except (ConnectionError, asyncio.TimeoutError, OSError, httpx.ConnectError) as e:
                # Reachability transitoire (cf. note OpenAIProvider.list_models) :
                # WARNING, pas ERROR — un provider down ne casse pas l'admin.
                logger.warning(
                    "Provider %s injoignable au listing des modèles (%s) — " "fallback liste vide",
                    name,
                    type(e).__name__,
                )
                all_models[name] = []
        return all_models

    async def list_models_for_provider(self, provider_name: str) -> List[Dict[str, Any]]:
        """Liste les modèles disponibles pour un provider spécifique."""
        if provider_name not in self._providers:
            logger.warning("Provider non trouvé: %s", provider_name)
            return []

        provider = self._providers[provider_name]
        try:
            return await provider.list_models()
        except (ConnectionError, asyncio.TimeoutError, OSError, httpx.ConnectError) as e:
            # Reachability transitoire (cf. note OpenAIProvider.list_models) :
            # WARNING, pas ERROR — un provider down ne casse pas l'admin.
            logger.warning(
                "Provider %s injoignable au listing des modèles (%s) — " "fallback liste vide",
                provider_name,
                type(e).__name__,
            )
            return []

    async def health_check_all(self, force_refresh: bool = False) -> Dict[str, bool]:
        """Vérifie la santé de tous les providers (cache TTL 5 min).

        ``force_refresh=True`` bypasse le cache — utilisé par le dashboard
        quand l'admin clique sur "Tester maintenant" pour obtenir un état
        frais sans attendre l'expiration du TTL.
        """
        now = time.time()
        cache_age = now - self._health_cache_time
        if (
            not force_refresh
            and self._health_cache is not None
            and cache_age < self.HEALTH_CACHE_TTL
        ):
            return self._health_cache

        results = {}
        for name, provider in self._providers.items():
            try:
                results[name] = await provider.health_check()
            except (ConnectionError, asyncio.TimeoutError, OSError, httpx.ConnectError):
                results[name] = False

        # LLM local fallback : stocké hors ``_providers`` (séparé pour que
        # le seed/registry primary ne le voie pas). Sans cette branche,
        # le dashboard ``/admin/ai-config`` n'affiche pas l'état Ollama
        # → l'admin pense être protégé alors qu'Ollama peut être down
        # depuis 3 jours. Clé ``"<name>_fallback"`` pour distinguer du
        # primary (cas pathologique : primary nommé ``"local"``).
        # Capture ref locale pour éviter race avec swap concurrent.
        local_fb = self._local_fallback
        if local_fb is not None:
            local_key = f"{local_fb.provider_name}_fallback"
            try:
                results[local_key] = await local_fb.health_check()
            except (ConnectionError, asyncio.TimeoutError, OSError, httpx.ConnectError):
                results[local_key] = False
            except Exception as exc:  # noqa: BLE001 — ne JAMAIS bloquer le dashboard
                logger.warning(
                    "Health check LLM local fallback a échoué (non-réseau) : %s",
                    exc,
                )
                results[local_key] = False

        self._health_cache = results
        self._health_cache_time = now
        return results

    def invalidate_health_cache(self) -> None:
        """Force un ping frais au prochain appel à ``health_check_all``.

        Appelé par le bouton "Tester maintenant" du dashboard providers.
        """
        self._health_cache = None
        self._health_cache_time = 0.0

    def get_health_cache_age_seconds(self) -> Optional[float]:
        """Age du dernier health check en cache (``None`` si jamais rempli)."""
        if self._health_cache is None or self._health_cache_time <= 0:
            return None
        return max(0.0, time.time() - self._health_cache_time)

    async def close_all(self):
        """Ferme tous les providers."""
        for provider in self._providers.values():
            await provider.close()

    @property
    def available_providers(self) -> List[str]:
        return list(self._providers.keys())


# Singleton
_llm_manager: Optional[LLMManager] = None
_providers_initialized_from_db = False

# Contexte d'appel — flippé à True par ``_try_local_fallback_or_reraise``
# avant de router vers le LLM local. Permet aux helpers de résolution
# (max_retries, temperature) de choisir entre les defaults cloud et local
# sans threader un flag explicit dans toutes les signatures providers.
import contextvars as _ctxvars  # noqa: E402

_in_local_fallback: _ctxvars.ContextVar[bool] = _ctxvars.ContextVar(
    "_in_local_fallback", default=False
)


def _resolve_max_retries() -> int:
    """Source unique : admin config (cloud OU local selon contexte) avec
    fallback static. Local prend le pas via ``_in_local_fallback`` quand
    le manager route vers le LLM local fallback."""
    m = _llm_manager
    if m is not None:
        if _in_local_fallback.get() and m.local_default_max_retries is not None:
            return m.local_default_max_retries
        if m.default_max_retries is not None:
            return m.default_max_retries
    return DEFAULT_MAX_RETRIES


def _resolve_default_temperature() -> float:
    """Idem pour ``temperature``. Local override via ``_in_local_fallback``."""
    m = _llm_manager
    if m is not None:
        if _in_local_fallback.get() and m.local_default_temperature is not None:
            return m.local_default_temperature
        if m.default_temperature is not None:
            return m.default_temperature
    return DEFAULT_TEMPERATURE


def _temperature_for_request(request: "LLMRequest") -> float:
    """Source unique : temperature explicite du caller > admin config > default
    static. Permet aux call sites qui veulent un control fin (e.g. analyse
    déterministe à 0.0) de garder l'override, tout en laissant les call sites
    "neutres" (Iris/Agent) suivre le réglage admin global.
    """
    if request.temperature is not None:
        return request.temperature
    return _resolve_default_temperature()


_providers_init_lock = asyncio.Lock()


def get_llm_manager() -> LLMManager:
    """Récupère ou crée le LLMManager singleton."""
    global _llm_manager
    if _llm_manager is None:
        _llm_manager = LLMManager()
        _init_default_providers(_llm_manager)
    return _llm_manager


async def _load_local_fallback_from_config(manager: "LLMManager", config_service) -> None:
    """Lit ``local_llm_*`` depuis la config et register le fallback.

    Atomic swap (review CRITICAL #6) : on construit le nouveau provider
    AVANT de toucher l'ancien. Si la construction lève (URL invalide,
    httpx OOM, etc.), l'ancien fallback reste actif → pas d'état
    incohérent où l'admin pense avoir activé mais le manager dit None.

    Pattern partagé entre ``ensure_providers_from_db`` (boot 1ère fois)
    et ``reinit_providers_from_config`` (save admin).
    """
    try:
        local_enabled = bool(await config_service.get("local_llm_enabled"))
    except Exception:  # noqa: BLE001
        local_enabled = False

    if not local_enabled:
        # Désactivé : si on avait un fallback, le retirer atomiquement
        if manager._local_fallback is not None:
            old = manager._local_fallback
            manager._local_fallback = None
            manager._local_fallback_model = None
            # Invalider le cache health_check : sans ça le dashboard
            # montre "local_fallback: True" pendant 5 min après que
            # l'admin a désactivé Ollama (review adversariale 2026-05-15).
            manager.invalidate_health_cache()
            try:
                await old.close()
            except Exception:  # noqa: BLE001
                pass
        return

    try:
        from app.services.ai.config_service import default_local_llm_base_url

        local_url = (await config_service.get("local_llm_base_url")) or default_local_llm_base_url()
        local_model = await config_service.get("local_llm_model") or ""
        # Validation SSRF (review HIGH #1) : refuser les schemes/hosts
        # qui exposent un service interne (metadata cloud, file://, etc.)
        if not _is_safe_local_llm_url(local_url):
            logger.warning(
                "LLM local : URL refusée pour raison sécurité (%s). "
                "Schémas autorisés : http/https. Hosts metadata "
                "(169.254.169.254, metadata.google.internal, "
                "metadata.azure.com) bloqués.",
                local_url,
            )
            return
        # Garde request-time (anti DNS-rebinding) : même contrôle que les probes
        # /status et /detect — résout l'hôte et refuse si une IP résolue est
        # metadata/link-local (privé/LAN reste autorisé). Symétrie : sans ça, le
        # chemin runtime (répété, non surveillé) serait MOINS protégé que le
        # simple test admin. getaddrinfo bloquant → to_thread.
        import asyncio as _asyncio

        _runtime_safe, _ = await _asyncio.to_thread(_assert_resolved_ip_safe, local_url)
        if not _runtime_safe:
            logger.warning(
                "LLM local : URL refusée (anti-rebinding) — résout vers une IP "
                "metadata/link-local interdite (%s). Fallback non enregistré.",
                local_url,
            )
            return
        # Timeout par modèle (admin-éditable). Cold start CPU peut dépasser
        # 60s — le défaut OPENAI_TIMEOUT (300s) est OK mais l'admin peut
        # le rabaisser pour fail-fast (Groq) ou le monter (Ollama distant).
        try:
            local_timeout_raw = await config_service.get("local_llm_timeout_seconds")
            local_timeout = float(local_timeout_raw) if local_timeout_raw else float(OPENAI_TIMEOUT)
        except (ValueError, TypeError):
            local_timeout = float(OPENAI_TIMEOUT)
        new_provider = OpenAIProvider(
            api_key="local",
            base_url=local_url,
            timeout=local_timeout,
            name="local",
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Init LLM local échouée : %s — fallback inchangé", exc)
        return

    # Atomic swap : si on avait un old, le close après le swap
    old = manager._local_fallback
    manager.register_local_fallback(new_provider, local_model or None)
    if old is not None and old is not new_provider:
        try:
            await old.close()
        except Exception:  # noqa: BLE001
            pass

    # Auto-sync registre LlmModel depuis Ollama (2026-05-20). Quand l'admin
    # active le LLM local, on probe immédiatement ``/api/show`` pour chaque
    # modèle installé et upsert ``context_window`` + ``max_output_tokens``
    # dans le registre. Sans ça, ``compute_dynamic_batch_size_async`` tombe
    # sur les fallbacks static silencieux de ``get_context_window_for_model``
    # (200k/8k) qui ne reflètent pas les vraies caps du modèle local — ce
    # qui produit des batch_size géants → modèle déraille sur CPU.
    # Background task : non-bloquant pour le boot, log warning si fail.
    try:
        import asyncio as _asyncio
        from app.core.database import get_session

        async def _bg_sync_ollama() -> None:
            try:
                from app.services.ai.litellm_registry_sync import (
                    _enrich_from_ollama,
                )

                async with get_session() as session:
                    stats = await _enrich_from_ollama(session, allow_regression=False)
                    logger.info(
                        "[BOOT] sync Ollama registry: %s",
                        {k: v for k, v in stats.items() if k != "errors"},
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning("[BOOT] sync Ollama registry échec (non bloquant) : %s", exc)

        _asyncio.create_task(_bg_sync_ollama())
    except Exception as exc:  # noqa: BLE001
        logger.warning("[BOOT] impossible de planifier sync Ollama : %s", exc)


def _stream_degradation_reason(
    primary_model: str,
    fallback_model: Optional[str],
    *,
    tools_present: bool = False,
) -> Optional[str]:
    """Détermine s'il faut dégrader le streaming en mode non-stream.

    Politique (décision admin 2026-05-20) : si **le primary OU le fallback**
    enregistré déclare ``supports_streaming=False`` dans le registre BDD,
    on désactive le streaming pour ce call et on passe en mode non-stream
    (events Anthropic-format simulés via ``_simulate_stream_from_non_stream``).
    Le call non-stream sous-jacent passe par ``manager.generate_with_tools``
    qui wire le fallback Ollama → continuité de service préservée.

    Pourquoi vérifier les deux modèles :

    - Si seul le primary est cassé pour le streaming, on doit dégrader (cas
      historique géré depuis review 2026-05-14).
    - Si seul le fallback est cassé pour le streaming, sans dégradation
      préventive, un crash primary en plein stream ne pourrait PAS basculer
      sur le fallback (le stream du provider Anthropic n'a pas de fallback
      wiré côté provider — cf. dette historique P1 #15). En dégradant
      d'emblée, le call non-stream sous-jacent ``manager.generate_with_tools``
      gère le fallback proprement.

    **Garde anti-théâtre** (review adversariale 2026-05-20) : dégrader pour
    cause de fallback non-streamable n'a de sens que si ce même fallback est
    EFFECTIVEMENT utilisable runtime. ``_try_local_fallback_or_reraise`` fait
    un fail-CLOSED sur ``supports_tool_use=True`` dès que des tools sont
    présents (lignes 4296-4318). Si l'admin a configuré un Phi-3 Mini
    sans tool_use et que des tools sont demandés, dégrader le streaming
    serait du théâtre : on perd l'UX progressive sans gagner de continuité
    (le fallback échouera de toute façon). Dans ce cas précis (cause
    `fallback_blocks` + `tools_present` + `supports_tool_use is not True`),
    on retourne ``None`` (pas de dégradation) — l'admin doit voir l'erreur
    cloud directement pour comprendre que son fallback est mal configuré.

    Args:
        primary_model: nom du modèle primary (vide → considéré comme inconnu).
        fallback_model: nom du modèle fallback local enregistré, ou ``None``
            si pas de fallback configuré (alors on ne check que le primary).
        tools_present: ``True`` si le call streamé demande des tools. Active
            la garde anti-théâtre décrite ci-dessus. ``False`` par défaut
            (rétro-compat, mais en pratique tous les callers Komptia
            streaming utilisent tools — Iris, copilot).

    Returns:
        ``None`` si le streaming est OK (les deux modèles supportent ou ne
        sont pas connus du registre — ``None`` = pas d'avis = on assume True).
        Aussi ``None`` si la dégradation serait inutile faute de fallback
        utilisable (cf. garde anti-théâtre).

        Sinon, une chaîne lisible expliquant la raison de la dégradation,
        utilisable directement dans un log INFO admin (ex: ``"modèle primary
        'claude-sonnet-4-6' déclare supports_streaming=False"``).
    """
    primary_supports = supports_capability_for_model(primary_model, "streaming")
    primary_blocks = primary_supports is False
    fallback_supports: Optional[bool] = None
    fallback_blocks = False
    if fallback_model:
        fallback_supports = supports_capability_for_model(fallback_model, "streaming")
        fallback_blocks = fallback_supports is False
    # Garde anti-théâtre : si on dégrade UNIQUEMENT à cause du fallback
    # non-streamable, vérifier que ce fallback est utilisable avec tools.
    # Sinon dégrader = perte UX stream sans gain de continuité.
    if fallback_blocks and not primary_blocks and tools_present and fallback_model:
        fb_tool_use = supports_capability_for_model(fallback_model, "supports_tool_use")
        if fb_tool_use is not True:
            # Pas de dégradation : le fallback échouerait le garde-fou
            # tool_use de _try_local_fallback_or_reraise. L'admin voit
            # l'erreur cloud directement = signal clair pour qu'il aille
            # corriger supports_tool_use dans /admin/ai-models.
            return None
    if primary_blocks and fallback_blocks:
        return (
            f"primary {primary_model!r} ET fallback {fallback_model!r} "
            "déclarent tous deux supports_streaming=False dans le registre BDD"
        )
    if primary_blocks:
        return (
            f"modèle primary {primary_model!r} déclare "
            "supports_streaming=False dans le registre BDD"
        )
    if fallback_blocks:
        return (
            f"modèle fallback {fallback_model!r} déclare "
            "supports_streaming=False dans le registre BDD — dégradation "
            "préventive pour permettre le fallback Ollama wiré sur "
            "generate_with_tools en cas d'échec primary"
        )
    return None


def _is_safe_local_llm_url(url: str) -> bool:
    """LOT 11 — Garde-fou SSRF sur ``LOCAL_LLM_BASE_URL``.

    Refuse les schémas non-HTTP et les hosts qui exposent des services
    internes / metadata cloud (review HIGH #1). L'admin peut utiliser
    n'importe quelle URL HTTP locale ou réseau privé légitime
    (Ollama localhost, LM Studio LAN, TGI cluster interne).

    Check *string* bon-marché (au save). Complété au *request-time* par
    ``_assert_resolved_ip_safe`` (résolution DNS réelle, anti-rebinding) avant
    toute requête serveur — appeler les DEUX sur un chemin qui fetch l'URL.
    """
    if not url or not isinstance(url, str):
        return False
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url.strip())
    except (ValueError, TypeError):
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    # Hosts metadata cloud explicitement bloqués
    blocked_hosts = {
        "169.254.169.254",  # AWS / Azure / GCP IMDS v1
        "100.100.100.200",  # Alibaba Cloud metadata
        "192.0.0.192",  # Oracle OCI metadata
        "metadata.google.internal",
        "metadata.azure.com",
        "[fd00:ec2::254]",  # AWS IMDS IPv6
    }
    if host in blocked_hosts:
        return False
    # IPv6 link-local (fe80::) — exposes interfaces sensibles
    if host.startswith("fe80:") or host.startswith("[fe80:"):
        return False
    return True


# IP littérales de metadata cloud à bloquer même APRÈS résolution DNS
# (anti-rebinding). Les ranges link-local (169.254/16, fe80::/10) qui les
# contiennent sont bloqués via ``ipaddress.is_link_local`` ci-dessous.
_CLOUD_METADATA_IPS = frozenset(
    {
        "169.254.169.254",  # AWS / Azure / GCP IMDS v1
        "100.100.100.200",  # Alibaba Cloud
        "192.0.0.192",  # Oracle OCI
        "fd00:ec2::254",  # AWS IMDS IPv6
    }
)


def _is_blocked_resolved_ip(ip_str: str) -> bool:
    """True si une IP (résolue ou littérale) doit être bloquée.

    Bloque les littéraux metadata multi-cloud + tout le range link-local
    (169.254.0.0/16, fe80::/10) qui les contient. AUTORISE explicitement
    loopback (127/8, ::1) et privé/LAN (10/8, 172.16/12, 192.168/16) —
    c'est le cas d'usage légitime d'un LLM local.
    """
    import ipaddress

    if ip_str in _CLOUD_METADATA_IPS:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # IPv4-mapped IPv6 (``::ffff:169.254.169.254``) : juger sur le v4 embarqué.
    # Sinon ``is_link_local`` vaut False sur la forme mappée et un littéral
    # mappé vers l'IMDS contournerait le garde.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return _is_blocked_resolved_ip(str(mapped))
    return bool(ip.is_link_local)


def _assert_resolved_ip_safe(url: str) -> "tuple[bool, Optional[str]]":
    """Garde SSRF *request-time* (anti DNS-rebinding — OWASP SSRF).

    Résout réellement le hostname et bloque si UNE des IP résolues pointe vers
    un endpoint metadata cloud / link-local. Complète ``_is_safe_local_llm_url``
    (check string au save) : ici on résout juste avant la requête httpx serveur.
    ``getaddrinfo`` est bloquant → l'appeler via ``asyncio.to_thread`` depuis un
    handler async pour ne pas bloquer l'event loop.

    Retour ``(safe, reason)`` :
      - ``(True, None)`` : sûr, OU hôte non résolvable (on laisse la requête
        échouer naturellement en « injoignable » — pas de régression vs le
        check string qui acceptait déjà un hostname interne non résolu).
      - ``(False, reason)`` : schéma/hôte refusé, ou IP résolue bloquée.
    """
    import socket
    from urllib.parse import urlparse

    if not _is_safe_local_llm_url(url):
        return False, "schéma ou hôte refusé (anti-SSRF)"
    host = (urlparse(url.strip()).hostname or "").strip("[]")
    if not host:
        return False, "hôte vide"
    # Hôte déjà une IP littérale → pas de DNS, jugement direct.
    try:
        import ipaddress

        ipaddress.ip_address(host)
        if _is_blocked_resolved_ip(host):
            return False, f"IP metadata/link-local bloquée ({host})"
        return True, None
    except ValueError:
        pass  # hostname → résolution réelle
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return True, None  # non résolvable → échec naturel « injoignable » en aval
    for info in infos:
        ip_str = info[4][0]
        if _is_blocked_resolved_ip(ip_str):
            return False, f"hôte résout vers une IP bloquée ({ip_str})"
    return True, None


def _warn_if_no_primary_model(api_type: str, primary_model: Optional[str]) -> None:
    """Avertit (côté serveur) si un provider est configuré sans modèle primary.

    État anormal — le JS de /admin/ai-config impose un modèle au save — mais
    atteignable via import de config, édition SQL directe, ou clé re-saisie
    sans "Tester". Sans modèle, ``set_default(api_type, "")`` laisse
    ``default_model_name`` vide et le 1er appel LLM sans modèle explicite
    échoue. Le garde-fou n'existait que côté JS : on rend la misconfig
    VISIBLE côté serveur (fail-loud).
    """
    if not primary_model:
        logger.warning(
            "Config IA : provider %r configuré (clé API valide) mais AUCUN "
            "modèle primary (primary_model vide). Les appels LLM sans modèle "
            "explicite échoueront — choisir un modèle via /admin/ai-config "
            "(tester la clé peuple la liste des modèles).",
            api_type,
        )


async def ensure_providers_from_db():
    """
    Charge les providers depuis les clés API stockées en BDD.
    Appelé au premier usage async pour compléter l'init sync.
    """
    global _providers_initialized_from_db
    if _providers_initialized_from_db:
        return

    async with _providers_init_lock:
        # Double-check après acquisition du lock
        if _providers_initialized_from_db:
            return

        manager = get_llm_manager()

        try:
            from app.services.ai.config_service import get_ai_config_service
            from app.constants_ai import detect_api_type

            config_service = get_ai_config_service()

            # Charger le provider depuis api_key + api_base_url
            api_key = await config_service.get("api_key")
            api_type: Optional[str] = None
            if api_key:
                base_url = await config_service.get("api_base_url") or ""
                api_type = detect_api_type(api_key, base_url)
                # Le nom interne du provider = api_type réel (anthropic|openai),
                # jamais une valeur arbitraire qui pourrait être incohérente.
                if api_type == "anthropic":
                    # Propager ``base_url`` au provider Anthropic : Vertex AI
                    # ou proxy custom via admin. Sans ça, le garde-fou
                    # d'éligibilité TTL 1h (``_long_ttl_eligible``) serait
                    # toujours ``True`` (ANTHROPIC_API_URL hardcodé) et un
                    # proxy pourrait recevoir ``ttl:"1h"`` par erreur.
                    provider = AnthropicProvider(
                        api_key=api_key,
                        base_url=base_url or None,
                    )
                else:
                    provider = OpenAIProvider(
                        api_key=api_key,
                        base_url=base_url or OPENAI_API_URL,
                        name="openai",
                    )
                manager.register_provider(provider)
                logger.info("Provider %s chargé depuis api_key", api_type)

            _providers_initialized_from_db = True

            # Appliquer le modèle choisi dans la config admin. Le provider
            # utilisé est TOUJOURS celui détecté depuis la clé (api_type) —
            # c'est la seule source de vérité, la valeur primary_provider
            # stockée en BDD peut être incohérente (bug historique d'UI).
            primary_provider_db = await config_service.get("primary_provider")
            primary_model = await config_service.get("primary_model")
            if api_type and api_type in manager._providers:
                _warn_if_no_primary_model(api_type, primary_model)
                manager.set_default(api_type, primary_model)
                logger.info(
                    "Provider par défaut: %s / %s (depuis config admin)",
                    api_type,
                    primary_model,
                )
                # Si la BDD stocke un primary_provider incohérent avec la clé,
                # on la corrige pour éviter que les UI suivantes affichent faux.
                if primary_provider_db and primary_provider_db != api_type:
                    logger.warning(
                        "Config BDD incohérente: primary_provider=%r mais clé "
                        "API détectée comme %r. Correction automatique.",
                        primary_provider_db,
                        api_type,
                    )
                    try:
                        await config_service.set(
                            "primary_provider",
                            api_type,
                            user_id=0,
                        )
                    except Exception as set_exc:
                        logger.warning(
                            "Impossible de corriger primary_provider: %s",
                            set_exc,
                        )

            # LLM local fallback (anonymiseur + fallback runtime).
            # Helper partagé avec reinit_providers_from_config (DRY).
            await _load_local_fallback_from_config(manager, config_service)
            # Hydrate les defaults runtime (temperature / max_retries / timeout)
            # depuis ``/admin/ai-config``. Source unique de vérité pour les
            # call sites LLM cloud + local.
            await manager.hydrate_defaults_from_config(config_service)
        except Exception as e:
            logger.warning("Impossible de charger les providers depuis la BDD: %s", e)


async def reinit_providers_from_config():
    """
    Réinitialise les providers avec les clés API de la config.
    À appeler après une mise à jour de la config via l'interface
    (changement de clé API, provider, ou modèle).
    """
    global _llm_manager, _providers_initialized_from_db  # noqa: F824
    if _llm_manager is None:
        return

    # Permettre à ensure_providers_from_db() de re-lire la config au prochain appel
    _providers_initialized_from_db = False

    from app.services.ai.config_service import get_ai_config_service
    from app.constants_ai import detect_api_type

    config_service = get_ai_config_service()

    # Fermer les providers existants
    for name, provider in list(_llm_manager._providers.items()):
        await provider.close()
    _llm_manager._providers.clear()

    # Fermer + reset le LLM local fallback aussi (l'admin peut avoir
    # changé l'URL ou le modèle dans /admin/ai-config). Sans ça, on
    # garderait l'ancien client httpx pointant vers l'ancien Ollama.
    if _llm_manager._local_fallback is not None:
        try:
            await _llm_manager._local_fallback.close()
        except Exception:  # noqa: BLE001
            pass
        _llm_manager._local_fallback = None
        _llm_manager._local_fallback_model = None

    # Charger le provider depuis api_key + api_base_url
    api_key = await config_service.get("api_key")
    api_type: Optional[str] = None
    if api_key:
        base_url = await config_service.get("api_base_url") or ""
        api_type = detect_api_type(api_key, base_url)
        # Le nom interne du provider = api_type réel. On ne fait JAMAIS
        # confiance à primary_provider stocké (peut être incohérent avec la clé).
        if api_type == "anthropic":
            # Switch admin Vertex ↔ officiel ↔ proxy : propager ``base_url``
            # pour que l'éligibilité TTL 1h (``_long_ttl_eligible``) reflète
            # l'endpoint réel et pas ANTHROPIC_API_URL par défaut.
            _llm_manager.register_provider(
                AnthropicProvider(api_key=api_key, base_url=base_url or None)
            )
        else:
            _llm_manager.register_provider(
                OpenAIProvider(
                    api_key=api_key,
                    base_url=base_url or OPENAI_API_URL,
                    name="openai",
                )
            )
        logger.info("Provider %s réinitialisé", api_type)

    # Appliquer le modèle choisi dans la config admin. Le provider utilisé est
    # TOUJOURS celui détecté depuis la clé. Si la BDD stocke un primary_provider
    # incohérent, on la corrige pour que les futures lectures soient saines.
    primary_provider_db = await config_service.get("primary_provider")
    primary_model = await config_service.get("primary_model")
    if api_type and api_type in _llm_manager._providers:
        _warn_if_no_primary_model(api_type, primary_model)
        _llm_manager.set_default(api_type, primary_model)
        logger.info(
            "Provider par défaut mis à jour: %s / %s",
            api_type,
            primary_model,
        )
        if primary_provider_db and primary_provider_db != api_type:
            logger.warning(
                "Config BDD incohérente: primary_provider=%r mais clé API "
                "détectée comme %r. Correction automatique.",
                primary_provider_db,
                api_type,
            )
            try:
                await config_service.set(
                    "primary_provider",
                    api_type,
                    user_id=0,
                )
            except Exception as set_exc:
                logger.warning(
                    "Impossible de corriger primary_provider: %s",
                    set_exc,
                )

    # Recharger le LLM local fallback via le helper partagé (DRY).
    # L'helper fait l'atomic swap (review CRITICAL #6) — l'ancien
    # provider reste actif si l'init du nouveau échoue.
    await _load_local_fallback_from_config(_llm_manager, config_service)
    # Re-hydrater les defaults runtime aux nouvelles valeurs admin.
    await _llm_manager.hydrate_defaults_from_config(config_service)

    # Marquer comme initialisé pour éviter des re-lectures DB inutiles
    _providers_initialized_from_db = True


def _init_default_providers(manager: LLMManager):
    """Initialise les providers par défaut depuis les variables d'environnement.

    L'ordre d'enregistrement est alphabétique ; le premier enregistré devient
    default (via len==1 dans register_provider). La config BDD (ensure_providers_from_db)
    applique ensuite le choix de l'utilisateur via set_default.
    """
    import os

    # Anthropic/Claude
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if anthropic_key:
        anthropic = AnthropicProvider(api_key=anthropic_key)
        manager.register_provider(anthropic)
        logger.info("Provider Anthropic/Claude enregistré (clé env détectée)")

    # OpenAI
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        openai = OpenAIProvider(api_key=openai_key)
        manager.register_provider(openai)
        logger.info("Provider OpenAI enregistré (clé env détectée)")
