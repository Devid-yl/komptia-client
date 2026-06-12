"""Hook central qui logue chaque appel LLM dans ``AIPerformanceLog``.

**Pourquoi ce module existe** : avant ce hook, le tracking de la consommation
API était fragmenté — seul ``agent_service._log_api_usage`` écrivait dans
``AIPerformanceLog``, et il aggregait toute une conversation Iris en une
seule ligne. Tous les autres call-sites (sync schéma, copilote,
automations, anonymizer, dashboards, reporting, …) consommaient des tokens
sans rien écrire en BDD. Résultat : le dashboard "Consommation API"
sous-estimait la facture Anthropic réelle d'un facteur ~10×.

Ce module est **la seule source de vérité** pour l'écriture
d'``AIPerformanceLog`` depuis les appels LLM. Il est invoqué automatiquement
par ``LLMManager`` à chaque appel — aucun call-site n'a besoin de logger
manuellement.

**Architecture** :

* ``record_llm_call_sync(...)`` extrait les tokens d'un ``LLMResponse``
  ou d'un raw dict (Anthropic/OpenAI), calcule le coût figé via le
  registre BDD pricing, et schedule une écriture async sans bloquer
  le retour de l'appel LLM.
* ``record_llm_call_async(...)`` est la version awaitable utilisée
  par les chemins déjà async.
* ``update_llm_call(row_id, **fields)`` permet à un caller (ex:
  ``agent_service``) d'enrichir la ligne après-coup avec les champs
  business (``question``, ``sql_generated``, ``user_feedback``, …).
* ``StreamAccountingWrapper`` aggregate les tokens d'un async generator
  streaming (Anthropic SSE / OpenAI chunks) puis flush en fin de stream.

Tous les écrits sont **defensive** : un échec d'écriture (DB locked,
constraint, …) loggue un warning mais ne propage jamais — on ne casse
pas le retour LLM pour un problème d'observabilité.

Le hook lit le contexte depuis ``app.utils.request_context`` :
* ``current_user_id()`` — user HTTP qui a déclenché l'appel
* ``current_caller()`` — origine sémantique posée via
  ``llm_call_context(caller=...)``
* ``current_conversation_id()`` — grouping (UUID conv Iris ou batch)
* ``current_request_id()`` — corrélation HTTP
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, AsyncGenerator, Optional

from sqlalchemy import update

from app.core import clock
from app.core.database import get_session
from app.core.db_retry import retry_on_locked
from app.models.ai_performance import AIPerformanceLog, QueryStatus
from app.utils.logger import get_logger
from app.utils.request_context import (
    current_caller,
    current_conversation_id,
    current_request_id,
    current_user_id,
)

logger = get_logger(__name__)


# Catalogue des callers connus (pour cohérence dashboard + lint au runtime).
# Tout caller posé via ``llm_call_context(caller=...)`` DEVRAIT figurer ici.
# La liste sert de contrat documenté — pas de validation runtime stricte
# (un caller inconnu loggue simplement un warning, ne bloque pas).
KNOWN_CALLERS: frozenset[str] = frozenset(
    {
        # Iris — agent principal de chat NL→SQL
        "iris_main",
        "iris_compress_history",
        "iris_explore_guard",
        # P2.1 — Résumé fin-de-conversation Iris (parité copilot_memory)
        "iris_session_memory",
        # Orchestrator phases
        "orchestrator_phase2_decompose",
        "orchestrator_phase3_brainstorm",
        "orchestrator_phase4_blueprint",
        "orchestrator_step_json",
        "orchestrator_step_sql",
        "orchestrator_feedback",
        "orchestrator_error_recovery",
        # Copilote (interventions sur résultats SQL)
        "copilot_workspace",
        "copilot_clarify",
        "copilot_memory_summarize",
        "copilot_cell_suggest",
        "copilot_cell_plan",
        "copilot_cell_exec",
        "copilot_cell_retry",
        "copilot_cell_cleanup",
        # Schema sync / enrichissement (admin / scheduler)
        "schema_sync",
        "schema_enrich_table",
        "schema_enrich_aliases",
        "schema_enrich_batch",
        "schema_welcome_suggestions",
        # Knowledge graph + sémantique
        "agent_knowledge",
        "agent_role_detect",
        "agent_tool_concepts",
        # Anonymisation (PII classification + amélioration des labels)
        "anonymizer_classify",
        "anonymizer_improve_pseudo",
        # Dashboards & reporting
        "dashboard_widget_planner",
        "dashboard_widget_analyst",
        "dashboard_widget_composer",
        "dashboard_widget_designer",
        # Agent tool-loop dashboards (PR 2.4 — alternative au pipeline 3-shot
        # ci-dessus). Activable via _USE_AGENT_PIPELINE dans
        # app/handlers/dashboard_builder.py.
        "dashboard_widget_planner_agent",
        "report_planner",
        "report_planner_agent",  # tool-loop mode (gros datasets, lazy access)
        "report_analyzer",
        # Data access suggestions
        "data_access_suggester",
        # Vanna (legacy fallback SQL gen)
        "vanna_generate",
        # Vanna : log "business" (page metier) — pas un appel LLM, juste
        # une ligne ``AIPerformanceLog`` créée pour différencier les usages
        # métier des appels API réels (tokens NULL = consommation hook).
        "vanna_business_log",
        # Iris one-shot (DAG executor) — réservé pour usage futur, pas
        # encore branché sur un call site (cf. EXPECTED_DEAD_OR_DYNAMIC
        # dans tests/unit/test_llm_runtime.py).
        "iris_one_shot",
        # Automation extract_nl (caller futur — DAG step pas encore branché
        # sur le runtime). Documenté ici pour que l'intégration future
        # n'ait qu'à poser le ``caller="automation_extract_nl"``.
        "automation_extract_nl",
        # Iris one-shot (transformations SQL ad-hoc — bouton "Charger toutes
        # les colonnes" et autres usages programmatiques de transform_sql_via_llm)
        "iris_oneshot_load_all_cols",
        # Iris one-shot drill-down (zoom sur une cellule/agrégat des résultats —
        # iris_oneshot.py) et fusion de la mémoire utilisateur Iris
        # (iris_user_memory.py). Sans ces entrées, /admin/ai-performance ne sait
        # pas filtrer ces appels et le tracker logue un warning par appel.
        "iris_oneshot_drilldown",
        "iris_user_memory_fuse",
        # Pipeline NL→SQL monolithique (scripts/pipeline.py). Chaque phase LLM
        # pose un caller dédié. Sans ces entrées, llm_call_tracker logue un
        # warning par appel et le cost tracking peut diverger (lien étroit
        # avec B3 = modèle hors registre pricing). Cf. run #7 / 2026-05-20 où
        # 56 appels pipeline sont sortis comme "caller inconnu" sur 68 total.
        "pipeline_p11_extract",  # Phase 1.1 — extraction des concepts NL
        "pipeline_p12_expand",  # Phase 1.2 — expansion termes (3 passes)
        "pipeline_p125_filter",  # Phase 1.2.5 — filtrage tables hors-sujet
        "pipeline_p126_curate",  # Phase 1.2.6 — curate routing par concept
        "pipeline_p2_rerank",  # Phase 2 — rerank des candidats schéma
        "pipeline_p3_factsheet",  # Phase 3 — concept fact sheets (probes)
        "pipeline_p4_compose_ir",  # Phase 4 — composition IR → SQL
        "pipeline_diagnose",  # Phase diagnostic + retry post-exec
        # Test / probe (cost négligeable)
        "probe",
        # Garde anti-régression test_llm_call_tracker_known_callers : ces
        # callers existent uniquement pour les tests unitaires, jamais en prod.
        "test_caller",
        "test_update",
    }
)


# Pattern pour redacter les API keys et bearer tokens dans error_message.
# Anthropic format: ``sk-ant-...``. OpenAI format: ``sk-...``. Bearer header:
# ``Bearer <token>``. On préfère redacter agressivement plutôt que de fuiter
# une clé dans le dashboard admin (avec un /admin/ai-performance qui
# affiche les error_messages, voir templates/admin/ai_performance.html).
_API_KEY_REDACT_RE = re.compile(
    r"(sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|"
    r"Bearer\s+[A-Za-z0-9._\-]+|x-api-key:\s*\S+)",
    re.IGNORECASE,
)


def _redact_secrets(text: str | None) -> str | None:
    """Remplace tout pattern ressemblant à une clé API par ``[REDACTED]``.

    Defensive : si un provider 401/403 echo la clé en clair dans son
    response body, on évite de la stocker en BDD (et donc de la rendre
    visible aux admins via /admin/ai-performance).
    """
    if not text:
        return text
    return _API_KEY_REDACT_RE.sub("[REDACTED]", text)


@dataclass(slots=True)
class _CallSnapshot:
    """État capturé d'un appel LLM, prêt à être persisté."""

    model_provider: str
    model_name: str
    status: QueryStatus
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    cache_read_tokens: Optional[int] = None
    cache_creation_tokens: Optional[int] = None
    thinking_tokens: Optional[int] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    temperature: Optional[float] = None
    question: Optional[str] = None
    cost_usd_snapshot: Optional[float] = None  # ``None`` = pricing inconnu
    caller: Optional[str] = None
    conversation_id: Optional[str] = None
    request_id: Optional[str] = None
    user_id: Optional[int] = None
    from_cache: bool = False


# Cache module-level pour throttler le warning "pricing inconnu" — sans ça,
# chaque appel LLM sur un modèle exotic spammerait les logs. Set Python
# thread-safe pour ajout (GIL). Pas borné : si l'admin teste 100 modèles
# exotiques, on garde 100 entries — négligeable.
_PRICING_WARNED_MODELS: set[str] = set()


def _public_registry_prices_model(model_name: str) -> bool:
    """Wrapper fail-soft autour de l'oracle public ``public_model_is_priced``
    (SSoT dans ``litellm_registry_sync`` — registre + cache + verdict mémoïsés
    là-bas). Sépare la responsabilité : ce module décide quoi FAIRE du verdict,
    ``litellm_registry_sync`` sait ce que LiteLLM tarife.

    Fail-soft → ``False`` : si l'import/lookup casse, on NE prétend PAS que le
    modèle est tarifé (retour au comportement historique 0.0). Cette rupture
    serait silencieuse → couverte par un test de garde bout-en-bout
    (``test_compute_cost_snapshot_paid_unpriced_real_registry``).
    """
    try:
        from app.services.ai.litellm_registry_sync import public_model_is_priced

        return public_model_is_priced(model_name)
    except Exception:  # noqa: BLE001 — best-effort, jamais bloquant
        return False


def _warn_missing_pricing_once(model_name: str) -> None:
    """Log un warning [BILLING] visible la première fois qu'on rencontre un
    modèle sans pricing dans le registre. Cf. review brainstorm 2026-05-14
    CRIT pricing fail-silent : sans ce signal, le dashboard cost affiche
    ``$0`` pour tout modèle non-seedé → facture invisible. Fix admin :
    ``POST /api/admin/llm/models/sync`` ou saisie manuelle pricing via
    ``/admin/ai-models``.

    Sanitize ``model_name`` contre log-injection (CRLF) — review adversariale
    2026-05-14 MIN. Le nom du modèle est admin-input via /admin/ai-models,
    donc déjà filtré côté formulaire, mais defense-in-depth.
    """
    if model_name in _PRICING_WARNED_MODELS:
        return
    _PRICING_WARNED_MODELS.add(model_name)
    safe_name = str(model_name).replace("\n", "\\n").replace("\r", "\\r")
    logger.warning(
        "[BILLING] Pricing inconnu pour modèle %r — cost_usd_snapshot=NULL "
        "dans ai_performance_logs. Le dashboard /admin/usage affichera $0 "
        "pour les appels sur ce modèle. Fix : sync registre via "
        "POST /api/admin/llm/models/sync, ou saisie manuelle pricing "
        "input/output/cache_read/cache_creation via /admin/ai-models.",
        safe_name,
    )


def clear_pricing_warning_cache(model_name: Optional[str] = None) -> None:
    """Purge le cache ``_PRICING_WARNED_MODELS``. Appelé après un update du
    registre ``LlmModel`` (insert/update pricing) pour ré-évaluer si le
    modèle a maintenant un pricing. Sinon le warning reste silencieux à
    vie même après que l'admin ait fixé le problème.

    Cf. review adversariale 2026-05-14 CRIT3.

    ``model_name=None`` : purge tout (utilisé après reinit_providers /
    invalidate du registre). ``model_name=str`` : purge un seul modèle
    (utilisé après PATCH /api/admin/llm/models/{name}).
    """
    if model_name is None:
        _PRICING_WARNED_MODELS.clear()
    else:
        _PRICING_WARNED_MODELS.discard(model_name)


def _compute_cost_snapshot(
    model_name: str,
    prompt_tokens: Optional[int],
    completion_tokens: Optional[int],
    cache_read_tokens: Optional[int],
    thinking_tokens: Optional[int],
    cache_creation_tokens: Optional[int] = None,
) -> Optional[float]:
    """Coût figé en USD, ou ``None`` si pricing inconnu pour ce modèle.

    Aligne avec la facturation réelle Anthropic / OpenAI cache pricing :
    - ``prompt_tokens`` : prix INPUT (full)
    - ``cache_read_tokens`` : prix CACHE_READ (Anthropic = 10% du input,
      OpenAI gpt-4o = 50%). Si pricing.cache_read = 0 → fallback prix INPUT
      (calcul legacy).
    - ``cache_creation_tokens`` : prix CACHE_CREATION (Anthropic = 125%
      du input). Si pricing.cache_creation = 0 → fallback prix INPUT.
    - ``completion_tokens + thinking_tokens`` : prix OUTPUT.

    On retourne ``None`` plutôt que ``0.0`` pour distinguer "vraiment
    gratuit" de "modèle non priced".
    """
    if not model_name:
        return None
    try:
        from app.constants_ai import get_pricing_for_model

        pricing = get_pricing_for_model(model_name)
        # Distinction "pricing absent" vs "pricing explicite à 0" (modèle
        # gratuit) — fix 2026-05-20 sur logs serveur où qwen2.5:3b-instruct,
        # phi3:mini, openai/gpt-oss-* warnent à chaque appel alors qu'ils
        # sont enregistrés en BDD avec ``input_price_per_mtok_usd=0.0``.
        #
        # Avant : 0/0 = "manquant" → warn + cost=NULL → dashboard $0
        # Après : 0/0 + modèle présent dans le registre BDD = gratuit
        #         légitime → cost=0.0 (pas NULL). Le distingue d'un
        #         fallback static 0/0 pour un modèle pas-encore-sync.
        #
        # Le check ``_registry_cache_lookup(name) is not None`` est la
        # SEULE source fiable : si l'admin (ou le sync LiteLLM/Ollama) a
        # explicitement upserté une row avec pricing=0, c'est qu'il a
        # validé que ce modèle est gratuit. Sinon (modèle pas-encore-vu
        # = static fallback), on warne pour que l'admin sache configurer.
        if not pricing:
            _warn_missing_pricing_once(model_name)
            return None
        input_price = float(pricing.get("input", 0.0))
        output_price = float(pricing.get("output", 0.0))
        if input_price == 0.0 and output_price == 0.0:
            from app.constants_ai import _registry_cache_lookup

            registered = _registry_cache_lookup(model_name, "name") is not None
            if not registered:
                _warn_missing_pricing_once(model_name)
                return None
            # Enregistré avec pricing 0/0 : NE PAS conclure "gratuit" trop vite.
            # Interroger l'oracle public (LiteLLM) : s'il tarife ce modèle, c'est
            # un PAYANT NON-ENRICHI (Anthropic/OpenAI dont la BD n'a pas encore
            # reçu les prix), pas un gratuit → warn + None au lieu d'un 0 $ muet
            # (denial-of-wallet masqué). Sinon (Ollama/local/inconnu) → gratuit
            # légitime → cost=0.0 explicite.
            if _public_registry_prices_model(model_name):
                _warn_missing_pricing_once(model_name)
                return None
            return 0.0
        cache_read_price = float(pricing.get("cache_read", 0.0)) or input_price
        cache_creation_price = float(pricing.get("cache_creation", 0.0)) or input_price
        cost = (
            (prompt_tokens or 0) * input_price / 1_000_000
            + (cache_read_tokens or 0) * cache_read_price / 1_000_000
            + (cache_creation_tokens or 0) * cache_creation_price / 1_000_000
            + ((completion_tokens or 0) + (thinking_tokens or 0)) * output_price / 1_000_000
        )
        return float(cost)
    except Exception as exc:  # noqa: BLE001 — defensive, ne JAMAIS bloquer le LLM
        logger.warning("Calcul du coût snapshot impossible pour %r : %s", model_name, exc)
        return None


def _extract_from_response_obj(response: Any) -> dict[str, Any]:
    """Extrait les tokens d'un ``LLMResponse`` ou d'un raw dict.

    Branche les deux formats de retour LLM :
    * ``LLMResponse`` (dataclass) — sortie de ``provider.generate()``
    * ``dict`` Anthropic-format — sortie de ``provider.generate_with_tools()``
      contient ``{"usage": {"input_tokens": ..., "output_tokens": ...}, ...}``

    Retourne un dict normalisé avec les clés :
    ``prompt_tokens, completion_tokens, total_tokens, cache_read_tokens,
    cache_creation_tokens, thinking_tokens, model_name``.
    """
    out: dict[str, Any] = {
        "prompt_tokens": None,
        "completion_tokens": None,
        "total_tokens": None,
        "cache_read_tokens": None,
        "cache_creation_tokens": None,
        "thinking_tokens": None,
        "model_name": None,
    }
    if response is None:
        return out

    # Cas 1 : LLMResponse (dataclass — accède aux attributs)
    if hasattr(response, "prompt_tokens"):
        out["prompt_tokens"] = getattr(response, "prompt_tokens", None)
        out["completion_tokens"] = getattr(response, "completion_tokens", None)
        out["total_tokens"] = getattr(response, "total_tokens", None)
        out["cache_read_tokens"] = getattr(response, "cache_read_tokens", None)
        out["cache_creation_tokens"] = getattr(response, "cache_creation_tokens", None)
        out["thinking_tokens"] = getattr(response, "thinking_tokens", None)
        out["model_name"] = getattr(response, "model", None)
        return out

    # Cas 2 : raw dict Anthropic (generate_with_tools sortie)
    if isinstance(response, dict):
        usage = response.get("usage") or {}
        # Anthropic : input_tokens / output_tokens
        # OpenAI compat (converti via _convert_openai_response_to_anthropic) :
        # même schéma normalisé sur input_tokens/output_tokens.
        prompt = usage.get("input_tokens")
        if prompt is None:
            prompt = usage.get("prompt_tokens")
        completion = usage.get("output_tokens")
        if completion is None:
            completion = usage.get("completion_tokens")
        out["prompt_tokens"] = prompt
        out["completion_tokens"] = completion
        out["total_tokens"] = usage.get("total_tokens")
        out["cache_read_tokens"] = usage.get("cache_read_input_tokens")
        out["cache_creation_tokens"] = usage.get("cache_creation_input_tokens")
        # Thinking — formats variables selon provider
        thinking = (
            usage.get("thinking_tokens")
            or usage.get("reasoning_tokens")
            or (usage.get("completion_tokens_details") or {}).get("reasoning_tokens")
        )
        out["thinking_tokens"] = thinking
        out["model_name"] = response.get("model")
        return out

    return out


def _normalize_model_name(raw: Any) -> str:
    """Normalise un ``model_name`` quelle que soit sa forme d'entrée.

    Couvre 3 cas observés ou plausibles :

    1. ``str`` propre (``"claude-sonnet-4-6"``) → retourné tel quel après
       strip + cap longueur.
    2. ``dict`` (``{"name": "X", "provider": "Y"}``) → extrait ``X``.
    3. ``str`` dict-stringifié (``"{'name': 'X', 'provider': 'Y'}"`` que
       Python aurait écrit via ``str({...})``) → parse avec
       :func:`ast.literal_eval` (refuse tout code, accepte juste
       les literals Python) et extrait ``X``.

    Fail-soft : entrée non normalisable → fallback ``"unknown"``. Logue
    un warning visible (un caller doit toujours passer une string —
    si un dict arrive ici c'est un bug en amont).

    Cap dur à 200 chars (alignement avec la colonne SQL
    ``llm_models.name VARCHAR(200)``).
    """
    import ast

    if raw is None or raw == "":
        return ""

    # Cas 2 : dict natif.
    if isinstance(raw, dict):
        candidate = raw.get("name") or raw.get("model")
        if isinstance(candidate, str) and candidate:
            logger.warning(
                "Tracker: model_name reçu sous forme de dict (clés=%s) — "
                "extraction de %r. Le caller devrait passer une string.",
                sorted(raw.keys())[:5],
                candidate[:50],
            )
            return candidate.strip()[:200]
        logger.warning(
            "Tracker: model_name dict sans clé 'name' utilisable (keys=%s). " "Fallback 'unknown'.",
            sorted(raw.keys())[:5],
        )
        return "unknown"

    if not isinstance(raw, str):
        logger.warning(
            "Tracker: model_name de type inattendu %s — fallback 'unknown'.",
            type(raw).__name__,
        )
        return "unknown"

    cleaned = raw.strip()
    # Cas 3 : dict-stringifié (commence par ``{``). On accepte les deux
    # clés ``name`` et ``model`` selon le caller — pas de pre-filter sur
    # la clé pour rester générique. ``ast.literal_eval`` protège contre
    # les non-literals via except ValueError/SyntaxError.
    # On évite ``json.loads`` car il rate les quotes simples typiques de
    # ``str(dict_python)``.
    if cleaned.startswith("{"):
        try:
            parsed = ast.literal_eval(cleaned)
            if isinstance(parsed, dict):
                candidate = parsed.get("name") or parsed.get("model")
                if isinstance(candidate, str) and candidate:
                    logger.warning(
                        "Tracker: model_name reçu en forme dict-stringifié, "
                        "extraction de %r. Le caller devrait passer le nom "
                        "directement, pas ``str(dict)``.",
                        candidate[:50],
                    )
                    return candidate.strip()[:200]
        except (ValueError, SyntaxError):
            # Pas un literal Python valide — laisse tomber le parse et
            # passe la string telle quelle (cap longueur appliqué après).
            pass

    # Cas 1 : string propre (ou string non-dict qu'on ne peut pas normaliser).
    return cleaned[:200]


def build_snapshot(
    *,
    request: Any,
    response: Any,
    provider_name: str,
    duration_seconds: Optional[float],
    error: Optional[BaseException] = None,
    from_cache: bool = False,
) -> _CallSnapshot:
    """Construit un ``_CallSnapshot`` à partir d'un appel LLM."""
    extracted = _extract_from_response_obj(response)

    # Modèle : préférer celui retourné dans la response, fallback request.model
    model_name = extracted.get("model_name") or getattr(request, "model", "") or ""
    # Defense-in-depth : normalise un model_name qui aurait été passé sous
    # forme de dict ``{"name": "...", "provider": "..."}`` ou de
    # dict-stringifié ``"{'name': '...', ...}"``. Bug historique (3 rows
    # 13-mai 2026 retrouvées avec ``model_name="{'name': 'claude-sonnet-4-6',
    # 'provider': 'anthropic'}"``) : sans cette garde, ``stats_service``
    # warnait "Pricing inconnu" sur chaque ``/api/ai/usage``, et le dashboard
    # affichait $0 pour ces rows. Générique : couvre n'importe quel modèle,
    # pas seulement claude-sonnet-4-6.
    model_name = _normalize_model_name(model_name)

    if error is not None:
        # Cancellation initiée par l'utilisateur ≠ erreur LLM. La conserver
        # comme LLM_ERROR pollue les error rate metrics du dashboard
        # (cf. ``stats_service.get_error_breakdown``) — un user qui clique
        # "stop" mid-stream apparaitrait comme une panne IA. On la
        # qualifie SUCCESS (consommation réelle, juste interrompue).
        if isinstance(error, asyncio.CancelledError):
            status = QueryStatus.SUCCESS
            error_message = "cancelled by user"
        elif isinstance(error, (asyncio.TimeoutError, TimeoutError)):
            # Distinguer TIMEOUT de LLM_ERROR pour que le dashboard
            # signale les pannes réseau / surcharge provider sans les
            # confondre avec les erreurs métier (validation, etc.).
            status = QueryStatus.TIMEOUT
            error_message = _redact_secrets(f"{type(error).__name__}: {error}")
            if error_message and len(error_message) > 2000:
                error_message = error_message[:2000]
        else:
            status = QueryStatus.LLM_ERROR
            raw_msg = f"{type(error).__name__}: {error}"
            error_message = _redact_secrets(raw_msg)
            if error_message and len(error_message) > 2000:
                error_message = error_message[:2000]
    else:
        status = QueryStatus.SUCCESS
        error_message = None

    # Recompute total_tokens si pas fourni mais les composants le sont
    p_tok = extracted.get("prompt_tokens")
    c_tok = extracted.get("completion_tokens")
    t_tok = extracted.get("total_tokens")
    if t_tok is None and (p_tok is not None or c_tok is not None):
        t_tok = (p_tok or 0) + (c_tok or 0)

    cost_snapshot = _compute_cost_snapshot(
        model_name=model_name,
        prompt_tokens=p_tok,
        completion_tokens=c_tok,
        cache_read_tokens=extracted.get("cache_read_tokens"),
        thinking_tokens=extracted.get("thinking_tokens"),
        cache_creation_tokens=extracted.get("cache_creation_tokens"),
    )

    # Question : tronquée pour éviter de stocker des prompts énormes
    # (le système prompt d'Iris peut faire 50KB). On garde le ``prompt``
    # brut limité à 4KB — assez pour tracer, pas assez pour saturer.
    question_raw = getattr(request, "prompt", None) or ""
    question = (question_raw[:4096] + "…") if len(question_raw) > 4096 else question_raw

    caller_value = current_caller() or None
    # Validation soft : caller inconnu loggué pour catch les typos (ex.
    # ``iris_mian`` au lieu de ``iris_main``). Pas de fail-closed — la
    # row est écrite quand même, mais le warning permet à l'admin de
    # repérer les attributions cassées dans la dashboard breakdown.
    if caller_value and caller_value not in KNOWN_CALLERS:
        logger.warning(
            "LLM caller %r inconnu — ajouter à KNOWN_CALLERS dans "
            "llm_call_tracker.py si légitime, sinon corriger la typo.",
            caller_value,
        )

    snap = _CallSnapshot(
        model_provider=provider_name or "unknown",
        model_name=model_name or "unknown",
        status=status,
        prompt_tokens=p_tok,
        completion_tokens=c_tok,
        total_tokens=t_tok,
        cache_read_tokens=extracted.get("cache_read_tokens"),
        cache_creation_tokens=extracted.get("cache_creation_tokens"),
        thinking_tokens=extracted.get("thinking_tokens"),
        duration_seconds=duration_seconds,
        error_message=error_message,
        temperature=getattr(request, "temperature", None),
        question=question or "",
        cost_usd_snapshot=cost_snapshot,
        caller=caller_value,
        conversation_id=current_conversation_id(),
        request_id=current_request_id() or None,
        user_id=current_user_id(),
        from_cache=from_cache,
    )

    # Anomalie détectable : SUCCESS + 0 tokens. Soit le provider n'a pas
    # renvoyé d'usage (rare), soit le wrapper streaming a raté l'aggregation.
    # On loggue bruyamment pour ne pas laisser passer un masquage silencieux.
    if status == QueryStatus.SUCCESS and (p_tok or 0) == 0 and (c_tok or 0) == 0:
        logger.warning(
            "LLM call SUCCESS mais 0 tokens capturés (provider=%s model=%s caller=%s) "
            "— probable bug d'extraction usage. Investiguer.",
            provider_name,
            model_name,
            snap.caller or "—",
        )

    return snap


async def _persist_snapshot(snap: _CallSnapshot) -> Optional[int]:
    """Écrit le snapshot dans ``ai_performance_logs``. Retourne l'``id`` créé.

    Defensive : tout échec (DB locked, constraint, …) loggue un warning et
    retourne ``None``. Ne JAMAIS lever — un appel LLM réussi ne doit pas
    foirer pour un problème d'observabilité.

    **Retry sur ``database is locked``** (fix 2026-05-22) : l'INSERT est
    wrappé dans :func:`retry_on_locked` (3 tentatives, backoff
    exponentiel 100ms → 400ms → 1.6s). Sans ce retry, sur burst (improve-
    pseudo + Iris en parallèle), une simple contention transitoire SQLite
    perdait la ligne d'audit silencieusement. Cohérent avec la doctrine
    explicite de ``db_retry.py`` : « audit log = perdre 1 ligne sur N
    retries-failed est acceptable » — le retry réduit le taux d'écriture
    perdue d'un facteur ~10× sans bloquer l'event loop (les sleep utilisent
    asyncio).
    """

    async def _do_insert() -> Optional[int]:
        async with get_session() as session:
            log = AIPerformanceLog(
                question=snap.question or "",
                model_provider=snap.model_provider,
                model_name=snap.model_name,
                temperature=snap.temperature,
                status=snap.status,
                error_message=snap.error_message,
                generation_time=snap.duration_seconds,
                total_time=snap.duration_seconds,
                prompt_tokens=snap.prompt_tokens,
                completion_tokens=snap.completion_tokens,
                total_tokens=snap.total_tokens,
                cache_read_tokens=snap.cache_read_tokens,
                cache_creation_tokens=snap.cache_creation_tokens,
                thinking_tokens=snap.thinking_tokens,
                cost_usd_snapshot=snap.cost_usd_snapshot,
                caller=snap.caller,
                conversation_id=snap.conversation_id,
                request_id=snap.request_id,
                user_id=snap.user_id,
                from_cache=snap.from_cache,
                created_at=clock.now(),
            )
            session.add(log)
            await session.commit()
            return log.id

    try:
        return await retry_on_locked(
            _do_insert,
            max_attempts=3,
            base_delay_s=0.1,
            max_delay_s=1.6,
            operation_name=f"ai_perf_log_insert[{snap.caller or '—'}]",
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Échec d'écriture AIPerformanceLog (caller=%s model=%s) : %s",
            snap.caller or "—",
            snap.model_name,
            exc,
        )
        return None


async def record_llm_call_async(
    *,
    request: Any,
    response: Any = None,
    provider_name: str,
    duration_seconds: Optional[float],
    error: Optional[BaseException] = None,
    from_cache: bool = False,
) -> Optional[int]:
    """Logue un appel LLM dans ``AIPerformanceLog``. Version awaitable.

    Retourne l'``id`` de la ligne créée (ou ``None`` si l'écriture a
    échoué). L'``id`` peut être utilisé par le caller pour enrichir la
    ligne ultérieurement via ``update_llm_call``.
    """
    snap = build_snapshot(
        request=request,
        response=response,
        provider_name=provider_name,
        duration_seconds=duration_seconds,
        error=error,
        from_cache=from_cache,
    )
    return await _persist_snapshot(snap)


async def update_llm_call(
    row_id: int,
    **fields: Any,
) -> None:
    """Met à jour des champs business sur une ligne ``AIPerformanceLog``.

    Utilisé par ``agent_service`` pour enrichir la ligne créée par le
    hook avec ``sql_generated``, ``sql_validated``, ``user_feedback``,
    ``was_corrected``, ``result_count``, etc.

    Ne lève jamais — defensive sur l'observabilité.
    """
    if not row_id:
        return
    # Whitelist STRICTE : seulement les champs business "post-call"
    # (résultat de la requête SQL, feedback utilisateur, RAG meta).
    # Les champs "consumption" (status, tokens, cost, model, caller,
    # error_message, from_cache) sont IMMUTABLES une fois écrits par le
    # hook — sinon un caller buggué pourrait flipper SUCCESS↔LLM_ERROR
    # rétroactivement et fausser l'audit trail.
    allowed = {
        "question",
        "sql_generated",
        "sql_validated",
        "result_count",
        "validation_time",
        "execution_time",
        "total_time",
        "rag_ddl_count",
        "rag_doc_count",
        "rag_example_count",
        "prompt_length",
        "user_feedback",
        "feedback_comment",
        "was_corrected",
        "corrected_sql",
    }
    payload = {k: v for k, v in fields.items() if k in allowed}
    if not payload:
        return
    try:
        async with get_session() as session:
            await session.execute(
                update(AIPerformanceLog).where(AIPerformanceLog.id == row_id).values(**payload)
            )
            await session.commit()
    except Exception as exc:  # noqa: BLE001
        logger.warning("update_llm_call(id=%d) failed: %s", row_id, exc)


# ─────────────────────────────────────────────────────────────────────────
# Budget aggregation (T24 — denial-of-wallet par conversation)
# ─────────────────────────────────────────────────────────────────────────


async def get_conversation_cost_usd(
    conversation_id: str | None,
    *,
    created_after: datetime | None = None,
    user_id: int | None = None,
) -> tuple[float, int]:
    """Retourne ``(sum_cost_usd, count_null_cost)`` pour les appels LLM
    agrégés sur ``conversation_id``.

    Aggrégation SQL : ``SUM(cost_usd_snapshot)`` filtré par
    ``conversation_id``. ``count_null_cost`` est le nombre de rows
    pour cette conversation où ``cost_usd_snapshot IS NULL`` (modèle
    hors registre pricing) — sert au caller à savoir si le budget
    est sous-évalué silencieusement.

    **Filtres de défense en profondeur (anti-leak post hard-delete)** :

    * ``created_after`` (optionnel) : restreint aux rows
      ``AIPerformanceLog.created_at >= created_after``. Posé par
      ``_check_conversation_budget`` à la ``Conversation.created_at``
      courante. Empêche un id de conversation réutilisé par SQLite
      (autoincrement sans keyword ``AUTOINCREMENT``) d'hériter des
      coûts d'une conv homonyme purgée par le hard-delete user.
    * ``user_id`` (optionnel) : restreint aux rows
      ``AIPerformanceLog.user_id == user_id``. Isolation cross-user :
      garantit qu'un cap par-conversation ne fuit pas entre comptes
      même si l'id transversal venait à coïncider.

    Les deux filtres se cumulent (AND). Si l'un est ``None``, la
    clause correspondante n'est pas posée — backward-compat
    préservée pour les callers qui ne passent pas ces paramètres.

    Defensive : retourne ``(0.0, 0)`` si conv_id vide/None, query
    échoue, ou aucune row. Ne lève jamais — le cap budget est
    best-effort et ne doit pas casser une conversation pour un
    problème d'observabilité (cf. doctrine ``record_llm_call_async``
    fail-soft).
    """
    if not conversation_id:
        return (0.0, 0)
    try:
        from sqlalchemy import case as _sa_case
        from sqlalchemy import func as _sa_func
        from sqlalchemy import select

        async with get_session() as session:
            cost_stmt = select(
                _sa_func.coalesce(_sa_func.sum(AIPerformanceLog.cost_usd_snapshot), 0.0),
                _sa_func.coalesce(
                    _sa_func.sum(
                        _sa_case(
                            (AIPerformanceLog.cost_usd_snapshot.is_(None), 1),
                            else_=0,
                        )
                    ),
                    0,
                ),
            ).where(AIPerformanceLog.conversation_id == conversation_id)
            if created_after is not None:
                cost_stmt = cost_stmt.where(AIPerformanceLog.created_at >= created_after)
            if user_id is not None:
                cost_stmt = cost_stmt.where(AIPerformanceLog.user_id == user_id)
            row = (await session.execute(cost_stmt)).one_or_none()
            if row is None:
                return (0.0, 0)
            return (float(row[0] or 0.0), int(row[1] or 0))
    except Exception as exc:  # noqa: BLE001 — fail-soft cf. doctrine module
        logger.warning(
            "get_conversation_cost_usd(conv=%s) failed: %s",
            conversation_id,
            exc,
        )
        return (0.0, 0)


async def get_conversation_cost_usd_for_ui(
    conversation_id: int | str | None,
    *,
    user_id: int | None = None,
) -> tuple[float, bool]:
    """Coût LLM cumulé d'UNE conversation, prêt pour l'affichage user (puce /iris).

    Wrapper *single source of truth* au-dessus de :func:`get_conversation_cost_usd`
    — appelé À LA FOIS par l'émission de l'event ``done`` (``agent_service``) et par
    la réhydratation de la page (``IrisPageHandler``). Centraliser ici évite deux
    implémentations divergentes du même calcul (cf. contrat « pas de duplication »).

    Retourne ``(cost_usd, cost_is_partial)`` où ``cost_is_partial`` vaut ``True``
    dès qu'au moins un appel de la conversation a un ``cost_usd_snapshot`` NULL
    (modèle hors registre pricing). L'UI affiche alors « ≥ » (coût minimum) plutôt
    qu'un chiffre faux présenté comme exact (anti « donnée fausse silencieuse »).

    **Anti-leak (corrige une donnée fausse silencieuse)** : récupère
    ``Conversation.created_at`` et le passe en ``created_after``. Après un
    hard-delete « Effacer la conversation », SQLite réutilise l'id (autoincrement
    sans mot-clé ``AUTOINCREMENT``) ; sans ce filtre, la conversation neuve
    hériterait du coût des ``AIPerformanceLog`` de la conversation purgée homonyme.
    C'est exactement ce filtre qui fait que le compteur « se réinitialise » à
    l'effacement, sans toucher aux logs (conservés pour l'audit admin).

    ``user_id`` est transmis pour l'isolation cross-user (défense en profondeur :
    un id transversal qui coïnciderait entre comptes ne fuite pas).

    Le ``conversation_id`` est casté en ``str`` AVANT la query :
    ``AIPerformanceLog.conversation_id`` est ``String(64)`` — un int provoquerait un
    mismatch de type qui sommerait silencieusement 0.0 (cf. ``iris_automation_bridge``).

    Fail-soft : ``(0.0, False)`` si conv ``None``/inexistante/erreur — un indicateur
    d'observabilité ne doit jamais casser un rendu de page ou un turn d'agent.
    """
    if conversation_id is None:
        return (0.0, False)
    try:
        from sqlalchemy import select

        from app.models.conversation import Conversation

        async with get_session() as session:
            row = (
                await session.execute(
                    select(Conversation.created_at).where(Conversation.id == int(conversation_id))
                )
            ).one_or_none()
        # Conv introuvable (jamais créée, ou purgée mid-stream) → aucun coût à
        # afficher. On préfère (0.0, False) à une query sans ``created_after``
        # (qui risquerait d'agréger des logs homonymes post-réutilisation d'id).
        if row is None:
            return (0.0, False)
        created_after = row[0]
        cost_usd, null_count = await get_conversation_cost_usd(
            str(conversation_id),
            created_after=created_after,
            user_id=user_id,
        )
        return (float(cost_usd or 0.0), null_count > 0)
    except Exception as exc:  # noqa: BLE001 — fail-soft cf. doctrine module
        logger.warning(
            "get_conversation_cost_usd_for_ui(conv=%s) failed: %s",
            conversation_id,
            exc,
        )
        return (0.0, False)


async def check_user_budget(user_id: int | None) -> tuple[bool, float, float]:
    """Garde budget par-utilisateur en mode **alerte** (détection, sans blocage).

    Retourne ``(exceeded, current_cost_usd, cap_usd)``. Détecte un dépassement
    de ``MAX_USD_PER_USER`` (fenêtre glissante ``BUDGET_WINDOW_HOURS``) pour les
    flux LLM **hors** boucle de l'agent Iris : ``plan_report`` (rapports IA) et
    ``run_copilot_agent`` (étape format des automatisations) l'appellent en mode
    ALERTE (log WARNING, pas de blocage — décision produit).

    ⚠️ **Pas une source unique** : le **chat Iris** garde sa PROPRE logique de
    plafond (``IrisAgent._check_conversation_budget`` — par-conversation, et
    **fail-CLOSED** si la conversation est purgée). Elle parse le même
    cap/fenêtre mais n'est PAS factorisée ici (logique parallèle à garder
    cohérente).

    Fail-open ``(False, 0.0, 0.0)`` si : ``user_id`` None ; cap configuré
    <= 0 ou non-numérique (admin a désactivé / corruption) ; fenêtre <= 0
    ou non-numérique ; erreur BDD (l'observabilité ne casse pas un flux).
    Lit ``MAX_USD_PER_USER`` / ``BUDGET_WINDOW_HOURS`` depuis ``ai_config``.
    """
    if user_id is None:
        return (False, 0.0, 0.0)
    try:
        from app.models.ai_config import AIConfigKey
        from app.services.ai.config_service import get_ai_config_service

        cfg = get_ai_config_service()
        cap_raw = await cfg.get(AIConfigKey.MAX_USD_PER_USER.value, default=0.0)
        window_raw = await cfg.get(AIConfigKey.BUDGET_WINDOW_HOURS.value, default=24)
        # bool est un sous-type de int — une corruption ``true`` ne doit pas
        # désactiver ni fixer silencieusement le cap (cf. _check_conversation_budget).
        if isinstance(cap_raw, bool) or isinstance(window_raw, bool):
            logger.error(
                "Budget cap config corrompu (bool) cap=%r window=%r — désactivé.",
                cap_raw,
                window_raw,
            )
            return (False, 0.0, 0.0)
        try:
            cap = float(cap_raw or 0.0)
        except (TypeError, ValueError):
            logger.error("MAX_USD_PER_USER invalide (%r) — cap désactivé.", cap_raw)
            return (False, 0.0, 0.0)
        try:
            window_hours = int(window_raw or 0)
        except (TypeError, ValueError):
            logger.error("BUDGET_WINDOW_HOURS invalide (%r) — cap désactivé.", window_raw)
            return (False, 0.0, 0.0)
        if cap <= 0 or window_hours <= 0:
            return (False, 0.0, 0.0)
        current, null_count = await get_user_cost_usd_window(
            user_id=user_id,
            window_hours=window_hours,
        )
        if null_count > 0:
            logger.info(
                "User %s: %d appel(s) LLM cost NULL sur %dh — budget sous-évalué.",
                user_id,
                null_count,
                window_hours,
            )
        return (current >= cap, current, cap)
    except Exception as exc:  # noqa: BLE001 — fail-open
        logger.warning("check_user_budget(user=%s) failed (fail-open): %s", user_id, exc)
        return (False, 0.0, 0.0)


async def get_user_cost_usd_window(
    user_id: int | None,
    window_hours: int,
) -> tuple[float, int]:
    """Retourne ``(sum_cost_usd, count_null_cost)`` pour les appels LLM
    d'un utilisateur sur une fenêtre glissante de ``window_hours``.

    Agrégation : ``SUM(cost_usd_snapshot) WHERE user_id=? AND
    created_at >= NOW(UTC) - timedelta(hours=window_hours)``.

    **Usage** : cap budget par-utilisateur avec reset automatique. La
    fenêtre est glissante (rolling) — un appel sort du cumul dès que
    son ``created_at`` est antérieur à ``now - window``. Pattern naturel
    de rate-limit budgétaire, évite les pics à minuit d'un cap calendaire.

    Le cap est commun à tous les utilisateurs (clé ai_config singleton),
    mais évalué séparément par user — analogue à
    ``STORAGE_QUOTA_PER_USER_BYTES``.

    L'index composite ``idx_perf_user_date(user_id, created_at)``
    (cf. ``AIPerformanceLog.__table_args__``) couvre exactement ce
    pattern de requête — perf O(log n).

    Defensive : retourne ``(0.0, 0)`` si user_id None/0,
    window_hours <= 0, query échoue. Ne lève jamais (doctrine
    ``record_llm_call_async`` fail-soft).
    """
    if not user_id or window_hours <= 0:
        return (0.0, 0)
    try:
        from datetime import timedelta

        from sqlalchemy import case as _sa_case
        from sqlalchemy import func as _sa_func
        from sqlalchemy import select

        # ``AIPerformanceLog.created_at`` est déclaré ``DateTime`` sans
        # ``timezone=True`` (SQLAlchemy strip le tz à l'INSERT). Comparer
        # une valeur tz-aware avec une colonne tz-naive lève TypeError
        # sur Postgres (silencieux sur SQLite). On strip le tz du
        # threshold pour rester compatible cross-dialect.
        threshold = (clock.now() - timedelta(hours=window_hours)).replace(tzinfo=None)
        async with get_session() as session:
            cost_stmt = (
                select(
                    _sa_func.coalesce(
                        _sa_func.sum(AIPerformanceLog.cost_usd_snapshot),
                        0.0,
                    ),
                    _sa_func.coalesce(
                        _sa_func.sum(
                            _sa_case(
                                (
                                    AIPerformanceLog.cost_usd_snapshot.is_(None),
                                    1,
                                ),
                                else_=0,
                            )
                        ),
                        0,
                    ),
                )
                .where(AIPerformanceLog.user_id == user_id)
                .where(AIPerformanceLog.created_at >= threshold)
            )
            row = (await session.execute(cost_stmt)).one_or_none()
            if row is None:
                return (0.0, 0)
            return (float(row[0] or 0.0), int(row[1] or 0))
    except Exception as exc:  # noqa: BLE001 — fail-soft cf. doctrine module
        logger.warning(
            "get_user_cost_usd_window(user_id=%s, window_h=%s) failed: %s",
            user_id,
            window_hours,
            exc,
        )
        return (0.0, 0)


# ─────────────────────────────────────────────────────────────────────────
# Streaming aggregator
# ─────────────────────────────────────────────────────────────────────────


class StreamAccountingWrapper:
    """Wrapper pour aggreger les tokens d'un async generator streaming.

    Anthropic SSE émet :
    * ``message_start`` avec ``message.usage.input_tokens`` (initial)
    * ``message_delta`` avec ``usage.output_tokens`` (cumulatif)
    * ``message_stop`` (fin)

    OpenAI streaming chunks ont un ``usage`` final si
    ``stream_options.include_usage=True`` est posé (le code provider
    le pose systématiquement).

    Usage::

        async with StreamAccountingWrapper(
            provider_name="anthropic",
            request=request,
        ) as wrapper:
            async for event in provider.stream_with_tools(...):
                wrapper.observe(event)
                yield event
        # à la sortie du ``with``, le snapshot est persisté.

    L'``__aexit__`` flush en BDD même en cas d'exception (tokens partiels
    + status=LLM_ERROR si une exception traverse).
    """

    def __init__(
        self,
        *,
        provider_name: str,
        request: Any,
    ) -> None:
        self.provider_name = provider_name
        self.request = request
        self._start_ts: Optional[float] = None
        self._error: Optional[BaseException] = None
        # Accumulateurs pour reconstituer un response-like dict
        self._prompt_tokens: Optional[int] = None
        self._completion_tokens: Optional[int] = None
        self._cache_read: Optional[int] = None
        self._cache_creation: Optional[int] = None
        self._thinking: Optional[int] = None
        self._model: Optional[str] = None
        self._row_id: Optional[int] = None
        # Flush idempotent : ``asyncio.Lock`` pour qu'un appel concurrent
        # à ``flush`` ne crée pas deux rows (le `_row_id is not None`
        # check seul est insuffisant — `await record_llm_call_async`
        # yield le loop avant d'assigner _row_id).
        self._flush_lock = asyncio.Lock()
        # Capture du contexte (caller, conversation_id) au MOMENT de la
        # création du wrapper. Sinon le ``flush()`` final lit les
        # ContextVars tardivement, et si le caller a quitté son
        # ``llm_call_context(...)`` entretemps, on logue avec caller=NULL.
        self._captured_caller = current_caller()
        self._captured_conversation = current_conversation_id()
        self._captured_request_id = current_request_id()
        self._captured_user_id = current_user_id()

    async def __aenter__(self) -> "StreamAccountingWrapper":
        self._start_ts = asyncio.get_event_loop().time()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self._error = exc
        await self.flush()
        # Ne pas avaler l'exception — on relog status=LLM_ERROR puis on laisse
        # remonter (return False / None au lieu de True).

    def observe(self, event: Any) -> None:
        """Met à jour les compteurs depuis un event SSE.

        Tolère :
        * Events Anthropic dict (``{"type": "message_start"|"message_delta", ...}``)
        * Events OpenAI dict (chunk avec ``"usage"`` final)
        * Strings ou autres types → ignore silencieusement
        """
        if not isinstance(event, dict):
            return
        ev_type = event.get("type")

        # Anthropic message_start : usage initial
        if ev_type == "message_start":
            msg = event.get("message") or {}
            usage = msg.get("usage") or {}
            self._merge_usage(usage)
            self._model = self._model or msg.get("model")
            return

        # Anthropic message_delta : usage cumulatif (overwrite, pas additif)
        if ev_type == "message_delta":
            usage = event.get("usage") or {}
            self._merge_usage(usage, additive_for_output=False)
            return

        # OpenAI compat — chunks avec ``usage`` final (provider l'a converti
        # en message_delta-like via _convert_openai_response_to_anthropic
        # pour stream_with_tools, mais on tolère les deux formats au cas où).
        if "usage" in event and isinstance(event["usage"], dict):
            self._merge_usage(event["usage"], additive_for_output=False)
            return

    def _merge_usage(
        self,
        usage: dict[str, Any],
        *,
        additive_for_output: bool = True,
    ) -> None:
        if not isinstance(usage, dict):
            return
        # Input tokens — Anthropic envoie au start, OpenAI à la fin.
        # On prend la valeur la plus récente NON-zéro pour éviter qu'un
        # ``input_tokens=0`` initial (cas cache 100%) écrase une valeur
        # réelle qui arriverait après. ``max`` est correct car les
        # providers fournissent une valeur cumulative ou unique.
        p = usage.get("input_tokens")
        if p is None:
            p = usage.get("prompt_tokens")
        if p is not None:
            p_int = int(p)
            if self._prompt_tokens is None or p_int > self._prompt_tokens:
                self._prompt_tokens = p_int

        # Output tokens — Anthropic message_delta envoie cumulatif (overwrite).
        # OpenAI final chunk envoie aussi cumulatif.
        c = usage.get("output_tokens")
        if c is None:
            c = usage.get("completion_tokens")
        if c is not None:
            if additive_for_output and self._completion_tokens is not None:
                self._completion_tokens = self._completion_tokens + int(c)
            else:
                self._completion_tokens = int(c)

        # Cache + thinking — préférer la dernière valeur non-zéro, même
        # logique que prompt_tokens.
        cr = usage.get("cache_read_input_tokens")
        if cr is not None:
            cr_int = int(cr)
            if self._cache_read is None or cr_int > self._cache_read:
                self._cache_read = cr_int
        cc = usage.get("cache_creation_input_tokens")
        if cc is not None:
            cc_int = int(cc)
            if self._cache_creation is None or cc_int > self._cache_creation:
                self._cache_creation = cc_int
        thinking = (
            usage.get("thinking_tokens")
            or usage.get("reasoning_tokens")
            or (usage.get("completion_tokens_details") or {}).get("reasoning_tokens")
        )
        if thinking is not None:
            self._thinking = int(thinking)

    def _build_response_dict(self) -> dict[str, Any]:
        """Reconstitue un response-like dict pour ``build_snapshot``."""
        return {
            "model": self._model,
            "usage": {
                "input_tokens": self._prompt_tokens,
                "output_tokens": self._completion_tokens,
                "cache_read_input_tokens": self._cache_read,
                "cache_creation_input_tokens": self._cache_creation,
                "thinking_tokens": self._thinking,
            },
        }

    async def flush(self) -> Optional[int]:
        """Persiste les tokens aggregés. Idempotent (no-op si déjà flushed).

        Restaure le ContextVar capturé à l'init pour que ``record_llm_call_async``
        lise les bonnes valeurs même si le caller a quitté son
        ``llm_call_context(...)`` entretemps. Lock pour éviter le double-flush
        concurrent.
        """
        async with self._flush_lock:
            if self._row_id is not None:
                return self._row_id
            duration = None
            if self._start_ts is not None:
                try:
                    duration = max(0.0, asyncio.get_event_loop().time() - self._start_ts)
                except RuntimeError:
                    duration = None
            # Restaurer le contexte capturé à __init__. ``llm_call_context``
            # est nestable — innermost wins — donc on pose temporairement
            # le caller capturé. Si on est encore dans un with original,
            # le caller posé écrase le current pour la durée du flush
            # puis sera restauré via le `with` (notre ContextVar tokens).
            from app.utils.request_context import (
                _caller as _caller_var,
                _conversation_id as _conv_var,
                _request_id as _req_var,
                _user_id as _user_var,
            )

            tokens = []
            if self._captured_caller:
                tokens.append((_caller_var, _caller_var.set(self._captured_caller)))
            if self._captured_conversation is not None:
                tokens.append((_conv_var, _conv_var.set(self._captured_conversation)))
            if self._captured_request_id:
                tokens.append((_req_var, _req_var.set(self._captured_request_id)))
            if self._captured_user_id is not None:
                tokens.append((_user_var, _user_var.set(self._captured_user_id)))
            try:
                self._row_id = await record_llm_call_async(
                    request=self.request,
                    response=self._build_response_dict(),
                    provider_name=self.provider_name,
                    duration_seconds=duration,
                    error=self._error,
                )
            finally:
                # Restaurer les ContextVars dans l'ordre inverse.
                for var, tok in reversed(tokens):
                    try:
                        var.reset(tok)
                    except ValueError:
                        # Si on est dans une autre task / loop, reset peut
                        # échouer — pas critique, le ContextVar finira
                        # par être garbage-collected.
                        pass
            return self._row_id


async def wrap_stream(
    *,
    provider_name: str,
    request: Any,
    source: AsyncGenerator[dict, None],
) -> AsyncGenerator[dict, None]:
    """Enrobe un async generator streaming pour aggréger les tokens.

    Usage dans ``LLMManager.stream_with_tools``::

        async for event in wrap_stream(
            provider_name=provider.provider_name,
            request=request,
            source=provider.stream_with_tools(...),
        ):
            yield event

    Le ``finally`` flush la ligne BDD même si le caller annule (CancelledError)
    ou que le provider lève en plein stream — on capture la consommation
    partielle avec ``status=LLM_ERROR``.
    """
    wrapper = StreamAccountingWrapper(provider_name=provider_name, request=request)
    async with wrapper:
        async for event in source:
            wrapper.observe(event)
            yield event
