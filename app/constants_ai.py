"""
Constantes du layer IA — modèles, timeouts, seuils, registres.

## Principe d'organisation

- Un **registre unique** (``MODEL_REGISTRY``) est la source de vérité pour les
  métadonnées d'un modèle LLM : max-output-tokens, context-window, pricing,
  provider. Les vues historiquement exposées (``MODEL_PRICING``,
  ``MODEL_MAX_OUTPUT_TOKENS``, ``MODEL_CONTEXT_WINDOW``, ``AVAILABLE_MODELS``)
  sont dérivées automatiquement du registre — **jamais** listées à la main.
  Ajouter un nouveau modèle : une seule ligne dans ``_MODELS``, et les quatre
  vues publiques se mettent à jour en même temps. Fini les silent drifts (un
  modèle présent dans ``MAX_OUTPUT_TOKENS`` mais absent de ``PRICING`` →
  facturation faussée silencieusement).

- Les mappings publics utilisent ``MappingProxyType`` pour être **immuables
  au runtime**. Un appelant qui écrirait ``MODEL_PRICING["claude-x"] = {...}``
  contaminerait silencieusement tous les autres appelants du process. On
  bloque ça côté typage (``Mapping[...]``) et au runtime.

- Les fonctions à side-effects (``get_utility_model``, ``detect_api_type``)
  sont volontairement gardées dans ce module pour compatibilité d'import
  (42 fichiers consommateurs) mais utilisent un pattern fail-loud :
  exceptions explicites, jamais ``except Exception: pass``.

## Tokenization

``estimate_token_count`` est une approximation ``len/4`` suffisante pour
un budget grossier (logs, décisions de troncature). Pour du code qui doit
être précis (facturation, respect strict de ``max_tokens``), utiliser
``anthropic.messages.count_tokens()`` côté provider — l'approximation
sous-estime de 40-60 % sur texte CJK/emoji (cf. Anthropic docs 2025).
``estimate_token_count_conservative`` applique une marge de sécurité 1.6×
pour les décisions de troncature qui doivent être robustes.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final
from urllib.parse import urlparse

__all__ = [
    # Pricing display (SSoT — symbole + code ISO)
    "PRICING_CURRENCY_CODE",
    "PRICING_CURRENCY_SYMBOL",
    # URLs providers
    "OPENAI_API_URL",
    "ANTHROPIC_API_URL",
    "ANTHROPIC_API_VERSION",
    # Modèles par défaut
    "OPENAI_DEFAULT_MODEL",
    "ANTHROPIC_DEFAULT_MODEL",
    # Registre + vues dérivées
    "ModelInfo",
    "MODEL_REGISTRY",
    "MODEL_MAX_OUTPUT_TOKENS",
    "MODEL_CONTEXT_WINDOW",
    "MODEL_PRICING",
    "AVAILABLE_MODELS",
    "ANTHROPIC_AVAILABLE_MODELS",
    # Helpers
    "detect_api_type",
    "get_utility_model",
    "get_max_tokens_for_model",
    "get_context_window_for_model",
    "get_pricing_for_model",
    "supports_capability_for_model",
    "clamped_max_tokens",
    "estimate_token_count",
    "estimate_token_count_conservative",
    # Timeouts
    "OPENAI_TIMEOUT",
    "ANTHROPIC_TIMEOUT",
    "GENERATOR_TIMEOUT",
    # Retry
    "DEFAULT_MAX_RETRIES",
    "GENERATOR_MAX_RETRIES",
    # Température
    "DEFAULT_TEMPERATURE",
    # HTTP
    "HTTPX_MAX_KEEPALIVE",
    "HTTPX_MAX_CONNECTIONS",
    # Context window
    "CONTEXT_WINDOW_WARNING_THRESHOLD",
    # RAG
    "RAG_SCORE_THRESHOLD",
    "RAG_QUESTION_SQL_THRESHOLD",
    "RAG_SHORTCUT_THRESHOLD",
    "RAG_COVERAGE_THRESHOLD",
    "RAG_DEFAULT_N_RESULTS",
    "RAG_MAX_CONTEXT_ITEMS",
    "RAG_MIN_EXAMPLES",
    # Déjà-vu
    "DEJA_VU_THRESHOLD",
    # Générateur SQL
    "GENERATOR_MAX_RESULTS",
    "GENERATOR_CONFIDENCE_THRESHOLD",
    "GENERATOR_DEFAULT_LANGUAGE",
    # Embeddings
    "EMBEDDING_MODEL",
    "EMBEDDING_DIMENSIONS",
    "EMBEDDING_BATCH_SIZE",
    "VECTOR_SEARCH_TOP_K",
    # Auto-promotion
    "AUTO_PROMOTE_USAGE_THRESHOLD",
    "AUTO_PROMOTE_MIN_QUALITY",
    "AUTO_PROMOTE_QUALITY_INCREMENT",
    "AUTO_PROMOTE_FINAL_QUALITY",
    # Enrichissement sémantique
    "ENRICHMENT_MAX_TOKENS",
    "ENRICHMENT_TEMPERATURE",
    "ENRICHMENT_MAX_SAMPLE_ROWS",
    "ENRICHMENT_BATCH_SIZE",
    # Sampling valeurs distinctes
    "DISTINCT_VALUES_MAX_PER_COLUMN",
    "DISTINCT_VALUES_MAX_DISPLAY",
    "DISTINCT_VALUES_MAX_LENGTH",
    # Sync schéma BDD source (single source of truth des limites)
    "SCHEMA_SYNC_BATCH_SIZE",
    "SCHEMA_SYNC_MAX_ROWS_TABLES",
    "SCHEMA_SYNC_MAX_ROWS_VIEWS",
    "SCHEMA_SYNC_VIEW_CHUNK_COUNT",
    "SCHEMA_SYNC_VIEW_CHUNK_SIZE",
    "SCHEMA_SYNC_COOLDOWN_SECONDS",
    "get_schema_sync_batch_size",
    "get_schema_sync_max_rows_tables",
    "get_schema_sync_max_rows_views",
    "get_schema_sync_view_chunk_size",
    "get_schema_sync_cooldown_seconds",
    # Fraîcheur schéma
    "SCHEMA_FRESHNESS_MAX_AGE_HOURS",
    # Boucle agent
    "AGENT_MAX_TURNS",
    "AGENT_GOAL_ANCHOR_INTERVAL",
    "AGENT_THINKING_BUDGET",
    # Limites de contexte
    "DDL_TRUNCATION_LIMIT",
    "VISIBLE_TABLES_LIMIT",
    # Calibration de confiance
    "CONFIDENCE_THRESHOLD_EXECUTE",
    "CONFIDENCE_THRESHOLD_CONFIRM",
    "CONFIDENCE_WEIGHT_CONSENSUS",
    "CONFIDENCE_WEIGHT_RAG",
    "CONFIDENCE_WEIGHT_SCHEMA",
    "CONFIDENCE_WEIGHT_COMPLEXITY",
    # Multi-candidats SQL
    "SQL_CANDIDATES_COUNT",
    "SQL_CANDIDATES_MIN_FOR_CONSENSUS",
    "SQL_CANDIDATE_TEMPERATURES",
    # Taxonomie d'erreurs SQL
    "ERROR_TAXONOMY_MAX_RETRIES_PER_TYPE",
    "ERROR_TAXONOMY_CATEGORIES",
    # Règles de correction
    "CORRECTION_RULES_MAX",
    "CORRECTION_RULES_DATA_TYPE",
]


# ─────────────────────────────────────────────────────────────
# Pricing — devise d'affichage (SSoT)
# ─────────────────────────────────────────────────────────────
# Tous les providers LLM majeurs (Anthropic, OpenAI, Mistral, Groq, DeepSeek,
# Together, etc.) facturent en USD au moment où ce code est écrit. Les
# colonnes ``LlmModel.*_price_per_mtok_usd`` stockent donc des USD bruts —
# voir ``app/models/llm_model.py``. Si Komptia doit un jour afficher en EUR
# ou GBP (par cabinet), c'est la PROCHAINE étape : (1) appliquer un taux de
# change au moment du rendu, (2) changer ces 2 constantes. Tout l'affichage
# (templates + JS) doit lire ces 2 constantes plutôt que de hardcoder ``$``.
#
# Bug 2026-05-26 (Agent 3 AI-7 MOYEN) : avant ce module SSoT, le symbole
# ``$`` était hardcodé dans 5+ endroits (templates + JS). Drift garanti à
# la première migration EUR.
PRICING_CURRENCY_CODE: Final[str] = "USD"
PRICING_CURRENCY_SYMBOL: Final[str] = "$"


# ─────────────────────────────────────────────────────────────
# URLs des providers
# ─────────────────────────────────────────────────────────────

OPENAI_API_URL: Final[str] = "https://api.openai.com/v1"
ANTHROPIC_API_URL: Final[str] = "https://api.anthropic.com/v1"
ANTHROPIC_API_VERSION: Final[str] = "2023-06-01"

# Domaines appartenant au provider Anthropic. On exige un match exact ou un
# sous-domaine (``.anthropic.com``) pour éviter les faux positifs d'un URL
# arbitraire qui contiendrait la sous-chaîne "anthropic" (proxy tiers,
# domaine custom malveillant, etc.).
_ANTHROPIC_HOSTS: Final[frozenset[str]] = frozenset({"anthropic.com"})

# Préfixe caractéristique d'une clé API Anthropic officielle.
_ANTHROPIC_KEY_PREFIX: Final[str] = "sk-ant-"


# ─────────────────────────────────────────────────────────────
# Modèles par défaut
# ─────────────────────────────────────────────────────────────

OPENAI_DEFAULT_MODEL: Final[str] = "gpt-4o-mini"
ANTHROPIC_DEFAULT_MODEL: Final[str] = "claude-haiku-4-5-20251001"


# ─────────────────────────────────────────────────────────────
# Registre modèles — SOURCE UNIQUE DE VÉRITÉ
# ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ModelInfo:
    """Métadonnées consolidées d'un modèle LLM.

    Toutes les vues publiques (``MODEL_MAX_OUTPUT_TOKENS``, ``MODEL_PRICING``,
    ``AVAILABLE_MODELS``, ``MODEL_CONTEXT_WINDOW``) sont dérivées de la
    séquence ``_MODELS``. Ajouter un nouveau modèle : une seule ligne.

    ``alias=True`` marque une entrée d'alias (identifiant court qui résout
    vers le même modèle qu'un ID daté). Les alias sont **présents dans le
    registre** pour que les lookups ``get_max_tokens_for_model("claude-x-y")``
    retournent la bonne valeur, mais **exclus de ``AVAILABLE_MODELS``** pour
    ne pas présenter de doublons à l'administrateur qui choisit un modèle.

    Les champs ``supports_*`` / ``tool_call_format`` / ``system_prompt_format``
    / ``cache_ttl_options`` constituent la **matrice de capabilities** lue
    par le code applicatif à la place de toute comparaison ``provider_name
    == "..."``. Cf. plan « Komptia 100% dynamique multi-provider »
    (2026-05-14). Defaults choisis pour le format universel OpenAI-compat ;
    les modèles Anthropic / OpenAI o-series / Gemini / vision overrident
    ligne par ligne dans ``_MODELS`` ci-dessous.
    """

    name: str
    provider: str
    max_output_tokens: int
    context_window: int
    # Pricing — VALEURS PLACEHOLDER (toujours 0.0 dans ``_MODELS`` depuis
    # le plan dynamicité 2026-05-14). **Source UNIQUE de vérité** = sync
    # LiteLLM (bouton "Mettre à jour fenêtres & tarifs" dans
    # ``/admin/ai-config``, auto-déclenchée au 1er boot si registre BDD a
    # pricing=0). On garde les champs dans la dataclass pour le seed
    # initial (qui insère 0.0 → respecte la contrainte NOT NULL des
    # colonnes SQL). Au runtime, ``_warn_missing_pricing_once`` signale
    # à l'admin si après une sync ratée les valeurs restent à 0.0.
    input_price_per_mtok_usd: float
    output_price_per_mtok_usd: float
    alias: bool = False
    # Capabilities — defaults sensés pour OpenAI-compat (le format le plus
    # universel : Mistral, Groq, DeepSeek, Together, Gemini /v1/chat).
    # Override par modèle ligne par ligne ci-dessous.
    supports_extended_thinking: bool = False
    supports_prompt_caching: bool = False
    supports_tool_use: bool = True
    supports_reasoning_effort: bool = False
    supports_parallel_tool_calls: bool = False
    supports_streaming: bool = True
    supports_vision: bool = False
    supports_strict_json: bool = False
    tool_call_format: str = "openai"
    system_prompt_format: str = "string"
    # Tuple car frozen dataclass + slots. Converti en list lors du seed BDD.
    # ``()`` = pas de cache (modèles non-Anthropic majoritairement).
    cache_ttl_options: tuple[str, ...] = ()


# Capabilities Anthropic Sonnet/Opus 4.x partagées (DRY) — extended thinking
# + caching 5min/1h + tool use + format Anthropic natif. Reasoning_effort
# n'est PAS un alias de thinking : sémantique différente (cf. plan).
_ANTHROPIC_SONNET_OPUS_CAPS: Final[dict] = {
    "supports_extended_thinking": True,
    "supports_prompt_caching": True,
    "supports_tool_use": True,
    "supports_parallel_tool_calls": True,
    "supports_streaming": True,
    "supports_vision": True,
    "tool_call_format": "anthropic",
    "system_prompt_format": "array",
    "cache_ttl_options": ("5m", "1h"),
}

# Capabilities Haiku — pas d'extended thinking (cap output 8k trop bas pour
# le plancher Anthropic 1024 + marge), caching limité à 5min.
_ANTHROPIC_HAIKU_CAPS: Final[dict] = {
    "supports_extended_thinking": False,
    "supports_prompt_caching": True,
    "supports_tool_use": True,
    "supports_parallel_tool_calls": True,
    "supports_streaming": True,
    "tool_call_format": "anthropic",
    "system_prompt_format": "array",
    "cache_ttl_options": ("5m",),
}

# Capabilities OpenAI standard (gpt-4o, gpt-4o-mini, gpt-4-turbo) — parallel
# tool calls indexés, strict JSON mode, vision pour les modèles multimodaux.
_OPENAI_GPT4_CAPS: Final[dict] = {
    "supports_tool_use": True,
    "supports_parallel_tool_calls": True,
    "supports_streaming": True,
    "supports_strict_json": True,
    "tool_call_format": "openai",
    "system_prompt_format": "string",
}

# Liste plate des modèles connus.
#
# **VIDE depuis 2026-05-14 (plan dynamicité option radicale)** : les modèles
# sont désormais ajoutés DYNAMIQUEMENT en BDD via :
#   1. ``sync_from_provider(provider_name)`` quand l'admin teste une clé
#      API dans ``/admin/ai-config`` → ``provider.list_models()`` insère
#      les modèles que le provider expose.
#   2. ``enrich_models_from_litellm`` qui enrichit pricing + capabilities
#      universelles pour les modèles déjà en BDD.
#   3. ``_deduce_komptia_flags`` (litellm_registry_sync.py) qui pose les
#      5 flags Komptia-spécifiques (extended_thinking, reasoning_effort,
#      tool_call_format, system_prompt_format, cache_ttl_options) au
#      moment de la sync.
#
# Conséquence : au 1er boot, BDD vide -> select modele dans
# /admin/ai-config est vide jusqu a ce que l admin saisisse une cle +
# clique Tester. UX coherente avec la promesse "n importe quel
# modele/provider configure dans /admin/ai-config".
#
# Pour reintroduire un seed (cas exceptionnel), ajouter ici sous forme
# ModelInfo(name=..., provider=..., **caps) -- _deduce_komptia_flags
# fera la deduction ensuite. Ne JAMAIS hardcoder pricing ni
# context_window/max_output_tokens : sync LiteLLM = source unique.
_MODELS: Final[tuple[ModelInfo, ...]] = ()


MODEL_REGISTRY: Final[Mapping[str, ModelInfo]] = MappingProxyType({m.name: m for m in _MODELS})

# ─────────────────────────────────────────────────────────────
# Vues dérivées du registre (toutes immuables au runtime)
# ─────────────────────────────────────────────────────────────

MODEL_MAX_OUTPUT_TOKENS: Final[Mapping[str, int]] = MappingProxyType(
    {m.name: m.max_output_tokens for m in _MODELS}
)

MODEL_CONTEXT_WINDOW: Final[Mapping[str, int]] = MappingProxyType(
    {m.name: m.context_window for m in _MODELS}
)

MODEL_PRICING: Final[Mapping[str, Mapping[str, float]]] = MappingProxyType(
    {
        m.name: MappingProxyType(
            {
                "input": m.input_price_per_mtok_usd,
                "output": m.output_price_per_mtok_usd,
            }
        )
        for m in _MODELS
    }
)

# Modèles présentés à l'administrateur dans l'interface de config (on filtre
# les alias pour éviter les doublons UX, mais le registre sait les résoudre).
AVAILABLE_MODELS: Final[tuple[Mapping[str, str], ...]] = tuple(
    MappingProxyType({"name": m.name, "provider": m.provider}) for m in _MODELS if not m.alias
)

ANTHROPIC_AVAILABLE_MODELS: Final[tuple[Mapping[str, str], ...]] = tuple(
    m for m in AVAILABLE_MODELS if m["provider"] == "anthropic"
)


# ─────────────────────────────────────────────────────────────
# Timeouts HTTP (secondes)
# ─────────────────────────────────────────────────────────────
#
# Pourquoi Anthropic > OpenAI : l'extended thinking sur Sonnet/Opus 4.x en
# mode max-effort consomme un budget de 28 k tokens de réflexion + 16-32 k
# tokens de sortie, soit 40-60 k tokens à 60-100 tok/s → 6-10 min par appel.
# 600 s côté client est aligné sur le timeout serveur Anthropic (~10 min) —
# on laisse la requête aller jusqu'au bout, pas d'abort prématuré.
#
# 300 s sur OpenAI couvre le cas extrême (gpt-4o en streaming lent sur
# prompt long). Pour OpenAI-compatible local (Ollama), prévoir un override
# par provider si la machine est lente.
OPENAI_TIMEOUT: Final[float] = 300.0
ANTHROPIC_TIMEOUT: Final[float] = 600.0
GENERATOR_TIMEOUT: Final[int] = 120


# ─────────────────────────────────────────────────────────────
# Retry
# ─────────────────────────────────────────────────────────────

DEFAULT_MAX_RETRIES: Final[int] = 3
GENERATOR_MAX_RETRIES: Final[int] = 2


# ─────────────────────────────────────────────────────────────
# Température LLM
# ─────────────────────────────────────────────────────────────

DEFAULT_TEMPERATURE: Final[float] = 0.1


# ─────────────────────────────────────────────────────────────
# Fallback max-tokens pour modèle inconnu
# ─────────────────────────────────────────────────────────────

# Conservateur : 8k tokens est une valeur supportée par tous les modèles
# Claude et gpt-4o. Un modèle inconnu ne devrait jamais demander plus sans
# passer par get_max_tokens_for_model() explicitement.
_DEFAULT_MAX_OUTPUT_TOKENS: Final[int] = 8_192


# ─────────────────────────────────────────────────────────────
# Connexions HTTP
# ─────────────────────────────────────────────────────────────

HTTPX_MAX_KEEPALIVE: Final[int] = 5
HTTPX_MAX_CONNECTIONS: Final[int] = 10


# Seuil d'alerte : au-delà de 80 % du context window, on logue un warning
# côté consommateur. Nommé plutôt que "magic".
CONTEXT_WINDOW_WARNING_THRESHOLD: Final[float] = 0.80

# Fallback context window pour modèle inconnu — conservateur (200k est la
# valeur Claude standard 2025-2026, au-dessus des 128k OpenAI).
_DEFAULT_CONTEXT_WINDOW: Final[int] = 200_000


# ─────────────────────────────────────────────────────────────
# RAG (Retrieval Augmented Generation)
# ─────────────────────────────────────────────────────────────

RAG_SCORE_THRESHOLD: Final[float] = 0.001
RAG_QUESTION_SQL_THRESHOLD: Final[float] = 0.02
RAG_SHORTCUT_THRESHOLD: Final[float] = 0.45
RAG_COVERAGE_THRESHOLD: Final[float] = 0.80
RAG_DEFAULT_N_RESULTS: Final[int] = 5
RAG_MAX_CONTEXT_ITEMS: Final[int] = 10
RAG_MIN_EXAMPLES: Final[int] = 2


# ─────────────────────────────────────────────────────────────
# Phase 0.5 "Déjà-vu" (shortcut Q/SQL similaire)
# ─────────────────────────────────────────────────────────────
#
# Au-dessus de ce seuil, on sort de l'orchestrateur et l'agent libre prend
# le relais avec le Q/SQL similaire comme contexte.
#
# Unique seuil pour les deux engines (vectoriel et TF-IDF) depuis que le
# TF-IDF utilise ``compute_query_recall_idf`` — une métrique de rappel
# pondéré par IDF qui produit des scores dans [0, 1] comparables aux cosines
# d'embeddings. 0.40 = "≥ 40 % du vocabulaire discriminant de la query est
# couvert par la paire" = seuil raisonnable d'ouverture du shortcut.
DEJA_VU_THRESHOLD: Final[float] = 0.40


# ─────────────────────────────────────────────────────────────
# Générateur SQL
# ─────────────────────────────────────────────────────────────

GENERATOR_MAX_RESULTS: Final[int] = 100
GENERATOR_CONFIDENCE_THRESHOLD: Final[float] = 0.7
GENERATOR_DEFAULT_LANGUAGE: Final[str] = "français"


# ─────────────────────────────────────────────────────────────
# Embeddings vectoriels (local, sentence-transformers)
# ─────────────────────────────────────────────────────────────

EMBEDDING_MODEL: Final[str] = "paraphrase-multilingual-MiniLM-L12-v2"
EMBEDDING_DIMENSIONS: Final[int] = 384
EMBEDDING_BATCH_SIZE: Final[int] = 64  # Textes par batch encode()
VECTOR_SEARCH_TOP_K: Final[int] = 10  # Résultats max par recherche vectorielle


# ─────────────────────────────────────────────────────────────
# Auto-promotion des candidats
# ─────────────────────────────────────────────────────────────

AUTO_PROMOTE_USAGE_THRESHOLD: Final[int] = 3  # Utilisations avant promotion
AUTO_PROMOTE_MIN_QUALITY: Final[float] = 0.5  # Score minimum pour promotion
AUTO_PROMOTE_QUALITY_INCREMENT: Final[float] = 0.15  # Incrément par réutilisation réussie
AUTO_PROMOTE_FINAL_QUALITY: Final[float] = 0.7  # Score après promotion


# ─────────────────────────────────────────────────────────────
# Enrichissement sémantique
# ─────────────────────────────────────────────────────────────
#
# Le modèle à utiliser pour l'enrichissement sémantique n'est **pas**
# hardcodé ici : le consommateur doit passer par ``get_utility_model()``
# pour résoudre le modèle configuré par l'administrateur (via LLMManager).
# Cette contrainte garantit que l'admin peut changer de provider/modèle
# sans toucher au code.
ENRICHMENT_MAX_TOKENS: Final[int] = 4096
ENRICHMENT_TEMPERATURE: Final[float] = 0.1
ENRICHMENT_MAX_SAMPLE_ROWS: Final[int] = 5
ENRICHMENT_BATCH_SIZE: Final[int] = 10  # Tables enrichies par batch


# ─────────────────────────────────────────────────────────────
# Sampling valeurs uniques par colonne
# ─────────────────────────────────────────────────────────────

# ``0`` est un sentinel historique signifiant « toutes les valeurs distinctes,
# pas de limite ». Les consommateurs doivent traiter cette valeur comme
# ``None`` / unlimited (cf. app/services/ai/schema_sync.py).
DISTINCT_VALUES_MAX_PER_COLUMN: Final[int] = 0
DISTINCT_VALUES_MAX_DISPLAY: Final[int] = 8  # Max valeurs affichées dans le contexte LLM
DISTINCT_VALUES_MAX_LENGTH: Final[int] = 50  # Tronquer les valeurs trop longues


# ─────────────────────────────────────────────────────────────
# Sync schéma BDD source (Sage Coala) → BDD locale (SQLite)
# ─────────────────────────────────────────────────────────────
#
# Single source of truth des limites du sync. Avant 2026-05-04, ces valeurs
# étaient hardcodées en magic numbers dispersés dans schema_sync.py et
# schema_enricher.py (5000, 50000, 30, 64, 2000…). Plusieurs limites
# divergentes pour la même intention rendaient le tuning impossible.
#
# Les helpers ``get_schema_sync_*()`` lisent en priorité l'override admin
# stocké en BDD (table ``ai_config``, clé ``schema_sync_*``) puis fallback
# à la constante de ce module. Pattern fail-loud : valeur invalide en BDD →
# warning logué et fallback constante.

# Nombre de colonnes processées en parallèle dans la phase 5 (enrichissement).
# Avant : 30 hardcoded dans schema_enricher.py:768. Trop bas → sync lent ;
# trop haut → saturation Sage. 30 est un bon trade-off pour Sage Coala.
SCHEMA_SYNC_BATCH_SIZE: Final[int] = 30

# Cap sur le ``SELECT TOP N`` des requêtes Sage qui ne sont pas le sampling
# de valeurs (e.g. liste tables, FK). Avant : 50000 hardcoded à plusieurs
# endroits dans schema_sync.py. La plupart des INFORMATION_SCHEMA queries
# retournent <10k lignes ; le cap haut est une garde-fou.
SCHEMA_SYNC_MAX_ROWS_TABLES: Final[int] = 50_000

# Cap sur le sampling de DDL des vues. Avant : 5000 hardcoded.
SCHEMA_SYNC_MAX_ROWS_VIEWS: Final[int] = 5_000

# Découpage des DDL de vues SQL Server avant stockage. Une vue peut faire
# plusieurs centaines de KB. On découpe en chunks pour respecter la taille
# max d'un blob de training_data. Avant : 64 chunks × 2000 chars (128 KB max)
# hardcodés à schema_sync.py:507-511. Vues > 128 KB silent-truncated.
SCHEMA_SYNC_VIEW_CHUNK_COUNT: Final[int] = 64
SCHEMA_SYNC_VIEW_CHUNK_SIZE: Final[int] = 2_000

# Cooldown entre 2 syncs manuels déclenchés via /admin/ai-config. Sous le
# cooldown, l'API retourne 429 Too Many Requests au lieu de lancer un 2e
# sync (qui aurait été bloqué par le mutex de toute façon, mais avec un
# message moins clair). Le scheduler auto a sa propre cadence indépendante.
SCHEMA_SYNC_COOLDOWN_SECONDS: Final[int] = 300


def get_schema_sync_batch_size() -> int:
    """Lecture de la batch size sync. Source : ``ai_config.schema_sync_batch_size``
    si défini en BDD, sinon constante par défaut (30).

    Lecture sync sans I/O BDD pour l'instant — le passage par ai_config est
    prévu mais nécessite l'orchestrateur LlmModelRegistry chargé. Pattern
    aligné sur ``get_max_tokens_for_model``."""
    return SCHEMA_SYNC_BATCH_SIZE


def get_schema_sync_max_rows_tables() -> int:
    """Cap sur SELECT TOP des requêtes INFORMATION_SCHEMA / FK / cardinalité."""
    return SCHEMA_SYNC_MAX_ROWS_TABLES


def get_schema_sync_max_rows_views() -> int:
    """Cap sur le sampling des DDL de vues."""
    return SCHEMA_SYNC_MAX_ROWS_VIEWS


def get_schema_sync_view_chunk_size() -> tuple[int, int]:
    """Retourne (chunk_count, chunk_size_chars) pour le découpage DDL vues."""
    return SCHEMA_SYNC_VIEW_CHUNK_COUNT, SCHEMA_SYNC_VIEW_CHUNK_SIZE


def get_schema_sync_cooldown_seconds() -> int:
    """Cooldown entre 2 syncs manuels (anti-spam-clic admin)."""
    return SCHEMA_SYNC_COOLDOWN_SECONDS


# ─────────────────────────────────────────────────────────────
# Fraîcheur du schéma
# ─────────────────────────────────────────────────────────────

SCHEMA_FRESHNESS_MAX_AGE_HOURS: Final[int] = 24  # Considéré obsolète après 24h


# ─────────────────────────────────────────────────────────────
# Boucle agent (think → act → observe)
# ─────────────────────────────────────────────────────────────

AGENT_MAX_TURNS: Final[int] = 25  # Tours max par échange
AGENT_GOAL_ANCHOR_INTERVAL: Final[int] = 5  # Rappeler l'objectif tous les N tours
AGENT_THINKING_BUDGET: Final[int] = 10_000  # Max tokens de réflexion interne par tour


# ─────────────────────────────────────────────────────────────
# Limites de contexte
# ─────────────────────────────────────────────────────────────

DDL_TRUNCATION_LIMIT: Final[int] = 8_000
VISIBLE_TABLES_LIMIT: Final[int] = 40


# ─────────────────────────────────────────────────────────────
# Calibration de confiance
# ─────────────────────────────────────────────────────────────

CONFIDENCE_THRESHOLD_EXECUTE: Final[float] = 0.85  # Exécuter sans demander
CONFIDENCE_THRESHOLD_CONFIRM: Final[float] = 0.60  # Montrer le SQL pour confirmation
# En dessous de CONFIRM → demander clarification à l'utilisateur.

# Poids des signaux dans le score de confiance composite. Invariant testé :
# la somme doit être 1.0 (cf. tests/unit/test_config_infra.py).
CONFIDENCE_WEIGHT_CONSENSUS: Final[float] = 0.35  # Accord entre candidats SQL
CONFIDENCE_WEIGHT_RAG: Final[float] = 0.30  # Couverture RAG (schéma + exemples)
CONFIDENCE_WEIGHT_SCHEMA: Final[float] = 0.20  # Tables/colonnes vérifiées
CONFIDENCE_WEIGHT_COMPLEXITY: Final[float] = 0.15  # Inverse de la complexité


# ─────────────────────────────────────────────────────────────
# Multi-candidats SQL
# ─────────────────────────────────────────────────────────────

SQL_CANDIDATES_COUNT: Final[int] = 3  # Nombre de variantes SQL à générer
SQL_CANDIDATES_MIN_FOR_CONSENSUS: Final[int] = 2  # Minimum identiques pour consensus
# Températures des candidats multi-variantes (diversité du consensus).
# [0.0 = déterministe, 0.3 = légèrement créatif, 0.7 = exploratoire].
# Tuple immuable : éviter qu'un appelant fasse ``.append()`` par erreur et
# contamine tous les autres appelants du process.
SQL_CANDIDATE_TEMPERATURES: Final[tuple[float, ...]] = (0.0, 0.3, 0.7)


# ─────────────────────────────────────────────────────────────
# Taxonomie d'erreurs SQL
# ─────────────────────────────────────────────────────────────

ERROR_TAXONOMY_MAX_RETRIES_PER_TYPE: Final[int] = 2  # Max corrections par type
ERROR_TAXONOMY_CATEGORIES: Final[tuple[str, ...]] = (
    "table_not_found",
    "column_not_found",
    "type_mismatch",
    "join_error",
    "agg_no_groupby",
    "having_vs_where",
    "null_arithmetic",
    "timeout_or_resource",
    "zero_rows",
)


# ─────────────────────────────────────────────────────────────
# Règles de correction (pattern MAGIC)
# ─────────────────────────────────────────────────────────────

CORRECTION_RULES_MAX: Final[int] = 500  # Limite de règles stockées
CORRECTION_RULES_DATA_TYPE: Final[str] = "correction_rule"  # data_type dans training_data


# ─────────────────────────────────────────────────────────────
# Helpers (détection provider / lookup registre / estimation tokens)
# ─────────────────────────────────────────────────────────────


def detect_api_type(api_key: str, base_url: str = "") -> str:
    """Détecte le protocole attendu : ``"anthropic"`` ou ``"openai"``.

    Anthropic est le seul provider avec un format de payload différent
    (``/v1/messages``, header ``anthropic-version``, etc.). Tous les autres
    — OpenAI, Groq, Mistral, DeepSeek, Together, OpenRouter, Ollama,
    Gemini-OpenAI-compat, self-hosted — parlent le dialecte OpenAI.

    Priorité :

    1. Si ``base_url`` résout vers ``anthropic.com`` ou un sous-domaine
       (``api.anthropic.com``) → ``"anthropic"``. On exige un match exact
       sur le **hostname** (via ``urlparse``) et non une simple présence
       de la sous-chaîne, pour ne pas tomber dans un piège type
       ``https://my-anthropic-proxy.example.com`` qui n'est pas Anthropic.
    2. Sinon, si la clé commence par ``sk-ant-`` → ``"anthropic"``.
    3. Sinon → ``"openai"`` (défaut universellement compatible).

    Paramètres :

    - ``api_key`` : clé brute du provider. Peut être vide.
    - ``base_url`` : URL du provider (avec ou sans schéma). Peut être vide.

    Ne lève jamais : retourne ``"openai"`` pour tout couple ``(api_key,
    base_url)`` ambigu — c'est le fallback safe car tous les providers non
    Anthropic parlent OpenAI.
    """
    if base_url:
        try:
            host = (urlparse(base_url).hostname or "").lower()
        except ValueError:
            host = ""
        if host and (host in _ANTHROPIC_HOSTS or _endswith_anthropic_domain(host)):
            return "anthropic"
    if api_key.startswith(_ANTHROPIC_KEY_PREFIX):
        return "anthropic"
    return "openai"


def _endswith_anthropic_domain(host: str) -> bool:
    """True si ``host`` est un sous-domaine strict de anthropic.com."""
    return any(host.endswith("." + h) for h in _ANTHROPIC_HOSTS)


def get_utility_model(provider_name: str | None) -> str:
    """Retourne le modèle configuré pour les tâches utilitaires.

    Stratégie :

    1. Utiliser le modèle principal défini dans ``LLMManager`` (choix admin).
    2. Sinon, fallback sur le modèle par défaut du provider (si connu).
    3. Sinon (provider inconnu ou ``None``) → ``ValueError`` fail-closed.

    On garde un fallback explicite pour les deux providers connus plutôt
    que de renvoyer ``ANTHROPIC_DEFAULT_MODEL`` aveuglément : un admin qui
    a configuré un provider OpenAI-compatible ne doit pas se retrouver à
    appeler un modèle Anthropic.

    ``ImportError`` / ``AttributeError`` lors du resolve de ``LLMManager``
    sont suivis d'un fallback sur le mapping static. On n'attrape **pas**
    ``Exception`` au sens large : un bug réel dans ``LLMManager`` doit
    remonter, pas être masqué.
    """
    if not provider_name:
        raise ValueError(
            "Aucun provider LLM configuré. "
            "Configurez un provider dans Administration > Config IA."
        )
    try:
        from app.services.ai.llm_providers import get_llm_manager

        manager = get_llm_manager()
        if manager.default_model_name:
            return manager.default_model_name
    except (ImportError, AttributeError):
        # Import circulaire pendant l'init ou manager non encore instancié.
        # On retombe sur le fallback static plus bas. Toute autre exception
        # (bug dans get_llm_manager) doit continuer à remonter.
        pass
    fallback = _PROVIDER_DEFAULT_MODELS.get(provider_name)
    if fallback is not None:
        return fallback
    raise ValueError(
        f"Aucun modèle configuré pour le provider {provider_name!r}. "
        "Configurez un modèle dans Administration > Config IA."
    )


# Mapping module-level : évite la recréation à chaque appel de
# ``get_utility_model``. Les clés sont les noms canoniques renvoyés par
# ``detect_api_type``.
_PROVIDER_DEFAULT_MODELS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "anthropic": ANTHROPIC_DEFAULT_MODEL,
        "openai": OPENAI_DEFAULT_MODEL,
    }
)


def _registry_cache_lookup(model_name: str, field: str) -> object | None:
    """Tente de lire ``field`` depuis le registre BDD (API publique).

    Retourne ``None`` si le registre n'est pas initialisé, le cache est vide,
    le modèle n'est pas connu, ou en cas d'erreur. **Jamais** levée — les
    helpers appelants doivent toujours pouvoir fallback sur le static.

    Pourquoi pas un appel async / session BDD : ces helpers sont appelés
    depuis des chemins synchrones (validation payload, calcul de cap,
    estimation de budget). Ouvrir une session ici introduirait des deadlocks
    ou un coût latence. Le cache mémoire est warm-up au boot
    (``seed_from_constants``) et après chaque override admin (handler patch).
    """
    try:
        from app.services.ai.llm_model_registry import LlmModelRegistry

        instance = LlmModelRegistry._instance
        if instance is None:
            return None
        # Délégué à l'API publique du registre (single source of truth pour
        # l'algo de résolution alias). Pas d'accès direct à ``_cache_by_name``.
        return instance.get_field_sync(model_name, field)
    except Exception:  # noqa: BLE001 — fallback ON DOIT marcher
        return None


def _safe_int_from_registry(value: object | None, fallback_label: str) -> int | None:
    """Cast registre → int, fail-soft. Retourne ``None`` si non-castable
    pour que le caller fallback sur le static plutôt que de crasher tout
    le pipeline LLM. Logge un warning visible — un schema BDD corrompu
    doit être remarqué, pas masqué."""
    if value is None:
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        import logging

        logging.getLogger(__name__).warning(
            "Registre LLM : valeur non-castable en int pour '%s' (%r) — "
            "fallback static utilisé. Schema BDD à investiguer.",
            fallback_label,
            value,
        )
        return None
    # D1-F1 : castable mais hors-domaine. ``_safe_int_from_registry`` ne sert
    # qu'à ``max_output_tokens`` / ``context_window`` qui sont TOUJOURS > 0. Un
    # 0/négatif vient d'un sync partiel ou d'un typo admin — le propager ferait
    # ``clamped_max_tokens`` retourner 0/négatif → tout appel LLM avec ce modèle
    # échouerait. On fallback sur le static (fail-soft, cohérent avec le
    # non-castable ci-dessus) en signalant.
    if result <= 0:
        import logging

        logging.getLogger(__name__).warning(
            "Registre LLM : valeur int hors-domaine (<=0) pour '%s' (%r) — "
            "fallback static utilisé. Schema BDD à investiguer.",
            fallback_label,
            value,
        )
        return None
    return result


def _safe_float_from_registry(value: object | None, fallback_label: str) -> float | None:
    """Symétrique de ``_safe_int_from_registry`` pour les floats (pricing)."""
    if value is None:
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        import logging

        logging.getLogger(__name__).warning(
            "Registre LLM : valeur non-castable en float pour '%s' (%r) — "
            "fallback static utilisé.",
            fallback_label,
            value,
        )
        return None
    # D1-F1 : un prix NÉGATIF est une corruption (on ne se fait pas payer pour
    # un appel LLM). ``0.0`` reste VALIDE (= « non précisé », fallback legacy
    # input_price côté modèle). On ne rejette donc que les négatifs → fallback
    # static avec warning.
    if result < 0:
        import logging

        logging.getLogger(__name__).warning(
            "Registre LLM : prix négatif pour '%s' (%r) — fallback static utilisé. "
            "Schema BDD à investiguer.",
            fallback_label,
            value,
        )
        return None
    return result


def get_max_tokens_for_model(model_name: str) -> int:
    """Retourne la limite max de tokens en sortie pour un modèle donné.

    **Priorité** :
    1. Registre BDD via cache mémoire (admin override, valeurs synced API).
    2. Match exact dans ``MODEL_MAX_OUTPUT_TOKENS`` (seed static).
    3. Match par préfixe (alias datés type ``claude-opus-4-7-20260101``).
    4. ``_DEFAULT_MAX_OUTPUT_TOKENS`` (8192) — conservateur.

    Un modèle inconnu n'est jamais une erreur fatale : on tronque
    conservativement plutôt que de lever.
    """
    if not model_name:
        return _DEFAULT_MAX_OUTPUT_TOKENS
    # 1. Registre BDD (admin override, source de vérité runtime)
    from_registry = _safe_int_from_registry(
        _registry_cache_lookup(model_name, "max_output_tokens"),
        f"{model_name}.max_output_tokens",
    )
    if from_registry is not None:
        return from_registry
    # 2-4. Fallback static
    if model_name in MODEL_MAX_OUTPUT_TOKENS:
        return MODEL_MAX_OUTPUT_TOKENS[model_name]
    best_key = _longest_prefix_match(model_name, MODEL_MAX_OUTPUT_TOKENS)
    return MODEL_MAX_OUTPUT_TOKENS[best_key] if best_key else _DEFAULT_MAX_OUTPUT_TOKENS


def get_context_window_for_model(model_name: str) -> int:
    """Retourne la taille du context window (input + output) pour un modèle.

    Même priorité que ``get_max_tokens_for_model`` : registre BDD prioritaire,
    fallback static. Permet à l'admin de bumper Sonnet 4.6 200K → 1M (GA mars
    2026) via UI sans redéploiement.
    """
    if not model_name:
        return _DEFAULT_CONTEXT_WINDOW
    from_registry = _safe_int_from_registry(
        _registry_cache_lookup(model_name, "context_window"),
        f"{model_name}.context_window",
    )
    if from_registry is not None:
        return from_registry
    if model_name in MODEL_CONTEXT_WINDOW:
        return MODEL_CONTEXT_WINDOW[model_name]
    best_key = _longest_prefix_match(model_name, MODEL_CONTEXT_WINDOW)
    return MODEL_CONTEXT_WINDOW[best_key] if best_key else _DEFAULT_CONTEXT_WINDOW


def get_pricing_for_model(model_name: str) -> Mapping[str, float] | None:
    """Retourne les prix ``{"input", "output", "cache_read", "cache_creation"}``
    (USD/Mtok).

    Priorité : registre BDD (override admin, pricing sync API), puis
    ``MODEL_PRICING`` static. Retourne ``None`` si aucun pricing connu —
    le caller doit logger un warning visible (modèle inconnu = denial-of-wallet
    masqué si on retournait silencieusement 0).

    ``cache_read`` / ``cache_creation`` valent ``0.0`` quand ils ne sont pas
    configurés au registre — le consommateur (``_compute_cost_snapshot``,
    ``stats_service``) retombe alors sur le prix INPUT via ``or input_price``
    (sémantique legacy préservée). Quand l'admin/le sync LiteLLM les renseigne,
    ils sont enfin réellement utilisés (avant D1-F2 ils n'étaient lus que par
    ``get_pricing_sync``, chemin MORT → le cache était facturé au prix input
    plein, ex. Anthropic cache_read = 0.1× input → surestimation 10×).

    **Pricing partiel** : si un seul des deux prix input/output est en BDD (admin a
    saisi input mais pas output, ou vice-versa), on **complète avec le static**
    plutôt que de fallback intégralement — sinon un override partiel
    écraserait silencieusement la moitié saine. Logue un warning pour que
    l'admin sache que sa config est incohérente.
    """
    if not model_name:
        return None
    in_price = _safe_float_from_registry(
        _registry_cache_lookup(model_name, "input_price_per_mtok_usd"),
        f"{model_name}.input_price_per_mtok_usd",
    )
    out_price = _safe_float_from_registry(
        _registry_cache_lookup(model_name, "output_price_per_mtok_usd"),
        f"{model_name}.output_price_per_mtok_usd",
    )
    # D1-F2 — cache_read / cache_creation passent par le MÊME garde range que
    # input/output (négatif = corruption → rejeté → 0.0 « non configuré »). Ils
    # sont peuplés par le sync LiteLLM (cf. litellm_registry_sync) mais n'étaient
    # exposés QUE par ``get_pricing_sync`` (0 caller = chemin mort) → le calcul de
    # coût réel les ignorait et facturait le cache au prix INPUT plein.
    cache_read = _safe_float_from_registry(
        _registry_cache_lookup(model_name, "cache_read_price_per_mtok_usd"),
        f"{model_name}.cache_read_price_per_mtok_usd",
    )
    cache_creation = _safe_float_from_registry(
        _registry_cache_lookup(model_name, "cache_creation_price_per_mtok_usd"),
        f"{model_name}.cache_creation_price_per_mtok_usd",
    )
    static = MODEL_PRICING.get(model_name)
    if static is None:
        best_key = _longest_prefix_match(model_name, MODEL_PRICING)
        static = MODEL_PRICING[best_key] if best_key else None

    if in_price is not None and out_price is not None:
        return {
            "input": in_price,
            "output": out_price,
            "cache_read": cache_read if cache_read is not None else 0.0,
            "cache_creation": cache_creation if cache_creation is not None else 0.0,
        }
    if in_price is not None or out_price is not None:
        # Pricing partiel — incohérence config admin
        import logging

        logging.getLogger(__name__).warning(
            "Pricing partiel pour '%s' (input=%s, output=%s). Compléter via "
            "/admin/ai-models pour éviter une facturation incohérente.",
            model_name,
            in_price,
            out_price,
        )
        if static is not None:
            return {
                "input": in_price if in_price is not None else float(static.get("input", 0.0)),
                "output": out_price if out_price is not None else float(static.get("output", 0.0)),
                "cache_read": (
                    cache_read if cache_read is not None else float(static.get("cache_read", 0.0))
                ),
                "cache_creation": (
                    cache_creation
                    if cache_creation is not None
                    else float(static.get("cache_creation", 0.0))
                ),
            }
        return None
    return static


def clamped_max_tokens(soft_limit: int | None = None, model_name: str | None = None) -> int:
    """Calcule un ``max_tokens`` *toujours valide* pour un modèle donné.

    **Pourquoi ce helper** : les call-sites avaient des magic numbers
    (``max_tokens=8192``, ``max_tokens=64``, ...) qui plantent au switch
    inter-modèles (Sonnet 64K → Haiku 8K → Mistral 4K). Avec ce helper :

    - ``soft_limit=None`` → retourne le cap réel du modèle
      (= ``get_max_tokens_for_model(model)``).
    - ``soft_limit=N`` (utility task volontairement courte) → retourne
      ``min(N, cap_modèle)``. Préserve la sémantique « courte » du caller
      tout en garantissant qu'on ne demande JAMAIS plus que ce que le
      modèle accepte.
    - ``model_name=None`` → utilise ``LLMManager.default_model_name`` (choix
      admin), fallback sur ``ANTHROPIC_DEFAULT_MODEL`` si manager absent.

    Le résultat respecte l'override admin via UI (registre BDD) puisque
    ``get_max_tokens_for_model`` consulte le registre en priorité.
    """
    if not model_name:
        try:
            from app.services.ai.llm_providers import get_llm_manager

            mgr = get_llm_manager()
            model_name = mgr.default_model_name or ""
        except Exception:  # noqa: BLE001
            model_name = ""
    if not model_name:
        model_name = ANTHROPIC_DEFAULT_MODEL
    cap = get_max_tokens_for_model(model_name)
    if soft_limit is None or soft_limit <= 0:
        return cap
    return min(int(soft_limit), cap)


def supports_capability_for_model(model_name: str, capability: str) -> bool | None:
    """Retourne ``True``/``False`` si le registre BDD a un avis explicite
    sur la capacité ``capability`` (``supports_extended_thinking``,
    ``supports_prompt_caching``, ``supports_tool_use``) pour ``model_name``.

    Retourne ``None`` si le registre ne connaît pas le modèle ou la capacité —
    le caller doit alors fallback sur sa logique habituelle (regex, default).

    Cette indirection permet à l'admin de désactiver une capability via
    UI (``PATCH /api/admin/llm/models/{name}``) sans redéploiement.
    """
    if not model_name or not capability:
        return None
    field = f"supports_{capability}" if not capability.startswith("supports_") else capability
    val = _registry_cache_lookup(model_name, field)
    if val is None:
        return None
    return bool(val)


def _longest_prefix_match(model_name: str, keys: Mapping[str, object]) -> str | None:
    """Retourne la clé la plus longue dont ``model_name`` débute par elle."""
    best: str | None = None
    for key in keys:
        if model_name.startswith(key) and (best is None or len(key) > len(best)):
            best = key
    return best


# ─────────────────────────────────────────────────────────────
# Estimation de tokens
# ─────────────────────────────────────────────────────────────

# Ratio caractères → tokens. Approximation raisonnable pour du texte latin
# standard (≈ 4 chars/token). **Sous-estime de 40-60 %** sur CJK, emoji,
# et texte riche en caractères spéciaux (docs Anthropic 2025-2026).
_CHARS_PER_TOKEN: Final[int] = 4

# Marge de sécurité pour la version conservatrice. Couvre la dérive CJK/
# emoji mesurée par Anthropic (max observé ≈ 1.6×).
_CONSERVATIVE_TOKEN_MARGIN: Final[float] = 1.6


def estimate_token_count(text: str) -> int:
    """Estimation rapide du nombre de tokens.

    Approximation basée sur ``len(text) / 4`` — suffisante pour du texte
    latin classique. **Sous-estime** significativement pour CJK, emoji,
    JSON lourd en structure. Utiliser pour :

    - Décisions de logging / budget grossier
    - Estimations d'UI
    - Tri / filtrage par taille

    **Ne pas utiliser** pour :

    - Calcul précis de ``max_tokens`` dans un appel API (utiliser
      ``anthropic.messages.count_tokens()`` côté provider).
    - Décisions de troncature qui DOIVENT éviter le dépassement
      (utiliser ``estimate_token_count_conservative``).
    """
    return len(text) // _CHARS_PER_TOKEN


def estimate_token_count_conservative(text: str) -> int:
    """Estimation conservatrice (borne supérieure) du nombre de tokens.

    Applique une marge de 1.6× pour couvrir la dérive CJK/emoji. À
    utiliser dans les décisions de troncature qui doivent éviter tout
    dépassement de context window (``context > limit`` plutôt que
    ``limit`` exact).
    """
    return int(len(text) * _CONSERVATIVE_TOKEN_MARGIN / _CHARS_PER_TOKEN) + 1
