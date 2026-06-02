"""Modèle ``LlmModel`` — registre dynamique des modèles LLM disponibles.

**Pourquoi ce modèle existe**

Avant : la liste des modèles (avec context_window, max_output_tokens, prix)
était hardcoded dans ``app.constants_ai._MODELS``. Toute release Anthropic
(nouveau modèle, changement de context_window comme Sonnet 4.6 200K → 1M)
exigeait une modification du code applicatif.

Avec ce modèle :

* Au démarrage, le service ``LlmModelRegistry`` synchronise depuis l'API
  (``provider.list_models()``) — tous les modèles disponibles côté provider
  apparaissent automatiquement.
* L'admin peut éditer manuellement les caractéristiques que les APIs
  n'exposent pas (``context_window``, prix). Le flag ``manually_overridden``
  protège ces valeurs lors d'une re-sync.
* L'app est ainsi **provider-agnostic** : ajouter Mistral, Gemini, etc.
  ne touche que la couche provider — le code applicatif lit toujours la BDD.

**Principes**

1. ``name`` est l'identifiant API du modèle (ex: ``claude-sonnet-4-6``).
   PRIMARY KEY logique côté code, ``id`` SQLAlchemy reste l'AUTOINCREMENT.
2. ``provider`` permet le multi-provider sans changement de schéma.
3. ``manually_overridden`` est un flag "ne pas écraser à la sync" — l'admin
   contrôle ses overrides (ex: pricing custom enterprise).
4. ``deprecated_at`` permet de marquer un modèle obsolète sans le supprimer
   (audit trail, runs historiques pointent encore dessus).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core import clock
from app.core.database import Base
from app.models.base import ensure_utc


class LlmModel(Base):
    """Registre dynamique d'un modèle LLM (Anthropic, OpenAI, ou tout
    provider futur).

    Champs synchronisés depuis l'API provider (``last_synced_at`` mis à jour
    à chaque sync) :
    - ``name``, ``display_name``, ``provider``, ``created_at_provider``

    Champs admin-editables (que les APIs n'exposent pas couramment) :
    - ``context_window``, ``max_output_tokens``
    - ``input_price_per_mtok_usd``, ``output_price_per_mtok_usd``
    - ``supports_extended_thinking``, ``supports_prompt_caching``,
      ``supports_tool_use``

    Métadata :
    - ``manually_overridden`` (bool) : vrai si l'admin a édité — la sync
      respecte les overrides.
    - ``deprecated_at`` (DateTime) : modèle marqué obsolète mais conservé.
    """

    __tablename__ = "llm_models"
    __table_args__ = (UniqueConstraint("provider", "name", name="uq_llm_model_provider_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Identifiants — clé logique = (provider, name).
    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    display_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    alias_of: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)

    # Caractéristiques techniques (admin-editable).
    context_window: Mapped[int] = mapped_column(Integer, nullable=False, default=200_000)
    max_output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=4_096)

    # Pricing — USD par million de tokens.
    input_price_per_mtok_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    output_price_per_mtok_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # Prompt caching pricing (Anthropic + OpenAI selon modèles). Anthropic :
    # cache_read = 10% du input price ; cache_creation = 125% du input price.
    # OpenAI gpt-4o : cache_read uniquement (pas de cache_creation distinct).
    # Si 0.0 (modèle non-précisé), fallback à input_price (calcul legacy).
    cache_read_price_per_mtok_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cache_creation_price_per_mtok_usd: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0
    )

    # Capabilities — exposées au LLM dispatcher pour activer/désactiver
    # les features advanced (extended thinking, cache control, tool use).
    # Source unique de vérité pour la **dynamicité multi-provider** : le
    # code lit ces flags au lieu de comparer ``provider_name``. Cf. plan
    # « Komptia 100% dynamique multi-provider » 2026-05-14.
    supports_extended_thinking: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    supports_prompt_caching: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    supports_tool_use: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Reasoning (OpenAI o-series / GPT-5 / Gemini thinking_budget). Format
    # de paramètre différent d'Anthropic ``thinking`` mais but équivalent
    # — le caller lit ce flag pour brancher la bonne stratégie d'effort.
    supports_reasoning_effort: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Parallel tool calls (OpenAI/Mistral/Groq émettent N tool_use blocks
    # dans un même tour ; Anthropic supporte aussi mais format différent).
    supports_parallel_tool_calls: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    # Streaming SSE. Default True : tous les providers majeurs (Anthropic,
    # OpenAI, Mistral, Groq, Gemini, Ollama) le supportent. Mettre False
    # uniquement pour cas exotiques (modèle batch-only, etc.) — le LLMManager
    # dégrade alors ``stream_with_tools`` vers un seul event final.
    supports_streaming: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Vision (image input). Claude 3.5+/Opus 4/Sonnet 4, GPT-4o, Gemini.
    # False par défaut — l'admin coche pour les modèles qui l'exposent.
    supports_vision: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # OpenAI strict JSON mode (``response_format`` avec ``json_schema``
    # + ``additionalProperties=False``). Anthropic n'a pas l'équivalent
    # natif mais peut produire du JSON via prompt (qualité variable).
    supports_strict_json: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Format des tool calls dans la réponse : ``"anthropic"`` (blocks
    # ``tool_use``) ou ``"openai"`` (``tool_calls`` avec ``index`` pour
    # parallel) ou ``"gemini"`` (function_call). Lu par les converters
    # côté provider pour normaliser au format Anthropic-pivot interne.
    # Défaut ``"openai"`` car c'est le format universel OpenAI-compat
    # (Mistral, Groq, DeepSeek, Together, Gemini via /v1/chat, etc.).
    tool_call_format: Mapped[str] = mapped_column(String(20), nullable=False, default="openai")
    # Format du system prompt : ``"string"`` (OpenAI, Mistral, Groq…) ou
    # ``"array"`` (Anthropic avec blocks + cache_control par section).
    system_prompt_format: Mapped[str] = mapped_column(String(20), nullable=False, default="string")
    # TTL options du cache (Anthropic : ``["5m"]`` ou ``["5m", "1h"]`` ;
    # OpenAI : cache implicite, valeur ``[]`` ; modèles sans cache : ``[]``).
    # Lu par ``_pick_cache_control_for_request`` pour choisir entre TTL
    # court (5min) et long (1h) selon la nature du run (tool loop long).
    cache_ttl_options: Mapped[Optional[list[str]]] = mapped_column(
        JSON, nullable=True, default=None
    )

    # LOT 8.12 — Timeout HTTP en secondes, override admin par modèle.
    # ``None`` = utilise le défaut du provider (Anthropic 600s, OpenAI 300s).
    # Use-cases : Groq fast (10s pour fail-fast), Ollama local lent
    # (1800s sur GPU faible), Mistral Large lent (900s).
    timeout_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Marque les modèles utilisés pour les tâches utilitaires (compact
    # summarizer, classification, etc.) — typiquement les Haiku/mini.
    # Quand l'admin a Opus en primary, ``_resolve_compact_summarizer_model``
    # peut router vers ce modèle pour économiser ×15 le coût.
    is_utility: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Métadata sync + override.
    last_synced_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    manually_overridden: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deprecated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at_provider: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Audit standard.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=clock.now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=clock.now,
        onupdate=clock.now,
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "provider": self.provider,
            "display_name": self.display_name,
            "alias_of": self.alias_of,
            "context_window": self.context_window,
            "max_output_tokens": self.max_output_tokens,
            "input_price_per_mtok_usd": self.input_price_per_mtok_usd,
            "cache_read_price_per_mtok_usd": self.cache_read_price_per_mtok_usd,
            "cache_creation_price_per_mtok_usd": self.cache_creation_price_per_mtok_usd,
            "output_price_per_mtok_usd": self.output_price_per_mtok_usd,
            "supports_extended_thinking": self.supports_extended_thinking,
            "supports_prompt_caching": self.supports_prompt_caching,
            "supports_tool_use": self.supports_tool_use,
            "supports_reasoning_effort": self.supports_reasoning_effort,
            "supports_parallel_tool_calls": self.supports_parallel_tool_calls,
            "supports_streaming": self.supports_streaming,
            "supports_vision": self.supports_vision,
            "supports_strict_json": self.supports_strict_json,
            "tool_call_format": self.tool_call_format,
            "system_prompt_format": self.system_prompt_format,
            "cache_ttl_options": self.cache_ttl_options or [],
            "timeout_seconds": self.timeout_seconds,
            "is_utility": self.is_utility,
            "last_synced_at": (
                ensure_utc(self.last_synced_at).isoformat() if self.last_synced_at else None
            ),
            "manually_overridden": self.manually_overridden,
            "deprecated_at": (
                ensure_utc(self.deprecated_at).isoformat() if self.deprecated_at else None
            ),
            "created_at_provider": (
                ensure_utc(self.created_at_provider).isoformat()
                if self.created_at_provider
                else None
            ),
            "created_at": ensure_utc(self.created_at).isoformat(),
            "updated_at": ensure_utc(self.updated_at).isoformat(),
        }
