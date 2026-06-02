"""
Module AI pour Komptia.

Ce package contient les services d'intelligence artificielle:
- SQLGenerator avec RAG intégré (inspiré Vanna.ai)
- Multi-provider LLM (OpenAI, Anthropic, etc.)
- Training Store (DDL, docs, paires Q/SQL)
- Schema Sync
- Stats & Performance tracking
"""

from app.services.ai.schema_loader import SchemaLoader, get_schema_loader
from app.services.ai.sql_validator import SQLValidator, ValidationError, SecurityLevel
from app.services.ai.llm_providers import (
    LLMProvider,
    LLMManager,
    LLMRequest,
    LLMResponse,
    OpenAIProvider,
    AnthropicProvider,
    get_llm_manager,
)
from app.services.ai.training_store import TrainingStore, get_training_store
from app.services.ai.schema_sync import SchemaSyncService, get_sync_service
from app.services.ai.stats_service import AIStatsService, get_ai_stats_service
from app.services.ai.concept_disambiguation import (
    Ambiguity,
    CandidateColumn,
    detect_ambiguous_concepts,
    format_disambiguation_batch_question,
)

__all__ = [
    # Core
    "SchemaLoader",
    "get_schema_loader",
    "SQLValidator",
    "ValidationError",
    "SecurityLevel",
    # Multi-LLM
    "LLMProvider",
    "LLMManager",
    "LLMRequest",
    "LLMResponse",
    "OpenAIProvider",
    "AnthropicProvider",
    "get_llm_manager",
    # Training
    "TrainingStore",
    "get_training_store",
    # Schema Sync
    "SchemaSyncService",
    "get_sync_service",
    # Stats
    "AIStatsService",
    "get_ai_stats_service",
    # Concept Disambiguation (task #98 — Phase 1.5)
    "Ambiguity",
    "CandidateColumn",
    "detect_ambiguous_concepts",
    "format_disambiguation_batch_question",
]
