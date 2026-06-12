"""
Modèle AIPerformanceLog pour le suivi des performances IA.

Chaque requête NL→SQL est loguée avec métriques détaillées
pour permettre le suivi, la comparaison de modèles et l'amélioration continue.
"""

from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional

from sqlalchemy import (
    Integer,
    String,
    Text,
    Float,
    DateTime,
    Boolean,
    ForeignKey,
    Enum,
    Index,
    JSON,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core import clock
from app.models.base import Base


class QueryStatus(str, PyEnum):
    """Statut d'une requête IA."""

    SUCCESS = "success"
    VALIDATION_ERROR = "validation_error"
    EXECUTION_ERROR = "execution_error"
    TIMEOUT = "timeout"
    LLM_ERROR = "llm_error"


class AIPerformanceLog(Base):
    """
    Log détaillé de chaque interaction IA NL→SQL.

    Permet:
    - Suivi du taux de réussite par modèle
    - Comparaison de performance entre modèles
    - Identification des types de questions problématiques
    - Mesure de la latence et des coûts
    """

    __tablename__ = "ai_performance_logs"

    id: Mapped[int] = mapped_column(primary_key=True)

    # Requête
    question: Mapped[str] = mapped_column(Text, nullable=False)
    sql_generated: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sql_validated: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Modèle IA utilisé
    model_provider: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # openai, anthropic — toujours renseigné à l'insertion
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)  # mistral, gpt-4, claude-3
    temperature: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Résultat
    status: Mapped[QueryStatus] = mapped_column(Enum(QueryStatus), nullable=False, index=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    result_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Timing (en secondes)
    generation_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )  # Temps génération SQL
    validation_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )  # Temps validation
    execution_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )  # Temps exécution BDD
    total_time: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # Temps total

    # Tokens (si disponible)
    prompt_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    total_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Tokens granulaires (cache Anthropic + extended thinking).
    # ``cache_read`` et ``cache_creation`` comptent dans l'input mais à des
    # tarifs différents — on les stocke séparément pour pouvoir recalculer
    # exactement. ``thinking_tokens`` compte dans l'output (Sonnet 3.7+).
    cache_read_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cache_creation_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    thinking_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Coût figé au moment de l'appel. Permet d'éviter de recalculer
    # rétroactivement lorsque le pricing du registre BDD change. ``NULL``
    # = "non priced" (modèle inconnu au moment de l'appel) — le dashboard
    # le distingue de ``0.0`` (vraiment 0$). Cf. ``llm_call_tracker``.
    cost_usd_snapshot: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Origine sémantique de l'appel : ``iris_main``, ``copilot_cell``,
    # ``schema_sync``, ``schema_enrich``, etc.
    # Permet le breakdown "consommation par feature" sur le dashboard.
    # ``NULL`` accepté (legacy + appels exotiques non instrumentés).
    caller: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # ID de conversation Iris (UUID) ou identifiant de batch (sync, etc.).
    # Permet de grouper N tours d'une même conv dans un dashboard.
    conversation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # ID de requête HTTP propagé via ``request_context``. ``NULL`` pour
    # les appels système (scheduler, startup).
    request_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Contexte RAG utilisé
    rag_ddl_count: Mapped[int] = mapped_column(
        Integer, nullable=True, default=0
    )  # Nombre de DDL injectés
    rag_doc_count: Mapped[int] = mapped_column(
        Integer, nullable=True, default=0
    )  # Nombre de docs injectés
    rag_example_count: Mapped[int] = mapped_column(
        Integer, nullable=True, default=0
    )  # Nombre d'exemples injectés
    prompt_length: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # Longueur du prompt total

    # Feedback utilisateur
    user_feedback: Mapped[Optional[str]] = mapped_column(
        String(20), nullable=True
    )  # positive, negative, null
    feedback_comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    was_corrected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )  # SQL corrigé manuellement
    corrected_sql: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Cache
    from_cache: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Utilisateur — ``ondelete="SET NULL"`` cohérent avec ``nullable=True``.
    # Si un admin supprime un user, on conserve les logs IA pour l'historique
    # global (coûts, perf, taux d'erreur), mais on détache le lien user
    # → KPI dashboard "user_id IS NOT NULL" filtrent ces rows orphelins
    # (cf. review adversariale finding EXAMINE-3).
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=clock.now)

    # Index composites pour les requêtes dashboard
    __table_args__ = (
        Index("idx_perf_model", "model_provider", "model_name"),
        Index("idx_perf_status_date", "status", "created_at"),
        Index("idx_perf_user_date", "user_id", "created_at"),
        Index("idx_perf_date", "created_at"),
        # Breakdown "consommation par feature" + grouping conversation.
        Index("idx_perf_caller_date", "caller", "created_at"),
        Index("idx_perf_conversation", "conversation_id"),
    )

    # ── Aliases compat dashboard ──────────────────────────────────────
    # Le dashboard a longtemps lu ``SearchHistory`` (model legacy jamais
    # alimenté par Iris). On l'a migré vers ``AIPerformanceLog`` (vraie
    # source). Pour préserver les templates qui utilisaient ``s.success`` et
    # ``s.feedback``, on expose ces noms en property en lecture seule. Ainsi :
    #
    # * ``log.success`` → ``True`` si ``status == QueryStatus.SUCCESS``,
    #   ``False`` pour tous les autres statuts (validation/exec/timeout/llm).
    # * ``log.feedback`` → alias de ``user_feedback`` (même type ``str | None``).
    #
    # ⚠️ Ces ``@property`` ne fonctionnent **pas** dans une expression
    # SQLAlchemy ``select()`` (elles ne sont pas mappées en colonne). Pour
    # filtrer/agréger côté SQL, utilisez ``status``/``user_feedback``
    # directement. Les alias servent uniquement au rendu Python (templates,
    # ``to_dict``-like, scripts).
    @property
    def success(self) -> bool:
        return self.status == QueryStatus.SUCCESS

    @property
    def feedback(self) -> Optional[str]:
        return self.user_feedback

    def __repr__(self):
        return (
            f"<AIPerformanceLog(id={self.id}, model={self.model_name}, "
            f"status={self.status}, time={self.total_time:.2f}s)>"
            if self.total_time is not None
            else f"<AIPerformanceLog(id={self.id}, model={self.model_name}, "
            f"status={self.status}, time=N/A)>"
        )

    def to_dict(self):
        return {
            "id": self.id,
            "question": self.question,
            "sql_generated": self.sql_generated,
            "model_provider": self.model_provider,
            "model_name": self.model_name,
            "status": self.status.value if self.status else None,
            "error_message": self.error_message,
            "result_count": self.result_count,
            "generation_time": self.generation_time,
            "validation_time": self.validation_time,
            "execution_time": self.execution_time,
            "total_time": self.total_time,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_creation_tokens": self.cache_creation_tokens,
            "thinking_tokens": self.thinking_tokens,
            "cost_usd_snapshot": self.cost_usd_snapshot,
            "caller": self.caller,
            "conversation_id": self.conversation_id,
            "request_id": self.request_id,
            "rag_ddl_count": self.rag_ddl_count,
            "rag_doc_count": self.rag_doc_count,
            "rag_example_count": self.rag_example_count,
            "user_feedback": self.user_feedback,
            "feedback_comment": self.feedback_comment,
            "was_corrected": self.was_corrected,
            "from_cache": self.from_cache,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class SchemaSync(Base):
    """
    Historique de synchronisation du schéma BDD.

    Trace chaque sync (auto ou manuelle) avec les changements détectés.
    """

    __tablename__ = "schema_syncs"

    id: Mapped[int] = mapped_column(primary_key=True)

    # Type de sync
    sync_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="manual"
    )  # manual, auto, scheduled

    # Résultat
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Changements détectés
    tables_added: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tables_removed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    columns_added: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    columns_removed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    changes_detail: Mapped[Optional[dict]] = mapped_column(
        JSON, nullable=True
    )  # Détail JSON des changements

    # Stats
    total_tables: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    total_columns: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Qui a lancé
    triggered_by: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=clock.now)

    def to_dict(self):
        return {
            "id": self.id,
            "sync_type": self.sync_type,
            "success": self.success,
            "error_message": self.error_message,
            "tables_added": self.tables_added,
            "tables_removed": self.tables_removed,
            "columns_added": self.columns_added,
            "columns_removed": self.columns_removed,
            "total_tables": self.total_tables,
            "total_columns": self.total_columns,
            "duration_seconds": self.duration_seconds,
            # ISO offset-aware (+00:00) : la colonne est relue NAÏVE depuis SQLite
            # → un isoformat() brut serait mal-parsé par new Date() côté JS
            # (<time data-fmt-local> de l'historique sync) = +Nh. clock.iso_utc
            # gère naïf→UTC et None→None.
            "created_at": clock.iso_utc(self.created_at),
        }
