"""
Modèle TrainingData pour le stockage des données d'entraînement IA.

Inspiré de Vanna.ai : stocke DDL, documentation métier et paires question-SQL
pour le RAG (Retrieval Augmented Generation).
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


class TrainingDataType(str, PyEnum):
    """Types de données d'entraînement (inspiré Vanna.ai).

    **Objets atomiques (RAG core)** :
    - ``DDL`` : ``CREATE TABLE`` — schéma des tables physiques.
    - ``DOCUMENTATION`` : contexte métier (règles, alias, descriptions
      sémantiques) sans rapport direct avec une table.
    - ``QUESTION_SQL`` : paires NL/SQL validées (few-shot RAG).
    - ``AGENT_MEMORY`` : mémoires persistantes de l'agent Iris
      (préférences user, faits récurrents).

    **Objets dérivés (Phase 1 — pour le closure transitif du mode invisible)** :
    - ``VIEW`` : vues SQL Server (``CREATE VIEW``). Une vue peut référencer
      d'autres tables/vues — la fermeture est gérée par
      ``TrainingData.depends_on`` (Phase 1.4, #16).
    - ``FUNCTION`` : fonctions SQL (TVF et scalaires). Mêmes contraintes
      de dépendances qu'une vue.
    - ``SYNONYM`` : synonymes SQL Server (``CREATE SYNONYM``) qui
      redirigent vers une autre table/vue/fonction. La cible est
      référencée dans ``depends_on``.

    **Pourquoi ces 3 types séparés** : avant Phase 1, vues/fonctions/
    synonymes étaient stockés comme ``DDL`` indistinctement, ce qui
    empêchait le closure transitif (impossible de savoir qu'une vue
    référence une table interdite). Séparer les types permet à
    l'enforcer de calculer « cette vue dépend-elle d'une table denied
    pour cet user ? » via le graph stocké en ``depends_on``.
    """

    DDL = "ddl"  # CREATE TABLE, schéma des tables physiques
    DOCUMENTATION = "documentation"  # Contexte métier, règles
    QUESTION_SQL = "question_sql"  # Paires question/SQL validées
    AGENT_MEMORY = "agent_memory"  # Mémoires persistantes de Iris
    # Objets dérivés (Phase 1) — pour le closure transitif du mode invisible.
    VIEW = "view"  # CREATE VIEW — dépend d'autres tables/vues
    FUNCTION = "function"  # CREATE FUNCTION (TVF / scalaire)
    SYNONYM = "synonym"  # CREATE SYNONYM — redirection vers une cible


class TrainingData(Base):
    """
    Données d'entraînement pour le RAG NL→SQL.

    Trois types (comme Vanna.ai):
    - DDL: schéma des tables (CREATE TABLE)
    - Documentation: contexte métier (ex: EC_Sens 0=Débit)
    - Question-SQL: paires validées par les utilisateurs
    """

    __tablename__ = "training_data"

    id: Mapped[int] = mapped_column(primary_key=True)
    data_type: Mapped[TrainingDataType] = mapped_column(
        Enum(TrainingDataType), nullable=False, index=True
    )

    # Contenu principal
    content: Mapped[str] = mapped_column(Text, nullable=False)  # DDL ou documentation
    question: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # Question NL (pour question_sql)
    sql: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # SQL validé (pour question_sql)

    # Métadonnées
    table_name: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )  # Table concernée (pour DDL)
    category: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )  # Catégorie (pour documentation)
    tags: Mapped[Optional[str]] = mapped_column(
        String(500), nullable=True
    )  # Tags séparés par virgule

    # Source et validation
    source: Mapped[str] = mapped_column(
        String(50), nullable=False, default="manual"
    )  # manual, auto_sync, feedback
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    pending_review: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )  # True = ajouté par feedback non-admin, en attente de validation
    quality_score: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )  # Score qualité 0-1
    usage_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )  # Nombre de fois utilisé dans RAG

    # Métadonnées structurées (enrichissement sémantique, etc.)
    # Note: "metadata" est réservé par SQLAlchemy Declarative, d'où "extra_metadata"
    extra_metadata: Mapped[Optional[dict]] = mapped_column(
        "metadata", JSON, nullable=True
    )  # Ex: {"enrichment_version": 1, "source_tables": [...], "confidence": 0.85}

    # Phase 1.4 (#16) — Dépendances structurées pour le closure transitif.
    # Liste des tables/vues/fonctions/synonymes référencés par ce record.
    # Exemples :
    # - SYNONYM "dbo.alias_paie" → ``depends_on=["dbo_F_SALAIRES"]``
    # - VIEW "V_RECAP" qui fait SELECT * FROM A JOIN B → ``["A", "B"]``
    # - FUNCTION qui interroge X → ``["X"]``
    # - DDL (table physique) → ``None`` ou ``[]`` (n'a pas de dépendance)
    # Format : liste de noms canoniques. La Phase 2.1 (#44) calcule la
    # fermeture transitive : si une dépendance est interdite, l'objet l'est
    # aussi.
    # Rétro-compat lecture : si ``depends_on`` est ``None`` et que
    # ``extra_metadata.target`` existe (synonymes pré-Phase 1.4), le lecteur
    # doit fallback. Le backfill au boot promeut ``extra_metadata.target``
    # vers ``depends_on=[target]`` pour les SYNONYM existants.
    depends_on: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Qui l'a ajouté
    created_by: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=clock.now)
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True, onupdate=clock.now
    )

    # Index pour recherche rapide
    __table_args__ = (
        Index("idx_training_type_active", "data_type", "is_active"),
        Index("idx_training_table", "table_name"),
        Index("idx_training_category", "category"),
    )

    def __repr__(self):
        return (
            f"<TrainingData(id={self.id}, type={self.data_type}, "
            f"table={self.table_name}, active={self.is_active})>"
        )

    def to_dict(self):
        return {
            "id": self.id,
            "data_type": self.data_type.value if self.data_type else None,
            "content": self.content,
            "question": self.question,
            "sql": self.sql,
            "table_name": self.table_name,
            "category": self.category,
            "tags": self.tags.split(",") if self.tags else [],
            "source": self.source,
            "is_active": self.is_active,
            "pending_review": self.pending_review,
            "quality_score": self.quality_score,
            "usage_count": self.usage_count,
            "metadata": self.extra_metadata,
            "depends_on": self.depends_on,  # Phase 1.4 (#16)
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
