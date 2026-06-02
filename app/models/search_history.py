"""
Modèle SearchHistory pour l'historique des recherches.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Optional
from sqlalchemy import Integer, String, Text, Float, DateTime, Boolean, ForeignKey, Index
from sqlalchemy.orm import relationship, Mapped, mapped_column

from app.core import clock
from app.models.base import Base

if TYPE_CHECKING:
    from app.models.user import User  # noqa: F401


class SearchHistory(Base):
    """
    Historique des recherches effectuées par les utilisateurs.

    Stocke la question posée, le SQL généré, les résultats,
    et éventuellement le feedback utilisateur.
    """

    __tablename__ = "search_history"
    __table_args__ = (
        Index("ix_search_history_feedback", "feedback"),
        Index("ix_search_history_feedback_status", "feedback_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    # Question et SQL
    question: Mapped[str] = mapped_column(Text, nullable=False)
    sql_generated: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sql_validated: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Résultats
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    result_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    execution_time: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # en secondes
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Métadonnées LLM
    model_used: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    generation_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )  # temps génération SQL
    temperature: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Feedback utilisateur (pour US-2.6)
    feedback: Mapped[Optional[str]] = mapped_column(
        String(20), nullable=True
    )  # 'positive', 'negative', null
    feedback_comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    feedback_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Feedback workflow (statut admin)
    feedback_status: Mapped[Optional[str]] = mapped_column(
        String(20), nullable=True, default="new"
    )  # 'new', 'reviewed', 'resolved'
    feedback_resolved_by: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    feedback_resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=clock.now)

    # Relations
    user: Mapped["User"] = relationship(
        "User", back_populates="search_history", foreign_keys=[user_id]
    )
    resolver: Mapped[Optional["User"]] = relationship("User", foreign_keys=[feedback_resolved_by])

    def __repr__(self):
        return (
            f"<SearchHistory(id={self.id}, user_id={self.user_id}, "
            f"question='{self.question[:50]}...', success={self.success})>"
        )

    def to_dict(self, include_sql=False, include_feedback=False):
        """
        Convertit en dictionnaire.

        Args:
            include_sql: Inclure le SQL généré (admin only)
            include_feedback: Inclure le feedback utilisateur

        Returns:
            Dictionnaire avec les données
        """
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "question": self.question,
            "success": self.success,
            "result_count": self.result_count,
            "execution_time": self.execution_time,
            "error_message": self.error_message,
            "model_used": self.model_used,
            "generation_time": self.generation_time,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

        if include_sql:
            data["sql_generated"] = self.sql_generated
            data["sql_validated"] = self.sql_validated

        if include_feedback:
            data["feedback"] = self.feedback
            data["feedback_comment"] = self.feedback_comment
            data["feedback_at"] = self.feedback_at.isoformat() if self.feedback_at else None
            data["feedback_status"] = self.feedback_status
            data["feedback_resolved_by"] = self.feedback_resolved_by
            data["feedback_resolved_at"] = (
                self.feedback_resolved_at.isoformat() if self.feedback_resolved_at else None
            )

        return data
