"""
Modèle UserPreference — Mémoire utilisateur persistante pour Iris.

Stocke les préférences, le vocabulaire métier et les requêtes fréquentes
de chaque utilisateur pour personnaliser les réponses de l'agent.
"""

from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel, ensure_utc

if TYPE_CHECKING:
    from app.models.user import User


class UserPreference(BaseModel):
    """
    Modèle pour stocker les préférences utilisateur persistantes.

    Categories:
        - vocabulary: Termes métier, abréviations, alias
        - preference: Préférences générales (langue, format, etc.)
        - frequent_query: Requêtes fréquentes mémorisées
        - ml_context: Contexte pour ML (historique décisions, patterns)
    """

    __tablename__ = "user_preferences"

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    key: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False, default="preference")

    user: Mapped["User"] = relationship("User", back_populates="preferences")

    __table_args__ = (
        UniqueConstraint("user_id", "key", name="uq_user_preference_key"),
        Index("ix_user_pref_category", "user_id", "category"),
    )

    def __repr__(self) -> str:
        return (
            f"<UserPreference(id={self.id}, user_id={self.user_id}, "
            f"key='{self.key}', category='{self.category}')>"
        )

    def to_dict(self) -> dict:
        """Convertit le modèle en dictionnaire"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "key": self.key,
            "value": self.value,
            "category": self.category,
            "created_at": (ensure_utc(self.created_at).isoformat() if self.created_at else None),
            "updated_at": (ensure_utc(self.updated_at).isoformat() if self.updated_at else None),
        }
