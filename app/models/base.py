"""
Modèle de base SQLAlchemy
Mixins et classes utilitaires pour tous les modèles
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.clock import ensure_utc
from app.core.database import Base

# ``ensure_utc`` vit désormais dans ``app.core.clock`` (source de vérité unique
# du temps). On le réexporte ici pour préserver les ~30 imports existants
# ``from app.models.base import ensure_utc`` sans churn — la convention de
# normalisation UTC reste donc définie à UN seul endroit.
__all__ = ["ensure_utc", "iso_or_none", "TimestampMixin", "BaseModel"]


def iso_or_none(dt: Optional[datetime]) -> Optional[str]:
    """Sérialise un datetime en ISO 8601 UTC, ou ``None`` si absent.

    Helper de sérialisation utilisé dans les ``to_dict()`` des modèles pour
    éviter la duplication ``ensure_utc(x).isoformat() if x else None`` — qui
    apparaît une trentaine de fois dans le projet (cf. ``user_preference``,
    ``user_onboarding_progress``, etc.).
    """
    aware = ensure_utc(dt)
    return aware.isoformat() if aware else None


class TimestampMixin:
    """
    Mixin pour ajouter created_at et updated_at automatiques
    """

    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, onupdate=func.now(), nullable=True
    )


class BaseModel(Base, TimestampMixin):
    """
    Modèle de base avec ID et timestamps
    Tous les modèles doivent hériter de cette classe
    """

    __abstract__ = True

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(id={self.id})>"

    def to_dict(self) -> dict:
        """Convertit le modèle en dictionnaire"""
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}
