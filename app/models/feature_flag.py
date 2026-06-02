"""
Modele FeatureFlag — drapeaux de fonctionnalites globaux.

Use case principal (Phase 1 DAG) : kill-switch admin pour desactiver
toutes les automatisations en cas d'incident production. Pattern generique
reutilisable pour d'autres flags futurs (ex: mode maintenance, bypass
cache LLM, etc.).

Design :
- `name` UNIQUE : identifie le flag. Convention kebab-case
  (ex: "automations-disabled", "llm-bypass-cache").
- `value` JSON : supporte bool, str, int, dict. Permet des flags
  structures si besoin (ex: "allowlist_users": [1, 5, 12]).
- Pas de defaut en base : un flag absent est consulte via
  `get_flag_value(name, default=...)`. Aucune creation au bootstrap.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.core import clock
from app.core.database import Base


class FeatureFlag(Base):
    """Drapeau de fonctionnalite global."""

    __tablename__ = "F_FEATURE_FLAG"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        comment="Identifiant du flag (kebab-case). Ex: 'automations-disabled'",
    )

    value: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment=(
            "Valeur du flag (bool, str, int, dict serializes en JSON). "
            "Envelopper les scalaires dans {'value': ...} pour le typage stable."
        ),
    )

    description: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        comment="Description libre du flag (usage, consequences)",
    )

    updated_by: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Email de l'admin qui a modifie le flag en dernier",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        onupdate=clock.now,
    )

    def __repr__(self) -> str:
        return f"<FeatureFlag(name='{self.name}', value={self.value})>"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "value": self.value,
            "description": self.description,
            "updated_by": self.updated_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# -----------------------------------------------------------------------------
# Noms canoniques des flags (evite les typos dans le code applicatif)
# -----------------------------------------------------------------------------


FLAG_AUTOMATIONS_DISABLED = "automations-disabled"
"""Kill-switch : si True, le scheduler refuse les nouvelles executions
d'automatisations et l'API /automations/:id/execute retourne 503."""
