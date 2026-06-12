"""
Modèle WebhookTrigger pour Komptia.

Représente un webhook qui déclenche une automatisation via HTTP POST.
Le token sert d'authentification — l'URL webhook est secrète.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import String, Text, Boolean, DateTime, Integer, ForeignKey
from sqlalchemy.orm import relationship, Mapped, mapped_column

from app.core import clock
from app.core.database import Base

if TYPE_CHECKING:
    from app.models.automation import Automation  # noqa: F401


class WebhookTrigger(Base):
    """
    Webhook qui déclenche une automatisation via HTTP POST.

    Chaque POST sur /webhook/{token} lance l'automatisation liée.
    Le token (UUID4) sert d'authentification — l'URL est secrète.
    """

    __tablename__ = "F_WEBHOOK_TRIGGER"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    automation_id: Mapped[int] = mapped_column(
        ForeignKey("F_AUTOMATION.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Automatisation déclenchée par ce webhook",
    )
    token: Mapped[str] = mapped_column(
        String(36),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: str(uuid.uuid4()),
        comment="Token UUID4 servant d'authentification dans l'URL",
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Description libre du webhook (ex: 'Depuis GitHub Actions')",
    )
    hmac_secret: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        default=None,
        comment=(
            "Secret partagé HMAC-SHA256 (hex/urlsafe, généré côté serveur). "
            "NULL = signature non exigée (compat token-seul) ; non-NULL = "
            "l'inbound exige X-Komptia-Signature + X-Komptia-Timestamp"
        ),
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Webhook actif ou désactivé",
    )
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Date du dernier déclenchement",
    )
    trigger_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Nombre total de déclenchements",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        comment="Date de création du webhook",
    )

    # Relationship (many-to-one)
    automation: Mapped["Automation"] = relationship("Automation", back_populates="webhooks")

    def __repr__(self):
        return (
            f"<WebhookTrigger(id={self.id}, "
            f"automation_id={self.automation_id}, "
            f"active={self.is_active})>"
        )

    def to_dict(self, include_url: bool = False, base_url: str = "", include_secret: bool = False):
        """Convertit en dict pour JSON API.

        Args:
            include_url: Inclure l'URL complète du webhook.
            base_url: Base URL (ex: https://komptia.local:8443).
            include_secret: Inclure ``hmac_secret`` en clair. Pattern
                « show-once » : UNIQUEMENT à la création/rotation (le caller
                doit le noter immédiatement) — JAMAIS dans les listes (un
                XSS/log/screenshot de la liste ne doit pas exfiltrer les
                secrets de signature). ``signature_required`` reste toujours
                exposé pour que l'UI sache l'état sans voir le secret.
        """
        result = {
            "id": self.id,
            "automation_id": self.automation_id,
            "token": self.token,
            "description": self.description,
            "is_active": self.is_active,
            "signature_required": bool(self.hmac_secret),
            "last_triggered_at": clock.iso_utc(self.last_triggered_at),
            "trigger_count": self.trigger_count,
            "created_at": clock.iso_utc(self.created_at),
        }
        if include_secret and self.hmac_secret:
            result["hmac_secret"] = self.hmac_secret
        if include_url:
            result["webhook_url"] = f"{base_url}/webhook/{self.token}"
        return result
