"""
Modèle EmailLog – Journal des emails envoyés par les automatisations.
"""

import json as _json
from datetime import datetime
from typing import Optional

from sqlalchemy import Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core import clock
from app.core.database import Base
from app.models.base import iso_or_none


class EmailLog(Base):
    """
    Trace chaque email envoyé par le système (automatisations, notifications…).
    """

    __tablename__ = "email_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Lien optionnel vers l'automatisation / exécution source
    automation_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("F_AUTOMATION.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    execution_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("F_EXECUTION.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Destinataire(s) – stocké comme JSON array string
    recipients: Mapped[str] = mapped_column(
        Text, nullable=False, comment="JSON array des destinataires"
    )
    cc_recipients: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="JSON array CC"
    )
    bcc_recipients: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="JSON array BCC"
    )

    # Contenu
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    template_name: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True, comment="Nom du template utilisé"
    )

    # Résultat
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    message_id: Mapped[Optional[str]] = mapped_column(
        String(200), nullable=True, comment="Message-ID SMTP"
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Pièces jointes
    attachment_count: Mapped[int] = mapped_column(Integer, default=0)
    attachment_names: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="JSON array noms fichiers"
    )

    # Métadonnées
    sent_at: Mapped[datetime] = mapped_column(
        DateTime, default=clock.now, nullable=False, index=True
    )
    sent_by_user_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relations
    automation = relationship("Automation", foreign_keys=[automation_id])
    execution = relationship("Execution", foreign_keys=[execution_id])

    def __repr__(self):
        return f"<EmailLog(id={self.id}, subject='{self.subject}', success={self.success})>"

    def _safe_json_loads(self, value: Optional[str]) -> list:
        """Parse JSON de manière sûre, retourne [] en cas d'erreur."""
        if not value:
            return []
        try:
            result = _json.loads(value)
            return result if isinstance(result, list) else []
        except (ValueError, TypeError, _json.JSONDecodeError):
            return []

    def to_dict(self) -> dict:
        """Sérialise pour ``/api/email-history``.

        ``bcc_recipients`` est exposé : ``/email-history`` est un log
        scopé au SENDER (ou à l'admin). Le sender voit SES propres
        envois — y compris ses BCC, qu'il a lui-même renseignés. La
        confidentialité BCC concerne les co-destinataires (qui n'ont
        jamais accès à ce log), pas l'auteur du mail.
        """
        return {
            "id": self.id,
            "automation_id": self.automation_id,
            "execution_id": self.execution_id,
            "recipients": self._safe_json_loads(self.recipients),
            "cc_recipients": self._safe_json_loads(self.cc_recipients),
            "bcc_recipients": self._safe_json_loads(self.bcc_recipients),
            "subject": self.subject,
            "template_name": self.template_name,
            "success": self.success,
            "message_id": self.message_id,
            "error_message": self.error_message,
            "attachment_count": self.attachment_count,
            "attachment_names": self._safe_json_loads(self.attachment_names),
            "sent_at": iso_or_none(self.sent_at),
            "sent_by_user_id": self.sent_by_user_id,
        }
