"""
Modèle Report – Stockage et archivage des rapports générés.
US-4.5 : Stockage & Archivage Rapports
"""

import secrets
from datetime import datetime
from typing import Optional

from sqlalchemy import Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core import clock
from app.core.database import Base
from app.models.base import ensure_utc, iso_or_none


class Report(Base):
    """
    Rapport généré et archivé dans le système.
    Stocke les métadonnées et le chemin vers le fichier physique.
    """

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Métadonnées
    title: Mapped[str] = mapped_column(
        String(300), nullable=False, index=True, comment="Titre du rapport"
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="Description ou résumé du rapport"
    )
    report_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="custom",
        index=True,
        comment="Type: 'ca_mensuel', 'balance_clients', 'factures_retard', 'custom'",
    )

    # Fichier
    file_path: Mapped[str] = mapped_column(
        String(500), nullable=False, comment="Chemin relatif du fichier dans data/reports/"
    )
    file_name: Mapped[str] = mapped_column(
        String(255), nullable=False, comment="Nom du fichier original"
    )
    file_format: Mapped[str] = mapped_column(
        String(10), nullable=False, default="pdf", comment="Format: 'pdf', 'csv', 'xlsx'"
    )
    file_size: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True, comment="Taille du fichier en octets"
    )

    # Propriétaire
    created_by_user_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Utilisateur ayant généré le rapport",
    )

    # Lien avec automatisation (optionnel)
    automation_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("F_AUTOMATION.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Automatisation source si généré automatiquement",
    )
    execution_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("F_EXECUTION.id", ondelete="SET NULL"),
        nullable=True,
        comment="Exécution source",
    )

    # Partage sécurisé
    share_token: Mapped[Optional[str]] = mapped_column(
        String(64),
        unique=True,
        nullable=True,
        index=True,
        comment="Token pour lien de partage public",
    )
    share_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True, comment="Expiration du lien de partage"
    )
    share_download_count: Mapped[int] = mapped_column(
        Integer, default=0, comment="Nombre de téléchargements via le lien"
    )

    # Rétention
    retention_days: Mapped[int] = mapped_column(
        Integer, default=90, nullable=False, comment="Nombre de jours avant suppression automatique"
    )
    is_archived: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Rapport archivé (ne sera pas supprimé par le cleanup)",
    )

    # Horodatage
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=clock.now, nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=clock.now,
        onupdate=clock.now,
    )

    # Relations
    user = relationship("User", foreign_keys=[created_by_user_id])
    automation = relationship("Automation", foreign_keys=[automation_id])

    def __repr__(self):
        return f"<Report(id={self.id}, title='{self.title}', format={self.file_format})>"

    def generate_share_token(self, expires_hours: int = 72) -> str:
        """Génère un token de partage sécurisé avec expiration."""
        from datetime import timedelta

        self.share_token = secrets.token_urlsafe(32)
        self.share_expires_at = clock.now() + timedelta(hours=expires_hours)
        self.share_download_count = 0
        return self.share_token

    @property
    def is_share_valid(self) -> bool:
        """Vérifie si le lien de partage est encore valide."""
        if not self.share_token:
            return False
        if self.share_expires_at and clock.now() > ensure_utc(self.share_expires_at):
            return False
        return True

    @property
    def is_expired(self) -> bool:
        """Vérifie si le rapport a dépassé sa période de rétention."""
        from datetime import timedelta

        if self.is_archived:
            return False
        expiry = ensure_utc(self.created_at) + timedelta(days=self.retention_days)
        return clock.now() > expiry

    @property
    def file_size_human(self) -> str:
        """Taille du fichier en format lisible (pure, sans side-effect)."""
        if not self.file_size:
            return "—"
        size = float(self.file_size)
        for unit in ("o", "Ko", "Mo", "Go"):
            if size < 1024:
                return f"{size:.0f} {unit}"
            size /= 1024
        return f"{size:.1f} To"

    def to_dict(self) -> dict:
        """Sérialise en dictionnaire."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "report_type": self.report_type,
            "file_name": self.file_name,
            "file_format": self.file_format,
            "file_size": self.file_size,
            "file_size_human": self.file_size_human,
            "created_by_user_id": self.created_by_user_id,
            "automation_id": self.automation_id,
            "share_token": self.share_token,
            "share_expires_at": iso_or_none(self.share_expires_at),
            "share_download_count": self.share_download_count,
            "is_share_valid": self.is_share_valid,
            "retention_days": self.retention_days,
            "is_archived": self.is_archived,
            "is_expired": self.is_expired,
            "created_at": iso_or_none(self.created_at),
            "updated_at": iso_or_none(self.updated_at),
        }
