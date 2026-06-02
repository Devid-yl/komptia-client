"""
Modèle LoginAttempt - Suivi des tentatives de connexion
Utilisé pour le rate limiting persistant basé sur SQLite
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.core import clock
from app.models.base import Base


class LoginAttempt(Base):
    """
    Modèle pour enregistrer les tentatives de connexion
    Permet le rate limiting persistant par IP

    Attributs:
        ip_address: Adresse IP du client (max 45 chars pour IPv6)
        username: Nom d'utilisateur tenté (optionnel)
        success: True si la tentative a réussi
        attempted_at: Timestamp de la tentative
    """

    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    attempted_at: Mapped[datetime] = mapped_column(DateTime, default=clock.now, index=True)

    __table_args__ = (Index("idx_ip_attempted_at", "ip_address", "attempted_at"),)

    def __repr__(self) -> str:
        status = "✓" if self.success else "✗"
        return f"<LoginAttempt(ip={self.ip_address}, user={self.username}, {status})>"
