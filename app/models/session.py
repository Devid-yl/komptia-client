"""
Modèle Session - Gestion des sessions utilisateur
"""

from datetime import datetime, timedelta
from typing import TYPE_CHECKING
import secrets

from sqlalchemy import String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core import clock
from app.core.database import Base
from app.models.base import ensure_utc
from app.config import config

if TYPE_CHECKING:
    from app.models.user import User


def generate_session_id() -> str:
    """Génère un ID de session sécurisé"""
    return secrets.token_hex(32)


def default_expiration() -> datetime:
    """Calcule la date d'expiration par défaut"""
    hours = config.security.session_timeout_hours
    return clock.now() + timedelta(hours=hours)


class Session(Base):
    """
    Modèle de session utilisateur

    Attributs:
        id: Token de session (64 caractères hex)
        user_id: ID de l'utilisateur
        ip_address: Adresse IP de la connexion
        user_agent: User-Agent du navigateur
        created_at: Date de création
        expires_at: Date d'expiration
        last_activity: Dernière activité
    """

    __tablename__ = "sessions"

    # ID = token de session
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_session_id)

    # Utilisateur
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Métadonnées connexion
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)  # IPv6 max length
    user_agent: Mapped[str] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=clock.now, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime, default=default_expiration, nullable=False, index=True
    )
    last_activity: Mapped[datetime] = mapped_column(DateTime, default=clock.now, nullable=False)

    # État
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    # Indique que l'utilisateur a coché « Garder ma session ouverte » à la
    # connexion. Pilote la durée de session : ``session_remember_timeout_hours``
    # (168h = 7j par défaut) au lieu de ``session_timeout_hours`` (8h). Le
    # glissement (``refresh``) lit aussi ce champ pour rester cohérent.
    # Bug 2026-05-26 : sans ce champ, la session BDD plafonnait à 8h même
    # avec remember_me=True → l'utilisateur était déconnecté avant l'expiration
    # du cookie navigateur (UX brisée).
    remember_me: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relations
    user: Mapped["User"] = relationship("User", back_populates="sessions")

    def __repr__(self) -> str:
        return f"<Session(id='{self.id[:8]}...', user_id={self.user_id})>"

    @property
    def is_expired(self) -> bool:
        """Vérifie si la session a expiré"""
        return clock.now() > ensure_utc(self.expires_at)

    @property
    def is_valid(self) -> bool:
        """Vérifie si la session est valide"""
        return not self.is_expired

    def refresh(self) -> None:
        """Rafraîchit la session (met à jour last_activity et expires_at).

        La durée appliquée dépend de ``self.remember_me`` :
        - True  → ``session_remember_timeout_hours`` (168h / 7j par défaut)
        - False → ``session_timeout_hours`` (8h par défaut)

        Sans cette distinction, le glissement écrasait le timeout étendu
        des sessions remember_me dès la première activité → bug 2026-05-26.
        """
        self.last_activity = clock.now()
        if self.remember_me:
            hours = config.security.session_remember_timeout_hours
        else:
            hours = config.security.session_timeout_hours
        self.expires_at = clock.now() + timedelta(hours=hours)

    def to_dict(self) -> dict:
        """Serialize WITHOUT session token — the id IS the secret token."""
        return {
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "is_active": self.is_active,
            "is_expired": self.is_expired,
        }

    @property
    def remaining_time(self) -> timedelta:
        """Temps restant avant expiration"""
        if self.is_expired:
            return timedelta(0)
        return ensure_utc(self.expires_at) - clock.now()
