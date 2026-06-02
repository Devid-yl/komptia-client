"""
Modèle User - Gestion des utilisateurs
"""

from datetime import datetime
from typing import Optional, List, TYPE_CHECKING

from sqlalchemy import String, Boolean, Text, DateTime, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.session import Session
    from app.models.search_history import SearchHistory
    from app.models.automation import Automation
    from app.models.user_storage import UserStorage
    from app.models.conversation import Conversation
    from app.models.user_preference import UserPreference
    from app.models.anonymization_term import AnonymizationTerm
    from app.models.data_access_rule import DataAccessRule
    from app.models.user_onboarding_progress import UserOnboardingProgress
    from app.models.user_activity_summary import UserActivitySummary


class UserRole(enum.Enum):
    """Rôles utilisateur disponibles"""

    ADMIN = "admin"
    USER = "user"


class User(BaseModel):
    """
    Modèle utilisateur

    Attributs:
        username: Nom d'utilisateur unique
        email: Email unique
        password_hash: Hash bcrypt du mot de passe
        role: Rôle (admin, user, reader)
        permissions: Permissions JSON (tables, montants max, etc.)
        is_active: Compte actif ou désactivé
        last_login: Dernière connexion
    """

    __tablename__ = "users"

    # Identifiants
    # ``email`` est l'identifiant de connexion (depuis 2026-05-11). ``username``
    # est conservé comme nom d'affichage (sidebar, audit logs textuels). Taille
    # 254 alignée RFC 5321 et ``_EMAIL_MAX_LEN`` côté settings handler.
    # L'unicité case-insensitive est garantie par l'index NOCASE recréé en
    # migration (cf. ``app/core/database.py``).
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False, index=True)

    # Authentification
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Rôle et permissions
    role: Mapped[UserRole] = mapped_column(SQLEnum(UserRole), default=UserRole.USER, nullable=False)
    permissions: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="JSON: {tables: [], max_amount: int}"
    )

    # Statut
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, insert_default=True, nullable=False
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Mémoire Iris user-scoped (parité ``copilot_memory`` côté workbook).
    # Une seule chaîne consolidée (≤ ``IRIS_USER_MEMORY_MAX_OUTPUT_CHARS``)
    # injectée inconditionnellement dans le system prompt de toutes les
    # conversations Iris de cet utilisateur. Auto-mise à jour fin-de-run
    # via fusion LLM (cf. ``app/services/ai/iris_user_memory.py``). Le user
    # peut consulter/éditer/effacer via ``/data-privacy``.
    iris_memory: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relations
    sessions: Mapped[List["Session"]] = relationship(
        "Session", back_populates="user", cascade="all, delete-orphan"
    )
    search_history: Mapped[List["SearchHistory"]] = relationship(
        "SearchHistory",
        back_populates="user",
        cascade="all, delete-orphan",
        order_by="desc(SearchHistory.created_at)",
        foreign_keys="[SearchHistory.user_id]",
    )
    # Relation `saved_queries` supprimee : la table SavedQuery a ete
    # droppee au profit du datastore filesystem (.sql files). La
    # `cascade="all, delete-orphan"` est portee maintenant par les
    # operations filesystem cote `/api/datastore/*`.
    automations: Mapped[List["Automation"]] = relationship(
        "Automation",
        back_populates="user",
        cascade="all, delete-orphan",
        order_by="desc(Automation.created_at)",
    )
    storage: Mapped[Optional["UserStorage"]] = relationship(
        "UserStorage", back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    conversations: Mapped[List["Conversation"]] = relationship(
        "Conversation",
        back_populates="user",
        cascade="all, delete-orphan",
        order_by="desc(Conversation.created_at)",
    )
    preferences: Mapped[List["UserPreference"]] = relationship(
        "UserPreference",
        back_populates="user",
        cascade="all, delete-orphan",
        order_by="desc(UserPreference.created_at)",
    )
    anonymization_terms: Mapped[List["AnonymizationTerm"]] = relationship(
        "AnonymizationTerm",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    data_access_rules: Mapped[List["DataAccessRule"]] = relationship(
        "DataAccessRule",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="[DataAccessRule.user_id]",
    )
    onboarding_progress: Mapped[List["UserOnboardingProgress"]] = relationship(
        "UserOnboardingProgress",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    activity_summary: Mapped[Optional["UserActivitySummary"]] = relationship(
        "UserActivitySummary",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username='{self.username}', role={self.role.value})>"

    @property
    def is_admin(self) -> bool:
        """Vérifie si l'utilisateur est admin"""
        return self.role == UserRole.ADMIN

    def has_permission(self, permission: str) -> bool:
        """
        Vérifie si l'utilisateur a une permission spécifique
        Les admins ont toutes les permissions
        """
        if self.is_admin:
            return True

        if not self.permissions:
            return False

        import json

        try:
            perms = json.loads(self.permissions)
            return permission in perms.get("permissions", [])
        except (json.JSONDecodeError, KeyError):
            return False

    def can_access_table(self, table_name: str) -> bool:
        """Vérifie si l'utilisateur peut accéder à une table Sage"""
        if self.is_admin:
            return True

        if not self.permissions:
            return False

        import json

        try:
            perms = json.loads(self.permissions)
            allowed_tables = perms.get("tables", [])
            return table_name in allowed_tables or "*" in allowed_tables
        except (json.JSONDecodeError, KeyError):
            return False

    # Security fields excluded from serialization
    _SENSITIVE_FIELDS = {"password_hash"}

    def to_dict(self) -> dict:
        """Sérialise en dictionnaire, SANS les champs sensibles (password_hash)."""
        return {
            col.name: getattr(self, col.name)
            for col in self.__table__.columns
            if col.name not in self._SENSITIVE_FIELDS
        }
