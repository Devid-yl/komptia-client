"""
Modèles pour la gestion des contacts email.
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column,
    Index,
    Integer,
    String,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    Table,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship, Mapped, mapped_column
from app.core import clock
from app.models.base import Base, iso_or_none

# Table association Many-to-Many contacts <-> listes.
# La PK composite ``(contact_id, distribution_list_id)`` indexe d'abord par
# ``contact_id`` ; un filtre par ``distribution_list_id`` seul ferait un
# full-scan dès que la table dépasse quelques milliers d'associations.
# L'index ci-dessous accélère ``get_distribution_list`` (chargement des
# membres d'une liste) et ``batch_add_members`` (check existence).
contact_list_association = Table(
    "contact_list_association",
    Base.metadata,
    Column("contact_id", Integer, ForeignKey("contacts.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "distribution_list_id",
        Integer,
        ForeignKey("distribution_lists.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Index("ix_assoc_distribution_list_id", "distribution_list_id"),
)


class Contact(Base):
    """
    Modèle représentant un contact destinataire d'emails.
    Chaque contact appartient à un utilisateur.
    """

    __tablename__ = "contacts"
    __table_args__ = (UniqueConstraint("user_id", "email", name="uq_contact_user_email"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # 254 = max RFC 5321 enveloppe SMTP. Aligné avec ``CONTACT_EMAIL_MAX_LENGTH``
    # dans ``app/constants.py``. ``email_validator`` rejette déjà au-delà,
    # mais on garde la borne au schéma pour le SQL (Postgres enforce).
    email: Mapped[str] = mapped_column(String(254), nullable=False, index=True)
    first_name: Mapped[Optional[str]] = mapped_column(String(100))
    last_name: Mapped[Optional[str]] = mapped_column(String(100))
    company: Mapped[Optional[str]] = mapped_column(String(200))
    # 50 chars = E.164 max 15 chiffres + indicatif + format français étendu
    # (``+33 (0)6 12 34 56 78 ext.123``). Aligné avec ``CONTACT_FIELD_LIMITS``.
    phone: Mapped[Optional[str]] = mapped_column(String(50))
    notes: Mapped[Optional[str]] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    unsubscribed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=clock.now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=clock.now,
        onupdate=clock.now,
        nullable=False,
    )

    # Relations
    distribution_lists: Mapped[List["DistributionList"]] = relationship(
        "DistributionList", secondary=contact_list_association, back_populates="contacts"
    )

    def __repr__(self):
        return f"<Contact(email='{self.email}', name='{self.full_name}')>"

    @property
    def full_name(self) -> str:
        """Retourne le nom complet."""
        parts = []
        if self.first_name:
            parts.append(self.first_name)
        if self.last_name:
            parts.append(self.last_name)
        return " ".join(parts) if parts else self.email

    @property
    def is_unsubscribed(self) -> bool:
        """Vérifie si le contact s'est désabonné."""
        return self.unsubscribed_at is not None

    def to_dict(self) -> dict:
        """Sérialise en dictionnaire (golden shape — toute évolution doit
        être accompagnée d'un test de couverture explicite côté frontend).

        ``user_id`` est exposé pour permettre aux tests anti-mass-assignment
        de vérifier qu'un PUT ne change pas le propriétaire. Le frontend
        l'ignore (chaque user ne voit que les contacts dont il est owner,
        donc l'info est triviale pour lui).
        """
        return {
            "id": self.id,
            "user_id": self.user_id,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "full_name": self.full_name,
            "company": self.company,
            "phone": self.phone,
            "notes": self.notes,
            "is_active": self.is_active,
            "is_unsubscribed": self.is_unsubscribed,
            "unsubscribed_at": iso_or_none(self.unsubscribed_at),
            "created_at": iso_or_none(self.created_at),
            "updated_at": iso_or_none(self.updated_at),
        }


class DistributionList(Base):
    """
    Modèle représentant une liste de diffusion (groupe de contacts).
    Chaque liste appartient à un utilisateur.
    """

    __tablename__ = "distribution_lists"
    __table_args__ = (UniqueConstraint("user_id", "name", name="uq_distlist_user_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=clock.now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=clock.now,
        onupdate=clock.now,
        nullable=False,
    )

    # Relations
    contacts: Mapped[List["Contact"]] = relationship(
        "Contact", secondary=contact_list_association, back_populates="distribution_lists"
    )

    def __repr__(self):
        # IMPORTANT : ne JAMAIS toucher ``self.contacts`` ici. Avec
        # SQLAlchemy async, ``len(self.contacts)`` hors session déclenche
        # ``MissingGreenlet`` — un ``print(dl)`` dans un debug naïf
        # crash en cascade. ``id``/``name`` sont eager-loaded.
        return f"<DistributionList id={self.id} name={self.name!r}>"

    def to_dict(self, contact_count: Optional[int] = None) -> dict:
        """Sérialise en dictionnaire.

        Args:
            contact_count: Si fourni, exposé sous la clé ``contact_count``.
                Le service est responsable de le calculer via SQL agrégé
                (``func.count``) — on ne déclenche JAMAIS un lazy-load
                via ``len(self.contacts)`` ici (cf. ``__repr__``).
        """
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "is_active": self.is_active,
            "created_at": iso_or_none(self.created_at),
            "updated_at": iso_or_none(self.updated_at),
        }
        if contact_count is not None:
            data["contact_count"] = contact_count
        return data
