"""Modèle ``DatabaseConnection`` — configuration des connexions BDD admin.

Une seule connexion peut être marquée ``is_active=True`` à la fois — invariant
maintenu par :func:`app.services.database.db_config_service.activate_connection`
via un ``UPDATE`` atomique. La contrainte unique partielle SQLite ``WHERE
is_active`` n'est pas modélisée ici car SQLAlchemy ne propose pas un mapping
portable, et le service est la seule porte d'écriture.

Le mot de passe est stocké chiffré (Fernet, dérivation PBKDF2-HMAC-SHA256
côté service) — JAMAIS en clair, JAMAIS dans la sortie ``to_dict()``. Le
paramètre ``include_password=True`` reste exposé pour les tests legacy
(``tests/unit/test_db_config_service_extended.py``) qui valident que le
champ encryptedstait sérialisable en cas d'export interne ; il ne doit
**jamais** être passé depuis un handler — un `staticmethod` ne peut pas
appliquer cette règle, donc on s'appuie sur la review code (cf. peer
``app/handlers/admin_smtp.py:_to_safe_dict``).

Les ``CheckConstraint`` valident les bornes au niveau BDD — défense-in-depth
en plus de la validation handler. SQLite respecte ces contraintes via
``PRAGMA foreign_keys = ON`` (déjà activé par ``app.core.database``).
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum as SQLEnum,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import BaseModel


class DatabaseType(enum.Enum):
    """Types de bases de données supportées (extensible)."""

    SQLSERVER = "sqlserver"
    # Extensible pour PostgreSQL, MySQL, etc.


class DatabaseConnection(BaseModel):
    """Configuration de connexion à une BDD source (lecture seule)."""

    __tablename__ = "database_connections"

    # Bornes validées au niveau BDD (défense-in-depth après la validation
    # handler). Cohérent avec _PORT_MIN/_PORT_MAX dans le handler.
    # NOTE : ``max_rows`` n'est PLUS borné côté BDD — convention Komptia
    # = l'admin décide via /admin/database, pas de hard cap technique.
    # Si une BDD existante a encore le CheckConstraint
    # ``ck_db_conn_max_rows_range`` (BETWEEN 1 AND 1000000), il restera
    # actif tant que la table ``db_connections`` n'est pas recréée
    # (``make db-init`` ou migration manuelle). Pour les BDD neuves =
    # aucune borne BDD, seul ``_MAX_ROWS_MIN``/``_MAX_ROWS_MAX`` côté
    # handler s'applique.
    __table_args__ = (
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_db_conn_port_range"),
        CheckConstraint("timeout BETWEEN 1 AND 600", name="ck_db_conn_timeout_range"),
    )

    # Nom descriptif de la connexion
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        unique=True,
        comment="Nom descriptif (ex: Sage Production, Sage Test)",
    )

    # Type de BDD
    db_type: Mapped[DatabaseType] = mapped_column(
        SQLEnum(DatabaseType), default=DatabaseType.SQLSERVER, nullable=False
    )

    # Paramètres de connexion
    host: Mapped[str] = mapped_column(String(255), nullable=False, comment="Adresse du serveur")
    port: Mapped[int] = mapped_column(Integer, default=1433, nullable=False)
    database: Mapped[str] = mapped_column(
        String(255), nullable=False, comment="Nom de la base de données"
    )
    username: Mapped[str] = mapped_column(String(255), nullable=False)

    # Mot de passe chiffré (Fernet via PBKDF2-HMAC-SHA256, salt persisté)
    encrypted_password: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Mot de passe chiffré via Fernet"
    )

    # Options
    timeout: Mapped[int] = mapped_column(
        Integer, default=30, nullable=False, comment="Timeout en secondes"
    )
    max_rows: Mapped[int] = mapped_column(
        Integer,
        default=10000,
        nullable=False,
        comment=(
            "Nombre max de lignes retournées. Défaut relevé 1000→10000 le "
            "2026-05-29 (demande user). Configurable par connexion via "
            "/admin/database, aucun hard cap applicatif (cf. no_double_cap)."
        ),
    )

    # Statut
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Si True, cette config est utilisée par le connecteur Sage",
    )

    server_version: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="Label court détecté au sync (ex: 'SQL Server 2016')"
    )

    # Dernière vérification de connexion
    last_tested_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_test_success: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    last_test_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Audit trail (qui a créé/modifié/activé)
    created_by: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    updated_by: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    last_activated_by: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    last_activated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def to_dict(self, include_password: bool = False) -> dict:
        """Sérialise en dict (sans mot de passe par défaut).

        ``include_password=True`` est réservé aux tests internes — un
        handler ne doit JAMAIS le passer (le mot de passe chiffré reste
        un secret applicatif : exposer la string Fernet permet à un
        attaquant qui aurait accès à FERNET_KEY de récupérer le clear).
        """
        data = {
            "id": self.id,
            "name": self.name,
            "db_type": self.db_type.value,
            "host": self.host,
            "port": self.port,
            "database": self.database,
            "username": self.username,
            "timeout": self.timeout,
            "max_rows": self.max_rows,
            "is_active": self.is_active,
            "server_version": self.server_version,
            "last_tested_at": self.last_tested_at.isoformat() if self.last_tested_at else None,
            "last_test_success": self.last_test_success,
            "last_test_message": self.last_test_message,
            "last_activated_at": (
                self.last_activated_at.isoformat() if self.last_activated_at else None
            ),
            "last_activated_by": self.last_activated_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_password:
            data["encrypted_password"] = self.encrypted_password
        return data

    def __repr__(self) -> str:
        return (
            f"<DatabaseConnection(name='{self.name}', host='{self.host}', active={self.is_active})>"
        )
