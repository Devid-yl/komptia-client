"""
Modèle SMTPGlobalConfig – Configuration SMTP globale pour tous les utilisateurs.
Gérée uniquement par les admins via l'interface web.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import Integer, String, Boolean, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.core import clock
from app.core.database import Base
from app.models.base import iso_or_none


class SMTPGlobalConfig(Base):
    """
    Configuration SMTP unique pour toute l'application.
    Gérée uniquement par les administrateurs.
    """

    __tablename__ = "smtp_global_config"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Configuration serveur
    host: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="localhost",
        comment="Serveur SMTP (ex: smtp.gmail.com)",
    )
    port: Mapped[int] = mapped_column(
        Integer, nullable=False, default=587, comment="Port SMTP (587 pour TLS, 465 pour SSL)"
    )
    username: Mapped[str] = mapped_column(
        String(255), nullable=False, default="", comment="Identifiant SMTP"
    )
    password: Mapped[str] = mapped_column(
        Text, nullable=False, default="", comment="Mot de passe ou token SMTP"
    )

    # Options de sécurité
    use_tls: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, comment="Utiliser STARTTLS"
    )

    # Expéditeur par défaut
    from_email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="noreply@komptia.local",
        comment="Email expéditeur",
    )
    from_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        default=None,
        comment="Nom de base de l'expéditeur (fallback sur company_name si non défini)",
    )

    # Nom de l'organisation utilisé partout (templates email, PDF, branding
    # global). Doit rester DYNAMIQUE — pas de hardcode d'un nom particulier
    # (axe Komptia 6 : généricité). Si NULL au boot, le helper
    # ``app.services.branding.get_company_name`` retourne le placeholder
    # neutre ``"[Entreprise à configurer]"`` pour ne pas crasher mais signaler
    # la config manquante à l'admin.
    company_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        default=None,
        comment="Nom de l'organisation (branding global). Configurable via /admin/settings.",
    )

    # Email destinataire du bouton "Signaler un bug" (feedback-reporter) ET
    # adresse d'approbation de la casquette Iris-DBA-write (SSoT partagé).
    # Override le default ``config.support_email`` (vide par défaut).
    # NULL = utilise le default config.py (cohérent avec le pattern
    # ``feedback_env_only_crypto_keys.md`` : les vars SMTP se configurent
    # dans l'app via /admin/, le default sert juste de fallback). Si l'admin
    # déploie Komptia chez une autre organisation, il peut surcharger ici.
    support_email: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        default=None,
        comment="Email destinataire des signalements (override config.support_email). Configurable via /admin/smtp-config.",
    )

    # Paramètres de retry
    max_retries: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3, comment="Nombre de tentatives en cas d'erreur"
    )
    retry_delay: Mapped[int] = mapped_column(
        Integer, nullable=False, default=5, comment="Délai entre tentatives (secondes)"
    )

    # Activation
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, comment="Configuration active"
    )

    # Horodatage
    created_at: Mapped[datetime] = mapped_column(DateTime, default=clock.now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=clock.now,
        onupdate=clock.now,
    )
    updated_by: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True, comment="Admin qui a modifié"
    )

    def __repr__(self):
        return f"<SMTPGlobalConfig(host='{self.host}', port={self.port}, enabled={self.enabled})>"

    def to_dict(self, include_password=False) -> dict:
        """Sérialise en dictionnaire."""
        result = {
            "id": self.id,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "use_tls": self.use_tls,
            "from_email": self.from_email,
            "from_name": self.from_name,
            "company_name": self.company_name,
            "support_email": self.support_email,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "enabled": self.enabled,
            "created_at": iso_or_none(self.created_at),
            "updated_at": iso_or_none(self.updated_at),
            "updated_by": self.updated_by,
        }
        if include_password:
            result["password"] = self.password
        return result
