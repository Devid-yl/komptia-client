"""
Modèle SMTPSettings – Configuration SMTP pour l'envoi d'emails.

⚠️ DÉPRÉCIÉ : Ce modèle n'est plus utilisé depuis la migration vers une config globale.
La configuration SMTP est maintenant centralisée dans le fichier .env (voir config.yaml).

Ce modèle est conservé pour:
- La compatibilité de la base de données existante
- L'historique des migrations (alembic)
- Éviter les erreurs d'import

Nouvelle approche:
- Configuration globale via .env (SMTP_HOST, SMTP_USER, etc.)
- Personnalisation automatique du nom d'expéditeur par utilisateur
- Reply-to configuré avec l'email de l'utilisateur
- Voir: docs/SMTP_CONFIGURATION.md
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import relationship

from app.core import clock
from app.core.database import Base


class SMTPSettings(Base):
    """
    Configuration SMTP pour l'envoi d'emails.
    Une configuration par utilisateur.
    """

    __tablename__ = "smtp_settings"
    __table_args__ = (Index("idx_smtp_user", "user_id", unique=True),)

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Utilisateur propriétaire
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        comment="Utilisateur propriétaire",
    )

    # Configuration serveur
    host = Column(
        String(255),
        nullable=False,
        default="localhost",
        comment="Serveur SMTP (ex: smtp.gmail.com)",
    )
    port = Column(
        Integer, nullable=False, default=587, comment="Port SMTP (587 pour TLS, 465 pour SSL)"
    )
    username = Column(String(255), nullable=False, default="", comment="Identifiant SMTP")
    password = Column(
        Text, nullable=False, default="", comment="Mot de passe ou token SMTP (crypté)"
    )

    # Options de sécurité
    use_tls = Column(Boolean, nullable=False, default=True, comment="Utiliser STARTTLS")
    use_ssl = Column(Boolean, nullable=False, default=False, comment="Utiliser SSL/TLS direct")

    # Expéditeur par défaut
    from_email = Column(
        String(255),
        nullable=False,
        default="noreply@komptia.local",
        comment="Email expéditeur par défaut",
    )
    from_name = Column(
        String(255), nullable=True, default="Komptia", comment="Nom affiché de l'expéditeur"
    )

    # Paramètres de retry
    max_retries = Column(
        Integer, nullable=False, default=3, comment="Nombre de tentatives en cas d'erreur"
    )
    retry_delay = Column(
        Integer, nullable=False, default=5, comment="Délai entre tentatives (secondes)"
    )

    # Activation
    enabled = Column(Boolean, nullable=False, default=False, comment="Configuration active")

    # Horodatage
    created_at = Column(DateTime, default=clock.now, nullable=False)
    updated_at = Column(
        DateTime,
        default=clock.now,
        onupdate=clock.now,
    )

    # Relation
    user = relationship("User", foreign_keys=[user_id])

    def __repr__(self):
        return f"<SMTPSettings(user_id={self.user_id}, host='{self.host}', port={self.port}, enabled={self.enabled})>"

    def to_dict(self, include_password=False) -> dict:
        """Sérialise en dictionnaire."""
        result = {
            "id": self.id,
            "user_id": self.user_id,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "use_tls": self.use_tls,
            "use_ssl": self.use_ssl,
            "from_email": self.from_email,
            "from_name": self.from_name,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_password:
            result["password"] = self.password
        return result
