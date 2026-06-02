"""
Modèle pour tracker le stockage utilisateur et appliquer des quotas.
"""

import json
from typing import Optional
from sqlalchemy import Column, Integer, BigInteger, String, ForeignKey, Index, Text
from sqlalchemy.orm import relationship

from app.core import clock
from app.core.database import Base


class UserStorage(Base):
    """Suivi du stockage et quotas par utilisateur."""

    __tablename__ = "user_storage"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True
    )

    # Quotas (en octets)
    quota_limit = Column(BigInteger, default=500 * 1024 * 1024, nullable=False)  # 500 MB par défaut
    # ``quota_used`` historique = bytes occupés par les FICHIERS
    # (datastore filesystem). Mis à jour dans ``StorageManager`` à chaque
    # upload/delete. Phase 2 ajoute ``db_bytes_used`` complémentaire.
    quota_used = Column(BigInteger, default=0, nullable=False)
    # Bytes BDD scopés ``user_id`` (anonymization_terms, conversations,
    # search_history, audit_logs, dashboards, …). Calculé périodiquement
    # par ``app.services.db_usage.update_user_db_usage`` (job quotidien
    # 02:00 + on-demand au render UI). Cf. ``_USER_SCOPED_TABLES``.
    db_bytes_used = Column(BigInteger, default=0, nullable=False)

    # Statistiques
    file_count = Column(Integer, default=0, nullable=False)
    last_upload = Column(Integer, nullable=True)  # Timestamp du dernier upload

    # Timestamps (INTEGER pour compatibilité avec migration)
    created_at = Column(Integer, nullable=False, default=lambda: int(clock.timestamp()))
    updated_at = Column(
        Integer,
        nullable=False,
        default=lambda: int(clock.timestamp()),
        onupdate=lambda: int(clock.timestamp()),
    )

    # Relations
    user = relationship("User", back_populates="storage")

    __table_args__ = (Index("idx_user_storage_user_id", "user_id"),)

    @property
    def total_used(self) -> int:
        """Total occupé : fichiers (``quota_used``) + données BDD
        (``db_bytes_used``). C'est sur ce total que le quota s'applique."""
        return (self.quota_used or 0) + (self.db_bytes_used or 0)

    @property
    def quota_percent(self) -> float:
        """Pourcentage de quota utilisé (fichiers + BDD)."""
        if self.quota_limit == 0:
            return 0.0
        return (self.total_used / self.quota_limit) * 100

    @property
    def quota_remaining(self) -> int:
        """Espace restant en octets (quota - fichiers - BDD)."""
        return max(0, self.quota_limit - self.total_used)

    @property
    def is_quota_exceeded(self) -> bool:
        """``True`` si le quota total (fichiers + BDD) est dépassé."""
        return self.total_used >= self.quota_limit

    def can_upload(self, file_size: int) -> tuple[bool, Optional[str]]:
        """
        Vérifie si un fichier peut être uploadé.

        Le calcul intègre désormais ``db_bytes_used`` : si la croissance BDD
        a déjà saturé le quota, l'upload est refusé même avec 0 fichier.
        Évite l'incohérence "0% fichiers mais quota plein".

        Returns:
            (bool, Optional[str]): (Peut uploader?, Message d'erreur si non)
        """
        if self.total_used + file_size > self.quota_limit:
            remaining = self.quota_remaining
            return False, f"Quota dépassé. Espace restant : {_human_size(remaining)}"
        return True, None

    def __repr__(self) -> str:
        return (
            f"<UserStorage(user_id={self.user_id}, "
            f"used={_human_size(self.quota_used)}/{_human_size(self.quota_limit)}, "
            f"files={self.file_count})>"
        )


class FileMetadata(Base):
    """Métadonnées des fichiers pour recherche rapide (sans scanner le filesystem)."""

    __tablename__ = "file_metadata"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # Chemin et identification
    file_path = Column(
        String(1024), nullable=False
    )  # Chemin relatif dans data/datastore/<user_id>/
    file_hash = Column(String(64), nullable=True)  # SHA-256 pour déduplication future

    # Métadonnées fichier
    filename = Column(String(255), nullable=False)
    extension = Column(String(50), nullable=True)
    mime_type = Column(String(100), nullable=True)
    size_bytes = Column(BigInteger, nullable=False)

    # Métadonnées supplémentaires
    description = Column(String(500), nullable=True)  # Description optionnelle
    tags = Column(String(500), nullable=True)  # Tags séparés par virgules

    # Contexte pour recherches enrichies (ajouté migration 011)
    search_history_id = Column(
        Integer, ForeignKey("search_history.id", ondelete="SET NULL"), nullable=True
    )
    columns_json = Column(Text, nullable=True)  # JSON: ["col1", "col2", ...] pour fichiers importés

    # Timestamps (INTEGER pour compatibilité avec migration)
    created_at = Column(Integer, nullable=False, default=lambda: int(clock.timestamp()))
    updated_at = Column(
        Integer,
        nullable=False,
        default=lambda: int(clock.timestamp()),
        onupdate=lambda: int(clock.timestamp()),
    )

    # Relations
    user = relationship("User")
    search_history = relationship("SearchHistory", foreign_keys=[search_history_id])

    __table_args__ = (
        Index("idx_file_metadata_user_id", "user_id"),
        Index("idx_file_metadata_extension", "extension"),
        Index("idx_file_metadata_filename", "filename"),
        Index("idx_file_metadata_search_history_id", "search_history_id"),
    )

    @property
    def columns(self) -> list[str]:
        """Récupère les colonnes depuis le JSON."""
        if not self.columns_json:
            return []
        try:
            return json.loads(self.columns_json)
        except (json.JSONDecodeError, TypeError):
            return []

    @columns.setter
    def columns(self, value: list[str]):
        """Enregistre les colonnes en JSON."""
        if value:
            self.columns_json = json.dumps(value, ensure_ascii=False)
        else:
            self.columns_json = None

    @property
    def has_context(self) -> bool:
        """Vérifie si le fichier a un contexte (SQL ou colonnes)."""
        return self.search_history_id is not None or bool(self.columns_json)

    @property
    def context_type(self) -> Optional[str]:
        """Type de contexte: 'search' (avec SQL) ou 'import' (colonnes seulement)."""
        if self.search_history_id is not None:
            return "search"
        elif self.columns_json:
            return "import"
        return None

    def __repr__(self) -> str:
        return (
            f"<FileMetadata(user_id={self.user_id}, "
            f"filename={self.filename}, "
            f"size={_human_size(self.size_bytes)}, "
            f"context={self.context_type})>"
        )


def _human_size(size: int) -> str:
    """Conversion octets → format lisible."""
    for unit in ("o", "Ko", "Mo", "Go"):
        if abs(size) < 1024:
            return f"{size:.0f} {unit}" if unit == "o" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} To"
