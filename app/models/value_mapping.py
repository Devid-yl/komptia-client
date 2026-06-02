"""
Modèle ValueMapping — Cache des valeurs réelles distinctes par (table, colonne).

Stocké dans SQLCipher (chiffré). JAMAIS exposé via le pipeline RAG.
Sert à résoudre les termes utilisateur (« montre-moi DUPONT ») vers la
bonne colonne SQL via lookup case-insensitive sur ``real_value_lower``.

L'anonymisation runtime des valeurs PII envoyées au LLM est gérée
exclusivement par ``/data-privacy`` (table ``anonymization_terms`` + le
``Pseudonymizer`` runtime), pas par ce cache. Cf. décision 2026-05-22.
"""

from datetime import datetime

from sqlalchemy import String, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.core import clock
from app.models.base import Base


class ValueMapping(Base):
    """Cache des vraies valeurs distinctes Sage (par table, colonne).

    Quand l'utilisateur dit "montre-moi DUPONT", le système cherche la
    colonne contenant cette valeur via ``real_value_lower``. Cette table
    n'est JAMAIS interrogée par le RAG ni envoyée au LLM en tant que
    table source — seul son contenu (les vraies valeurs) peut être
    référencé indirectement via les outils Iris, après application du
    Pseudonymizer si le terme est configuré dans /data-privacy.
    """

    __tablename__ = "value_mapping"

    id: Mapped[int] = mapped_column(primary_key=True)

    table_name: Mapped[str] = mapped_column(String(100), nullable=False)
    column_name: Mapped[str] = mapped_column(String(100), nullable=False)

    real_value: Mapped[str] = mapped_column(String(200), nullable=False)
    real_value_lower: Mapped[str] = mapped_column(String(200), nullable=False)

    value_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="text"
    )  # text, number, date, code

    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=clock.now)

    __table_args__ = (
        Index("idx_vm_real_lower", "real_value_lower"),
        Index("idx_vm_table_col", "table_name", "column_name"),
        Index(
            "idx_vm_unique",
            "table_name",
            "column_name",
            "real_value_lower",
            unique=True,
        ),
    )

    def __repr__(self):
        truncated = self.real_value[:3] + "…" if self.real_value else ""
        return (
            f"<ValueMapping({self.table_name}.{self.column_name}: "
            f"'{truncated}' [{self.value_type}])>"
        )

    def to_dict(self):
        """Serialize WITHOUT real_value — confidential data must never leak to API."""
        return {
            "id": self.id,
            "table_name": self.table_name,
            "column_name": self.column_name,
            "value_type": self.value_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
