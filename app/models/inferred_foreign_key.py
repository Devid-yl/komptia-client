"""Modèle InferredForeignKey — Foreign keys empiriques (BDD source sans FK déclarées).

Beaucoup de BDD legacy n'exposent pas leurs FK via INFORMATION_SCHEMA. Sans
relations, la Phase 1.5 BFS du pipeline NL→SQL perd la capacité de proposer
des chemins de JOIN entre tables. Ce modèle persiste les FK *inférées* par
deux signaux orthogonaux :

* **value_overlap** — colonne A.x contient à ≥ X % les valeurs de la PK B.y.
  Mesure empirique, fiable même sans convention de nommage.
* **naming_pattern** — colonne A.x a un nom qui dérive du nom de la table B
  (token de B + suffixe ``ref|id|key|fk|num|code|no`` ou préfixe symétrique).
  Mesure structurelle, fiable même quand la table est vide.

Quand les deux signaux concordent (``kind='naming_and_value'``) la
confiance est haute. Pas de hardcode d'une convention BDD source : la
détection s'applique à toute BDD SQL connectée à Komptia.

Stockage SQLCipher (chiffré). Tronquée + reconstruite à chaque sync —
l'auteur de la sync garantit que les UPDATE/INSERT/DELETE concomitants
sur la BDD source sont propagés au prochain sync, pas en temps réel.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core import clock
from app.models.base import Base

# Valeurs autorisées pour ``kind`` — gardées comme constantes module-level
# pour rester DRY entre le code applicatif, les tests et la documentation.
# Pas un Enum SQLAlchemy : on veut pouvoir ajouter une 4ᵉ catégorie sans
# migration de type (SQLite stocke un VARCHAR). La validation est faite
# par les helpers ``app/services/ai/fk_inference.py`` qui produisent les
# rows — la BDD reste tolérante côté schéma.
KIND_VALUE_OVERLAP = "value_overlap"
KIND_NAMING_PATTERN = "naming_pattern"
KIND_NAMING_AND_VALUE = "naming_and_value"
INFERRED_FK_KINDS = (
    KIND_VALUE_OVERLAP,
    KIND_NAMING_PATTERN,
    KIND_NAMING_AND_VALUE,
)


class InferredForeignKey(Base):
    """Foreign key découverte empiriquement sur la BDD source.

    Persistée dans ``komptia.db`` (BDD locale chiffrée). Aucune écriture
    sur la BDD source — celle-ci reste read-only par contrat Komptia.
    """

    __tablename__ = "inferred_foreign_keys"

    id: Mapped[int] = mapped_column(primary_key=True)

    # Identifiants table/colonne tels que présents dans la BDD source.
    # Stockés tels-quels (casse préservée) ; la dédup case-insensitive est
    # assurée par les helpers qui produisent les rows + l'index unique
    # ci-dessous (sur LOWER(...) pour ne pas se laisser piéger par la
    # casse de la BDD source — SQL Server n'est pas sensible à la casse
    # par défaut, mais le ramassis multi-BDD doit l'être pour la dédup).
    source_table: Mapped[str] = mapped_column(String(128), nullable=False)
    source_column: Mapped[str] = mapped_column(String(128), nullable=False)
    target_table: Mapped[str] = mapped_column(String(128), nullable=False)
    target_column: Mapped[str] = mapped_column(String(128), nullable=False)

    # 'value_overlap' | 'naming_pattern' | 'naming_and_value'. Cf. constantes
    # ci-dessus pour l'enum côté code applicatif (pas côté schéma).
    kind: Mapped[str] = mapped_column(String(32), nullable=False)

    # [0.0, 1.0] — produit par ``combine_signals`` dans ``fk_inference.py``.
    # 0.99+ = quasi-certitude (value_overlap haut + naming match), 0.5 =
    # signal faible isolé. La Phase 1.5 BFS peut filtrer à confidence ≥ X.
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    # JSON sérialisé en TEXT (compact, lisible debug). Contient typiquement :
    # {"overlap": 42, "containment": 0.99, "src_distinct": 50,
    #  "tgt_distinct": 50, "pattern_matched": "ClientId→Client.Id"}
    # Pas de schéma strict — l'auteur de la sync peut enrichir librement.
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=clock.now)

    __table_args__ = (
        # Dédup au niveau (source_table, source_column, target_table,
        # target_column) — un même couple ne doit pas produire 2 rows à
        # travers les syncs successifs. La table + ses indexes sont créés
        # au boot par ``Base.metadata.create_all`` (cf.
        # ``app/core/database.py:init_database`` ~ligne 1377) — aucune
        # migration ``_Migration`` séparée n'est nécessaire pour une table
        # *nouvelle*. La normalisation de casse des identifiants côté BDD
        # source (SQL Server peut écrire ``ClientId`` ou ``CLIENTID`` selon
        # collation) est assurée par les helpers ``fk_inference.py`` qui
        # produisent les rows avec une casse canonique stable.
        Index(
            "idx_ifk_unique",
            "source_table",
            "source_column",
            "target_table",
            "target_column",
            unique=True,
        ),
        # Index pour BFS Phase 1.5 : lookup par source ou target.
        Index("idx_ifk_source", "source_table"),
        Index("idx_ifk_target", "target_table"),
    )

    def __repr__(self) -> str:
        return (
            f"<InferredForeignKey({self.source_table}.{self.source_column} "
            f"→ {self.target_table}.{self.target_column}, "
            f"kind={self.kind}, conf={self.confidence:.2f})>"
        )

    def to_dict(self) -> dict:
        """Sérialisation pour les API debug/admin (jamais exposée user public)."""
        return {
            "id": self.id,
            "source_table": self.source_table,
            "source_column": self.source_column,
            "target_table": self.target_table,
            "target_column": self.target_column,
            "kind": self.kind,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
