"""Modèle ``ConceptGlossary`` — glossaire global concept NL → (table, col).

Alimenté par ``AgentKnowledge.learn_from_conversation_feedback`` quand
l'utilisateur valide un run pipeline avec ✅. Persiste la résolution Phase 2.5
data-driven (concept_resolution[c].best) du run validé pour qu'Iris s'appuie
dessus sur des queries futures qui mentionnent les mêmes concepts.

Doctrine (cf. CLAUDE.md « Vision » + section « Gladys workflow 8-phases ») :
    8. Feedback ✅ → enrichit la doc partagée Iris (alimentation RAG).

Mono-déploiement : un seul périmètre par instance Komptia, pas de
colonne discriminante d'isolation (pas de ``tenant_id`` / scope multi-clients).

Plusieurs entrées par concept admises : un même terme NL (« exemple »)
peut légitimement résoudre vers (Table1, colA) dans un contexte et
(Table2, colB) dans un autre. La désambiguïsation aval pondère par
``usage_count`` et ``confidence``. L'unicité est sur le **triplet**
(concept, table_name, column_name) pour upsert idempotent.

Hors scope (cf. clarif David 2026-05-21) :
- Q/A user spécifique (ex : variante de mesure, périmètre) — user-specific,
  ne va pas dans la doc partagée. Reste dans ``app.services.ai.user_qa_session``
  per-run.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import BaseModel


class ConceptGlossary(BaseModel):
    """Glossaire global concept NL → (table, colonne) validé par feedback ✅."""

    __tablename__ = "concept_glossary"

    # Concept NL (ex: « facturation totale », « dossier »). Stocké en
    # ``lower()`` côté caller pour matching insensible à la casse cohérent
    # avec le pattern training_store (déduplication par contenu normalisé).
    concept: Mapped[str] = mapped_column(String(200), nullable=False, index=True)

    # Résolution Phase 2.5 (best candidate du run validé)
    table_name: Mapped[str] = mapped_column(String(128), nullable=False)
    column_name: Mapped[str] = mapped_column(String(128), nullable=False)

    # Métadonnées sémantiques (extraites du concept_resolution Phase 2.5)
    # ``value_type`` ∈ {"text", "number", "date", "code", "datetime", ...}
    value_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Si le concept est calculé par formule (cf. extracted.derivables Phase 1.1)
    # plutôt que mappé à une colonne unique, on stocke quand même la colonne
    # « primaire » du calcul pour traçabilité, avec ce flag.
    is_derived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Score [0,1] — typiquement 1.0 sur ✅ direct, ratio_gap depuis Phase 2.5
    # sinon. Source d'information pour le ranking aval.
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)

    # Origine : "feedback_validate" (✅ user direct), "feedback_adjust"
    # (🔄 user), "manual" (admin), etc. Aligné avec ``TrainingData.source``.
    source: Mapped[str] = mapped_column(String(50), default="feedback_validate", nullable=False)

    # Compteur d'usage : incrémenté à chaque ✅ ré-validant le même triplet
    # (concept, table_name, column_name). Permet au scoring aval de
    # privilégier les mappings éprouvés sur ceux validés une seule fois.
    usage_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Audit : qui a déclenché l'écriture (user dont la ✅ a alimenté le
    # glossaire). FK nullable pour tolérer les imports manuels admin.
    created_by: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    __table_args__ = (
        # Lookup secondaire (analyse : « quels concepts pointent vers X.Y ? »)
        Index("ix_concept_glossary_table_col", "table_name", "column_name"),
        # Triplet unique pour upsert idempotent côté caller.
        # NOTE: SQLite traite NULL comme distinct → si ``column_name`` était
        # nullable, deux NULL pour le même (concept, table) seraient permis.
        # Ici les 3 colonnes sont NOT NULL donc l'unicité est stricte.
        Index(
            "ux_concept_glossary_mapping",
            "concept",
            "table_name",
            "column_name",
            unique=True,
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<ConceptGlossary(id={self.id}, concept={self.concept!r}, "
            f"map={self.table_name}.{self.column_name}, "
            f"usage_count={self.usage_count})>"
        )
