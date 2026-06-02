"""
Modele AutomationEdge pour Komptia.

Represente une arete du graphe DAG d'une automatisation : relie deux steps
(source -> cible) et porte un type de donnee (`workbook`, `report_file`,
`trigger`). L'executor parcourt le graphe topologiquement a l'execution.

Historique :
- Avant : workflows lineaires, etapes ordonnees par `step_order` (entier).
- Phase 1 DAG : introduction de cette table ; `step_order` conserve comme
  hint d'affichage mais n'est plus la source de verite d'execution.

Design :
- FK directe vers F_AUTOMATION : permet de detecter rapidement les edges
  orphelins si une automation est supprimee (ondelete=CASCADE) et de valider
  qu'un edge ne traverse pas deux automations (check applicatif).
- FK vers F_AUTOMATION_STEP : cascade egalement. Si un step est supprime,
  toutes ses aretes disparaissent automatiquement.
- `UNIQUE(from_step_id, to_step_id)` : pas de duplication d'arete.
- `metadata_json` : reserve pour extensions futures (merge_strategy sur
  fan-in si jamais besoin, tags, annotations UI). Nullable, pas d'usage en
  Phase 1.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import String, DateTime, ForeignKey, JSON, UniqueConstraint, CheckConstraint
from sqlalchemy.orm import relationship, Mapped, mapped_column

from app.core import clock
from app.core.database import Base

if TYPE_CHECKING:
    from app.models.automation import Automation  # noqa: F401
    from app.models.automation_step import AutomationStep  # noqa: F401


# Types de donnees portees par une arete (cf. design_automations_dag.md §1.1)
EDGE_DATA_TYPES = ("workbook", "report_file", "trigger")


class AutomationEdge(Base):
    """
    Arete du graphe DAG d'une automatisation.

    Relie `from_step_id` (sortie) a `to_step_id` (entree). Le `data_type`
    doit etre coherent avec la sortie du step source et l'entree acceptee
    par le step cible (validation au save, cf. `dag_validator.py`).
    """

    __tablename__ = "F_AUTOMATION_EDGE"

    # Identification
    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    automation_id: Mapped[int] = mapped_column(
        ForeignKey("F_AUTOMATION.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Automatisation a laquelle appartient cette arete",
    )

    from_step_id: Mapped[int] = mapped_column(
        ForeignKey("F_AUTOMATION_STEP.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Step source (sortie) de l'arete",
    )

    to_step_id: Mapped[int] = mapped_column(
        ForeignKey("F_AUTOMATION_STEP.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Step cible (entree) de l'arete",
    )

    # Type de donnee
    data_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Type de donnee transportee (workbook, report_file, trigger)",
    )

    # Metadata (reserve extensions futures)
    metadata_json: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Metadata JSON reservee aux extensions futures (fan-in merge, tags, etc.)",
    )

    # Timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        comment="Date de creation de l'arete",
    )

    # Contraintes table :
    # - Pas de duplication d'arete entre deux memes steps.
    # - Pas de self-loop (CHECK SQL applicatif, defense-in-depth en plus de
    #   la verif au dag_validator).
    __table_args__ = (
        UniqueConstraint("from_step_id", "to_step_id", name="uq_automation_edge_from_to"),
        CheckConstraint("from_step_id != to_step_id", name="ck_automation_edge_no_self_loop"),
    )

    # Relations
    automation: Mapped["Automation"] = relationship("Automation", back_populates="edges")
    from_step: Mapped["AutomationStep"] = relationship(
        "AutomationStep",
        foreign_keys=[from_step_id],
        back_populates="outgoing_edges",
    )
    to_step: Mapped["AutomationStep"] = relationship(
        "AutomationStep",
        foreign_keys=[to_step_id],
        back_populates="incoming_edges",
    )

    def __repr__(self) -> str:
        return (
            f"<AutomationEdge(id={self.id}, "
            f"from={self.from_step_id}, to={self.to_step_id}, "
            f"type='{self.data_type}')>"
        )

    def to_dict(self) -> dict:
        """Convertit en dictionnaire pour JSON API."""
        return {
            "id": self.id,
            "automation_id": self.automation_id,
            "from_step_id": self.from_step_id,
            "to_step_id": self.to_step_id,
            "data_type": self.data_type,
            "metadata": self.metadata_json or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
