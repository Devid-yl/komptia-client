"""
Modèle Execution pour Komptia.

Historique des exécutions d'automatisations.
"""

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import String, Text, DateTime, ForeignKey, Float, JSON
from sqlalchemy.orm import relationship, Mapped, mapped_column
from app.core import clock
from app.core.database import Base
from app.models.base import ensure_utc

if TYPE_CHECKING:
    from app.models.automation import Automation  # noqa: F401
    from app.models.step_execution import StepExecution  # noqa: F401


class Execution(Base):
    """
    Exécution d'une automatisation : historique et résultats.

    Une execution est créée à chaque fois qu'une automation est lancée.
    Elle stocke le statut, la durée, le résultat et les erreurs éventuelles.
    """

    __tablename__ = "F_EXECUTION"

    # Identification
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    automation_id: Mapped[int] = mapped_column(
        ForeignKey("F_AUTOMATION.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="ID de l'automatisation exécutée",
    )

    # État
    # 'waiting' : etape email_wait_response en attente d'une reponse externe.
    # Lifecycle : pending → running → (waiting → running)* → success|failed|cancelled
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        insert_default="pending",
        index=True,
        comment="Statut: 'pending', 'running', 'waiting', 'success', 'failed', 'partial', 'cancelled'",
    )

    # Timing
    started_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        index=True,
        comment="Date/heure de début d'exécution",
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True, comment="Date/heure de fin d'exécution"
    )
    duration_seconds: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True, comment="Durée totale en secondes (finished_at - started_at)"
    )

    # Résultat
    result_rows: Mapped[Optional[int]] = mapped_column(
        nullable=True, comment="Nombre de lignes retournées par la requête"
    )
    output_file_path: Mapped[Optional[str]] = mapped_column(
        String(500), nullable=True, comment="Chemin du fichier de sortie généré (CSV, Excel, PDF)"
    )

    # Erreur
    error_message: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="Message d'erreur si status='failed'"
    )
    error_traceback: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="Stack trace complète en cas d'erreur"
    )

    # Phase 2 DAG : trace du declencheur (cf. design §1.7)
    trigger_source: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="manual",
        server_default="manual",
        index=True,
        comment="Source du declenchement: scheduled / webhook / manual / replay",
    )
    triggered_by_user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User qui a declenche (manual ou replay uniquement, NULL pour scheduled/webhook)",
    )
    trigger_payload: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Payload JSON du trigger (webhook body, scheduled cron, etc.)",
    )

    # Checkpoint pour reprise après un step `email_wait_response`.
    # Format : {"step_outputs": {step_id: workbook_dict_or_null, ...},
    #           "step_output_files": {step_id: file_path, ...},
    #           "executed_step_ids": [int, ...]}
    # Posé au moment où le DAG hit un step waiting. Au resume, on
    # rehydrate context.step_outputs depuis ce checkpoint et on relance
    # le DAG à partir du step waiting (sans re-exec les steps deja faits).
    # NULL tant qu'aucun wait n'a eu lieu pour cette execution.
    wait_checkpoint: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Snapshot des step_outputs au moment d'un wait (pour resume)",
    )

    # Relations
    automation: Mapped["Automation"] = relationship("Automation", back_populates="executions")
    step_executions: Mapped[List["StepExecution"]] = relationship(
        "StepExecution",
        back_populates="execution",
        cascade="all, delete-orphan",
        order_by="StepExecution.step_order",
    )

    def __init__(self, **kwargs):
        if "status" not in kwargs:
            kwargs["status"] = "pending"
        super().__init__(**kwargs)

    def __repr__(self):
        return (
            f"<Execution(id={self.id}, automation_id={self.automation_id}, status='{self.status}')>"
        )

    def to_dict(self):
        """Convertit en dictionnaire pour JSON API.

        N'accède PAS aux relations (automation) pour éviter MissingGreenlet.
        N'expose PAS le chemin absolu du fichier (sécurité).
        """
        return {
            "id": self.id,
            "automation_id": self.automation_id,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "result_rows": self.result_rows,
            "has_output_file": bool(self.output_file_path),
            "error_message": self.error_message,
            # Phase 2 DAG : trace du declencheur
            "trigger_source": self.trigger_source,
            "triggered_by_user_id": self.triggered_by_user_id,
        }

    def mark_running(self):
        """Marque l'exécution comme en cours."""
        self.status = "running"
        self.started_at = clock.now()

    def mark_success(self, result_rows=None, output_file_path=None):
        """Marque l'exécution comme réussie."""
        self.status = "success"
        self.finished_at = clock.now()
        self.duration_seconds = (self.finished_at - ensure_utc(self.started_at)).total_seconds()
        self.result_rows = result_rows
        self.output_file_path = output_file_path

    def mark_failed(self, error_message, error_traceback=None):
        """Marque l'exécution comme échouée."""
        self.status = "failed"
        self.finished_at = clock.now()
        self.duration_seconds = (self.finished_at - ensure_utc(self.started_at)).total_seconds()
        self.error_message = error_message
        self.error_traceback = error_traceback

    def mark_partial(self, error_message, result_rows=None, output_file_path=None):
        """Marque l'exécution comme partielle : certains steps ont réussi, d'autres
        ont échoué (cas `fail_policy=continue` typiquement, ou un sink fail
        alors qu'un autre sink succeed dans un fan-out). L'utilisateur doit
        être prévenu — c'est un demi-succès, pas un succès silencieux.

        L'``error_message`` agrégé liste les step_names qui ont fail (cf.
        executor `_aggregate_step_errors`). ``result_rows`` et
        ``output_file_path`` reflètent la partie qui A réussi.
        """
        self.status = "partial"
        self.finished_at = clock.now()
        self.duration_seconds = (self.finished_at - ensure_utc(self.started_at)).total_seconds()
        self.result_rows = result_rows
        self.output_file_path = output_file_path
        self.error_message = error_message

    def mark_cancelled(self, error_message: Optional[str] = None):
        """Marque l'exécution comme annulée.

        ``error_message`` optionnel : utilise pour cas « annulation par
        nouvelle exec » (cancel-on-next-run) où on veut garder une trace
        textuelle pour l'UI/audit. Aucun effet si None.
        """
        self.status = "cancelled"
        self.finished_at = clock.now()
        self.duration_seconds = (self.finished_at - ensure_utc(self.started_at)).total_seconds()
        if error_message is not None:
            self.error_message = error_message

    def mark_waiting(self):
        """Marque l'exécution comme en attente d'une reponse externe.

        Le finished_at n'est PAS pose : l'execution n'est pas terminee,
        elle est suspendue. duration_seconds reste None tant qu'on n'a
        pas atteint un statut terminal (success/failed/cancelled apres
        resume ou expiration).
        """
        self.status = "waiting"

    @property
    def is_running(self):
        """Vérifie si l'exécution est en cours (incluant waiting)."""
        return self.status in self.active_statuses()

    @classmethod
    def terminal_statuses(cls) -> tuple[str, ...]:
        """Statuts terminaux (SSoT — réutilisé par ``is_finished`` et le
        backstop boot ``loader._TERMINAL_EXECUTION_STATUSES``). Si un statut
        terminal est ajouté (ex: ``expired``), c'est ICI qu'on le déclare —
        plus de liste dupliquée qui divergerait silencieusement."""
        return ("success", "failed", "cancelled", "partial")

    @classmethod
    def active_statuses(cls) -> tuple[str, ...]:
        """Statuts non-terminaux (en file / en cours / en attente) — SSoT
        réutilisé par ``is_running``. Symétrique de ``terminal_statuses``.

        ⚠️ NE PAS confondre avec les listes ``["pending", "running"]`` du
        réconciliateur d'orphelins (scheduler) et du panneau « en cours » :
        celles-ci excluent VOLONTAIREMENT ``waiting`` (une exécution suspendue
        sur une réponse externe ne doit ni être réconciliée-failed, ni comptée
        comme « active » dans la barre de progression). C'est un concept
        distinct — ne pas les remplacer par ``active_statuses()``."""
        return ("pending", "running", "waiting")

    @classmethod
    def all_statuses(cls) -> tuple[str, ...]:
        """Ensemble exhaustif des statuts valides (terminaux + actifs) — SSoT
        pour valider un filtre statut côté handler (un statut inconnu produirait
        ``WHERE status='xxx'`` → 0 ligne silencieuse = faux vide trompeur)."""
        return cls.terminal_statuses() + cls.active_statuses()

    @property
    def is_finished(self):
        """Vérifie si l'exécution est terminée."""
        return self.status in self.terminal_statuses()

    @property
    def is_waiting(self):
        """Vrai si l'execution est suspendue en attente d'une reponse."""
        return self.status == "waiting"

    @property
    def is_successful(self):
        """Vérifie si l'exécution a réussi."""
        return self.status == "success"
