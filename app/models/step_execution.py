"""
Modele StepExecution pour Komptia.

Historique d'execution par etape dans un workflow multi-etapes.
Chaque Execution (workflow) produit 0..N StepExecution, un par etape executee.
Permet le suivi step-by-step: timing, nombre de lignes, warnings, erreurs.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Optional, List

from sqlalchemy import String, Text, DateTime, Float, ForeignKey, JSON
from sqlalchemy.orm import relationship, Mapped, mapped_column

from app.core import clock
from app.core.database import Base

if TYPE_CHECKING:
    from app.models.execution import Execution  # noqa: F401


class StepExecution(Base):
    """
    Resultat d'execution d'une etape individuelle dans un workflow.

    Cree par l'executor pour chaque etape executee (extract, transform,
    validate, report, email). Permet de voir le detail step-by-step
    dans l'historique d'execution.
    """

    __tablename__ = "F_STEP_EXECUTION"

    # Identification
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    execution_id: Mapped[int] = mapped_column(
        ForeignKey("F_EXECUTION.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="ID de l'execution parente",
    )
    step_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("F_AUTOMATION_STEP.id", ondelete="SET NULL"),
        nullable=True,
        comment="ID de l'etape (NULL si etape geree par executor sans step en BDD)",
    )

    # Identification de l'etape
    step_order: Mapped[int] = mapped_column(
        nullable=False,
        default=0,
        comment="Ordre d'execution (1-based)",
    )
    step_name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        default="",
        comment="Nom de l'etape",
    )
    step_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="",
        comment="Type d'etape (extract_sql, filter_rows, etc.)",
    )

    # Retry tracking
    attempt_number: Mapped[int] = mapped_column(
        nullable=False,
        default=1,
        server_default="1",
        comment="Numero de tentative (1 = premier essai, 2+ = retry)",
    )

    # Resultat
    # 'waiting' : step `email_wait_response` en attente de reponse externe.
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        insert_default="pending",
        comment="Statut: pending, running, waiting, success, failed, skipped, retried",
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Debut d'execution de l'etape",
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Fin d'execution de l'etape",
    )
    duration_ms: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Duree en millisecondes",
    )

    # Donnees
    rows_in: Mapped[Optional[int]] = mapped_column(
        nullable=True,
        default=0,
        comment="Nombre de lignes en entree",
    )
    rows_out: Mapped[Optional[int]] = mapped_column(
        nullable=True,
        default=0,
        comment="Nombre de lignes en sortie",
    )
    warnings: Mapped[Optional[List]] = mapped_column(
        JSON,
        nullable=True,
        default=list,
        comment="Liste des avertissements generes par l'etape",
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Message d'erreur si status=failed",
    )
    # P5.5 (audit 2026-05-26) — Classe d'exception qui a fait planter le step
    # (ex: ``DataAccessDeniedError``, ``QueryError``, ``SageConnectionError``).
    # Utilisé par ``executor.execute_automation::_has_failed`` (ligne ~422)
    # pour détecter spécifiquement ``DataAccessDeniedError`` et déclencher
    # l'auto-pause RLS (Phase 2.5.6 #77). Sans ce field, le check
    # ``getattr(s, "error_class", None)`` retournait TOUJOURS None après
    # reload BDD → auto-pause jamais déclenchée (bug latent DAG ET legacy).
    error_class: Mapped[Optional[str]] = mapped_column(
        String(80),
        nullable=True,
        comment="Classe d'exception (type(exc).__name__) si status=failed",
    )

    # --- Observabilite Phase 2 DAG (§2.6) ---
    trace_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True,
        index=True,
        comment="UUID de correlation du run (propage a chaque step du meme run)",
    )
    step_input: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Snapshot des inputs recus par ce step (tronque si > seuil)",
    )
    step_output: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Snapshot des outputs produits par ce step (tronque si > seuil)",
    )
    config_snapshot: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Config effective apres resolution des {{variables}}",
    )
    sql_executed: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="SQL effectif envoye a Sage (nodes extract_sql uniquement)",
    )
    spill_parquet_path: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Chemin du fichier parquet si step_output > seuil (spill disque)",
    )
    llm_tokens_in: Mapped[Optional[int]] = mapped_column(
        nullable=True,
        comment="Tokens d'entree consommes par le LLM (nodes format)",
    )
    llm_tokens_out: Mapped[Optional[int]] = mapped_column(
        nullable=True,
        comment="Tokens de sortie generes par le LLM",
    )
    llm_cost_eur: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Cout LLM estime en euros (pricing provider-specifique)",
    )

    # Relations
    execution: Mapped["Execution"] = relationship("Execution", back_populates="step_executions")

    def __repr__(self):
        return (
            f"<StepExecution(id={self.id}, execution_id={self.execution_id}, "
            f"step={self.step_name}, status='{self.status}')>"
        )

    def to_dict(self, *, include_sensitive: bool = False):
        """Convertit en dictionnaire pour JSON API.

        Args:
            include_sensitive: Si True, inclut les champs sensibles
                (SQL effectif, snapshots input/output, config resolue).
                Ces champs peuvent contenir des donnees client (emails,
                noms, valeurs metier).

                **Politique d'autorisation (Phase 3c)** : ces champs sont
                exposables a l'UTILISATEUR PROPRIETAIRE de l'execution
                (verifie via ownership 404 anti-oracle dans le handler).
                Le partage cross-user reste interdit ; un admin externe
                voulant inspecter une execution d'un autre utilisateur
                doit passer par un endpoint admin dedie (non encore
                implemente). Le caller doit donc imposer SOIT ownership
                strict, SOIT `require_role("admin")` selon le contexte.

                Les blobs ``step_output`` sont deja tronques en BDD a
                ~100 lignes/onglet par ``workbook_snapshot_for_db`` —
                pas de risque de fuite de donnees au-dela de cet
                echantillon.

                Les ``error_message`` peuvent contenir des stack traces
                ou credentials (CWE-209) — le caller DOIT les passer par
                ``_sanitize_error_message`` avant exposition.
        """
        base = {
            "id": self.id,
            "execution_id": self.execution_id,
            "step_id": self.step_id,
            "step_order": self.step_order,
            "step_name": self.step_name,
            "step_type": self.step_type,
            "attempt_number": self.attempt_number,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_ms": self.duration_ms,
            "rows_in": self.rows_in,
            "rows_out": self.rows_out,
            "warnings": self.warnings or [],
            "error_message": self.error_message,
            # Observabilite "light" (non sensible)
            "trace_id": self.trace_id,
            "spill_parquet_path": self.spill_parquet_path,
            "llm_tokens_in": self.llm_tokens_in,
            "llm_tokens_out": self.llm_tokens_out,
            "llm_cost_eur": self.llm_cost_eur,
        }
        if include_sensitive:
            base.update(
                {
                    "step_input": self.step_input,
                    "step_output": self.step_output,
                    "config_snapshot": self.config_snapshot,
                    "sql_executed": self.sql_executed,
                }
            )
        return base

    def mark_running(self):
        """Marque l'etape comme en cours."""
        self.status = "running"
        self.started_at = clock.now()

    def mark_success(self, rows_in=0, rows_out=0, duration_ms=0.0, warnings=None):
        """Marque l'etape comme reussie."""
        self.status = "success"
        self.finished_at = clock.now()
        self.rows_in = rows_in
        self.rows_out = rows_out
        self.duration_ms = duration_ms
        self.warnings = warnings or []

    def mark_failed(self, error_message, rows_in=0, duration_ms=0.0):
        """Marque l'etape comme echouee."""
        self.status = "failed"
        self.finished_at = clock.now()
        self.rows_in = rows_in
        self.duration_ms = duration_ms
        self.error_message = error_message

    def mark_skipped(self):
        """Marque l'etape comme sautee (condition non remplie)."""
        self.status = "skipped"
        self.finished_at = clock.now()
        self.duration_ms = 0.0

    def mark_waiting(self):
        """Marque l'etape comme en attente d'une reponse externe.

        Pose started_at si manquant, NE pose PAS finished_at (la step
        n'est pas terminee, elle est suspendue). duration_ms reste None
        jusqu'au resume (success) ou au timeout (failed/cancelled).
        """
        self.status = "waiting"
        if self.started_at is None:
            self.started_at = clock.now()
