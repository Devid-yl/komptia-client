"""Modèles ``PipelineRun`` et ``PipelinePhaseExecution``.

Persiste l'état d'une exécution de la pipeline NL→SQL (``scripts/pipeline.py``)
lancée depuis l'agent SQL d'Iris. Permet la supervision phase-par-phase, la
reprise (``--resume`` / ``goto_phase``), et l'historique côté utilisateur.

Doctrine :

- ``PipelineRun`` est une **enveloppe** : ce qui doit survivre aux redémarrages
  serveur (status, query_nl, output_dir, schema snapshot, coût final).
- ``PipelinePhaseExecution`` est le **journal** des phases : 1 ligne par
  ``(run_id, phase_id, attempt_number)``. ``goto_phase`` n'efface pas les
  attempts — il ajoute un nouvel attempt et marque les précédents
  ``is_superseded=True`` pour traçabilité.
- Les artefacts JSON volumineux (``run.json`` snapshot, prompts, raw responses)
  vivent dans ``output_dir`` sur le filesystem, pas en BDD. Le champ
  ``artifact_path`` pointe vers le fichier sérialisé. ``metadata_summary``
  reste lisible directement (counts, top items — JSON court).
- Isolation user : lecture/écriture passent par ``user_id`` côté handler.
  Les modèles ne portent pas la logique d'autorisation (séparation des
  responsabilités). FK ``conversation_id`` en ``ON DELETE SET NULL`` car un
  run peut survivre à la suppression de sa conversation parente.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SQLEnum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core import clock
from app.models.base import BaseModel, ensure_utc

if TYPE_CHECKING:
    pass


class PipelineRunStatus(str, enum.Enum):
    """Cycle de vie d'un run pipeline.

    Transitions valides :
        pending → running → (paused → running)* → success|failed|cancelled
    """

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"
    # Arrêt volontaire à une phase intermédiaire (feature « preview » Iris —
    # docs/design/iris_stop_at_phase.md). TERMINAL (run terminé sur le scope
    # demandé, sans SQL final) mais resumable via pipeline_resume. Distinct de
    # SUCCESS (pas de final_sql) et de PAUSED (suspension mid-run).
    STOPPED_EARLY = "stopped_early"

    @classmethod
    def terminal(cls) -> "frozenset[PipelineRunStatus]":
        """Statuts FINAUX immuables (SSoT — adversarial A6 #9).

        Source unique réutilisée par ``PipelineRun.is_terminal()``, le cleanup
        TTL (``cleanup_pipeline_runs_job``) et la réconciliation boot. Si un
        statut est ajouté à l'enum, c'est ICI qu'on décide s'il est terminal —
        plus de liste ``(success, failed, cancelled)`` dupliquée qui divergerait
        silencieusement.
        """
        return frozenset({cls.SUCCESS, cls.FAILED, cls.CANCELLED, cls.STOPPED_EARLY})

    @classmethod
    def active_volatile(cls) -> "frozenset[PipelineRunStatus]":
        """Statuts actifs qui EXIGENT un runner en mémoire (volatil).

        Complément ciblé par ``reconcile_orphan_runs`` au boot : après un
        redémarrage, le registre des runners est vide → tout run dans un de
        ces statuts est un fantôme. ``PAUSED`` n'en fait PAS partie : c'est un
        checkpoint durable resumable depuis le snapshot disque (sans runner).
        """
        return frozenset({cls.PENDING, cls.RUNNING})


class PipelineMode(str, enum.Enum):
    """Mode Phase 4 du composer SQL.

    - ``LEGACY`` : LLM produit du SQL libre (Phase 4a).
    - ``IR`` : LLM produit un Intermediate Representation via tool_use, le
      système traduit en SQL (Phase 4b — composer IR Z.1-Z.8 + W.1-W.4).
      Plus mature pour les cas analytiques complexes (rentabilité). Défaut.
    """

    LEGACY = "legacy"
    IR = "ir"


class TriggeredVia(str, enum.Enum):
    """Origine du run.

    Sert à distinguer les runs lancés par Iris en chat vs panneau dédié vs
    appel API direct. Utilisé pour les stats admin et le breakdown par
    surface UX.
    """

    IRIS_CHAT = "iris_chat"  # Tool ``run_pipeline`` invoqué par l'agent
    IRIS_PANEL = "iris_panel"  # Click utilisateur sur le panneau pipeline
    API = "api"  # POST /api/iris/pipeline-run direct


class PipelinePhaseStatus(str, enum.Enum):
    """Statut d'une phase individuelle."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PipelineRun(BaseModel):
    """Run de la pipeline NL→SQL.

    Une instance représente UNE invocation utilisateur : depuis la requête
    naturelle jusqu'au SQL final (ou échec). Persistée en BDD pour
    rehydration au reload, historique par user, et cleanup TTL.
    """

    __tablename__ = "pipeline_runs"

    # Propriétaire (isolation cross-user)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Conversation associée. Nullable : un run survit à la suppression de
    # sa conversation parente (ON DELETE SET NULL côté FK pour cohérence).
    conversation_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("conversations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Entrée utilisateur
    query_nl: Mapped[str] = mapped_column(Text, nullable=False)

    # Configuration du run
    mode: Mapped[PipelineMode] = mapped_column(
        SQLEnum(PipelineMode), nullable=False, default=PipelineMode.IR
    )
    # task #82 (2026-05-21) : default inversé `True → False`. Les vues métier
    # (viewMissions03, viewGroupes01, etc.) sont maintenant INCLUSES par défaut
    # dans le shortlist Phase 1.5 → le LLM peut les utiliser pour générer du
    # SQL correct (rapport YoY). La protection anti-hallucination reste assurée
    # par ``phase_1_5_scoring_fk(block_view_mined_fk=True)`` qui bloque les FK
    # INFÉRÉES des vues (pas les vues elles-mêmes). Pour forcer le mode test
    # « tables uniquement », passer explicitement ``block_all_views=True`` à
    # l'appel CLI ou via le tool ``run_pipeline``.
    block_all_views: Mapped[bool] = mapped_column(
        Boolean, default=False, insert_default=False, nullable=False
    )
    use_sage: Mapped[bool] = mapped_column(
        Boolean, default=True, insert_default=True, nullable=False
    )

    # Arrêt volontaire à une phase intermédiaire (feature « preview » Iris —
    # docs/design/iris_stop_at_phase.md). NULL = run complet jusqu'au SQL.
    # Quand non-NULL, le run se termine en statut STOPPED_EARLY après cette
    # phase (sans final_sql). Le « pourquoi terminal » reste porté par
    # ``status`` (SSoT PipelineRunStatus) — PAS de colonne ``terminal_reason``
    # dupliquée ; le ``terminal_reason`` niveau script (run.json) est traduit
    # en statut par le runner.
    stop_after_phase: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # B6 — lien run preview → run de continuation. Posé par ``resume_pipeline_run``
    # sur le NOUVEAU run créé. Permet de refuser un 2e resume depuis la même
    # source tant qu'un enfant NON-terminal existe (idempotence déterministe
    # anti double-resume — backstop backend de la mitigation frontend B4). Plain
    # Integer indexé (pas de FK : on requête seulement par valeur, pas de cascade).
    resumed_from_run_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)

    # Cycle de vie
    status: Mapped[PipelineRunStatus] = mapped_column(
        SQLEnum(PipelineRunStatus), nullable=False, default=PipelineRunStatus.PENDING
    )
    current_phase: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    last_completed_phase: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # Timing — distinct de created_at (queue vs effective start)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Résultats
    final_sql: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_traceback: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    row_count_warning: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    # Filesystem (un dossier par run pour isolation)
    output_dir: Mapped[str] = mapped_column(String(500), nullable=False)

    # Traçabilité LLM (corrélation avec AIPerformanceLog)
    request_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    triggered_via: Mapped[TriggeredVia] = mapped_column(
        SQLEnum(TriggeredVia), nullable=False, default=TriggeredVia.IRIS_CHAT
    )
    cancelled_by_user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Snapshot du schéma au démarrage du run.
    # Format : timestamp ISO du dernier ``SchemaSync.created_at`` réussi
    # (ou ``"unknown"``). Sert à détecter divergence si le schéma bouge
    # PENDANT le run (admin trigger un sync entre temps). Lecture seule
    # au runtime — purement informatif côté UI.
    schema_version_at_start: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Coût total agrégé (somme des phases)
    total_tokens_input: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_tokens_output: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_cost_usd: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Soft-delete
    is_archived: Mapped[bool] = mapped_column(
        Boolean, default=False, insert_default=False, nullable=False
    )

    # Relations
    phase_executions: Mapped[List["PipelinePhaseExecution"]] = relationship(
        "PipelinePhaseExecution",
        back_populates="pipeline_run",
        cascade="all, delete-orphan",
        order_by=("PipelinePhaseExecution.phase_id, PipelinePhaseExecution.attempt_number"),
    )

    __table_args__ = (
        Index("ix_pipeline_runs_user_status", "user_id", "status"),
        Index(
            "ix_pipeline_runs_user_archived_created",
            "user_id",
            "is_archived",
            "created_at",
        ),
    )

    # ── Méthodes de cycle de vie ──────────────────────────────────────────

    def mark_running(self) -> None:
        self.status = PipelineRunStatus.RUNNING
        if self.started_at is None:
            self.started_at = clock.now()

    def mark_paused(self) -> None:
        self.status = PipelineRunStatus.PAUSED

    # B2 (bug hunt) — FAIL-CLOSED des transitions terminales. Les `mark_*`
    # terminaux ne doivent JAMAIS écraser un statut DÉJÀ terminal : sinon une
    # race (ex: « Annuler » cliqué entre la fin de la dernière phase et le
    # mark terminal du runner) ferait passer un run CANCELLED en SUCCESS/
    # STOPPED_EARLY — un run annulé présenté comme arrêt propre/succès (viole
    # CRIT-B). Sous sérialisation des écritures SQLite + re-read frais de
    # `_update_run_status`, le PREMIER statut terminal committé gagne (pas de
    # lost-update, pas de corruption — les deux issues sont des terminaux
    # valides). `mark_running`/`mark_paused` ne sont PAS gardés (transitions
    # depuis pending/running légitimes).

    # Les mark_* terminaux retournent ``bool`` : True si la transition a PRIS,
    # False si le run était DÉJÀ terminal (garde B2 → no-op). B8 : le caller
    # (runner) gate la publication de l'event terminal sur ce retour, pour ne
    # pas émettre un event « complete » sur un run déjà CANCELLED par une race
    # (cohérence event ↔ BDD).
    def mark_success(self, final_sql: str, *, row_count_warning: bool = False) -> bool:
        if self.is_terminal():
            return False
        self.status = PipelineRunStatus.SUCCESS
        self.final_sql = final_sql
        self.row_count_warning = row_count_warning
        self.finished_at = clock.now()
        if self.started_at:
            delta = self.finished_at - ensure_utc(self.started_at)
            self.duration_seconds = delta.total_seconds()
        return True

    def mark_failed(self, message: str, traceback_text: Optional[str] = None) -> bool:
        if self.is_terminal():
            return False
        self.status = PipelineRunStatus.FAILED
        self.error_message = message
        self.error_traceback = traceback_text
        self.finished_at = clock.now()
        if self.started_at:
            delta = self.finished_at - ensure_utc(self.started_at)
            self.duration_seconds = delta.total_seconds()
        return True

    def mark_cancelled(self, by_user_id: Optional[int] = None) -> bool:
        if self.is_terminal():
            return False
        self.status = PipelineRunStatus.CANCELLED
        self.cancelled_by_user_id = by_user_id
        self.finished_at = clock.now()
        if self.started_at:
            delta = self.finished_at - ensure_utc(self.started_at)
            self.duration_seconds = delta.total_seconds()
        return True

    def mark_stopped_early(self) -> bool:
        """Run arrêté volontairement à une phase intermédiaire (preview Iris).

        Statut TERMINAL distinct de SUCCESS (aucun SQL final produit) et de
        PAUSED (suspension mid-run). ``stop_after_phase`` (posé à la création
        du run) indique la phase cible. Resumable via ``pipeline_resume`` qui
        crée un NOUVEAU run depuis le snapshot tronqué — ce run-ci reste
        terminal. Appelé par le runner quand ``state.terminal_reason ==
        "stopped_clean"`` (jamais inféré de l'absence de final_sql — CRIT-B).
        Fail-closed (B2) : n'écrase pas un statut déjà terminal (race cancel).
        Retourne True si la transition a pris, False si déjà terminal (B8).
        """
        if self.is_terminal():
            return False
        self.status = PipelineRunStatus.STOPPED_EARLY
        self.finished_at = clock.now()
        if self.started_at:
            delta = self.finished_at - ensure_utc(self.started_at)
            self.duration_seconds = delta.total_seconds()
        return True

    def is_terminal(self) -> bool:
        """Run dans un état final (immutable). SSoT : ``PipelineRunStatus.terminal()``."""
        return self.status in PipelineRunStatus.terminal()

    def to_dict(self) -> dict:
        """Sérialisation pour API JSON."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "conversation_id": self.conversation_id,
            "query_nl": self.query_nl,
            "mode": self.mode.value if isinstance(self.mode, enum.Enum) else self.mode,
            "block_all_views": self.block_all_views,
            "use_sage": self.use_sage,
            "stop_after_phase": self.stop_after_phase,
            "resumed_from_run_id": self.resumed_from_run_id,
            "status": (self.status.value if isinstance(self.status, enum.Enum) else self.status),
            "current_phase": self.current_phase,
            "last_completed_phase": self.last_completed_phase,
            "started_at": (ensure_utc(self.started_at).isoformat() if self.started_at else None),
            "finished_at": (ensure_utc(self.finished_at).isoformat() if self.finished_at else None),
            "duration_seconds": self.duration_seconds,
            "final_sql": self.final_sql,
            "error_message": self.error_message,
            "row_count_warning": self.row_count_warning,
            "request_id": self.request_id,
            "triggered_via": (
                self.triggered_via.value
                if isinstance(self.triggered_via, enum.Enum)
                else self.triggered_via
            ),
            "schema_version_at_start": self.schema_version_at_start,
            "total_tokens_input": self.total_tokens_input,
            "total_tokens_output": self.total_tokens_output,
            "total_cost_usd": self.total_cost_usd,
            "is_archived": self.is_archived,
            "created_at": (ensure_utc(self.created_at).isoformat() if self.created_at else None),
        }


class PipelinePhaseExecution(BaseModel):
    """Journal d'exécution d'une phase de la pipeline.

    Une ligne par tuple ``(run_id, phase_id, attempt_number)``. Le champ
    ``is_superseded`` distingue les versions historisées (après un
    ``goto_phase`` qui a relancé une phase amont) du dernier attempt actif.
    """

    __tablename__ = "pipeline_phase_executions"

    pipeline_run_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("pipeline_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Identification de la phase (clé canonique de PHASES_ORDER)
    phase_id: Mapped[str] = mapped_column(String(20), nullable=False)
    phase_label: Mapped[str] = mapped_column(String(200), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Statut
    status: Mapped[PipelinePhaseStatus] = mapped_column(
        SQLEnum(PipelinePhaseStatus), nullable=False, default=PipelinePhaseStatus.PENDING
    )

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Coûts
    tokens_input: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tokens_output: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    cost_usd_snapshot: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Filesystem : chemin du JSON snapshot de cette phase (distinct de
    # ``output_dir`` du run qui contient le ``run.json`` agrégé).
    artifact_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Métadonnées synthétiques (JSON sérialisé en TEXT — counts, top items,
    # zéro donnée sensible). Le contenu détaillé reste dans ``artifact_path``.
    metadata_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Erreur (si status == FAILED)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_traceback: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Marqueur d'historicité — True quand un goto_phase a fait passer cette
    # exécution au rang d'historique (un nouvel attempt l'a remplacée).
    is_superseded: Mapped[bool] = mapped_column(
        Boolean, default=False, insert_default=False, nullable=False
    )

    # Relations
    pipeline_run: Mapped["PipelineRun"] = relationship(
        "PipelineRun", back_populates="phase_executions"
    )

    __table_args__ = (
        Index(
            "ix_pipeline_phase_run_phase_attempt",
            "pipeline_run_id",
            "phase_id",
            "attempt_number",
        ),
        Index(
            "ix_pipeline_phase_run_active",
            "pipeline_run_id",
            "is_superseded",
        ),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pipeline_run_id": self.pipeline_run_id,
            "phase_id": self.phase_id,
            "phase_label": self.phase_label,
            "attempt_number": self.attempt_number,
            "status": (self.status.value if isinstance(self.status, enum.Enum) else self.status),
            "started_at": (ensure_utc(self.started_at).isoformat() if self.started_at else None),
            "finished_at": (ensure_utc(self.finished_at).isoformat() if self.finished_at else None),
            "duration_seconds": self.duration_seconds,
            "tokens_input": self.tokens_input,
            "tokens_output": self.tokens_output,
            "cost_usd_snapshot": self.cost_usd_snapshot,
            "artifact_path": self.artifact_path,
            "metadata_summary": self.metadata_summary,
            "error_message": self.error_message,
            "is_superseded": self.is_superseded,
        }
