"""
Modèle Automation pour Komptia.

Représente une automatisation : requête planifiée + rapport + envoi email.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Optional
from sqlalchemy import (
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    LargeBinary,
)
from sqlalchemy.orm import relationship, Mapped, mapped_column
from app.core import clock
from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User  # noqa: F401
    from app.models.execution import Execution  # noqa: F401
    from app.models.automation_step import AutomationStep  # noqa: F401
    from app.models.automation_edge import AutomationEdge  # noqa: F401
    from app.models.webhook_trigger import WebhookTrigger  # noqa: F401


class Automation(Base):
    """
    Automatisation : requête planifiée qui génère un rapport périodique.

    Workflow:
    1. Utilisateur crée une automation via wizard (US-3.3)
    2. Scheduler lance l'automation selon schedule (US-3.2)
    3. Exécuteur génère le rapport et l'envoie (US-3.4)
    4. Historique stocké dans Execution
    """

    __tablename__ = "F_AUTOMATION"

    # Identification
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        index=True,
        comment="Nom court de l'automatisation (ex: 'Rapport hebdo clients')",
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="Description détaillée de l'automatisation"
    )

    # Requête
    query_type: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="nl",
        comment="Type de requête: 'nl' (langage naturel) ou 'sql' (SQL direct)",
    )
    query_text: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Texte de la requête (question NL ou SQL brut)"
    )

    # Planification
    schedule_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="daily",
        comment="Type de planification: 'once', 'daily', 'weekly', 'monthly', 'cron'",
    )
    schedule_config: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Config JSON: hour, minute, day_of_week, cron",
    )

    # Sortie
    output_format: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="csv",
        comment="Format de sortie: 'csv', 'excel', 'pdf'",
    )
    recipients: Mapped[Optional[list]] = mapped_column(
        JSON,
        nullable=True,
        comment="Liste emails destinataires: ['user@example.com', 'admin@example.com']",
    )

    # Notifications
    notify_on_failure: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Envoyer un email de notification en cas d'echec d'execution",
    )
    notify_on_success: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Envoyer un email de notification en cas de succes d'execution",
    )
    notification_emails: Mapped[Optional[list]] = mapped_column(
        JSON,
        nullable=True,
        comment="Emails de notification (defaut: email du proprietaire)",
    )

    # État
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Automatisation active (planifiée) ou inactive (en pause)",
    )

    # **Phase 2.5.6.ter (#100)** — Traçabilité auto-pause.
    # Quand ``is_active=False`` à cause d'un échec automatique (data_access
    # denied, max_total_rows dépassé, etc.), on enregistre la raison pour
    # que l'admin/user comprenne pourquoi sans devoir grep les logs.
    # Affiché en badge UI dans la liste des autos. NULL = pause manuelle.
    paused_reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment=(
            "Raison textuelle de l'auto-pause (data_access_denied, "
            "max_rows_exceeded, etc.). NULL = pause manuelle ou jamais pausée."
        ),
    )
    paused_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp UTC de la dernière auto-pause (NULL si jamais).",
    )

    # **Phase 2.5.6.bis (#99)** — Compteur d'échecs consécutifs non-RLS.
    # Une auto qui échoue 5x d'affilée (LLM down, SMTP timeout, BDD lente,
    # etc., PAS data_access) est probablement cassée structurellement.
    # Auto-pause au lieu de continuer à essayer tous les jours pour rien.
    # Reset à 0 sur la 1ère exécution réussie. Les échecs data_access ne
    # comptent PAS ici (path séparé qui auto-pause immédiatement via #77).
    consecutive_failure_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment=(
            "Nombre d'échecs CONSÉCUTIFS non-RLS. Reset à 0 sur success. "
            "Auto-pause via paused_reason='too_many_failures' au seuil "
            "MAX_CONSECUTIVE_FAILURES."
        ),
    )

    # Phase 2 DAG : fail_policy — comportement si un node echoue en cours d'exec.
    # - "abort" (defaut) : descendants du node failed marques skipped ;
    #   branches INDEPENDANTES continuent jusqu'au bout.
    # - "abort_all" : tout le graphe s'arrete des qu'un node echoue.
    # - "best_effort" : on continue partout, les nodes dependants recoivent
    #   None comme entree (dangereux, a reserver aux cas non-critiques).
    fail_policy: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="abort",
        server_default="abort",
        comment="Fail policy DAG: abort / abort_all / best_effort",
    )

    # Phase 2d DAG : circuit-breaker par run pour eviter les runs pathologiques
    # (SQL qui retourne 10M lignes, boucle LLM infinie, run qui depasse 1h).
    # NULL = pas de limite. Enforcement runtime dans DAG executor.
    max_llm_cost_eur: Mapped[Optional[float]] = mapped_column(
        nullable=True,
        comment="Cout LLM max cumule par run en euros (NULL = pas de limite)",
    )
    max_total_rows: Mapped[Optional[int]] = mapped_column(
        nullable=True,
        comment="Nombre max de lignes cumulees (rows_out tous nodes) par run",
    )
    max_duration_seconds: Mapped[Optional[int]] = mapped_column(
        nullable=True,
        comment="Duree max du run en secondes (abort si depasse)",
    )

    # T28 — Snapshot pipeline pour reproductibilite (gzipped JSON).
    # Capture a la creation : schema_version (SchemaSync), modele LLM,
    # provider, parametres + pipeline_state si fourni (concepts_resolved,
    # ir_final, sql_final). Permet replay_automation() pour detecter le
    # drift entre l'etat initial et l'etat courant (schema/modele/SQL).
    # Decompresse + parse via app.services.automation.snapshot_service.
    # NULL = automation creee avant T28 ou capture echouee en best-effort.
    #
    # ⚠️ V2 perf : la colonne peut peser jusqu'a 1 MiB gzippe par row.
    # Marquer ``deferred=True`` casse l'acces lazy en async (MissingGreenlet
    # sur SQLite+aiosqlite). Pour la liste des autos, utiliser
    # ``.options(defer(Automation.snapshot_json))`` cote handler quand le
    # blob n'est pas necessaire — au lieu de rendre la colonne deferred
    # par defaut (qui force un eager opt-in partout sinon crash).
    snapshot_json: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary,
        nullable=True,
        comment="Snapshot pipeline gzippé (JSON) pour reproductibilité — capture à la création",
    )

    # Ownership
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Utilisateur propriétaire de l'automatisation",
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        comment="Date de création de l'automatisation",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        onupdate=clock.now,
        comment="Date de dernière modification",
    )

    # Cluster-N 2026-05-26 — Optimistic concurrency token (ETag/If-Match).
    # Compteur monotone strictement croissant incrémenté à CHAQUE mutation
    # de l'automation OU de ses children (steps, edges, schedule). Le
    # client envoie `If-Match: <version>` sur PUT ; le serveur renvoie
    # 409 Conflict si la version BDD diverge (= autre onglet a sauvé entre
    # temps). Empêche la perte silencieuse de données multi-onglets.
    # Atomic UPDATE WHERE id=? AND version=? (compare-and-swap) garantit
    # safety même en multi-instance.
    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
        comment=(
            "Version optimistic-locking (ETag). Incrémentée à chaque "
            "mutation de l'auto ou de ses steps/edges. Utilisée par les "
            "PUT handlers via header If-Match → 409 si mismatch."
        ),
    )

    # Relations
    user: Mapped["User"] = relationship("User", back_populates="automations")
    executions: Mapped[list["Execution"]] = relationship(
        "Execution",
        back_populates="automation",
        cascade="all, delete-orphan",
        order_by="desc(Execution.started_at)",
    )
    steps: Mapped[list["AutomationStep"]] = relationship(
        "AutomationStep",
        back_populates="automation",
        cascade="all, delete-orphan",
        order_by="AutomationStep.step_order",
    )
    edges: Mapped[list["AutomationEdge"]] = relationship(
        "AutomationEdge",
        back_populates="automation",
        cascade="all, delete-orphan",
    )
    webhooks: Mapped[list["WebhookTrigger"]] = relationship(
        "WebhookTrigger",
        back_populates="automation",
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<Automation(id={self.id}, name='{self.name}', active={self.is_active})>"

    @property
    def is_workflow(self) -> bool:
        """True si cette automation utilise le mode workflow multi-etapes.

        ATTENTION: Necessite que `steps` soit eager-loaded (selectinload).
        """
        return bool(self.steps)

    def to_dict(self, include_steps: bool = False):
        """Convertit en dictionnaire pour JSON API.

        N'accede PAS aux relations (executions) pour eviter MissingGreenlet
        si appele hors session async. Utiliser une requete COUNT separee
        si le nombre d'executions est necessaire.

        Args:
            include_steps: Si True, inclut les etapes du workflow.
                Necessite selectinload(Automation.steps).
        """
        result = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "query_type": self.query_type,
            "query_text": self.query_text,
            "schedule_type": self.schedule_type,
            "schedule_config": self.schedule_config,
            "output_format": self.output_format,
            "recipients": self.recipients,
            "notify_on_failure": self.notify_on_failure,
            "notify_on_success": self.notify_on_success,
            "notification_emails": self.notification_emails,
            "is_active": self.is_active,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            # Cluster-N 2026-05-26 — optimistic concurrency token exposé
            # au client (qui le renvoie ensuite via header `If-Match`).
            "version": int(self.version or 1),
        }
        if include_steps:
            result["steps"] = [s.to_dict() for s in self.steps]
            result["is_workflow"] = bool(self.steps)
        return result

    @property
    def last_execution(self):
        """Retourne la dernière exécution (la plus récente).

        ATTENTION: Nécessite que `executions` soit eager-loaded (selectinload).
        Si appelé hors session async → MissingGreenlet.
        """
        return self.executions[0] if self.executions else None

    @property
    def success_rate(self) -> float:
        """Calcule le taux de succès des exécutions.

        ATTENTION: Nécessite que `executions` soit eager-loaded (selectinload).
        Pour les calculs en batch, préférer une requête SQL avec COUNT/SUM.
        """
        if not self.executions:
            return 0.0

        total = len(self.executions)
        successful = sum(1 for e in self.executions if e.status == "success")
        return (successful / total) * 100
