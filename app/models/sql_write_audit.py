"""Audit trail des opérations d'écriture SQL proposées par Iris.

Doctrine sénior :

1. **Trail intégral, pas best-effort.** Toute proposition d'écriture déclenche
   une ligne avec ``status="preview"``. L'approbation humaine fait passer
   ``status`` à ``executed`` (ou ``failed``/``aborted``). Aucune écriture
   réelle ne peut survenir sans qu'une ligne corresponde — l'audit est
   construit AVANT l'exécution, pas après.

2. **Préservation après suppression utilisateur.** ``ON DELETE SET NULL`` sur
   ``user_id`` et ``conversation_id`` : si un compte admin est supprimé, le
   trail des opérations qu'il a lancées reste lisible (compliance).

3. **Approval token single-use, opaque.** Le ``approval_token`` est généré
   par le service (UUID) et stocké tel quel ; ``unique=True`` empêche le
   replay côté BDD. Le service vérifie ``status == "preview"`` avant
   exécution — un token consommé est marqué ``executed``/``failed``.

4. **Statuts fermés (pas d'enum string libre).** Le service accepte
   uniquement les valeurs de ``SqlWriteStatus`` ; toute autre chaîne lève
   une exception côté service. La colonne reste ``String`` plutôt qu'un
   enum SQLAlchemy pour rester portable SQLite/SQL Server local.

5. **Snapshots tronqués.** ``before_sample``/``after_sample`` sont limités
   par le service à 10 lignes max — un audit log ne doit pas devenir un
   data-lake. Le SQL exécuté est stocké en clair (pas de PII obfuscation
   côté audit : qui-quand-quoi est l'objet de l'audit).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core import clock
from app.core.database import Base


class SqlWriteStatus(str, Enum):
    """Statuts du cycle de vie d'une proposition d'écriture SQL.

    Workflow attendu :
        ``REJECTED_BY_VALIDATOR`` (terminal — refus avant tout envoi)
        ou
        ``AWAITING_DBA`` → ``EXECUTED`` (succès) / ``FAILED`` (erreur runtime)
                       → ``ABORTED`` (refusé explicitement par le DBA)
                       → ``EXPIRED`` (TTL atteint sans réponse DBA).

    Description :
        - ``REJECTED_BY_VALIDATOR`` : SQL refusé par le validateur AST
          AVANT envoi de mail. Pas d'exécution possible. Audit conservé
          pour analyser les fausses pistes du LLM.
        - ``AWAITING_DBA`` : validateur OK + mail envoyé au DBA externe
          configuré dans ``ai_config.IRIS_WRITE_APPROVER_EMAIL``. En
          attente de la réponse (clic du lien d'approbation dans le mail).
          Le DBA est censé faire un snapshot de la BDD AVANT de cliquer.
        - ``EXECUTED`` : DBA a cliqué Confirmer, l'exécution réelle s'est
          déroulée avec succès. ``actual_rows`` posé.
        - ``FAILED`` : DBA a cliqué Confirmer, mais l'exécution a planté
          (rollback automatique). ``error_message`` posé.
        - ``ABORTED`` : DBA a cliqué Refuser dans le mail.
        - ``EXPIRED`` : ``expires_at`` dépassé sans réponse DBA. Le cleanup
          périodique ou la prochaine consultation du token bascule en
          ``EXPIRED``.
    """

    AWAITING_DBA = "awaiting_dba"
    EXECUTED = "executed"
    FAILED = "failed"
    ABORTED = "aborted"
    EXPIRED = "expired"
    REJECTED_BY_VALIDATOR = "rejected_by_validator"


class SqlWriteOperation(str, Enum):
    """Opérations d'écriture autorisées (toutes les autres sont refusées
    par le validateur AST avant audit)."""

    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"


class SqlWriteAuditLog(Base):
    """Ligne d'audit pour une proposition d'écriture SQL via Iris.

    Une ligne est créée DÈS la proposition (même refusée). Le statut
    suit le cycle preview → executed/failed/aborted/expired/rejected.

    Index :
        - ``user_id`` (filtrage par admin auteur)
        - ``created_at`` (tri récent en premier dans la vue audit)
        - ``status`` (filtrage UI : afficher les pending vs historique)
        - ``approval_token`` (lookup direct par token, unique)
    """

    __tablename__ = "sql_write_audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Auteur de la proposition (NULL si compte supprimé après le fait)
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Conversation Iris d'origine (lien optionnel — exécutions hors-conv possibles)
    conversation_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("conversations.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Identifiant de requête (traçabilité log/audit cross-handlers)
    request_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Demande utilisateur en langage naturel (ce qui a déclenché la proposition)
    original_nl_request: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Intent fourni par le LLM (résumé naturel de l'opération)
    intent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # SQL proposé (texte brut, tel que produit par le LLM)
    generated_sql: Mapped[str] = mapped_column(Text, nullable=False)

    # Tables touchées extraites par le validateur AST (JSON list[str])
    parsed_tables: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)

    # Opération unique (INSERT/UPDATE/DELETE) — string pour portabilité
    parsed_operation: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # Estimation pré-execution (issue du dry-run COUNT ou ROLLBACK)
    estimated_rows: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Lignes effectivement modifiées (NULL tant que non exécuté)
    actual_rows: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Échantillon avant exécution (JSON list[dict], max 10 rows imposé par le service)
    before_sample: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(JSON, nullable=True)

    # Échantillon après exécution (idem, max 10 rows)
    after_sample: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(JSON, nullable=True)

    # Statut courant (cf. SqlWriteStatus)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=SqlWriteStatus.AWAITING_DBA.value,
        index=True,
    )

    # Message d'erreur si status=failed/rejected
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Hash SHA-256 (hex 64 chars) du token brut envoyé dans le mail au DBA.
    # Le token brut n'est JAMAIS persisté ; lookup BDD = SHA-256(token_recv).
    # ``unique=True`` empêche tout replay côté BDD.
    approval_token_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )

    # Quand le token expire (awaiting → expired après cette date si non répondu)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # Email du DBA destinataire (audité pour traçabilité)
    dba_email: Mapped[str] = mapped_column(String(254), nullable=False)

    # Timestamp d'approbation OU de refus du DBA (NULL tant que pending)
    dba_responded_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # IP source du clic d'approbation/refus (audit anti-abuse)
    dba_response_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    # Cap rows configuré au moment de la proposition (audit de la limite app)
    max_rows_at_propose: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Durée d'exécution réelle (NULL tant que non exécuté)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        onupdate=clock.now,
    )

    __table_args__ = (
        # Recherche rapide "mes previews encore valides"
        Index("ix_sql_write_audit_status_user", "status", "user_id"),
        # Recherche rapide cleanup expirations
        Index("ix_sql_write_audit_status_expires", "status", "expires_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<SqlWriteAuditLog(id={self.id}, status={self.status!r}, "
            f"op={self.parsed_operation!r}, user_id={self.user_id})>"
        )

    def to_dict(self) -> dict[str, Any]:
        """Sérialisation pour l'UI admin (vue audit)."""
        from app.models.base import ensure_utc

        return {
            "id": self.id,
            "user_id": self.user_id,
            "conversation_id": self.conversation_id,
            "request_id": self.request_id,
            "original_nl_request": self.original_nl_request,
            "intent": self.intent,
            "generated_sql": self.generated_sql,
            "parsed_tables": self.parsed_tables or [],
            "parsed_operation": self.parsed_operation,
            "estimated_rows": self.estimated_rows,
            "actual_rows": self.actual_rows,
            "before_sample": self.before_sample,
            "after_sample": self.after_sample,
            "status": self.status,
            "error_message": self.error_message,
            "dba_email": self.dba_email,
            "dba_responded_at": (
                ensure_utc(self.dba_responded_at).isoformat() if self.dba_responded_at else None
            ),
            "max_rows_at_propose": self.max_rows_at_propose,
            "duration_ms": self.duration_ms,
            "created_at": (ensure_utc(self.created_at).isoformat() if self.created_at else None),
            "updated_at": (ensure_utc(self.updated_at).isoformat() if self.updated_at else None),
            "expires_at": (ensure_utc(self.expires_at).isoformat() if self.expires_at else None),
        }


__all__ = [
    "SqlWriteAuditLog",
    "SqlWriteStatus",
    "SqlWriteOperation",
]
