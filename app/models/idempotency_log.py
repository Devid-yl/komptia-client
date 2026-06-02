"""
Modele IdempotencyLog — protection contre les doublons sur les sinks (email, report).

Probleme resolu (design §2.6) :
- Un workflow qui envoie un email echoue apres l'envoi SMTP mais avant le
  commit DB. A la prochaine execution, le run est relance → email envoye
  une deuxieme fois. "La cliente a recu 47 mails identiques a 3h du matin."

Solution :
- Avant chaque operation irreversible (send_email, write_report), calcul
  d'une idempotency_key = sha256(inputs + config_snapshot + run_date_iso)
  ou `run_date_iso` est la DATE (YYYY-MM-DD) du run, pas le datetime.
  Granularite jour : 2 runs successifs du meme workflow dans la meme
  journee produisent la meme key → doublon detecte. 2 runs espaces de
  plusieurs jours produisent des keys differentes (comportement voulu).
- INSERT dans F_IDEMPOTENCY_LOG avec `key` UNIQUE. Si la key existe deja
  dans la fenetre TTL (24h), le sink est skippe.

Design :
- TTL configurable (defaut 24h) pour purge auto des entrees anciennes.
- FK vers StepExecution pour audit (quelle tentative a produit cette key).
- Pas d'index sur expires_at en Phase 2a — le purge scheduled job peut
  scanner toute la table (taille raisonnable : N workflows × M sinks/run
  × runs_par_jour). On ajoutera un index si le volume grossit.
"""

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core import clock
from app.core.database import Base

if TYPE_CHECKING:
    from app.models.step_execution import StepExecution  # noqa: F401


# TTL par defaut pour les entrees idempotency (24h). Une key plus vieille
# que ca ne bloque plus un nouvel envoi — considere comme "nouvelle occurrence".
IDEMPOTENCY_TTL_HOURS: int = 24


class IdempotencyLog(Base):
    """Journal des operations idempotentes (sinks : email, report)."""

    __tablename__ = "F_IDEMPOTENCY_LOG"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    key: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        comment="Hash sha256 hex de (inputs + config + run_date)",
    )

    step_execution_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("F_STEP_EXECUTION.id", ondelete="SET NULL"),
        nullable=True,
        comment="StepExecution qui a produit cette key (audit)",
    )

    sink_kind: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Type de sink: 'email' ou 'report'",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=lambda: clock.now() + timedelta(hours=IDEMPOTENCY_TTL_HOURS),
        comment="Apres cette date, un nouvel envoi avec la meme key est autorise",
    )

    def __repr__(self) -> str:
        return f"<IdempotencyLog(key='{self.key[:12]}...', sink='{self.sink_kind}')>"

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """True si la fenetre d'idempotency a expire (nouvelle occurrence autorisee).

        SQLite/aiosqlite restitue les DateTime sans tzinfo. On rattache UTC
        si manquant pour eviter le TypeError "naive vs aware" au compare.
        """
        check_time = now or clock.now()
        expires = self.expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return check_time >= expires
