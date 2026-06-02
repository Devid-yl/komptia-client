"""Modèle ``UserOnboardingProgress`` — état d'avancement d'un tour d'onboarding par utilisateur.

Cette table remplace le ``localStorage`` côté navigateur comme source de vérité
de l'état d'onboarding. Le ``localStorage`` ne survit pas à un changement de
navigateur, un mode privé, ni un appareil différent — autant de cas où
l'utilisateur revoit indûment des tours déjà terminés (ou pire, ne reçoit
plus les triggers de réactivation parce que l'admin ne sait pas qu'il les a
ratés).

Doctrine sénior :

1. **Une ligne = un (user, tour)**. ``UniqueConstraint(user_id, tour_key)``
   garantit l'unicité. Un ``UPSERT`` côté API (``INSERT … ON CONFLICT
   DO UPDATE``) est attendu pour gérer les courses multi-onglets : 2 onglets
   du même user qui finissent simultanément le même tour ne créent pas de
   doublon — le second INSERT bascule en UPDATE.

2. **Trois timestamps, pas un état enum**. ``started_at``, ``completed_at``,
   ``skipped_at`` sont conservés indépendamment pour audit. La logique
   applicative considère « complété » dès que ``completed_at`` est non-null,
   peu importe la valeur de ``skipped_at`` (un user peut skipper puis
   compléter ; on garde la trace des deux). ``last_step_seen`` permet
   de reprendre un tour interrompu (refresh, fermeture d'onglet).

3. **Cascade DELETE**. RGPD oblige : supprimer un utilisateur efface ses
   traces d'onboarding. ``ondelete="CASCADE"`` au niveau FK + ``cascade=
   "all, delete-orphan"`` côté ``User.onboarding_progress`` couvrent les
   deux chemins (SQL direct et ORM session.delete).

4. **Indexes pour les agrégations métriques**. Le dashboard admin
   ``/admin/onboarding-metrics`` (T3.3) calcule ``completion_rate`` et
   ``skip_rate`` par ``tour_key``. Les deux indexes ``(tour_key,
   completed_at)`` et ``(tour_key, skipped_at)`` couvrent ces requêtes en
   range-scan plutôt qu'en table-scan.

5. **Pas de ``unique=True`` sur ``user_id`` seul**. Un utilisateur a une
   ligne PAR tour — donc ``user_id`` est répété N fois (N = nombre de tours
   vus). L'index sur ``user_id`` (``index=True``) accélère le ``GET
   /api/onboarding/state`` qui retourne l'état complet d'un user.

Références :
- ``app/models/user_preference.py`` — pattern ``(user_id, key)`` analogue.
- ``feedback_use_db_not_localstorage.md`` (mémoire 2026-05-17) — décision
  de migrer le tracking côté serveur.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel, iso_or_none

if TYPE_CHECKING:
    from app.models.user import User


TourState = Literal["not_started", "in_progress", "skipped", "completed"]


class UserOnboardingProgress(BaseModel):
    """Avancement d'un utilisateur sur un tour d'onboarding spécifique.

    Une ligne par couple ``(user_id, tour_key)``. Les trois timestamps
    ``started_at`` / ``completed_at`` / ``skipped_at`` sont indépendants ;
    la logique applicative privilégie ``completed_at`` quand les deux
    derniers sont posés (skip puis complétion = audit ``skipped_at``
    conservé, état effectif = complété).
    """

    __tablename__ = "user_onboarding_progress"

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Utilisateur concerné — CASCADE pour cohérence RGPD.",
    )
    tour_key: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Identifiant logique du tour (ex. 'iris_v1', 'datastore_v1').",
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Premier affichage du tour à l'utilisateur.",
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Tour terminé jusqu'à la dernière étape.",
    )
    skipped_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Tour quitté avant la fin par action utilisateur.",
    )
    last_step_seen: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Dernière étape vue (0-indexé) — permet la reprise.",
    )

    user: Mapped["User"] = relationship("User", back_populates="onboarding_progress")

    __table_args__ = (
        UniqueConstraint("user_id", "tour_key", name="uq_onboarding_user_tour"),
        Index("ix_onboarding_tour_completed", "tour_key", "completed_at"),
        Index("ix_onboarding_tour_skipped", "tour_key", "skipped_at"),
    )

    @property
    def state(self) -> TourState:
        """État effectif du tour — source unique de vérité pour __repr__/handlers.

        Priorité : ``completed_at`` > ``skipped_at`` > ``started_at``. Un user
        peut skipper puis compléter ; on conserve l'audit des deux timestamps,
        mais l'état effectif est ``completed`` dès que ``completed_at`` est
        posé.
        """
        if self.completed_at is not None:
            return "completed"
        if self.skipped_at is not None:
            return "skipped"
        if self.started_at is not None:
            return "in_progress"
        return "not_started"

    def __repr__(self) -> str:
        return (
            f"<UserOnboardingProgress(id={self.id}, user_id={self.user_id}, "
            f"tour_key='{self.tour_key}', state={self.state})>"
        )

    def to_dict(self) -> dict[str, Any]:
        """Sérialise pour l'API onboarding. Timestamps normalisés en UTC."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "tour_key": self.tour_key,
            "state": self.state,
            "started_at": iso_or_none(self.started_at),
            "completed_at": iso_or_none(self.completed_at),
            "skipped_at": iso_or_none(self.skipped_at),
            "last_step_seen": self.last_step_seen,
            "created_at": iso_or_none(self.created_at),
            "updated_at": iso_or_none(self.updated_at),
        }
