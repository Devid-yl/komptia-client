"""Modèle ``UserActivitySummary`` — résumé d'activité par utilisateur.

Une ligne par utilisateur (relation 1-1 avec ``users``) qui maintient les
derniers timestamps et les compteurs d'usage des fonctionnalités clés. Ce
résumé alimente :

- les **triggers comportementaux** (T3.2) : « user n'a pas posé de question
  à Iris depuis 3 jours → toast au prochain login »,
- le **dashboard onboarding-metrics** (T3.3) : médianes TTV, activation
  rate D7, liste des utilisateurs dormants,
- le **throttle des nudges** (``last_nudged_at``) : maximum un message
  de relance par utilisateur par semaine, tous canaux confondus.

Doctrine sénior :

1. **Aggregate, pas event log**. Cette table ne stocke PAS chaque
   événement — elle maintient un résumé (last_*, total_*). Les événements
   bruts vivent dans leurs tables d'origine (``conversation_messages`` pour
   Iris, ``executions`` pour automations, ``reports`` pour les rapports).
   L'aggregate suffit aux triggers et métriques, et tient en RAM.

2. **Lazy-create à la première écriture**. Aucun backfill au boot : les
   users existants n'ont pas de ligne tant qu'ils ne se reconnectent pas.
   Le hook ``BaseHandler.prepare()`` (T3.1) fait un ``INSERT ... ON
   CONFLICT DO NOTHING`` + ``UPDATE last_seen_at`` à chaque requête HTTP
   authentifiée, ce qui crée la ligne au premier accès. Bien plus simple
   qu'une migration data lourde.

3. **Relation 1-1 avec ``users``**. ``user_id`` est ``unique=True`` + FK
   CASCADE. Côté ``User``, la relation est déclarée avec ``uselist=False``
   pour pointer sur l'objet unique (pas une liste). Suppression utilisateur
   → suppression cascadée du résumé (RGPD).

4. **``first_seen_at`` et ``last_seen_at`` non-nullables avec default**.
   Ces deux champs sont toujours présents (posés à la création de la
   ligne). Les autres ``last_*_at`` restent nullables car ils ne sont
   pertinents qu'après la première utilisation de la feature correspondante.

5. **Index sur ``last_seen_at``**. Le job APScheduler de relance (T3.2)
   exécute ``SELECT user_id FROM user_activity_summary WHERE last_seen_at
   < NOW() - INTERVAL 14 DAY``. Avec quelques dizaines/centaines de users,
   c'est marginal, mais le pattern est correct et reste vrai à 10 000+.

6. **``last_nudged_at`` global, pas par canal**. Le throttle est unifié :
   peu importe si le nudge est un toast in-app, un email, ou un push, on
   compte UN message par 7 jours. Si on devait segmenter par canal plus
   tard, il faudrait une table séparée ``user_nudges_log``.

7. **Compteurs lifetime, jamais décrémentés**. ``total_iris_queries``,
   ``total_automations_created``, ``total_reports_generated`` sont des
   compteurs cumulatifs *lifetime* : la suppression d'une conversation
   ou d'une automation ne les décrémente PAS. Conserver l'historique
   d'usage est nécessaire pour les cohortes d'activation D7/D30 — si on
   décrémentait, une cohorte rétroactive serait fausse. Le bug-pattern à
   éviter : un futur dev qui implémente un décrément casserait
   silencieusement les métriques.

8. **``default=func.now()`` (SQL-side) volontaire**. Cohérent avec
   ``BaseModel.TimestampMixin`` (``app/models/base.py:30``) qui utilise
   ``func.now()`` pour ``created_at``. ``TenantSetupProgress`` utilise
   ``lambda UTC`` Python-side parce qu'il hérite de ``Base`` direct
   (pas BaseModel), avec le même pattern singleton (``id=1`` fixe).
   Les deux patterns produisent le même résultat fonctionnel ; la
   normalisation UTC se fait à la sortie via ``iso_or_none``.

Références :
- ``app/models/user_storage.py`` — pattern 1-1 ``user_id`` UNIQUE.
- T3.1 / T3.2 (todo list) — services qui consomment cet aggregate.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel, iso_or_none

if TYPE_CHECKING:
    from app.models.user import User


class UserActivitySummary(BaseModel):
    """Résumé d'activité d'un utilisateur (relation 1-1 avec ``users``).

    Sert de source de vérité pour les triggers de relance, les métriques
    onboarding et le throttle des nudges.
    """

    __tablename__ = "user_activity_summary"

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        comment="Utilisateur concerné — 1-1, CASCADE pour RGPD.",
    )

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=func.now(),
        comment="Premier accès authentifié de l'utilisateur après création.",
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=func.now(),
        comment="Dernier accès authentifié (mis à jour à chaque requête HTTP).",
    )

    last_iris_query_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Dernière question posée à Iris.",
    )
    last_automation_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Dernière automation exécutée (manuelle ou planifiée).",
    )
    last_report_generated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Dernier rapport généré.",
    )
    last_dashboard_viewed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Dernier dashboard consulté.",
    )

    total_iris_queries: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Nombre cumulé de questions posées à Iris.",
    )
    total_automations_created: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Nombre cumulé d'automations créées.",
    )
    total_reports_generated: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Nombre cumulé de rapports générés.",
    )

    last_nudged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Dernière relance comportementale (tous canaux confondus).",
    )

    user: Mapped["User"] = relationship(
        "User",
        back_populates="activity_summary",
        uselist=False,
    )

    __table_args__ = (Index("ix_activity_last_seen", "last_seen_at"),)

    def __repr__(self) -> str:
        return (
            f"<UserActivitySummary(user_id={self.user_id}, "
            f"queries={self.total_iris_queries}, last_seen={self.last_seen_at!r})>"
        )

    def to_dict(self) -> dict[str, Any]:
        """Sérialise pour l'API métriques. Timestamps en UTC."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "first_seen_at": iso_or_none(self.first_seen_at),
            "last_seen_at": iso_or_none(self.last_seen_at),
            "last_iris_query_at": iso_or_none(self.last_iris_query_at),
            "last_automation_run_at": iso_or_none(self.last_automation_run_at),
            "last_report_generated_at": iso_or_none(self.last_report_generated_at),
            "last_dashboard_viewed_at": iso_or_none(self.last_dashboard_viewed_at),
            "total_iris_queries": self.total_iris_queries,
            "total_automations_created": self.total_automations_created,
            "total_reports_generated": self.total_reports_generated,
            "last_nudged_at": iso_or_none(self.last_nudged_at),
            "created_at": iso_or_none(self.created_at),
            "updated_at": iso_or_none(self.updated_at),
        }
