"""Modèle ``QueryDiffHistory`` — diff temporel persisté entre exécutions
de questions répétées (T30).

Quand un utilisateur pose une question similaire à un historique récent
(recall-IDF ≥ :data:`app.services.ai.result_diff.DIFF_RECALL_THRESHOLD`),
le service ``result_diff`` calcule le delta sur les rows résultats. Ce
delta est sérialisé ici pour relecture sans re-calcul (typiquement dans
la grille Iris au reload d'une conversation, ou pour audit "qu'a changé
entre 2 runs").

**Confidentialité** : ``diff_json`` peut contenir des données réelles
de la BDD source du client (cellules ``added``/``removed``/cells
modifiées). Implication : la table doit vivre dans la BDD locale
SQLCipher chiffrée au même titre que les autres données client. Un
job TTL (cf. :func:`app.services.cleanup.db_retention.cleanup_query_diff_history`)
purge les rows > 30 jours par défaut pour borner la croissance.

**FKs** :

* ``user_id`` → ``users.id ON DELETE SET NULL`` (préserve l'audit
  même si user supprimé, cohérent avec ``AIPerformanceLog``).
* ``search_id_current`` / ``search_id_prev`` → ``ai_performance_logs.id
  ON DELETE CASCADE`` (un diff sans son log de référence n'a plus
  de sens).

**Unicité** : un index unique sur la paire ``(search_id_current,
search_id_prev)`` empêche les doublons (race condition entre 2 caller
concurrents qui appellent ``persist_query_diff`` en parallèle pour la
même paire). Le caller doit catch ``IntegrityError`` ou utiliser un
``ON CONFLICT DO NOTHING`` selon le besoin.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, Index, Integer, JSON, Numeric
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.ai_performance import AIPerformanceLog
    from app.models.user import User


class QueryDiffHistory(BaseModel):
    """Diff JSON entre 2 exécutions d'une même requête (logique).

    Hérite de :class:`BaseModel` → fournit ``id``, ``created_at``,
    ``updated_at`` automatiques. La table est créée par
    ``Base.metadata.create_all`` au boot (pas de migration ALTER
    nécessaire pour la création).
    """

    __tablename__ = "query_diff_history"
    __table_args__ = (
        # Lookup courant : "tous les diffs d'un user récents"
        Index("ix_query_diff_user_created", "user_id", "created_at"),
        # Lookup par log courant : "le diff associé à ce search_id"
        Index("ix_query_diff_search_current", "search_id_current"),
        # Unicité de la paire pour empêcher les doublons concurrents.
        Index(
            "ix_query_diff_pair",
            "search_id_current",
            "search_id_prev",
            unique=True,
        ),
    )

    user_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    #: ID de l'``AIPerformanceLog`` correspondant à l'exécution courante.
    search_id_current: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("ai_performance_logs.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: ID de l'``AIPerformanceLog`` correspondant à l'exécution précédente.
    search_id_prev: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("ai_performance_logs.id", ondelete="CASCADE"),
        nullable=False,
    )

    #: Score recall-IDF entre les 2 questions (0.0 à 1.0). ``Numeric(5,4)``
    #: au lieu de ``Float`` pour précision exacte sur la comparaison
    #: contre seuil (``WHERE recall_score >= 0.50``).
    recall_score: Mapped[Optional[float]] = mapped_column(Numeric(5, 4), nullable=True)

    #: Compteurs dénormalisés extraits de ``diff_json["summary"]`` —
    #: permet des requêtes analytiques indexables ("diffs avec >100 rows
    #: ajoutées") sans parser le JSON. Aligné avec les axes 7+13 du
    #: contrat qualité Komptia (single source of truth + analytics
    #: queryables).
    added_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    removed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    modified_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    #: Diff JSON sérialisé (cf.
    #: :func:`app.services.ai.result_diff.format_result_diff_for_ui`).
    #: Structure : ``{added, removed, modified, summary, key_columns,
    #: schema_changed, *_truncated, *_total}``.
    diff_json: Mapped[dict] = mapped_column(JSON, nullable=False)

    # ``lazy="raise"`` + ``passive_deletes=True`` :
    # - lazy="raise" : fail-fast en async hors session (au lieu d'un
    #   crash MissingGreenlet en prod). Le caller doit utiliser
    #   ``selectinload(QueryDiffHistory.current_search)`` explicitement.
    # - passive_deletes=True : aligne SQLAlchemy 2.0 avec l'ondelete
    #   CASCADE de la BDD (sinon SQLAlchemy ne sait pas que la cascade
    #   est gérée côté BDD et peut produire des messages confus).
    user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[user_id], lazy="raise")
    current_search: Mapped["AIPerformanceLog"] = relationship(
        "AIPerformanceLog",
        foreign_keys=[search_id_current],
        lazy="raise",
        passive_deletes=True,
    )
    previous_search: Mapped["AIPerformanceLog"] = relationship(
        "AIPerformanceLog",
        foreign_keys=[search_id_prev],
        lazy="raise",
        passive_deletes=True,
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "search_id_current": self.search_id_current,
            "search_id_prev": self.search_id_prev,
            "recall_score": float(self.recall_score) if self.recall_score is not None else None,
            "added_count": self.added_count,
            "removed_count": self.removed_count,
            "modified_count": self.modified_count,
            "diff_json": self.diff_json,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
