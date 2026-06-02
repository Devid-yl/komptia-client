"""Modèle ``AnonymizationAudit`` — journal immuable des modifications de la
liste de termes d'anonymisation d'un utilisateur.

Chaque action user (création, mise à jour de flags, changement de pseudo,
suppression manuelle ou par cleanup) produit une row ici. Permet :

- **Audit RGPD** (article 15-22 — droit d'accès, rectification, effacement) :
  l'utilisateur peut consulter l'historique de SES propres modifications.
- **Debug** : retracer pourquoi un terme a basculé enabled=True à un moment
  précis (utilisateur via panneau ? auto-classifier ? job de cleanup ?).
- **Détection d'anomalies** : un user qui désactive massivement des termes
  critiques en clair = signal d'alerte (typiquement, une attaque social
  engineering ou un compte compromis).

**Pas une source de vérité de l'état** — c'est ``AnonymizationTerm`` qui
contient l'état courant. Cette table est un journal append-only.

**Volume attendu** : 2-3 rows par terme par mois en usage normal. Pour un
user actif (500 termes), ~1500-3000 rows/mois. TTL géré par
``cleanup_anonymization_audit`` (cf. ``app/services/cleanup/db_retention.py``)
— 90 jours par défaut, configurable via
``ANONYMIZATION_AUDIT_RETENTION_DAYS``.

**Limite RGPD connue (à traiter)** : la colonne ``term`` contient le
cleartext (cap 500 chars) et la row survit pendant ``retention_days`` après
suppression du terme actif dans ``anonymization_terms``. Concrètement,
si un user supprime un terme PII (ex: IBAN) le J0, l'audit row le conserve
jusqu'à J+90. Implication : un erase-user RGPD article 17 sélectif (un
seul terme) n'efface PAS l'audit row correspondant. La cascade
``user_id ondelete='CASCADE'`` couvre l'effacement total du user, mais
pas l'effacement granulaire. Mitigation future possible : flag
``term_hashed`` + champ ``term_hash`` (SHA-256 tronqué) qui prend le
relais après suppression du term original. À traiter dans une tâche
dédiée si la conformité l'exige.
"""

from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Index, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.user import User


class AnonymizationAudit(BaseModel):
    """Une row = une modification de la liste de termes d'un utilisateur.

    ``triggered_by`` : qui a déclenché l'action ?

    - ``"user_panel"`` : édition manuelle via ``PUT /api/anonymization/terms``
    - ``"copilot"`` : reconcile automatique au boot d'un classeur
    - ``"auto_classifier"`` : LLM local Ollama (auto_classify)
    - ``"system_cleanup"`` : job quotidien (terme orphelin)
    - ``"system_migration"`` : backfill ponctuel via migration BDD

    ``action`` : ``"insert"`` (créé), ``"update"`` (modifié), ``"delete"`` (supprimé).

    ``changed_fields`` : JSON ``{"field": [old_value, new_value]}``. Pour
    ``insert``, ``old_value`` est null ; pour ``delete``, ``new_value`` est null.

    ``reason`` : commentaire libre court (ex: "cleanup: not in active_tokens",
    "user marked critical via panel", "auto-detected high-risk PII").
    """

    __tablename__ = "anonymization_audit"

    user_id: Mapped[int | None] = mapped_column(
        Integer,
        # BLOCKING #11 review : ``ondelete=SET NULL`` (et non CASCADE) pour
        # préserver le journal d'audit même quand l'utilisateur est supprimé.
        # La docstring de cette classe promet "table append-only / journal
        # immuable" — un CASCADE contredisait cette promesse silencieusement.
        # Pour un wipe RGPD article 17 explicite, le endpoint
        # ``POST /api/anonymization/wipe`` purge l'audit du user de façon
        # contrôlée (avec re-génération d'un audit row "wipe"). Sinon
        # l'historique reste — utile pour audit RGPD futur ("qu'a-t-on fait
        # de telle donnée ? quand ? pourquoi ?").
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    #: Référence à la row courante (peut être null si l'audit concerne une
    #: suppression — la row n'existe plus).
    anonymization_term_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("anonymization_terms.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    #: Snapshot du cleartext (pour pouvoir afficher l'audit même après
    #: suppression de la row originale).
    term: Mapped[str] = mapped_column(String(500), nullable=False)
    #: Snapshot des flags au moment de l'action (pour pouvoir reconstituer
    #: l'état historique sans joindre).
    category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    enabled: Mapped[bool | None] = mapped_column(nullable=True)
    confirmed: Mapped[bool | None] = mapped_column(nullable=True)
    #: Origine de l'action (cf. docstring classe).
    triggered_by: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    #: User qui a déclenché (différent de user_id si admin agit pour le
    #: compte d'un autre — pas le cas actuel mais prévu). Null pour les
    #: actions système (cleanup, migration).
    triggered_by_user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    #: Type d'action.
    action: Mapped[str] = mapped_column(String(20), nullable=False)
    #: Diff structuré ``{"field": [old, new]}``.
    changed_fields: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    #: Commentaire libre.
    reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    #: Référence au classeur d'origine (si applicable — ex: terme détecté
    #: lors du reconcile d'un classeur précis).
    classeur_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)

    # Suggestion #38 review : typage cohérent avec la FK ondelete=SET NULL
    # (ligne 70-86). Après un DELETE user, ``audit.user`` peut être None —
    # le typage doit le refléter sinon mypy ne flagge pas les bugs.
    user: Mapped["User | None"] = relationship(
        "User",
        foreign_keys=[user_id],
    )
    triggered_by_user: Mapped["User | None"] = relationship(
        "User",
        foreign_keys=[triggered_by_user_id],
    )

    __table_args__ = (
        #: Lecture chronologique inverse de l'historique d'un user.
        Index("ix_anon_audit_user_created", "user_id", "created_at"),
        #: Filtrage par origine pour stats (combien d'actions auto vs user).
        Index("ix_anon_audit_triggered_by", "triggered_by"),
    )

    def __repr__(self) -> str:
        # term jamais en clair dans __repr__ (cf. AnonymizationTerm).
        return (
            f"<AnonymizationAudit(id={self.id}, user_id={self.user_id}, "
            f"action={self.action}, triggered_by={self.triggered_by})>"
        )
