"""Modèle ``TenantSetupProgress`` — checklist d'amorçage du déploiement (singleton).

Stocke l'état d'avancement du **setup admin initial** d'un déploiement Komptia :
connexion à la BDD source, configuration du LLM, du SMTP, première invitation
utilisateur. Le bandeau de checklist sur ``/admin`` (T2.1) lit cette ligne et
masque chaque jalon dès que son timestamp est posé.

Doctrine sénior :

1. **Singleton row (``id=1`` fixe)**. Komptia est mono-déploiement
   (cf. ``CLAUDE.md`` — une organisation = un déploiement Komptia). Le PK ``id=1``
   est posé explicitement (``autoincrement=False``) — un ``INSERT`` accidentel
   d'une seconde ligne échoue immédiatement avec ``PRIMARY KEY conflict``,
   évitant la sémantique « N lignes historiques + read latest » qui aurait
   inutilement compliqué les lectures et dupliqué ce que ``updated_at`` trace
   déjà.

2. **Hérite de ``Base`` directement, pas ``BaseModel``**. ``BaseModel`` impose
   ``id: Mapped[int] = mapped_column(Integer, primary_key=True,
   autoincrement=True)`` — incompatible avec un singleton à PK fixe.
   Réécriture explicite de ``id`` / ``created_at`` / ``updated_at`` pour
   conserver le contrat (mêmes types, mêmes defaults UTC).

3. **Sept timestamps nullables**. Chaque jalon de la checklist a son propre
   champ ; ``NULL`` = pas encore franchi, valeur = horodatage du
   franchissement. Cette modélisation explicite est préférée à un champ
   ``status`` enum parce que la checklist du bandeau a besoin de savoir
   QUAND chaque étape a été franchie (audit + UX « franchi il y a 2 jours »).

4. **``dismissed_at`` séparé de ``completed_at``**. ``dismissed_at`` signifie
   « l'admin a cliqué "Je sais ce que je fais, masque ça" » sans forcément
   avoir franchi toutes les étapes. ``completed_at`` se pose
   automatiquement quand les 5 jalons sont posés (logique applicative). Le
   bandeau s'efface si l'un ou l'autre est non-null.

5. **Pas de FK vers ``users``**. Le singleton appartient au déploiement, pas
   à un utilisateur en particulier. L'audit « qui a franchi quoi » se fait
   via ``AuditLog`` (table existante) — ne pas dupliquer cet historique ici.

6. **Conservation après ``dismissed_at`` / ``completed_at``**. La ligne n'est
   JAMAIS supprimée. Un admin peut toujours « reprendre la configuration »
   via un lien dans le menu : on remet ``dismissed_at = NULL`` et le bandeau
   réapparaît.

Références :
- ``CLAUDE.md`` (section « Komptia ») — mono-déploiement.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final, Optional

from sqlalchemy import CheckConstraint, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.core import clock
from app.core.database import Base
from app.models.base import iso_or_none

#: Identifiant fixe de la ligne unique. Posé explicitement à la création
#: (pas d'autoincrement) pour interdire l'existence de plusieurs lignes
#: par accident — un INSERT additionnel échouera avec PRIMARY KEY conflict
#: ET la ``CheckConstraint("id = 1")`` rejette toute ligne avec un id autre.
SINGLETON_ROW_ID: Final[int] = 1

#: Champs représentant les jalons fonctionnels du setup (ordre = ordre UI).
#: Centralisé pour que la property ``is_complete`` et le bandeau front
#: partagent la même liste — ajout d'un jalon = un seul endroit à modifier.
TENANT_SETUP_MILESTONE_FIELDS: Final[tuple[str, ...]] = (
    "welcome_seen_at",
    "database_configured_at",
    "llm_configured_at",
    "smtp_configured_at",
    "first_user_invited_at",
)


class TenantSetupProgress(Base):
    """État d'avancement de la checklist de setup admin (ligne singleton).

    Sept timestamps représentent les jalons clés :

    - ``welcome_seen_at`` : premier affichage du bandeau de bienvenue
      (auto-validé dès que l'admin charge ``/admin`` la première fois).
    - ``database_configured_at`` : connexion BDD source validée (test
      de connexion réussi).
    - ``llm_configured_at`` : clé API LLM acceptée + modèle détecté.
    - ``smtp_configured_at`` : envoi SMTP de test réussi.
    - ``first_user_invited_at`` : un user non-admin a été créé (le flow
      d'invitation lui-même n'est pas implémenté dans le tier 1 — la
      création API simple suffit comme signal).
    - ``dismissed_at`` : l'admin a explicitement masqué la checklist
      via le bouton « Je sais ce que je fais ».
    - ``completed_at`` : les cinq jalons précédents sont franchis (posé
      par la logique applicative, pas par l'utilisateur).
    """

    __tablename__ = "tenant_setup_progress"

    # PK explicite — autoincrement=False car singleton (id=1 fixe).
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)

    welcome_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Premier affichage du bandeau de bienvenue.",
    )
    database_configured_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Connexion à la BDD source validée par un test.",
    )
    llm_configured_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Provider LLM configuré (clé acceptée, modèle détecté).",
    )
    smtp_configured_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Envoi SMTP de test réussi.",
    )
    first_user_invited_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Première création d'un utilisateur non-admin.",
    )
    dismissed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Bandeau masqué explicitement par l'admin.",
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Les cinq jalons franchis — posé par la logique applicative.",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        onupdate=clock.now,
    )

    __table_args__ = (
        CheckConstraint(f"id = {SINGLETON_ROW_ID}", name="ck_tenant_setup_singleton"),
    )

    @property
    def is_complete(self) -> bool:
        """``True`` si tous les jalons fonctionnels sont franchis.

        Lit ``TENANT_SETUP_MILESTONE_FIELDS`` pour rester en phase avec le
        bandeau front (ajout d'un jalon = un seul endroit à modifier).
        """
        return all(getattr(self, field) is not None for field in TENANT_SETUP_MILESTONE_FIELDS)

    @property
    def should_hide_banner(self) -> bool:
        """``True`` si le bandeau de checklist ne doit plus s'afficher.

        Le bandeau s'efface quand :
        - l'admin l'a explicitement dismissé (``dismissed_at`` posé), OU
        - tous les jalons fonctionnels sont franchis (``is_complete``).

        ``completed_at`` n'est pas relu ici : la posture explicite par
        l'admin (dismiss) ou la complétion réelle de la checklist suffisent.
        ``completed_at`` reste exposé pour l'audit du moment exact où la
        checklist est passée à 100 %.
        """
        return self.dismissed_at is not None or self.is_complete

    def to_dict(self) -> dict[str, Any]:
        """Sérialise la ligne pour l'API admin. Timestamps en UTC."""
        return {
            "id": self.id,
            "welcome_seen_at": iso_or_none(self.welcome_seen_at),
            "database_configured_at": iso_or_none(self.database_configured_at),
            "llm_configured_at": iso_or_none(self.llm_configured_at),
            "smtp_configured_at": iso_or_none(self.smtp_configured_at),
            "first_user_invited_at": iso_or_none(self.first_user_invited_at),
            "dismissed_at": iso_or_none(self.dismissed_at),
            "completed_at": iso_or_none(self.completed_at),
            "is_complete": self.is_complete,
            "should_hide_banner": self.should_hide_banner,
            "created_at": iso_or_none(self.created_at),
            "updated_at": iso_or_none(self.updated_at),
        }

    def __repr__(self) -> str:
        return (
            f"<TenantSetupProgress(id={self.id}, complete={self.is_complete}, "
            f"hide_banner={self.should_hide_banner})>"
        )
