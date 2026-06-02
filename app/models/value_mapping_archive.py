"""Modèle ``ValueMappingArchive`` — snapshot append-only de l'index legacy
``value_mapping`` avant un futur refactor vers une anonymisation bijective.

Contexte (tâche #18 du plan d'anonymisation Komptia)
====================================================

L'index ``value_mapping`` est aujourd'hui peuplé par
``app/services/ai/schema_enricher._anonymize_value`` qui produit des tokens
**lossy** (ex: ``DUPONT → DPNT`` par retrait des voyelles). Le format est
historique et pose deux problèmes :

1. **Lossy** — non bijectif : plusieurs cleartexts peuvent en théorie collisionner
   sur le même token (ex: ``DPONT``/``DUPONT`` → ``DPNT``).
2. **Désaligné** avec le nouveau ``Pseudonymizer``
   (``app/services/anonymization/pseudonymizer.py``, format ``§...§``) qui est
   strictement bijectif et déjà utilisé par ``copilot_agent``.

La décision actée pour le court terme (cf. ``docs/value_mapping_legacy_strategy.md``) :

- **Conserver** ``value_mapping`` legacy tant que la live-query Sage n'est pas
  stabilisée — son contenu est régénéré à chaque ``schema_sync`` et la migration
  vers du bijectif touche ~27 call sites, donc à programmer après stabilisation.
- **Archiver une fois** l'état avant tout refactor pour permettre un diff
  cleartext-par-cleartext entre l'ancien (``DPNT``) et le nouveau (``§...§``)
  format au moment de la bascule. Sans cette archive, l'historique est perdu
  car ``value_mapping`` est rebâti à chaque sync (DELETE+INSERT par colonne).

Ce module définit la table de snapshot. Le peuplement initial se fait via
une migration ``data`` self-idempotente définie dans
``app/core/database.py`` (``snapshot_legacy_lossy_pre_task_18``) qui
``INSERT INTO value_mapping_archive ... SELECT ... FROM value_mapping
WHERE NOT EXISTS (...)``. Au 2ᵉ boot, la clause ``NOT EXISTS`` ne matche
plus → no-op silencieux.

Pourquoi un nouveau modèle plutôt qu'une colonne sur ``value_mapping``
=====================================================================

- ``value_mapping`` est un cache : ``schema_enricher._store_value_mappings``
  fait ``DELETE WHERE table_name=? AND column_name=?`` puis ré-INSERT à
  chaque sync de colonne. Une colonne ``archived_at`` y serait écrasée
  immédiatement.
- L'archive doit survivre aux syncs ; elle DOIT être disjointe.
- La séparation préserve aussi un test simple : la table ``value_mapping``
  garde son schéma stable, l'archive vit dans son propre cycle de vie.

Sécurité / RGPD
===============

Cette table contient les MÊMES données que ``value_mapping`` (cleartext +
forme anonymisée), donc elle DOIT vivre dans la BDD chiffrée SQLCipher.
``BaseModel`` (via ``app.models.base``) garantit l'enregistrement dans
``Base.metadata`` qui est unique et chiffré au boot
(``app/core/database.init_db``). **Ne JAMAIS exposer cette table à un
endpoint API non-admin** — comme pour ``value_mapping``, elle n'a aucun
caller frontend prévu.

Volume attendu
==============

À la 1ʳᵉ archive, ``value_mapping`` contient typiquement 50K-200K rows
(800 tables × 30 colonnes × 5-10 valeurs distinctes). L'archive est un
INSERT ... SELECT en une seule transaction → l'overhead SQLite est
négligeable (~1-2 secondes pour 200K rows sur un SSD).

L'archive ne grossit PAS au fil des syncs (snapshot one-shot). Si un futur
refactor décide d'en faire un journal multi-snapshot, ajouter un nouveau
``archive_reason`` distinct → la WHERE NOT EXISTS prendra le relais
(une nouvelle migration ``data`` avec un autre reason déclenchera un nouvel
INSERT sans toucher l'existant).
"""

from datetime import datetime

from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core import clock
from app.models.base import Base


class ValueMappingArchive(Base):
    """Snapshot append-only de ``value_mapping`` avant le refactor lossy →
    bijectif.

    Schéma : mirror exact de ``ValueMapping`` (mêmes colonnes, mêmes types,
    mêmes longueurs) + deux colonnes d'instrumentation (``archived_at`` et
    ``archive_reason``). Garder le mirror exact permet de joindre les deux
    tables sans cast au moment du refactor diff.

    La PK est ``id`` autoincrement (et NON la PK de ``value_mapping``) car
    une archive n'est pas un état courant — c'est une row immuable
    associée à un ``archive_reason`` donné. Plusieurs snapshots futurs
    (avec des ``archive_reason`` distincts) pourraient référencer la même
    ``(table_name, column_name, real_value_lower)`` → pas de contrainte
    unique sur ce triplet ici (volontaire).
    """

    __tablename__ = "value_mapping_archive"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # ── Mirror exact de ValueMapping ────────────────────────────────────
    # Garder les mêmes types/longueurs garantit que l'INSERT...SELECT de la
    # migration ne perd pas de données par troncature et que les
    # comparaisons cleartext-par-cleartext lors du refactor diff sont
    # valides sans cast.
    #
    # Limite SQLite (à connaître) : ``String(N)`` est **advisory** — SQLite
    # n'enforce PAS la longueur, ni au INSERT direct ni à l'INSERT...SELECT
    # (cf. https://www.sqlite.org/datatype3.html §3 "Type Affinity"). Une
    # row de ``value_mapping`` qui contiendrait un ``real_value`` de 300
    # chars (impossible via le producteur ``schema_enricher`` qui clampe
    # à 200, mais théoriquement possible via INSERT manuel) sera copiée
    # **intégralement** dans l'archive — pas de troncature silencieuse.
    # Côté ORM, SQLAlchemy 2.0 ne valide pas non plus la longueur au
    # ``add()`` — la garde de cohérence est exclusivement côté producteur.

    table_name: Mapped[str] = mapped_column(String(100), nullable=False)
    column_name: Mapped[str] = mapped_column(String(100), nullable=False)
    real_value: Mapped[str] = mapped_column(String(200), nullable=False)
    real_value_lower: Mapped[str] = mapped_column(String(200), nullable=False)
    # Note 2026-05-22 : la colonne ``anonymized_value`` (présente côté
    # ``ValueMapping`` jusqu'à cette date) a été supprimée — /data-privacy
    # (``anonymization_terms``) est désormais la seule source des pseudos
    # runtime. L'archive ne la stocke donc plus.
    value_type: Mapped[str] = mapped_column(String(20), nullable=False, default="text")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=clock.now)

    # ── Instrumentation archive ─────────────────────────────────────────
    # Permet de distinguer plusieurs snapshots si un futur refactor en
    # déclenche d'autres avec un ``archive_reason`` distinct (la migration
    # ``data`` actuelle utilise ``"pre-refactor-task-18"``).

    #: Timestamp UTC de l'archivage (peuplé par la migration via
    #: ``CURRENT_TIMESTAMP``). Sert au audit script à reporter l'âge du
    #: snapshot et à un futur diff multi-snapshot à les ordonner.
    archived_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=clock.now)

    #: Étiquette stable identifiant la migration qui a produit cette row.
    #: Sert au self-idempotent ``WHERE NOT EXISTS`` de la migration ``data``
    #: et de filtre lisible pour le audit script. Format conseillé :
    #: ``"<intent>-task-<id>"`` pour traçabilité dans les MANIFESTs.
    archive_reason: Mapped[str] = mapped_column(String(100), nullable=False)

    __table_args__ = (
        # Filtre principal du audit script et de la WHERE NOT EXISTS de la
        # migration ``data`` (vérifie en O(log n) que ce snapshot n'a pas
        # déjà été inséré).
        Index("idx_vma_archive_reason", "archive_reason"),
        # Lookup parité avec ``value_mapping`` pour faciliter les diffs au
        # moment du refactor (joindre par table+colonne).
        Index("idx_vma_table_col", "table_name", "column_name"),
    )

    def __repr__(self) -> str:
        rv = self.real_value or ""
        truncated = (rv[:3] + "…") if len(rv) > 4 else "<redacted>"
        return (
            f"<ValueMappingArchive(reason={self.archive_reason}, "
            f"{self.table_name}.{self.column_name}: '{truncated}' [{self.value_type}])>"
        )

    def to_dict(self) -> dict:
        """Sérialisation SANS ``real_value`` — règle de confidentialité
        identique à ``ValueMapping.to_dict``."""
        return {
            "id": self.id,
            "table_name": self.table_name,
            "column_name": self.column_name,
            "value_type": self.value_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "archived_at": self.archived_at.isoformat() if self.archived_at else None,
            "archive_reason": self.archive_reason,
        }
