"""Modèle ``DataAccessRule`` — règles d'accès aux données BDD source par utilisateur.

Ce modèle stocke des règles **fines** (table, colonne, ligne) qui restreignent
ce qu'un utilisateur peut consulter dans la base source (Sage Coala ou autre
SQL Server connecté). Les règles sont appliquées au runtime par
:mod:`app.services.data_access.enforcer` à 3 niveaux defense-in-depth :

1. Filtrage du contexte LLM (``agent_knowledge._get_table_catalogue``) — Iris
   ne mentionne pas les tables interdites.
2. Validation pre-flight de la SQL avant exécution (rejet si table/colonne
   interdite).
3. Injection de filtres ``WHERE col IN (...)`` via sqlglot AST avant
   l'exécution finale (row-level security).

**Granularité** :

- ``scope_type = "table"`` : autorise/interdit toute la table. ``column_name``
  et ``allowed_values`` ignorés.
- ``scope_type = "column"`` : interdit/autorise une colonne spécifique d'une
  table. ``allowed_values`` ignoré.
- ``scope_type = "row"`` : filtre par valeurs sur une colonne (ex: comptable
  qui ne voit que ses dossiers ``CodeDossier IN ('D001','D002')``).
  ``allowed_values`` doit être une liste JSON non vide.

**Composition** : un user peut avoir plusieurs règles. La résolution suit
la stratégie **deny wins** (fail-closed) — voir
:func:`app.services.data_access.enforcer.check_sql_access`.

**Pourquoi pas réutiliser ``User.permissions`` (JSON existant)** ?
Le champ JSON est dead-code, plat, et n'a pas la granularité nécessaire
(ligne, audit par règle, ``created_by``). Une table dédiée permet :

- Indexes ciblés (``user_id, table_name``) pour lookup runtime rapide.
- Audit fin (qui a créé la règle, quand).
- Cap par user pour éviter explosion (voir ``MAX_RULES_PER_USER``).
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING, Any, List, Optional

from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.models.base import BaseModel, ensure_utc

if TYPE_CHECKING:
    from app.models.user import User


class DataAccessScope(enum.Enum):
    """Granularité d'une règle d'accès."""

    TABLE = "table"
    COLUMN = "column"
    ROW = "row"


class DataAccessEffect(enum.Enum):
    """Effet d'une règle (allow / deny)."""

    ALLOW = "allow"
    DENY = "deny"


class DataAccessRule(BaseModel):
    """Une règle d'accès aux données BDD pour un utilisateur donné.

    Lecture pratique :

    - ``scope=table, effect=deny, table=F_SALAIRES`` → l'user ne peut pas
      requêter ``F_SALAIRES``.
    - ``scope=column, effect=deny, table=F_PERSONNEL, column=Salaire`` →
      l'user peut requêter ``F_PERSONNEL`` mais pas la colonne ``Salaire``.
    - ``scope=row, effect=allow, table=F_DOSSIER, column=CodeDossier,
      allowed_values=["D001","D002"]`` → injection automatique
      ``WHERE F_DOSSIER.CodeDossier IN ('D001','D002')`` dans toute SQL
      qui touche ``F_DOSSIER``.
    """

    __tablename__ = "data_access_rules"

    # FK utilisateur cible (la règle s'applique à ce user)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Granularité — table | column | row
    scope_type: Mapped[DataAccessScope] = mapped_column(
        SQLEnum(DataAccessScope),
        nullable=False,
    )

    # Nom de la table cible (toujours requis, indépendamment du scope)
    # Cap 128 chars : aligné sur INFORMATION_SCHEMA SQL Server
    table_name: Mapped[str] = mapped_column(String(128), nullable=False)

    # Nom de colonne (requis si scope ∈ {column, row})
    column_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Effet : allow ou deny. Default deny (fail-closed)
    effect: Mapped[DataAccessEffect] = mapped_column(
        SQLEnum(DataAccessEffect),
        default=DataAccessEffect.DENY,
        nullable=False,
    )

    #: Valeurs autorisées pour scope=row (liste JSON). Stockée tel quel.
    #: Validation amont : non-vide, pas de NULL, pas de caractères de quote
    #: non-échappés (le binding via sqlglot params s'occupe du SQL).
    allowed_values: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)

    # Audit : qui a créé la règle (admin)
    created_by: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Annotation libre (justification, contexte) — affichée dans l'UI admin
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # **#139 — Soft-delete pour le toast undo post-delete**. NULL = règle
    # active (visible dans la liste, appliquée à l'enforcement). Non NULL =
    # supprimée logiquement à cette date — filtrée hors de
    # ``list_rules_for_user`` et de ``get_rule`` (sauf demande explicite
    # ``include_deleted=True``, utilisée par l'endpoint /restore qui doit
    # pouvoir relire une règle deleted_at non-NULL pour la restaurer). Le
    # purge physique des rows soft-deleted depuis > 30 jours est délégué à
    # un job cleanup futur (cf. ``db_retention.py`` pattern existant).
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        index=True,
    )

    @property
    def is_deleted(self) -> bool:
        """Helper pour les call-sites : ``deleted_at is not None``."""
        return self.deleted_at is not None

    # Relations
    user: Mapped["User"] = relationship(
        "User",
        back_populates="data_access_rules",
        foreign_keys=[user_id],
    )

    __table_args__ = (
        # Lookup runtime fréquent : "toutes les règles de cet user pour cette table"
        Index("ix_dar_user_table", "user_id", "table_name"),
        # Lookup pour filtrage par granularité ("toutes les denied tables d'un user")
        Index("ix_dar_user_scope", "user_id", "scope_type"),
        # **P0 (#125) — Anti-doublon silencieux.**
        # Empêche un admin de poser 2× la même règle (ex: 2× deny F_SALAIRES
        # sur le même user) — bug latent identifié dans la review brainstorm.
        # La contrainte est sur le tuple "logique" de règle.
        #
        # ATTENTION SQLite : NULL est considéré comme distinct par défaut
        # (2 lignes avec column_name=NULL passent la contrainte). Donc on
        # complète côté applicatif via ``find_duplicate_rule`` dans
        # ``app/services/data_access/repository.py`` qui filtre proprement
        # ``column_name IS NULL`` pour les scope=table.
        UniqueConstraint(
            "user_id",
            "scope_type",
            "table_name",
            "column_name",
            "effect",
            name="uq_dar_user_scope_table_col_effect",
        ),
    )

    def __repr__(self) -> str:
        # Pas de PII : juste les flags. ``allowed_values`` exclu (peut contenir
        # des codes métier sensibles).
        return (
            f"<DataAccessRule(id={self.id}, user_id={self.user_id}, "
            f"scope={self.scope_type.value}, effect={self.effect.value}, "
            f"table={self.table_name!r})>"
        )

    def to_dict(self) -> dict:
        """Sérialise pour API. ``allowed_values`` exposé tel quel — l'UI
        admin a déjà l'autorisation de voir ces valeurs (cf. ``@admin_required``)."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "scope_type": self.scope_type.value,
            "table_name": self.table_name,
            "column_name": self.column_name,
            "effect": self.effect.value,
            "allowed_values": self.allowed_values,
            "created_by": self.created_by,
            "note": self.note,
            "created_at": (ensure_utc(self.created_at).isoformat() if self.created_at else None),
            "updated_at": (ensure_utc(self.updated_at).isoformat() if self.updated_at else None),
        }


# ---------------------------------------------------------------------------
# Validation helpers (côté code applicatif — appelés par repository/handler)
# ---------------------------------------------------------------------------


#: Cap dur du nombre de règles par user (defense vs DoS local et coût mémoire
#: dans le cache enforcer). 1000 est largement au-dessus de tout cas réel.
MAX_RULES_PER_USER: int = 1000

#: Cap dur de la liste ``allowed_values`` pour scope=row. Au-delà,
#: le ``IN (...)`` deviendrait inefficace côté SQL Server (plan d'exécution
#: dégradé) et explosif côté JSON.
MAX_ALLOWED_VALUES: int = 5000


def validate_rule_payload(payload: dict) -> List[str]:
    """Valide la structure d'une règle reçue d'API.

    Retourne une liste d'erreurs (vide = valide). Pas d'exception — les
    handlers décident comment répondre (400 vs 422 vs sanitize+retry).

    Validations effectuées :

    - ``scope_type`` ∈ {"table", "column", "row"}
    - ``effect`` ∈ {"allow", "deny"}
    - ``table_name`` : str non vide, len ≤ 128, pas de caractères douteux
      (le binding aval via sqlglot empêchera l'injection SQL, mais on
      filtre tôt pour clarté)
    - ``column_name`` : requis si scope ∈ {column, row}, len ≤ 128
    - ``allowed_values`` : requis si scope=row, liste non vide ≤
      ``MAX_ALLOWED_VALUES``, éléments str/int/float (pas de None, dict, list)
    - ``note`` : str ≤ 1000 chars (cap mou pour UI)
    """
    errors: List[str] = []
    if not isinstance(payload, dict):
        return ["Le corps de la règle doit être un objet JSON."]

    # scope_type
    scope = payload.get("scope_type")
    if scope not in {"table", "column", "row"}:
        errors.append("scope_type invalide : doit être 'table', 'column' ou 'row'.")

    # effect
    effect = payload.get("effect")
    if effect not in {"allow", "deny"}:
        errors.append("effect invalide : doit être 'allow' ou 'deny'.")

    # ── V1 : effet sémantiquement actif par scope ─────────────────────
    # - scope=table : seul deny est appliqué au runtime (cf. enforcer.py
    #   ``denied_tables``). Un allow sur table est stocké mais ignoré
    #   (commentaire ``enforcer.py`` : "on reste compositionnel, pas de
    #   deny par défaut"). Garder l'option dans le payload = inviter
    #   l'admin à créer des règles inopérantes silencieuses → on rejette.
    # - scope=column : idem, seul deny est appliqué ; allow stocké
    #   uniquement pour future utilisation (``has_any_allow_rule``).
    # - scope=row : seul allow est sémantique (WHERE col IN (...)).
    #   deny non supporté V1 (cf. enforcer.py:285-296).
    if scope == "table" and effect == "allow":
        errors.append(
            "effect='allow' n'est pas appliqué pour scope='table' (V1). "
            "Utilisez deny pour bloquer, ou ne posez pas de règle pour "
            "autoriser par défaut."
        )
    if scope == "column" and effect == "allow":
        errors.append(
            "effect='allow' n'est pas appliqué pour scope='column' (V1). "
            "Utilisez deny pour masquer une colonne, ou ne posez pas de "
            "règle pour autoriser par défaut."
        )
    if scope == "row" and effect == "deny":
        errors.append(
            "effect='deny' n'est pas supporté pour scope='row' (V1). "
            "Utilisez allow avec la liste des valeurs autorisées."
        )

    # table_name
    table = payload.get("table_name")
    if not isinstance(table, str) or not table.strip():
        errors.append("table_name est requis (chaîne non vide).")
    elif len(table) > 128:
        errors.append("table_name trop long (max 128 caractères).")
    elif len(table.strip()) < 3 and effect == "deny":
        # **Phase 2.5.bis.6 follow-up (#115)** — Refuser deny avec nom court.
        # Justification : le scrub mode invisible utilise word-boundary
        # ``\b<name>\b`` (case-insensitive). Sur un nom de 1-2 caractères
        # (par exemple ``deny F`` ou ``deny ID``), le matching produit
        # des faux positifs systématiques sur tout texte LLM contenant
        # ces lettres en mot-entier (« le champ ID », « l'option F »).
        # Conséquence pratique : chaque réponse Iris déclenche un
        # ``DataAccessLeakDetectedError`` → l'user ne peut plus utiliser
        # l'app du tout. Pour Sage Coala (préfixes ``F_``, ``T_``,
        # ``CD_``...) ce cas ne se présente jamais, mais on protège les
        # BDD génériques avec des colonnes mono-lettre.
        errors.append(
            "table_name trop court pour un deny (min 3 caractères). "
            "Un nom de 1-2 caractères produirait des faux positifs sur "
            "tous les mots LLM contenant ces lettres."
        )

    # column_name conditionnel
    column = payload.get("column_name")
    if scope in {"column", "row"}:
        if not isinstance(column, str) or not column.strip():
            errors.append(f"column_name est requis pour scope='{scope}'.")
        elif len(column) > 128:
            errors.append("column_name trop long (max 128 caractères).")
        elif scope == "column" and effect == "deny" and len(column.strip()) < 3:
            # **#115** — Même protection que pour table_name : nom court +
            # deny = faux positifs systématiques dans le scrub LLM.
            errors.append(
                "column_name trop court pour un deny (min 3 caractères). "
                "Un nom de 1-2 caractères produirait des faux positifs sur "
                "tous les mots LLM contenant ces lettres."
            )

    # allowed_values conditionnel
    if scope == "row":
        values = payload.get("allowed_values")
        if not isinstance(values, list) or len(values) == 0:
            errors.append("allowed_values doit être une liste non vide pour scope='row'.")
        elif len(values) > MAX_ALLOWED_VALUES:
            errors.append(
                f"allowed_values dépasse le cap ({len(values)} > " f"{MAX_ALLOWED_VALUES})."
            )
        else:
            for idx, val in enumerate(values):
                if val is None:
                    errors.append(f"allowed_values[{idx}] : NULL interdit.")
                    break
                if not isinstance(val, (str, int, float, bool)):
                    errors.append(
                        f"allowed_values[{idx}] : type invalide " f"(str/int/float attendu)."
                    )
                    break
                if isinstance(val, str) and len(val) > 500:
                    errors.append(f"allowed_values[{idx}] : chaîne trop longue (max 500).")
                    break

    # note (optionnel)
    note = payload.get("note")
    if note is not None:
        if not isinstance(note, str):
            errors.append("note doit être une chaîne.")
        elif len(note) > 1000:
            errors.append("note trop longue (max 1000 caractères).")

    return errors
