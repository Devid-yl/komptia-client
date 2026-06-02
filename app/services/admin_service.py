"""Service d'administration — invariants, transitions d'état et opérations atomiques.

Centralise les règles métier des mutations d'utilisateurs (create, update, delete,
soft-delete) appelées par :mod:`app.handlers.admin`. Les handlers doivent rester
fins : parser la requête, déléguer au service, formater la réponse.

Garanties fournies ici (et rien dans le handler) :

- **Invariant "au moins un administrateur actif"** — Vérifié AVANT toute mutation
  qui retire un admin (demote rôle, passage ``is_active=False``, hard-delete).
- **Révocation de sessions** — Toute perte de privilège (demote, désactivation,
  suppression) invalide atomiquement les sessions actives de la cible pour
  couper les cookies encore valides côté client.
- **Unicité username / email** — Exposée via :class:`UsernameExistsError` /
  :class:`EmailExistsError`. Le handler n'a PAS besoin de matcher des chaînes
  dans ``str(exception)``.

Limitation connue (SQLite) : SQLite ne supporte pas ``SELECT ... FOR UPDATE``.
La fenêtre TOCTOU est réduite en enchaînant l'invariant et la mutation dans la
même transaction mais pas éliminée. Sur une vraie BDD (Postgres, MySQL), la
fenêtre peut être fermée en wrappant la transaction via
``async with session.begin():`` + ``SELECT ... FOR UPDATE`` sur les admins.
"""

from __future__ import annotations

from typing import Literal

from sqlalchemy import Column, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import KomptiaError
from app.models.contact import Contact, DistributionList
from app.models.session import Session as SessionModel
from app.models.user import User, UserRole
from app.utils.logger import get_logger

logger = get_logger(__name__)

__all__ = [
    "AdminError",
    "UsernameExistsError",
    "EmailExistsError",
    "LastAdminError",
    "count_other_active_admins",
    "ensure_not_last_admin",
    "revoke_user_sessions",
    "purge_user_owned_data",
    "active_user_count",
]


AdminOperation = Literal["demote", "deactivate", "delete"]


# ---------------------------------------------------------------------------
# Exceptions métier (le handler les mappe sur HTTP via ``http_status``)
# ---------------------------------------------------------------------------


class AdminError(KomptiaError):
    """Tronc : erreurs d'opération administrateur sur des utilisateurs."""

    default_code = "ADMIN_ERROR"
    http_status = 400


class UsernameExistsError(AdminError):
    """Le nom d'utilisateur est déjà pris par un autre compte."""

    default_code = "ADMIN_USERNAME_EXISTS"
    http_status = 409


class EmailExistsError(AdminError):
    """L'email est déjà utilisé par un autre compte."""

    default_code = "ADMIN_EMAIL_EXISTS"
    http_status = 409


class LastAdminError(AdminError):
    """La mutation demandée laisserait le système sans administrateur actif.

    Bloque les 4 transitions à risque : demote de rôle, passage inactif, hard-delete,
    et soft-delete d'un compte admin actif.
    """

    default_code = "ADMIN_LAST_ADMIN_GUARD"
    http_status = 400


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------


async def count_other_active_admins(session: AsyncSession, *, exclude_user_id: int) -> int:
    """Compte les admins actifs en excluant ``exclude_user_id``.

    ``>= 1`` → la mutation sur la cible est sûre (il restera un admin).
    ``== 0`` → la mutation retire le dernier administrateur et doit être refusée.
    """
    result = await session.execute(
        select(func.count())
        .select_from(User)
        .where(
            User.role == UserRole.ADMIN,
            User.is_active.is_(True),
            User.id != exclude_user_id,
        )
    )
    return int(result.scalar() or 0)


async def ensure_not_last_admin(
    session: AsyncSession,
    *,
    target_user_id: int,
    operation: AdminOperation,
) -> None:
    """Lève :class:`LastAdminError` si la mutation laisserait 0 admin actif.

    Doit être appelé dans la même transaction que la mutation. Sur SQLite la
    fenêtre TOCTOU n'est pas fermable (pas de ``SELECT FOR UPDATE``) — deux
    admins peuvent théoriquement passer le check puis se couper mutuellement.
    Mitigation : les handlers enchaînent check + mutation sans ``await``
    long-courrier intercalé, ce qui réduit la fenêtre au temps d'un round-trip
    SQLite (ms). Sur Postgres, upgrader en posant un lock.
    """
    remaining = await count_other_active_admins(session, exclude_user_id=target_user_id)
    if remaining < 1:
        raise LastAdminError(
            "Impossible : il s'agit du dernier administrateur actif.",
            context={"target_user_id": target_user_id, "operation": operation},
        )


async def revoke_user_sessions(session: AsyncSession, user_id: int) -> int:
    """Invalide toutes les sessions actives d'un utilisateur.

    Appelé quand un utilisateur perd un privilège (demote, désactivation,
    suppression) pour que les cookies encore valides ne puissent plus être
    utilisés. Retourne le nombre de sessions effectivement révoquées.
    """
    result = await session.execute(
        update(SessionModel)
        .where(
            SessionModel.user_id == user_id,
            SessionModel.is_active.is_(True),
        )
        .values(is_active=False)
    )
    return int(result.rowcount or 0)


def _user_attribution_setnull_columns() -> list[Column]:
    """Colonnes FK → ``users.id`` déclarées ``ondelete=SET NULL`` (attributions).

    Introspection DYNAMIQUE du metadata SQLAlchemy : auto-suit toute nouvelle FK
    ``SET NULL`` vers ``users`` ajoutée à un modèle (cf. audit RGPD 10a,
    ``test_rgpd_user_cascade_audit``). Pas de liste codée en dur → un futur
    ``created_by`` / ``triggered_by`` est couvert sans toucher ce helper.
    """
    cols: list[Column] = []
    for table in User.metadata.tables.values():
        for fk in table.foreign_keys:
            if fk.column.table.name != "users":
                continue
            if (fk.ondelete or "").upper() == "SET NULL":
                cols.append(fk.parent)
    return cols


async def purge_user_owned_data(session: AsyncSession, user_id: int) -> None:
    """Nettoie les données rattachées à un user AVANT son hard-delete.

    Sous ``PRAGMA foreign_keys=ON`` (cf. ``app/core/database.py``),
    ``session.delete(user)`` lèverait une ``IntegrityError`` sur toute FK enfant
    en RESTRICT. Deux familles, traitées selon l'intention déclarée du modèle :

    * **user-owned NOT NULL** (``Contact`` / ``DistributionList``) → hard-delete
      (RGPD art.17 : la donnée disparaît avec l'user). Ces FK déclarent
      ``ondelete=CASCADE`` depuis 10a → le delete explicite est redondant sur une
      BDD fraîche mais **nécessaire** sur une BDD antérieure (SQLite ne ré-écrit
      pas une contrainte FK sans rebuild de table).
    * **attributions** (``created_by`` / ``triggered_by`` …) → ``SET NULL`` : la
      donnée partagée (glossaire, training, historique de sync) survit, on perd
      seulement l'auteur. Nullées ici de façon **dynamique** (introspection des
      FK ``SET NULL`` via :func:`_user_attribution_setnull_columns`) → couvre les
      BDD antérieures à 10a dont ces FK sont encore en RESTRICT.

    Les autres relations user-owned (sessions, automations, conversations,
    preferences…) sont couvertes par la cascade ORM ``delete-orphan`` portée par
    ``User`` lors du ``session.delete`` → inutile de les traiter ici.

    **Async-safe** : Core ``delete``/``update`` (zéro lazy-load). Idempotent.
    À appeler dans la MÊME transaction que le ``session.delete`` (aucun commit
    ici → atomicité réelle gérée par le caller).

    **Perf** : ~1 UPDATE par FK ``SET NULL`` (≈ une douzaine). La suppression
    d'un user est une opération admin RARE, et les lignes DOIVENT être nullées
    de toute façon (par l'app ici, ou par le SET NULL DB au delete) → pas de
    volume d'écriture supplémentaire, seulement les ``WHERE col = uid`` (indexés
    pour les colonnes FK indexées). Sur un bulk delete de N users : ~12·N UPDATE,
    acceptable pour un batch admin (à optimiser via introspection du schéma live
    si un jour la flotte supprime des users en masse).
    """
    # 1. user-owned hard data (FK NOT NULL) — supprimé.
    await session.execute(delete(Contact).where(Contact.user_id == user_id))
    await session.execute(delete(DistributionList).where(DistributionList.user_id == user_id))
    # 2. attributions (FK SET NULL) — nullées dynamiquement (defense-in-depth
    #    + couverture des BDD pré-10a encore en RESTRICT sur ces colonnes).
    for col in _user_attribution_setnull_columns():
        await session.execute(update(col.table).where(col == user_id).values({col.key: None}))


async def active_user_count(session: AsyncSession) -> int:
    """Nombre d'utilisateurs actifs — sert au contrôle de ``max_users``."""
    result = await session.execute(
        select(func.count()).select_from(User).where(User.is_active.is_(True))
    )
    return int(result.scalar() or 0)


async def count_basic_user_stats(session: AsyncSession) -> dict[str, int]:
    """Compteurs utilisateurs « basiques » — SSoT pour les dashboards.

    Retourne ``{total, active, admins}`` calculé en 3 ``SELECT COUNT(*)``
    UTILISÉS PARTOUT (admin home banner KPI, dashboard admin stats).

    Bug 2026-05-26 (Agent 2 brainstorm F1 critique) : avant ce helper,
    ``app/handlers/admin.py`` et ``app/services/dashboard/admin_stats.py``
    recalculaient ``total_users`` indépendamment avec deux requêtes
    légèrement différentes — risque de drift quand on ajoute un filtre
    (``is_user_call``, ``deleted_at``, etc.).

    Maintenant les deux sites consomment ce helper → cohérence garantie.
    """
    total = (
        await session.execute(select(func.count()).select_from(User))
    ).scalar() or 0
    active = (
        await session.execute(
            select(func.count()).select_from(User).where(User.is_active.is_(True))
        )
    ).scalar() or 0
    admins = (
        await session.execute(
            select(func.count()).select_from(User).where(User.role == UserRole.ADMIN)
        )
    ).scalar() or 0
    return {
        "total": int(total),
        "active": int(active),
        "admins": int(admins),
    }
