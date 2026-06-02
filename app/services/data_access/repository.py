"""CRUD async sur ``DataAccessRule`` — règles d'accès aux données source.

Toutes les fonctions prennent une session SQLAlchemy async explicite (fournie
par ``BaseHandler.db_session()`` ou un wrapper asyncio). Elles N'ENGAGENT PAS
le commit — c'est le caller qui décide (le context manager ``get_session()``
commit en sortie).

**Contrat de validation** : :func:`app.models.data_access_rule.validate_rule_payload`
DOIT être appelé en amont par le handler. Ce repository fait des contrôles
défensifs (longueurs, types) en ceinture-bretelles, mais ne renvoie pas
d'erreurs structurées — il lève ``ValueError`` en cas d'invariant cassé
(symptôme d'un bug applicatif).

**Pattern** : on s'inspire de :mod:`app.services.anonymization.repository`
(state replace + upsert + delete) — voir là-bas pour le rationnel des
choix d'API.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import clock
from app.models.data_access_rule import (
    MAX_ALLOWED_VALUES,
    MAX_RULES_PER_USER,
    DataAccessEffect,
    DataAccessRule,
    DataAccessScope,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Conversion payload (dict API) → ORM kwargs
# ---------------------------------------------------------------------------


def _payload_to_kwargs(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Convertit un dict d'API en kwargs ORM (énums résolues).

    Suppose que ``validate_rule_payload`` a déjà été appelé. Lève
    ``ValueError`` si un champ manquant/invalide est détecté (filet de
    sécurité — ne devrait pas arriver en pratique).
    """
    scope_raw = payload.get("scope_type")
    effect_raw = payload.get("effect")
    try:
        scope = DataAccessScope(scope_raw)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"scope_type invalide : {scope_raw!r}") from exc
    try:
        effect = DataAccessEffect(effect_raw)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"effect invalide : {effect_raw!r}") from exc

    table = payload.get("table_name")
    if not isinstance(table, str) or not table.strip():
        raise ValueError("table_name requis (chaîne non vide).")
    table = table.strip()
    if len(table) > 128:
        raise ValueError("table_name trop long.")

    column = payload.get("column_name")
    if column is not None:
        if not isinstance(column, str):
            raise ValueError("column_name doit être une chaîne.")
        column = column.strip() or None
        if column is not None and len(column) > 128:
            raise ValueError("column_name trop long.")

    if scope in (DataAccessScope.COLUMN, DataAccessScope.ROW) and not column:
        raise ValueError(f"column_name requis pour scope='{scope.value}'.")

    allowed_values = payload.get("allowed_values")
    if scope == DataAccessScope.ROW:
        if not isinstance(allowed_values, list) or not allowed_values:
            raise ValueError("allowed_values doit être une liste non vide pour scope='row'.")
        if len(allowed_values) > MAX_ALLOWED_VALUES:
            raise ValueError(f"allowed_values dépasse le cap ({MAX_ALLOWED_VALUES}).")
    else:
        # Pour table/column on ignore allowed_values
        allowed_values = None

    note = payload.get("note")
    if note is not None and not isinstance(note, str):
        raise ValueError("note doit être une chaîne.")
    if isinstance(note, str):
        note = note.strip() or None
        if note is not None and len(note) > 1000:
            raise ValueError("note trop longue.")

    return {
        "scope_type": scope,
        "table_name": table,
        "column_name": column,
        "effect": effect,
        "allowed_values": allowed_values,
        "note": note,
    }


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


async def list_rules_for_user(
    session: AsyncSession,
    user_id: int,
) -> List[DataAccessRule]:
    """Retourne toutes les règles ACTIVES configurées pour un utilisateur.

    Aucun filtrage des effects : on expose tout (allow + deny). L'enforcer
    compose selon la stratégie deny-wins.

    **#139** — Filtre ``deleted_at IS NULL`` : les règles soft-deleted ne
    sont visibles ni dans la liste admin ni dans l'enforcement runtime
    (pas d'effet sur les SQL). Restauration via ``restore_rule``.
    """
    if user_id is None:
        return []
    stmt = (
        select(DataAccessRule)
        .where(
            DataAccessRule.user_id == user_id,
            DataAccessRule.deleted_at.is_(None),
        )
        .order_by(DataAccessRule.table_name, DataAccessRule.scope_type)
    )
    rows = (await session.scalars(stmt)).all()
    return list(rows)


async def get_rule(
    session: AsyncSession,
    rule_id: int,
    *,
    include_deleted: bool = False,
) -> Optional[DataAccessRule]:
    """Accesseur unitaire — pour les API DELETE/PUT par ID.

    **#139** — Filtre ``deleted_at IS NULL`` par défaut. L'endpoint
    ``POST /api/admin/data-access/rules/{id}/restore`` doit passer
    ``include_deleted=True`` pour récupérer la règle soft-deleted à
    restaurer.
    """
    if rule_id is None:
        return None
    rule = await session.get(DataAccessRule, rule_id)
    if rule is None:
        return None
    if not include_deleted and rule.deleted_at is not None:
        return None
    return rule


async def count_rules_for_user(session: AsyncSession, user_id: int) -> int:
    """Compte les règles ACTIVES d'un utilisateur — pour les guards côté
    handler (cap ``MAX_RULES_PER_USER``).

    **#139** — Filtre ``deleted_at IS NULL`` : une règle soft-deleted ne
    consomme pas le quota. Sinon un admin qui soft-delete puis recrée
    une règle hit le cap deux fois.
    """
    if user_id is None:
        return 0
    from sqlalchemy import func

    stmt = select(func.count(DataAccessRule.id)).where(
        DataAccessRule.user_id == user_id,
        DataAccessRule.deleted_at.is_(None),
    )
    return int((await session.scalar(stmt)) or 0)


async def list_user_ids_with_rules(session: AsyncSession) -> List[int]:
    """Retourne la liste des ``user_id`` qui ont au moins une règle.

    Utilisé par l'invalidation globale du cache enforcer (sur changement
    du flag d'enforcement, par exemple).
    """
    stmt = select(DataAccessRule.user_id).distinct()
    rows = (await session.scalars(stmt)).all()
    return [int(r) for r in rows]


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------


class DuplicateRuleError(ValueError):
    """**P0 (#125)** — Levée par :func:`create_rule` quand une règle
    identique existe déjà pour cet user (même ``user_id`` + ``scope_type``
    + ``table_name`` + ``column_name`` + ``effect``).

    Sous-classe de ``ValueError`` pour rester compatible avec le caller
    handler qui catche déjà ``ValueError`` → 422. Le handler peut
    isinstance-checker pour retourner 409 Conflict avec message dédié.
    """


async def _find_duplicate_rule(
    session: AsyncSession,
    user_id: int,
    scope_type: DataAccessScope,
    table_name: str,
    column_name: Optional[str],
    effect: DataAccessEffect,
) -> Optional[DataAccessRule]:
    """**P0 (#125)** — Cherche une règle existante ACTIVE avec le même
    tuple logique. Filtre correctement ``column_name IS NULL`` (que
    SQLite considère comme NULL=distinct par défaut dans une UNIQUE).

    **#139** — Filtre ``deleted_at IS NULL`` : une règle soft-deleted ne
    bloque PAS la création d'une nouvelle identique. L'admin qui a
    cliqué Delete puis veut immédiatement la recréer ne doit pas voir
    409. Compromis : si l'admin clique ensuite Annuler dans la fenêtre
    toast 8s, le ``restore_rule`` peut violer l'UNIQUE constraint BDD
    (le caller doit catch IntegrityError → 409 actionable).
    """
    stmt = select(DataAccessRule).where(
        DataAccessRule.user_id == user_id,
        DataAccessRule.scope_type == scope_type,
        DataAccessRule.table_name == table_name,
        DataAccessRule.effect == effect,
        DataAccessRule.deleted_at.is_(None),
    )
    if column_name is None:
        stmt = stmt.where(DataAccessRule.column_name.is_(None))
    else:
        stmt = stmt.where(DataAccessRule.column_name == column_name)
    result = await session.execute(stmt.limit(1))
    return result.scalar_one_or_none()


async def create_rule(
    session: AsyncSession,
    user_id: int,
    payload: Dict[str, Any],
    created_by: Optional[int],
) -> DataAccessRule:
    """Crée une règle pour un utilisateur.

    Lève ``ValueError`` si le payload est invalide (filet de sécurité —
    le handler doit avoir validé en amont via ``validate_rule_payload``).

    Vérifie le cap ``MAX_RULES_PER_USER`` AVANT insertion. Lève ``ValueError``
    si dépassé (le handler doit traduire en 422).

    **P0 (#125)** — Lève :class:`DuplicateRuleError` si une règle avec
    le même tuple logique (``user_id``, ``scope_type``, ``table_name``,
    ``column_name``, ``effect``) existe déjà. Defense-in-depth en
    complément de l'UniqueConstraint BDD (qui ne couvre pas le cas
    ``column_name=NULL`` sur SQLite, cf. commentaire du modèle).
    """
    if user_id is None:
        raise ValueError("user_id requis.")

    current_count = await count_rules_for_user(session, user_id)
    if current_count >= MAX_RULES_PER_USER:
        raise ValueError(
            f"L'utilisateur a atteint le cap de règles "
            f"({MAX_RULES_PER_USER}). Supprimez-en avant d'en créer."
        )

    kwargs = _payload_to_kwargs(payload)

    # **P0 (#125)** — Anti-doublon applicatif.
    existing = await _find_duplicate_rule(
        session,
        user_id=user_id,
        scope_type=kwargs["scope_type"],
        table_name=kwargs["table_name"],
        column_name=kwargs["column_name"],
        effect=kwargs["effect"],
    )
    if existing is not None:
        raise DuplicateRuleError(
            f"Une règle identique existe déjà (id={existing.id}). "
            f"Modifie-la au lieu d'en créer une nouvelle, ou supprime-la "
            f"d'abord."
        )

    rule = DataAccessRule(
        user_id=user_id,
        created_by=created_by,
        **kwargs,
    )
    session.add(rule)
    await session.flush()  # populate rule.id
    logger.info(
        "data_access rule created: id=%s user_id=%s scope=%s table=%s effect=%s",
        rule.id,
        user_id,
        rule.scope_type.value,
        rule.table_name,
        rule.effect.value,
    )
    return rule


async def update_rule(
    session: AsyncSession,
    rule_id: int,
    payload: Dict[str, Any],
) -> Optional[DataAccessRule]:
    """Met à jour les champs mutables d'une règle.

    Retourne la règle mise à jour ou ``None`` si l'ID n'existe pas.
    Le ``user_id`` n'est PAS mutable — pour déplacer une règle, il faut
    la supprimer et en recréer une.
    """
    rule = await get_rule(session, rule_id)
    if rule is None:
        return None

    kwargs = _payload_to_kwargs(payload)
    rule.scope_type = kwargs["scope_type"]
    rule.table_name = kwargs["table_name"]
    rule.column_name = kwargs["column_name"]
    rule.effect = kwargs["effect"]
    rule.allowed_values = kwargs["allowed_values"]
    rule.note = kwargs["note"]
    await session.flush()
    return rule


async def delete_rule(session: AsyncSession, rule_id: int) -> bool:
    """**#139 — Soft-delete d'une règle.** Set ``deleted_at = NOW()``.

    Retourne ``True`` si soft-supprimée (la règle existait et était
    active), ``False`` si l'ID n'existait pas OU était déjà
    soft-supprimée (idempotent).

    Le hard-delete (purge physique) est délégué à un job cleanup futur
    pour les rows ``deleted_at < NOW() - 30j`` (cf. pattern
    ``db_retention.py``). En attendant, les rows soft-deleted restent
    en BDD mais filtrées hors de toutes les queries de lecture.

    Implémentation via ORM mutation (``rule.deleted_at = now``) plutôt
    que ``sa_update`` direct pour préserver la cohérence de l'identity
    map — sinon le caller qui re-lit ``get_rule(rid)`` après commit
    voit la version cached pré-update (vécu lors des tests #139).
    """
    if rule_id is None:
        return False
    rule = await session.get(DataAccessRule, rule_id)
    if rule is None or rule.deleted_at is not None:
        return False
    rule.deleted_at = clock.now()
    await session.flush()
    return True


async def restore_rule(session: AsyncSession, rule_id: int) -> Optional[DataAccessRule]:
    """**#139 — Restauration d'une règle soft-deleted.** Set
    ``deleted_at = NULL``.

    Retourne la règle restaurée, ou ``None`` si :
    - L'ID n'existe pas (jamais créée OU hard-deleted par cleanup).
    - La règle est déjà active (``deleted_at IS NULL``) — idempotent.

    **Conflit unique** : si une règle identique a été créée après le
    soft-delete (admin clique Annuler 8s plus tard mais entre-temps a
    recréé la même règle), la restauration peut violer
    ``uq_dar_user_scope_table_col_effect``. Le caller doit gérer
    l'``IntegrityError`` → 409 Conflict avec message admin-actionnable
    ("Une règle identique a été créée entre-temps").
    """
    if rule_id is None:
        return None
    rule = await session.get(DataAccessRule, rule_id)
    if rule is None or rule.deleted_at is None:
        return None
    rule.deleted_at = None
    await session.flush()
    return rule


async def delete_all_rules_for_user(
    session: AsyncSession,
    user_id: int,
) -> int:
    """Supprime toutes les règles d'un utilisateur. Retourne le compte."""
    if user_id is None:
        return 0
    stmt = delete(DataAccessRule).where(DataAccessRule.user_id == user_id)
    result = await session.execute(stmt)
    return result.rowcount or 0


def _serialize_rule_for_audit(rule: DataAccessRule) -> Dict[str, Any]:
    """Sérialise une règle pour le snapshot audit pre-replace.

    Cible : reconstruction manuelle de toutes les règles d'un user après
    un bulk replace. Inclut tous les champs métier (sauf clés techniques
    type ``created_at`` qui ne servent pas à reconstruire la sémantique).
    """
    return {
        "id": rule.id,
        "scope_type": rule.scope_type.value if rule.scope_type else None,
        "table_name": rule.table_name,
        "column_name": rule.column_name,
        "effect": rule.effect.value if rule.effect else None,
        "allowed_values": rule.allowed_values,
        "note": rule.note,
        "deleted_at": rule.deleted_at.isoformat() if rule.deleted_at else None,
    }


async def replace_rules_for_user(
    session: AsyncSession,
    user_id: int,
    rules: Iterable[Dict[str, Any]],
    created_by: Optional[int],
) -> Dict[str, int]:
    """Remplace toutes les règles d'un utilisateur (delete + bulk insert).

    Usage : ``PUT /api/admin/data-access/users/{user_id}/rules`` après
    édition de l'admin.

    Atomique : si un payload est invalide, **rien** n'est écrit (la session
    sera roll-back par le caller). Vérifie le cap ``MAX_RULES_PER_USER``
    AVANT le delete pour éviter de supprimer puis échouer.

    Bug 2026-05-26 (Agent 4 DA-C2 critique) : avant le fix, ``DELETE FROM``
    hard-supprimait les règles incompatible avec ``restore_rule`` (mécanique
    undo 8s #139). L'admin perdait DÉFINITIVEMENT toutes ses règles passées.
    Fix : avant le hard-delete, poser un snapshot JSON COMPLET dans
    ``audit_logs.details`` (``action="data_access.bulk_replace"``) pour
    permettre la reconstruction manuelle. L'undo 8s n'est pas restauré
    sur bulk (incompatible UNIQUE constraint qui ignore deleted_at) mais
    l'historique est désormais reconstructible.

    Retourne un dict : ``{deleted, inserted, snapshot_audit_id}``.
    """
    rules_list = list(rules or [])
    if len(rules_list) > MAX_RULES_PER_USER:
        raise ValueError(f"Trop de règles ({len(rules_list)} > {MAX_RULES_PER_USER}).")

    # Pré-valider tous les payloads avant le delete (atomicité)
    kwargs_list = [_payload_to_kwargs(p) for p in rules_list]

    # Bug DA-C2 : snapshot audit AVANT le hard-delete (sinon rollback en
    # cas d'erreur du flush ne remet pas l'audit). On charge TOUTES les
    # règles de cet user (actives + soft-deleted) pour reconstruction
    # complète. Le job cleanup TTL 30j (db_retention.py) finira par purger
    # les rows audit obsolètes — c'est OK car le snapshot vit dans
    # audit_logs.details (Text/JSON) qui a sa propre rétention.
    import json as _json
    from app.models.audit import AuditLog

    snapshot_q = await session.execute(
        select(DataAccessRule).where(DataAccessRule.user_id == user_id)
    )
    existing_rules = list(snapshot_q.scalars().all())
    snapshot = {
        "action": "data_access.bulk_replace",
        "user_id": user_id,
        "replaced_at": clock.now().isoformat(),
        "rules_before": [_serialize_rule_for_audit(r) for r in existing_rules],
    }
    audit_row = AuditLog(
        user_id=created_by,
        action="data_access.bulk_replace",
        entity_type="user",
        entity_id=user_id,
        details=_json.dumps(snapshot, ensure_ascii=False),
    )
    session.add(audit_row)
    await session.flush()  # garantit que l'audit a un id avant le delete
    snapshot_audit_id = audit_row.id

    deleted = await delete_all_rules_for_user(session, user_id)

    inserted = 0
    for kwargs in kwargs_list:
        session.add(
            DataAccessRule(
                user_id=user_id,
                created_by=created_by,
                **kwargs,
            )
        )
        inserted += 1
    await session.flush()

    logger.info(
        "data_access rules replaced: user_id=%s deleted=%d inserted=%d " "by=%s audit_id=%s",
        user_id,
        deleted,
        inserted,
        created_by,
        snapshot_audit_id,
    )
    return {
        "deleted": deleted,
        "inserted": inserted,
        "snapshot_audit_id": snapshot_audit_id,
    }
