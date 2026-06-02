"""Lifecycle d'une Conversation Iris — source de vérité unique.

**Invariant** : au plus 1 ``Conversation(is_active=True)`` par ``user_id``.
- ``IrisClearAPIHandler`` soft-delete (UPDATE is_active=False) toutes les
  actives quand l'user clique « Effacer ».
- ``_rehydrate_conversation`` rehydrate avec ``LIMIT 1 ORDER BY updated_at DESC``
  → si l'invariant est violé (anomalie BDD), prend la plus récente, perd les
  autres silencieusement.

**Avant ce module** : deux call sites créaient des conv sans réutiliser
l'active existante, accumulant des orphelins :
- ``IrisAgent._get_or_create_conversation`` (agent_service.py) — appelée à
  chaque message si l'agent est invoqué sans conv_id (rare en pratique car
  ``IrisPageHandler.get`` rehydrate l'id).
- ``IrisWebSocketHandler._run_agent`` (iris.py) — pré-création pour avoir
  un id stable avant le 1er event persisté (Solution B). À chaque reconnect
  WS sans conv_id, créait une nouvelle.

**Après** : ces 2 sites appellent ``get_or_create_active_conversation`` qui
réutilise l'active si elle existe (le cas commun) et crée seulement si
nécessaire. Plus d'orphelins, plus de duplication.

Cf. adversarial review BLOCKING #4 (multiples actives) + #9 (orphelin si
crash avant le 1er event — résolu en réutilisant la conv pré-créée).
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.database import get_session
from app.models.conversation import Conversation, ConversationSource
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def get_or_create_active_conversation(
    user_id: int,
    agent_role: str = "iris",
    source: str = ConversationSource.PAGE.value,
) -> Optional[int]:
    """Retourne l'id de la conv active de l'user pour ce rôle+source, ou en crée une.

    Args:
        user_id : id de l'utilisateur (FK)
        agent_role : rôle de l'agent (défaut ``"iris"``). **Inclus dans le
            scope de recherche** : on ne réutilise PAS une conv d'un autre
            rôle. Si l'user a une vieille conv ``sql_expert`` active (rôle
            d'avant le rebranding 2026-04-10) et appelle ce SSOT pour
            ``"iris"``, on crée une nouvelle conv ``iris`` plutôt que de
            polluer/écraser la sql_expert. Cf. incident 2026-05-10 où
            une vieille conv ``sql_expert`` "expert comptable" pouvait
            être servie au lieu d'une conv ``iris`` plus récente.
        source : entry point d'origine (cf. enum :class:`ConversationSource`).
            **Inclus dans le scope de recherche** au même titre qu'``agent_role`` :
            la page ``/iris`` et le floating widget ont chacun leur conv
            indépendante. Sans ce filtre, le widget polluait la conv de la
            page (bug 2026-05-21). Défaut ``page`` pour rétrocompat — les
            callers historiques sans param n'ont jamais été le widget.

    Returns:
        ``int`` id de la conv (existante ou nouvelle), ou ``None`` si la
        BDD est down (fail-soft : caller décide quoi faire).

    Note : si plusieurs conv ``is_active=True`` existent pour ce
    ``(user, agent_role, source)`` (anomalie d'une session pré-fix
    BLOCKING #4), retourne la plus récente. Les autres restent en BDD
    mais seront purgées au prochain « Effacer » (qui scope par source).
    """
    try:
        async with get_session() as session:
            stmt = (
                select(Conversation)
                .where(
                    Conversation.user_id == user_id,
                    Conversation.is_active.is_(True),
                    Conversation.agent_role == agent_role,
                    Conversation.source == source,
                )
                .order_by(Conversation.updated_at.desc())
                .limit(1)
            )
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()
            if existing is not None:
                return existing.id

            # Aucune active : créer
            new_conv = Conversation(
                user_id=user_id,
                agent_role=agent_role,
                source=source,
                is_active=True,
                message_count=0,
                total_tokens=0,
            )
            session.add(new_conv)
            try:
                await session.commit()
            except IntegrityError:
                # Race TOCTOU : un autre call concurrent (autre WS du
                # même user) a inséré une conv pour le même scope entre
                # notre SELECT et notre INSERT. Le partial unique index
                # ``uq_conversations_active_scope`` (cf. modèle) lève
                # ``IntegrityError`` côté BDD. On rollback et re-SELECT
                # pour récupérer la conv du winner — sans cela, la promesse
                # « 1 active par (user, role, source) » serait un vœu pieux
                # (cf. adversarial #1 du 2026-05-21 sur fix #22).
                await session.rollback()
                retry_result = await session.execute(stmt)
                winner = retry_result.scalar_one_or_none()
                if winner is not None:
                    logger.info(
                        "Conversation race resolved (winner=%d) " "user_id=%s role=%s source=%s",
                        winner.id,
                        user_id,
                        agent_role,
                        source,
                    )
                    return winner.id
                # Edge case : l'IntegrityError n'est pas due au scope
                # (autre contrainte ?), ou la conv winner a été supprimée
                # entre le rollback et le re-SELECT. On re-lève pour
                # tomber dans le except global qui retourne None (fail-soft).
                raise
            await session.refresh(new_conv)
            logger.info(
                "Conversation created: id=%d user_id=%s role=%s source=%s",
                new_conv.id,
                user_id,
                agent_role,
                source,
            )
            return new_conv.id
    except Exception as exc:  # noqa: BLE001 — fail-soft
        logger.warning(
            "get_or_create_active_conversation failed (user=%s source=%s): %s",
            user_id,
            source,
            exc,
        )
        return None


async def assert_conversation_owned_by_user(
    conversation_id: int,
    user_id: int,
    expected_source: Optional[str] = None,
) -> bool:
    """Vérifie qu'une conversation appartient bien à l'utilisateur — et
    optionnellement qu'elle provient bien de l'entry point déclaré.

    Defense-in-depth : utilisable depuis le handler WS AVANT d'instancier
    le persister (cf. adversarial review BLOCKING #6 — TOCTOU IDOR).
    L'agent vérifie aussi en aval, mais reposer 100% sur l'aval = brèche
    silencieuse au prochain refactor.

    Args:
        expected_source: si fourni, fail-close aussi quand
            ``conv.source != expected_source``. Sans ce check, un client
            widget pouvait envoyer un conversation_id ``page`` (ou
            inversement) et écrire dans la conv de l'autre entry point
            — exactement le bug que ``fix #22`` était censé fermer
            (cf. adversarial #4 du 2026-05-21).

    Returns:
        True si la conv existe, ``conv.user_id == user_id`` ET (si
        ``expected_source`` est fourni) ``conv.source == expected_source``.
        False sinon (conv inexistante OU not owned OU source mismatch OU
        BDD error).
    """
    if conversation_id is None or user_id is None:
        return False
    try:
        async with get_session() as session:
            stmt = (
                select(Conversation.user_id, Conversation.source)
                .where(Conversation.id == conversation_id)
                .limit(1)
            )
            result = await session.execute(stmt)
            row = result.first()
            if row is None:
                return False
            owner_id, source_value = row
            if owner_id != user_id:
                return False
            if expected_source is not None and source_value != expected_source:
                return False
            return True
    except Exception as exc:  # noqa: BLE001 — fail-closed (return False)
        logger.warning(
            "assert_conversation_owned_by_user failed (conv=%s user=%s " "expected_source=%s): %s",
            conversation_id,
            user_id,
            expected_source,
            exc,
        )
        return False
