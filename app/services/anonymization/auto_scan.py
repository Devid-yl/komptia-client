"""Hooks d'auto-scan pour alimenter ``anonymization_terms`` en continu.

Doctrine "dès qu'ils sont là il faut scanner" (David 2026-05-20) : un
dashboard / une automation / un message Iris créé ou modifié doit
immédiatement alimenter ``anonymization_terms`` sans attendre que
l'utilisateur clique sur "Scanner mes données" depuis ``/data/privacy``.

Single fire-and-forget hook : ouvre sa propre session async (pas
partagée avec le caller, qui peut être un handler HTTP déjà en train
de commit), appelle le scanner approprié, commit. Les erreurs sont
loggées mais jamais propagées au caller (le user ne doit pas voir un
500 parce que le scan d'anonymisation a échoué).

Pattern : caller appelle ``schedule_target_rescan(user_id, kind, target_id)``
APRÈS son propre commit. Le scan se déroule en arrière-plan via
``asyncio.create_task``.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.services.anonymization.user_id_guard import is_valid_user_id

logger = logging.getLogger(__name__)

# Strong-refs des tasks de rescan fire-and-forget. Les callers de
# schedule_target_rescan / schedule_iris_messages_rescan jettent la task
# retournée → sans ce set, Python 3.12+ (asyncio ne garde qu'une WeakSet) peut
# GC la task AVANT le rescan PII → état d'anonymisation périmé silencieusement.
# Cf. mémoire feedback_asyncio_create_task_strong_ref + pattern _audit_tasks.
_rescan_tasks: set = set()


async def _rescan_dashboard(user_id: int, dashboard_id: int) -> None:
    """Scanne un dashboard et upsert ses tokens. Best-effort silencieux."""
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.core.database import get_session
    from app.models.dashboard import Dashboard, DashboardSchedule
    from app.services.anonymization.api_service import scan_dashboard_terms

    try:
        async with get_session() as session:
            result = await session.execute(
                select(Dashboard)
                .where(Dashboard.id == dashboard_id)
                .where(Dashboard.user_id == user_id)
                .options(
                    selectinload(Dashboard.widgets),
                    selectinload(Dashboard.filters),
                )
            )
            dash = result.scalar_one_or_none()
            if dash is None or dash.is_template:
                return

            sched_result = await session.execute(
                select(DashboardSchedule).where(DashboardSchedule.dashboard_id == dashboard_id)
            )
            schedules = list(sched_result.scalars().all())

            payload = {
                "id": dash.id,
                "name": getattr(dash, "name", None),
                "description": getattr(dash, "description", None),
                "template_description": getattr(dash, "template_description", None),
                "is_template": False,
                "widgets": [
                    {
                        "id": w.id,
                        "title": getattr(w, "title", None),
                        "data_source_config": getattr(w, "data_source_config", None),
                    }
                    for w in (dash.widgets or [])
                ],
                "filters": [
                    {
                        "id": f.id,
                        "label": getattr(f, "label", None),
                        "values_source": getattr(f, "values_source", None),
                        "values_config": getattr(f, "values_config", None),
                    }
                    for f in (dash.filters or [])
                ],
                "schedules": [
                    {
                        "id": s.id,
                        "subject": getattr(s, "subject", None),
                        "message": getattr(s, "message", None),
                        "recipients": getattr(s, "recipients", None),
                    }
                    for s in schedules
                ],
            }
            await scan_dashboard_terms(session, user_id=user_id, dashboard=payload)
            await session.commit()
    except Exception:  # noqa: BLE001 — fire-and-forget, jamais propager
        logger.warning(
            "auto_scan dashboard user=%s id=%s : échec silencieux",
            user_id,
            dashboard_id,
            exc_info=True,
        )


async def _rescan_automation(user_id: int, automation_id: int) -> None:
    """Scanne une automation et upsert ses tokens. Best-effort silencieux."""
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.core.database import get_session
    from app.models.automation import Automation
    from app.models.automation_step import AutomationStep
    from app.services.anonymization.api_service import scan_automation_terms

    try:
        async with get_session() as session:
            result = await session.execute(
                select(Automation)
                .where(Automation.id == automation_id)
                .where(Automation.user_id == user_id)
                .options(selectinload(Automation.steps))
            )
            auto = result.scalar_one_or_none()
            if auto is None:
                return

            steps_result = await session.execute(
                select(AutomationStep)
                .where(AutomationStep.automation_id == automation_id)
                .order_by(AutomationStep.step_order)
            )
            steps = list(steps_result.scalars().all())

            payload = {
                "id": auto.id,
                "name": getattr(auto, "name", None),
                "description": getattr(auto, "description", None),
                "query_text": getattr(auto, "query_text", None),
                "query_type": getattr(auto, "query_type", None),
                "recipients": getattr(auto, "recipients", None),
                "notification_emails": getattr(auto, "notification_emails", None),
                "steps": [
                    {
                        "id": s.id,
                        "name": getattr(s, "name", None),
                        "config": getattr(s, "config", None),
                    }
                    for s in steps
                ],
            }
            await scan_automation_terms(session, user_id=user_id, automation=payload)
            await session.commit()
    except Exception:  # noqa: BLE001
        logger.warning(
            "auto_scan automation user=%s id=%s : échec silencieux",
            user_id,
            automation_id,
            exc_info=True,
        )


async def _rescan_iris_message(user_id: int, message_id: int) -> None:
    """Scanne un message Iris persisté (tool_result SQL) et upsert ses tokens.

    Appelé en hook après le commit d'un ``ConversationMessage`` avec
    ``tool_result`` non-null. Parse le JSON, extrait ``rows``, délègue
    à ``scan_sql_result_terms``. Best-effort silencieux.

    Defense-in-depth ownership : le message_id doit appartenir à
    ``user_id`` via sa Conversation (cross-user check). Sinon le scan
    serait un vecteur de leak."""
    import json

    from sqlalchemy import select

    from app.core.database import get_session
    from app.models.conversation import Conversation, ConversationMessage
    from app.services.anonymization.api_service import scan_sql_result_terms

    try:
        async with get_session() as session:
            # user_id vit sur Conversation, pas ConversationMessage — JOIN
            # défensif pour interdire le scan d'un message d'un autre user.
            result = await session.execute(
                select(ConversationMessage)
                .join(Conversation, ConversationMessage.conversation_id == Conversation.id)
                .where(ConversationMessage.id == message_id)
                .where(Conversation.user_id == user_id)
            )
            msg = result.scalar_one_or_none()
            if msg is None or not msg.tool_result:
                return

            try:
                parsed = json.loads(msg.tool_result)
            except (json.JSONDecodeError, ValueError):
                return
            if not isinstance(parsed, dict):
                return

            rows_raw = parsed.get("rows")
            cols_raw = parsed.get("columns")
            if not isinstance(rows_raw, list):
                return
            rows = [r for r in rows_raw if isinstance(r, dict)]
            if not rows:
                return
            columns = (
                [str(c) for c in cols_raw if c is not None] if isinstance(cols_raw, list) else None
            )

            conv_id = getattr(msg, "conversation_id", None)
            if conv_id is None:
                return
            source_ref = f"iris:{conv_id}"

            await scan_sql_result_terms(
                session,
                user_id=user_id,
                rows=rows,
                columns=columns,
                source_ref=source_ref,
            )
            await session.commit()
    except Exception:  # noqa: BLE001
        logger.warning(
            "auto_scan iris_message user=%s id=%s : échec silencieux",
            user_id,
            message_id,
            exc_info=True,
        )


async def _rescan_iris_messages_batch(user_id: int, message_ids: list[int]) -> None:
    """Scanne plusieurs messages Iris dans UNE SEULE session async.

    Évite la concurrence SQLite (1 task = 1 session = 1 connexion). Sur
    un tour Iris avec 10 outils, ouvrir 10 sessions parallèles produit
    des ``OperationalError: database is locked`` silencieusement avalés
    par le ``except Exception`` du chemin individuel (cf. review
    adversariale 2026-05-20 BLOCKING #2).

    Iter sériel : un échec sur un message ne bloque pas les suivants
    (try/except interne).
    """
    import json

    from sqlalchemy import select

    from app.core.database import get_session
    from app.models.conversation import Conversation, ConversationMessage
    from app.services.anonymization.api_service import scan_sql_result_terms

    if not message_ids:
        return

    try:
        async with get_session() as session:
            for message_id in message_ids:
                try:
                    result = await session.execute(
                        select(ConversationMessage)
                        .join(
                            Conversation,
                            ConversationMessage.conversation_id == Conversation.id,
                        )
                        .where(ConversationMessage.id == message_id)
                        .where(Conversation.user_id == user_id)
                    )
                    msg = result.scalar_one_or_none()
                    if msg is None or not msg.tool_result:
                        continue

                    try:
                        parsed = json.loads(msg.tool_result)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(parsed, dict):
                        continue
                    rows_raw = parsed.get("rows")
                    cols_raw = parsed.get("columns")
                    if not isinstance(rows_raw, list):
                        continue
                    rows = [r for r in rows_raw if isinstance(r, dict)]
                    if not rows:
                        continue
                    columns = (
                        [str(c) for c in cols_raw if c is not None]
                        if isinstance(cols_raw, list)
                        else None
                    )
                    conv_id = getattr(msg, "conversation_id", None)
                    if conv_id is None:
                        continue
                    source_ref = f"iris:{conv_id}"
                    await scan_sql_result_terms(
                        session,
                        user_id=user_id,
                        rows=rows,
                        columns=columns,
                        source_ref=source_ref,
                    )
                except Exception:  # noqa: BLE001 — per-message fail-soft
                    logger.warning(
                        "auto_scan iris_messages_batch msg=%s : skip",
                        message_id,
                        exc_info=True,
                    )
                    continue
            # 1 commit pour TOUS les messages du batch → 1 lock SQLite
            # acquis et libéré, pas N concurrents.
            await session.commit()
    except Exception:  # noqa: BLE001
        logger.warning(
            "auto_scan iris_messages_batch user=%s : échec global silencieux",
            user_id,
            exc_info=True,
        )


def schedule_iris_messages_rescan(
    user_id: int,
    message_ids: list[int],
) -> Optional[asyncio.Task]:
    """Fire-and-forget rescan d'un lot de messages Iris en UNE session.

    Utilisé par :func:`agent_service._save_turn` pour éviter d'ouvrir N
    sessions concurrentes (1 par tool_message persisté dans le tour),
    cf. review adversariale 2026-05-20 BLOCKING #2.
    """
    if not is_valid_user_id(user_id):
        return None
    if not message_ids:
        return None
    clean_ids = [int(m) for m in message_ids if isinstance(m, int) and m > 0]
    if not clean_ids:
        return None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.debug(
            "auto_scan: pas d'event-loop courant, skip iris batch " "(user=%s, %d messages)",
            user_id,
            len(clean_ids),
        )
        return None
    task = loop.create_task(_rescan_iris_messages_batch(user_id, clean_ids))
    _rescan_tasks.add(task)
    task.add_done_callback(_rescan_tasks.discard)
    return task


def schedule_target_rescan(
    user_id: int,
    kind: str,
    target_id: int,
) -> Optional[asyncio.Task]:
    """Fire-and-forget rescan asynchrone.

    À appeler depuis n'importe quel handler ou service APRÈS son commit
    (pour que le rescan voie la dernière version du target en BDD).

    Args:
        user_id: propriétaire de la ressource.
        kind: ``"dashboard"`` | ``"automation"`` | ``"iris_message"``.
        target_id: PK de la ressource à scanner.

    Returns:
        La task créée si un event-loop tourne, sinon ``None`` (cas test
        sync sans loop). Caller peut ignorer la valeur de retour.
    """
    if not is_valid_user_id(user_id):
        return None
    if not isinstance(target_id, int) or target_id <= 0:
        return None
    handler = {
        "dashboard": _rescan_dashboard,
        "automation": _rescan_automation,
        "iris_message": _rescan_iris_message,
    }.get(kind)
    if handler is None:
        logger.warning("auto_scan: kind inconnu %r (skip)", kind)
        return None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # Pas d'event-loop courant (appel depuis code sync, par ex.
        # script ad-hoc) : on n'a aucun moyen de scheduler proprement.
        # On loggue et on no-op — le scan complet via "Scanner mes
        # données" rattrapera de toute façon.
        logger.debug(
            "auto_scan: pas d'event-loop courant, skip schedule " "(kind=%s target_id=%s)",
            kind,
            target_id,
        )
        return None
    task = loop.create_task(handler(user_id, target_id))
    _rescan_tasks.add(task)
    task.add_done_callback(_rescan_tasks.discard)
    return task
