"""
Outils App Controller pour l'agent Iris.

Ces handlers permettent à Iris de piloter toutes les fonctionnalités
de l'application Komptia : automatisations, contacts, emails, rapports,
utilisateurs, configuration et statistiques.

Chaque handler appelle directement les services existants de l'app,
servant de pont entre l'agent IA et la couche métier.
"""

import asyncio
import json
from typing import Any, Dict

from sqlalchemy import select, desc

from app.core.database import get_session
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Exécutions d'automation lancées par Iris (fire-and-forget strong-ref)
# ---------------------------------------------------------------------------
# #50 — conteneur de références vivantes des Tasks d'exécution déclenchées
# par l'outil ``manage_automations`` (action ``execute``). Sans référence
# forte, ``asyncio.create_task`` peut être collectée par le GC avant la fin
# (Python 3.12+). ``add_done_callback(discard)`` libère à la complétion.
# Pattern aligné sur ``main._ServerLifecycle._background_tasks`` / webhooks.
_IRIS_EXEC_TASKS: "set[asyncio.Task[Any]]" = set()


async def _run_automation_via_iris(
    automation_id: int, user_id: int | None, auto_name: str
) -> None:
    """Exécute réellement l'automation en arrière-plan (fire-and-forget).

    Délègue à l'API publique ``execute_automation`` — MÊME point d'entrée
    que le bouton « Exécuter » de l'UI, le scheduler et les webhooks (SSoT).
    C'est ``execute_automation`` qui crée et réconcilie SA PROPRE ligne
    ``Execution`` (status pending→running→success/failed) : aucune ligne
    fantôme n'est créée ici.

    Les exceptions sont loggées et JAMAIS propagées — une Task fire-and-forget
    qui lève termine en « exception set but not retrieved » (erreur invisible).
    """
    try:
        from app.services.automation.executor import execute_automation

        await execute_automation(
            automation_id,
            manual=True,
            trigger_source="manual",
            triggered_by_user_id=user_id,
        )
    except Exception:  # noqa: BLE001 — fire-and-forget : on log tout
        logger.exception(
            "Iris: échec de l'exécution d'automation en arrière-plan",
            extra={"automation_id": automation_id, "name": auto_name},
        )


def _resolve_smtp_from_name(smtp_config: Dict[str, Any]) -> str:
    """Retourne le ``from_name`` SMTP : valeur explicite du config OU
    branding global. Pas de hardcode "Komptia"/"Cabinet X" ici."""
    explicit = smtp_config.get("from_name")
    if explicit:
        return str(explicit)
    from app.services.branding import get_smtp_from_name

    return get_smtp_from_name()


def _safe_int(value: Any, default: int | None = None) -> int | None:
    """Safely convert a value to int. Returns default on failure."""
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _safe_json_loads(raw: str | None, fallback: Any = None) -> Any:
    """Parse JSON safely, returning fallback on corrupt data."""
    if not raw:
        return fallback if fallback is not None else []
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return fallback if fallback is not None else []


def _escape_like(value: str) -> str:
    """Escape LIKE wildcards (%, _) for safe use in ilike() patterns."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ---------------------------------------------------------------------------
# 1. manage_automations
# ---------------------------------------------------------------------------


async def _handle_manage_automations(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Gère les automatisations : lister, créer, activer/désactiver, exécuter, supprimer."""
    from app.models.automation import Automation

    action: str = tool_input.get("action", "list")
    user_id = getattr(user, "id", None)

    try:
        if action == "list":
            async with get_session() as session:
                stmt = (
                    select(Automation)
                    .where(Automation.user_id == user_id)
                    .order_by(desc(Automation.updated_at))
                    .limit(50)
                )
                result = await session.execute(stmt)
                automations = result.scalars().all()

            return {
                "success": True,
                "action": "list",
                "count": len(automations),
                "automations": [
                    {
                        "id": a.id,
                        "name": a.name,
                        "description": a.description,
                        "query_type": a.query_type,
                        "schedule_type": a.schedule_type,
                        "output_format": a.output_format,
                        "is_active": a.is_active,
                        "recipients": _safe_json_loads(a.recipients, []),
                    }
                    for a in automations
                ],
            }

        elif action == "create":
            name = tool_input.get("name", "").strip()
            if not name:
                return {"success": False, "error": "Le nom est requis."}

            async with get_session() as session:
                automation = Automation(
                    user_id=user_id,
                    name=name[:200],
                    description=tool_input.get("description", ""),
                    query_type=tool_input.get("query_type", "nl"),
                    query_text=tool_input.get("query_text", ""),
                    schedule_type=tool_input.get("schedule_type", "once"),
                    schedule_config=json.dumps(tool_input.get("schedule_config", {})),
                    output_format=tool_input.get("output_format", "csv"),
                    recipients=json.dumps(tool_input.get("recipients", [])),
                    is_active=False,  # Inactive by default — user must confirm
                )
                session.add(automation)
                await session.commit()
                await session.refresh(automation)

            logger.info(
                "Automation created via Iris: id=%d, name=%s",
                automation.id,
                name,
            )
            return {
                "success": True,
                "action": "create",
                "automation_id": automation.id,
                "name": name,
                "note": "Automatisation créée en mode inactif. Activez-la pour démarrer.",
            }

        elif action == "toggle":
            automation_id = _safe_int(tool_input.get("automation_id"))
            if not automation_id:
                return {"success": False, "error": "automation_id requis."}

            async with get_session() as session:
                auto = await session.get(Automation, automation_id)
                if not auto or auto.user_id != user_id:
                    return {"success": False, "error": "Automatisation introuvable."}

                new_state = not auto.is_active
                auto.is_active = new_state
                await session.commit()

            logger.info(
                "Automation toggled via Iris: id=%d, active=%s",
                automation_id,
                new_state,
            )
            return {
                "success": True,
                "action": "toggle",
                "automation_id": automation_id,
                "is_active": new_state,
            }

        elif action == "execute":
            automation_id = _safe_int(tool_input.get("automation_id"))
            if not automation_id:
                return {"success": False, "error": "automation_id requis."}

            # #50 — on charge aussi les relations steps/edges (selectinload :
            # règle ORM async-safe, lecture APRÈS la session) pour pré-valider
            # le DAG. selectinload importé localement comme dans les autres
            # branches lazy de ce module.
            from sqlalchemy.orm import selectinload

            async with get_session() as session:
                # #50 — Kill-switch global admin, vérifié AVANT de prétendre
                # « lancé ». MÊME SSoT que l'executor (feature_flag_service).
                # En fire-and-forget, si le kill-switch est actif l'executor
                # refuse SANS créer de ligne Execution (executor.py:176) : sans
                # ce pré-check l'user verrait « lancée » sans aucune trace en
                # historique (données fausses). Defense-in-depth : l'executor
                # revérifie de toute façon (race flag→run).
                from app.models.feature_flag import FLAG_AUTOMATIONS_DISABLED
                from app.services.automation.feature_flag_service import is_truthy

                if await is_truthy(session, FLAG_AUTOMATIONS_DISABLED, default=False):
                    return {
                        "success": False,
                        "error": (
                            "Les exécutions d'automatisations sont temporairement "
                            "désactivées par l'administrateur."
                        ),
                    }

                auto = await session.get(
                    Automation,
                    automation_id,
                    options=[
                        selectinload(Automation.steps),
                        selectinload(Automation.edges),
                    ],
                )
                if not auto or auto.user_id != user_id:
                    return {"success": False, "error": "Automatisation introuvable."}

                # Capture avant sortie de session (évite l'accès à un attribut
                # expiré / lazy-load hors session).
                auto_name = auto.name
                steps = list(auto.steps)
                edges = list(auto.edges)

            # #50 — Pré-validation DAG avec le MÊME validateur que le bouton
            # « Exécuter » de l'UI (SSoT ``validate_all(for_activation=True)``).
            # Un workflow incomplet est refusé HONNÊTEMENT au lieu d'être
            # faussement annoncé « lancé » puis d'échouer en silence. Forme des
            # dicts alignée sur ``app/handlers/automations.py`` (clé step_type).
            from app.services.automation.dag_validator import (
                errors_to_json,
                validate_all,
            )

            val_nodes = [
                {
                    "id": s.id,
                    "step_type": (
                        s.step_type.value if hasattr(s.step_type, "value") else s.step_type
                    ),
                    "name": s.name,
                    "config": s.config or {},
                    "is_enabled": s.is_enabled,
                }
                for s in steps
            ]
            val_edges = [
                {
                    "id": e.id,
                    "from_step_id": e.from_step_id,
                    "to_step_id": e.to_step_id,
                    "data_type": e.data_type,
                }
                for e in edges
            ]
            val_errors = list(validate_all(val_nodes, val_edges, for_activation=True))
            if val_errors:
                return {
                    "success": False,
                    "error": (
                        f"Workflow incomplet : « {auto_name} » ne peut pas être "
                        "lancée tant que sa configuration n'est pas valide."
                    ),
                    "validation_errors": errors_to_json(val_errors),
                }

            # #50 — Lancement RÉEL en arrière-plan via l'API publique stable
            # ``execute_automation`` (fire-and-forget strong-ref). Avant : on
            # créait une ligne ``Execution`` « pending » fantôme JAMAIS exécutée
            # (costume-sans-corps + ligne bloquée « en cours » à vie). Désormais
            # c'est ``execute_automation`` qui crée et réconcilie SA PROPRE
            # ligne d'exécution, comme le bouton « Exécuter » et le scheduler.
            task = asyncio.create_task(
                _run_automation_via_iris(automation_id, user_id, auto_name)
            )
            _IRIS_EXEC_TASKS.add(task)
            task.add_done_callback(_IRIS_EXEC_TASKS.discard)

            logger.info(
                "Automation execution lancée via Iris: automation_id=%d",
                automation_id,
            )
            return {
                "success": True,
                "action": "execute",
                "automation_id": automation_id,
                "name": auto_name,
                "note": (
                    "Exécution lancée en arrière-plan. Suis son avancement dans "
                    "l'historique des exécutions de l'automatisation."
                ),
            }

        elif action == "delete":
            automation_id = _safe_int(tool_input.get("automation_id"))
            if not automation_id:
                return {"success": False, "error": "automation_id requis."}

            async with get_session() as session:
                auto = await session.get(Automation, automation_id)
                if not auto or auto.user_id != user_id:
                    return {"success": False, "error": "Automatisation introuvable."}

                await session.delete(auto)
                await session.commit()

            logger.info("Automation deleted via Iris: id=%d", automation_id)
            return {
                "success": True,
                "action": "delete",
                "automation_id": automation_id,
            }

        else:
            return {"success": False, "error": f"Action inconnue : {action}"}

    except Exception as exc:
        logger.error("manage_automations failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de la gestion des automatisations."}


# ---------------------------------------------------------------------------
# 2. list_execution_history
# ---------------------------------------------------------------------------


async def _handle_list_execution_history(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict:
    """Liste l'historique d'exécution des automatisations."""
    from app.models.automation import Automation
    from app.models.execution import Execution

    user_id = getattr(user, "id", None)
    automation_id = _safe_int(tool_input.get("automation_id"))
    status_filter = tool_input.get("status")
    limit = min(_safe_int(tool_input.get("limit"), 20), 100)

    try:
        async with get_session() as session:
            stmt = (
                select(Execution)
                .join(Automation, Execution.automation_id == Automation.id)
                .where(Automation.user_id == user_id)
            )

            if automation_id:
                stmt = stmt.where(Execution.automation_id == automation_id)
            if status_filter:
                stmt = stmt.where(Execution.status == status_filter)

            stmt = stmt.order_by(desc(Execution.started_at)).limit(limit)
            result = await session.execute(stmt)
            executions = result.scalars().all()

        return {
            "success": True,
            "count": len(executions),
            "executions": [
                {
                    "id": e.id,
                    "automation_id": e.automation_id,
                    "status": e.status,
                    "started_at": str(e.started_at) if e.started_at else None,
                    "finished_at": str(e.finished_at) if e.finished_at else None,
                    "duration_seconds": e.duration_seconds,
                    "result_rows": e.result_rows,
                    "error_message": e.error_message[:200] if e.error_message else None,
                }
                for e in executions
            ],
        }

    except Exception as exc:
        logger.error("list_execution_history failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de la récupération de l'historique."}


# ---------------------------------------------------------------------------
# 3. manage_contacts
# ---------------------------------------------------------------------------


async def _handle_manage_contacts(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """CRUD des contacts de l'utilisateur."""
    from app.models.contact import Contact

    action: str = tool_input.get("action", "list")
    user_id = getattr(user, "id", None)

    try:
        if action == "list":
            search = tool_input.get("search", "")
            limit = min(_safe_int(tool_input.get("limit"), 25), 100)

            async with get_session() as session:
                stmt = select(Contact).where(
                    Contact.user_id == user_id, Contact.is_active.is_(True)
                )
                if search:
                    escaped = _escape_like(search)
                    pattern = f"%{escaped}%"
                    stmt = stmt.where(
                        (Contact.email.ilike(pattern, escape="\\"))
                        | (Contact.first_name.ilike(pattern, escape="\\"))
                        | (Contact.last_name.ilike(pattern, escape="\\"))
                        | (Contact.company.ilike(pattern, escape="\\"))
                    )
                stmt = stmt.order_by(Contact.last_name).limit(limit)
                result = await session.execute(stmt)
                contacts = result.scalars().all()

            return {
                "success": True,
                "action": "list",
                "count": len(contacts),
                "contacts": [
                    {
                        "id": c.id,
                        "email": c.email,
                        "first_name": c.first_name,
                        "last_name": c.last_name,
                        "company": c.company,
                        "phone": c.phone,
                    }
                    for c in contacts
                ],
            }

        elif action == "create":
            email = (tool_input.get("email") or "").strip().lower()
            if not email or "@" not in email:
                return {"success": False, "error": "Email invalide."}

            async with get_session() as session:
                # Check duplicate
                existing = await session.execute(
                    select(Contact).where(
                        Contact.user_id == user_id,
                        Contact.email == email,
                    )
                )
                if existing.scalar_one_or_none():
                    return {"success": False, "error": "Ce contact existe déjà."}

                contact = Contact(
                    user_id=user_id,
                    email=email,
                    first_name=tool_input.get("first_name", ""),
                    last_name=tool_input.get("last_name", ""),
                    company=tool_input.get("company", ""),
                    phone=tool_input.get("phone", ""),
                    is_active=True,
                )
                session.add(contact)
                await session.commit()
                await session.refresh(contact)

            logger.info("Contact created via Iris: id=%d", contact.id)
            return {
                "success": True,
                "action": "create",
                "contact_id": contact.id,
                "email": email,
            }

        elif action == "update":
            contact_id = _safe_int(tool_input.get("contact_id"))
            if not contact_id:
                return {"success": False, "error": "contact_id requis."}

            async with get_session() as session:
                contact = await session.get(Contact, contact_id)
                if not contact or contact.user_id != user_id:
                    return {"success": False, "error": "Contact introuvable."}

                for field in ("email", "first_name", "last_name", "company", "phone"):
                    if field in tool_input:
                        setattr(contact, field, tool_input[field])
                await session.commit()

            return {"success": True, "action": "update", "contact_id": contact_id}

        elif action == "delete":
            contact_id = _safe_int(tool_input.get("contact_id"))
            if not contact_id:
                return {"success": False, "error": "contact_id requis."}

            async with get_session() as session:
                contact = await session.get(Contact, contact_id)
                if not contact or contact.user_id != user_id:
                    return {"success": False, "error": "Contact introuvable."}

                contact.is_active = False  # Soft delete
                await session.commit()

            return {"success": True, "action": "delete", "contact_id": contact_id}

        else:
            return {"success": False, "error": f"Action inconnue : {action}"}

    except Exception as exc:
        logger.error("manage_contacts failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de la gestion des contacts."}


# ---------------------------------------------------------------------------
# 4. manage_distribution_lists
# ---------------------------------------------------------------------------


async def _handle_manage_distribution_lists(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict:
    """Gestion des listes de diffusion."""
    from app.models.contact import Contact, DistributionList
    from sqlalchemy.orm import selectinload

    action: str = tool_input.get("action", "list")
    user_id = getattr(user, "id", None)

    try:
        if action == "list":
            async with get_session() as session:
                stmt = (
                    select(DistributionList)
                    .options(selectinload(DistributionList.contacts))
                    .where(
                        DistributionList.user_id == user_id,
                        DistributionList.is_active.is_(True),
                    )
                    .order_by(DistributionList.name)
                )
                result = await session.execute(stmt)
                lists = result.scalars().all()

                # Build response inside session (eager-loaded contacts)
                lists_data = [
                    {
                        "id": dl.id,
                        "name": dl.name,
                        "description": dl.description,
                        "member_count": len(dl.contacts) if dl.contacts else 0,
                    }
                    for dl in lists
                ]

            return {
                "success": True,
                "action": "list",
                "count": len(lists_data),
                "lists": lists_data,
            }

        elif action == "create":
            name = (tool_input.get("name") or "").strip()
            if not name:
                return {"success": False, "error": "Le nom est requis."}

            async with get_session() as session:
                dl = DistributionList(
                    user_id=user_id,
                    name=name[:100],
                    description=tool_input.get("description", ""),
                    is_active=True,
                )
                session.add(dl)
                await session.commit()
                await session.refresh(dl)

            return {
                "success": True,
                "action": "create",
                "list_id": dl.id,
                "name": name,
            }

        elif action == "add_members":
            list_id = _safe_int(tool_input.get("list_id"))
            contact_ids = tool_input.get("contact_ids", [])
            if not list_id or not contact_ids:
                return {"success": False, "error": "list_id et contact_ids requis."}

            async with get_session() as session:
                stmt = (
                    select(DistributionList)
                    .options(selectinload(DistributionList.contacts))
                    .where(DistributionList.id == list_id)
                )
                result = await session.execute(stmt)
                dl = result.scalar_one_or_none()
                if not dl or dl.user_id != user_id:
                    return {"success": False, "error": "Liste introuvable."}

                added = 0
                for cid in contact_ids:
                    cid_int = _safe_int(cid)
                    if not cid_int:
                        continue
                    contact = await session.get(Contact, cid_int)
                    if contact and contact.user_id == user_id:
                        if contact not in dl.contacts:
                            dl.contacts.append(contact)
                            added += 1
                await session.commit()

            return {
                "success": True,
                "action": "add_members",
                "list_id": list_id,
                "added": added,
            }

        elif action == "remove_member":
            list_id = _safe_int(tool_input.get("list_id"))
            contact_id = _safe_int(tool_input.get("contact_id"))
            if not list_id or not contact_id:
                return {
                    "success": False,
                    "error": "list_id et contact_id requis.",
                }

            async with get_session() as session:
                stmt = (
                    select(DistributionList)
                    .options(selectinload(DistributionList.contacts))
                    .where(DistributionList.id == list_id)
                )
                result = await session.execute(stmt)
                dl = result.scalar_one_or_none()
                if not dl or dl.user_id != user_id:
                    return {"success": False, "error": "Liste introuvable."}

                contact = await session.get(Contact, contact_id)
                if not contact or contact.user_id != user_id:
                    return {"success": False, "error": "Contact introuvable."}
                if contact not in dl.contacts:
                    return {"success": False, "error": "Contact non trouvé dans cette liste."}

                dl.contacts.remove(contact)
                await session.commit()

            return {
                "success": True,
                "action": "remove_member",
                "list_id": list_id,
                "contact_id": contact_id,
            }

        else:
            return {"success": False, "error": f"Action inconnue : {action}"}

    except Exception as exc:
        logger.error("manage_distribution_lists failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de la gestion des listes."}


# ---------------------------------------------------------------------------
# 5. send_email
# ---------------------------------------------------------------------------


async def _load_smtp_config() -> dict | None:
    """Load SMTP config from DB (global config) or .env fallback.

    Cycle 17 #12 : factorisé via ``smtp_factory.load_smtp_config_dict``.
    Conserve cette wrapper async pour rétro-compat avec les tests qui
    patchent ``app.services.ai.agent_tools_app._load_smtp_config``."""
    from app.services.email.smtp_factory import load_smtp_config_dict

    return await load_smtp_config_dict()


async def _handle_send_email(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Envoie un email via le service SMTP configuré."""
    import re

    recipients = tool_input.get("recipients", [])
    subject = (tool_input.get("subject") or "").strip()
    body_html = (tool_input.get("body_html") or "").strip()

    # Dé-anonymisation CRITIQUE : le sujet et le corps partent vers un
    # destinataire EXTERNE (SMTP). Si le LLM a inséré des fragments
    # ~XXX, ils sortent du périmètre de l'app — une vraie fuite de
    # confidentialité à l'extérieur. Fail-safe : si le service échoue,
    # on bloque l'envoi plutôt que d'envoyer potentiellement des
    # fragments obfusqués dans un mail.
    try:
        from app.services.ai.agent_tools import _restore_for_user_safe

        subject = await _restore_for_user_safe(subject)
        body_html = await _restore_for_user_safe(body_html)
    except Exception as _restore_exc:
        logger.warning(
            "send_email: confidentiality restore failed, refusing send: %s",
            _restore_exc,
        )
        return {
            "success": False,
            "error": (
                "Service de confidentialité indisponible. " "Envoi du mail refusé par précaution."
            ),
        }

    if not recipients:
        return {"success": False, "error": "Au moins un destinataire requis."}
    if len(recipients) > 50:
        return {"success": False, "error": "Maximum 50 destinataires par envoi."}
    if not subject:
        return {"success": False, "error": "Le sujet est requis."}
    if not body_html:
        return {"success": False, "error": "Le corps du message est requis."}

    # Validate email format for all recipients
    _email_re = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    invalid = [r for r in recipients if not isinstance(r, str) or not _email_re.match(r.strip())]
    if invalid:
        return {
            "success": False,
            "error": f"Emails invalides : {', '.join(str(e) for e in invalid[:3])}",
        }
    recipients = [r.strip() for r in recipients]

    # Rate limit: max 5 emails per agent turn
    emails_sent_count = len(context.get("emails_sent", []))
    if emails_sent_count >= 5:
        return {
            "success": False,
            "error": "Limite d'envoi atteinte (5 emails max par tour).",
        }

    # Load SMTP config from DB or .env
    smtp_config = await _load_smtp_config()
    if not smtp_config:
        return {
            "success": False,
            "error": "SMTP non configuré. Demandez à un administrateur de configurer le serveur SMTP.",
        }

    try:
        # Q2 cycle 15 : factory unique. Iris envoie au nom branding admin.
        from app.services.email.smtp_factory import build_smtp_client_from_dict

        client = build_smtp_client_from_dict(
            smtp_config,
            from_name_override=_resolve_smtp_from_name(smtp_config),
        )
        # Audit ``EmailLog`` centralisé via ``SMTPClient.send_email``
        # (kwargs ``sent_by_user_id``). Pas de write inline ici (cf.
        # ``services/email/smtp_client.py`` — single source of truth pour
        # les 11 sites d'envoi de Komptia).
        result = await client.send_email(
            to_emails=recipients,
            subject=subject,
            body_html=body_html,
            sent_by_user_id=getattr(user, "id", None),
        )

        if result.get("success"):
            logger.info(
                "Email sent via Iris to %d recipients",
                len(recipients),
            )

            # Store for agent_service to yield email_sent event
            if "emails_sent" not in context:
                context["emails_sent"] = []
            context["emails_sent"].append(
                {
                    "recipients": recipients,
                    "subject": subject,
                }
            )

            return {
                "success": True,
                "recipients_count": len(recipients),
                "subject": subject,
            }
        else:
            return {
                "success": False,
                "error": "Échec de l'envoi. Vérifiez la config SMTP.",
            }

    except Exception as exc:
        logger.error("send_email failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de l'envoi de l'email."}


# ---------------------------------------------------------------------------
# 6. list_reports
# ---------------------------------------------------------------------------


async def _handle_list_reports(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Liste, partage ou archive les rapports."""
    from app.models.report import Report
    from app.models.user import UserRole

    action: str = tool_input.get("action", "list")
    user_id = getattr(user, "id", None)
    is_admin = getattr(user, "role", None) == UserRole.ADMIN.value

    try:
        if action == "list":
            report_type = tool_input.get("report_type")
            file_format = tool_input.get("file_format")
            limit = min(_safe_int(tool_input.get("limit"), 20), 100)

            async with get_session() as session:
                stmt = select(Report).order_by(desc(Report.created_at))
                if not is_admin:
                    stmt = stmt.where(Report.created_by_user_id == user_id)
                if report_type:
                    stmt = stmt.where(Report.report_type == report_type)
                if file_format:
                    stmt = stmt.where(Report.file_format == file_format)
                stmt = stmt.limit(limit)

                result = await session.execute(stmt)
                reports = result.scalars().all()

            return {
                "success": True,
                "action": "list",
                "count": len(reports),
                "reports": [
                    {
                        "id": r.id,
                        "title": r.title,
                        "report_type": r.report_type,
                        "file_format": r.file_format,
                        "file_size": r.file_size,
                        "is_archived": r.is_archived,
                        "has_share_link": r.share_token is not None,
                        "created_at": str(r.created_at),
                    }
                    for r in reports
                ],
            }

        elif action == "share":
            report_id = _safe_int(tool_input.get("report_id"))
            if not report_id:
                return {"success": False, "error": "report_id requis."}

            # Ownership check
            async with get_session() as session:
                report = await session.get(Report, report_id)
                if not report or (not is_admin and report.created_by_user_id != user_id):
                    return {"success": False, "error": "Rapport introuvable."}

            from app.services.reporting.report_storage import get_report_storage

            storage = get_report_storage()
            token = await storage.create_share_link(report_id)
            if token:
                return {
                    "success": True,
                    "action": "share",
                    "report_id": report_id,
                    "share_token": token,
                    "share_url": f"/share/report/{token}",
                }
            return {"success": False, "error": "Impossible de créer le lien."}

        elif action == "archive":
            report_id = _safe_int(tool_input.get("report_id"))
            if not report_id:
                return {"success": False, "error": "report_id requis."}

            # Ownership check
            async with get_session() as session:
                report = await session.get(Report, report_id)
                if not report or (not is_admin and report.created_by_user_id != user_id):
                    return {"success": False, "error": "Rapport introuvable."}

            from app.services.reporting.report_storage import get_report_storage

            storage = get_report_storage()
            new_state = await storage.toggle_archive(report_id)
            return {
                "success": True,
                "action": "archive",
                "report_id": report_id,
                "is_archived": new_state,
            }

        else:
            return {"success": False, "error": f"Action inconnue : {action}"}

    except Exception as exc:
        logger.error("list_reports failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de la gestion des rapports."}


# ---------------------------------------------------------------------------
# 7. manage_users (admin only)
# ---------------------------------------------------------------------------


async def _handle_manage_users(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Gestion des utilisateurs (admin uniquement)."""
    from app.models.user import User, UserRole

    # Admin check
    if getattr(user, "role", None) != UserRole.ADMIN.value:
        return {
            "success": False,
            "error": "Permission refusée. Réservé aux administrateurs.",
        }

    action: str = tool_input.get("action", "list")

    try:
        if action == "list":
            async with get_session() as session:
                stmt = select(User).order_by(User.username).limit(100)
                result = await session.execute(stmt)
                users = result.scalars().all()

            return {
                "success": True,
                "action": "list",
                "count": len(users),
                "users": [
                    {
                        "id": u.id,
                        "username": u.username,
                        "email": u.email,
                        "role": u.role,
                        "is_active": u.is_active,
                        "last_login": str(u.last_login) if u.last_login else None,
                    }
                    for u in users
                ],
            }

        elif action == "create":
            from app.services.auth.password_hasher import get_password_hasher

            username = (tool_input.get("username") or "").strip()
            email = (tool_input.get("email") or "").strip().lower()
            password = tool_input.get("password", "")
            role = tool_input.get("role", "user")

            if not username or len(username) < 3:
                return {"success": False, "error": "Username min 3 caractères."}
            if not email or "@" not in email:
                return {"success": False, "error": "Email invalide."}
            if not password or len(password) < 8:
                return {"success": False, "error": "Mot de passe min 8 caractères."}

            hasher = get_password_hasher()
            hashed = hasher.hash_password(password)

            async with get_session() as session:
                # Check uniqueness
                existing = await session.execute(
                    select(User).where((User.username == username) | (User.email == email))
                )
                if existing.scalar_one_or_none():
                    return {
                        "success": False,
                        "error": "Username ou email déjà utilisé.",
                    }

                new_user = User(
                    username=username,
                    email=email,
                    password_hash=hashed,
                    role=role,
                    is_active=True,
                )
                session.add(new_user)
                await session.commit()
                await session.refresh(new_user)

            logger.info("User created via Iris: id=%d, username=%s", new_user.id, username)
            return {
                "success": True,
                "action": "create",
                "user_id": new_user.id,
                "username": username,
            }

        elif action == "update":
            target_id = _safe_int(tool_input.get("user_id"))
            if not target_id:
                return {"success": False, "error": "user_id requis."}

            # Validate role if provided
            if "role" in tool_input:
                valid_roles = [r.value for r in UserRole]
                if tool_input["role"] not in valid_roles:
                    return {
                        "success": False,
                        "error": f"Rôle invalide. Valeurs possibles : {valid_roles}",
                    }

            async with get_session() as session:
                target = await session.get(User, target_id)
                if not target:
                    return {"success": False, "error": "Utilisateur introuvable."}

                for field in ("email", "role", "is_active"):
                    if field in tool_input:
                        setattr(target, field, tool_input[field])
                await session.commit()

            return {"success": True, "action": "update", "user_id": target_id}

        elif action == "deactivate":
            target_id = _safe_int(tool_input.get("user_id"))
            if not target_id:
                return {"success": False, "error": "user_id requis."}

            async with get_session() as session:
                target = await session.get(User, target_id)
                if not target:
                    return {"success": False, "error": "Utilisateur introuvable."}
                target.is_active = False
                await session.commit()

            return {
                "success": True,
                "action": "deactivate",
                "user_id": target_id,
            }

        else:
            return {"success": False, "error": f"Action inconnue : {action}"}

    except Exception as exc:
        logger.error("manage_users failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de la gestion des utilisateurs."}


# ---------------------------------------------------------------------------
# 8. get_app_stats
# ---------------------------------------------------------------------------


async def _handle_get_app_stats(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Récupère les statistiques de l'app (dashboard, IA, performance)."""
    category: str = tool_input.get("category", "dashboard")
    user_id = getattr(user, "id", None)

    try:
        if category == "dashboard":
            from app.services.dashboard.charts import (
                get_stats_service,
            )

            service = get_stats_service()
            stats = await service.get_user_stats(user_id)
            return {"success": True, "category": "dashboard", "stats": stats}

        elif category == "ai":
            from app.services.ai.stats_service import AIStatsService

            service = AIStatsService()
            stats = await service.get_stats(days=30)
            return {"success": True, "category": "ai", "stats": stats}

        elif category == "performance":
            from app.services.performance_stats_service import (
                get_performance_stats_service,
            )

            service = get_performance_stats_service()
            overview = await service.get_overview(days=30)
            return {
                "success": True,
                "category": "performance",
                "stats": overview,
            }

        elif category == "all":
            from app.services.dashboard.charts import (
                get_stats_service,
            )

            service = get_stats_service()
            dashboard_stats = await service.get_user_stats(user_id)
            combined = {"dashboard": dashboard_stats}

            # Best-effort: add AI and performance stats if services exist
            try:
                from app.services.ai.stats_service import AIStatsService

                ai_service = AIStatsService()
                combined["ai"] = await ai_service.get_stats(days=30)
            except Exception:
                logger.warning("Failed to load AI stats", exc_info=True)
                combined["ai"] = None

            try:
                from app.services.performance_stats_service import (
                    get_performance_stats_service,
                )

                perf_service = get_performance_stats_service()
                combined["performance"] = await perf_service.get_overview(days=30)
            except Exception:
                logger.warning("Failed to load performance stats", exc_info=True)
                combined["performance"] = None

            return {"success": True, "category": "all", "stats": combined}

        else:
            return {"success": False, "error": f"Catégorie inconnue : {category}"}

    except Exception as exc:
        logger.error("get_app_stats failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de la récupération des stats."}


# ---------------------------------------------------------------------------
# 9. manage_app_config (admin only)
# ---------------------------------------------------------------------------


async def _handle_manage_app_config(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Lecture et modification de la configuration (admin uniquement)."""
    from app.models.user import UserRole

    if getattr(user, "role", None) != UserRole.ADMIN.value:
        return {
            "success": False,
            "error": "Permission refusée. Réservé aux administrateurs.",
        }

    action: str = tool_input.get("action", "get")
    config_category: str = tool_input.get("category", "ai")

    try:
        if action == "get":
            if config_category == "ai":
                from app.services.ai.config_service import get_ai_config_service

                service = get_ai_config_service()
                config = await service.get_all()
                # Allowlist of safe-to-display config keys
                _SAFE_AI_KEYS = {
                    "default_provider",
                    "default_model",
                    "temperature",
                    "max_tokens",
                    "enabled",
                    "provider_name",
                    "model_name",
                    "timeout",
                    "retry_count",
                }
                safe_config = {}
                for key, value in config.items():
                    if key.lower() in _SAFE_AI_KEYS:
                        safe_config[key] = value
                    else:
                        safe_config[key] = "***" if value else None
                return {
                    "success": True,
                    "action": "get",
                    "category": "ai",
                    "config": safe_config,
                }

            elif config_category == "smtp":
                from app.models.smtp_global_config import SMTPGlobalConfig

                async with get_session() as session:
                    result = await session.execute(select(SMTPGlobalConfig).limit(1))
                    smtp = result.scalar_one_or_none()

                if smtp:
                    return {
                        "success": True,
                        "action": "get",
                        "category": "smtp",
                        "config": {
                            "host": smtp.host,
                            "port": smtp.port,
                            "username": smtp.username,
                            "from_email": smtp.from_email,
                            "use_tls": smtp.use_tls,
                            "enabled": smtp.enabled,
                            "password": "***" if smtp.password else None,
                        },
                    }
                return {
                    "success": True,
                    "action": "get",
                    "category": "smtp",
                    "config": None,
                    "note": "Aucune configuration SMTP trouvée.",
                }

            elif config_category == "database":
                from app.services.database.db_config_service import (
                    list_connections,
                )

                connections = await list_connections()
                return {
                    "success": True,
                    "action": "get",
                    "category": "database",
                    "connections": [
                        {
                            "id": c.get("id"),
                            "name": c.get("name"),
                            "host": c.get("host"),
                            "database": c.get("database"),
                            "is_active": c.get("is_active"),
                        }
                        for c in connections
                    ],
                }

            else:
                return {
                    "success": False,
                    "error": f"Catégorie inconnue : {config_category}",
                }

        elif action == "update":
            updates = tool_input.get("updates", {})
            if not updates:
                return {"success": False, "error": "Aucune mise à jour fournie."}

            if config_category == "ai":
                from app.services.ai.config_service import get_ai_config_service

                service = get_ai_config_service()
                await service.update(updates)
                logger.info(
                    "AI config updated via Iris: keys=%s",
                    list(updates.keys()),
                )
                return {
                    "success": True,
                    "action": "update",
                    "category": "ai",
                    "updated_keys": list(updates.keys()),
                }

            else:
                return {
                    "success": False,
                    "error": "Mise à jour non supportée pour cette catégorie.",
                }

        else:
            return {"success": False, "error": f"Action inconnue : {action}"}

    except Exception as exc:
        logger.error("manage_app_config failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de la gestion de la config."}


# ---------------------------------------------------------------------------
# Export — handler registry
# ---------------------------------------------------------------------------

APP_TOOL_HANDLERS = {
    "manage_automations": _handle_manage_automations,
    "list_execution_history": _handle_list_execution_history,
    "manage_contacts": _handle_manage_contacts,
    "manage_distribution_lists": _handle_manage_distribution_lists,
    "send_email": _handle_send_email,
    "list_reports": _handle_list_reports,
    "manage_users": _handle_manage_users,
    "get_app_stats": _handle_get_app_stats,
    "manage_app_config": _handle_manage_app_config,
}
