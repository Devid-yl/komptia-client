"""
Service de livraison planifiée de dashboards par email.

Rend les données de tous les widgets d'un dashboard en HTML
et les envoie aux destinataires configurés via SMTP.
Supporte l'envoi d'un export CSV/Excel en pièce jointe.
"""

import html
import logging
import re
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import config
from app.core import clock
from app.services.branding import get_smtp_from_name

logger = logging.getLogger(__name__)

# Regex email simple (même pattern que executor.py)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


async def load_smtp_config(session: AsyncSession) -> Optional[Dict[str, Any]]:
    """Charge la config SMTP depuis DB puis .env en fallback.

    Cycle 17 #12 : factorisé via ``smtp_factory.load_smtp_config_dict``.
    Conserve cette fonction module-level pour rétro-compat avec les tests
    qui la patchent par nom (``patch("app.services.dashboard.delivery_service.load_smtp_config")``).
    """
    from app.services.email.smtp_factory import load_smtp_config_dict

    return await load_smtp_config_dict(session=session)


def _render_widget_html(widget_dict: dict, widget_data: dict) -> str:
    """Rend un widget individuel en HTML pour email."""
    title = html.escape(widget_dict.get("title", "Widget"))
    wtype = widget_data.get("type", "table")

    parts = [
        '<div style="margin-bottom:24px;border:1px solid #e5e7eb;'
        'border-radius:8px;overflow:hidden">',
        f'<div style="background:#f9fafb;padding:12px 16px;'
        f'border-bottom:1px solid #e5e7eb;font-weight:600;font-size:14px">'
        f"{title}</div>",
        '<div style="padding:16px">',
    ]

    if "error" in widget_data:
        safe_err = html.escape(str(widget_data["error"])[:200])
        parts.append(f'<p style="color:#ef4444;font-size:13px">Erreur : {safe_err}</p>')
    elif wtype == "kpi":
        value = widget_data.get("value", "\u2014")
        label = html.escape(str(widget_data.get("label", "")))
        parts.append(
            f'<div style="text-align:center;padding:12px">'
            f'<div style="font-size:32px;font-weight:700;color:#1f2937">'
            f"{html.escape(str(value))}</div>"
            f'<div style="font-size:13px;color:#6b7280;margin-top:4px">'
            f"{label}</div></div>"
        )
    elif wtype == "chart":
        _render_chart_as_table(parts, widget_data)
    elif wtype == "table":
        _render_table(parts, widget_data)
    else:
        parts.append('<p style="color:#9ca3af;font-size:13px">Type non support\u00e9</p>')

    parts.append("</div></div>")
    return "\n".join(parts)


def _render_chart_as_table(parts: list, widget_data: dict) -> None:
    """Rend les données chart sous forme de tableau pour email."""
    labels = widget_data.get("labels", [])
    datasets = widget_data.get("datasets", [])
    if not datasets:
        parts.append('<p style="color:#9ca3af;font-size:13px">Aucune donn\u00e9e</p>')
        return

    parts.append('<table style="width:100%;border-collapse:collapse;font-size:13px">')
    header_cells = [
        '<th style="padding:6px 8px;border-bottom:2px solid '
        '#e5e7eb;text-align:left;color:#6b7280"></th>'
    ]
    for ds in datasets:
        ds_label = html.escape(str(ds.get("label", "")))
        header_cells.append(
            f'<th style="padding:6px 8px;border-bottom:2px solid '
            f'#e5e7eb;text-align:right;color:#6b7280">{ds_label}</th>'
        )
    parts.append("<tr>" + "".join(header_cells) + "</tr>")

    for i, lbl in enumerate(labels[:20]):
        safe_lbl = html.escape(str(lbl))
        row_cells = [
            f'<td style="padding:6px 8px;border-bottom:1px solid ' f'#f3f4f6">{safe_lbl}</td>'
        ]
        for ds in datasets:
            vals = ds.get("data", [])
            val = vals[i] if i < len(vals) else "\u2014"
            row_cells.append(
                f'<td style="padding:6px 8px;border-bottom:1px solid '
                f'#f3f4f6;text-align:right">{html.escape(str(val))}</td>'
            )
        parts.append("<tr>" + "".join(row_cells) + "</tr>")

    if len(labels) > 20:
        colspan = len(datasets) + 1
        parts.append(
            f'<tr><td colspan="{colspan}" style="padding:6px 8px;'
            f'color:#9ca3af;font-style:italic">'
            f"... et {len(labels) - 20} lignes de plus</td></tr>"
        )
    parts.append("</table>")


def _render_table(parts: list, widget_data: dict) -> None:
    """Rend les données table pour email."""
    columns = widget_data.get("columns", [])
    rows = widget_data.get("rows", [])
    if not columns or not rows:
        parts.append('<p style="color:#9ca3af;font-size:13px">Aucune donn\u00e9e</p>')
        return

    parts.append('<table style="width:100%;border-collapse:collapse;font-size:13px">')
    header_cells = []
    for col in columns:
        safe_col = html.escape(str(col))
        header_cells.append(
            f'<th style="padding:6px 8px;border-bottom:2px solid '
            f'#e5e7eb;text-align:left;color:#6b7280">{safe_col}</th>'
        )
    parts.append("<tr>" + "".join(header_cells) + "</tr>")

    for row in rows[:30]:
        row_cells = []
        for val in row:
            safe_val = html.escape(str(val) if val is not None else "\u2014")
            row_cells.append(
                f'<td style="padding:6px 8px;border-bottom:1px solid ' f'#f3f4f6">{safe_val}</td>'
            )
        parts.append("<tr>" + "".join(row_cells) + "</tr>")

    if len(rows) > 30:
        parts.append(
            f'<tr><td colspan="{len(columns)}" style="padding:6px 8px;'
            f'color:#9ca3af;font-style:italic">'
            f"... et {len(rows) - 30} lignes de plus</td></tr>"
        )
    parts.append("</table>")


def render_dashboard_email(
    dashboard_name: str,
    period_days: int,
    widgets: List[dict],
    widget_data: Dict[int, dict],
    custom_message: Optional[str] = None,
) -> str:
    """G\u00e9n\u00e8re le HTML complet de l'email de dashboard."""
    safe_name = html.escape(dashboard_name)
    now_str = clock.now().strftime("%d/%m/%Y \u00e0 %H:%M UTC")

    parts = [
        '<div style="font-family:Arial,sans-serif;max-width:800px;' 'margin:0 auto">',
        '<div style="background:#4F46E5;color:white;padding:20px 24px;'
        'border-radius:8px 8px 0 0">',
        f'<div style="font-size:20px;font-weight:700">' f"&#128202; {safe_name}</div>",
        f'<div style="font-size:13px;margin-top:4px;opacity:0.9">'
        f"Rapport automatique \u2014 P\u00e9riode : {period_days} jours"
        f" \u2014 {now_str}</div>",
        "</div>",
        '<div style="padding:24px;border:1px solid #e5e7eb;border-top:none;'
        'border-radius:0 0 8px 8px">',
    ]

    if custom_message:
        safe_msg = html.escape(custom_message[:1000])
        parts.append(f'<p style="margin:0 0 20px;color:#374151;font-size:14px">' f"{safe_msg}</p>")

    if not widgets:
        parts.append('<p style="color:#9ca3af">Ce dashboard ne contient aucun widget.</p>')
    else:
        sorted_widgets = sorted(widgets, key=lambda w: w.get("position_order", 0))
        for w in sorted_widgets:
            wid = w.get("id")
            data = widget_data.get(wid) or widget_data.get(str(wid), {})
            parts.append(_render_widget_html(w, data))

    parts.append(
        '<p style="margin-top:24px;font-size:12px;color:#9ca3af;'
        'border-top:1px solid #f3f4f6;padding-top:12px">'
        "Ce message a \u00e9t\u00e9 envoy\u00e9 automatiquement par Komptia. "
        "Vous recevez cet email car vous \u00eates abonn\u00e9 \u00e0 la "
        "livraison planifi\u00e9e de ce dashboard.</p>"
    )
    parts.append("</div></div>")
    return "\n".join(parts)


async def send_dashboard_email(
    session: AsyncSession,
    dashboard_id: int,
    user_id: int,
    recipients: Optional[List[str]] = None,
    period_days: int = 30,
    export_format: Optional[str] = None,
    custom_subject: Optional[str] = None,
    custom_message: Optional[str] = None,
) -> Dict[str, Any]:
    """Envoie un dashboard par email (version async).

    Args:
        session: Session DB async
        dashboard_id: ID du dashboard
        user_id: ID du propri\u00e9taire (pour acc\u00e8s aux donn\u00e9es)
        recipients: Liste d'emails
        period_days: P\u00e9riode de donn\u00e9es
        export_format: 'csv' ou 'excel' pour pi\u00e8ce jointe (None = pas de PJ)
        custom_subject: Sujet personnalis\u00e9
        custom_message: Message personnalis\u00e9

    Returns:
        Dict avec success, message, etc.
    """
    from app.models.dashboard import Dashboard
    from app.services.dashboard.dashboard_builder_service import (
        DashboardBuilderService,
    )

    # Load dashboard with widgets — defense-in-depth (tâche #102) :
    # le filtre user_id symétrique évite tout leak cross-user si un futur
    # caller oublie l'ownership check côté handler (alignement avec
    # ``get_all_widget_data`` et ``export_dashboard`` du service builder).
    #
    # Invariant attendu côté scheduler (``send_dashboard_delivery_job``) :
    # ``schedule.user_id == dashboard.user_id`` est garanti par construction
    # à la création du ``DashboardSchedule`` (handler PUT ligne 1473-1477 :
    # ``user_id=self.current_user.id`` qui est déjà passé par
    # ``_load_owned_dashboard_or_response``). Si un futur transfert
    # d'ownership casse cet invariant, ce filtre fera fail-closed avec
    # ``{"success": False, "error": "Dashboard introuvable."}`` (silent
    # disable du schedule via ``_update_schedule_status``) — comportement
    # désiré : refuser l'envoi plutôt que de leaker cross-user.
    result = await session.execute(
        select(Dashboard)
        .options(selectinload(Dashboard.widgets))
        .where(Dashboard.id == dashboard_id, Dashboard.user_id == user_id)
    )
    dashboard = result.scalar_one_or_none()
    if not dashboard:
        return {"success": False, "error": "Dashboard introuvable."}

    # Fail-closed (CLAUDE.md règle #5) : on charge l'owner AVANT tout travail.
    # Un owner absent (orphelin / corruption BDD) ou DÉSACTIVÉ ne doit JAMAIS
    # déclencher d'envoi :
    #  (1) owner=None propagé à l'enforcer RLS = bypass legacy
    #      (``query_executor`` : ``user=None`` → AUCUNE règle data-access
    #      appliquée) → fuite de données Sage non filtrées dans l'email.
    #  (2) un compte désactivé (offboarding : ``admin.py`` met is_active=False
    #      + révoque les sessions, mais NE désactive PAS les DashboardSchedule)
    #      ne doit plus émettre d'activité automatisée.
    # On refuse l'envoi : le caller enregistre l'échec via
    # ``_update_schedule_status`` (le schedule reste ACTIF et re-tentera au
    # prochain tick cron, SANS fuite — il n'est PAS auto-désactivé ; option
    # future : retirer le schedule quand l'owner est désactivé). Réactiver
    # l'user fait repartir l'envoi naturellement (aucun état à restaurer).
    from app.models.user import User as _User

    owner = await session.get(_User, user_id)
    if owner is None or not owner.is_active:
        return {
            "success": False,
            "error": "Propriétaire du tableau de bord introuvable ou désactivé.",
        }

    # Determine recipients \u2014 fallback sur l'email de l'owner (d\u00e9j\u00e0 charg\u00e9 +
    # valid\u00e9 actif ci-dessus ; owner.id == user_id == dashboard.user_id par
    # construction du WHERE). R\u00e9utilise ``owner`` \u2192 \u00e9vite un session.get redondant.
    target_emails = recipients
    if not target_emails or not isinstance(target_emails, list):
        if not owner.email:
            return {
                "success": False,
                "error": "Aucun destinataire configur\u00e9.",
            }
        target_emails = [owner.email]

    valid_emails = [e for e in target_emails if isinstance(e, str) and _EMAIL_RE.match(e)]
    if not valid_emails:
        return {
            "success": False,
            "error": "Aucun email valide parmi les destinataires.",
        }

    # Load SMTP config
    smtp_cfg = await load_smtp_config(session)
    if not smtp_cfg:
        return {"success": False, "error": "SMTP non configur\u00e9."}

    # Get widget data — l'owner (déjà chargé et validé actif ci-dessus) est
    # propagé à l'enforcement RLS (un schedule cron exécute des SQL
    # "comme l'owner").
    service = DashboardBuilderService()
    widget_data = await service.get_all_widget_data(
        session,
        dashboard_id,
        user_id,
        period_override=period_days,
        user=owner,
    )

    widgets_dicts = [w.to_dict() for w in dashboard.widgets]

    # Render email HTML
    body_html = render_dashboard_email(
        dashboard_name=dashboard.name,
        period_days=period_days,
        widgets=widgets_dicts,
        widget_data=widget_data,
        custom_message=custom_message,
    )

    subject = custom_subject or f"[Komptia] Dashboard \u2014 {dashboard.name}"

    # Optionally generate export attachment.
    # Prod-loop task #11 (axe 21 — growth bounded) : la liste
    # ``tmp_paths_to_cleanup`` accumule chaque tempfile créé
    # IMMÉDIATEMENT après ``mkstemp`` (avant le write — couvre les
    # échecs mid-write). Le ``try/finally`` autour du SMTP send garantit
    # le cleanup même si ``send_email`` raise (timeout, auth fail,
    # OSError réseau, SMTPException). Sans ce finally, l'exception
    # propage AVANT ``os.unlink`` → orphelin par retry APScheduler.
    attachments = None
    tmp_paths_to_cleanup: List[str] = []
    try:
        if export_format in ("csv", "excel"):
            try:
                # ``user=owner`` : MÊME enforcement RLS que le corps de l'email
                # (get_all_widget_data plus haut). Sans ça, la PIÈCE JOINTE
                # CSV/Excel tournait avec user=None → bypass legacy de l'executor
                # → fuite de données Sage NON filtrées. owner déjà chargé +
                # validé actif au début de send_dashboard_email.
                export_result = await service.export_dashboard(
                    session,
                    dashboard_id,
                    user_id,
                    export_format,
                    period_days,
                    user=owner,
                )
                if export_result:
                    import tempfile
                    import os

                    filename, file_bytes, content_type = export_result
                    fd, tmp_path = tempfile.mkstemp(
                        suffix=".xlsx" if export_format == "excel" else ".csv"
                    )
                    tmp_paths_to_cleanup.append(tmp_path)
                    os.close(fd)
                    with open(tmp_path, "wb") as f:
                        f.write(file_bytes)
                    attachments = [
                        {
                            "path": tmp_path,
                            "filename": filename,
                            "content_type": content_type,
                        }
                    ]
            except Exception:
                logger.warning(
                    "Erreur g\u00e9n\u00e9ration export dashboard %d",
                    dashboard_id,
                    exc_info=True,
                )
                # Continue without attachment

        # Send email — Q2 cycle 15 : factory unique. Pas de hardcode "Komptia" :
        # si la config explicite n'a pas de from_name, on lit le branding admin
        # via get_smtp_from_name() (axe 6 : généricité).
        from app.services.email.smtp_factory import build_smtp_client_from_dict

        smtp_client = build_smtp_client_from_dict(
            smtp_cfg,
            from_name_override=smtp_cfg.get("from_name") or get_smtp_from_name(),
        )

        from app.services.email.template_names import EmailTemplate

        send_result = await smtp_client.send_email(
            to_emails=valid_emails,
            subject=subject,
            body_html=body_html,
            attachments=attachments,
            sent_by_user_id=user_id,
            template_name=EmailTemplate.DASHBOARD_DELIVERY.value,
        )

        return send_result
    finally:
        if tmp_paths_to_cleanup:
            import os

            for path in tmp_paths_to_cleanup:
                try:
                    os.unlink(path)
                except OSError:
                    pass


def send_dashboard_delivery_job(schedule_id: int) -> None:
    """Job synchrone pour APScheduler \u2014 envoie un dashboard planifi\u00e9.

    Runs in APScheduler's ThreadPoolExecutor.
    Uses IOLoop.add_callback to delegate to async code.
    """
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session

        from app.core.database import get_db_url
        from app.models.dashboard import Dashboard, DashboardSchedule
        from app.models.user import User

        engine = create_engine(get_db_url())
        try:
            with Session(engine) as session:
                schedule = session.get(DashboardSchedule, schedule_id)
                if not schedule:
                    logger.warning("DashboardSchedule #%d introuvable", schedule_id)
                    return

                if not schedule.is_active:
                    logger.debug("DashboardSchedule #%d: inactif, skip", schedule_id)
                    return

                dashboard = session.get(Dashboard, schedule.dashboard_id)
                if not dashboard:
                    logger.warning(
                        "Dashboard #%d introuvable (schedule #%d)",
                        schedule.dashboard_id,
                        schedule_id,
                    )
                    return

                # Get recipients
                recipients = schedule.recipients
                if not recipients or not isinstance(recipients, list):
                    user = session.get(User, schedule.user_id)
                    if not user or not user.email:
                        logger.warning(
                            "Schedule #%d: pas de destinataire",
                            schedule_id,
                        )
                        return
                    recipients = [user.email]

                valid_emails = [e for e in recipients if isinstance(e, str) and _EMAIL_RE.match(e)]
                if not valid_emails:
                    return

                # Capture values for async callback
                dash_id = schedule.dashboard_id
                owner_id = schedule.user_id
                fmt = schedule.export_format
                subj = schedule.subject
                msg = schedule.message
                sid = schedule.id

                from tornado.ioloop import IOLoop

                async def _async_send():
                    from app.core.database import get_session_factory

                    factory = get_session_factory()
                    async with factory() as async_session:
                        result = await send_dashboard_email(
                            async_session,
                            dash_id,
                            owner_id,
                            recipients=valid_emails,
                            period_days=30,
                            export_format=fmt,
                            custom_subject=subj,
                            custom_message=msg,
                        )
                        # Update schedule status
                        _update_schedule_status(sid, result)

                try:
                    loop = IOLoop.current()
                    loop.add_callback(_async_send)
                    logger.info(
                        "Schedule #%d (dashboard #%d): " "livraison lanc\u00e9e vers %s",
                        schedule_id,
                        dash_id,
                        ", ".join(valid_emails),
                    )
                except RuntimeError:
                    logger.warning("Schedule #%d: pas d'IOLoop", schedule_id)

        finally:
            engine.dispose()
    except Exception:
        logger.error("Erreur livraison schedule #%d", schedule_id, exc_info=True)


def _update_schedule_status(schedule_id: int, result: Dict[str, Any]) -> None:
    """Met \u00e0 jour last_sent_at / last_status / last_error (sync)."""
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session

        from app.core.database import get_db_url
        from app.models.dashboard import DashboardSchedule

        engine = create_engine(get_db_url())
        try:
            with Session(engine) as session:
                schedule = session.get(DashboardSchedule, schedule_id)
                if schedule:
                    schedule.last_sent_at = clock.now()
                    if result.get("success"):
                        schedule.last_status = "success"
                        schedule.last_error = None
                    else:
                        schedule.last_status = "failure"
                        err = result.get("error", "Erreur inconnue")
                        schedule.last_error = str(err)[:500]
                    session.commit()
        finally:
            engine.dispose()
    except (SQLAlchemyError, OSError):
        logger.warning("Erreur MAJ statut schedule #%d", schedule_id, exc_info=True)


def _load_smtp_config_sync(session) -> Optional[Dict[str, Any]]:
    """Charge la config SMTP (version sync pour APScheduler)."""
    try:
        from app.models.smtp_global_config import SMTPGlobalConfig

        result = session.execute(
            select(SMTPGlobalConfig).order_by(SMTPGlobalConfig.id.desc()).limit(1)
        )
        smtp_cfg = result.scalar_one_or_none()
    except SQLAlchemyError:
        logger.warning("Erreur lecture SMTP sync", exc_info=True)
        smtp_cfg = None

    if smtp_cfg and smtp_cfg.enabled:
        # #69 (B6-F1) — le password SMTP est chiffré at-rest en BDD (Fernet, parité
        # db-config/ai-config). Il DOIT être déchiffré avant d'être passé à
        # build_smtp_client_from_dict (qui consomme cfg["password"] tel quel). Sans
        # ce decrypt, ce chemin sync APScheduler (envoi planifié des dashboards)
        # passait le TOKEN chiffré comme mot de passe → échec d'auth SMTP SILENCIEUX
        # (tâche de fond, aucun user devant l'écran). Les autres lecteurs BDD
        # (smtp_factory, admin_smtp) déchiffrent déjà ; ce site était le seul oublié.
        # ``_lenient`` = compat legacy clair (déploiement pré-chiffrement) → no-op.
        from app.services.email.smtp_factory import decrypt_smtp_password_lenient

        return {
            "host": smtp_cfg.host,
            "port": smtp_cfg.port,
            "username": smtp_cfg.username,
            "password": decrypt_smtp_password_lenient(smtp_cfg.password),
            "use_tls": smtp_cfg.use_tls,
            "from_email": smtp_cfg.from_email,
            "from_name": smtp_cfg.from_name,
            "max_retries": smtp_cfg.max_retries,
            "retry_delay": smtp_cfg.retry_delay,
        }

    if config.smtp.host and config.smtp.username:
        return {
            "host": config.smtp.host,
            "port": config.smtp.port,
            "username": config.smtp.username,
            "password": config.smtp.password,
            "use_tls": config.smtp.use_tls,
            "from_email": config.smtp.from_email,
            "from_name": config.smtp.from_name,
            "max_retries": 3,
            "retry_delay": 5,
        }

    return None
