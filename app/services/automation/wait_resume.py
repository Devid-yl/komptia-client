"""Utilities for the ``email_wait_response`` step lifecycle.

Three responsibilities :

1. ``compute_wait_expires_at`` — TTL adaptatif selon le schedule de
   l'auto. Pour cron : next_run - 5min (eviter conflit avec prochain run).
   Pour once / manuel : 30j default. Override via wait_timeout_hours.

2. ``serialize_wait_checkpoint`` / ``deserialize_wait_checkpoint`` —
   Snapshot des ``step_outputs`` (workbooks in-memory) et
   ``step_output_files`` (paths de fichiers PDF/xlsx) au moment du wait,
   pour rehydrate au resume sans re-exec les steps deja faits.

3. ``send_wait_request_email`` — Compose et envoie le mail au destinataire
   avec le lien tokenise. Utilise le SMTPClient existant via
   ``smtp_factory.build_smtp_client_from_dict``.

La fonction ``resume_automation`` (reprise reelle du DAG) vit dans
``executor.py`` car elle a besoin d'un acces direct a l'executor pour
relancer le DAG depuis le checkpoint. Ce module se limite aux helpers.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.core import clock
from app.services.email.template_names import EmailTemplate as _EmailTemplate
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Defaults
_DEFAULT_FALLBACK_HOURS = 24 * 30  # 30 jours pour autos one-shot/manuelles
_MAX_WAIT_HOURS = 24 * 30  # Cap dur (securite HMAC + risque oubli backlog)
_MIN_WAIT_HOURS = 1  # Plancher : un wait < 1h est suspect (typo user)
_NEXT_RUN_SAFETY_MARGIN_MINUTES = 5  # Eviter le conflit pile au prochain run


def compute_wait_expires_at(
    automation: Any,
    *,
    requested_hours: int = 0,
    now: Optional[datetime] = None,
) -> datetime:
    """Calcule l'expiration d'un WaitToken selon le schedule de l'auto.

    Args:
        automation: l'objet Automation (a au moins ``schedule_type`` et
            ``schedule_config`` ou methode ``next_run_after``).
        requested_hours: override admin (>0). 0 = auto.
        now: timestamp courant (pour tests deterministes). Default UTC.

    Returns:
        ``datetime`` UTC d'expiration.

    Logique :
    - Override > 0 : utilise tel quel, clampe entre 1h et 30j.
    - Sinon, si l'auto a un cron recurrent : next_run - 5min.
    - Sinon (one-shot ou manuel) : now + 30j.

    Garantit : expires_at > now (toujours dans le futur).
    """
    if now is None:
        now = clock.now()

    # Override explicite (admin) → respect avec clamp
    if requested_hours and requested_hours > 0:
        hours = max(_MIN_WAIT_HOURS, min(requested_hours, _MAX_WAIT_HOURS))
        return now + timedelta(hours=hours)

    # Auto : derivation depuis le schedule
    next_run = _next_scheduled_run(automation, after=now)
    if next_run is not None and next_run > now:
        candidate = next_run - timedelta(minutes=_NEXT_RUN_SAFETY_MARGIN_MINUTES)
        if candidate > now:
            # Clamp aussi au cap dur (un cron annuel ne ferait pas un
            # wait de 1 an — c'est un over-engineering inutile).
            cap = now + timedelta(hours=_MAX_WAIT_HOURS)
            return min(candidate, cap)

    # Fallback : 30 jours
    return now + timedelta(hours=_DEFAULT_FALLBACK_HOURS)


def _next_scheduled_run(automation: Any, *, after: datetime) -> Optional[datetime]:
    """Retourne la prochaine execution planifiee apres ``after``, ou None.

    Utilise APScheduler si possible (job_id = ``automation_<id>``), sinon
    None. Fallback gracieux : si APScheduler n'est pas joignable, on
    retombe sur la logique 30j.
    """
    try:
        from app.services.automation.scheduler import get_scheduler

        sched = get_scheduler()
        if sched is None:
            return None
        job_id = f"automation_{automation.id}"
        job = sched.scheduler.get_job(job_id)
        if job is None or job.next_run_time is None:
            return None
        nrt = job.next_run_time
        # Normaliser en UTC tz-aware (APScheduler peut renvoyer aware
        # avec tz != UTC).
        if nrt.tzinfo is None:
            nrt = nrt.replace(tzinfo=timezone.utc)
        else:
            nrt = nrt.astimezone(timezone.utc)
        return nrt if nrt > after else None
    except Exception:  # noqa: BLE001 — fallback safe
        logger.debug("compute_wait_expires_at: APScheduler indisponible, fallback 30j")
        return None


def serialize_wait_checkpoint(
    *,
    step_outputs: Dict[int, Optional[Dict[str, Any]]],
    step_output_files: Dict[int, Any],
    executed_step_ids: List[int],
    wait_token_id: int,
    wait_step_id: int,
    reminder_hours_before: int = 0,
) -> Dict[str, Any]:
    """Serialise les step_outputs en JSON-safe pour ``Execution.wait_checkpoint``.

    Les workbooks sont des dicts JSON-natifs (deja le format DAG).
    Les paths fichiers (Path → str). Les step_outputs avec des objets
    non-JSON (datetime, Decimal) sont stringifies via ``default=str``
    au moment de la persistance SQLAlchemy (colonne JSON).

    Format :
        {
            "version": 1,
            "wait_token_id": int,
            "wait_step_id": int,
            "reminder_hours_before": int,
            "step_outputs": {step_id: workbook_dict_or_null},
            "step_output_files": {step_id: file_path_str},
            "executed_step_ids": [int, ...],
            "created_at": iso_str,
        }
    """
    return {
        "version": 1,
        "wait_token_id": wait_token_id,
        "wait_step_id": wait_step_id,
        "reminder_hours_before": int(reminder_hours_before or 0),
        # Convertir keys en str (JSON ne supporte pas les keys int)
        "step_outputs": {str(sid): wb for sid, wb in (step_outputs or {}).items()},
        "step_output_files": {
            str(sid): str(path) for sid, path in (step_output_files or {}).items()
        },
        "executed_step_ids": list(executed_step_ids or []),
        "created_at": clock.now().isoformat(),
    }


def deserialize_wait_checkpoint(
    checkpoint: Dict[str, Any],
) -> Dict[str, Any]:
    """Reconstruit les structures runtime a partir du JSON persiste.

    Returns:
        ``{
            "step_outputs": {int: workbook | None},
            "step_output_files": {int: Path},
            "executed_step_ids": [int, ...],
            "wait_token_id": int,
            "wait_step_id": int,
            "reminder_hours_before": int,
        }``
    """
    if not isinstance(checkpoint, dict):
        raise ValueError("Checkpoint invalide (pas un dict)")
    raw_outputs = checkpoint.get("step_outputs") or {}
    raw_files = checkpoint.get("step_output_files") or {}
    return {
        "step_outputs": {int(k): v for k, v in raw_outputs.items()},
        "step_output_files": {int(k): Path(v) for k, v in raw_files.items()},
        "executed_step_ids": [int(s) for s in checkpoint.get("executed_step_ids") or []],
        "wait_token_id": int(checkpoint.get("wait_token_id", 0)),
        "wait_step_id": int(checkpoint.get("wait_step_id", 0)),
        "reminder_hours_before": int(checkpoint.get("reminder_hours_before", 0)),
    }


async def send_wait_request_email(
    *,
    smtp_config: Optional[Dict[str, Any]],
    automation: Any,
    execution_id: int,
    step_name: str,
    recipient: str,
    subject: str,
    body: str,
    token_public: str,
    response_kind: str,
    file_format: str,
    expires_at: datetime,
    attachments: Optional[List[str]] = None,
) -> None:
    """Envoie le mail au destinataire avec le lien tokenise.

    Ne fait PAS de retry custom : le SMTPClient gere deja les retries via
    ``max_retries`` / ``retry_delay`` configures dans SMTPGlobalConfig.
    Si l'envoi echoue definitivement, on raise et le caller (executor)
    rollback la WaitToken row.

    Args:
        smtp_config: dict de config SMTP (host/port/...). None si
            indispo → erreur explicite (envoi impossible).
        recipient: email unique du destinataire.
        token_public: token a inclure dans l'URL.
        ...
    """
    if not smtp_config:
        raise ValueError(
            "Configuration SMTP indisponible — impossible d'envoyer le mail. "
            "Configurer via /admin/smtp."
        )

    from app.services.email.smtp_factory import build_smtp_client_from_dict
    from app.services.branding import get_company_name
    from app.config import config as app_config

    # Cluster-X 2026-05-26 — Élimination du fallback hardcodé
    # `http://127.0.0.1:8888` qui produisait des emails avec liens
    # cassés pour les destinataires externes (cabinet déployé en prod
    # avec public_base_url non configuré). On log un WARNING actionnable
    # et on continue avec un placeholder explicite qui signale à
    # l'utilisateur final que la config admin est incomplète.
    server_cfg = getattr(app_config, "server", None)
    public_base_url = getattr(server_cfg, "public_base_url", None) if server_cfg else None
    if not public_base_url:
        logger.error(
            "Cluster-X : public_base_url non configurée. Email wait_response "
            "envoie un lien avec placeholder. Configurer via /admin/server."
        )
        # Placeholder visible dans l'email — l'admin verra l'incident.
        public_base_url = "http://[komptia-non-configure]"
    base_url = public_base_url.rstrip("/")
    wait_url = f"{base_url}/automations/wait/{token_public}"

    company_name = get_company_name()
    expires_local = expires_at.strftime("%d/%m/%Y a %H:%M UTC")

    # Description du type de reponse pour l'utilisateur
    if response_kind == "text":
        kind_desc = "Une reponse texte est attendue."
    elif response_kind == "file":
        if file_format == "csv":
            kind_desc = "Un fichier CSV est attendu en piece jointe."
        elif file_format == "xlsx":
            kind_desc = "Un fichier Excel (.xlsx) est attendu en piece jointe."
        else:
            kind_desc = "Un fichier CSV ou Excel est attendu en piece jointe."
    else:  # both
        kind_desc = "Une reponse texte ET/OU un fichier (CSV/Excel) sont attendus."

    # Body HTML simple (le body user est inseré tel quel mais escape).
    import html as _html

    body_safe = _html.escape(body) if body else ""
    body_html = body_safe.replace("\n", "<br/>") if body_safe else ""

    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height:1.5; color:#333; max-width:600px; margin:0 auto; padding:20px;">
  <h2 style="color:#111;">{_html.escape(subject)}</h2>
  {f"<div>{body_html}</div><br/>" if body_html else ""}
  <p>{_html.escape(kind_desc)}</p>
  <p style="margin:24px 0;">
    <a href="{wait_url}" style="display:inline-block; padding:12px 24px; background:#2563eb; color:#fff; text-decoration:none; border-radius:6px; font-weight:500;">Repondre</a>
  </p>
  <p style="font-size:12px; color:#666;">
    Lien valable jusqu'au <strong>{expires_local}</strong>.<br/>
    Si vous ne pouvez pas cliquer le bouton, copiez ce lien :<br/>
    <a href="{wait_url}" style="color:#2563eb; word-break:break-all;">{wait_url}</a>
  </p>
  <hr style="border:none; border-top:1px solid #eee; margin:24px 0;"/>
  <p style="font-size:11px; color:#999;">
    Demande envoyee par <strong>{_html.escape(company_name)}</strong>.<br/>
    Automatisation : {_html.escape(getattr(automation, "name", "") or "")} (execution #{execution_id}, etape « {_html.escape(step_name)} »)
  </p>
</body>
</html>"""

    text_content = (f"{subject}\n\n" f"{body}\n\n" if body else "") + (
        f"{kind_desc}\n\n"
        f"Repondre : {wait_url}\n\n"
        f"Lien valable jusqu'au {expires_local}.\n\n"
        f"---\n"
        f"Demande envoyee par {company_name}.\n"
        f"Automatisation : {getattr(automation, 'name', '') or ''} "
        f"(execution #{execution_id}, etape « {step_name} »)"
    )

    smtp_client = build_smtp_client_from_dict(smtp_config)
    if smtp_client is None:
        raise ValueError("Configuration SMTP invalide (host/port/user/password manquants).")

    result = await smtp_client.send_email(
        to_emails=[recipient],
        subject=subject,
        body_text=text_content,
        body_html=html_content,
        attachments=attachments or None,
        reply_to=None,
        automation_id=getattr(automation, "id", None),
        execution_id=execution_id,
        sent_by_user_id=getattr(automation, "user_id", None),
        template_name=_EmailTemplate.WAIT_REQUEST.value,
    )
    if not (result and result.get("success")):
        err = (result or {}).get("error") or "raison inconnue"
        raise RuntimeError(f"Envoi mail echec : {err}")


async def convert_response_to_workbook(
    wait_row: Any,
    step_name: str = "Reponse destinataire",
) -> Dict[str, Any]:
    """Convertit la reponse d'un WaitToken en workbook Komptia.

    - response_kind == "text" → 1 onglet avec colonne "reponse_texte"
      contenant la chaine soumise (ou vide si absente).
    - response_kind == "file" → charge le fichier (CSV ou XLSX) en
      onglet via les loaders existants ``external_sheets``.
    - response_kind == "both" → onglet "Reponse texte" + onglet
      "Reponse fichier" (s'ils existent).

    Le workbook resultant a le format DAG standard (cf. `workbook_service`)
    et peut etre passe aux steps aval (rapport, format_copilot, etc.).
    """
    from app.services.automation.workbook_service import rows_to_workbook

    kind = (getattr(wait_row, "response_kind", "text") or "text").lower()
    text = getattr(wait_row, "response_text", None) or ""
    file_path = getattr(wait_row, "response_file_path", None)
    file_name = getattr(wait_row, "response_file_name", None) or "reponse"

    text_tab: Optional[Dict[str, Any]] = None
    file_workbook: Optional[Dict[str, Any]] = None

    if kind in ("text", "both") and text:
        text_wb = rows_to_workbook(
            [{"reponse_texte": text}],
            tab_label=f"{step_name} — texte",
        )
        text_tab = (text_wb.get("tabs") or [None])[0]

    if kind in ("file", "both") and file_path:
        try:
            from app.services.external_sheets import (
                load_csv_file,
                load_excel_sheet,
            )
        except ImportError:
            load_csv_file = None  # type: ignore[assignment]
            load_excel_sheet = None  # type: ignore[assignment]

        ext = Path(file_path).suffix.lower()
        try:
            if ext == ".csv" and load_csv_file is not None:
                rows = await load_csv_file(file_path)
            elif ext == ".xlsx" and load_excel_sheet is not None:
                rows = await load_excel_sheet(file_path)
            else:
                logger.warning("convert_response_to_workbook: extension non geree '%s'", ext)
                rows = []
            if rows:
                file_workbook = rows_to_workbook(rows, tab_label=f"{step_name} — {file_name}")
        except Exception:  # noqa: BLE001 — robustesse resume
            logger.exception("convert_response_to_workbook: load fichier echec '%s'", file_path)

    # Fusion finale en 1 workbook avec 0..2 onglets.
    tabs: List[Dict[str, Any]] = []
    if text_tab is not None:
        tabs.append(text_tab)
    if file_workbook is not None:
        tabs.extend(file_workbook.get("tabs") or [])
    if not tabs:
        # Aucune donnee exploitable → workbook 1 cellule "vide" pour
        # signaler qu'une reponse a ete soumise sans contenu utile.
        empty_wb = rows_to_workbook(
            [{"reponse": "(reponse vide)"}],
            tab_label=f"{step_name} — vide",
        )
        tabs = empty_wb.get("tabs") or []
    return {"version": 1, "app": "komptia", "tabs": tabs, "warnings": []}


async def expire_overdue_wait_tokens() -> Dict[str, int]:
    """Cleanup periodique : expire les WaitToken dont expires_at est depasse.

    Pour chaque token expire :
    - mark `WaitToken.status = 'expired'`
    - mark Execution `failed` avec message clair (le destinataire n'a
      jamais repondu, l'auto ne peut pas reprendre)
    - notif owner par mail (best-effort)
    - purge le wait_checkpoint sur Execution (libere espace BDD)

    Returns:
        ``{"expired": N, "notified": M}`` pour les logs.
    """
    from sqlalchemy import select as _select
    from app.core.database import get_session_factory
    from app.models.automation import Automation
    from app.models.execution import Execution
    from app.models.user import User
    from app.models.wait_token import WaitToken
    from app.services.email.smtp_factory import load_smtp_config_dict

    sf = get_session_factory()
    now = clock.now()
    expired_count = 0
    notif_jobs: List[Tuple[str, str, str, int, Optional[int], Optional[int]]] = (
        []
    )  # (owner_email, auto_name, recipient, exec_id, automation_id, automation_user_id)

    # Cluster-G (G3) 2026-05-26 — chunking pour éviter OOM si l'app est
    # down 7+ jours et 10k+ tokens expirent en backlog. Pattern aligné
    # sur ``db_retention._cleanup_table_by_age`` (LIMIT N + commit/chunk).
    # Chaque chunk marque les rows ``status='expired'`` → la requête
    # suivante ne les voit plus → terminaison naturelle de la boucle.
    _CHUNK_SIZE = 500

    async with sf() as sess:
        while True:
            rows_q = await sess.execute(
                _select(WaitToken)
                .where(
                    WaitToken.status == "pending",
                    WaitToken.expires_at < now,
                )
                .limit(_CHUNK_SIZE)
            )
            rows = list(rows_q.scalars().all())
            if not rows:
                break
            for token in rows:
                token.mark_expired()
                exec_row = await sess.get(Execution, token.execution_id)
                if exec_row is not None and exec_row.status == "waiting":
                    exec_row.mark_failed(
                        error_message=(
                            f"Aucune reponse recue de {token.recipient_email} "
                            f"avant l'echeance ({token.expires_at.isoformat()})."
                        ),
                    )
                    exec_row.wait_checkpoint = None
                    # Charge auto + owner pour la notif
                    auto = await sess.get(Automation, exec_row.automation_id)
                    if auto is not None:
                        owner = await sess.get(User, auto.user_id)
                        if owner is not None and getattr(owner, "email", None):
                            notif_jobs.append(
                                (
                                    owner.email,
                                    auto.name or f"Automation #{auto.id}",
                                    token.recipient_email,
                                    exec_row.id,
                                    auto.id,
                                    auto.user_id,
                                )
                            )
                expired_count += 1
            # Commit chaque chunk pour libérer le WAL et permettre aux
            # autres writes de progresser (cf. doctrine db_retention).
            await sess.commit()
            if len(rows) < _CHUNK_SIZE:
                break  # dernier chunk traité

        if expired_count > 0:
            logger.info(
                "expire_overdue_wait_tokens: %d token(s) expire(s)",
                expired_count,
            )

    # Notifs owner (best-effort, hors transaction)
    notified = 0
    if notif_jobs:
        try:
            smtp_config = await load_smtp_config_dict()
        except Exception:  # noqa: BLE001
            smtp_config = None
        if smtp_config:
            from app.services.email.smtp_factory import build_smtp_client_from_dict

            client = build_smtp_client_from_dict(smtp_config)
            if client is not None:
                from app.services.branding import get_company_name

                company = get_company_name()
                for owner_email, auto_name, recipient, exec_id, auto_id, auto_user_id in notif_jobs:
                    try:
                        await client.send_email(
                            to_emails=[owner_email],
                            subject=f"{company} — Tache expiree : {auto_name}",
                            body_text=(
                                f"Bonjour,\n\n"
                                f"L'automatisation « {auto_name} » (execution #{exec_id}) "
                                f"attendait une reponse de {recipient}, mais aucune reponse "
                                f"n'a ete recue avant l'echeance.\n\n"
                                f"L'execution est marquee « echouee ». Vous pouvez la "
                                f"re-jouer manuellement ou attendre la prochaine execution "
                                f"planifiee.\n\n"
                                f"{company}"
                            ),
                            body_html=None,
                            automation_id=auto_id,
                            execution_id=exec_id,
                            sent_by_user_id=auto_user_id,
                            template_name=_EmailTemplate.WAIT_EXPIRED_NOTIF.value,
                        )
                        notified += 1
                    except Exception:  # noqa: BLE001
                        logger.warning(
                            "expire_overdue: notif owner echec %s",
                            owner_email,
                            exc_info=True,
                        )

    return {"expired": expired_count, "notified": notified}


async def send_wait_reminders() -> Dict[str, int]:
    """Cleanup periodique : envoie un rappel aux owners pour les WaitToken
    qui approchent de l'expiration et n'ont pas encore eu de rappel.

    Le delai de rappel est lu depuis ``Execution.wait_checkpoint.reminder_hours_before``
    (configurable par l'user au step). Si 0 = pas de rappel.

    Returns:
        ``{"reminded": N}``
    """
    from sqlalchemy import select as _select
    from app.core.database import get_session_factory
    from app.models.automation import Automation
    from app.models.execution import Execution
    from app.models.user import User
    from app.models.wait_token import WaitToken
    from app.services.email.smtp_factory import load_smtp_config_dict

    sf = get_session_factory()
    now = clock.now()
    reminders: List[Tuple[Any, str, str, int, int, Optional[int]]] = (
        []
    )  # (token, owner_email, auto_name, exec_id, automation_id, automation_user_id)

    async with sf() as sess:
        rows_q = await sess.execute(
            _select(WaitToken).where(
                WaitToken.status == "pending",
                WaitToken.reminder_sent_at.is_(None),
            )
        )
        for token in rows_q.scalars().all():
            exec_row = await sess.get(Execution, token.execution_id)
            if exec_row is None or exec_row.status != "waiting":
                continue
            checkpoint = exec_row.wait_checkpoint or {}
            reminder_h = int(checkpoint.get("reminder_hours_before", 0) or 0)
            if reminder_h <= 0:
                continue
            from app.models.base import ensure_utc as _eu

            time_left = _eu(token.expires_at) - now
            if time_left.total_seconds() <= 0:
                continue  # deja expire, sera traite par expire_overdue
            if time_left > timedelta(hours=reminder_h):
                continue  # encore trop tot pour le rappel
            auto = await sess.get(Automation, exec_row.automation_id)
            owner = await sess.get(User, auto.user_id) if auto else None
            if not (owner and getattr(owner, "email", None)):
                continue
            reminders.append(
                (token, owner.email, auto.name or "", exec_row.id, auto.id, auto.user_id)
            )
            token.reminder_sent_at = now
        if reminders:
            await sess.commit()

    if not reminders:
        return {"reminded": 0}

    try:
        smtp_config = await load_smtp_config_dict()
    except Exception:  # noqa: BLE001
        smtp_config = None
    if not smtp_config:
        return {"reminded": 0}

    from app.services.email.smtp_factory import build_smtp_client_from_dict

    client = build_smtp_client_from_dict(smtp_config)
    if client is None:
        return {"reminded": 0}

    from app.services.branding import get_company_name

    company = get_company_name()
    reminded = 0
    for token, owner_email, auto_name, exec_id, auto_id, auto_user_id in reminders:
        time_left = (clock.now() - token.expires_at).total_seconds() / 3600.0
        # time_left est negatif (futur) — on prend abs en heures
        h_left = max(0, int(round(abs(time_left))))
        try:
            await client.send_email(
                to_emails=[owner_email],
                subject=f"{company} — Rappel : reponse en attente ({auto_name})",
                body_text=(
                    f"Bonjour,\n\n"
                    f"L'automatisation « {auto_name} » (execution #{exec_id}) "
                    f"attend une reponse de {token.recipient_email}.\n"
                    f"Le lien expire dans environ {h_left}h.\n\n"
                    f"Si vous voulez relancer une demande, vous pouvez "
                    f"re-executer manuellement l'automatisation.\n\n"
                    f"{company}"
                ),
                body_html=None,
                automation_id=auto_id,
                execution_id=exec_id,
                sent_by_user_id=auto_user_id,
                template_name=_EmailTemplate.WAIT_REMINDER.value,
            )
            reminded += 1
        except Exception:  # noqa: BLE001
            logger.warning(
                "send_wait_reminders: notif echec %s",
                owner_email,
                exc_info=True,
            )

    if reminded:
        logger.info("send_wait_reminders: %d rappel(s) envoye(s)", reminded)
    return {"reminded": reminded}


_DEFAULT_WAIT_TOKEN_RETENTION_DAYS = 30


def _wait_token_retention_days() -> int:
    """Rétention des WaitToken TERMINAUX (env ``WAIT_TOKEN_RETENTION_DAYS``)."""
    import os

    raw = os.environ.get("WAIT_TOKEN_RETENTION_DAYS", str(_DEFAULT_WAIT_TOKEN_RETENTION_DAYS))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_WAIT_TOKEN_RETENTION_DAYS
    return max(1, value)


def _purge_wait_upload_dirs(token_hashes: List[str]) -> int:
    """Retire les dossiers d'upload ``wait_uploads/{token_hash[:16]}`` des tokens
    purgés (A7-M11). Best-effort + garde-fou anti-traversal (refuse tout chemin
    hors de la racine ``wait_uploads``). SSoT du chemin = ``_wait_uploads_dir``
    (import paresseux : évite un cycle service→handler au chargement)."""
    import shutil

    try:
        from app.handlers.wait_response import _wait_uploads_dir
    except Exception:  # noqa: BLE001 — pas de cleanup FS si le helper est indispo
        return 0

    try:
        root = _wait_uploads_dir().resolve()
    except OSError:
        return 0

    removed = 0
    for token_hash in token_hashes:
        if not token_hash:
            continue
        try:
            target = (root / token_hash[:16]).resolve()
            target.relative_to(root)  # anti-traversal
        except (ValueError, OSError):
            continue
        if target.is_dir():
            try:
                shutil.rmtree(target)
                removed += 1
            except OSError:
                logger.warning("purge_wait_upload_dirs: rmtree échec %s", target)
    return removed


async def purge_terminal_wait_tokens() -> Dict[str, int]:
    """Cleanup rétention (axe 21) : SUPPRIME les ``WaitToken`` TERMINAUX
    (resolved/expired/cancelled) plus vieux que ``WAIT_TOKEN_RETENTION_DAYS``,
    + leurs dossiers d'upload (A7-M11/M12).

    Sans ça, ``F_WAIT_TOKEN`` (qui contient du PII : ``recipient_email``) et les
    fichiers uploadés par les destinataires croissent à VIE. La réponse utile
    vit déjà dans l'output de l'``Execution`` — le token n'est qu'un artefact
    d'auth, inutile une fois terminal. Idempotent, chunké (anti-OOM),
    best-effort sur le filesystem.
    """
    from sqlalchemy import select as _select, delete as _delete
    from app.core.database import get_session_factory
    from app.models.wait_token import WaitToken

    sf = get_session_factory()
    cutoff = clock.now() - timedelta(days=_wait_token_retention_days())
    _TERMINAL = ("resolved", "expired", "cancelled")
    _CHUNK_SIZE = 500
    purged = 0
    hashes: List[str] = []

    async with sf() as sess:
        while True:
            rows = (
                await sess.execute(
                    _select(WaitToken.id, WaitToken.token_hash)
                    .where(
                        WaitToken.status.in_(_TERMINAL),
                        WaitToken.created_at < cutoff,
                    )
                    .limit(_CHUNK_SIZE)
                )
            ).all()
            if not rows:
                break
            ids = [r[0] for r in rows]
            hashes.extend(r[1] for r in rows if r[1])
            await sess.execute(_delete(WaitToken).where(WaitToken.id.in_(ids)))
            await sess.commit()
            purged += len(ids)
            if len(rows) < _CHUNK_SIZE:
                break

    dirs_removed = _purge_wait_upload_dirs(hashes) if hashes else 0
    return {"purged": purged, "dirs_removed": dirs_removed}


def cleanup_wait_tokens_job() -> None:
    """Sync wrapper pour APScheduler. Bridge vers asyncio.

    Cumule expire_overdue_wait_tokens + send_wait_reminders + purge rétention
    en un seul job (toutes les 15 min). Best-effort : un crash partiel ne
    bloque pas le job suivant.
    """
    import asyncio as _asyncio

    from app.services.email.smtp_client import run_then_drain_email_log

    async def _run() -> None:
        try:
            stats_exp = await expire_overdue_wait_tokens()
            if stats_exp.get("expired"):
                logger.info("cleanup_wait_tokens: %s", stats_exp)
        except Exception:  # noqa: BLE001
            logger.exception("cleanup_wait_tokens: expire crash")
        try:
            stats_rem = await send_wait_reminders()
            if stats_rem.get("reminded"):
                logger.info("cleanup_wait_tokens: %s", stats_rem)
        except Exception:  # noqa: BLE001
            logger.exception("cleanup_wait_tokens: reminders crash")
        try:
            stats_purge = await purge_terminal_wait_tokens()
            if stats_purge.get("purged") or stats_purge.get("dirs_removed"):
                logger.info("cleanup_wait_tokens: %s", stats_purge)
        except Exception:  # noqa: BLE001
            logger.exception("cleanup_wait_tokens: purge crash")

    try:
        _asyncio.run(run_then_drain_email_log(_run()))
    except Exception:  # noqa: BLE001
        logger.exception("cleanup_wait_tokens_job: asyncio.run crash")


async def cancel_pending_waits_for_automation(
    automation_id: int,
    *,
    reason: str = "Annulee : nouvelle execution declenchee",
    step_id: Optional[int] = None,
    notify_owner: bool = True,
) -> int:
    """Annule toutes les Executions ``waiting`` + leurs WaitTokens pendant
    pour une automation donnee.

    Use case principal : cancel-on-next-run. Quand une nouvelle
    execution (scheduled / manual / webhook) demarre, on ne veut pas
    laisser l'execution precedente bloquee en attente — on l'annule
    proprement, on invalide tous les tokens, et on notifie les
    destinataires que leur reponse n'est plus attendue.

    Best-effort sur les emails : si l'envoi echec, on log et on continue
    (l'annulation BDD a deja eu lieu, le destinataire decouvrira juste
    le 410 quand il cliquera).

    Args:
        automation_id: l'auto dont on annule les waits.
        reason: message stocke dans WaitToken.cancellation_reason
                + Execution.error_message + dans le mail.
        step_id: Cluster-S 2026-05-26 — si fourni, ne cancel QUE les
                tokens liés à ce step (cas DELETE step). Si None, cancel
                tous les tokens de l'auto (cas DELETE auto / toggle off).
        notify_owner: Cluster-S 2026-05-26 — si True (défaut), envoie un
                résumé au propriétaire de l'auto en plus des destinataires
                (mirror :func:`expire_overdue_wait_tokens` pour cohérence).
                False = silent cancel (cas cancel-on-next-run où l'owner
                a déjà déclenché lui-même la re-exec).

    Returns:
        Le nombre d'Executions annulees.
    """
    from sqlalchemy import select as _select
    from app.core.database import get_session_factory
    from app.models.execution import Execution
    from app.models.wait_token import WaitToken
    from app.services.email.smtp_factory import load_smtp_config_dict

    sf = get_session_factory()
    cancelled_count = 0
    cancelled_recipients: List[str] = []

    async with sf() as sess:
        execs_q = await sess.execute(
            _select(Execution).where(
                Execution.automation_id == automation_id,
                Execution.status == "waiting",
            )
        )
        waiting_execs = list(execs_q.scalars().all())
        if not waiting_execs:
            return 0

        for exec_row in waiting_execs:
            # Annule les tokens pendants de cette exec. Cluster-S : si
            # step_id fourni, on filtre — sinon tous les tokens de l'exec.
            tokens_query = _select(WaitToken).where(
                WaitToken.execution_id == exec_row.id,
                WaitToken.status == "pending",
            )
            if step_id is not None:
                tokens_query = tokens_query.where(WaitToken.step_id == step_id)

            tokens_q = await sess.execute(tokens_query)
            exec_has_cancelled_token = False
            for token in tokens_q.scalars().all():
                token.mark_cancelled(reason)
                cancelled_recipients.append(token.recipient_email)
                exec_has_cancelled_token = True

            # Cluster-S — si step_id filter actif et aucun token de cette
            # exec ne matche, on NE marque PAS l'exec comme cancelled.
            # L'exec peut attendre un AUTRE step ; la canceller serait
            # une fausse abort (UX surprise + perte historique).
            if step_id is not None and not exec_has_cancelled_token:
                continue

            # Annule l'execution avec un message clair pour l'UI history
            exec_row.mark_cancelled(error_message=reason)
            # Purge le checkpoint (libere de l'espace BDD, tracable via
            # les step_executions de toute facon)
            exec_row.wait_checkpoint = None
            cancelled_count += 1

        # Charge un automation snapshot pour le mail (best-effort)
        from app.models.automation import Automation as _Auto

        auto = await sess.get(_Auto, automation_id)
        await sess.commit()

    if cancelled_count > 0:
        logger.info(
            "cancel_pending_waits_for_automation: auto=%d, %d execs annulees, "
            "%d destinataires notifies",
            automation_id,
            cancelled_count,
            len(cancelled_recipients),
        )

    # Notifier les destinataires (best-effort, hors transaction)
    if cancelled_recipients:
        try:
            smtp_config = await load_smtp_config_dict()
        except Exception:  # noqa: BLE001
            smtp_config = None
            logger.warning("cancel_pending_waits: load SMTP config echec — pas de notif")
        if smtp_config and auto is not None:
            for recipient in set(cancelled_recipients):  # dedup
                try:
                    await send_wait_cancellation_email(
                        smtp_config=smtp_config,
                        automation=auto,
                        recipient=recipient,
                        reason=reason,
                    )
                except Exception:  # noqa: BLE001
                    logger.warning(
                        "cancel_pending_waits: notif echec pour %s",
                        recipient,
                        exc_info=True,
                    )

            # Cluster-S 2026-05-26 — Notif owner symétrique (mirror
            # expire_overdue_wait_tokens). Sans ça, l'owner ne sait pas
            # que sa task a été annulée par effet de bord (delete step,
            # toggle off, etc.) → confusion lors du prochain run.
            if notify_owner:
                owner_email = None
                owner_user_id = None
                try:
                    from app.models.user import User as _User

                    sf2 = get_session_factory()
                    async with sf2() as sess2:
                        owner = await sess2.get(_User, auto.user_id)
                        if owner is not None and getattr(owner, "is_active", False):
                            owner_email = getattr(owner, "email", None)
                            owner_user_id = owner.id
                except Exception:  # noqa: BLE001
                    logger.warning(
                        "cancel_pending_waits: lookup owner echec auto=%d",
                        automation_id,
                        exc_info=True,
                    )

                if owner_email:
                    try:
                        await send_wait_cancellation_owner_email(
                            smtp_config=smtp_config,
                            automation=auto,
                            owner_email=owner_email,
                            recipients_count=len(set(cancelled_recipients)),
                            executions_count=cancelled_count,
                            reason=reason,
                            automation_user_id=owner_user_id,
                        )
                    except Exception:  # noqa: BLE001
                        logger.warning(
                            "cancel_pending_waits: notif owner echec %s",
                            owner_email,
                            exc_info=True,
                        )

    return cancelled_count


async def send_wait_cancellation_owner_email(
    *,
    smtp_config: Optional[Dict[str, Any]],
    automation: Any,
    owner_email: str,
    recipients_count: int,
    executions_count: int,
    reason: str,
    automation_user_id: Optional[int] = None,
) -> None:
    """Cluster-S 2026-05-26 — Notifie le proprio que ses waits ont été
    annulés (effet de bord d'un delete step / toggle off / delete auto).

    Mirror sémantique de :func:`send_wait_cancellation_email` mais avec
    un sujet/body adapté au proprio (récap volumétrique).
    """
    if not smtp_config:
        return
    from app.services.email.smtp_factory import build_smtp_client_from_dict
    from app.services.branding import get_company_name

    company = get_company_name()
    auto_name = getattr(automation, "name", "") or "Automatisation"
    subject = f"Taches en attente annulees — {auto_name}"
    body = (
        f"<p>Bonjour,</p>"
        f"<p>Les taches en attente de votre automatisation "
        f"<strong>{auto_name}</strong> ont été annulées.</p>"
        f"<ul>"
        f"<li>Executions annulees : {executions_count}</li>"
        f"<li>Destinataires notifies : {recipients_count}</li>"
        f"<li>Motif : {reason}</li>"
        f"</ul>"
        f"<p>Si vous souhaitez relancer cette automatisation, "
        f"rendez-vous sur l'application.</p>"
        f"<p style='color: #6b7280; font-size: 0.85em;'>— {company}</p>"
    )

    try:
        from app.services.email.template_names import EmailTemplate

        smtp_client = build_smtp_client_from_dict(smtp_config)
        await smtp_client.send_email(
            to_emails=[owner_email],
            subject=subject,
            body_html=body,
            automation_id=getattr(automation, "id", None),
            sent_by_user_id=automation_user_id,
            template_name=(
                EmailTemplate.WAIT_CANCELLATION_OWNER.value
                if hasattr(EmailTemplate, "WAIT_CANCELLATION_OWNER")
                else "wait_cancellation_owner"
            ),
        )
    except Exception:  # noqa: BLE001
        # Best-effort : log + propage pour que le caller logue aussi.
        raise


async def send_wait_cancellation_email(
    *,
    smtp_config: Optional[Dict[str, Any]],
    automation: Any,
    recipient: str,
    reason: str,
) -> None:
    """Notifie le destinataire que sa tache a ete annulee.

    Best-effort : si l'envoi echoue, on logge mais on ne bloque pas
    l'annulation (le destinataire decouvrira juste le 410 quand il
    cliquera).
    """
    if not smtp_config:
        return
    from app.services.email.smtp_factory import build_smtp_client_from_dict
    from app.services.branding import get_company_name

    company = get_company_name()
    subject = f"Tache annulee — {getattr(automation, 'name', '') or company}"
    body = (
        f"Bonjour,\n\n"
        f"La demande envoyee precedemment a ete annulee :\n"
        f"  Raison : {reason}\n\n"
        f"Vous pouvez ignorer le mail precedent et son lien.\n"
        f"Si vous avez deja repondu, votre reponse a ete enregistree mais ne "
        f"sera pas utilisee.\n\n"
        f"Cordialement,\n"
        f"{company}"
    )
    smtp = build_smtp_client_from_dict(smtp_config)
    if smtp is None:
        return
    try:
        await smtp.send_email(
            to_emails=[recipient],
            subject=subject,
            body_text=body,
            body_html=None,
            automation_id=getattr(automation, "id", None),
            sent_by_user_id=getattr(automation, "user_id", None),
            template_name=_EmailTemplate.WAIT_CANCELLATION.value,
        )
    except Exception:  # noqa: BLE001 — best-effort
        logger.warning(
            "send_wait_cancellation_email: envoi echec pour %s",
            recipient,
            exc_info=True,
        )
