"""Dispatcher email pour les exécutions d'automations.

D3 phase 2 (cycle 20) : extrait des méthodes ``_send_workflow_email`` et
``_send_email`` de :class:`AutomationExecutor` pour réduire la god class.
Ces fonctions n'avaient besoin que de la config SMTP (déjà factorisée
via :func:`load_smtp_config_dict`), des destinataires et du contexte
d'exécution — aucune dépendance forte au runtime executor.

Ce module unifie les 2 stratégies d'envoi :

* :func:`send_workflow_step_email` — utilisé par le step ``email`` du DAG
  workflow. HTML construit en place avec récap warnings.
* :func:`send_legacy_pipeline_email` — utilisé par l'ancien pipeline
  mono-step (``_run_pipeline``). Rendu via template Jinja
  ``automation_report`` avec fallback HTML simple.

Toutes deux retombent sur le factory ``build_smtp_client_from_dict`` et
le helper de branding ``_resolve_smtp_from_name``.
"""

from __future__ import annotations

from html import escape as html_escape
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core import clock
from app.utils.logger import get_logger
from app.utils.validators import is_valid_email

logger = get_logger(__name__)


def _safe_attachment_name(name: Optional[str], *, fallback: str = "attachment") -> str:
    """Cluster-32 2026-05-26 — Sanitize un filename pour Content-Disposition.

    Le header MIME ``Content-Disposition: attachment; filename="X"`` est
    construit par le client SMTP à partir du dict ``{"filename": ...}``.
    Si le name contient ``\\r\\n``, ``;``, ``"`` ou des caractères de
    contrôle, un attacker peut injecter des headers (BCC arbitraire,
    spoofing destinataires) ou casser le parsing chez le destinataire.

    Stratégie défensive :
    1. Retirer les caractères de contrôle (NUL, CR, LF, etc.).
    2. Remplacer les caractères dangereux pour header (``";\\\\``).
    3. Limiter à 200 chars (RFC 2231 conseille < 255 octets).
    4. Fallback explicite si le résultat est vide après sanitization.

    Pour les non-ASCII, on conserve les caractères Unicode standard
    (le client SMTP doit faire le RFC 2231 encoding via le module
    ``email.utils.encode_rfc2231`` ou équivalent — pas notre rôle ici).
    On filtre juste les chars qui CASSENT le parsing header brut.
    """
    if not name or not isinstance(name, str):
        return fallback

    # 1. Retirer les caractères de contrôle (NUL + C0/C1 sauf espace).
    cleaned = "".join(
        ch for ch in name if ord(ch) >= 0x20 and ord(ch) != 0x7F  # printable ASCII + Unicode
    )

    # 2. Remplacer les caractères dangereux pour header par "_".
    # `"` et `\` cassent le quoted-string. `;` sépare les paramètres.
    # `/` est un séparateur de path (anti-confusion path-traversal).
    # `\r\n` déjà retirés en étape 1, mais defensive.
    for bad_char in '"\\;\r\n\t/\\':
        cleaned = cleaned.replace(bad_char, "_")

    # 3. Trim leading/trailing whitespace + dots (Windows file conventions).
    cleaned = cleaned.strip(" .")

    # 4. Cap à 200 chars (préserve la marge sous le 255-octet RFC 2231).
    cleaned = cleaned[:200]

    return cleaned if cleaned else fallback


def _resolve_smtp_from_name(smtp_config: Dict[str, Any]) -> str:
    """Retourne ``from_name`` SMTP : valeur explicite OU branding global.

    Pas de hardcode "Komptia" / "Cabinet X" ici (axe 6 : généricité).
    Cohérent avec la version originale dans ``executor.py`` ligne 34.
    """
    explicit = smtp_config.get("from_name")
    if explicit:
        return explicit
    # Fallback : nom configuré côté branding (config admin).
    # Cluster-D 2026-05-26 — fallback FINAL = PLACEHOLDER_COMPANY_NAME
    # ("[Entreprise à configurer]") au lieu de ``config.app_name`` qui
    # vaut "Komptia" par défaut. Sinon white-label cassé : un cabinet
    # client recevait des emails signés "Komptia" si branding mal
    # configuré côté admin, sans signal visible.
    try:
        from app.services.branding import get_smtp_from_name

        return get_smtp_from_name()
    except Exception:  # noqa: BLE001 — fallback branding placeholder
        # Cluster-33 silent OK : si get_smtp_from_name lève (cas rare :
        # branding service early boot, table absent), on retourne le
        # PLACEHOLDER_COMPANY_NAME visible côté destinataire — l'admin
        # voit immédiatement qu'il doit configurer le branding.
        from app.services.branding import PLACEHOLDER_COMPANY_NAME

        return PLACEHOLDER_COMPANY_NAME


def _build_execution_detail_url(execution_id: int) -> str:
    """**P5.3 (audit 2026-05-26)** — Construit l'URL absolue de la page
    détail d'une exécution, pour l'inclure dans les emails de notification
    d'échec.

    SSoT base_url : ``config.server.public_base_url`` (cf. iris_write_session
    _build_approver_url pour le même pattern). Fallback localhost si non
    configuré (cas dev) — l'admin doit configurer ``public_base_url`` pour
    que les liens fonctionnent depuis les clients mail externes.
    """
    from app.config import config as app_config

    base_url = (
        getattr(app_config, "server", None) and getattr(app_config.server, "public_base_url", None)
    ) or "http://127.0.0.1:8888"
    base_url = base_url.rstrip("/")
    return f"{base_url}/executions/{int(execution_id)}"


async def send_workflow_step_email(
    smtp_config: Optional[Dict[str, Any]],
    automation_id: int,
    recipients: List[str],
    subject: str,
    file_path: Path,
    rows_count: int,
    warnings: List[str],
    owner_is_active: bool,
    *,
    automation_user_id: Optional[int] = None,
    execution_id: Optional[int] = None,
) -> None:
    """Envoie un email dans le cadre d'un step ``email`` du DAG workflow.

    Args:
        smtp_config: Config SMTP déjà chargée par le caller (None = SMTP off).
        automation_id: ID de l'automation pour le log.
        recipients: Liste d'emails ; les URL ``://`` sont filtrées (anti-loop).
        subject: Objet de l'email.
        file_path: Pièce jointe (rapport généré).
        rows_count: Nombre de lignes du résultat (pour le récap).
        warnings: Warnings runtime à inclure dans le HTML (mutable, sera
            étendu par le caller en cas d'erreur).
        owner_is_active: Si False → on n'envoie PAS l'email (compte
            désactivé par admin = pas de leak applicatif). Contrat S7,
            mirror de :func:`send_legacy_pipeline_email` et
            :func:`send_execution_notification`. **Sans défaut** — un
            futur caller DOIT penser au check (fail-closed by design).
            **Cluster-R 2026-05-26** : avant ce param, le DAG step
            envoyait des emails même pour comptes désactivés (S7
            fail-OPEN — leak compliance / RGPD soft-delete bypass).

    Side-effects: le caller voit les warnings ajoutés à `warnings` (la liste
    fournie). Pas de retour. Si l'envoi SMTP échoue (ConnectionError,
    SMTPException, timeout, etc.), le warning est ajouté à `warnings` pour
    diagnostics PUIS l'exception est propagée au caller (executor retry loop)
    pour que le step soit marqué ``failed`` au lieu de ``success`` silencieux.
    """
    # Cluster-R (S7) 2026-05-26 — Compte désactivé : aucun envoi
    # applicatif, peu importe la config SMTP ou les recipients fournis.
    # DOIT précéder TOUT autre check (SMTP, recipients, attachments)
    # pour empêcher tout side-effect observable depuis l'extérieur.
    if not owner_is_active:
        logger.info(
            "Workflow step email skip — proprietaire desactive (automation %d)",
            automation_id,
        )
        warnings.append("Email step ignore : compte proprietaire desactive")
        return

    if not smtp_config:
        warnings.append("SMTP non configure, email non envoye")
        return

    # `is_valid_email` rejette les URLs (`://`) — defense anti-webhook-loop
    # (design §3.8) : un user qui mettrait `https://komptia.local/webhook/...`
    # dans recipients ne crashe pas le pipeline mais l'entree est filtree.
    valid = [r for r in recipients if is_valid_email(r)]
    if not valid:
        warnings.append("Aucun destinataire email valide")
        return

    try:
        from app.services.email.smtp_factory import build_smtp_client_from_dict

        smtp_client = build_smtp_client_from_dict(
            smtp_config,
            from_name_override=_resolve_smtp_from_name(smtp_config),
        )

        safe_subject = html_escape(subject)
        safe_filename = html_escape(file_path.name)
        # Cluster-D 2026-05-26 — branding dynamique (white-label)
        from app.services.branding import get_company_name

        safe_company = html_escape(get_company_name())
        body_html = (
            f"<h2>{safe_subject}</h2>"
            f"<p>Rapport genere automatiquement par {safe_company}.</p>"
            f"<p>Lignes: {rows_count} | "
            f"Fichier: {safe_filename}</p>"
        )
        if warnings:
            body_html += "<h3>Avertissements</h3><ul>"
            body_html += "".join(f"<li>{html_escape(str(w))}</li>" for w in warnings)
            body_html += "</ul>"

        attachments = []
        if file_path.exists():
            # Cluster-32 2026-05-26 — Sanitize filename pour Content-Disposition
            # anti-CRLF injection (step name attacker-controlled).
            attachments.append(
                {
                    "path": str(file_path),
                    "filename": _safe_attachment_name(file_path.name),
                }
            )

        from app.services.email.template_names import EmailTemplate

        _send_res = await smtp_client.send_email(
            to_emails=valid,
            subject=subject,
            body_html=body_html,
            attachments=attachments if attachments else None,
            automation_id=automation_id,
            execution_id=execution_id,
            sent_by_user_id=automation_user_id,
            template_name=EmailTemplate.DAG_EMAIL_STEP.value,
        )
        # #52 — une pièce jointe SKIPPÉE (rapport trop volumineux, fichier
        # purgé/symlink…) est sinon un angle mort : le mail part sans le
        # fichier et le step est « success ». On remonte au caller via la
        # liste `warnings` mutable (lue par l'executor → visible dans le
        # détail du run / monitor) pour que David sache que le rapport
        # configuré n'a PAS été joint.
        for _sk in (_send_res or {}).get("skipped_attachments") or []:
            _nm = _sk.get("name") if isinstance(_sk, dict) else None
            _rs = _sk.get("reason") if isinstance(_sk, dict) else None
            warnings.append(f"Pièce jointe NON envoyée : {_nm} ({_rs})")
            logger.warning(
                "Automation %d : pièce jointe non envoyée (%s) — %s",
                automation_id,
                _rs,
                _nm,
            )
    except Exception:
        logger.error(
            "Erreur envoi email workflow (automation %d)",
            automation_id,
            exc_info=True,
        )
        warnings.append("Erreur lors de l'envoi de l'email")
        # Propager au caller (executor retry loop) pour mark step=failed.
        # Sans ce raise, status='success' alors qu'aucun mail n'est parti
        # (silent failure axe 5 taxonomie + axe 21 observabilite).
        raise


async def send_legacy_pipeline_email(
    smtp_config: Optional[Dict[str, Any]],
    automation_id: int,
    automation_name: str,
    automation_description: Optional[str],
    automation_recipients: Optional[List[str]],
    output_format: Optional[str],
    execution_finished_at: Optional[datetime],
    execution_duration_seconds: Optional[float],
    execution_result_rows: Optional[int],
    output_file: Path,
    owner_is_active: bool,
    *,
    automation_user_id: Optional[int] = None,
    execution_id: Optional[int] = None,
) -> None:
    """Envoie le rapport par email depuis l'ancien pipeline mono-step.

    Utilise le template Jinja ``automation_report`` avec fallback HTML
    simple si le template est introuvable.

    Args:
        smtp_config: Config SMTP déjà chargée (None = SMTP off, log warning).
        automation_id, automation_name, automation_description: Métadonnées
            de l'automation pour le log et le rendu HTML.
        automation_recipients: Liste de destinataires depuis l'auto config.
            Les URL ``://`` sont filtrées (anti-loop).
        output_format: Format du rapport (csv/excel/pdf) pour affichage.
        execution_finished_at, execution_duration_seconds, execution_result_rows:
            Métadonnées de l'exécution pour le rendu HTML.
        output_file: Pièce jointe.
        owner_is_active: Si False → on n'envoie PAS le rapport (compte
            désactivé par admin = pas de leak applicatif). Contrat S7,
            mirror de :func:`send_execution_notification`. Sans défaut
            (fail-closed by design — un futur caller doit penser au check).
    """
    # S7 — Compte désactivé : aucun envoi applicatif, peu importe la config
    # ou les recipients. DOIT précéder validation SMTP / résolution
    # ``automation_recipients`` sinon ``automation_recipients`` non-vide
    # bypasse le silence applicatif (fail-OPEN — cf.
    # test_owner_is_active_check_precedes_recipients_resolution).
    if not owner_is_active:
        logger.info(
            "Rapport legacy skip — proprietaire desactive (automation %d)",
            automation_id,
        )
        return

    if not smtp_config:
        logger.warning(
            "SMTP non configure, email non envoye pour automation %d",
            automation_id,
        )
        return

    # Valider les clés SMTP requises (cohérent avec la validation factory
    # mais on retourne early en log warning au lieu de crasher).
    required_keys = {"host", "port", "username", "password", "use_tls", "from_email"}
    missing = required_keys - set(smtp_config.keys())
    if missing or not smtp_config.get("host") or not smtp_config.get("username"):
        logger.warning("Config SMTP incomplete, email non envoye")
        return

    if not automation_recipients or not isinstance(automation_recipients, list):
        return

    valid_recipients = [r for r in automation_recipients if is_valid_email(r)]
    if not valid_recipients:
        logger.warning("Aucun destinataire valide pour automation %d", automation_id)
        return

    try:
        from app.services.email.smtp_factory import build_smtp_client_from_dict
        from app.services.email.template_renderer import get_renderer

        renderer = get_renderer()
        duration = f"{execution_duration_seconds:.1f}s" if execution_duration_seconds else "N/A"
        # Heure SERVEUR (config.server.timezone via clock.to_local) : un email est
        # une sortie backend (aucun navigateur pour convertir). Avant : strftime
        # sur l'UTC brut (+4h pour America/Guadeloupe). `or clock.now_local()` =
        # filet mypy/runtime (to_local ne renvoie None que pour une valeur
        # illisible, jamais le cas ici — execution_finished_at est un datetime).
        execution_date = (
            clock.to_local(execution_finished_at or clock.now()) or clock.now_local()
        ).strftime("%d/%m/%Y à %H:%M")

        try:
            # Cluster-D 2026-05-26 — injecter company_name dans le contexte
            # pour que les templates puissent l'afficher via {{ sender_name
            # | default(company_name) }} (au lieu d'un fallback "Komptia"
            # hardcodé dans le template).
            from app.services.branding import get_company_name

            body_html = renderer.render_html(
                "automation_report",
                {
                    "automation_name": automation_name,
                    "description": automation_description,
                    "result_rows": execution_result_rows or 0,
                    "output_format": output_format or "csv",
                    "execution_duration": duration,
                    "execution_date": execution_date,
                    "company_name": get_company_name(),
                },
            )
        except Exception:
            logger.warning(
                "Template email introuvable, utilisation HTML simple",
                exc_info=True,
            )
            safe_name = html_escape(automation_name)
            body_html = (
                f"<h2>Rapport automatisé : {safe_name}</h2>"
                f"<p>Votre rapport a été généré avec succès.</p>"
                f"<p>Lignes retournées : {execution_result_rows or 0}</p>"
                f"<p>Le fichier est joint à cet email.</p>"
            )

        smtp_client = build_smtp_client_from_dict(
            smtp_config,
            from_name_override=_resolve_smtp_from_name(smtp_config),
        )

        attachments = []
        if output_file.exists():
            # Cluster-32 2026-05-26 — Sanitize filename anti-CRLF injection.
            attachments.append(
                {
                    "path": str(output_file),
                    "filename": _safe_attachment_name(output_file.name),
                }
            )

        from app.services.email.template_names import EmailTemplate

        result = await smtp_client.send_email(
            to_emails=valid_recipients,
            subject=f"Rapport automatisé : {automation_name}",
            body_html=body_html,
            attachments=attachments if attachments else None,
            automation_id=automation_id,
            execution_id=execution_id,
            sent_by_user_id=automation_user_id,
            template_name=EmailTemplate.AUTOMATION_REPORT.value,
        )

        if result.get("success"):
            logger.info(
                "Email envoye pour automation %d (%d destinataires)",
                automation_id,
                len(valid_recipients),
            )
        else:
            logger.error(
                "Echec envoi email pour automation %d",
                automation_id,
                exc_info=True,
            )

    except Exception:
        logger.error("Erreur envoi email automation %d", automation_id, exc_info=True)


async def send_execution_notification(
    smtp_config: Optional[Dict[str, Any]],
    automation_id: int,
    automation_name: str,
    automation_user_id: int,
    notification_emails: Optional[List[str]],
    success: bool,
    execution_started_at: Optional[datetime],
    execution_duration_seconds: Optional[float],
    execution_result_rows: Optional[int],
    error_message: Optional[str],
    fallback_owner_email: Optional[str],
    owner_is_active: bool,
    execution_id: Optional[int] = None,
    paused_reason: Optional[str] = None,
) -> None:
    """Envoie une notification email sur succès ou échec d'exécution.

    ENGINE-1 — si ``paused_reason`` est fourni, l'email inclut une bannière
    « Automatisation mise en pause » en tête + un sujet ⏸ explicite. Le caller
    DOIT forcer l'envoi dans ce cas (même si ``notify_on_failure=False``) : une
    auto-pause silencieuse laisse l'owner croire que tout tourne.

    Best-effort : les erreurs de notification ne remontent JAMAIS au
    pipeline (catch-all + log). Le pipeline ne doit pas casser à cause
    d'un échec SMTP.

    Args:
        smtp_config: Config SMTP déjà chargée par le caller (None = SMTP off).
        automation_id, automation_name, automation_user_id: Métadonnées auto.
        notification_emails: Liste d'emails configurée. Si vide/None,
            le caller doit fournir ``fallback_owner_email`` (avec
            ``owner_is_active=True`` pour éviter de notifier un compte
            désactivé — S7).
        success: True = mail vert avec "Succes", False = rouge avec "Echec".
        execution_started_at, execution_duration_seconds, execution_result_rows:
            Métadonnées de l'exécution pour le récap HTML.
        error_message: Trace courte (tronquée à 500 chars dans le HTML)
            si ``success=False``. Ignoré sinon.
        fallback_owner_email: Email du propriétaire de l'auto, utilisé
            UNIQUEMENT si notification_emails est vide.
        owner_is_active: Si False → on ne notifie PAS le propriétaire
            (compte désactivé par admin = pas de leak applicatif). S7.
    """
    try:
        if not smtp_config:
            logger.debug(
                "SMTP non configure, notification non envoyee pour automation %d",
                automation_id,
            )
            return

        # S7 — Compte désactivé : aucune notification, peu importe la config.
        # Doit précéder la résolution des destinataires sinon une
        # ``notification_emails`` non-vide bypasse le silence applicatif
        # (fail-OPEN — cf. test_owner_is_active_check_precedes_notif_emails_resolution).
        if not owner_is_active:
            logger.info(
                "Notification skip — proprietaire desactive (automation %d, user %d)",
                automation_id,
                automation_user_id,
            )
            return

        # Determiner les destinataires : config explicite OU fallback owner
        notif_emails = notification_emails
        if not notif_emails or not isinstance(notif_emails, list):
            if not fallback_owner_email:
                logger.debug(
                    "Pas d'email proprietaire pour notification automation %d",
                    automation_id,
                )
                return
            notif_emails = [fallback_owner_email]

        # `is_valid_email` rejette les URLs `://` (anti-webhook-loop §3.8).
        valid = [r for r in notif_emails if is_valid_email(r)]
        if not valid:
            return

        # Construire le contenu du mail
        safe_name = html_escape(automation_name)
        status_label = "Succes" if success else "Echec"
        status_color = "#22c55e" if success else "#ef4444"
        status_icon = "&#10004;" if success else "&#10008;"

        duration = "N/A"
        if execution_duration_seconds is not None:
            duration = f"{execution_duration_seconds:.1f}s"

        # Date affichée en TZ machine (config.server.timezone) plutôt que
        # UTC brut. L'utilisateur reçoit "15:51 (America/Guadeloupe)" et
        # pas "19:51 UTC" qui décale silencieusement de 4h. Cf. retour
        # David 2026-05-08 sur les heures incorrectes dans email + UI.
        try:
            from zoneinfo import ZoneInfo

            from app.config import config as _komptia_config

            _local_tz_name = _komptia_config.server.timezone
            _local_tz = ZoneInfo(_local_tz_name)
        except Exception:  # noqa: BLE001 — Cluster-33 : silent OK
            # Fallback bénin UTC quand config.server.timezone absent (boot
            # early, config corrompue). Pas de log car ce path est attendu
            # en cold-start et noierait les logs. Le rendu email continue
            # avec un timestamp UTC explicite — pas de donnée fausse.
            _local_tz_name = "UTC"
            _local_tz = timezone.utc

        def _fmt_local(dt: Optional[datetime]) -> str:
            """Formate un datetime UTC en heure locale lisible avec suffixe TZ."""
            if dt is None:
                return ""
            # Naive datetime stocke en BDD ⇒ on assume UTC.
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(_local_tz).strftime("%d/%m/%Y a %H:%M") + f" ({_local_tz_name})"

        exec_date = _fmt_local(clock.now())
        if execution_started_at:
            exec_date = _fmt_local(execution_started_at)

        body_parts = [
            '<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">',
            f'<div style="background:{status_color};color:white;padding:16px 24px;'
            f'border-radius:8px 8px 0 0;font-size:18px">'
            f"{status_icon} Automatisation : {status_label}</div>",
            '<div style="border:1px solid #e5e7eb;border-top:none;padding:24px;'
            'border-radius:0 0 8px 8px">',
            f'<p style="margin:0 0 12px"><strong>{safe_name}</strong></p>',
            '<table style="width:100%;border-collapse:collapse;font-size:14px">',
            f'<tr><td style="padding:6px 0;color:#6b7280">Statut</td>'
            f'<td style="padding:6px 0;font-weight:600;color:{status_color}">'
            f"{status_label}</td></tr>",
            f'<tr><td style="padding:6px 0;color:#6b7280">Duree</td>'
            f'<td style="padding:6px 0">{duration}</td></tr>',
            f'<tr><td style="padding:6px 0;color:#6b7280">Date</td>'
            f'<td style="padding:6px 0">{exec_date}</td></tr>',
        ]

        # ENGINE-1 — bannière de PAUSE AUTO en tête du contenu (index 3 = juste
        # après l'ouverture du content div, avant le nom) : l'owner doit savoir
        # que l'automatisation a été DÉSACTIVÉE, pas juste qu'un run a échoué.
        if paused_reason == "once_completed":
            # ENGINE-1-once (#50) — fin de vie ATTENDUE d'une automation « une
            # fois » : cadrage NEUTRE/positif (bleu), PAS l'alerte jaune des
            # pauses-erreur (qui alarmerait à tort sur un run RÉUSSI).
            body_parts.insert(
                3,
                '<div style="margin:0 0 16px;padding:12px 14px;background:#eff6ff;'
                "border:1px solid #bfdbfe;border-left:4px solid #2563eb;"
                'border-radius:6px;font-size:13px;color:#1e40af">'
                "<strong>&#10003; Automatisation « une fois » terminée.</strong> "
                "Elle s'est exécutée comme prévu et est maintenant désactivée. "
                "Réactivez-la depuis la page Automatisations pour la relancer."
                "</div>",
            )
        elif paused_reason:
            # Revue [3] — PAS de hardcode du nom d'app (white-label, axe 6) :
            # on interpole le nom dynamique (get_company_name, même SSoT que le
            # footer ci-dessous).
            from app.services.branding import get_company_name as _get_company_name

            _pause_app = _get_company_name()
            _pause_labels = {
                "too_many_failures": (
                    f"Trop d'échecs consécutifs — {_pause_app} l'a désactivée "
                    "pour éviter de répéter des exécutions ou envois en erreur."
                ),
                "data_access_denied": (
                    "Un accès aux données requis a été retiré."
                ),
            }
            _pause_label = _pause_labels.get(
                paused_reason, "L'automatisation a été mise en pause automatiquement."
            )
            body_parts.insert(
                3,
                '<div style="margin:0 0 16px;padding:12px 14px;background:#fffbeb;'
                "border:1px solid #fcd34d;border-left:4px solid #d97706;"
                'border-radius:6px;font-size:13px;color:#92400e">'
                "<strong>&#9888; Automatisation mise en pause.</strong> "
                f"{html_escape(_pause_label)} "
                "Réactivez-la depuis la page Automatisations après diagnostic."
                "</div>",
            )

        if success and execution_result_rows is not None:
            body_parts.append(
                f'<tr><td style="padding:6px 0;color:#6b7280">Lignes</td>'
                f'<td style="padding:6px 0">{execution_result_rows}</td></tr>'
            )

        body_parts.append("</table>")

        if not success and error_message:
            # P5.3 (audit 2026-05-26) — Avant : ``html_escape(error_message[:500])``
            # coupait sans ``…`` (le user croyait avoir le message complet) et
            # sans lien vers ``/executions/N`` pour le détail complet
            # (error_traceback admin-only). Maintenant :
            # - Ajout ``…`` explicite si tronqué (signal visuel "il y a plus")
            # - Lien actionnable vers la page detail si execution_id fourni
            _truncated = len(error_message) > 500
            _displayed = error_message[:500] + ("…" if _truncated else "")
            safe_error = html_escape(_displayed)
            _err_block_parts = [
                f'<div style="margin-top:16px;padding:12px;background:#fef2f2;'
                f"border:1px solid #fecaca;border-radius:6px;font-size:13px;"
                f'color:#991b1b">'
                f"<strong>Erreur :</strong> {safe_error}"
            ]
            if execution_id is not None:
                _detail_url = _build_execution_detail_url(execution_id)
                _err_block_parts.append(
                    f'<div style="margin-top:8px;font-size:12px">'
                    f'<a href="{html_escape(_detail_url)}" '
                    f'style="color:#991b1b;text-decoration:underline">'
                    f"Voir le détail complet de l'exécution"
                    f"</a></div>"
                )
            _err_block_parts.append("</div>")
            body_parts.append("".join(_err_block_parts))

        # Cluster-D 2026-05-26 — branding dynamique (white-label)
        from app.services.branding import get_company_name

        company_name = get_company_name()
        safe_company = html_escape(company_name)
        body_parts.append(
            '<p style="margin-top:16px;font-size:12px;color:#9ca3af">'
            f"Ce message a ete envoye automatiquement par {safe_company}.</p>"
        )
        body_parts.append("</div></div>")
        body_html = "\n".join(body_parts)

        if paused_reason and paused_reason != "once_completed":
            subject = f"[{company_name}] ⏸ EN PAUSE — {automation_name}"
        else:
            # ENGINE-1-once (#50) — once_completed est un SUCCÈS attendu : garder
            # le sujet de statut normal, PAS l'alarme « ⏸ EN PAUSE ».
            subject = f"[{company_name}] {status_label} — {automation_name}"

        from app.services.email.smtp_factory import build_smtp_client_from_dict

        smtp_client = build_smtp_client_from_dict(
            smtp_config,
            from_name_override=_resolve_smtp_from_name(smtp_config),
        )

        from app.services.email.template_names import EmailTemplate

        result = await smtp_client.send_email(
            to_emails=valid,
            subject=subject,
            body_html=body_html,
            automation_id=automation_id,
            sent_by_user_id=automation_user_id,
            template_name=EmailTemplate.EXECUTION_NOTIFICATION.value,
        )

        if result.get("success"):
            logger.info(
                "Notification %s envoyee pour automation %d (%d destinataires)",
                status_label.lower(),
                automation_id,
                len(valid),
            )
        else:
            logger.warning(
                "Echec notification %s pour automation %d",
                status_label.lower(),
                automation_id,
            )

    except Exception:
        # Best-effort: ne jamais faire crasher le pipeline pour une notification
        logger.error(
            "Erreur envoi notification automation %d",
            automation_id,
            exc_info=True,
        )


__all__ = (
    "send_workflow_step_email",
    "send_legacy_pipeline_email",
    "send_execution_notification",
)
