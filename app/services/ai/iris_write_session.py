"""Service d'orchestration du workflow "Iris-DBA-write" — écritures SQL
via Iris avec approbation par DBA externe par mail.

Workflow :

    1. Admin demande à Iris de modifier des données.
    2. Iris (LLM) appelle le tool ``propose_sql_write(sql, intent)``.
    3. Ce service :
        a. Casquette active pour les admins (``enabled`` figé à ``True`` —
           pas de toggle applicatif dans cette version ; branche morte
           conservée pour un éventuel toggle futur).
        b. Vérifie ``user.role == admin`` (sinon refus).
        c. Vérifie l'« Email support » (/admin/smtp-config, résolu via
           ``resolve_support_email``) configuré (sinon refus, fail-closed).
        d. Parse + valide via ``write_validator.parse_and_validate_write``.
        e. Dry-run via ``sage_connector.execute_write(dry_run=True)`` →
           obtient ``estimated_rows``.
        f. Pas de cap automatique de lignes : ``estimated_rows`` est
           présenté au DBA dans le mail pour revue humaine.
        g. Issue token HMAC ``iw1.<uuid>.<sig>``.
        h. Insère ``SqlWriteAuditLog`` (status=AWAITING_DBA, hash stocké).
        i. Construit + envoie un mail au DBA avec le SQL et le lien
           d'approbation (clic = exécution).
    4. DBA reçoit le mail, fait un snapshot de la BDD, clique le lien.
    5. Handler ``/api/iris/sql-write/dba-confirm`` :
        a. Décode le token, lookup BDD par hash.
        b. Vérifie status=AWAITING_DBA + non expiré.
        c. Appelle ``dba_confirm()`` qui exécute la SQL pour de vrai.
        d. Update status=EXECUTED ou FAILED.
        e. Notifie l'admin demandeur par mail (succès/échec).

Sans réponse du DBA dans le TTL d'approbation (168 h = 7 j), le token
expire — aucune modification possible.

Doctrine sénior :

1. **Single source of vérité = SqlWriteAuditLog**. Tout le state du
   workflow est dans cette row. Pas de cache mémoire ; un restart
   serveur ne perd rien.

2. **Token brut non persisté.** Seul le SHA-256 est en BDD. Un dump
   BDD ne permet pas de forger un lien valide.

3. **Single-use enforcé en BDD.** ``approval_token_hash`` est UNIQUE.
   Le service vérifie ``status == AWAITING_DBA`` avant exécution —
   un token déjà consommé ne peut pas re-déclencher.

4. **Fail-closed partout.** « Email support » non configuré → refus.
   SMTP non configuré → refus. Validateur AST échoue → refus. Tout va
   dans l'audit log avec ``REJECTED_BY_VALIDATOR`` pour analyse.
"""

from __future__ import annotations

import html as _html
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Final, Optional

from sqlalchemy import select, update

from app.core import clock
from app.core.database import get_session
from app.models.base import ensure_utc
from app.models.sql_write_audit import (
    SqlWriteAuditLog,
    SqlWriteStatus,
)
from app.services.database.sage_connector import get_sage_connector
from app.services.email.template_names import EmailTemplate as _EmailTemplate
from app.services.database.write_validator import (
    WriteValidationResult,
    parse_and_validate_write,
)
from app.utils.iris_write_token_codec import issue_token, parse_and_verify
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

# Constantes _TTL_HOURS_* et _MAX_ROWS_FALLBACK retirées 2026-05-15 :
# valeurs hardcodées dans ``_get_iris_write_config`` (TTL=168h fixe,
# pas de cap rows). Cf. docstring de la fonction pour le contexte.

# Statut interne transitoire utilisé entre la réservation atomique de la
# row (UPDATE conditionnel) et l'exécution Sage. JAMAIS exposé dans
# ``SqlWriteStatus`` (l'enum) car c'est une mécanique interne du flow
# dba_confirm. Si une row reste bloquée en ``executing`` (crash app
# pendant Sage), un cleanup périodique pourrait la re-marquer, mais
# c'est une situation déjà visible dans l'audit.
_INTERNAL_EXECUTING_STATUS: str = "executing"

# Au-delà de ce délai en `executing`, on considère que l'app a crashé et
# on bascule la row en FAILED. 30 minutes laisse largement le temps à un
# UPDATE Sage gros volume de finir.
_ZOMBIE_AGE_SECONDS: int = 30 * 60

# Tolérance de dérive du volume entre l'approbation DBA et l'exécution
# (CRITIQUE 2026-05-31, review snapshot 20b8902). Le DBA approuve un volume
# (``estimated_rows`` affiché dans le mail). Entre le propose et le confirm
# (TTL jusqu'à 168 h), les données source bougent : un DELETE approuvé à
# « ~5 lignes » pourrait en toucher des milliers. On re-dry-run au confirm et
# on refuse fail-closed si le volume a CRU significativement (le DBA n'a pas
# validé ce scope). Une diminution est tolérée (moins dangereux). Tolérance =
# plancher absolu OU facteur relatif, pour ne pas bloquer une fluctuation
# anodine sur de petits ensembles. Valeurs TECHNIQUES (pas business) ;
# pourront devenir un réglage admin si le besoin émerge.
_ROW_DRIFT_GROWTH_FACTOR: Final[float] = 1.5
_ROW_DRIFT_ABS_FLOOR: Final[int] = 10


# ---------------------------------------------------------------------------
# Datatypes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProposeResult:
    """Résultat de ``propose_sql_write`` exposé au caller (handler agent_tools)."""

    success: bool
    audit_id: Optional[int] = None
    status: Optional[str] = None
    operation: Optional[str] = None
    tables: list[str] = field(default_factory=list)
    estimated_rows: Optional[int] = None
    dba_email: Optional[str] = None
    expires_at: Optional[datetime] = None
    user_message: str = ""
    error: Optional[str] = None


@dataclass(frozen=True, slots=True)
class ConfirmResult:
    """Résultat de ``dba_confirm`` / ``dba_reject`` (vue handler)."""

    success: bool
    audit_id: Optional[int] = None
    status: Optional[str] = None
    actual_rows: Optional[int] = None
    error: Optional[str] = None
    user_message: str = ""


# ---------------------------------------------------------------------------
# Helpers AIConfig
# ---------------------------------------------------------------------------


async def _get_iris_write_config() -> dict[str, Any]:
    """Config Iris-write.

    * ``approver_email`` : résolu **dynamiquement** depuis l'« Email support »
      configuré dans ``/admin/smtp-config`` (``SMTPGlobalConfig.support_email``)
      — **même source de vérité que le bug-reporter** (SSoT
      :func:`resolve_support_email`, décision user 2026-05-19, aucun hardcode).
      Vaut ``None`` si l'admin n'a pas configuré d'email support → la
      proposition d'écriture est refusée **fail-closed** (cf. étape 3 de
      :func:`propose_sql_write`).
    * ``enabled`` toujours ``True`` — la casquette est dispo pour les admins
      en permanence (pas de toggle de désactivation dans cette version).
    * ``ttl_hours`` = 168 (7 jours) — laisse au DBA le temps de faire un
      snapshot tranquille avant de cliquer le lien d'approbation.
    * ``max_rows`` : pas de cap applicatif. Le DBA voit le nombre estimé de
      lignes (dry-run) dans le mail et décide humainement.

    Note : 4 clés AIConfig (``IRIS_WRITE_ENABLED`` / ``_MAX_ROWS`` /
    ``_APPROVER_EMAIL`` / ``_APPROVAL_TTL_HOURS``) + leur section
    ``/admin/ai-config`` ont été retirées le 2026-05-15. L'approbateur ne
    réutilise désormais plus une clé dédiée mais l'email support global.
    """
    from app.services.feedback.feedback_service import resolve_support_email

    return {
        "enabled": True,
        "max_rows": None,  # sentinel : pas de cap, check runtime neutralisé
        "approver_email": await resolve_support_email(),
        "ttl_hours": 168,
    }


def _is_admin(user: Any) -> bool:
    """Vérifie que ``user`` est admin (compatible enum ou string)."""
    role = getattr(user, "role", None)
    return role == "admin" or getattr(role, "value", None) == "admin"


def _row_estimate_drifted(
    approved: Optional[int], fresh: int, operation: Optional[str] = None
) -> bool:
    """``True`` si le volume ré-estimé au confirm diverge dangereusement de
    l'estimation approuvée par le DBA — **selon le type d'opération**.

    Le danger dépend de la réversibilité (CRITIQUE adversarial 2026-05-31) :

    * ``DELETE`` / ``UPDATE`` (destructif, irréversible sans le snapshot DBA) :
      tolérance ZÉRO sur la croissance. Le DBA a approuvé ~``approved`` lignes
      détruites/écrasées ; TOUTE augmentation = scope non validé → on bloque.
      (Une opération approuvée à 0 ligne qui en toucherait → bloque aussi.)
    * ``INSERT`` (additif, réversible par suppression) : tolérance relative/
      absolue — la sur-insertion est moins grave —, autorisée sous
      ``max(approved + _ROW_DRIFT_ABS_FLOOR, approved * _ROW_DRIFT_GROWTH_FACTOR)``.
    * opération inconnue / absente → traitée comme destructive (fail-closed).

    Dans tous les cas : ``approved is None`` (pas de baseline) → bloque ;
    ``fresh <= approved`` (diminution ou égalité) → autorise.

    Limite résiduelle ASSUMÉE : ce contrôle borne le VOLUME, pas le SCOPE — un
    SQL ré-estimé au même nombre de lignes peut en toucher de DIFFÉRENTES (ex:
    ``WHERE date < @cutoff`` sur une base vivante). Et la fenêtre entre ce
    dry-run et l'exécution réelle qui suit n'est pas nulle. Le snapshot du DBA
    avant approbation reste le filet de sécurité ultime.
    """
    if approved is None:
        return True
    if fresh <= approved:
        return False
    # Ici : fresh > approved (croissance du volume impacté).
    if (operation or "").upper() == "INSERT":
        allowed = max(approved + _ROW_DRIFT_ABS_FLOOR, int(approved * _ROW_DRIFT_GROWTH_FACTOR))
        return fresh > allowed
    # DELETE / UPDATE / opération inconnue → destructif/irréversible :
    # toute croissance au-delà de l'approuvé est refusée (fail-closed).
    return True


# ---------------------------------------------------------------------------
# Mail helpers
# ---------------------------------------------------------------------------


async def _build_approver_url(token_public: str) -> str:
    """Construit l'URL du lien d'approbation que le DBA recevra."""
    from app.config import config as app_config

    base_url = (
        getattr(app_config, "server", None) and getattr(app_config.server, "public_base_url", None)
    ) or "http://127.0.0.1:8888"
    base_url = base_url.rstrip("/")
    return f"{base_url}/iris/sql-write/dba/{token_public}"


async def _send_dba_approval_email(
    *,
    approver_email: str,
    audit: SqlWriteAuditLog,
    token_public: str,
    requesting_user: Any,
) -> bool:
    """Envoie le mail au DBA avec lien d'approbation. Retourne True si OK."""
    from app.services.branding import get_company_name
    from app.services.email.smtp_factory import (
        build_smtp_client_from_dict,
        load_smtp_config_dict,
    )

    smtp_cfg = await load_smtp_config_dict()
    if smtp_cfg is None:
        logger.error("iris_write_session: SMTP non configuré, mail DBA impossible")
        return False
    try:
        client = build_smtp_client_from_dict(smtp_cfg)
    except (KeyError, ValueError) as exc:
        logger.error("iris_write_session: SMTP config invalide: %s", exc)
        return False

    company = get_company_name()
    approver_url = await _build_approver_url(token_public)
    expires_str = audit.expires_at.strftime("%d/%m/%Y à %H:%M UTC")
    user_label = (
        getattr(requesting_user, "email", None)
        or getattr(requesting_user, "username", None)
        or f"user#{getattr(requesting_user, 'id', '?')}"
    )

    subject = (
        f"[{company}] Iris demande votre approbation pour une écriture SQL "
        f"({audit.parsed_operation} sur {', '.join(audit.parsed_tables or ['?'])})"
    )

    sql_safe = _html.escape(audit.generated_sql or "")
    intent_safe = _html.escape(audit.intent or "—")
    user_safe = _html.escape(user_label)
    tables_safe = _html.escape(", ".join(audit.parsed_tables or []))

    text_body = (
        f"Iris a reçu une demande d'écriture SQL de l'admin '{user_label}'.\n\n"
        f"Intention :\n{audit.intent or '(non précisée)'}\n\n"
        f"Opération : {audit.parsed_operation} sur {', '.join(audit.parsed_tables or [])}\n"
        f"Lignes estimées : {audit.estimated_rows}\n\n"
        f"SQL proposé :\n{audit.generated_sql}\n\n"
        f"⚠ AVANT de cliquer le lien d'approbation, faites un SNAPSHOT "
        f"de la base source (sauvegarde / dump). Une fois exécutée, "
        f"l'opération NE PEUT PAS être annulée automatiquement.\n\n"
        f"Cliquer le lien ci-dessous pour approuver et exécuter :\n"
        f"  {approver_url}\n\n"
        f"Sans réponse, AUCUNE modification n'a lieu. Le lien expire le {expires_str}.\n"
    )

    html_body = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;line-height:1.6;color:#222;max-width:680px;margin:0 auto;padding:20px;background:#0f172a;">
  <div style="background:#1e293b;color:#e2e8f0;padding:24px;border-radius:12px;border:1px solid #334155;">
    <h2 style="color:#f8fafc;margin:0 0 12px;">⚠ Iris demande votre feu vert</h2>
    <p>L'administrateur <strong>{user_safe}</strong> a demandé à Iris d'exécuter une écriture SQL sur la base source de <strong>{_html.escape(company)}</strong>.</p>

    <h3 style="color:#fbbf24;margin-top:20px;">Avant tout : faites un snapshot</h3>
    <p>Une opération <code>{_html.escape(audit.parsed_operation or '?')}</code> est destructive. <strong>Sauvegardez la BDD AVANT de cliquer le lien d'approbation.</strong></p>

    <h3 style="color:#f8fafc;margin-top:20px;">Détails</h3>
    <table style="width:100%;border-collapse:collapse;color:#cbd5e1;">
      <tr><td style="padding:6px 0;width:160px;color:#94a3b8;">Opération</td><td><code>{_html.escape(audit.parsed_operation or '?')}</code></td></tr>
      <tr><td style="padding:6px 0;color:#94a3b8;">Tables</td><td>{tables_safe or '?'}</td></tr>
      <tr><td style="padding:6px 0;color:#94a3b8;">Lignes estimées</td><td><strong style="color:#fbbf24;">{audit.estimated_rows}</strong></td></tr>
      <tr><td style="padding:6px 0;color:#94a3b8;">Intention</td><td>{intent_safe}</td></tr>
    </table>

    <h3 style="color:#f8fafc;margin-top:20px;">SQL proposé</h3>
    <pre style="background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;overflow-x:auto;border:1px solid #334155;font-size:13px;">{sql_safe}</pre>

    <p style="margin:28px 0;text-align:center;">
      <a href="{approver_url}" style="display:inline-block;padding:14px 28px;background:#dc2626;color:#fff;text-decoration:none;border-radius:8px;font-weight:600;">
        Ouvrir la page d'approbation
      </a>
    </p>

    <p style="font-size:13px;color:#94a3b8;">
      Le lien ouvre une page de confirmation où vous devrez cliquer une seconde fois pour exécuter.
      <br/>Sans réponse, <strong>AUCUNE modification n'a lieu</strong>.
      <br/>Lien valide jusqu'au <strong>{_html.escape(expires_str)}</strong>.
    </p>
    <hr style="border:none;border-top:1px solid #334155;margin:20px 0;"/>
    <p style="font-size:11px;color:#64748b;">
      Audit ID : {audit.id} · Komptia/Iris-DBA-write
    </p>
  </div>
</body></html>"""

    try:
        result = await client.send_email(
            to_emails=approver_email,
            subject=subject,
            body_html=html_body,
            body_text=text_body,
            sent_by_user_id=getattr(requesting_user, "id", None),
            template_name=_EmailTemplate.IRIS_DBA_APPROVAL_REQUEST.value,
        )
    except Exception as exc:  # noqa: BLE001 — on ne sait pas tous les types
        logger.error("iris_write_session: send_email exception: %s", exc, exc_info=True)
        return False

    if not result.get("success"):
        logger.error("iris_write_session: send_email failed: %s", result.get("error", "?"))
        return False
    return True


async def _send_admin_notification(
    *,
    requesting_user: Any,
    audit: SqlWriteAuditLog,
    final_status: str,
) -> None:
    """Notifie l'admin demandeur du résultat (succès ou échec). Best-effort
    — un échec d'envoi mail ici ne fait pas planter le flow principal."""
    target = getattr(requesting_user, "email", None)
    if not target:
        return  # Pas d'email admin → pas de notif (cas dev/test)

    from app.services.branding import get_company_name
    from app.services.email.smtp_factory import (
        build_smtp_client_from_dict,
        load_smtp_config_dict,
    )

    smtp_cfg = await load_smtp_config_dict()
    if smtp_cfg is None:
        return
    try:
        client = build_smtp_client_from_dict(smtp_cfg)
    except (KeyError, ValueError):
        return

    company = get_company_name()
    if final_status == SqlWriteStatus.EXECUTED.value:
        subject = f"[{company}] ✓ Écriture SQL exécutée ({audit.parsed_operation})"
        msg = (
            f"Le DBA a approuvé et la requête a été exécutée.\n"
            f"Lignes effectivement modifiées : {audit.actual_rows}\n"
        )
    elif final_status == SqlWriteStatus.FAILED.value:
        subject = f"[{company}] ✗ Écriture SQL échouée ({audit.parsed_operation})"
        msg = (
            f"Le DBA a approuvé mais l'exécution a échoué (rollback automatique).\n"
            f"Erreur : {audit.error_message or 'inconnue'}\n"
        )
    elif final_status == SqlWriteStatus.ABORTED.value:
        subject = f"[{company}] ⊘ Écriture SQL refusée par le DBA"
        msg = "Le DBA a refusé la demande. Aucune modification n'a eu lieu.\n"
    else:
        return  # Statut intermédiaire — pas de notif

    # #80 — SQL COMPLET (cohérent avec le mail d'approbation DBA, l.295, qui
    # l'inclut entier) : l'admin notifié doit vérifier EXACTEMENT ce qui a été
    # exécuté. L'ancien ``[:500]` MUET pouvait lui faire croire que le SQL
    # s'arrêtait là (multi-CTE > 500 chars). Fallback fail-loud sur un
    # generated_sql None (anomalie attendue impossible à un statut terminal —
    # on la SIGNALE au lieu d'une ligne « SQL : » vide muette ; best-effort,
    # ne crashe pas comme l'ancien ``None[:500]``).
    _sql_for_notif = audit.generated_sql or f"(SQL absent de l'audit #{audit.id} — anomalie)"
    body_text = f"{msg}\n" f"Audit ID : {audit.id}\n" f"SQL : {_sql_for_notif}\n"
    try:
        await client.send_email(
            to_emails=str(target),
            subject=subject,
            body_html=f"<pre>{_html.escape(body_text)}</pre>",
            body_text=body_text,
            sent_by_user_id=getattr(requesting_user, "id", None),
            template_name=_EmailTemplate.IRIS_DBA_ADMIN_NOTIFICATION.value,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("iris_write_session: admin notif failed: %s", exc)


# ---------------------------------------------------------------------------
# API publique : propose / confirm / reject / cleanup
# ---------------------------------------------------------------------------


async def propose_sql_write(
    *,
    user: Any,
    sql: str,
    intent: str,
    conversation_id: Optional[int] = None,
    request_id: Optional[str] = None,
    original_nl: Optional[str] = None,
) -> ProposeResult:
    """Casquette Iris-DBA-write : valide, dry-run, audit, mail au DBA.

    Returns:
        ``ProposeResult`` que le caller (agent_tools handler) sérialise
        pour l'agent LLM. La SQL n'est PAS encore exécutée — elle ne
        le sera qu'après le clic du DBA dans le mail.
    """
    cfg = await _get_iris_write_config()

    # 1. Toggle global (enabled est figé à True dans cette version — branche
    # conservée pour un éventuel toggle d'admin futur).
    if not cfg["enabled"]:
        return ProposeResult(
            success=False,
            user_message="La casquette Iris-DBA-write est désactivée.",
            error="iris_write_disabled",
        )

    # 2. Permission
    if not _is_admin(user):
        return ProposeResult(
            success=False,
            user_message="Cette action est réservée aux administrateurs.",
            error="not_admin",
        )

    # 3. Approbateur configuré (= email support, SSoT /admin/smtp-config)
    if not cfg["approver_email"]:
        return ProposeResult(
            success=False,
            user_message=(
                "Aucune adresse d'approbation n'est configurée. Renseignez "
                "l'« Email support (signalements) » dans /admin/smtp-config "
                "avant d'utiliser l'écriture assistée."
            ),
            error="no_approver_email",
        )

    # 4. Validation AST
    validation: WriteValidationResult = parse_and_validate_write(sql)
    if not validation.is_valid:
        # Audit du refus pour analyse
        async with get_session() as session:
            row = SqlWriteAuditLog(
                user_id=getattr(user, "id", None),
                conversation_id=conversation_id,
                request_id=request_id,
                original_nl_request=original_nl,
                intent=intent,
                generated_sql=sql,
                parsed_tables=None,
                parsed_operation=None,
                estimated_rows=None,
                status=SqlWriteStatus.REJECTED_BY_VALIDATOR.value,
                error_message=validation.error,
                approval_token_hash=_one_off_hash(),  # row-unique mais inutilisable
                expires_at=clock.now(),
                dba_email=cfg["approver_email"],
                max_rows_at_propose=cfg["max_rows"],
            )
            session.add(row)
            await session.commit()
            audit_id = row.id
        return ProposeResult(
            success=False,
            audit_id=audit_id,
            status=SqlWriteStatus.REJECTED_BY_VALIDATOR.value,
            user_message=f"SQL refusé par le validateur : {validation.error}",
            error=validation.error,
        )

    # 5. Dry-run pour estimer les lignes affectées
    sage = get_sage_connector()
    try:
        dry_result = await sage.execute_write(validation.normalized_sql or sql, dry_run=True)
    except Exception as exc:  # noqa: BLE001 — on capture toute erreur d'estimation
        logger.warning("iris_write_session: dry-run failed: %s", exc)
        async with get_session() as session:
            row = SqlWriteAuditLog(
                user_id=getattr(user, "id", None),
                conversation_id=conversation_id,
                request_id=request_id,
                original_nl_request=original_nl,
                intent=intent,
                generated_sql=validation.normalized_sql or sql,
                parsed_tables=validation.tables,
                parsed_operation=validation.operation,
                estimated_rows=None,
                status=SqlWriteStatus.REJECTED_BY_VALIDATOR.value,
                error_message=f"dry-run failed: {exc}",
                approval_token_hash=_one_off_hash(),
                expires_at=clock.now(),
                dba_email=cfg["approver_email"],
                max_rows_at_propose=cfg["max_rows"],
            )
            session.add(row)
            await session.commit()
            audit_id = row.id
        return ProposeResult(
            success=False,
            audit_id=audit_id,
            status=SqlWriteStatus.REJECTED_BY_VALIDATOR.value,
            user_message=(
                "Échec du dry-run sur la base source. Vérifie que la requête "
                "est syntaxiquement valide et que les tables existent."
            ),
            error=str(exc),
        )

    estimated = int(dry_result.get("rows_affected", 0))

    # 6. Cap rows — neutralisé (cf. demande user 2026-05-15 "cap rows y'en
    # a pas"). Le DBA voit le nombre estimé de lignes dans le mail et
    # décide humainement de cliquer le lien ou non. C'est lui le garde-fou,
    # pas un nombre arbitraire en config. ``cfg["max_rows"]`` reste à
    # ``None`` (sentinel) → le check est skippé.

    # 7. Token + audit + envoi mail
    token_public, token_hash = issue_token()
    expires_at = clock.now() + timedelta(hours=cfg["ttl_hours"])

    async with get_session() as session:
        row = SqlWriteAuditLog(
            user_id=getattr(user, "id", None),
            conversation_id=conversation_id,
            request_id=request_id,
            original_nl_request=original_nl,
            intent=intent,
            generated_sql=validation.normalized_sql or sql,
            parsed_tables=validation.tables,
            parsed_operation=validation.operation,
            estimated_rows=estimated,
            status=SqlWriteStatus.AWAITING_DBA.value,
            approval_token_hash=token_hash,
            expires_at=expires_at,
            dba_email=cfg["approver_email"],
            max_rows_at_propose=cfg["max_rows"],
        )
        session.add(row)
        await session.commit()
        audit_id = row.id
        # Capturer les valeurs avant fin de session (cf. règle ORM async safe)
        captured_audit = row

    # Envoi mail (le mail peut prendre 1-3s — on le fait hors session BDD)
    try:
        sent = await _send_dba_approval_email(
            approver_email=cfg["approver_email"],
            audit=captured_audit,
            token_public=token_public,
            requesting_user=user,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("iris_write_session: mail send unexpected error: %s", exc)
        sent = False

    if not sent:
        # Marquer l'audit en erreur — le DBA n'a rien reçu, le token est
        # mort né.
        async with get_session() as session:
            await session.execute(
                update(SqlWriteAuditLog)
                .where(SqlWriteAuditLog.id == audit_id)
                .values(
                    status=SqlWriteStatus.FAILED.value,
                    error_message="mail au DBA non envoyé (SMTP injoignable ?)",
                )
            )
            await session.commit()
        return ProposeResult(
            success=False,
            audit_id=audit_id,
            status=SqlWriteStatus.FAILED.value,
            estimated_rows=estimated,
            error="mail_send_failed",
            user_message=(
                "Le mail au DBA n'a pas pu être envoyé (SMTP injoignable). "
                "Vérifier la configuration /admin/smtp et réessayer."
            ),
        )

    return ProposeResult(
        success=True,
        audit_id=audit_id,
        status=SqlWriteStatus.AWAITING_DBA.value,
        operation=validation.operation,
        tables=validation.tables,
        estimated_rows=estimated,
        dba_email=cfg["approver_email"],
        expires_at=expires_at,
        user_message=(
            f"Mail envoyé au DBA ({cfg['approver_email']}). L'opération "
            f"({validation.operation} ~{estimated} lignes) ne sera exécutée "
            "qu'après son feu vert (clic dans le mail). Sans réponse avant "
            f"{expires_at.strftime('%d/%m/%Y %H:%M UTC')}, le lien expire "
            "et aucune modification n'a lieu."
        ),
    )


async def dba_confirm(*, token_public: str, ip: Optional[str] = None) -> ConfirmResult:
    """Le DBA a cliqué le lien d'approbation. On exécute la SQL pour de vrai.

    **Anti-race condition (TOCTOU)** : on n'inspecte pas puis modifie en
    deux temps. À la place, on fait un UPDATE conditionnel atomique
    (``WHERE status='awaiting_dba' AND expires_at > now``) qui réserve
    la row en passant son statut à ``executing`` (état transitoire). Si
    ``rowcount == 0`` après l'UPDATE, c'est qu'un autre clic a déjà
    consommé le token (double-clic, deux onglets, etc.) — on retourne
    une erreur sans exécuter. Garantie BDD-level : exactly-once.
    """
    token_hash = parse_and_verify(token_public)
    if token_hash is None:
        return ConfirmResult(
            success=False,
            error="invalid_token",
            user_message="Lien d'approbation invalide ou corrompu.",
        )

    now = clock.now()

    # Étape 1 — réservation atomique : passer awaiting_dba → executing
    # SI ET SEULEMENT SI le statut est awaiting_dba ET non expiré.
    async with get_session() as session:
        reserve_stmt = (
            update(SqlWriteAuditLog)
            .where(
                SqlWriteAuditLog.approval_token_hash == token_hash,
                SqlWriteAuditLog.status == SqlWriteStatus.AWAITING_DBA.value,
                SqlWriteAuditLog.expires_at > now,
            )
            .values(
                status=_INTERNAL_EXECUTING_STATUS,
                dba_responded_at=now,
                dba_response_ip=(ip or "")[:45] or None,
            )
        )
        reserve_res = await session.execute(reserve_stmt)
        await session.commit()
        reserved = (reserve_res.rowcount or 0) == 1

    if not reserved:
        # Lookup pour donner un message précis à l'utilisateur (déjà
        # traité ? expiré ? token inconnu ?). Pas de course possible
        # ici : on lit après le UPDATE conditionnel.
        async with get_session() as session:
            res = await session.execute(
                select(SqlWriteAuditLog).where(SqlWriteAuditLog.approval_token_hash == token_hash)
            )
            audit = res.scalar_one_or_none()
            if audit is None:
                return ConfirmResult(
                    success=False,
                    error="not_found",
                    user_message="Demande introuvable.",
                )
            # Si non-expired mais pas awaiting_dba, c'est un re-clic
            # (already executed/aborted/executing par l'autre tab).
            if clock.now() > ensure_utc(audit.expires_at) and (
                audit.status == SqlWriteStatus.AWAITING_DBA.value
            ):
                # Cas TTL dépassé : marquer expired (idempotent)
                async with get_session() as s2:
                    await s2.execute(
                        update(SqlWriteAuditLog)
                        .where(
                            SqlWriteAuditLog.id == audit.id,
                            SqlWriteAuditLog.status == SqlWriteStatus.AWAITING_DBA.value,
                        )
                        .values(status=SqlWriteStatus.EXPIRED.value)
                    )
                    await s2.commit()
                return ConfirmResult(
                    success=False,
                    audit_id=audit.id,
                    status=SqlWriteStatus.EXPIRED.value,
                    error="expired",
                    user_message=(
                        "Le lien a expiré. L'admin doit refaire une nouvelle " "demande à Iris."
                    ),
                )
            return ConfirmResult(
                success=False,
                audit_id=audit.id,
                status=audit.status,
                error="already_handled",
                user_message=(
                    f"Cette demande a déjà été traitée (statut : {audit.status}). "
                    "Aucune action effectuée."
                ),
            )

    # Étape 2 — la row est réservée (status=executing). Lookup pour
    # capturer les champs nécessaires à l'exécution.
    async with get_session() as session:
        res = await session.execute(
            select(SqlWriteAuditLog).where(SqlWriteAuditLog.approval_token_hash == token_hash)
        )
        audit = res.scalar_one_or_none()
        if audit is None:
            # Race rare (review consolidée, cohérence taxonomie 4-cas) : la row a
            # été réservée (status=executing) puis supprimée par un cleanup/purge
            # concurrent avant ce lookup. On retourne un message métier propre
            # plutôt qu'un NoResultFound → 500. Cohérent avec les autres lookups
            # du fichier (scalar_one_or_none).
            logger.warning(
                "iris_write_session: row introuvable au lookup post-réservation "
                "(token_hash=%s...) — supprimée concurremment ?",
                token_hash[:12],
            )
            return ConfirmResult(
                success=False,
                error="not_found",
                user_message="Demande introuvable (a-t-elle été supprimée entre-temps ?).",
            )
        captured_id = audit.id
        captured_sql = audit.generated_sql
        captured_user_id = audit.user_id
        captured_op = audit.parsed_operation
        captured_estimated = audit.estimated_rows

    # Defense-in-depth — re-valider la FORME du SQL au moment de l'exécution :
    # si la ligne sql_write_audit a été altérée entre le propose et le confirm,
    # une transformation en DDL / SQL invalide / non-DML est rejetée ici. Respecte
    # la doctrine "jamais de SQL à l'aveugle".
    #
    # PORTÉE EXACTE (review adversariale du snapshot 20b8902) : ce check ne ferme
    # PAS entièrement la fenêtre TOCTOU. Il bloque le changement de FORME
    # (DML→DDL, SQL cassé), mais PAS la substitution par un AUTRE DML
    # syntaxiquement valide (ex: ``DELETE FROM A`` → ``DELETE FROM B``) : aucun
    # hash du contenu approuvé n'est vérifié (le token est signé sur l'UUID, pas
    # sur le SQL). Cette substitution exige un write-access DIRECT à la SQLite
    # locale = menace haut-privilège, dont la vraie parade est (1) l'audit trail
    # intégral (qui/quoi/quand, persisté) et (2) le snapshot BDD que le DBA fait
    # AVANT d'approuver. Un verrouillage fort du contenu nécessiterait de lier le
    # SHA-256 du SQL normalisé dans la SIGNATURE du token (bump iw1→iw2) — non
    # fait ici : invaliderait les tokens d'approbation en vol pour un gain
    # marginal face à ce threat model.
    revalidation = parse_and_validate_write(captured_sql)
    if not revalidation.is_valid:
        async with get_session() as session:
            await session.execute(
                update(SqlWriteAuditLog)
                .where(SqlWriteAuditLog.id == captured_id)
                .values(
                    status=SqlWriteStatus.FAILED.value,
                    error_message=(f"re-validation échouée: {revalidation.error}")[:500],
                )
            )
            await session.commit()
        logger.error(
            "iris_write_session: re-validation FAILED audit=%d: %s",
            captured_id,
            revalidation.error,
        )
        return ConfirmResult(
            success=False,
            audit_id=captured_id,
            status=SqlWriteStatus.FAILED.value,
            error="revalidation_failed",
            user_message=(
                "La requête n'a pas repassé la validation de sécurité au "
                "moment de l'exécution. Aucune modification n'a été effectuée."
            ),
        )

    # Étape 2bis — re-estimer le volume au confirm et le comparer à l'estimation
    # approuvée par le DBA. La re-validation AST ci-dessus ferme la fenêtre
    # « SQL altéré » ; ce check-ci ferme la fenêtre « volume changé » entre le
    # propose et le confirm (CRITIQUE 2026-05-31, review snapshot 20b8902). Le
    # dry-run est rollback (aucune écriture) — coût faible, garantie forte.
    sage = get_sage_connector()
    try:
        recheck = await sage.execute_write(captured_sql, dry_run=True)
        fresh_estimated = int(recheck.get("rows_affected", 0))
    except Exception as exc:  # noqa: BLE001 — volume non vérifiable → fail-closed
        async with get_session() as session:
            await session.execute(
                update(SqlWriteAuditLog)
                .where(SqlWriteAuditLog.id == captured_id)
                .values(
                    status=SqlWriteStatus.FAILED.value,
                    error_message=(f"re-estimation (dry-run) échouée au confirm: {exc}")[:500],
                )
            )
            await session.commit()
        logger.error(
            "iris_write_session: re-estimation dry-run FAILED audit=%d: %s",
            captured_id,
            exc,
        )
        return ConfirmResult(
            success=False,
            audit_id=captured_id,
            status=SqlWriteStatus.FAILED.value,
            error="recheck_failed",
            user_message=(
                "Impossible de re-vérifier le volume impacté au moment de "
                "l'exécution (base source injoignable ?). Aucune modification "
                "n'a été effectuée — refaire une demande à Iris."
            ),
        )

    if _row_estimate_drifted(captured_estimated, fresh_estimated, captured_op):
        async with get_session() as session:
            await session.execute(
                update(SqlWriteAuditLog)
                .where(SqlWriteAuditLog.id == captured_id)
                .values(
                    status=SqlWriteStatus.FAILED.value,
                    error_message=(
                        f"volume divergent depuis l'approbation: "
                        f"approuvé≈{captured_estimated}, ré-estimé={fresh_estimated}"
                    )[:500],
                )
            )
            await session.commit()
        logger.warning(
            "iris_write_session: volume drift audit=%d approved=%s fresh=%s — "
            "exécution refusée fail-closed",
            captured_id,
            captured_estimated,
            fresh_estimated,
        )
        return ConfirmResult(
            success=False,
            audit_id=captured_id,
            status=SqlWriteStatus.FAILED.value,
            error="row_estimate_drift",
            user_message=(
                f"Le volume impacté a changé depuis l'approbation du DBA "
                f"(approuvé : ~{captured_estimated} ligne(s), maintenant : "
                f"~{fresh_estimated}). Par sécurité, l'exécution est refusée. "
                "L'admin doit refaire une demande à Iris pour ce volume."
            ),
        )

    # Exécuter pour de vrai (hors session BDD pour ne pas tenir la transaction)
    actual_rows: int = 0
    error_msg: Optional[str] = None
    final_status = SqlWriteStatus.EXECUTED.value
    try:
        run = await sage.execute_write(captured_sql, dry_run=False)
        actual_rows = int(run.get("rows_affected", 0))
    except Exception as exc:  # noqa: BLE001 — toute erreur runtime
        error_msg = str(exc)[:500]
        final_status = SqlWriteStatus.FAILED.value
        logger.error(
            "iris_write_session: execution failed audit=%d: %s",
            captured_id,
            exc,
            exc_info=True,
        )

    # Update audit (la row est en `executing` depuis la réservation —
    # on bascule en final). dba_responded_at + dba_response_ip ont
    # déjà été posés à la réservation, on les laisse.
    async with get_session() as session:
        await session.execute(
            update(SqlWriteAuditLog)
            .where(SqlWriteAuditLog.id == captured_id)
            .values(
                status=final_status,
                actual_rows=actual_rows if final_status == SqlWriteStatus.EXECUTED.value else None,
                error_message=error_msg,
            )
        )
        await session.commit()
        result = await session.execute(
            select(SqlWriteAuditLog).where(SqlWriteAuditLog.id == captured_id)
        )
        refreshed = result.scalar_one()
        # capturer pour notif
        notif_audit = refreshed

    # Notif admin demandeur (best-effort)
    if captured_user_id is not None:
        from app.models.user import User

        async with get_session() as session:
            res = await session.execute(select(User).where(User.id == captured_user_id))
            requesting_user = res.scalar_one_or_none()
        if requesting_user is not None:
            try:
                await _send_admin_notification(
                    requesting_user=requesting_user,
                    audit=notif_audit,
                    final_status=final_status,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("iris_write_session: admin notif raised: %s", exc)

    if final_status == SqlWriteStatus.EXECUTED.value:
        return ConfirmResult(
            success=True,
            audit_id=captured_id,
            status=final_status,
            actual_rows=actual_rows,
            user_message=(
                f"Exécution réussie : {actual_rows} ligne(s) modifiée(s) " f"({captured_op})."
            ),
        )
    return ConfirmResult(
        success=False,
        audit_id=captured_id,
        status=final_status,
        error=error_msg,
        user_message=(
            "L'exécution a échoué (rollback automatique). " f"Détail : {error_msg or 'inconnu'}."
        ),
    )


async def dba_reject(
    *, token_public: str, ip: Optional[str] = None, reason: str = ""
) -> ConfirmResult:
    """Le DBA a cliqué Refuser. On marque ABORTED, pas d'exécution.

    Anti-TOCTOU : même pattern que ``dba_confirm`` — UPDATE conditionnel
    atomique pour éviter la double-action si le DBA double-clique.
    """
    token_hash = parse_and_verify(token_public)
    if token_hash is None:
        return ConfirmResult(success=False, error="invalid_token", user_message="Lien invalide.")

    now = clock.now()
    error_message = f"refusé par DBA : {reason[:400]}" if reason else None

    async with get_session() as session:
        reject_stmt = (
            update(SqlWriteAuditLog)
            .where(
                SqlWriteAuditLog.approval_token_hash == token_hash,
                SqlWriteAuditLog.status == SqlWriteStatus.AWAITING_DBA.value,
            )
            .values(
                status=SqlWriteStatus.ABORTED.value,
                dba_responded_at=now,
                dba_response_ip=(ip or "")[:45] or None,
                error_message=error_message,
            )
        )
        res = await session.execute(reject_stmt)
        await session.commit()
        rejected = (res.rowcount or 0) == 1

    if not rejected:
        # Lookup pour message précis
        async with get_session() as session:
            res = await session.execute(
                select(SqlWriteAuditLog).where(SqlWriteAuditLog.approval_token_hash == token_hash)
            )
            audit = res.scalar_one_or_none()
            if audit is None:
                return ConfirmResult(
                    success=False,
                    error="not_found",
                    user_message="Demande introuvable.",
                )
            return ConfirmResult(
                success=False,
                audit_id=audit.id,
                status=audit.status,
                error="already_handled",
                user_message=f"Demande déjà traitée (statut : {audit.status}).",
            )

    # Reload pour notif (out-of-session safe car expire_on_commit=False
    # global Komptia, vérifié database.py:1357).
    async with get_session() as session:
        res = await session.execute(
            select(SqlWriteAuditLog).where(SqlWriteAuditLog.approval_token_hash == token_hash)
        )
        notif_audit = res.scalar_one()
        captured_audit_id = notif_audit.id
        captured_user_id = notif_audit.user_id

    if captured_user_id is not None:
        from app.models.user import User

        async with get_session() as session:
            res = await session.execute(select(User).where(User.id == captured_user_id))
            requesting_user = res.scalar_one_or_none()
        if requesting_user is not None:
            try:
                await _send_admin_notification(
                    requesting_user=requesting_user,
                    audit=notif_audit,
                    final_status=SqlWriteStatus.ABORTED.value,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("iris_write_session: admin notif raised: %s", exc)

    return ConfirmResult(
        success=True,
        audit_id=captured_audit_id,
        status=SqlWriteStatus.ABORTED.value,
        user_message="Demande refusée. Aucune modification effectuée.",
    )


async def get_audit_by_id(
    audit_id: int, user_id: int, *, is_admin: bool
) -> Optional[SqlWriteAuditLog]:
    """Lookup d'un audit log spécifique pour la vue admin.

    L'admin demandeur (``user_id == audit.user_id``) ou un admin global
    (``is_admin``) peut consulter. Sinon retourne None (404 côté handler).
    """
    async with get_session() as session:
        res = await session.execute(select(SqlWriteAuditLog).where(SqlWriteAuditLog.id == audit_id))
        audit = res.scalar_one_or_none()
        if audit is None:
            return None
        if not is_admin and audit.user_id != user_id:
            return None
        return audit


async def cleanup_expired_and_zombie() -> dict[str, int]:
    """Marque ``EXPIRED`` / ``FAILED`` les rows obsolètes.

    Deux passes :
        1. ``AWAITING_DBA`` dont ``expires_at`` est dépassé → ``EXPIRED``.
        2. ``executing`` (statut interne transitoire) dont ``updated_at``
           est plus vieux que ``_ZOMBIE_THRESHOLD`` → ``FAILED`` avec
           message explicite. Détecte les crashs app pendant l'exécution
           Sage (la row reste bloquée sinon car le commit final n'a
           jamais eu lieu).

    Cron-friendly (idempotent). Retourne ``{"expired": N, "zombies": M}``.
    """
    now = clock.now()
    zombie_cutoff = now - timedelta(seconds=_ZOMBIE_AGE_SECONDS)
    async with get_session() as session:
        # Passe 1 — expirations propres
        res_expired = await session.execute(
            update(SqlWriteAuditLog)
            .where(
                SqlWriteAuditLog.status == SqlWriteStatus.AWAITING_DBA.value,
                SqlWriteAuditLog.expires_at < now,
            )
            .values(status=SqlWriteStatus.EXPIRED.value)
        )
        # Passe 2 — zombies executing
        res_zombies = await session.execute(
            update(SqlWriteAuditLog)
            .where(
                SqlWriteAuditLog.status == _INTERNAL_EXECUTING_STATUS,
                SqlWriteAuditLog.updated_at < zombie_cutoff,
            )
            .values(
                status=SqlWriteStatus.FAILED.value,
                error_message=(
                    "Exécution interrompue (crash serveur ou timeout) — "
                    "vérifier l'état réel de la BDD source manuellement."
                ),
            )
        )
        await session.commit()
        return {
            "expired": int(res_expired.rowcount or 0),
            "zombies": int(res_zombies.rowcount or 0),
        }


def cleanup_expired_and_zombie_job() -> None:
    """Wrapper sync APScheduler pour :func:`cleanup_expired_and_zombie`.

    Le ``BackgroundScheduler`` (threads) appelle ``job.func()`` SANS await :
    passer une ``async def`` directement crée une coroutine jamais awaitée
    (RuntimeWarning "coroutine ... was never awaited" en prod, job marqué
    "executed successfully" alors que le cleanup ne tourne JAMAIS — bug
    constaté le 2026-06-11). Pattern identique à
    ``wait_resume.cleanup_wait_tokens_job`` : module-level (APScheduler
    sérialise une référence textuelle ``module:func`` pour le jobstore
    persistant — une closure casse) + bridge ``asyncio.run`` + engine dédié
    (l'engine global est lié à la boucle Tornado → cross-loop interdit).
    Pas de ``run_then_drain_email_log`` : le cleanup ne fait que des UPDATE,
    aucun mail/notification.
    """
    import asyncio as _asyncio

    from app.core.database import dedicated_session_scope

    async def _job() -> None:
        async with dedicated_session_scope():
            stats = await cleanup_expired_and_zombie()
            if stats.get("expired") or stats.get("zombies"):
                logger.info("cleanup_iris_sql_write: %s", stats)

    try:
        _asyncio.run(_job())
    except Exception:  # noqa: BLE001 — un lock DB transitoire ne doit pas tuer le job
        logger.exception("cleanup_expired_and_zombie_job: asyncio.run crash")


# Alias rétrocompat (le scheduler utilise le nouveau nom).
expire_old_pending = cleanup_expired_and_zombie


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _one_off_hash() -> str:
    """Génère un hash unique pour les rows d'audit à statut terminal qui
    ne doivent jamais avoir de token réutilisable. La colonne
    ``approval_token_hash`` est UNIQUE → on doit poser une valeur
    différente à chaque insertion.
    """
    import secrets

    return secrets.token_hex(32)  # 64 chars hex, isolé du codec HMAC


__all__ = [
    "ProposeResult",
    "ConfirmResult",
    "propose_sql_write",
    "dba_confirm",
    "dba_reject",
    "cleanup_expired_and_zombie",
    "cleanup_expired_and_zombie_job",  # wrapper sync APScheduler
    "expire_old_pending",  # alias rétrocompat
]
