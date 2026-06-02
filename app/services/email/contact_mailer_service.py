"""Service métier pour l'envoi d'emails libres aux contacts d'un user.

Pourquoi ce module
------------------
``ReportEmailHandler`` (`app/handlers/reports.py`) sait déjà envoyer des
emails — mais avec **rapports en pièces jointes obligatoires**. Pour la
feature "envoyer un mail depuis /contacts", on a besoin d'un envoi
**libre** (subject + body + destinataires), sans pièce jointe forcée.

Plutôt que de tordre ``ReportEmailHandler`` (qui aurait fini avec 6
chemins ``if`` selon le cas d'usage), on extrait la logique réutilisable
dans ce service. Si une 3ᵉ feature email surgit (ex: notifier les users
d'une automation cassée), elle réutilise ce service.

Différences vs `/reports`
-------------------------
* **Pas de pièce jointe** (subject + body suffisent).
* **Filtre RGPD** : ``unsubscribed_at IS NOT NULL`` est exclu côté SQL.
  Le handler ``/reports`` actuel ne filtre PAS — bug noté dans la review
  adversariale, à corriger en parallèle.
* **Body en TEXTE** (pas HTML libre) — l'utilisateur tape du texte plain,
  on échappe et on wrappe en HTML simple. Évite le risque XSS d'un
  WYSIWYG côté client.
* **Caps explicites** : ``MAX_SUBJECT=500`` (aligné `EmailLog.subject`),
  ``MAX_BODY=10000`` (raisonnable pour un email pro).

Sécurité
--------
* Multi-tenant strict : ``Contact.user_id == user.id`` partout.
* Anti-injection email : ``is_valid_email()`` (validators.py) sur chaque
  destinataire AVANT l'appel SMTP.
* Anti-XSS body : ``html.escape()`` du texte utilisateur.
* Anti-CRLF subject : ``smtp_client._sanitize_header`` (interne).
* Aucun PII en clair dans les logs : ``hash_pii()`` sur les emails
  destinataires (cf. `request_context.py`).
* Audit trail : entrée ``EmailLog`` créée systématiquement via le chemin
  centralisé ``SMTPClient.send_email`` (audit_log=True par défaut, succès OU
  échec) — l'admin peut auditer après coup.

À NE PAS oublier au moment de la mise en prod
---------------------------------------------
* Lien de désabonnement RGPD dans le footer (TODO ouvert pour quand
  l'endpoint public ``/unsubscribe?token=...`` sera implémenté). Pour
  l'instant, le footer affiche juste un texte qui mentionne la possibilité.
"""

from __future__ import annotations

import html as html_module
import logging
import smtplib
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import config
from app.models.contact import Contact, DistributionList
from app.models.user import User
from app.services.email.smtp_factory import build_smtp_client_from_db
from app.utils.request_context import current_log_extra, hash_pii
from app.utils.validators import is_valid_email

logger = logging.getLogger(__name__)


# ── Bornes input (alignées sur le schéma EmailLog) ──────────────────
MAX_EMAIL_SUBJECT_LENGTH = 500
MAX_EMAIL_BODY_LENGTH = 10_000
MAX_RECIPIENTS_PER_SEND = 500


@dataclass
class ContactMailResult:
    """Retour du service ``send_email_to_contacts``.

    ``recipients_count`` est le nombre de destinataires réellement
    contactés (post-déduplication, post-filtre RGPD). ``skipped_*``
    expose les exclusions pour que le frontend affiche un feedback honnête
    plutôt qu'un "succès" trompeur quand 50 % des destinataires ont été
    silencieusement ignorés.
    """

    success: bool
    recipients_count: int = 0
    skipped_unsubscribed: int = 0
    skipped_invalid_email: int = 0
    refused_count: int = 0
    error: str | None = None
    status_code: int = 200


def _build_html_body(text_body: str, sender_username: str) -> str:
    """Wrappe un texte plain dans un HTML simple, anti-XSS.

    On garde le HTML minimaliste (pas de WYSIWYG) : ``<p>`` + ``<br/>``
    pour les sauts de ligne. ``html.escape`` neutralise les ``<script>``
    qu'un user pourrait taper.

    Le footer mentionne la possibilité de se désabonner (sans lien actif
    pour l'instant — TODO endpoint ``/unsubscribe?token=...`` à implémenter
    pour conformité RGPD complète).
    """
    safe_text = html_module.escape(text_body).replace("\n", "<br/>")
    safe_sender = html_module.escape(sender_username)
    return (
        '<html><body style="font-family:sans-serif;color:#222;line-height:1.5;">'
        f"<div>{safe_text}</div>"
        '<hr style="margin-top:32px;border:none;border-top:1px solid #ddd;"/>'
        f'<p style="font-size:11px;color:#888;">'
        f"Email envoyé via {html_module.escape(config.app_name)} par {safe_sender}.<br/>"
        "Pour vous désabonner et ne plus recevoir ces messages, contactez l'expéditeur."
        "</p>"
        "</body></html>"
    )


async def _resolve_unique_contacts(
    session: AsyncSession,
    user: User,
    contact_ids: list[int],
    list_ids: list[int],
) -> tuple[list[Contact], int]:
    """Charge les contacts à mailer, multi-tenant-safe, RGPD-compliant.

    Filtres appliqués **AU NIVEAU SQL** (pas en Python — fix adversarial S-02
    pour fermer la fenêtre de race condition entre SELECT et filter) :
    * ``Contact.user_id == user.id`` (multi-tenant)
    * ``Contact.is_active.is_(True)`` (anti désactivation manuelle, S-03)
    * ``Contact.unsubscribed_at.is_(None)`` (RGPD, S-02)
    * ``DistributionList.is_active.is_(True)`` quand on passe par list_ids

    Retourne ``(eligible_contacts, skipped_excluded)``. Les contacts
    exclus regroupent désactivés + désabonnés + (membres de listes
    désactivées) : on agrège pour ne pas mentir sur le détail (un 2ᵉ
    SELECT ferait la distinction mais coût sans gain UX). Le frontend
    affiche "X exclus (désactivés ou désabonnés)" — transparence > silence.
    """
    eligible: dict[int, Contact] = {}
    seen_ids_total: set[int] = set()

    # 1) Contacts directs (par IDs).
    if contact_ids:
        # Compte total matchant (owner uniquement) pour calculer les exclus.
        total_result = await session.execute(
            select(Contact.id).where(
                Contact.id.in_(contact_ids),
                Contact.user_id == user.id,
            )
        )
        seen_ids_total.update(row[0] for row in total_result.all())

        # Eligible : owner + actif + non désabonné. Filtre SQL.
        elig_result = await session.execute(
            select(Contact).where(
                Contact.id.in_(contact_ids),
                Contact.user_id == user.id,
                Contact.is_active.is_(True),
                Contact.unsubscribed_at.is_(None),
            )
        )
        for c in elig_result.scalars().all():
            eligible[c.id] = c

    # 2) Contacts via listes — la liste DOIT être active. Les contacts
    # désabonnés/inactifs sont filtrés au niveau Python car selectinload
    # ne supporte pas un WHERE sur la cible chargée. Mais c'est OK : le
    # multi-tenant + active de la LISTE est déjà filtré côté SQL.
    if list_ids:
        result = await session.execute(
            select(DistributionList)
            .where(
                DistributionList.id.in_(list_ids),
                DistributionList.user_id == user.id,
                DistributionList.is_active.is_(True),
            )
            .options(selectinload(DistributionList.contacts))
        )
        for dl in result.scalars().all():
            for c in dl.contacts:
                if c.user_id != user.id:
                    continue
                seen_ids_total.add(c.id)
                if c.is_active and not c.is_unsubscribed:
                    eligible[c.id] = c

    skipped_excluded = len(seen_ids_total - set(eligible.keys()))
    return list(eligible.values()), skipped_excluded


async def resolve_recipient_emails(
    session: AsyncSession,
    user: User,
    contact_ids: list[int],
    list_ids: list[int],
) -> tuple[list[str], int, int]:
    """Résout les emails destinataires éligibles — SSoT partagé contacts + reports.

    Source de vérité UNIQUE de « qui peut-on mailer ». Applique le filtre
    multi-tenant + RGPD (``is_active`` + ``unsubscribed_at``, au niveau SQL
    via :func:`_resolve_unique_contacts`), puis déduplique **case-insensitive**
    et valide chaque adresse via ``is_valid_email``.

    Ne filtre PAS le plafond ``MAX_RECIPIENTS_PER_SEND`` : chaque appelant
    formate l'erreur « trop de destinataires » selon sa couche transport (un
    service renvoie un ``ContactMailResult``, un handler lève une ``HTTPError``).

    Returns:
        ``(emails_ordered, skipped_unsubscribed, skipped_invalid)`` —
        ``emails_ordered`` préserve l'ordre de première apparition.
    """
    contacts, skipped_unsubscribed = await _resolve_unique_contacts(
        session, user, contact_ids, list_ids
    )
    # Dédup par email **case-insensitive** : zéro provider réel ne distingue
    # ``A@x.com`` de ``a@x.com``. Sans normalisation, deux contacts au casing
    # différent enverraient deux mails.
    emails_ordered: list[str] = []
    seen_lower: set[str] = set()
    skipped_invalid = 0
    for c in contacts:
        if not c.email or not is_valid_email(c.email):
            skipped_invalid += 1
            continue
        key = c.email.lower()
        if key in seen_lower:
            continue
        seen_lower.add(key)
        emails_ordered.append(c.email)
    return emails_ordered, skipped_unsubscribed, skipped_invalid


async def send_email_to_contacts(
    session: AsyncSession,
    user: User,
    *,
    contact_ids: list[int],
    list_ids: list[int],
    subject: str,
    body: str,
) -> ContactMailResult:
    """Envoie un email texte aux contacts désignés (multi-tenant-safe).

    Args:
        session: Session SQLAlchemy async (commit géré par le caller).
        user: Acteur authentifié, owner des contacts/listes ciblés.
        contact_ids: IDs de contacts directement sélectionnés.
        list_ids: IDs de listes de diffusion (les membres seront résolus).
        subject: Objet (≤ ``MAX_EMAIL_SUBJECT_LENGTH``, non vide).
        body: Texte plain (≤ ``MAX_EMAIL_BODY_LENGTH``, non vide).

    Returns:
        :class:`ContactMailResult` avec statut + compteurs détaillés.

    Raises:
        Aucune exception métier : tout est encapsulé dans le retour.
        Les erreurs SMTP / DB sont catchées, loggées, et exposées via
        ``result.error`` avec un ``status_code`` HTTP indicatif.
    """
    # ── Validation input ──────────────────────────────────────────────
    if not subject or not subject.strip():
        return ContactMailResult(success=False, error="L'objet est requis", status_code=400)
    if len(subject) > MAX_EMAIL_SUBJECT_LENGTH:
        return ContactMailResult(
            success=False,
            error=f"L'objet dépasse {MAX_EMAIL_SUBJECT_LENGTH} caractères",
            status_code=400,
        )
    if not body or not body.strip():
        return ContactMailResult(success=False, error="Le message est requis", status_code=400)
    if len(body) > MAX_EMAIL_BODY_LENGTH:
        return ContactMailResult(
            success=False,
            error=f"Le message dépasse {MAX_EMAIL_BODY_LENGTH} caractères",
            status_code=400,
        )
    # Anti CRLF/header-injection : un subject contenant ``\r`` ou ``\n``
    # permet d'injecter des en-têtes SMTP arbitraires (Bcc:, Reply-To:,
    # MIME-Version:…). ``_sanitize_header`` du SMTPClient lève ValueError
    # NON-catchée — on coupe court ici avec un 400 propre + audit.
    if "\r" in subject or "\n" in subject:
        return ContactMailResult(
            success=False,
            error="L'objet contient des caractères interdits (retour à la ligne)",
            status_code=400,
        )
    if not contact_ids and not list_ids:
        return ContactMailResult(
            success=False, error="Aucun destinataire spécifié", status_code=400
        )

    # ── Résolution destinataires (multi-tenant + RGPD) — SSoT partagé ──
    # Même résolveur que ``/reports`` (cf. resolve_recipient_emails) : on ne
    # duplique plus la logique filtre + dédup + validation.
    emails_ordered, skipped_unsubscribed, skipped_invalid = await resolve_recipient_emails(
        session, user, contact_ids, list_ids
    )
    if not emails_ordered:
        # Soit tous désabonnés/inactifs, soit aucune adresse valide.
        msg = (
            "Tous les destinataires sélectionnés sont désabonnés (RGPD)"
            if skipped_unsubscribed
            else "Aucune adresse email valide parmi les destinataires"
        )
        return ContactMailResult(
            success=False,
            error=msg,
            skipped_unsubscribed=skipped_unsubscribed,
            skipped_invalid_email=skipped_invalid,
            status_code=400,
        )

    # Borne dure anti-DoS (un user qui mailerait 100k personnes via une
    # liste géante doit passer par les automatisations, pas par la modale).
    if len(emails_ordered) > MAX_RECIPIENTS_PER_SEND:
        return ContactMailResult(
            success=False,
            error=(
                f"Trop de destinataires ({len(emails_ordered)}). "
                f"Maximum {MAX_RECIPIENTS_PER_SEND} par envoi — utilisez "
                "les automatisations pour des envois plus volumineux."
            ),
            status_code=400,
        )

    # ── SMTP : factory centralisé (lit SMTPGlobalConfig actif) ────────
    smtp_client = await build_smtp_client_from_db(
        fallback_from_name=f"{user.username} via {config.app_name}",
    )
    if smtp_client is None:
        return ContactMailResult(
            success=False,
            error=(
                "Configuration SMTP absente ou désactivée. "
                "Demandez à un administrateur de configurer l'envoi d'emails."
            ),
            status_code=400,
        )

    # ── Envoi ────────────────────────────────────────────────────────
    # PRIVACY (fix adversarial S-04) : on envoie le mail À l'expéditeur
    # lui-même (To:) et tous les destinataires en BCC. Sinon le contact A
    # voit en clair l'email du contact B dans son champ ``To:`` —
    # divulgation de carnet d'adresses entre clients du cabinet.
    #
    # AUDIT : centralisé dans ``SMTPClient.send_email`` (kwargs
    # ``audit_log=True`` par défaut, ``sent_by_user_id=user.id``). Plus
    # de pré-flight commit local — l'audit est post-send best-effort. On
    # accepte la (très rare) fenêtre crash mid-flow pour garantir la
    # single-source-of-truth de l'audit sur les 11 sites d'envoi (cf.
    # ``app/services/email/smtp_client.py``).
    body_html = _build_html_body(body, user.username)
    try:
        send_result = await smtp_client.send_email(
            to_emails=[user.email],
            bcc_emails=emails_ordered,
            subject=subject,
            body_html=body_html,
            reply_to=user.email,
            sent_by_user_id=user.id,
        )
    except (smtplib.SMTPException, OSError, ValueError) as exc:
        # ``ValueError`` peut être levé par ``_sanitize_header`` du SMTPClient
        # si un header (subject, from_name, reply_to) contient CRLF. Fix S-01.
        logger.error(
            "Contact email send failed (SMTP/OS)",
            exc_info=True,
            extra=current_log_extra(
                operation="contact_email_send",
                exc_type=type(exc).__name__,
                recipients_count=len(emails_ordered),
            ),
        )
        return ContactMailResult(
            success=False,
            error="Erreur SMTP — l'email n'a pas pu être envoyé",
            recipients_count=len(emails_ordered),
            skipped_unsubscribed=skipped_unsubscribed,
            skipped_invalid_email=skipped_invalid,
            status_code=500,
        )

    if not send_result.get("success"):
        # Le sender est en To: (copie) et les vrais destinataires en BCC.
        # ``refused_recipients`` peut donc inclure l'adresse du sender : on ne
        # compte comme refusés que les VRAIS destinataires (intersection avec
        # ``emails_ordered``). Sinon un refus de la copie sender masquerait un
        # envoi pourtant réussi (faux échec total) ou fausserait le compteur.
        # Case-insensitive : le serveur SMTP peut canonicaliser/minusculiser
        # l'adresse RCPT échouée (RFC) alors que ``emails_ordered`` garde la
        # casse d'origine. Sans normalisation on raterait le refus → on
        # rapporterait à tort un destinataire refusé comme livré (donnée
        # fausse). Cohérent avec la dédup case-insensitive plus haut.
        refused = send_result.get("refused_recipients") or []
        refused_lower = {str(e).lower() for e in refused}
        refused_count = sum(1 for e in emails_ordered if e.lower() in refused_lower)
        delivered = len(emails_ordered) - refused_count
        if send_result.get("partial_success") and delivered > 0:
            logger.warning(
                "Contact email partiel : %s/%s destinataire(s) refusé(s)",
                refused_count,
                len(emails_ordered),
            )
            return ContactMailResult(
                success=True,
                recipients_count=delivered,
                skipped_unsubscribed=skipped_unsubscribed,
                skipped_invalid_email=skipped_invalid,
                refused_count=refused_count,
            )
        logger.error(
            "Contact email send: SMTP returned failure",
            extra=current_log_extra(
                operation="contact_email_send",
                recipients_count=len(emails_ordered),
                smtp_error=send_result.get("error"),
            ),
        )
        return ContactMailResult(
            success=False,
            error="L'email n'a pas pu être envoyé",
            recipients_count=len(emails_ordered),
            skipped_unsubscribed=skipped_unsubscribed,
            skipped_invalid_email=skipped_invalid,
            status_code=500,
        )

    # Audit RGPD-friendly : on logue les emails sous forme HASHÉE pour
    # corrélation sans stocker la PII en clair pendant 30j.
    logger.info(
        "Contact email sent",
        extra=current_log_extra(
            operation="contact_email_send",
            recipients_count=len(emails_ordered),
            recipients_hash=[hash_pii(e) for e in emails_ordered[:10]],
            recipients_truncated=len(emails_ordered) > 10,
            subject_hash=hash_pii(subject),
            skipped_unsubscribed=skipped_unsubscribed,
            skipped_invalid_email=skipped_invalid,
        ),
    )
    return ContactMailResult(
        success=True,
        recipients_count=len(emails_ordered),
        skipped_unsubscribed=skipped_unsubscribed,
        skipped_invalid_email=skipped_invalid,
    )


# NOTE : ``_log_email_failure`` retiré — l'audit ``EmailLog`` est désormais
# centralisé dans ``SMTPClient.send_email`` (single source of truth pour
# les 11 sites d'envoi de la codebase).
