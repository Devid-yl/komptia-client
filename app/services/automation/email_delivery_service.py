"""
Service d'envoi d'emails avec delivery strategies + DistributionList.

Expose `resolve_recipients` + `apply_delivery_strategy` pour les nodes
email du DAG. Les 4 strategies du design §1.9 sont supportees :

1. `single_email_all_recipients` (defaut) — 1 email a TOUS les destinataires
2. `single_email_multi_attachments` — 1 email, N pieces jointes (fan-in)
3. `one_email_per_recipient` — N emails distincts, 1 par destinataire (nominatif)
4. `one_email_per_attachment` — N emails distincts, 1 par piece jointe

Design :
- Pur : ne fait pas l'envoi SMTP lui-meme. Retourne une liste de "tickets"
  {to, cc, bcc, attachments, subject, body} que l'executor consomme en
  appelant SMTPClient pour chaque ticket. Testable en unite sans SMTP.
- Generique : accepte des dicts de config + DistributionList optionnelle.
  Aucun hardcoding d'email ou de domaine.
- Fail-closed : config invalide → ValueError explicite.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.contact import DistributionList
from app.utils.logger import get_logger
from app.utils.validators import is_valid_email

logger = get_logger(__name__)


VALID_DELIVERY_STRATEGIES = (
    "single_email_all_recipients",
    "single_email_multi_attachments",
    "one_email_per_recipient",
    "one_email_per_attachment",
)


@dataclass
class EmailTicket:
    """Un email a envoyer (1 ticket = 1 appel SMTP)."""

    to: List[str] = field(default_factory=list)
    cc: List[str] = field(default_factory=list)
    bcc: List[str] = field(default_factory=list)
    subject: str = ""
    body: str = ""
    attachments: List[str] = field(default_factory=list)  # chemins absolus


# -----------------------------------------------------------------------------
# Resolution des destinataires
# -----------------------------------------------------------------------------


async def resolve_recipients(
    session: AsyncSession,
    *,
    to: Optional[List[str]] = None,
    cc: Optional[List[str]] = None,
    bcc: Optional[List[str]] = None,
    from_distribution_list_id: Optional[int] = None,
    owner_user_id: int,
) -> Dict[str, List[str]]:
    """Resout les destinataires finaux depuis la config email du node.

    - Si `from_distribution_list_id` est present, on ajoute les emails des
      contacts de la DistributionList (owner-check).
    - Sinon, on utilise les listes `to/cc/bcc` telles quelles.
    - Deduplication case-insensitive en preservant l'ordre.
    - Validation ownership : la DistributionList doit appartenir a
      `owner_user_id` (fail-closed sinon).

    Args:
        session: Session SQLAlchemy async.
        to: Liste d'emails explicites.
        cc: Liste d'emails en copie.
        bcc: Liste d'emails en copie cachee.
        from_distribution_list_id: Optionnel, ID d'une DistributionList.
        owner_user_id: User.id proprietaire (pour ownership check).

    Returns:
        Dict {"to": [...], "cc": [...], "bcc": [...]} avec emails dedupliques.

    Raises:
        ValueError si la DistributionList est introuvable ou non autorisee.
    """
    if not isinstance(owner_user_id, int):
        raise ValueError("owner_user_id est obligatoire (fail-closed ownership).")

    to_list = list(to or [])
    cc_list = list(cc or [])
    bcc_list = list(bcc or [])

    if from_distribution_list_id is not None:
        result = await session.execute(
            select(DistributionList)
            .where(DistributionList.id == int(from_distribution_list_id))
            .options(selectinload(DistributionList.contacts))
        )
        dlist = result.scalar_one_or_none()
        if dlist is None:
            raise ValueError(f"DistributionList {from_distribution_list_id} introuvable.")
        if dlist.user_id != owner_user_id:
            raise ValueError(
                f"DistributionList {from_distribution_list_id} non autorisee "
                f"pour l'utilisateur {owner_user_id}."
            )
        if not dlist.is_active:
            raise ValueError(f"DistributionList '{dlist.name}' desactivee : impossible d'envoyer.")
        for contact in dlist.contacts:
            # F3 (review loop) — SSoT destinataires : aligner sur
            # contact_mailer_service._resolve_unique_contacts (qui filtre
            # is_active.is_(True)). Un contact DÉSACTIVÉ ne doit être mailé par
            # AUCUN chemin (UI /contacts, /reports) ; l'automation via une liste
            # de diffusion ne doit pas être la seule exception silencieuse.
            if not contact.is_active:
                continue
            if contact.is_unsubscribed:
                continue
            if not contact.email:
                continue
            to_list.append(contact.email)

    # Defense-in-depth : un contact malforme en BDD ou une URL injectee dans
    # une saisie explicite ne doit jamais empoisonner le sanitize SMTP downstream
    # (qui abort tout le send au lieu de skip le mauvais destinataire).
    # Aligne avec email_dispatcher.py:85, 193, 341 — single source of truth.
    to_list = [e for e in to_list if is_valid_email(e)]
    cc_list = [e for e in cc_list if is_valid_email(e)]
    bcc_list = [e for e in bcc_list if is_valid_email(e)]

    # Dedup case-insensitive en preservant l'ordre (le 1er vu gagne)
    return {
        "to": _dedup_preserve(to_list),
        "cc": _dedup_preserve(cc_list),
        "bcc": _dedup_preserve(bcc_list),
    }


def _dedup_preserve(items: Iterable[str]) -> List[str]:
    """Deduplique en preservant l'ordre (case-insensitive)."""
    seen: set = set()
    result: List[str] = []
    for item in items:
        if not item or not isinstance(item, str):
            continue
        key = item.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(item.strip())
    return result


# -----------------------------------------------------------------------------
# Corps du mail (texte brut -> HTML)
# -----------------------------------------------------------------------------


def plain_text_to_email_html(text: object) -> str:
    """Convertit un corps d'email saisi en TEXTE BRUT vers du HTML sur.

    Contrat partage par les steps ``email`` et ``email_wait_response`` :
    le champ ``body`` de la config est du texte brut. Il est echappe HTML
    (un ``<b>`` colle par l'utilisateur s'affiche litteralement — pas
    d'injection HTML dans le mail) et les sauts de ligne deviennent des
    ``<br/>``. Les fins de ligne CRLF/CR (saisie API ou Windows) sont
    normalisees en LF d'abord pour ne pas laisser de CR orphelins.

    Args:
        text: Corps en texte brut. Coerce en ``str`` si autre type —
            une config poussee hors UI ne doit pas crasher l'envoi.

    Returns:
        Fragment HTML sur ("" si texte vide ou None).
    """
    if text is None:
        return ""
    normalized = str(text).replace("\r\n", "\n").replace("\r", "\n")
    return html.escape(normalized).replace("\n", "<br/>")


# -----------------------------------------------------------------------------
# Delivery strategies
# -----------------------------------------------------------------------------


def apply_delivery_strategy(
    *,
    strategy: str,
    recipients: Dict[str, List[str]],
    attachments: Sequence[str],
    subject: str,
    body: str,
) -> List[EmailTicket]:
    """Eclate un envoi en N tickets selon la strategie.

    Args:
        strategy: Une des VALID_DELIVERY_STRATEGIES.
        recipients: Dict {"to", "cc", "bcc"} des destinataires resolus.
        attachments: Liste de chemins de fichiers (peut etre vide).
        subject: Sujet de l'email.
        body: Corps de l'email.

    Returns:
        Liste de EmailTicket. Chaque ticket = 1 appel SMTP.

    Raises:
        ValueError si la strategie est inconnue ou la config incoherente
        (ex: one_email_per_attachment sans attachments).
    """
    if strategy not in VALID_DELIVERY_STRATEGIES:
        raise ValueError(
            f"Strategie de livraison inconnue: '{strategy}'. "
            f"Valeurs: {list(VALID_DELIVERY_STRATEGIES)}"
        )

    to_list = list(recipients.get("to", []))
    cc_list = list(recipients.get("cc", []))
    bcc_list = list(recipients.get("bcc", []))
    attachments_list = list(attachments or [])

    if not to_list and not cc_list and not bcc_list:
        # Pas de destinataire → aucun ticket (l'adapter loggue un warning)
        return []

    if strategy == "single_email_all_recipients":
        # 1 email a tous, avec TOUTES les attachments
        return [
            EmailTicket(
                to=to_list,
                cc=cc_list,
                bcc=bcc_list,
                subject=subject,
                body=body,
                attachments=attachments_list,
            )
        ]

    if strategy == "single_email_multi_attachments":
        # Identique a single_email_all pour le moment (toutes les pj).
        # Semantique explicite : l'utilisateur declare que c'est OK d'envoyer
        # 5 pj dans un seul mail (plutot que 5 mails separes).
        return [
            EmailTicket(
                to=to_list,
                cc=cc_list,
                bcc=bcc_list,
                subject=subject,
                body=body,
                attachments=attachments_list,
            )
        ]

    if strategy == "one_email_per_recipient":
        # N emails (1 par destinataire To). Cc/Bcc gardes identiques dans
        # tous les mails (le contrat du nominatif : le To est specifique).
        tickets: List[EmailTicket] = []
        for recipient in to_list:
            tickets.append(
                EmailTicket(
                    to=[recipient],
                    cc=cc_list,
                    bcc=bcc_list,
                    subject=subject,
                    body=body,
                    attachments=attachments_list,
                )
            )
        return tickets

    if strategy == "one_email_per_attachment":
        # N emails (1 par piece jointe). Tous les destinataires recoivent
        # chaque email. Si pas d'attachments, fallback sur single.
        if not attachments_list:
            return [
                EmailTicket(
                    to=to_list,
                    cc=cc_list,
                    bcc=bcc_list,
                    subject=subject,
                    body=body,
                    attachments=[],
                )
            ]
        tickets = []
        for attachment in attachments_list:
            tickets.append(
                EmailTicket(
                    to=to_list,
                    cc=cc_list,
                    bcc=bcc_list,
                    subject=subject,
                    body=body,
                    attachments=[attachment],
                )
            )
        return tickets

    # Unreachable (strategy validee en debut)
    return []
