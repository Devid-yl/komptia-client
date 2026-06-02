"""Modele ``WaitToken`` — corruption-resistant token pour les etapes
``email_wait_response`` qui suspendent une automation jusqu'a ce qu'un
destinataire externe soumette une reponse via lien tokenise.

Architecture (cf. brainstorm Feature 1 — « lien dans le mail » n8n-style)
------------------------------------------------------------------------

1. Step ``email_wait_response`` execute :
   - Cree une row WaitToken (token UUID + HMAC + expires_at)
   - Envoie le mail au destinataire avec le lien
     ``https://komptia.tld/automations/wait/{token}``
   - Marque step + execution = ``waiting``
   - Persist le checkpoint (snapshot des step_outputs) sur Execution

2. Destinataire ouvre le lien :
   - GET ``/automations/wait/{token}`` valide HMAC + expires_at + status
   - Affiche un form (texte / upload / les deux)

3. Destinataire soumet :
   - POST ``/automations/wait/{token}`` valide a nouveau + stocke reponse
   - Marque WaitToken.status = ``resolved``
   - Schedule un job APScheduler one-shot pour reprendre l'execution

4. Reprise :
   - L'executor rehydrate le checkpoint depuis Execution.wait_checkpoint
   - Le step ``email_wait_response`` retourne maintenant la reponse comme
     output (workbook si fichier upload, classeur 1-cellule si juste texte)
   - Le DAG continue avec les steps suivants

Securite
--------
* ``token`` est UUID4 (entropie >= 122 bits) genere a la creation.
* ``token_hash`` (SHA-256) est ce qui est stocke et indexe — le token
  brut n'est JAMAIS persiste cote serveur (defense en profondeur :
  meme un dump BDD ne permet pas de forger un lien valide).
* Validation : on hash le token recu de l'URL et on cherche par
  ``token_hash``, puis on compare en constant-time (defense vs timing).
* HMAC supplementaire dans le token brut (cf. ``app/utils/wait_token_codec.py``)
  garantit qu'un attaquant ne peut pas brute-forcer des UUIDs.

Lifecycle
---------
``pending`` → ``resolved`` (reponse recue)
            → ``expired`` (TTL atteint sans reponse)
            → ``cancelled`` (cancel-on-next-run, user desactive, etc.)

RGPD / privacy
--------------
La reponse texte (``response_text``) et le fichier (``response_file_path``)
sont traites comme des donnees utilisateur classiques : chiffres au repos
via SQLCipher (BDD) et stockage filesystem dans le datastore proprio
de l'automation. Pas d'exposition cross-user.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core import clock
from app.models.base import Base

# Statuts valides — frozen, pas une enum BDD pour eviter migration
# au moindre nouveau statut futur.
WAIT_TOKEN_STATUSES = ("pending", "resolved", "expired", "cancelled")

# Reponses acceptees par l'UI (mirror du config_schema email_wait_response).
WAIT_RESPONSE_KINDS = ("text", "file", "both")


class WaitToken(Base):
    """Lien tokenise pour qu'un destinataire externe reponde a un step
    ``email_wait_response`` et fasse reprendre l'automation.

    Une row par envoi. Si l'admin re-execute l'automation pendant
    l'attente, l'ancienne row est marquee ``cancelled`` et une nouvelle
    est creee au prochain hit du step.
    """

    __tablename__ = "F_WAIT_TOKEN"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    execution_id: Mapped[int] = mapped_column(
        ForeignKey("F_EXECUTION.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Execution qui attend cette reponse",
    )
    step_id: Mapped[int] = mapped_column(
        ForeignKey("F_AUTOMATION_STEP.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Step email_wait_response qui a cree ce token",
    )

    # Hash SHA-256 (hex 64 chars) du token brut. Le token brut n'est
    # jamais stocke ; lookup = SHA-256(token_recu) puis compare_digest.
    token_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
        comment="SHA-256 du token brut (jamais persiste)",
    )

    recipient_email: Mapped[str] = mapped_column(
        String(254),  # RFC 5321
        nullable=False,
        comment="Email du destinataire qui doit repondre",
    )

    # text | file | both (cf. WAIT_RESPONSE_KINDS)
    response_kind: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="text",
        comment="Type de reponse attendue (text, file, both)",
    )

    # csv | xlsx | both — applicable si response_kind != text
    file_format: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="both",
        comment="Format de fichier accepte (csv, xlsx, both)",
    )

    # pending | resolved | expired | cancelled
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        index=True,
        comment="Statut courant du token (cf. WAIT_TOKEN_STATUSES)",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        comment="Date de creation du token (= envoi du mail)",
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        index=True,
        comment="Date d'expiration calculee (TTL adaptatif ou override)",
    )

    # Reponse recue
    response_text: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Reponse libre saisie par le destinataire (response_kind != file)",
    )
    response_file_path: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        comment="Chemin relatif du fichier uploade (response_kind != text)",
    )
    response_file_name: Mapped[Optional[str]] = mapped_column(
        String(200),
        nullable=True,
        comment="Nom original du fichier (avant sanitisation)",
    )
    response_file_size: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Taille en octets du fichier uploade",
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Date a laquelle le destinataire a soumis sa reponse",
    )
    resolved_from_ip: Mapped[Optional[str]] = mapped_column(
        String(45),  # IPv6 max
        nullable=True,
        comment="IP du submit (audit trail, anti-abuse)",
    )

    # Metadonnees pour affichage / annulation
    cancellation_reason: Mapped[Optional[str]] = mapped_column(
        String(200),
        nullable=True,
        comment=(
            "Raison de l'annulation si status='cancelled' "
            "(ex: 'Nouvelle execution declenchee', 'User desactive')"
        ),
    )
    reminder_sent_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Date du rappel envoye au proprio (NULL si jamais envoye)",
    )

    # Relations
    execution = relationship("Execution", backref="wait_tokens")

    __table_args__ = (
        Index("ix_wait_token_status_expires", "status", "expires_at"),
        Index("ix_wait_token_execution_step", "execution_id", "step_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<WaitToken(id={self.id}, exec={self.execution_id}, "
            f"step={self.step_id}, status='{self.status}')>"
        )

    @property
    def is_pending(self) -> bool:
        return self.status == "pending"

    @property
    def is_resolved(self) -> bool:
        return self.status == "resolved"

    @property
    def is_expired_now(self) -> bool:
        """True si pending ET expires_at depasse l'heure courante.

        Verification active (vs flag persiste) : un cron tournera plus
        tard pour basculer status='pending' -> 'expired' en BDD, mais
        cote handler on doit refuser un lien deja expire meme si le
        cron n'est pas encore passe.
        """
        if self.status != "pending":
            return False
        from app.models.base import ensure_utc

        return clock.now() > ensure_utc(self.expires_at)

    def mark_resolved(
        self,
        *,
        response_text: Optional[str] = None,
        response_file_path: Optional[str] = None,
        response_file_name: Optional[str] = None,
        response_file_size: Optional[int] = None,
        resolved_from_ip: Optional[str] = None,
    ) -> None:
        """Pose la reponse + status='resolved'."""
        self.status = "resolved"
        self.resolved_at = clock.now()
        if response_text is not None:
            self.response_text = response_text
        if response_file_path is not None:
            self.response_file_path = response_file_path
            self.response_file_name = response_file_name
            self.response_file_size = response_file_size
        if resolved_from_ip is not None:
            self.resolved_from_ip = resolved_from_ip[:45]  # cap IPv6

    def mark_expired(self) -> None:
        self.status = "expired"

    def mark_cancelled(self, reason: str) -> None:
        self.status = "cancelled"
        self.cancellation_reason = (reason or "")[:200]

    def to_dict(self, *, include_response: bool = False) -> dict:
        """Sortie JSON pour l'API admin (page /executions ou similaire).

        ``include_response=True`` n'inclut le contenu de la reponse que
        si l'appelant a verifie l'ownership (proprio de l'automation).
        Defaut False pour minimiser le risque de leak accidentel.
        """
        out = {
            "id": self.id,
            "execution_id": self.execution_id,
            "step_id": self.step_id,
            "recipient_email": self.recipient_email,
            "response_kind": self.response_kind,
            "file_format": self.file_format,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "cancellation_reason": self.cancellation_reason,
            "has_response_text": bool(self.response_text),
            "has_response_file": bool(self.response_file_path),
            "response_file_name": self.response_file_name,
            "response_file_size": self.response_file_size,
        }
        if include_response:
            out["response_text"] = self.response_text
            out["response_file_path"] = self.response_file_path
        return out
