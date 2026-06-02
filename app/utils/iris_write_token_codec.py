"""Codec HMAC pour les tokens d'approbation des écritures SQL via Iris.

Le token public envoyé dans le mail au DBA externe a la forme :

    ``iw1.<uuid_hex>.<hmac_hex>``

où :
- ``iw1`` = version du format
- ``uuid_hex`` = UUID4 (32 chars hex) — entropie >= 122 bits
- ``hmac_hex`` = HMAC-SHA256(uuid_hex, SECRET_KEY) tronqué à 32 chars

Vérification : on parse le token, on revalide le HMAC, puis on hash
``uuid_hex`` avec SHA-256 pour lookup dans
``sql_write_audit_log.approval_token_hash``.

Le HMAC permet de rejeter en O(1) un attaquant qui tenterait de
brute-forcer des UUID au hasard sans avoir capturé aucun token. La
table ``sql_write_audit_log`` ne stocke JAMAIS l'UUID brut, uniquement
son SHA-256, donc même un dump BDD ne permet pas de forger un lien.

Codec **séparé** de ``wait_token_codec`` (qui sert aux automations
``email_wait_response``) pour deux raisons :
    1. **Scope crypto distinct** : la clé dérivée utilise le préfixe
       ``"iris-write:"`` au lieu de ``"wait-token:"`` — un token
       valide pour un wait_response NE PEUT PAS être réutilisé pour
       approuver une écriture SQL (et inverse).
    2. **Sémantique différente** : un wait_token a un response_kind
       et est lié à un step d'automation ; ici on a juste un
       lien GO/NOGO. Pas de confusion possible.

Réf : CWE-330 (Use of Insufficiently Random Values), OWASP Cheat Sheet
sur les tokens cryptographiques.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import uuid
from typing import Optional, Tuple

from app.utils.logger import get_logger

logger = get_logger(__name__)

#: Version du format. Bump si on change la structure.
_TOKEN_VERSION = "iw1"

#: Longueur du HMAC tronqué dans le token public. 32 hex = 128 bits.
_HMAC_HEX_LEN = 32

#: Fallback ephémère si SECRET_KEY est absent (process-scoped — un
#: restart serveur invalide TOUS les tokens en cours, ce qui est
#: documenté comme dégradation gracieuse).
_EPHEMERAL_SECRET = secrets.token_bytes(32)


_warned_about_ephemeral = False


def _secret() -> bytes:
    """Dérive une clé HMAC distincte des autres usages crypto pour
    éviter les collisions inter-fonctionnalités.

    Si ``SECRET_KEY`` est absent, on fallback sur un secret éphémère
    process-scoped et on logue un WARNING **à chaque émission** (pas
    juste une fois) pour que l'admin voit l'erreur dans les logs et
    configure ``SECRET_KEY`` avant de stabiliser le déploiement.
    """
    global _warned_about_ephemeral
    raw = os.environ.get("SECRET_KEY") or ""
    if not raw:
        if not _warned_about_ephemeral:
            logger.error(
                "SECRET_KEY absent — iris-write-token-codec utilise une clé "
                "éphémère qui sera invalidée à chaque restart Tornado. "
                "Configurer SECRET_KEY dans .env pour que les liens "
                "d'approbation DBA survivent aux redémarrages."
            )
            _warned_about_ephemeral = True
        return _EPHEMERAL_SECRET
    return hashlib.sha256(("iris-write:" + raw).encode("utf-8")).digest()


def issue_token() -> Tuple[str, str]:
    """Génère un nouveau token public + son hash pour stockage.

    Returns:
        Tuple ``(token_public, token_hash)`` :
            - ``token_public`` : à inclure dans l'URL du mail au DBA
              (``iw1.<uuid>.<hmac>``). N'est PAS persisté.
            - ``token_hash`` : à stocker dans
              ``sql_write_audit_log.approval_token_hash`` (SHA-256 hex
              de l'UUID brut, 64 chars).

    Le token public n'est plus accessible après cet appel. Le caller
    doit l'envoyer au DBA immédiatement — on ne peut PAS le re-dériver
    depuis le hash.
    """
    raw_uuid = uuid.uuid4().hex  # 32 chars hex, 122 bits d'entropie
    sig = hmac.new(_secret(), raw_uuid.encode("ascii"), hashlib.sha256).hexdigest()
    truncated_sig = sig[:_HMAC_HEX_LEN]
    token_public = f"{_TOKEN_VERSION}.{raw_uuid}.{truncated_sig}"
    token_hash = hashlib.sha256(raw_uuid.encode("ascii")).hexdigest()
    return token_public, token_hash


def parse_and_verify(token_public: str) -> Optional[str]:
    """Parse un token reçu de l'URL et retourne son ``token_hash`` si valide.

    Returns:
        ``token_hash`` (64 chars hex) pour lookup BDD si le token
        est syntactiquement valide ET que le HMAC matche. ``None``
        sinon (signature invalide, format cassé, version inconnue).

    Ne fait PAS de lookup BDD ni de check d'expiration — c'est au
    handler appelant de faire ces vérifications via la row
    ``SqlWriteAuditLog`` correspondante. Cette fonction se limite à
    la vérification cryptographique (défense en profondeur : un
    attaquant qui n'a pas capturé le token brut ne peut pas en forger
    un valide même s'il connaît des UUIDs).
    """
    if not isinstance(token_public, str):
        return None
    if len(token_public) > 200:
        # Defense DoS : refuser les tokens trop longs avant tout parsing.
        return None
    parts = token_public.split(".")
    if len(parts) != 3:
        return None
    version, raw_uuid, sig_recv = parts
    if version != _TOKEN_VERSION:
        return None
    # UUID = 32 chars hex strict
    if len(raw_uuid) != 32 or not all(c in "0123456789abcdef" for c in raw_uuid):
        return None
    if len(sig_recv) != _HMAC_HEX_LEN:
        return None
    expected = hmac.new(_secret(), raw_uuid.encode("ascii"), hashlib.sha256).hexdigest()
    expected_truncated = expected[:_HMAC_HEX_LEN]
    if not hmac.compare_digest(expected_truncated, sig_recv):
        return None
    return hashlib.sha256(raw_uuid.encode("ascii")).hexdigest()


__all__ = ["issue_token", "parse_and_verify"]
