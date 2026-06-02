"""Codec HMAC pour les tokens de step ``email_wait_response``.

Le token public envoye dans le mail au destinataire a la forme :

    ``wt1.<uuid_hex>.<hmac_hex>``

ou :
- ``wt1`` = version du format (futur-proof)
- ``uuid_hex`` = UUID4 (32 chars hex) — entropie >= 122 bits
- ``hmac_hex`` = HMAC-SHA256(uuid_hex, SECRET_KEY) tronque a 32 chars

Verification : on parse le token, on revalide le HMAC, puis on hash
``uuid_hex`` avec SHA-256 pour lookup dans ``F_WAIT_TOKEN.token_hash``.

Le HMAC permet de rejeter en O(1) un attaquant qui tenterait de
brute-forcer des UUID au hasard sans avoir capture aucun token. La
table ``F_WAIT_TOKEN`` ne stocke JAMAIS l'UUID brut, uniquement son
SHA-256, donc meme un dump BDD ne permet pas de forger un lien.

Ne PAS utiliser ce codec hors du contexte ``email_wait_response`` :
les autres tokens (preview output, webhooks) ont leurs propres codecs
avec des semantiques d'expiration et de scope distinctes.
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

#: Version du format. Bump si on change la structure (ex: ajout d'un
#: scope explicite dans le token).
_TOKEN_VERSION = "wt1"

#: Longueur du HMAC tronque dans le token public. 32 hex chars = 128
#: bits — suffisant contre brute-force online (rate-limited par
#: l'endpoint), tout en gardant l'URL maniable.
_HMAC_HEX_LEN = 32

#: Fallback si SECRET_KEY est absent. Genere une seule fois au load
#: du module (process-scoped) — un restart serveur invalide TOUS les
#: liens en cours, ce qui est documente comme « degradation gracieuse »
#: si l'admin oublie de configurer SECRET_KEY.
_EPHEMERAL_SECRET = secrets.token_bytes(32)


def _secret() -> bytes:
    raw = os.environ.get("SECRET_KEY") or ""
    if not raw:
        return _EPHEMERAL_SECRET
    # Derive cle distincte du reste des usages crypto pour eviter les
    # collisions inter-fonctionnalites (preview, webhook, wait...).
    return hashlib.sha256(("wait-token:" + raw).encode("utf-8")).digest()


def issue_token() -> Tuple[str, str]:
    """Genere un nouveau token public + son hash.

    Returns:
        (token_public, token_hash) :
        - ``token_public`` : a inclure dans l'URL du mail
          (``wt1.<uuid>.<hmac>``)
        - ``token_hash`` : a stocker dans ``F_WAIT_TOKEN.token_hash``
          (SHA-256 hex de l'UUID brut, 64 chars)

    Le token public n'est plus accessible apres cet appel (le caller
    doit l'envoyer au destinataire immediatement, on ne peut PAS le
    re-deriver depuis le hash).
    """
    raw_uuid = uuid.uuid4().hex  # 32 chars hex, 122 bits d'entropie
    sig = hmac.new(_secret(), raw_uuid.encode("ascii"), hashlib.sha256).hexdigest()
    truncated_sig = sig[:_HMAC_HEX_LEN]
    token_public = f"{_TOKEN_VERSION}.{raw_uuid}.{truncated_sig}"
    token_hash = hashlib.sha256(raw_uuid.encode("ascii")).hexdigest()
    return token_public, token_hash


def parse_and_verify(token_public: str) -> Optional[str]:
    """Parse un token recu de l'URL et retourne son ``token_hash`` si valide.

    Returns:
        ``token_hash`` (64 chars hex) pour lookup BDD si le token
        est syntactiquement valide ET que le HMAC matche. ``None`` sinon
        (signature invalide, format casse, version inconnue).

    Ne fait PAS de lookup BDD ni de check d'expiration — c'est au
    handler appelant de faire ces verifications via la row ``WaitToken``
    correspondante. Cette fonction se limite a la verification
    cryptographique (defense en profondeur : un attaquant qui n'a pas
    capture le token brut ne peut pas en forger un valide meme s'il
    connait des UUIDs).
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
    # UUID = 32 chars hex strict. Refuser tout ce qui n'est pas conforme
    # avant d'invoquer hashlib (anti-DoS au cas ou un attaquant envoie
    # 100M de requetes avec des chars exotiques).
    if len(raw_uuid) != 32 or not all(c in "0123456789abcdef" for c in raw_uuid):
        return None
    if len(sig_recv) != _HMAC_HEX_LEN:
        return None
    expected = hmac.new(_secret(), raw_uuid.encode("ascii"), hashlib.sha256).hexdigest()
    expected_truncated = expected[:_HMAC_HEX_LEN]
    if not hmac.compare_digest(expected_truncated, sig_recv):
        return None
    return hashlib.sha256(raw_uuid.encode("ascii")).hexdigest()
