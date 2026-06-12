"""
Hachage et vérification des mots de passe avec bcrypt

Utilise bcrypt pour le hachage sécurisé avec salt automatique.
"""

import bcrypt
from typing import Optional

from app.utils.logger import get_logger
from app.core.exceptions import AuthenticationError, PasswordTooLongError
from app.core.constants_auth import (
    PASSWORD_MAX_BYTES,
    encode_password_for_bcrypt,
    password_exceeds_bcrypt_limit,
)

logger = get_logger(__name__)


class PasswordHasher:
    """
    Gestionnaire de hachage des mots de passe avec bcrypt

    Features:
    - Salt automatique
    - Coût adaptatif (work factor)
    - Hachage sécurisé avec bcrypt
    """

    def __init__(self, rounds: int = 12):
        """
        Initialise le hasher

        Args:
            rounds: Nombre de rounds bcrypt (2^rounds iterations)
                   Défaut: 12 (4096 iterations)
                   Recommandé: 10-14
        """
        self.rounds = rounds

    def hash_password(self, password: str, *, allow_truncate: bool = False) -> str:
        """
        Hache un mot de passe avec bcrypt.

        bcrypt ignore les octets au-delà du 72e (cf.
        :data:`~app.core.constants_auth.PASSWORD_MAX_BYTES`). Cette méthode
        **refuse** par défaut un mot de passe trop long (garde-fou : tout chemin
        « set » doit déjà avoir validé en amont via
        :func:`~app.core.constants_auth.password_exceeds_bcrypt_limit` et renvoyé
        une 400). Un refus loud > une troncature silencieuse qui ferait croire à
        l'utilisateur que ses octets 73+ comptent.

        Args:
            password: Mot de passe en clair.
            allow_truncate: si ``True``, tronque à 72 octets au lieu de lever.
                **À n'utiliser que pour le re-hachage d'un mot de passe DÉJÀ
                accepté** (``_maybe_rehash`` après un login réussi sur un hash
                legacy créé sous bcrypt 4.x, qui tronquait). Pour un nouveau mot
                de passe, laisser ``False`` afin de rejeter explicitement.

        Returns:
            Hash bcrypt (str).

        Raises:
            PasswordTooLongError: mot de passe > 72 octets et ``allow_truncate``
                est ``False``.
            AuthenticationError: mot de passe vide, ou échec bcrypt inattendu.
        """
        if not password:
            raise AuthenticationError("Le mot de passe ne peut pas être vide")

        if password_exceeds_bcrypt_limit(password):
            if not allow_truncate:
                raise PasswordTooLongError(
                    "Le mot de passe ne peut pas dépasser "
                    f"{PASSWORD_MAX_BYTES} octets (limite de l'algorithme bcrypt)."
                )
            # Re-hachage d'un secret déjà accepté : on reproduit la troncature
            # historique de bcrypt 4.x pour rester cohérent avec le chemin verify.
            password_bytes = encode_password_for_bcrypt(password)
        else:
            password_bytes = password.encode("utf-8")

        try:
            # Générer le salt et hacher
            salt = bcrypt.gensalt(rounds=self.rounds)
            hashed = bcrypt.hashpw(password_bytes, salt)

            # Retourner en string
            return hashed.decode("utf-8")

        except (UnicodeError, ValueError, OSError) as exc:
            logger.error("Erreur hachage mot de passe", exc_info=True)
            raise AuthenticationError("Erreur lors du hachage du mot de passe") from exc

    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Vérifie un mot de passe contre son hash bcrypt.

        ADV-S6 : on garde le early-return si ``hashed`` est vide/invalide
        (impossible de vérifier sans hash valide), MAIS on ne court-circuite
        PAS sur ``not password`` — sinon timing leak (le caller détecte
        "user existe ?" en mesurant si le bcrypt s'est exécuté). Le caller
        responsable a déjà filtré les passwords vides AVANT (cf.
        :class:`LoginHandler.post` ligne ``MISSING_FIELDS``) ; ici on fait
        confiance et on paie le coût bcrypt même sur password vide.

        Args:
            password: Mot de passe en clair (peut être "" — voir doctrine).
            hashed: Hash bcrypt stocké (peut être "" → False sans coût).

        Returns:
            True si correspond, False sinon.
        """
        if not hashed:
            # Pas de hash = on ne peut pas vérifier ; aucun coût bcrypt
            # disponible sans hash valide en input.
            return False

        try:
            # Troncature à 72 octets AVANT checkpw (cf. PASSWORD_MAX_BYTES) :
            #   * compat avec les hashes legacy créés sous bcrypt 4.x (qui
            #     tronquait silencieusement) — sans ça, un user au mdp >72o créé
            #     avant ce fix serait lockout au login ;
            #   * robustesse cross-version — bcrypt 5.x lève ``ValueError`` sur
            #     un input >72o ; on le tronque nous-mêmes pour ne jamais lever.
            # ``encode_password_for_bcrypt`` gère ``None`` → ``b""`` (le coût
            # bcrypt est quand même payé : doctrine timing-attack préservée).
            password_bytes = encode_password_for_bcrypt(password)
            hashed_bytes = hashed.encode("utf-8")
            return bcrypt.checkpw(password_bytes, hashed_bytes)
        except (UnicodeError, ValueError):
            logger.error("Erreur vérification mot de passe", exc_info=True)
            return False

    def needs_rehash(self, hashed: str) -> bool:
        """
        Vérifie si un hash doit être recalculé (rounds obsolètes)

        Args:
            hashed: Hash bcrypt à vérifier

        Returns:
            True si le hash doit être recalculé
        """
        try:
            # Extraire les rounds du hash
            # Format bcrypt: $2b$rounds$salt+hash
            parts = hashed.split("$")
            if len(parts) >= 3:
                current_rounds = int(parts[2])
                return current_rounds < self.rounds

            return True

        except (IndexError, ValueError):
            return True


# Instance globale
_hasher: Optional[PasswordHasher] = None


def get_password_hasher() -> PasswordHasher:
    """Retourne l'instance globale du hasher (lazy init)"""
    global _hasher
    if _hasher is None:
        from app.config import config

        _hasher = PasswordHasher(rounds=config.security.bcrypt_rounds)
    return _hasher
