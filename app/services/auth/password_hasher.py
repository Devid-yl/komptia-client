"""
Hachage et vérification des mots de passe avec bcrypt

Utilise bcrypt pour le hachage sécurisé avec salt automatique.
"""

import bcrypt
from typing import Optional

from app.utils.logger import get_logger
from app.core.exceptions import AuthenticationError

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

    def hash_password(self, password: str) -> str:
        """
        Hache un mot de passe avec bcrypt

        Args:
            password: Mot de passe en clair

        Returns:
            Hash bcrypt (str)

        Raises:
            AuthenticationError: Si le hachage échoue
        """
        if not password:
            raise AuthenticationError("Le mot de passe ne peut pas être vide")

        try:
            # Convertir en bytes
            password_bytes = password.encode("utf-8")

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
            password_bytes = (password or "").encode("utf-8")
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
