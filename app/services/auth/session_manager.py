"""Gestionnaire de sessions utilisateur.

Crée, vérifie et détruit les sessions, avec intégration à la base de données.

Doctrine senior
---------------
1. **Source unique pour la durée de session** — le default ``session_lifetime_hours``
   est toujours lu depuis :class:`SecurityConfig`. Aucune valeur magique
   "24" / "8" en double dans le code (cf. anciennement :
   ``SessionManager(session_lifetime_hours=24)`` divergeait de
   ``config.security.session_timeout_hours=8``).
2. **Pas de PII utilisateur en log clair** — on logue ``user_id`` uniquement.
   Le ``username`` reste côté BDD (corrélation possible via id) mais ne
   pollue pas les logs structurés (RGPD + cohérence avec
   :mod:`app.handlers.auth`).
3. **Pas de morceau de secret en log** — on logue un *fingerprint*
   (HMAC-SHA-256 tronqué de 16 hex chars) du token de session, jamais
   un préfixe brut. Un préfixe expose 32 bits du secret ; un fingerprint
   ne permet pas de reconstruire le token.
4. **Comparaisons SQLAlchemy en ``.is_(True/False)``** — pas de ``== True``
   noqa. Style cohérent avec le reste du code.
5. **Pas de ``refresh()`` après commit quand on a déjà l'objet en main** —
   l'``id`` est fixé manuellement (= token), ``created_at`` est généré
   côté Python : la SELECT supplémentaire est inutile.

Conventions
-----------
* ``from __future__ import annotations``.
* Type hints modernes (``X | None`` plutôt que ``Optional[X]``).
* Aucun message d'erreur métier hardcoded — les messages utilisateur
  vivent dans :mod:`app.handlers.auth._Messages` (centralisation).
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import timedelta
from typing import Final, Iterable

from sqlalchemy import delete as sa_delete, select, update as sa_update
from sqlalchemy.exc import SQLAlchemyError

from app.config import config
from app.core import clock
from app.core.database import get_session
from app.core.exceptions import AuthenticationError
from app.models.session import Session as SessionModel
from app.models.user import User
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ── Constantes du module ─────────────────────────────────────────────────

#: Longueur en hex du fingerprint loggé pour identifier une session sans
#: exposer le secret. 16 hex = 64 bits — assez pour distinguer plusieurs
#: millions de sessions sans collision pratique, sans rendre le token
#: bruteforceable depuis le log.
_TOKEN_FINGERPRINT_LEN: Final[int] = 16

#: Durée après laquelle une session inactive est purgée définitivement
#: (au lieu de juste désactivée). 7 jours = trade-off audit ↔ poids BDD.
_PURGE_AFTER_DAYS: Final[int] = 7

#: Bytes d'aléa pour ``generate_token`` (32 bytes → 64 hex chars).
_TOKEN_BYTES: Final[int] = 32


def _fingerprint_token(token: str) -> str:
    """Empreinte non-réversible d'un token pour les logs.

    On utilise HMAC-SHA-256 avec une clé DÉRIVÉE de ``config.security.secret_key`` :
    cette clé est stable entre redémarrages (forensique possible), tout en
    restant distincte du secret_key (un attaquant qui lit les logs ne
    récupère pas directement la clé de session). C'est la solution
    proposée par ADV-M1 — avant : la clé était regénérée chaque process,
    interdisant toute corrélation "ce cookie a-t-il déjà été vu ?" entre
    deux runs (utile en investigation post-incident).
    """
    if not token:
        return "<empty>"
    digest = hmac.new(_FINGERPRINT_KEY, token.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:_TOKEN_FINGERPRINT_LEN]


#: Clé HMAC pour les fingerprints de logs. Dérivée du SECRET_KEY pour
#: rester stable entre redémarrages (cf. ADV-M1). On utilise un préfixe
#: "session-fp" pour ne PAS dériver la même valeur que d'autres usages
#: éventuels du SECRET_KEY (ex : signing JWT).
_FINGERPRINT_KEY: bytes = hashlib.sha256(
    ("session-fp" + config.security.secret_key).encode("utf-8")
).digest()


class SessionManager:
    """Gestionnaire de sessions utilisateur.

    Toutes les méthodes async sont *fail-safe* : une erreur BDD
    (:class:`SQLAlchemyError`) est loggée et retombe sur ``None`` /
    ``False`` / liste vide selon la sémantique de l'opération.

    Args:
        session_lifetime_hours: Durée de vie d'une session en heures. Si
            ``None`` (défaut), lit ``config.security.session_timeout_hours``
            au moment de l'instanciation. **Source unique** : pas de
            magic number qui divergerait silencieusement.
    """

    def __init__(self, session_lifetime_hours: int | None = None) -> None:
        if session_lifetime_hours is None:
            session_lifetime_hours = config.security.session_timeout_hours
        if session_lifetime_hours <= 0:
            raise ValueError(
                f"session_lifetime_hours doit être > 0 (reçu : {session_lifetime_hours})"
            )
        self.session_lifetime: timedelta = timedelta(hours=session_lifetime_hours)

    # ── Génération de token ──────────────────────────────────────────────

    def generate_token(self) -> str:
        """Génère un token de session sécurisé (64 hex chars = 32 bytes).

        Délègue à :func:`app.models.session.generate_session_id` — source
        unique d'aléa pour les tokens de session. Avant LOGIN-E2, deux
        fonctions identiques cohabitaient (drift garanti à la moindre
        évolution de l'entropie cible).
        """
        from app.models.session import generate_session_id

        return generate_session_id()

    # ── Création ─────────────────────────────────────────────────────────

    async def create_session(
        self,
        user_id: int,
        ip_address: str | None = None,
        user_agent: str | None = None,
        *,
        remember_me: bool = False,
    ) -> SessionModel:
        """Crée une nouvelle session pour un utilisateur.

        Vérifie que ``user_id`` désigne un compte actif (defense en
        profondeur même si le caller a déjà vérifié — coût négligeable,
        protège d'un appel d'API mal écrit).

        ``remember_me`` (kwarg-only) : si True, la session est créée avec
        ``expires_at = now + session_remember_timeout_hours`` (168h / 7j par
        défaut) au lieu de ``session_timeout_hours`` (8h). La colonne
        ``Session.remember_me`` est aussi persistée pour que les futurs
        ``refresh()`` (sliding window) utilisent la bonne durée. Sans cette
        propagation, le glissement écrasait l'extended timeout à la première
        activité de l'utilisateur (bug 2026-05-26).
        """
        try:
            async with get_session() as db:
                result = await db.execute(select(User).where(User.id == user_id))
                user = result.scalar_one_or_none()

                if user is None:
                    raise AuthenticationError("Utilisateur introuvable")
                if not user.is_active:
                    raise AuthenticationError("Compte utilisateur désactivé")

                token = self.generate_token()
                # Choisit la durée selon remember_me. On lit ``config``
                # dynamiquement (pas ``self.session_lifetime``) parce que :
                # 1. La config remember_me n'est pas dans ``__init__``.
                # 2. Le SessionManager est un singleton, instancié au boot ;
                #    relire la config permet à un admin qui modifie
                #    session_remember_timeout_hours à chaud de voir l'effet.
                if remember_me:
                    lifetime = timedelta(hours=config.security.session_remember_timeout_hours)
                else:
                    lifetime = self.session_lifetime
                expires_at = clock.now() + lifetime

                session = SessionModel(
                    id=token,  # ID = token (clé primaire)
                    user_id=user_id,
                    expires_at=expires_at,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    remember_me=remember_me,
                )

                db.add(session)
                await db.commit()
                # Pas de ``db.refresh(session)`` : l'id est fixé manuellement
                # (= token), ``created_at`` / ``last_activity`` sont générés
                # côté Python. Une SELECT supplémentaire serait pure perte.

                logger.info(
                    "Session créée",
                    extra={
                        "user_id": user_id,
                        "session_fp": _fingerprint_token(session.id),
                        "expires_at": expires_at.isoformat(),
                    },
                )
                return session
        except AuthenticationError:
            raise
        except SQLAlchemyError as exc:
            logger.error("Erreur création session", exc_info=exc)
            raise AuthenticationError("Impossible de créer la session") from exc

    # ── Lecture ──────────────────────────────────────────────────────────

    async def get_session(self, token: str | None) -> SessionModel | None:
        """Récupère une session active depuis son token. ``None`` sinon.

        ADV-S5 : si la session est expirée, on désactive en INLINE dans la
        même transaction (UPDATE direct) au lieu d'ouvrir une 2e session
        DB via ``destroy_session()``. Avant : race ms possible (deux workers
        SELECT la même expirée + UPDATE+log dupliqué). Si l'UPDATE inline
        échoue, on ne crash pas — le cleanup périodique fera le ménage.
        """
        if not token:
            return None

        try:
            async with get_session() as db:
                result = await db.execute(
                    select(SessionModel)
                    .where(SessionModel.id == token)
                    .where(SessionModel.is_active.is_(True))
                )
                session = result.scalar_one_or_none()

                if session is not None and session.is_expired:
                    # Désactivation INLINE (même transaction) — pas de 2e
                    # ouverture de session DB pour éviter la race.
                    try:
                        await db.execute(
                            sa_update(SessionModel)
                            .where(SessionModel.id == session.id)
                            .where(SessionModel.is_active.is_(True))
                            .values(is_active=False)
                        )
                        await db.commit()
                        logger.info(
                            "Session expirée désactivée inline",
                            extra={
                                "session_fp": _fingerprint_token(session.id),
                                "user_id": session.user_id,
                            },
                        )
                    except SQLAlchemyError:
                        # Best-effort : si l'UPDATE échoue, le cleanup
                        # périodique nettoiera. Pas grave pour l'user
                        # (qui voit None = anonyme = redirect login).
                        logger.warning(
                            "Échec désactivation inline session expirée",
                            exc_info=True,
                        )
                    return None
                return session
        except SQLAlchemyError as exc:
            logger.error("Erreur récupération session", exc_info=exc)
            return None

    async def get_user_from_token(self, token: str | None) -> User | None:
        """Charge l'utilisateur lié au token. ``None`` si invalide / inactif."""
        session = await self.get_session(token)
        if session is None:
            return None

        try:
            async with get_session() as db:
                result = await db.execute(select(User).where(User.id == session.user_id))
                user = result.scalar_one_or_none()

                if user is not None and not user.is_active:
                    # Désactivation pendant la session : on la révoque tout
                    # de suite (cohérent avec auth.py — un compte désactivé
                    # = comme s'il n'existait pas).
                    await self.destroy_session(token)
                    return None
                return user
        except SQLAlchemyError as exc:
            logger.error("Erreur récupération utilisateur", exc_info=exc)
            return None

    # ── Destruction ──────────────────────────────────────────────────────

    async def destroy_session(self, token: str | None) -> bool:
        """Soft-delete d'une session (logout). Idempotent."""
        if not token:
            return False

        try:
            async with get_session() as db:
                result = await db.execute(select(SessionModel).where(SessionModel.id == token))
                session = result.scalar_one_or_none()
                if session is None:
                    return False
                if not session.is_active:
                    return False  # déjà détruite (idempotence)

                session.is_active = False
                await db.commit()

                logger.info(
                    "Session détruite",
                    extra={
                        "session_fp": _fingerprint_token(session.id),
                        "user_id": session.user_id,
                    },
                )
                return True
        except SQLAlchemyError as exc:
            logger.error("Erreur destruction session", exc_info=exc)
            return False

    async def destroy_sessions_except(self, user_id: int, keep_token: str | None = None) -> int:
        """Révoque toutes les sessions actives d'un utilisateur sauf
        ``keep_token``. Defense-in-depth : ``keep_token`` est vérifié comme
        appartenant bien à ``user_id``. Sinon fail-closed (rien révoqué)."""
        try:
            async with get_session() as db:
                verified_keep: str | None = None
                if keep_token:
                    probe = await db.execute(
                        select(SessionModel)
                        .where(SessionModel.id == keep_token)
                        .where(SessionModel.user_id == user_id)
                        .where(SessionModel.is_active.is_(True))
                    )
                    if probe.scalar_one_or_none() is not None:
                        verified_keep = keep_token

                if keep_token and verified_keep is None:
                    logger.warning(
                        "destroy_sessions_except : keep_token invalide, fail-closed",
                        extra={"user_id": user_id},
                    )
                    return 0

                stmt = (
                    sa_update(SessionModel)
                    .where(SessionModel.user_id == user_id)
                    .where(SessionModel.is_active.is_(True))
                    .values(is_active=False)
                )
                if verified_keep:
                    stmt = stmt.where(SessionModel.id != verified_keep)

                result = await db.execute(stmt)
                revoked = result.rowcount or 0
                await db.commit()

                if revoked > 0:
                    logger.info(
                        "Sessions révoquées (sauf courante)",
                        extra={"user_id": user_id, "revoked": revoked},
                    )
                return revoked
        except SQLAlchemyError as exc:
            logger.error("Erreur révocation sessions", exc_info=exc)
            return 0

    # ── Maintenance périodique ───────────────────────────────────────────

    async def cleanup_expired_sessions(self) -> int:
        """Nettoie les sessions expirées (appelé périodiquement par main).

        Étape 1 — désactive en bulk les sessions expirées encore actives.
        Étape 2 — supprime définitivement celles inactives depuis plus de
        ``_PURGE_AFTER_DAYS`` jours (sinon la table croît indéfiniment).
        """
        try:
            async with get_session() as db:
                now = clock.now()

                deactivate_result = await db.execute(
                    sa_update(SessionModel)
                    .where(SessionModel.is_active.is_(True))
                    .where(SessionModel.expires_at < now)
                    .values(is_active=False)
                )
                deactivated = deactivate_result.rowcount or 0

                purge_cutoff = now - timedelta(days=_PURGE_AFTER_DAYS)
                purge_result = await db.execute(
                    sa_delete(SessionModel)
                    .where(SessionModel.is_active.is_(False))
                    .where(SessionModel.expires_at < purge_cutoff)
                )
                purged = purge_result.rowcount or 0

                await db.commit()

                total = deactivated + purged
                if total > 0:
                    logger.info(
                        "Sessions nettoyées : %d désactivées, %d purgées",
                        deactivated,
                        purged,
                    )
                return total
        except SQLAlchemyError as exc:
            logger.error("Erreur nettoyage sessions", exc_info=exc)
            return 0

    async def get_user_sessions(self, user_id: int) -> list[SessionModel]:
        """Retourne toutes les sessions actives d'un utilisateur (audit UI)."""
        try:
            async with get_session() as db:
                result = await db.execute(
                    select(SessionModel)
                    .where(SessionModel.user_id == user_id)
                    .where(SessionModel.is_active.is_(True))
                    .order_by(SessionModel.created_at.desc())
                )
                rows: Iterable[SessionModel] = result.scalars().all()
                return list(rows)
        except SQLAlchemyError as exc:
            logger.error("Erreur récupération sessions utilisateur", exc_info=exc)
            return []


# ── Singleton ─────────────────────────────────────────────────────────────

_session_manager: SessionManager | None = None


def get_session_manager() -> SessionManager:
    """Retourne l'instance singleton (lazy init lue depuis la config)."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()  # ← lit config par défaut
    return _session_manager


def reset_session_manager() -> None:
    """Force la recréation du singleton (utilisé en tests pour appliquer
    un monkeypatch sur ``config.security.session_timeout_hours``)."""
    global _session_manager
    _session_manager = None
