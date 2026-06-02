"""Rate limiter dédié à l'authentification, persisté en base.

Contrairement à :class:`app.utils.rate_limiter.RateLimiter` (mémoire), ce
service interroge la table ``login_attempts`` : une attaque par bruteforce
ne peut pas être réinitialisée par un redémarrage du serveur.

Conformément à OWASP ASVS 4.0 V2.2.1 et à l'Authentication Cheat Sheet, on
applique **simultanément** deux compteurs :

* **par IP** — bloque un bot qui testerait des comptes différents depuis la
  même source.
* **par username** — bloque une attaque distribuée sur un seul compte (un
  seul compte qui voit 100 tentatives en 15 min est également anormal).

La fenêtre et le seuil viennent de ``SecurityConfig``. Zéro magic number ici.

IPv6 est normalisé vers son /64 (prefix opérateur) : un attaquant qui
pivoterait entre 10 000 adresses de son allocation /64 se verrait quand
même regroupé derrière un seul compteur (cf. OneUptime, IETF RFC 6177 et
"How to Handle IPv6 in Rate Limiting Middleware", mars 2026).

Note déploiement (ADV-M5) — derrière proxy/load-balancer
--------------------------------------------------------
``request.remote_ip`` côté Tornado retourne par défaut l'IP de la
connexion TCP directe (le proxy). Pour que ce rate limiter voie l'IP
réelle du client, l'``Application`` Tornado DOIT être instanciée avec
``xheaders=True`` (Tornado lit alors ``X-Forwarded-For`` / ``X-Real-IP``
posés par le proxy de confiance). Si vous déployez Komptia derrière
nginx/HAProxy/Cloudflare et que ``xheaders`` n'est pas activé,
**tous les utilisateurs partageront un seul bucket** (l'IP du proxy)
— c'est-à-dire que le compteur saute à 5 sur la 5e tentative globale,
peu importe la légitimité. Vérifier ce paramètre au déploiement.

Toutes les opérations ont pour unité de recouvrement un ``SQLAlchemyError``
(le service logge et retombe sur ``fail-closed`` : en cas d'erreur BDD, on
bloque plutôt que d'autoriser un bruteforce silencieux).
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Final, Optional

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.config import config
from app.core import clock
from app.core.constants_auth import casefold_email
from app.core.database import get_session
from app.models.login_attempt import LoginAttempt
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Longueur max indexée dans ``login_attempts.ip_address`` (VARCHAR(45) =
# un IPv6 complet + zone). On l'utilise comme borne défensive pour éviter
# qu'un header X-Forwarded-For trafiqué n'insère un blob géant.
_IP_ADDRESS_MAX_LENGTH: Final[int] = 45

# Préfixe /64 pour IPv6 : agrégation par allocation client (voir docstring).
_IPV6_CLIENT_PREFIX: Final[int] = 64

# Valeur de fallback si la normalisation d'une IP échoue — on préserve
# une chaîne lisible pour les logs tout en restant hashable et bornée.
_IP_UNKNOWN: Final[str] = "unknown"

# Limite défensive sur username pour le compteur. La table autorise
# jusqu'à 255 chars via ``String(255)``.
_USERNAME_COUNTER_MAX_LENGTH: Final[int] = 255


class LoginRateLimiter:
    """Rate limiter persistant pour l'authentification.

    Ne stocke rien en mémoire — toutes les décisions passent par la table
    ``login_attempts``. Le coût est une requête ``SELECT COUNT(*)`` par
    tentative, négligeable sur SQLite avec l'index composite
    ``(ip_address, attempted_at)`` déjà défini sur le modèle.

    Note sur le paramètre ``username`` (depuis 2026-05-11)
    -------------------------------------------------------
    Depuis la bascule du login vers l'email comme identifiant
    (cf. ``app/handlers/auth.py``), le paramètre ``username`` des méthodes
    publiques reçoit l'EMAIL normalisé (déjà ``strip().lower()``) du caller.
    La colonne BDD ``LoginAttempt.username VARCHAR(255)`` accueille cet
    email tel quel — pas renommée pour éviter une migration destructive
    sur SQLite (impact sur l'index composite et les tests existants).

    Sémantiquement c'est un "identifier de tentative". La normalisation
    ``_sanitize_username`` (strip + lower 255) reste correcte pour un email.
    """

    def __init__(
        self,
        *,
        max_attempts: int,
        window_seconds: int,
    ) -> None:
        self._max_attempts = max_attempts
        self._window = timedelta(seconds=window_seconds)

    @property
    def max_attempts(self) -> int:
        return self._max_attempts

    @property
    def window_seconds(self) -> int:
        return int(self._window.total_seconds())

    @staticmethod
    def normalize_ip(raw: Optional[str]) -> str:
        """Normalise une IP pour servir de clé de rate limit.

        * IPv4 reste inchangé ("192.0.2.1").
        * IPv4-mapped-IPv6 ("::ffff:192.0.2.1") retombe sur l'IPv4 réelle.
        * IPv6 est ramené à son /64 ("2001:db8::...") → "2001:db8::/64".
        * None, chaîne vide, valeur illisible → ``"unknown"`` (une seule
          bucket, pas des milliers de valeurs parasites).

        La valeur retournée reste bornée à 45 caractères (colonne BDD).
        """
        if not raw:
            return _IP_UNKNOWN

        # Tornado peut passer une IPv6 avec identifiant de zone ("fe80::1%eth0")
        # que ``ipaddress.ip_address`` refuse. On coupe proprement.
        candidate = raw.split("%", 1)[0].strip()
        if not candidate:
            return _IP_UNKNOWN

        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return _IP_UNKNOWN

        if isinstance(address, ipaddress.IPv6Address):
            # Un IPv4-mapped ("::ffff:a.b.c.d") doit être rangé avec son IPv4
            # — sinon un client dual-stack compterait dans deux buckets.
            if address.ipv4_mapped is not None:
                return str(address.ipv4_mapped)
            network = ipaddress.ip_network(f"{address}/{_IPV6_CLIENT_PREFIX}", strict=False)
            key = str(network)
        else:
            key = str(address)

        return key[:_IP_ADDRESS_MAX_LENGTH]

    @staticmethod
    def _sanitize_username(username: Optional[str]) -> Optional[str]:
        if not username:
            return None
        # Depuis 2026-05-11, ``username`` reçoit un email casefolded par le
        # handler. On re-casefold ici en defense-in-depth (caller potentiellement
        # un autre service futur qui oublierait la normalisation).
        # ``casefold_email`` gère Unicode correctement (ß, İ, …) — empêche un
        # attaquant de contourner le compteur en alternant casse Unicode.
        normalized = casefold_email(username)
        if not normalized:
            return None
        # Cap par bytes utf-8 (pas chars) pour respecter la colonne BDD
        # ``LoginAttempt.username VARCHAR(255)`` même sur backends stricts
        # (Postgres count en bytes). On retombe sur un decode lossless.
        encoded = normalized.encode("utf-8")
        if len(encoded) > _USERNAME_COUNTER_MAX_LENGTH:
            encoded = encoded[:_USERNAME_COUNTER_MAX_LENGTH]
            normalized = encoded.decode("utf-8", errors="ignore")
        return normalized

    async def check_block_with_deadline(
        self,
        *,
        ip: Optional[str],
        username: Optional[str],
    ) -> tuple[bool, Optional[int]]:
        """Vérifie le blocage ET calcule la deadline en UN SEUL aller-retour BDD.

        Avant ADV-S2, ``is_blocked`` puis ``seconds_until_unblocked``
        faisaient 4 SELECT non-atomiques → race possible entre les deux
        appels (un attempt insère/sort de la fenêtre entre temps).
        Cette méthode atomise : on lit jusqu'à ``max_attempts`` timestamps
        par compteur ASC, on déduit ``blocked`` (compteur >= max) ET la
        deadline de débloquage en une seule transaction.

        Retourne ``(blocked, seconds_until_unblocked_or_None)``.

        Sémantique du déblocage (ADV-S2/S3) :
        ``is_blocked`` est OR (IP_count >= max OU user_count >= max).
        Pour être DÉBLOQUÉ il faut que les DEUX retombent < max →
        deadline = ``max(deadline_ip, deadline_user)`` (le plus tard
        qui passe en dessous).

        ADV-S3 : pour gérer correctement N > max_attempts (cas où
        ``record_attempt`` continue d'enregistrer après blocage), on
        sélectionne ``LIMIT N + 1`` puis on raisonne sur la
        ``(len(rows) - max_attempts + 1)``ème la plus ancienne — c'est
        celle dont la sortie permettra de passer SOUS max_attempts. Avec
        un cap raisonnable (LIMIT max_attempts × 4) pour éviter de
        scanner la table entière sous attaque massive.
        """
        window_start = clock.now() - self._window
        normalized_ip = self.normalize_ip(ip)
        lowered_username = self._sanitize_username(username)

        # Cap défensif : on lit jusqu'à 4 × max_attempts pour avoir une
        # estimation raisonnable de la deadline même sous attaque
        # (~20 lignes max au SELECT — négligeable).
        scan_limit = self._max_attempts * 4

        try:
            async with get_session() as db:
                stmt_ip = (
                    select(LoginAttempt.attempted_at)
                    .where(LoginAttempt.ip_address == normalized_ip)
                    .where(LoginAttempt.success.is_(False))
                    .where(LoginAttempt.attempted_at >= window_start)
                    .order_by(LoginAttempt.attempted_at.asc())
                    .limit(scan_limit)
                )
                ip_rows = list((await db.execute(stmt_ip)).scalars().all())

                user_rows: list[datetime] = []
                if lowered_username is not None:
                    # ADV-C7 : on stocke username déjà en lowercase Python
                    # (cf. ``record_attempt``), donc égalité directe — plus
                    # de ``func.lower()`` SQLite qui ne marche que pour
                    # ASCII et permettait un bypass via casse Unicode.
                    stmt_user = (
                        select(LoginAttempt.attempted_at)
                        .where(LoginAttempt.username == lowered_username)
                        .where(LoginAttempt.success.is_(False))
                        .where(LoginAttempt.attempted_at >= window_start)
                        .order_by(LoginAttempt.attempted_at.asc())
                        .limit(scan_limit)
                    )
                    user_rows = list((await db.execute(stmt_user)).scalars().all())
        except SQLAlchemyError:
            logger.error(
                "LoginRateLimiter: échec SELECT, fail-closed (blocage sans countdown)",
                exc_info=True,
            )
            return (True, None)

        ip_count = len(ip_rows)
        user_count = len(user_rows)
        ip_blocked = ip_count >= self._max_attempts
        user_blocked = user_count >= self._max_attempts
        blocked = ip_blocked or user_blocked

        if not blocked:
            return (False, None)

        deadline_candidates: list[datetime] = []
        # Pour chaque compteur bloqué, on prend l'attempt à l'index
        # ``count - max_attempts`` (0-indexé = la (count - max + 1)ème
        # la plus ancienne) dont la sortie de fenêtre fera passer le
        # compteur SOUS max_attempts.
        if ip_blocked:
            idx = ip_count - self._max_attempts
            deadline_candidates.append(ip_rows[idx])
        if user_blocked:
            idx = user_count - self._max_attempts
            deadline_candidates.append(user_rows[idx])

        # max() = le plus tard à débloquer (sémantique OR de blocked).
        oldest_blocking = max(deadline_candidates)
        if oldest_blocking.tzinfo is None:
            oldest_blocking = oldest_blocking.replace(tzinfo=timezone.utc)
        unblock_at = oldest_blocking + self._window
        remaining = (unblock_at - clock.now()).total_seconds()
        if remaining <= 0:
            return (True, None)
        return (True, int(remaining) + 1)

    async def seconds_until_unblocked(
        self,
        *,
        ip: Optional[str],
        username: Optional[str],
    ) -> Optional[int]:
        """Compat : retourne juste le countdown. Préférer
        :meth:`check_block_with_deadline` qui combine blocked + deadline."""
        _, seconds = await self.check_block_with_deadline(ip=ip, username=username)
        return seconds

    async def is_blocked(
        self,
        *,
        ip: Optional[str],
        username: Optional[str],
    ) -> bool:
        """Compat : retourne juste blocked. Préférer
        :meth:`check_block_with_deadline` (1 SELECT au lieu de 2)."""
        blocked, _ = await self.check_block_with_deadline(ip=ip, username=username)
        return blocked

    async def record_attempt(
        self,
        *,
        ip: Optional[str],
        username: Optional[str],
        success: bool,
    ) -> None:
        """Enregistre une tentative — silencieux en cas d'erreur BDD.

        ADV-C7/M9 : le ``username`` est stocké LOWERCASE (Python str.lower()
        Unicode-aware) pour permettre l'égalité directe au lookup.
        """
        normalized_ip = self.normalize_ip(ip)
        trimmed_username = self._sanitize_username(username)

        try:
            async with get_session() as db:
                db.add(
                    LoginAttempt(
                        ip_address=normalized_ip,
                        username=trimmed_username,
                        success=success,
                        attempted_at=clock.now(),
                    )
                )
        except SQLAlchemyError:
            logger.error(
                "LoginRateLimiter: échec INSERT login_attempts (audit perdu)",
                exc_info=True,
            )

    async def reset_failures_after_success(
        self,
        *,
        ip: Optional[str],
        username: Optional[str],
    ) -> None:
        """ADV-S4 : après une authentification réussie, on purge les
        tentatives ratées récentes pour cette IP **et** ce username.

        Justification : un user qui tape 4 fois faux puis bon ne doit pas
        rester pénalisé. Sans purge, il restait à 4 attempts dans la
        fenêtre — sa prochaine erreur de frappe le ferait re-bloquer
        immédiatement (alors qu'on sait qu'il connaît son mdp).

        Méthode : DELETE des attempts ``success=False`` pour cette IP
        ET pour ce username dans la fenêtre courante. Best-effort —
        si la BDD est HS, on log et on continue (le user vient de se
        connecter, on ne va pas le bloquer en lui disant "désolé").
        """
        from sqlalchemy import delete as sa_delete

        window_start = clock.now() - self._window
        normalized_ip = self.normalize_ip(ip)
        trimmed_username = self._sanitize_username(username)

        try:
            async with get_session() as db:
                stmt = sa_delete(LoginAttempt).where(
                    LoginAttempt.success.is_(False),
                    LoginAttempt.attempted_at >= window_start,
                )
                # On supprime si IP match OU username match (pour purger
                # les deux compteurs qui auraient pu être fillés).
                from sqlalchemy import or_

                or_clauses = [LoginAttempt.ip_address == normalized_ip]
                if trimmed_username is not None:
                    or_clauses.append(LoginAttempt.username == trimmed_username)
                stmt = stmt.where(or_(*or_clauses))
                await db.execute(stmt)
                await db.commit()
        except SQLAlchemyError:
            logger.warning(
                "LoginRateLimiter: échec reset failures post-success (best-effort)",
                exc_info=True,
            )


_rate_limiter: Optional[LoginRateLimiter] = None


def get_login_rate_limiter() -> LoginRateLimiter:
    """Singleton paresseux, lu depuis la config courante au 1er appel.

    Les tests qui mutent ``config.security.rate_limit_login`` peuvent
    appeler :func:`reset_login_rate_limiter` entre chaque cas pour forcer
    la relecture.
    """
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = LoginRateLimiter(
            max_attempts=config.security.rate_limit_login,
            window_seconds=config.security.rate_limit_login_window_seconds,
        )
    return _rate_limiter


def reset_login_rate_limiter() -> None:
    """Force la recréation du singleton (utilisé dans les tests)."""
    global _rate_limiter
    _rate_limiter = None
