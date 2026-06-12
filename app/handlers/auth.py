"""Handlers HTTP de connexion / déconnexion.

Sommaire
--------
* :class:`LoginHandler`   — GET (formulaire) / POST (authentification).
* :class:`LogoutHandler`  — GET et POST (destruction de session + cookie).

Règles de sécurité appliquées (OWASP ASVS 4.0 + Auth Cheat Sheet 2025)
---------------------------------------------------------------------
1. **Erreurs client unifiées** — on ne renvoie jamais ``str(exception)`` à
   l'utilisateur ; un message français générique court-circuite toute fuite
   de traceback, de chemin ou de requête SQL.
2. **Anti-énumération** — même temps de réponse pour un compte inconnu /
   inactif que pour un mauvais mot de passe (``bcrypt.checkpw`` contre un
   hash factice avec les rounds effectifs du projet).
3. **Anti-bruteforce** — :mod:`app.services.auth.login_rate_limiter` bloque
   par IP **et** par username (ASVS V2.2.1).
4. **Anti-fixation** — le cookie de session est (re)posé après authentification
   via ``set_secure_cookie`` ; un cookie pré-auth trafiqué est écrasé.
5. **Anti-open-redirect** — ``is_safe_redirect_url`` refuse les URLs absolues
   et les schémas dangereux (``javascript:``, ``data:``).
6. **PII restreinte en log** — username non loggé en clair, user-agent
   tronqué à ``config.security.user_agent_log_max_length``.
7. **Défense-in-depth sur cookie** — ``httponly`` + ``samesite=Lax`` +
   ``secure`` en production.

Conventions d'écriture
----------------------
* ``from __future__ import annotations`` — cohérence typing avec le reste.
* Free functions interdites : toute la logique transite par :class:`LoginHandler`
  ou un service (``login_rate_limiter``). Les helpers locaux sont préfixés
  ``_`` et ne touchent pas ``self``.
* Aucun magic number ni message hardcodé dans le corps du handler ;
  ``_MESSAGES`` et :class:`SecurityConfig` centralisent.
* Aucun nom d'organisation / client / logiciel métier (règle CLAUDE.md
  *généricité*) — la page de login est rendue avec ``app_name`` lu depuis
  ``config.app_name``.
"""

from __future__ import annotations

import asyncio
import bcrypt as _bcrypt
import threading
from typing import Any, Final, Optional

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError

from app.config import config
from app.core import clock
from app.core.constants_auth import EMAIL_MAX_LENGTH, casefold_email
from app.core.database import get_session
from app.core.exceptions import AuthenticationError
from app.handlers.base import BaseHandler, SESSION_COOKIE_NAME, authenticated
from app.middleware.security import is_safe_redirect_url
from app.models.audit import AuditAction
from app.models.user import User
from app.services.audit import record_audit_best_effort
from app.services.auth.login_rate_limiter import get_login_rate_limiter
from app.services.auth.password_hasher import get_password_hasher
from app.services.auth.session_manager import get_session_manager
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ``SESSION_COOKIE_NAME`` est défini dans ``app.handlers.base`` (source de
# vérité unique). Re-export via l'import ci-dessus pour compatibilité
# ascendante — les tests et modules existants continuent de pouvoir écrire
# ``from app.handlers.auth import SESSION_COOKIE_NAME``.
__all__ = (
    "LoginHandler",
    "LogoutHandler",
    "XsrfTokenAPIHandler",
    "SESSION_COOKIE_NAME",
)

# ── Constantes (Final → mypy bloque toute réassignation) ──────────────────

#: URL par défaut post-login si ``next`` est absent, dangereux, ou pointe
#: sur ``/login`` (boucle qu'on court-circuite).
_DEFAULT_NEXT_URL: Final[str] = "/dashboard"

#: URL post-logout.
_LOGIN_URL: Final[str] = "/login"

#: Template Jinja2 rendu pour la page de login (GET + POST erreurs).
_LOGIN_TEMPLATE: Final[str] = "auth/login.html"

#: Plafond défensif sur la longueur de l'argument ``?next=...`` accepté.
#: Une URL relative légitime tient en quelques dizaines de caractères ; un
#: payload géant (10 ko) signale une tentative de pollution log / DoS — on
#: retombe sur ``_DEFAULT_NEXT_URL`` plutôt que de propager.
_NEXT_URL_MAX_LENGTH: Final[int] = 2048

#: Plafond défensif sur la longueur du password reçu (ADV-S7).
#: bcrypt tronque silencieusement à 72 octets. Au-delà de 1024 caractères,
#: c'est sûrement une tentative DoS bcrypt (allocation mémoire avant le
#: hash) — on rejette comme MISSING_FIELDS générique pour éviter timing leak.
_PASSWORD_MAX_LENGTH: Final[int] = 1024

#: Plafond email — alias local de :data:`app.core.constants_auth.EMAIL_MAX_LENGTH`
#: (RFC 5321 ``Path`` = 254 chars). Source of truth dans le module partagé pour
#: éviter le drift entre ``users.email VARCHAR(254)`` (BDD), le ``maxlength``
#: HTML5 et la normalisation backend.
_EMAIL_MAX_LENGTH: Final[int] = EMAIL_MAX_LENGTH


class _Messages:
    """Messages utilisateur centralisés (français, ton cohérent avec l'UI).

    Aucun message ne référence un rôle, une table SQL, ou une exception
    — expose uniquement ce qui est actionnable pour l'utilisateur.
    """

    INVALID_CREDENTIALS: Final[str] = "Email ou mot de passe incorrect."
    RATE_LIMITED: Final[str] = "Trop de tentatives de connexion. Réessayez dans quelques minutes."
    MISSING_FIELDS: Final[str] = "Veuillez saisir votre email et votre mot de passe."
    GENERIC_ERROR: Final[str] = "Une erreur est survenue. Veuillez réessayer."

    @staticmethod
    def rate_limited_with_countdown(seconds_left: int) -> str:
        """Variante de :attr:`RATE_LIMITED` avec un compte à rebours précis.

        Évite le message vague "Réessayez dans quelques minutes" — l'user
        sait combien de temps attendre. Pas de leak (le compteur est déjà
        déductible côté attaquant en mesurant les réponses HTTP).
        """
        if seconds_left <= 60:
            return (
                "Trop de tentatives de connexion. Réessayez dans "
                f"{max(seconds_left, 1)} seconde(s)."
            )
        minutes = (seconds_left + 59) // 60
        return "Trop de tentatives de connexion. Réessayez dans " f"{minutes} minute(s)."


async def _record_login_audit(
    *,
    user_id: Optional[int],
    action: str,
    entity_id: Optional[int],
    details: dict[str, Any],
    ip_address: str,
    user_agent: str,
) -> None:
    """Trace un événement d'authentification dans ``audit_logs`` (journal légal).

    Best-effort, jamais bloquant pour le login : délègue au helper SSoT
    :func:`record_audit_best_effort` (session dédiée + timeout borné +
    classification des erreurs transitoire/inattendue). ``entity_type`` est
    toujours ``"user"`` pour ces événements d'authentification.
    """
    await record_audit_best_effort(
        user_id=user_id,
        action=action,
        entity_type="user",
        entity_id=entity_id,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
    )


# ── Timing-attack mitigation : dummy hash lazy & aligné sur bcrypt_rounds ──

#: LRU cap pour _dummy_hash_cache (ADV-M6). En pratique on ne change
#: ``bcrypt_rounds`` jamais à runtime, donc 1 entrée suffit ; on tolère
#: 4 pour gérer les tests qui paramétrent rounds. Au-delà, on évince la
#: plus ancienne (insertion-order Python 3.7+).
_DUMMY_HASH_CACHE_MAX: Final[int] = 4

_dummy_hash_cache: dict[int, str] = {}
_dummy_hash_lock: threading.Lock = threading.Lock()


def _compute_dummy_hash_sync(rounds: int) -> str:
    """Calcul bcrypt synchrone (~200 ms à rounds=12). Bloquant ; à
    invoquer via ``asyncio.to_thread`` depuis un contexte async."""
    return _bcrypt.hashpw(b"dummy-password", _bcrypt.gensalt(rounds=rounds)).decode("utf-8")



async def _get_dummy_hash_async() -> str:
    """Retourne le hash factice en async — calcul bcrypt délégué dans un
    thread (asyncio.to_thread) pour ne JAMAIS freezer l'event-loop ~200ms
    au premier appel post-démarrage. Une fois en cache, retour immédiat.

    ADV-M6 : avant, le premier ``_get_dummy_hash`` synchrone bloquait
    l'event-loop sur le hashpw initial, laissant tous les autres handlers
    en attente. Maintenant : retour immédiat si cache hit, sinon délégué
    au thread pool.
    """
    rounds = config.security.bcrypt_rounds
    cached = _dummy_hash_cache.get(rounds)
    if cached is not None:
        return cached
    # Pas en cache : calcul dans un thread pour ne pas freezer event-loop.
    hashed = await asyncio.to_thread(_compute_dummy_hash_sync, rounds)
    with _dummy_hash_lock:
        # LRU cap : si on dépasse, on évince la plus ancienne (insertion-order).
        if rounds not in _dummy_hash_cache and len(_dummy_hash_cache) >= _DUMMY_HASH_CACHE_MAX:
            _dummy_hash_cache.pop(next(iter(_dummy_hash_cache)))
        _dummy_hash_cache.setdefault(rounds, hashed)
        return _dummy_hash_cache[rounds]


def _get_dummy_hash() -> str:
    """Compat : retourne le hash factice synchronously. PRÉFÉRER
    :func:`_get_dummy_hash_async` dans un contexte ``async def`` pour
    ne pas freezer l'event-loop au premier appel.

    Cette version sync existe pour la rétrocompat avec les tests
    qui appellent ``_get_dummy_hash()`` directement.
    """
    rounds = config.security.bcrypt_rounds
    cached = _dummy_hash_cache.get(rounds)
    if cached is not None:
        return cached
    with _dummy_hash_lock:
        cached = _dummy_hash_cache.get(rounds)
        if cached is None:
            cached = _compute_dummy_hash_sync(rounds)
            if len(_dummy_hash_cache) >= _DUMMY_HASH_CACHE_MAX:
                _dummy_hash_cache.pop(next(iter(_dummy_hash_cache)))
            _dummy_hash_cache[rounds] = cached
        return cached


# ── Helpers pure functions (logique testable sans instancier un handler) ──


def _resolve_next_url(raw: Optional[str]) -> str:
    """Retourne une URL de redirection sûre.

    * ``None`` / vide / trop longue / dangereuse / identique au ``/login``
      → fallback.
    * Sinon renvoie l'URL telle quelle (déjà filtrée par ``is_safe_redirect_url``).
    """
    if not raw:
        return _DEFAULT_NEXT_URL
    # Plafond défensif AVANT validation : ``is_safe_redirect_url`` lit la
    # chaîne entière (regex + urlsplit) — un payload de plusieurs MB
    # consommerait CPU+mémoire pour rien. À 2 ko on est très large pour
    # une URL relative légitime, et étroit pour un attaquant.
    if len(raw) > _NEXT_URL_MAX_LENGTH:
        return _DEFAULT_NEXT_URL
    if not is_safe_redirect_url(raw):
        return _DEFAULT_NEXT_URL
    # Boucle pénible si l'UI bookmark ``/login?next=/login``.
    if raw == _LOGIN_URL or raw.startswith(f"{_LOGIN_URL}?"):
        return _DEFAULT_NEXT_URL
    return raw


def _normalize_login_email(raw: Optional[str]) -> str:
    """Normalise un email saisi en login.

    Délègue à :func:`app.core.constants_auth.casefold_email` (single source
    of truth). Pipeline : ``strip()`` → ``casefold()`` Unicode-aware → refus
    si > :data:`EMAIL_MAX_LENGTH` (PAS de truncate silencieux : un email
    surdimensionné est inconnu de la BDD par définition de la colonne, donc
    on retombe sur "no match" déterministe — ferme le canal d'énumération
    par truncate).

    Pourquoi ``casefold()`` et pas ``lower()`` :
    ``"STRAẞE@x.fr".lower()`` retourne ``"straße@x.fr"`` (eszett conservé),
    alors que ``.casefold()`` retourne ``"strasse@x.fr"`` — c'est cette
    deuxième forme qui matche la row BDD après migration Python. Idem
    capitalisation turque (``İ`` → ``i̇``), sigma médian grec, etc.
    """
    return casefold_email(raw)


def _truncate_user_agent(raw: Optional[str]) -> str:
    """Tronque l'user-agent à la limite configurée avant de la persister.

    Un client peut envoyer un user-agent de plusieurs kilo-octets (bot
    exotique, PoC d'injection). On limite pour éviter de bourrer la table
    ``sessions.user_agent`` et les logs structurés.
    """
    if not raw:
        return ""
    max_len = config.security.user_agent_log_max_length
    return raw[:max_len]


def _format_session_duration_human(hours: int) -> str:
    """Formate une durée en heures vers un libellé FR lisible.

    - ``168`` → ``"7 jours"`` (multiple exact de 24)
    - ``24``  → ``"1 jour"``  (singulier)
    - ``36``  → ``"36h"``     (pas multiple de 24, on garde l'heure)
    - ``8``   → ``"8h"``
    - ``0`` ou négatif → ``"0h"`` (défensif — la config valide >0 ailleurs).

    Utilisé pour le label de la case « Garder ma session ouverte » sur
    ``/login`` : l'utilisateur voit la VRAIE durée (7 jours, pas 168h).
    """
    if hours is None or hours <= 0:
        return "0h"
    if hours >= 24 and hours % 24 == 0:
        days = hours // 24
        return f"{days} jour" if days == 1 else f"{days} jours"
    return f"{hours}h"


def _build_cookie_options(*, remember_me: bool, partitioned: bool = False) -> dict[str, Any]:
    """Construit les options ``set_secure_cookie`` alignées sur la config.

    ADV-M2 : ``expires_days`` est strictement aligné sur
    ``session_timeout_hours`` côté BDD — Tornado supporte les fractions
    de jour, donc 8h donne 0.333 jour. Avant : ``max(.../24, 1)`` plafonnait
    à 1 jour minimum, créant l'incohérence "cookie persiste 24h alors que
    la session BDD expire à 8h" → user déconnecté côté serveur en plein
    milieu d'une session "Remember me" → UX confuse.

    ``partitioned`` (kwarg-only, default False) : ajoute le flag ``Partitioned``
    (CHIPS, Chrome 118+, 2024). Utile UNIQUEMENT pour les cookies servis
    dans un contexte cross-site (iframe d'un site tiers). Komptia est
    une app **first-party** (même origine que le navigateur principal) —
    le browser ignore silencieusement ``Partitioned`` quand
    ``SameSite=Lax`` ou ``SameSite=Strict``. L'ajouter aujourd'hui ne
    casse rien, mais allonge le header sans bénéfice runtime.

    Si un jour Komptia est embarqué en iframe (white-label, intégration
    tierce), il faudra :

    1. Passer ``samesite="None"`` (sinon le cookie ne traverse pas).
    2. Forcer ``secure=True`` (obligation navigateur avec ``SameSite=None``).
    3. Passer ``partitioned=True`` ici (CHIPS isole le cookie par
       embedder, évite tracking cross-site, conforme Chrome 2024+).

    Tornado 6.5 propage les kwargs ``set_cookie`` au :class:`http.cookies.Morsel` —
    ``Partitioned`` est dans la liste réservée Python 3.10+, donc il
    suffit d'activer le kwarg quand le moment viendra (axe 24 Komptia).

    Bug 2026-05-26 (Agent 1 brainstorm L-2+L-6) : le kwarg ``partitioned``
    est désormais accepté pour permettre l'activation future via toggle
    config sans rééditer cette fonction.
    """
    options: dict[str, Any] = {
        "httponly": True,
        "secure": config.is_production(),
        "samesite": "Lax",
    }
    if partitioned:
        # CHIPS Chrome 118+ — préparation pour iframe embed futur. Le flag
        # est ignoré silencieusement par les navigateurs sans support.
        options["partitioned"] = True
    if remember_me:
        # « Garder ma session ouverte » coché → cookie aligné sur
        # ``session_remember_timeout_hours`` (168h / 7j par défaut). La
        # session BDD utilise la même valeur (SessionManager.create_session +
        # Session.refresh) → pas de cookie-vivant/session-morte (ADV-M2).
        # Bug 2026-05-26 : avant, on lisait ``session_timeout_hours`` (8h)
        # → l'utilisateur s'attendait à rester connecté longtemps mais
        # était déconnecté à 8h.
        session_hours = config.security.session_remember_timeout_hours
        options["expires_days"] = session_hours / 24
    else:
        # Cookie de session navigateur : disparaît à la fermeture du browser.
        # La session BDD garde sa durée standard (``session_timeout_hours``,
        # 8h par défaut) pour l'inactivité serveur.
        options["expires_days"] = None
    return options


async def _rehash_if_needed(user_id: int, current_hash: str, plaintext: str) -> None:
    """Re-hashe le mot de passe si les rounds bcrypt ont été augmentés
    depuis le dernier login.

    Utilise un UPDATE ... WHERE password_hash = :current_hash (pattern CAS :
    compare-and-swap) pour éviter la race où deux logins concurrents
    calculeraient un nouveau hash et l'écriraient coup sur coup. Si une
    autre session a déjà migré le hash, notre UPDATE ne matche rien —
    comportement idempotent voulu.
    """
    hasher = get_password_hasher()
    if not hasher.needs_rehash(current_hash):
        return
    try:
        # ``allow_truncate=True`` : ``plaintext`` vient d'un login RÉUSSI, donc
        # un mot de passe legacy >72 octets (créé sous bcrypt 4.x) a déjà été
        # accepté via la troncature au verify. Le re-hacher sans tronquer
        # lèverait PasswordTooLongError ; on tronque pour rester cohérent.
        new_hash = hasher.hash_password(plaintext, allow_truncate=True)
        async with get_session() as db:
            result = await db.execute(
                update(User)
                .where(User.id == user_id, User.password_hash == current_hash)
                .values(password_hash=new_hash)
            )
            await db.commit()
            if result.rowcount:
                logger.info(
                    "Hash mot de passe migré (rounds obsolètes)",
                    extra={"user_id": user_id},
                )
    except (SQLAlchemyError, AuthenticationError):
        # hash_password peut lever AuthenticationError si bcrypt explose.
        # On laisse simplement la prochaine connexion réessayer.
        logger.warning("Rehash échoué, sera retenté au prochain login", exc_info=True)


async def _update_last_login(user_id: int, now_utc: Any) -> None:
    """Met à jour ``users.last_login`` sans perturber le reste.

    Indispensable pour l'écran admin (colonne 'dernière connexion') et
    pour détecter les comptes inactifs en production. En cas d'échec, on
    log seulement — pas de raison d'interrompre l'ouverture de session.
    """
    try:
        async with get_session() as db:
            await db.execute(update(User).where(User.id == user_id).values(last_login=now_utc))
            await db.commit()
    except SQLAlchemyError:
        logger.warning("Échec mise à jour last_login", extra={"user_id": user_id})


# ── Handlers HTTP ─────────────────────────────────────────────────────────


class LoginHandler(BaseHandler):
    """GET affiche le formulaire ; POST authentifie et pose la session."""

    def _render_login(self, *, next_url: str, error: Optional[str] = None) -> None:
        # Expose les deux durées au template :
        # - ``session_timeout_hours`` : session navigateur par défaut (sans
        #   "Garder ma session" coché). 8h.
        # - ``session_remember_timeout_hours`` : session étendue quand l'user
        #   coche la case. 168h (7j) par défaut.
        # - ``session_remember_human`` : version humaine formatée pour le label
        #   ("7 jours" ou "168h"). Évite un calcul ``{{ x // 24 }}`` dans
        #   Tornado qui supporte mal les expressions complexes.
        # Le label de la case s'appuie sur ``session_remember_human`` pour
        # montrer la VRAIE durée à laquelle l'utilisateur s'engage. Bug
        # 2026-05-26 : le label précédent "Se souvenir de moi" suggérait
        # jours/semaines alors que la session BDD plafonnait à 8h, et le
        # premier patch (#81) avait corrigé le label mais pas la durée
        # effective. Cette version aligne les deux.
        self.render(
            _LOGIN_TEMPLATE,
            next_url=next_url,
            error=error,
            app_name=config.app_name,
            session_timeout_hours=config.security.session_timeout_hours,
            session_remember_timeout_hours=config.security.session_remember_timeout_hours,
            session_remember_human=_format_session_duration_human(
                config.security.session_remember_timeout_hours
            ),
        )

    async def get(self) -> None:
        """Affiche la page de connexion (ou redirige si déjà connecté)."""
        if self.current_user:
            self.redirect(_resolve_next_url(self.get_argument("next", _DEFAULT_NEXT_URL)))
            return

        next_url = _resolve_next_url(self.get_argument("next", _DEFAULT_NEXT_URL))
        self._render_login(next_url=next_url, error=None)

    async def post(self) -> None:
        """Traite le formulaire POST de connexion."""
        email = _normalize_login_email(self.get_argument("email", ""))
        password = self.get_argument("password", "")
        next_url = _resolve_next_url(self.get_argument("next", _DEFAULT_NEXT_URL))
        remember_me = self.get_argument("remember_me", "off") == "on"
        client_ip = self.request.remote_ip
        rate_limiter = get_login_rate_limiter()

        # ADV-S7 : plafond password AVANT toute opération coûteuse —
        # un payload de 10 MB allouerait 10 MB en mémoire (encode UTF-8)
        # avant d'arriver à bcrypt. On rejette comme MISSING_FIELDS pour
        # ne pas révéler que le rejet est dû à la longueur (timing leak).
        if len(password) > _PASSWORD_MAX_LENGTH:
            logger.warning(
                "Login : password length excessive (DoS bcrypt prévenu)",
                extra={
                    "ip": rate_limiter.normalize_ip(client_ip),
                    "length": len(password),
                },
            )
            self._render_login(next_url=next_url, error=_Messages.MISSING_FIELDS)
            return

        # 1) Rate limiting + countdown atomique en UN seul SELECT (ADV-S2).
        # Le rate-limiter expose toujours le paramètre ``username`` (colonne
        # BDD ``LoginAttempt.username``) — on y passe l'email depuis 2026-05-11.
        # La colonne n'est pas renommée pour éviter une migration destructive.
        is_blocked, seconds_left = await rate_limiter.check_block_with_deadline(
            ip=client_ip, username=email or None
        )
        if is_blocked:
            logger.warning(
                "Rate limit atteint",
                extra={
                    "ip": rate_limiter.normalize_ip(client_ip),
                    "seconds_left": seconds_left,
                },
            )
            error_msg = (
                _Messages.rate_limited_with_countdown(seconds_left)
                if seconds_left is not None
                else _Messages.RATE_LIMITED
            )
            self._render_login(next_url=next_url, error=error_msg)
            return

        # 2) Validation input minimum.
        if not email or not password:
            self._render_login(next_url=next_url, error=_Messages.MISSING_FIELDS)
            return

        try:
            user = await self._authenticate(email=email, password=password)
        except AuthenticationError:
            await rate_limiter.record_attempt(ip=client_ip, username=email, success=False)
            logger.warning(
                "Échec de connexion",
                extra={
                    "ip": rate_limiter.normalize_ip(client_ip),
                    "email_length": len(email),
                },
            )
            # Audit légal : tentative échouée (sans l'email tenté — anti-énumération ;
            # le rate-limiter trace déjà par username pour l'anti-bruteforce).
            await _record_login_audit(
                user_id=None,
                action=AuditAction.LOGIN_FAILED,
                entity_id=None,
                details={"email_length": len(email)},
                ip_address=rate_limiter.normalize_ip(client_ip),
                user_agent=_truncate_user_agent(self.request.headers.get("User-Agent", "")),
            )
            # Message générique : jamais str(exc) (risque de fuite).
            self._render_login(next_url=next_url, error=_Messages.INVALID_CREDENTIALS)
            return
        except SQLAlchemyError:
            logger.error("Erreur BDD pendant le login", exc_info=True)
            self._render_login(next_url=next_url, error=_Messages.GENERIC_ERROR)
            return

        # 3) Authentification réussie : session + cookie + audit + last_login.
        try:
            now_utc = clock.now()
            await _rehash_if_needed(user.id, user.password_hash, password)
            await _update_last_login(user.id, now_utc)

            session_manager = get_session_manager()
            session = await session_manager.create_session(
                user_id=user.id,
                ip_address=rate_limiter.normalize_ip(client_ip),
                user_agent=_truncate_user_agent(self.request.headers.get("User-Agent", "")),
                remember_me=remember_me,
            )
        except (SQLAlchemyError, AuthenticationError):
            logger.error("Création de session échouée post-auth", exc_info=True)
            self._render_login(next_url=next_url, error=_Messages.GENERIC_ERROR)
            return

        # Audit légal : connexion réussie tracée dans ``audit_logs``.
        await _record_login_audit(
            user_id=user.id,
            action=AuditAction.LOGIN,
            entity_id=user.id,
            details={"remember_me": remember_me},
            ip_address=rate_limiter.normalize_ip(client_ip),
            user_agent=_truncate_user_agent(self.request.headers.get("User-Agent", "")),
        )

        # ADV-S4 : on enregistre le succès (audit rate-limiter) ET on purge les
        # attempts ratées récentes — un user qui retape 4 fois faux puis bon ne
        # doit pas rester pénalisé pour ses prochaines connexions.
        await rate_limiter.record_attempt(ip=client_ip, username=email, success=True)
        await rate_limiter.reset_failures_after_success(ip=client_ip, username=email)

        self.set_secure_cookie(
            SESSION_COOKIE_NAME,
            session.id,
            **_build_cookie_options(remember_me=remember_me),
        )
        # Régénère le token XSRF pour éviter une attaque de session fixation
        # post-login (OWASP Auth Cheat Sheet 2025).
        self.clear_cookie("_xsrf")
        _ = self.xsrf_token  # déclenche la ré-émission du cookie

        logger.info(
            "Connexion réussie",
            extra={
                "user_id": user.id,
                "ip": rate_limiter.normalize_ip(client_ip),
            },
        )
        self.redirect(next_url)

    async def _authenticate(self, *, email: str, password: str) -> User:
        """Vérifie ``email`` + ``password``. Lève ``AuthenticationError``
        en cas d'échec — sans différencier 'inconnu' / 'inactif' / 'mauvais
        mot de passe' (anti-énumération).

        ``email`` est attendu DÉJÀ NORMALISÉ par ``_normalize_login_email``
        (Unicode casefold + cap longueur). La migration ``lowercase_email``
        garantit que TOUTES les rows ``users.email`` sont stockées casefoldées
        Python (pas seulement ``LOWER()`` SQL ASCII-only). On peut donc faire
        une égalité directe — plus performant (index utilisable) et plus safe
        que ``func.lower(User.email)`` qui ne folde que l'ASCII côté SQLite
        et raterait les eszett, accents capitalisés, sigma grec, etc.

        Mitigation timing-attack (LOGIN-A6) : le coût ``bcrypt.verify`` est
        constant (~200ms à rounds=12), payé dans tous les cas (vrai
        hash OU dummy hash factice aligné sur les mêmes rounds). La
        latence du SELECT BDD reste théoriquement observable (cache hit
        vs miss SQLite) mais cette différence est négligeable face au
        temps bcrypt et indistinguable du jitter réseau. Pas de
        contre-mesure supplémentaire nécessaire à ce niveau de menace.
        """
        async with get_session() as db:
            result = await db.execute(select(User).where(User.email == email))
            user = result.scalar_one_or_none()

        hasher = get_password_hasher()

        # Compte inconnu ou inactif : on fait un bcrypt check factice pour
        # égaliser le temps de réponse (anti-timing / anti-énumération).
        # ADV-M6 : utiliser la version async (asyncio.to_thread interne)
        # pour ne pas freezer l'event-loop ~200ms au premier appel.
        if user is None or not user.is_active:
            dummy = await _get_dummy_hash_async()
            hasher.verify_password(password, dummy)
            raise AuthenticationError("invalid_credentials")

        if not hasher.verify_password(password, user.password_hash):
            raise AuthenticationError("invalid_credentials")

        return user


class LogoutHandler(BaseHandler):
    """Détruit la session (BDD + cookie) puis redirige vers ``/login``."""

    async def _destroy_session_from_cookie(self) -> None:
        """Détruit la session BDD associée au cookie courant (idempotent).

        Cas couverts :

        * Pas de cookie → no-op (logout d'un user déjà déconnecté).
        * Cookie corrompu (bytes non UTF-8 ou non décodables) → log debug
          (ADV-S8 : pas warning — un attaquant qui spamme /logout avec
          des cookies corrompus génèrerait sinon 1 warning par tentative,
          DoS sur l'observabilité). Le ``clear_cookie`` qui suit retire
          le cookie côté client. La session BDD orpheline éventuelle est
          purgée par le cleanup périodique.
        * Token vide après décodage → no-op.
        """
        raw_token = self.get_secure_cookie(SESSION_COOKIE_NAME)
        if not raw_token:
            return
        try:
            token_str = raw_token.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            logger.debug(
                "Cookie %s corrompu lors du logout — clear côté client, "
                "purge BDD différée au cleanup périodique",
                SESSION_COOKIE_NAME,
            )
            return
        if not token_str:
            return
        session_manager = get_session_manager()
        await session_manager.destroy_session(token_str)

    async def get(self) -> None:
        """Déconnexion (idempotente — fonctionne même sans session)."""
        await self._destroy_session_from_cookie()

        logger.info(
            "Déconnexion",
            extra={
                "ip": get_login_rate_limiter().normalize_ip(self.request.remote_ip),
            },
        )

        # ``clear_cookie`` doit répliquer les flags de ``set_secure_cookie``
        # pour que le navigateur efface effectivement le cookie. Sinon
        # cookies fantômes sur Safari iOS / Firefox strict.
        #
        # ADV-M4 : on émet DEUX clear_cookie — un avec secure=True et un
        # avec secure=False — pour gérer la transition dev→prod. Si un
        # cookie a été posé en dev (secure=False) et que l'app passe en
        # production, le clear avec secure=True ne matcherait pas et le
        # cookie resterait. Émettre les deux purge dans tous les cas.
        for secure_flag in (True, False):
            self.clear_cookie(
                SESSION_COOKIE_NAME,
                path="/",
                secure=secure_flag,
                samesite="Lax",
                httponly=True,
            )
        self.redirect(_LOGIN_URL)

    async def post(self) -> None:
        """POST logout (CSRF-protégé par Tornado xsrf_cookies)."""
        await self.get()


class XsrfTokenAPIHandler(BaseHandler):
    """``GET /api/auth/xsrf`` — retourne le token XSRF courant et force la
    ré-émission du cookie ``_xsrf``.

    Pourquoi cet endpoint existe
    ----------------------------
    Tornado régénère le cookie ``_xsrf`` à chaque login (cf.
    :meth:`LoginHandler.post`, ``self.clear_cookie('_xsrf')`` puis
    ``_ = self.xsrf_token``). C'est volontaire (anti session-fixation,
    OWASP Auth Cheat Sheet). Effet de bord : toute page **déjà rendue**
    avant le login (typiquement un onglet ``/iris`` resté ouvert pendant
    qu'on se reconnecte dans un autre onglet) garde dans son JS un
    ``IRIS_CONFIG.xsrfToken`` figé sur l'ancien hash, alors que le
    cookie envoyé par le navigateur est désormais le nouveau.

    Résultat : à la prochaine reconnexion WebSocket, le serveur compare
    URL-token (ancien) vs cookie (nouveau) → mismatch → ``check_xsrf_cookie``
    fail → boucle de reconnect en 4003.

    Cet endpoint casse cette boucle : le client appelle
    ``GET /api/auth/xsrf`` AVANT chaque ``new WebSocket(...)`` ; la
    requête HTTP fait deux choses utiles :

    1. Force ``_ = self.xsrf_token`` côté serveur via
       :meth:`BaseHandler.prepare` -- ça (re-)émet le cookie ``_xsrf``
       avec un mask frais (le hash sous-jacent reste celui de la session
       courante).
    2. Renvoie ce token dans le body JSON, prêt à être mis dans
       ``?_xsrf=...`` -- garantit que URL et cookie ont le même hash
       au moment de la handshake WebSocket qui suit immédiatement.

    Sécurité (ADV-M8)
    -----------------
    * ``@authenticated`` : un anonyme n'a aucune raison de récupérer un
      token et pollue inutilement les rate-limits si on l'autorisait.
      Pour un anonyme on retourne 401 (le client fait alors un
      ``location.reload()`` et passera par ``/login``).
    * Pas de ``Cache-Control`` agressif -- c'est un endpoint qui DOIT
      être ré-exécuté (pas servi depuis cache).
    * Le token retourné est déjà du PII session-scope ; il sort déjà
      dans toutes les pages HTML rendues. Aucune élévation de privilège.
    * **NB :** cet endpoint est utilisé par ``feedback-reporter.js`` pour
      retry sur 403 XSRF (cookie disparu suite à un crash de prepare()),
      ET par ``iris.js`` au handshake WebSocket pour éviter la dérive
      cookie/URL-token quand l'user se reconnecte dans un autre onglet.
      Les futures relectures ne doivent pas confondre cet endpoint avec
      un "rate-limit bypass" ; c'est un mécanisme de cohérence XSRF.
    """

    @authenticated
    async def get(self) -> None:
        # ``BaseHandler.prepare`` a déjà touché ``self.xsrf_token`` (cf.
        # commentaire ligne 240+ de base.py) -- le cookie est donc déjà
        # ré-émis. On lit la valeur ici pour la renvoyer au client.
        token = self.xsrf_token
        # Tornado renvoie ``bytes`` ; on décode pour le JSON.
        if isinstance(token, (bytes, bytearray)):
            token_str = token.decode("ascii")
        else:
            token_str = str(token)
        # ``no-store`` : pas de cache navigateur ni proxy. Chaque hit doit
        # ré-exécuter pour garantir que le cookie est posé maintenant.
        self.set_header("Cache-Control", "no-store")
        self.write_json({"token": token_str})
