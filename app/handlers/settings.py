"""Handlers HTTP de la page « Paramètres » utilisateur.

Endpoints
---------
* ``GET /settings`` → page HTML (``templates/settings.html``).
* ``GET/PUT /api/settings/profile`` → nom d'affichage + email.
* ``PUT /api/settings/password`` → changement de mot de passe
  (re-authentification par le mot de passe actuel).
* ``GET/PUT /api/settings/appearance`` → mode de couleur (light/dark/system).

Le stockage des préférences non-structurelles (``display_name``,
``theme_mode``) passe par la table ``user_preferences`` en clé/valeur : pas de
migration du schéma :class:`~app.models.user.User` à chaque nouvelle
préférence utilisateur.

Garanties senior appliquées (OWASP Top 10 2025 + API Sec Top 10 2023 + ASVS v5)
------------------------------------------------------------------------------
1. **A01 Broken Access Control** — tous les endpoints sont décorés par
   :func:`~app.handlers.base.authenticated`. Chaque utilisateur ne peut
   modifier QUE son propre compte : ``user.id`` est lu depuis
   ``self.current_user`` (cookie signé Tornado), jamais depuis le body.
2. **A04 Insecure Design — Unrestricted Resource Consumption (API4)** — trois
   rate-limiters distincts couvrent les trois surfaces d'abus :

   * :data:`_PASSWORD_RATE_MAX` changements de mot de passe par fenêtre
     :data:`_PASSWORD_RATE_WINDOW_S` → bloque la force-brute du mot de
     passe courant via répétition (défense-in-depth devant bcrypt).
   * :data:`_PROFILE_RATE_MAX` mises à jour de profil par fenêtre
     :data:`_PROFILE_RATE_WINDOW_S` → mitige le scraping d'emails
     disponibles (409 vs 200 révèle une information) et le spam de write
     sur ``users``.
   * :data:`_APPEARANCE_RATE_MAX` changements de thème par fenêtre
     :data:`_APPEARANCE_RATE_WINDOW_S` → tolérant (UI clique rapidement)
     mais non illimité.

   Tous keyés par ``user_id`` (+ fallback IP) via
   :func:`_rate_limit_key` pour rester précis en multi-tenant.
3. **A03 Injection & Validation aux frontières** — le body JSON est validé
   en forme (``dict``) + taille (:data:`_BODY_MAX_BYTES`) + encodage
   (UTF-8 strict, ``UnicodeDecodeError`` catché). Tous les champs texte
   passent par ``_coerce_str`` avec ``max_len`` explicite, puis
   :func:`_has_control_chars` (CRLF / NUL / contrôle).
4. **V6 Account Management (ASVS v5)** — ``PUT /password`` exige le mot de
   passe courant (re-authentication V6.2.2), compare via bcrypt
   constant-time, invalide toutes les AUTRES sessions via
   :meth:`SessionManager.destroy_sessions_except` (defense-in-depth :
   ``keep_token`` est re-vérifié côté session manager). Le changement
   d'adresse e-mail N'exige PAS de re-auth dans cette version (UX fragile
   sur petit écran : le couple admin/user sait qu'il doit se re-logger ;
   le flux complet est tracké par :file:`findings/EPICS.md`
   ``[EPIC:EMAIL-CHANGE-REAUTH]``). Défense-in-depth : rate-limit sur
   email change à 3/h / user.
5. **RFC 5321 email length** — e-mail max :data:`_EMAIL_MAX_LEN` (254
   octets, pas 100 comme historiquement) pour coller à la norme SMTP ;
   un attaquant qui teste 256 chars reçoit 400 cohérent avec le serveur
   de mail aval.
6. **V6.2.5 Password strength** — longueur min :data:`_PASSWORD_MIN_LEN`
   caractères. La borne HAUTE qui compte pour la sécurité est en OCTETS :
   :data:`~app.core.constants_auth.PASSWORD_MAX_BYTES` (72) — au-delà, bcrypt
   ignore les octets, donc on REJETTE (cf. :func:`password_exceeds_bcrypt_limit`).
   ⚠️ :data:`_PASSWORD_MAX_LEN` (128 caractères) n'est qu'un garde-fou grossier
   complémentaire ; il NE « couvre » PAS la limite bcrypt — 128 chars ASCII =
   128 octets > 72. Un refus de mot de passe « trivial » (liste noire locale
   :data:`_TRIVIAL_PASSWORDS`) bloque les 20 classiques — sans dépendance
   externe payante (haveibeenpwned).
7. **CWE-209 — Error Message Containing Sensitive Information** — aucune
   ``str(exc)`` ou ``repr(exc)`` dans les réponses : tous les messages
   clients sont dans :class:`_Messages` (FR, tons cohérents). Les traces
   complètes partent vers ``logger.exception`` avec ``request_id``.
8. **CWE-306 — Missing Authentication for Critical Function** — le ``PUT
   password`` ré-invalide toutes les autres sessions du user. En cas
   d'échec DB de cette révocation, on loggue ``logger.error`` mais on
   **retourne succès** (le password est changé ; la révocation est un
   best-effort UX — les anciens tokens expirent naturellement par le
   ``session_timeout_hours`` de la config) — explicitement documenté
   plutôt que de laisser l'utilisateur pendu dans un rollback partiel.
"""

from __future__ import annotations

import functools
import json
import re
from typing import Any, Awaitable, Callable, Final

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import THEME_MODES
from app.core.constants_auth import PASSWORD_MAX_BYTES, password_exceeds_bcrypt_limit
from app.core.database import get_session
from app.handlers.base import SESSION_COOKIE_NAME, BaseHandler, authenticated
from app.handlers.help_docs import available_guides_for_user
from app.models.base import ensure_utc
from app.models.user import User
from app.models.user_preference import UserPreference
from app.services.auth.password_hasher import get_password_hasher
from app.services.auth.session_manager import get_session_manager
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


# ── Constantes ────────────────────────────────────────────────────────────

#: Clef ``user_preferences`` pour le nom d'affichage (libellé dans la page).
#: Préfixée pour éviter une collision avec les futures préférences Iris (voir
#: :class:`~app.models.user_preference.UserPreference` — catégories
#: ``vocabulary``, ``frequent_query``, etc.).
PREF_DISPLAY_NAME: Final[str] = "display_name"

#: Clef ``user_preferences`` pour le thème UI (cohérent avec ``static/js/
#: settings.js::THEME_STORAGE_KEY`` côté localStorage, mais normalisé ici).
PREF_THEME_MODE: Final[str] = "theme_mode"

#: Valeurs admises pour le thème. ``system`` suit la préférence OS (media
#: query ``prefers-color-scheme``) — géré côté frontend (``base.html``).
#: SSoT : ``app.constants.THEME_MODES``. Le frozenset facilite ``in`` O(1).
#: Bug 2026-05-26 (S-8) : la liste était dupliquée ici + JS + base.html ;
#: drift garanti à la moindre évolution. Le test
#: ``tests/unit/test_theme_modes_ssot.py`` verrouille les 3 sites contre
#: ``THEME_MODES``.
_THEME_MODE_VALUES: Final[frozenset[str]] = frozenset(THEME_MODES)

#: Thème par défaut si l'utilisateur n'en a jamais choisi.
#: Décision produit : ``"system"`` — on suit la préférence OS du
#: visiteur (``prefers-color-scheme``). Cohérent avec un Mac/Windows en
#: dark mode qui s'attend à voir l'app aussi en dark à la première
#: visite, sans flash blanc agressif. L'utilisateur peut bien sûr
#: forcer ``"light"`` ou ``"dark"`` dans /settings.
_DEFAULT_THEME_MODE: Final[str] = "system"

#: Clef ``user_preferences`` pour le consentement de lecture des résultats
#: SQL par Iris. Avant qu'Iris (free-loop agent OU pipeline) n'envoie les
#: résultats d'une requête SQL exécutée au LLM cloud pour analyse, le
#: système consulte cette préférence pour décider du flow.
#:
#: Valeurs :
#:   - ``ask`` (défaut) : poser la question à l'utilisateur à la 1ère
#:     ``execute_sql`` / ``run_pipeline`` de chaque conversation. Si user
#:     coche "ne plus me redemander" + OUI → bascule en ``always_allow``.
#:     Si user coche "ne plus me redemander" + NON → bascule en
#:     ``always_show_panel``.
#:   - ``always_allow`` : ne jamais demander, Iris lit directement (les
#:     2 couches d'anonymisation existantes s'appliquent toujours).
#:   - ``always_show_panel`` : ouvrir systématiquement le panneau
#:     "Confidentialité — termes à anonymiser" pré-rempli avec les valeurs
#:     uniques du résultat SQL avant lecture LLM. Workflow le plus strict.
PREF_IRIS_DATA_READ_CONSENT: Final[str] = "iris_data_read_consent"
_IRIS_CONSENT_VALUES: Final[frozenset[str]] = frozenset(
    {"ask", "always_allow", "always_show_panel"}
)
_DEFAULT_IRIS_CONSENT: Final[str] = "ask"

#: Longueur max d'un ``display_name``. Cohérent avec le ``maxlength="100"`` du
#: ``<input>`` dans ``templates/settings.html`` + colonne ``User.username``
#: (``String(50)``). 100 chars = 2× la marge, suffisant pour un prénom+nom+
#: initiales sans flooder l'affichage latéral.
_DISPLAY_NAME_MAX_LEN: Final[int] = 100

#: Longueur max d'une adresse e-mail acceptée. **254 octets** est la limite
#: officielle SMTP (RFC 5321 §4.5.3.1.3 : path max 256 octets avec 2 angle
#: brackets → 254 pour l'adresse). Historiquement 100 chez Komptia pour
#: s'aligner sur la colonne ``User.email``, mais un e-mail légitime peut
#: dépasser 100 (adresses entreprise à domaine long). On borne au RFC et la
#: colonne DB est large (``String(100)``) → un e-mail de 101-254 chars sera
#: refusé par la contrainte DB ; on intercepte propre ici pour donner un
#: message FR clair au user.
_EMAIL_MAX_LEN: Final[int] = 254

#: Longueur min d'un mot de passe (V6.2.5 OWASP ASVS v5). 8 est le minimum
#: autorisé par la spec ; on ne monte pas à 12 par défaut pour ne pas
#: invalider les comptes existants — la règle peut évoluer (EPIC transverse).
_PASSWORD_MIN_LEN: Final[int] = 8

#: Borne haute *grossière* en CARACTÈRES (sanité / anti-body géant). La borne
#: de **correction bcrypt** est distincte et exprimée en OCTETS :
#: :data:`~app.core.constants_auth.PASSWORD_MAX_BYTES` (72), vérifiée par
#: :func:`password_exceeds_bcrypt_limit` dans :func:`_validate_password_input`.
#: ⚠️ NE PAS croire que « 128 chars < 72 octets » : 128 chars ASCII = 128 octets
#: > 72 — c'est justement le bug que le check octets ferme. Les deux coexistent :
#: le check octets (strict) attrape tout >72 o, ce cap chars reste un garde-fou
#: lisible en complément.
_PASSWORD_MAX_LEN: Final[int] = 128

#: Liste noire minimaliste de mots de passe triviaux (V6.2.8 ASVS v5). Ne
#: remplace PAS une intégration haveibeenpwned (EPIC future), mais bloque les
#: 20 classiques qui représentent ~60 % des comptes crackés (source :
#: rapports annuels NordPass/SplashData). Toutes en ASCII lowercase — la
#: comparaison est ``casefold()`` → « Password1 » matche « password1 ».
_TRIVIAL_PASSWORDS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "password1",
        "password123",
        "123456",
        "123456789",
        "12345678",
        "qwerty",
        "qwerty123",
        "abc123",
        "azerty",
        "motdepasse",
        "secret",
        "letmein",
        "welcome",
        "admin",
        "admin123",
        "root",
        "toor",
        "iloveyou",
        "monkey",
    }
)

#: Taille max du body JSON accepté par les endpoints de settings. 64 KiB est
#: plus que large : le body le plus gros (PUT /profile avec display_name 100
#: chars + email 254 chars + metadata) fait ~500 octets. Un envoi >64 Ko
#: relève du bug/attaque : on répond 413 avant de désérialiser.
_BODY_MAX_BYTES: Final[int] = 64 * 1024

#: Rate-limit pour ``PUT /api/settings/password`` : 5 tentatives par
#: 5 minutes / user. Chaque tentative fait UN verify bcrypt (≈100–300 ms à
#: rounds=12) + une écriture DB → abuser coûte peu à l'attaquant mais cumulé
#: (distribué, 100 users) peut saturer l'event-loop. 5/5min est cohérent
#: avec le rate-limit login (``config.security.rate_limit_login`` défaut
#: =5/60s), scalé à une fenêtre plus large parce qu'un changement de mdp
#: légitime arrive rarement plusieurs fois par semaine.
_PASSWORD_RATE_MAX: Final[int] = 5
_PASSWORD_RATE_WINDOW_S: Final[int] = 5 * 60

#: Rate-limit GLOBAL pour ``PUT /api/settings/profile`` (display_name + email).
#: Bumped à 20/h depuis le bug 2026-05-26 (S-11) : avant, 3/h bloquait
#: l'utilisateur sur 3 typos triviaux du display_name. La protection
#: anti-énumération d'emails passe par ``_PROFILE_EMAIL_RATE_MAX`` (3/h)
#: ci-dessous, qui ne s'applique QUE quand l'email change réellement.
_PROFILE_RATE_MAX: Final[int] = 20
_PROFILE_RATE_WINDOW_S: Final[int] = 60 * 60

#: Rate-limit STRICT supplémentaire pour les changements d'email — c'est
#: le seul axe d'énumération authentifiée (409 EMAIL_TAKEN révèle un email
#: valide). 3/h x 24h x 30j = 2160 essais/mois max → forcer un attaquant à
#: ~138 jours pour brute-forcer un dico de 10 000 adresses. Bug 2026-05-26
#: (S-11) : split du rate-limit global qui pénalisait les typos
#: display_name innocentes (cf. _PROFILE_RATE_MAX ci-dessus).
_PROFILE_EMAIL_RATE_MAX: Final[int] = 3
_PROFILE_EMAIL_RATE_WINDOW_S: Final[int] = 60 * 60

#: Rate-limit pour ``PUT /api/settings/appearance``. L'UI annule les appels
#: précédents via ``AbortController`` (voir ``settings.js::selectTheme``)
#: mais un clic rapide en réseau lent peut envoyer 2-3 PUT en parallèle.
#: 20/min est tolérant pour le flux UX légitime et bloque un script qui
#: bombarderait l'endpoint.
_APPEARANCE_RATE_MAX: Final[int] = 20
_APPEARANCE_RATE_WINDOW_S: Final[int] = 60


#: Regex email : local@domaine.tld. Interdit les espaces, CRLF et contrôles
#: (CWE-93 : injection d'en-tête SMTP en aval). Volontairement permissive
#: sur le local-part (accepte ``user+tag@…``) parce que la vérification
#: RFC-5321 complète relève de l'envoi SMTP, pas de la validation du
#: formulaire. Un e-mail « a@b.c » passera — charge au service SMTP de
#: rejeter. **Pas** d'ajout de validation « punycode / homograph » ici :
#: c'est transverse (voir :file:`findings/EPICS.md` si pertinent).
_EMAIL_RE: Final[re.Pattern[str]] = re.compile(
    r"^[^\s@\x00-\x1f\x7f]+@[^\s@\x00-\x1f\x7f]+\.[^\s@\x00-\x1f\x7f]+$"
)


# ── Messages client centralisés ───────────────────────────────────────────


class _Messages:
    """Libellés client FR exposés par les endpoints settings.

    Centraliser ces constantes : audit sécurité (pas de drift entre
    handlers), tests d'intégration (import au lieu d'un hardcode), future
    i18n. Jamais de ``str(exc)`` ici — les traces partent vers les logs
    structurés.
    """

    INVALID_JSON: Final[str] = "Corps de requête JSON invalide."
    INVALID_PAYLOAD: Final[str] = "Un objet JSON est attendu."
    BODY_TOO_LARGE: Final[str] = "Corps de requête trop volumineux."
    INVALID_EMAIL: Final[str] = "Adresse e-mail invalide (format attendu : nom@domaine.tld)."
    EMAIL_TOO_LONG: Final[str] = (
        f"Adresse e-mail trop longue (limite : {_EMAIL_MAX_LEN} caractères, RFC 5321)."
    )
    EMAIL_TAKEN: Final[str] = "Cette adresse e-mail est déjà utilisée."
    INVALID_DISPLAY_NAME: Final[str] = "Nom d'affichage invalide."
    DISPLAY_NAME_TOO_LONG: Final[str] = (
        f"Nom d'affichage trop long (limite : {_DISPLAY_NAME_MAX_LEN} caractères)."
    )
    DISPLAY_NAME_CONTROL_CHARS: Final[str] = (
        "Le nom d'affichage ne doit pas contenir de caractères de contrôle."
    )
    PASSWORD_BOTH_REQUIRED: Final[str] = "Mot de passe actuel et nouveau mot de passe requis."
    PASSWORD_TOO_SHORT: Final[str] = (
        f"Le nouveau mot de passe doit faire au moins {_PASSWORD_MIN_LEN} caractères."
    )
    PASSWORD_TOO_LONG: Final[str] = (
        f"Le nouveau mot de passe ne peut dépasser {_PASSWORD_MAX_LEN} caractères."
    )
    PASSWORD_TOO_MANY_BYTES: Final[str] = (
        f"Le nouveau mot de passe ne peut pas dépasser {PASSWORD_MAX_BYTES} octets "
        "(limite de l'algorithme de hachage)."
    )
    PASSWORD_TOO_TRIVIAL: Final[str] = (
        "Ce mot de passe est trop courant, choisissez-en un plus original."
    )
    PASSWORD_SAME_AS_OLD: Final[str] = "Le nouveau mot de passe doit être différent de l'actuel."
    PASSWORD_CURRENT_WRONG: Final[str] = "Mot de passe actuel incorrect."
    INVALID_THEME: Final[str] = "Valeur attendue : « light », « dark » ou « system »."
    USER_NOT_FOUND: Final[str] = "Utilisateur introuvable."
    RATE_LIMITED_PASSWORD: Final[str] = (
        f"Trop de changements de mot de passe "
        f"(limite : {_PASSWORD_RATE_MAX} par "
        f"{_PASSWORD_RATE_WINDOW_S // 60} minutes). Patientez avant de réessayer."
    )
    RATE_LIMITED_PROFILE: Final[str] = (
        f"Trop de mises à jour du profil "
        f"(limite : {_PROFILE_RATE_MAX} par heure). "
        f"Patientez avant de réessayer."
    )
    RATE_LIMITED_PROFILE_EMAIL: Final[str] = (
        f"Trop de changements d'adresse email "
        f"(limite : {_PROFILE_EMAIL_RATE_MAX} par heure). "
        f"Patientez avant de réessayer."
    )
    RATE_LIMITED_APPEARANCE: Final[str] = (
        f"Trop de changements de thème " f"(limite : {_APPEARANCE_RATE_MAX} par minute)."
    )
    # ``PERSISTENCE_CONFLICT`` : message pour les VRAIS 409 (race
    # UPDATE/INSERT, IntegrityError sur unique constraint, etc.).
    # Ne PAS l'utiliser pour les 5xx — voir ``GENERIC_SERVER_ERROR`` ci-dessous.
    PERSISTENCE_CONFLICT: Final[str] = "Conflit de persistance, réessayez."
    # Bug 2026-05-26 (Agent 1 brainstorm S-6) : avant, le décorateur
    # ``_db_safe`` renvoyait 500 + ``PERSISTENCE_CONFLICT`` — l'user voyait
    # « Conflit » et le confondait avec un 409 (conflict business). Maintenant
    # on émet ce message dédié 5xx, aligné taxonomie 4-cas axe 5(c) :
    # 5xx = erreur serveur, l'user peut « Signaler » via le bouton
    # bug-report.js global (qui envoie un mail à l'« Email support »
    # configuré dans /admin/smtp-config).
    GENERIC_SERVER_ERROR: Final[str] = (
        "Une erreur est survenue côté serveur. Réessayez dans quelques "
        "secondes. Si le problème persiste, utilisez le bouton « Signaler »."
    )
    COMPANY_FORBIDDEN: Final[str] = (
        "Reservé aux administrateurs (ce nom apparaît dans tous les emails et rapports)."
    )
    COMPANY_TOO_LONG: Final[str] = "Nom d'entreprise trop long (limite : 200 caractères)."
    COMPANY_INVALID: Final[str] = "Nom d'entreprise invalide (caractères de contrôle interdits)."
    RATE_LIMITED_COMPANY: Final[str] = (
        "Trop de modifications du nom d'entreprise (limite : 10 par heure)."
    )
    INVALID_IRIS_CONSENT: Final[str] = (
        "Valeur attendue pour le consentement Iris : « ask », « always_allow » "
        "ou « always_show_panel »."
    )
    RATE_LIMITED_IRIS_CONSENT: Final[str] = (
        "Trop de modifications du consentement Iris (limite : 20 par minute)."
    )


# ── Rate limiters partagés ────────────────────────────────────────────────

#: Rate-limiter ``PUT /api/settings/password``.
_password_rate_limiter: Final[RateLimiter] = RateLimiter()

#: Rate-limiter global ``PUT /api/settings/profile`` (20/h depuis S-11).
_profile_rate_limiter: Final[RateLimiter] = RateLimiter()

#: Rate-limiter spécifique aux CHANGEMENTS d'email — appliqué EN PLUS
#: du global quand ``email`` diverge de la valeur BDD. Anti-énumération
#: stricte (3/h). Bug 2026-05-26 (S-11).
_profile_email_rate_limiter: Final[RateLimiter] = RateLimiter()

#: Rate-limiter ``PUT /api/settings/appearance``.
_appearance_rate_limiter: Final[RateLimiter] = RateLimiter()

#: Rate-limiter ``PUT /api/settings/company`` — 10/heure par admin.
#: Modification du nom d'entreprise = action rare (config initiale,
#: rebranding ponctuel). Limite serree pour empecher l'abus.
_company_rate_limiter: Final[RateLimiter] = RateLimiter()

#: Rate-limiter ``PUT /api/settings/iris-consent``. 20/min : la pref peut
#: aussi être togglée depuis le checkbox "ne plus me redemander" en plein
#: flow Iris (via le WS handler ``data_read_consent_response``) — il faut
#: laisser le débit nécessaire à un user qui change d'avis plusieurs fois
#: en rapide succession, sans permettre un script de spam.
_iris_consent_rate_limiter: Final[RateLimiter] = RateLimiter()
_IRIS_CONSENT_RATE_MAX: Final[int] = 20
_IRIS_CONSENT_RATE_WINDOW_S: Final[int] = 60
_COMPANY_RATE_MAX: Final[int] = 10
_COMPANY_RATE_WINDOW_S: Final[int] = 3600
_COMPANY_NAME_MAX_LEN: Final[int] = 200


# ── Helpers purs (testables sans handler) ─────────────────────────────────


def _has_control_chars(value: str) -> bool:
    """Détecte un caractère de contrôle (0x00-0x1F ou 0x7F) dans ``value``.

    Contrairement à l'ancienne implémentation, **aucune exception pour
    ``\\t``** : un nom d'affichage légitime n'inclut jamais de tabulation,
    et l'accepter ouvre la porte à des collisions visuelles (deux users
    « Jean\\tDupont » et « Jean Dupont » rendent pareil dans la plupart
    des UI). Fail-closed : en cas de doute, rejet.
    """
    return any(ord(c) < 32 or ord(c) == 0x7F for c in value)


def _is_valid_email(value: str) -> bool:
    """Valide une adresse e-mail contre la regex locale + longueur RFC 5321.

    Pure : pas de side-effect (DNS lookup, SMTP probe) — la validation
    sémantique complète appartient au service SMTP en aval.
    """
    if not value or len(value) > _EMAIL_MAX_LEN:
        return False
    return bool(_EMAIL_RE.match(value))


def _coerce_str(value: Any) -> str | None:
    """Coerce un body JSON value → ``str`` ou ``None``.

    * ``None`` → ``None`` (absent).
    * ``str`` → tel quel (le caller fait le strip/len).
    * Autre type (dict, list, int, bool) → ``None`` (le caller décide
      si c'est 400 ou skip).

    Distingue « absent » (``None`` retourné) de « présent mais invalide »
    (aussi ``None``) ; les callers qui ont besoin de discriminer doivent
    tester ``key in body`` avant.
    """
    if value is None or isinstance(value, str):
        return value
    return None


def _http_error(handler: BaseHandler, status: int, message: str) -> None:
    """Écrit une réponse d'erreur au shape ``{error, message}`` rétrocompatible
    avec ``static/js/settings.js::errorMessage``.

    Shape identique au contrat historique du fichier : le frontend lit
    ``data.message || data.error``, donc on fournit les deux. ``error`` est
    aussi utilisé comme *error-code* (chaîne stable ASCII pour tests) et
    ``message`` est le libellé FR user-visible.

    Migration future (cf. :file:`findings/EPICS.md` EPIC:LLM-COST-GUARDRAILS
    qui standardise le shape enrichi) : on pourra ajouter ``error_code`` et
    ``request_id`` sans casser settings.js — l'ajout de champs est
    rétrocompatible.
    """
    handler.write_json(
        {"error": message, "message": message},
        status,
    )


def _parse_body_or_error(handler: BaseHandler) -> dict[str, Any] | None:
    """Parse le body JSON ; écrit une 400/413 et retourne ``None`` si invalide.

    Pré-check ``Content-Length`` avant désérialisation : évite de lire
    ``request.body`` en RAM pour un envoi pathologique, et bloque le
    ``json.loads`` synchrone qui freezerait l'event-loop.

    Rejets :

    * Content-Length > :data:`_BODY_MAX_BYTES` → 413
    * Body non-UTF-8 → 400 (``UnicodeDecodeError`` catché explicitement,
      pas via ``except Exception`` trop large)
    * Body JSON invalide → 400
    * Top-level non-dict (array, scalar, null) → 400 (évite
      ``AttributeError`` sur ``body.get(...)``)
    """
    content_length_raw = handler.request.headers.get("Content-Length")
    if content_length_raw:
        try:
            if int(content_length_raw) > _BODY_MAX_BYTES:
                _http_error(handler, 413, _Messages.BODY_TOO_LARGE)
                return None
        except ValueError:
            # Header malformé : on laisse json.loads trancher.
            pass

    # Second filet : body réel (si Content-Length absent ou menti).
    raw = handler.request.body
    if raw and len(raw) > _BODY_MAX_BYTES:
        _http_error(handler, 413, _Messages.BODY_TOO_LARGE)
        return None

    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError, ValueError) as exc:
        logger.info(
            "Body JSON invalide sur /api/settings",
            extra={
                "request_id": getattr(handler, "request_id", "?"),
                "err_class": exc.__class__.__name__,
                "path": handler.request.uri,
            },
        )
        _http_error(handler, 400, _Messages.INVALID_JSON)
        return None

    if not isinstance(parsed, dict):
        _http_error(handler, 400, _Messages.INVALID_PAYLOAD)
        return None

    return parsed


def _rate_limit_key(handler: BaseHandler, prefix: str) -> str:
    """Construit la clef rate-limit.

    ``<prefix>:<user_id>`` si authentifié, ``<prefix>:ip:<remote_ip>``
    sinon. Les handlers de settings étant tous ``@authenticated``, la
    branche IP ne devrait jamais s'exécuter en prod — fallback conservé
    pour les tests et les futures évolutions (endpoint public).
    """
    user = getattr(handler, "current_user", None)
    user_id = getattr(user, "id", None) if user else None
    if user_id is not None:
        return f"{prefix}:{user_id}"
    ip = handler.request.remote_ip or "anonymous"
    return f"{prefix}:ip:{ip}"


def _validate_email_or_error(handler: BaseHandler, raw: Any) -> tuple[str | None, bool]:
    """Valide et normalise un e-mail reçu dans un body JSON.

    Retourne ``(email_normalized_or_None, handler_wrote_error)`` :

    * ``(None, False)`` si l'e-mail est absent (``raw is None``) — le
      caller conserve l'e-mail existant.
    * ``(email, False)`` si valide (déjà ``strip().lower()``).
    * ``(None, True)`` si invalide ; ``handler.write_json`` a déjà écrit
      la 400 appropriée. Le caller doit ``return`` immédiatement.

    Séparé du handler pour être testable sans requête HTTP.
    """
    if raw is None:
        return None, False
    if not isinstance(raw, str):
        _http_error(handler, 400, _Messages.INVALID_EMAIL)
        return None, True
    candidate = raw.strip().lower()
    if len(candidate) > _EMAIL_MAX_LEN:
        _http_error(handler, 400, _Messages.EMAIL_TOO_LONG)
        return None, True
    if not _is_valid_email(candidate):
        _http_error(handler, 400, _Messages.INVALID_EMAIL)
        return None, True
    return candidate, False


def _validate_display_name_or_error(
    handler: BaseHandler, raw: Any
) -> tuple[str | None, bool, bool]:
    """Valide et normalise un ``display_name`` reçu dans un body JSON.

    Retourne ``(cleaned_or_None, should_clear, handler_wrote_error)`` :

    * ``(None, False, False)`` si absent — le caller conserve l'existant.
    * ``("", True, False)`` si l'user a envoyé ``""`` ou whitespace only
      → intention « effacer le display name ».
    * ``(cleaned, False, False)`` si valide.
    * ``(None, False, True)`` si invalide ; 400 déjà écrite.
    """
    if raw is None:
        return None, False, False
    if not isinstance(raw, str):
        _http_error(handler, 400, _Messages.INVALID_DISPLAY_NAME)
        return None, False, True
    cleaned = raw.strip()
    if cleaned == "":
        return "", True, False
    if len(cleaned) > _DISPLAY_NAME_MAX_LEN:
        _http_error(handler, 400, _Messages.DISPLAY_NAME_TOO_LONG)
        return None, False, True
    if _has_control_chars(cleaned):
        _http_error(handler, 400, _Messages.DISPLAY_NAME_CONTROL_CHARS)
        return None, False, True
    return cleaned, False, False


def _validate_password_input(
    handler: BaseHandler, current_pw: Any, new_pw: Any
) -> tuple[str, str] | None:
    """Valide ``current_password`` + ``new_password``.

    Retourne ``(current_pw_str, new_pw_str)`` si tout est bon, sinon
    ``None`` (et une 400 a déjà été écrite).

    Checks couvrant ASVS v5 V6.2 (longueur min/max, non-trivial, différent
    de l'actuel). La vérification bcrypt du ``current_pw`` est faite par
    le handler (nécessite un accès DB).
    """
    if not isinstance(current_pw, str) or not isinstance(new_pw, str):
        _http_error(handler, 400, _Messages.PASSWORD_BOTH_REQUIRED)
        return None
    if len(new_pw) < _PASSWORD_MIN_LEN:
        _http_error(handler, 400, _Messages.PASSWORD_TOO_SHORT)
        return None
    if len(new_pw) > _PASSWORD_MAX_LEN:
        _http_error(handler, 400, _Messages.PASSWORD_TOO_LONG)
        return None
    # Borne de correction bcrypt (octets, pas caractères) : au-delà de 72 o, les
    # octets sont ignorés par l'algo — on rejette plutôt que de tronquer en
    # silence (cf. app.core.constants_auth.PASSWORD_MAX_BYTES, SSoT).
    if password_exceeds_bcrypt_limit(new_pw):
        _http_error(handler, 400, _Messages.PASSWORD_TOO_MANY_BYTES)
        return None
    if new_pw.casefold() in _TRIVIAL_PASSWORDS:
        _http_error(handler, 400, _Messages.PASSWORD_TOO_TRIVIAL)
        return None
    if current_pw == new_pw:
        _http_error(handler, 400, _Messages.PASSWORD_SAME_AS_OLD)
        return None
    return current_pw, new_pw


def _serialize_profile(user: User, display_name: str) -> dict[str, Any]:
    """Structure stable de la réponse profil — shared GET + PUT.

    ``display_name`` est toujours une ``str`` (pas ``None``) pour coller à
    ``settings.js::fillProfile`` qui fait ``el.value = val || ''``. Un
    ``None`` serait rendu « null » par JSON.stringify si consommé ailleurs.
    """
    # ``ensure_utc(...)`` garantit un suffixe ``+00:00`` dans l'ISO. Sans
    # ça, JS ``new Date(iso)`` interpréterait la chaîne comme heure locale
    # (le datetime SQLite est stocké naïf via ``DateTime``), ce qui
    # affichait des heures décalées d'un fuseau côté front (cf. bug
    # « DERNIÈRE CONNEXION » sur /admin/users).
    created_at_utc = ensure_utc(user.created_at)
    last_login_utc = ensure_utc(user.last_login)
    return {
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "display_name": display_name,
        "created_at": created_at_utc.isoformat() if created_at_utc else None,
        "last_login": last_login_utc.isoformat() if last_login_utc else None,
    }


# ── Accès ``user_preferences`` (SQLAlchemy async) ─────────────────────────


async def _get_pref(session: AsyncSession, user_id: int, key: str) -> UserPreference | None:
    """Charge une préférence donnée ; ``None`` si absente."""
    result = await session.execute(
        select(UserPreference).where(
            UserPreference.user_id == user_id,
            UserPreference.key == key,
        )
    )
    return result.scalar_one_or_none()


async def _upsert_pref(
    session: AsyncSession,
    user_id: int,
    key: str,
    value: str,
    category: str = "preference",
) -> None:
    """Crée ou met à jour une préférence.

    Race condition : deux writers parallèles peuvent tous deux voir
    ``None`` au SELECT puis faire deux INSERT — la contrainte
    ``uq_user_preference_key`` bloque le second. On capte
    :class:`IntegrityError` et on retente UNE fois (la seconde passe
    verra le premier INSERT et ira sur la branche UPDATE). Au-delà :
    on propage — il y a probablement un vrai problème de schéma.
    """
    for attempt in (0, 1):
        pref = await _get_pref(session, user_id, key)
        if pref is None:
            session.add(UserPreference(user_id=user_id, key=key, value=value, category=category))
        else:
            pref.value = value
            pref.category = category
        try:
            await session.flush()
            return
        except IntegrityError:
            if attempt == 1:
                raise
            await session.rollback()


async def _delete_pref(session: AsyncSession, user_id: int, key: str) -> None:
    """Supprime une préférence si elle existe — idempotent (pas de 404 si
    absente, la requête ``DELETE`` n'a simplement rien à faire).
    """
    await session.execute(
        delete(UserPreference).where(
            UserPreference.user_id == user_id,
            UserPreference.key == key,
        )
    )


async def _load_user_or_404(session: AsyncSession, user_id: int) -> User | None:
    """Recharge un :class:`User` dans la session courante — garantit un
    attribut frais (pas de détachement ORM après ``expire_on_commit``).
    """
    result = await session.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


# ── Helper rate-limit (pas d'effet de bord au-dessus du handler) ──────────


def _check_rate_limit(
    handler: BaseHandler,
    limiter: RateLimiter,
    prefix: str,
    max_requests: int,
    window_s: int,
    message: str,
) -> bool:
    """Vérifie le rate-limit ; écrit 429 si dépassé. Retourne ``True`` si OK.

    Log ``info`` en cas de dépassement : utile pour corréler un abus (mais
    pas ``warning`` — un user normal peut occasionnellement taper du mur,
    ce n'est pas en soi un incident sécurité sauf répétition).
    """
    key = _rate_limit_key(handler, prefix)
    if not limiter.check(key, max_requests, window_s):
        logger.info(
            "Rate-limit dépassé sur /api/settings",
            extra={
                "request_id": getattr(handler, "request_id", "?"),
                "user_id": getattr(handler.current_user, "id", None),
                "prefix": prefix,
                "limit": max_requests,
                "window_s": window_s,
            },
        )
        _http_error(handler, 429, message)
        return False
    return True


# ── Décorateur : wraps une coroutine handler + catch DB propre ────────────


_HandlerMethod = Callable[..., Awaitable[Any]]


def _db_safe(method: _HandlerMethod) -> _HandlerMethod:
    """Décore une méthode de handler settings : transforme
    :class:`SQLAlchemyError` en 500 déterministe avec log structuré.

    Le message client ne fuite pas ``str(exc)`` — le watchdog de base.py
    (écoutant ``write_error``) agrège les 5xx par fichier. Chaque handler
    reste concis (le try/except DB est factorisé).
    """

    @functools.wraps(method)
    async def wrapper(self: BaseHandler, *args: Any, **kwargs: Any) -> Any:
        try:
            return await method(self, *args, **kwargs)
        except SQLAlchemyError:
            logger.exception(
                "SQLAlchemyError dans un handler settings",
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "user_id": getattr(self.current_user, "id", None),
                    "path": self.request.uri,
                },
            )
            # Bug 2026-05-26 (S-6) : message dédié 5xx — différent du
            # vrai 409 ``PERSISTENCE_CONFLICT``. L'user voit explicitement
            # « erreur serveur » + indication « Signaler ».
            _http_error(self, 500, _Messages.GENERIC_SERVER_ERROR)
            return None

    return wrapper


# ── Page HTML ─────────────────────────────────────────────────────────────


class SettingsPageHandler(BaseHandler):
    """``GET /settings`` — rend la page Paramètres.

    Pas d'auto-chargement des données côté serveur : la page s'hydrate
    via ``fetch('/api/settings/profile')`` et ``/appearance`` au DOM
    ready (``static/js/settings.js::init``). Avantages : séparation
    claire render/API, page publique rapide à rendre même si la DB est
    lente (le spinner tourne dans l'UI pendant l'hydratation).
    """

    @authenticated
    async def get(self) -> None:
        # Expose la SSoT branding au template pour que le placeholder du
        # champ "Mon entreprise" soit aligné sur ``PLACEHOLDER_COMPANY_NAME``
        # (cf. ``app/services/branding.py``). Avant 2026-05-26 (Bug S-12),
        # le template hardcodait ``"Ex: Cabinet Dupont"`` — nom propre
        # fictif divergent + violation de ``feedback_no_real_names_in_code``.
        # Idem dans le JS via ``res.data.placeholder`` (cf. S-1) : les deux
        # convergent maintenant sur la même constante.
        from app.services.branding import PLACEHOLDER_COMPANY_NAME

        # Section « Aide » : guides PDF visibles par CET utilisateur. Le filtrage
        # rôle + existence-disque est fait côté serveur (SSoT help_docs) — le
        # template ne fait que rendre la liste reçue. La vraie frontière de
        # sécurité reste l'endpoint /help/guides/<key> (re-check du rôle).
        help_guides = available_guides_for_user(self.current_user)

        self.render(
            "settings.html",
            page_title="Paramètres",
            company_placeholder=PLACEHOLDER_COMPANY_NAME,
            help_guides=help_guides,
        )


# ── API : Profil ──────────────────────────────────────────────────────────


class SettingsProfileAPIHandler(BaseHandler):
    """``GET/PUT /api/settings/profile`` — nom d'affichage + e-mail.

    Champs modifiables :

    * ``display_name`` (optionnel, vide → effacé) ;
    * ``email`` (RFC 5321 valide, unique en base).

    ``username`` et ``role`` ne sont PAS modifiables via cet endpoint —
    leur changement relève d'un flux admin. ``last_login`` est en
    lecture seule, tenu à jour par le login handler.
    """

    @authenticated
    @_db_safe
    async def get(self) -> None:
        user = self.current_user
        assert user is not None  # @authenticated garantit
        async with get_session() as session:
            db_user = await _load_user_or_404(session, user.id) or user
            pref = await _get_pref(session, db_user.id, PREF_DISPLAY_NAME)
            display_name = pref.value if pref else ""
        self.write_json(_serialize_profile(db_user, display_name))

    @authenticated
    @_db_safe
    async def put(self) -> None:
        user = self.current_user
        assert user is not None

        if not _check_rate_limit(
            self,
            _profile_rate_limiter,
            "settings_profile",
            _PROFILE_RATE_MAX,
            _PROFILE_RATE_WINDOW_S,
            _Messages.RATE_LIMITED_PROFILE,
        ):
            return

        body = _parse_body_or_error(self)
        if body is None:
            return

        email_to_set, emitted = _validate_email_or_error(self, body.get("email"))
        if emitted:
            return

        display_to_set, clear_display, emitted = _validate_display_name_or_error(
            self, body.get("display_name")
        )
        if emitted:
            return

        async with get_session() as session:
            db_user = await _load_user_or_404(session, user.id)
            if db_user is None:
                _http_error(self, 404, _Messages.USER_NOT_FOUND)
                return

            if email_to_set is not None and email_to_set != db_user.email:
                # Bug 2026-05-26 (S-11) : check rate-limit SUPPLÉMENTAIRE pour
                # les changements d'email seuls — anti-énumération stricte
                # (3/h). Le rate-limit global (20/h ligne 798) couvre déjà
                # display_name + autres ; ici on protège uniquement le bucket
                # email qui révèle 409 EMAIL_TAKEN sur scraping.
                if not _check_rate_limit(
                    self,
                    _profile_email_rate_limiter,
                    "settings_profile_email",
                    _PROFILE_EMAIL_RATE_MAX,
                    _PROFILE_EMAIL_RATE_WINDOW_S,
                    _Messages.RATE_LIMITED_PROFILE_EMAIL,
                ):
                    return
                # Check pré-flight (UX : message clair) + filet via
                # IntegrityError sur commit (race TOCTOU).
                existing = await session.execute(
                    select(User).where(
                        User.email == email_to_set,
                        User.id != db_user.id,
                    )
                )
                if existing.scalar_one_or_none() is not None:
                    _http_error(self, 409, _Messages.EMAIL_TAKEN)
                    return
                db_user.email = email_to_set

            if clear_display:
                await _delete_pref(session, db_user.id, PREF_DISPLAY_NAME)
            elif display_to_set is not None:
                await _upsert_pref(session, db_user.id, PREF_DISPLAY_NAME, display_to_set)

            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                _http_error(self, 409, _Messages.EMAIL_TAKEN)
                return

            # Recharge le display_name APRÈS commit pour refléter l'état
            # réel (évite la rustine « if not modifié, re-read » qui
            # obscurcissait l'intention dans l'ancienne version).
            pref_after = await _get_pref(session, db_user.id, PREF_DISPLAY_NAME)
            display_name = pref_after.value if pref_after else ""

            # Capture les attributs avant la sortie du context manager :
            # ``db_user`` sera détaché après fermeture (expire_on_commit).
            payload = _serialize_profile(db_user, display_name)

        logger.info(
            "Profil mis à jour",
            extra={
                "request_id": getattr(self, "request_id", "?"),
                "user_id": user.id,
                "email_changed": email_to_set is not None,
                "display_changed": display_to_set is not None or clear_display,
            },
        )

        self.write_json(payload)


# ── API : Mot de passe ────────────────────────────────────────────────────


class SettingsPasswordAPIHandler(BaseHandler):
    """``PUT /api/settings/password`` — changement de mot de passe.

    Flux :

    1. Rate-limit :data:`_PASSWORD_RATE_MAX` / :data:`_PASSWORD_RATE_WINDOW_S`.
    2. Validation body (longueur, trivial, différent).
    3. Bcrypt ``verify_password`` du mot de passe actuel (constant-time).
    4. Bcrypt ``hash_password`` du nouveau + commit.
    5. Invalidation des autres sessions du user (``keep_token`` =
       cookie courant, re-vérifié par :meth:`SessionManager.
       destroy_sessions_except`).

    En cas d'échec de l'étape 5, on loggue ``error`` mais on **retourne
    succès** : le password est changé, c'est l'objectif principal.
    Laisser le rollback partiel de la révocation serait pire UX.
    """

    @authenticated
    @_db_safe
    async def put(self) -> None:
        user = self.current_user
        assert user is not None

        if not _check_rate_limit(
            self,
            _password_rate_limiter,
            "settings_password",
            _PASSWORD_RATE_MAX,
            _PASSWORD_RATE_WINDOW_S,
            _Messages.RATE_LIMITED_PASSWORD,
        ):
            return

        body = _parse_body_or_error(self)
        if body is None:
            return

        validated = _validate_password_input(
            self, body.get("current_password"), body.get("new_password")
        )
        if validated is None:
            return
        current_pw, new_pw = validated

        hasher = get_password_hasher()

        async with get_session() as session:
            db_user = await _load_user_or_404(session, user.id)
            if db_user is None:
                _http_error(self, 404, _Messages.USER_NOT_FOUND)
                return

            if not hasher.verify_password(current_pw, db_user.password_hash):
                logger.warning(
                    "Échec de vérification du mot de passe actuel",
                    extra={
                        "request_id": getattr(self, "request_id", "?"),
                        "user_id": db_user.id,
                        "ip": self.request.remote_ip,
                    },
                )
                _http_error(self, 400, _Messages.PASSWORD_CURRENT_WRONG)
                return

            db_user.password_hash = hasher.hash_password(new_pw)
            await session.commit()

        # --- Révocation best-effort des autres sessions ----------------
        current_token = self._read_current_session_token()
        revoked = 0
        if current_token:
            try:
                revoked = await get_session_manager().destroy_sessions_except(
                    user.id, keep_token=current_token
                )
            except SQLAlchemyError:
                # Non-bloquant : le password est changé. Les anciens tokens
                # expireront via session_timeout_hours. On loggue pour
                # qu'un ops voie le problème dans les métriques.
                logger.exception(
                    "Échec de la révocation des autres sessions après changement mdp",
                    extra={
                        "request_id": getattr(self, "request_id", "?"),
                        "user_id": user.id,
                    },
                )
        else:
            logger.warning(
                "Changement mdp sans token session identifiable — "
                "révocation des autres sessions ignorée",
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "user_id": user.id,
                },
            )

        logger.info(
            "Mot de passe changé",
            extra={
                "request_id": getattr(self, "request_id", "?"),
                "user_id": user.id,
                "sessions_revoked": revoked,
            },
        )

        self.write_json({"success": True, "sessions_revoked": revoked})

    def _read_current_session_token(self) -> str | None:
        """Lit le cookie signé courant en ``str`` ou ``None``.

        Fail-closed : si le cookie est absent, corrompu ou non-UTF-8,
        la révocation des autres sessions est skippée pour ne pas
        déconnecter l'utilisateur courant sans le vouloir. Le
        :meth:`destroy_sessions_except` re-vérifie de toute façon
        l'ownership du ``keep_token``.
        """
        token_bytes = self.get_secure_cookie(SESSION_COOKIE_NAME)
        if not token_bytes:
            return None
        try:
            return token_bytes.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            logger.warning(
                "Cookie session courant corrompu — révocation skippée",
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "user_id": getattr(self.current_user, "id", None),
                },
            )
            return None


# ── API : Apparence ───────────────────────────────────────────────────────


class SettingsAppearanceAPIHandler(BaseHandler):
    """``GET/PUT /api/settings/appearance`` — mode de couleur UI.

    Valeurs admises : ``light``, ``dark``, ``system``. La validation est
    stricte (``theme not in`` :data:`_THEME_MODE_VALUES` → 400).
    """

    @authenticated
    @_db_safe
    async def get(self) -> None:
        user = self.current_user
        assert user is not None
        async with get_session() as session:
            pref = await _get_pref(session, user.id, PREF_THEME_MODE)
            theme = pref.value if pref else _DEFAULT_THEME_MODE
            if theme not in _THEME_MODE_VALUES:
                # Valeur corrompue en DB (migration manuelle, édition
                # externe) → on force le défaut pour éviter qu'une UI
                # casse sur une valeur inconnue.
                theme = _DEFAULT_THEME_MODE
        self.write_json({"theme_mode": theme})

    @authenticated
    @_db_safe
    async def put(self) -> None:
        user = self.current_user
        assert user is not None

        if not _check_rate_limit(
            self,
            _appearance_rate_limiter,
            "settings_appearance",
            _APPEARANCE_RATE_MAX,
            _APPEARANCE_RATE_WINDOW_S,
            _Messages.RATE_LIMITED_APPEARANCE,
        ):
            return

        body = _parse_body_or_error(self)
        if body is None:
            return

        theme = body.get("theme_mode")
        if not isinstance(theme, str) or theme not in _THEME_MODE_VALUES:
            _http_error(self, 400, _Messages.INVALID_THEME)
            return

        async with get_session() as session:
            try:
                await _upsert_pref(session, user.id, PREF_THEME_MODE, theme)
                await session.commit()
            except IntegrityError:
                await session.rollback()
                _http_error(self, 409, _Messages.PERSISTENCE_CONFLICT)
                return

        self.write_json({"theme_mode": theme})


class SettingsCompanyAPIHandler(BaseHandler):
    """``GET/PUT /api/settings/company`` — nom d'entreprise global.

    Le ``company_name`` est stocke dans ``smtp_global_config`` (table
    globale unique) et apparaît dans :
    - les rapports PDF (pied de page)
    - les emails sortants (expediteur ``<user> via <company>``)

    **Reserve aux administrateurs** : la modification s'applique a toute
    l'instance Komptia, donc seul un admin peut la changer. Tout autre
    role recoit 403 sur GET et PUT (anti-oracle : un user normal n'a
    meme pas a connaître le nom de l'entreprise via l'API — ce nom est
    deja visible dans les emails qu'il recoit).
    """

    def _ensure_admin(self) -> bool:
        # Bug 2026-05-26 (Agent 1 brainstorm S-9) : SSoT via
        # ``base.is_admin(user)`` — partage le pattern canonical avec le
        # décorateur ``admin_required``. Évite la divergence sémantique
        # entre la comparaison ad-hoc ``str().lower()`` historique et
        # le check enum direct utilisé partout ailleurs.
        from app.handlers.base import is_admin

        if not is_admin(self.current_user):
            _http_error(self, 403, _Messages.COMPANY_FORBIDDEN)
            return False
        return True

    @authenticated
    @_db_safe
    async def get(self) -> None:
        if not self._ensure_admin():
            return
        from app.models.smtp_global_config import SMTPGlobalConfig
        from app.services.branding import PLACEHOLDER_COMPANY_NAME

        async with get_session() as session:
            row = (await session.execute(select(SMTPGlobalConfig).limit(1))).scalar_one_or_none()
            current = (row.company_name if row else None) or ""
        self.write_json(
            {
                "company_name": current,
                "placeholder": PLACEHOLDER_COMPANY_NAME,
            }
        )

    @authenticated
    @_db_safe
    async def put(self) -> None:
        if not self._ensure_admin():
            return
        if not _check_rate_limit(
            self,
            _company_rate_limiter,
            "settings_company",
            _COMPANY_RATE_MAX,
            _COMPANY_RATE_WINDOW_S,
            _Messages.RATE_LIMITED_COMPANY,
        ):
            return

        body = _parse_body_or_error(self)
        if body is None:
            return

        raw = body.get("company_name", "")
        if not isinstance(raw, str):
            _http_error(self, 400, _Messages.COMPANY_INVALID)
            return
        value = raw.strip()
        if len(value) > _COMPANY_NAME_MAX_LEN:
            _http_error(self, 400, _Messages.COMPANY_TOO_LONG)
            return
        if value and _has_control_chars(value):
            _http_error(self, 400, _Messages.COMPANY_INVALID)
            return
        # Vide autorise → revient au placeholder branding (cf. branding.py).
        # On stocke NULL plutot qu'une chaine vide pour rester coherent
        # avec la colonne (Optional[str]).
        store_value = value or None

        from app.models.smtp_global_config import SMTPGlobalConfig
        from app.services.branding import (
            PLACEHOLDER_COMPANY_NAME,
            invalidate_company_name_cache,
        )

        async with get_session() as session:
            row = (await session.execute(select(SMTPGlobalConfig).limit(1))).scalar_one_or_none()
            if row is None:
                # Pas de config SMTP encore : on cree une row minimale
                # juste pour porter le company_name (les autres champs
                # SMTP restent NULL → SMTP indisponible jusqu'à config
                # via /admin/smtp, mais le branding rapport/PDF marche).
                row = SMTPGlobalConfig(company_name=store_value)
                session.add(row)
            else:
                row.company_name = store_value
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                _http_error(self, 409, _Messages.PERSISTENCE_CONFLICT)
                return

        # Propage l'update aux call-sites (sinon TTL 60s du cache).
        invalidate_company_name_cache()

        self.write_json(
            {
                "company_name": value,
                "placeholder": PLACEHOLDER_COMPANY_NAME,
            }
        )


# ── API : Consentement lecture données Iris ──────────────────────────────


class SettingsIrisConsentAPIHandler(BaseHandler):
    """``GET/PUT /api/settings/iris-consent`` — préférence utilisateur sur
    la lecture des résultats SQL par Iris (free-loop agent + pipeline).

    Avant qu'Iris n'envoie les résultats d'une requête SQL exécutée au LLM
    cloud pour analyse, le runtime consulte cette préférence pour décider
    du flow utilisateur. Le détail des 3 valeurs admises est documenté
    sur :data:`PREF_IRIS_DATA_READ_CONSENT`.

    L'endpoint est consommé par 2 callers :

    1. La section « Confidentialité Iris » de la page ``/settings`` (UI
       déclarative — l'utilisateur choisit sa pref une fois).
    2. Le WS handler ``data_read_consent_response`` (cf. ``handlers/iris.py``)
       quand l'utilisateur coche « ne plus me redemander » dans le modal
       inline en plein flow Iris — bascule alors automatiquement la pref
       en ``always_allow`` ou ``always_show_panel`` selon la réponse.
    """

    @authenticated
    @_db_safe
    async def get(self) -> None:
        user = self.current_user
        assert user is not None
        async with get_session() as session:
            pref = await _get_pref(session, user.id, PREF_IRIS_DATA_READ_CONSENT)
            value = pref.value if pref else _DEFAULT_IRIS_CONSENT
            if value not in _IRIS_CONSENT_VALUES:
                # Valeur corrompue (migration manuelle, édition externe)
                # → on force le défaut pour ne pas bloquer Iris sur une
                # pref invalide.
                value = _DEFAULT_IRIS_CONSENT
        self.write_json({"iris_data_read_consent": value})

    @authenticated
    @_db_safe
    async def put(self) -> None:
        user = self.current_user
        assert user is not None

        if not _check_rate_limit(
            self,
            _iris_consent_rate_limiter,
            "settings_iris_consent",
            _IRIS_CONSENT_RATE_MAX,
            _IRIS_CONSENT_RATE_WINDOW_S,
            _Messages.RATE_LIMITED_IRIS_CONSENT,
        ):
            return

        body = _parse_body_or_error(self)
        if body is None:
            return

        value = body.get("iris_data_read_consent")
        if not isinstance(value, str) or value not in _IRIS_CONSENT_VALUES:
            _http_error(self, 400, _Messages.INVALID_IRIS_CONSENT)
            return

        async with get_session() as session:
            try:
                await _upsert_pref(session, user.id, PREF_IRIS_DATA_READ_CONSENT, value)
                await session.commit()
            except IntegrityError:
                await session.rollback()
                _http_error(self, 409, _Messages.PERSISTENCE_CONFLICT)
                return

        self.write_json({"iris_data_read_consent": value})


class SettingsBootstrapAPIHandler(BaseHandler):
    """``GET /api/settings/bootstrap`` — agrégateur lecture-only du boot /settings.

    Bug 2026-05-26 (Agent 1 brainstorm S-14 MOYEN) : la page ``/settings``
    déclenche plusieurs ``fetch`` séquentiels au boot (``profile``, ``appearance``,
    ``company``, ``iris-consent``, ``user-memory``). N RTT + N sessions BDD =
    200ms+ visible en 3G/WiFi instable. Cet endpoint les concatène en 1 RTT + 1
    session. ``user_memory`` est gratuit (colonne ``User.iris_memory`` déjà chargée).

    Politique de sécurité :
    - Auth : ``@authenticated``. Les 4 endpoints individuels restent
      disponibles (rétrocompat + UI les re-fetch en PUT response).
    - ``company`` UNIQUEMENT pour les admins (aligne ``SettingsCompanyAPI``).
      Pour les non-admins, la clé est ``None``.
    - Tolérance aux erreurs : un sous-fetch qui plante (ex: pref BDD
      corrompue) renvoie sa valeur par défaut plutôt que de faire 500.
    """

    @authenticated
    @_db_safe
    async def get(self) -> None:
        user = self.current_user
        assert user is not None  # @authenticated garantit

        from app.handlers.base import is_admin

        user_is_admin = is_admin(user)

        async with get_session() as session:
            db_user = await _load_user_or_404(session, user.id) or user
            try:
                pref_display = await _get_pref(session, db_user.id, PREF_DISPLAY_NAME)
                display_name = pref_display.value if pref_display else ""
            except Exception:
                display_name = ""

            # Sur EXCEPTION de lecture (≠ pref absente), le bloc vaut ``None`` : le
            # front distingue ainsi « pref par défaut » de « lecture échouée » et
            # bascule sur son fallback individuel (qui a sa propre logique :
            # localStorage scopé pour le thème, taxonomie d'erreur, etc.). Servir
            # un défaut silencieux écraserait le vrai choix (= données fausses).
            appearance_block = None
            try:
                pref_theme = await _get_pref(session, user.id, PREF_THEME_MODE)
                theme = pref_theme.value if pref_theme else _DEFAULT_THEME_MODE
                if theme not in _THEME_MODE_VALUES:
                    theme = _DEFAULT_THEME_MODE
                appearance_block = {"theme_mode": theme}
            except Exception:
                appearance_block = None

            iris_consent_block = None
            try:
                pref_iris = await _get_pref(session, user.id, PREF_IRIS_DATA_READ_CONSENT)
                iris_value = pref_iris.value if pref_iris else _DEFAULT_IRIS_CONSENT
                if iris_value not in _IRIS_CONSENT_VALUES:
                    iris_value = _DEFAULT_IRIS_CONSENT
                iris_consent_block = {"iris_data_read_consent": iris_value}
            except Exception:
                iris_consent_block = None

            company_block = None
            if user_is_admin:
                try:
                    from app.models.smtp_global_config import SMTPGlobalConfig
                    from app.services.branding import PLACEHOLDER_COMPANY_NAME

                    row = (
                        await session.execute(select(SMTPGlobalConfig).limit(1))
                    ).scalar_one_or_none()
                    current = (row.company_name if row else None) or ""
                    company_block = {
                        "company_name": current,
                        "placeholder": PLACEHOLDER_COMPANY_NAME,
                    }
                except Exception:
                    company_block = None

            # user_memory : GRATUIT — ``db_user.iris_memory`` est une colonne déjà
            # chargée (0 requête en plus). Sur exception → ``None`` (PAS un défaut
            # ``max_chars:0`` qui bloquerait le textarea à maxLength=0 côté front)
            # → le front bascule sur son fallback ``/api/iris/user-memory``.
            user_memory_block = None
            try:
                from app.services.ai.iris_user_memory import IRIS_USER_MEMORY_MAX_CHARS

                _mem = db_user.iris_memory or ""
                user_memory_block = {
                    "memory": _mem,
                    "char_count": len(_mem),
                    "max_chars": IRIS_USER_MEMORY_MAX_CHARS,
                }
            except Exception:
                user_memory_block = None

        self.write_json(
            {
                "success": True,
                "profile": _serialize_profile(db_user, display_name),
                "appearance": appearance_block,
                "iris_consent": iris_consent_block,
                "company": company_block,
                "user_memory": user_memory_block,
            }
        )
