"""
Middleware de sécurité HTTP — Tornado.

Doctrine senior (numérotée, traçable aux standards).

1. Anti-XSS moderne — CSP v3 avec nonce aléatoire par requête (W3C CSP3).
   'unsafe-inline' interdit sur script-src (nonce obligatoire). 'unsafe-inline'
   toléré sur style-src uniquement, justifié par Tailwind (build local) + 19
   styles inline dans les templates + 10 blocks <style>. Retirer 'unsafe-inline'
   sur style-src exige un refactor des templates (hors scope middleware).
   Refs: OWASP ASVS v5 V14.4, W3C CSP3, CWE-79.

2. Anti-clickjacking — X-Frame-Options: DENY + frame-ancestors 'none' en
   défense en profondeur (frame-ancestors ignoré par les vieux navigateurs,
   X-Frame-Options ignoré par les modernes). Refs: OWASP ASVS v5 V14.4.7,
   CWE-1021.

3. Anti-MIME-sniffing — X-Content-Type-Options: nosniff. Empêche le
   navigateur d'interpréter un fichier .txt en HTML/JS. Refs: OWASP ASVS v5
   V14.4.8, CWE-434.

4. HSTS preload 2 ans — max-age=63072000 (recommandation hstspreload.org),
   includeSubDomains, preload. Activé UNIQUEMENT sur requêtes HTTPS
   (RFC 6797 §7.2 : HSTS header sur HTTP DOIT être ignoré — on n'émet pas
   pour éviter pollution logs). Refs: RFC 6797, CWE-319.

5. X-XSS-Protection = 0 — OWASP Secure Headers 2025 : le header est
   déprécié. Chrome XSSAuditor historique a CRÉÉ des XSS. On envoie
   explicitement "0" pour écraser tout default navigateur potentiellement
   dangereux. CSP remplace cette protection. Refs: OWASP Secure Headers
   Project 2025, MDN X-XSS-Protection.

6. Referrer-Policy strict — strict-origin-when-cross-origin. Leak contrôlé :
   cross-origin → uniquement l'origine (pas le path), same-origin → URL
   complète. Refs: OWASP ASVS v5 V14.4, W3C Referrer Policy.

7. Permissions-Policy fail-closed — désactive geolocation/micro/camera/
   paiement/USB/capteurs. L'application n'utilise aucune de ces API donc
   fail-closed par défaut. Refs: W3C Permissions Policy, OWASP Secure
   Headers Project.

8. Cross-Origin isolation (Spectre) — COOP: same-origin isole la window
   group (bloque window.opener cross-origin). CORP: same-origin empêche
   embed cross-origin des ressources (anti-XSLeak). Refs: MDN COOP/CORP,
   OWASP 2025.

9. Cache-Control sensible — routes /api/* et /admin* → no-store sans cache
   ni revalidation (anti-fuite disque/proxy). Pragma: no-cache pour compat
   HTTP/1.0. Refs: OWASP ASVS v5 V14.2, CWE-525.

10. Open-redirect safe (is_safe_redirect_url) — fail-closed. Rejette :
    (a) URL vide, None, ou non-str ;
    (b) caractères de contrôle ASCII raw (\\t \\n \\r \\x00..\\x1f \\x7f) et
        URL-encodés (%09 %0a %0d %00) — CRLF injection, header injection ;
    (c) backslash \\ — WHATWG URL §4.4.1 : \\ est normalisé en / pour URLs
        "special" (http/https), donc "/\\evil.com" devient "//evil.com" dans
        le navigateur → bypass protocol-relative ;
    (d) Unicode spoofing (NBSP, zero-width, LSEP/PSEP, BOM) — plusieurs
        navigateurs strippent ces caractères avant normalisation URL ;
    (e) schémas dangereux : http/https/protocol-relative/javascript/data/
        vbscript/file/ftp/about ;
    (f) chemins relatifs (../admin, dashboard sans /) ;
    (g) .. dans le path — path traversal frontal ;
    (h) double validation raw + decoded (anti-bypass URL-encoding) ;
    (i) défense en profondeur : urlsplit + posixpath.normpath.
    Refs: OWASP ASVS v5 V5.1.5, CWE-601, CWE-20, WHATWG URL spec.

Références globales :
- OWASP Top 10 2021 A05 (Security Misconfiguration) / A01 (Access Control)
- OWASP ASVS v5 (V14 Configuration, V5 Validation)
- OWASP Secure Headers Project 2025
- OWASP API Security Top 10 2023
- W3C CSP Level 3, Permissions Policy, Referrer Policy
- CWE-79, CWE-601, CWE-319, CWE-1021, CWE-434, CWE-525, CWE-20
"""

from __future__ import annotations

import posixpath
import re
import secrets
from typing import Final
from urllib.parse import unquote, urlsplit

from tornado.web import RequestHandler

from app.utils.logger import get_logger

__all__ = ("SecurityHeadersMiddleware", "is_safe_redirect_url")

logger = get_logger(__name__)


# ----- CSP / Nonce -----
# 16 octets = 128 bits d'entropie. W3C CSP3 §6.6.4 recommande ≥ 128 bits
# pour empêcher brute-force du nonce par l'attaquant.
_CSP_NONCE_BYTES: Final[int] = 16

# Sources tierces EFFECTIVEMENT utilisées (vérifié dans templates/).
# cdn.tailwindcss.com retiré car Tailwind est build localement
# (/static/css/tailwind.min.css, make css). cdn.plot.ly ET cdn.jsdelivr.net
# retirés : Plotly / Chart.js / Bootstrap-icons sont désormais servis en LOCAL
# depuis /static/vendor/* (vérifié — aucun template ne charge de script tiers).
# Laisser un CDN non utilisé élargit la surface d'attaque pour rien → tuple vide.
_SCRIPT_TRUSTED_SOURCES: Final[tuple[str, ...]] = ()
_STYLE_TRUSTED_SOURCES: Final[tuple[str, ...]] = ("https://fonts.googleapis.com",)
_FONT_TRUSTED_SOURCES: Final[tuple[str, ...]] = ("https://fonts.gstatic.com",)


# ----- HSTS -----
# 2 ans en secondes. Minimum recommandé par hstspreload.org pour inscription
# sur la liste preload des navigateurs (Chrome/Firefox/Safari). Réduire en
# dessous de 1 an (31_536_000) sans retrait préalable de la liste preload
# rendrait le site inaccessible en cas de problème TLS.
_HSTS_MAX_AGE_SECONDS: Final[int] = 63_072_000


# ----- X-XSS-Protection -----
# OWASP Secure Headers Project 2025 : "0" (désactivé).
# Chrome XSSAuditor historique a introduit des XSS (reflected via auditor).
# La valeur "1; mode=block" est dépréciée et non supportée par Firefox/
# Safari moderne. CSP (règle 1) est le remplacement standard.
_X_XSS_PROTECTION_VALUE: Final[str] = "0"


# ----- Cross-Origin isolation (Spectre mitigations) -----
_COOP_VALUE: Final[str] = "same-origin"
_CORP_VALUE: Final[str] = "same-origin"


# ----- Cache-Control sensible -----
# Préfixes de routes qui ne doivent JAMAIS être mis en cache (disque, proxy).
_SENSITIVE_PATH_PREFIXES: Final[tuple[str, ...]] = ("/api/", "/admin")
_CACHE_CONTROL_NO_STORE: Final[str] = "no-store, no-cache, must-revalidate, private"


# ----- Redirect safety -----
# Schémas dangereux — s'ajoutent au rejet des URLs absolues (http/https) et
# protocol-relative (//). Lower-case uniquement (comparaison case-insensitive).
_DANGEROUS_SCHEMES: Final[tuple[str, ...]] = (
    "javascript",
    "data",
    "vbscript",
    "file",
    "ftp",
    "about",
    "blob",
)

# Caractères de contrôle ASCII (\\x00-\\x1f \\x7f) + backslash.
# - Control chars : CRLF injection (split request), header injection (\\r\\n)
# - Backslash : WHATWG URL §4.4.1 normalise "\\" → "/" pour URLs "special"
#   donc "/\\evil.com" devient "//evil.com" dans le navigateur (bypass
#   protocol-relative) → REJET obligatoire.
_CONTROL_CHARS_PATTERN: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f\\]")

# Caractères Unicode strippés ou normalisés par certains navigateurs AVANT
# la validation URL. Ne pas inclure les accents ou caractères imprimables
# légitimes (é, ü, ñ...) — uniquement whitespace invisible ou zéro-width.
# - U+00A0 NO-BREAK SPACE
# - U+200B-U+200D ZERO-WIDTH (SPACE, NON-JOINER, JOINER)
# - U+2028 LINE SEPARATOR
# - U+2029 PARAGRAPH SEPARATOR
# - U+FEFF ZERO-WIDTH NO-BREAK SPACE (BOM)
_UNICODE_SPOOFING_CHARS: Final[frozenset[str]] = frozenset(
    "\u00a0\u200b\u200c\u200d\u2028\u2029\ufeff"
)


class SecurityHeadersMiddleware:
    """
    Middleware ajoutant les headers de sécurité HTTP à chaque réponse.

    Appelé depuis BaseHandler.prepare() pour garantir l'application AVANT
    tout write(). Voir doctrine module pour la liste complète des headers
    et leur justification.
    """

    @staticmethod
    def apply_security_headers(handler: RequestHandler) -> None:
        """
        Applique les headers de sécurité à une réponse Tornado.

        Effets de bord :
        - handler.csp_nonce : nonce CSP (réutilisable dans templates Jinja2
          via {{ handler.csp_nonce }})
        - handler.set_header() : écrit les headers HTTP

        Args:
            handler: RequestHandler Tornado (toute sous-classe)
        """
        nonce = SecurityHeadersMiddleware._generate_csp_nonce(handler)

        handler.set_header(
            "Content-Security-Policy",
            SecurityHeadersMiddleware._build_csp(nonce),
        )
        # ``Reporting-Endpoints`` est le pendant moderne de ``report-uri``
        # pour la directive ``report-to`` de la CSP. Posé à chaque requête
        # car les navigateurs récents (Chrome 96+, Edge) le requièrent
        # pour activer l'API Reporting. Les vieux navigateurs ignorent
        # silencieusement et retombent sur ``report-uri`` (legacy CSP2).
        handler.set_header(
            "Reporting-Endpoints",
            'csp-endpoint="/api/csp-report"',
        )
        handler.set_header("X-Frame-Options", "DENY")
        handler.set_header("X-Content-Type-Options", "nosniff")
        handler.set_header("X-XSS-Protection", _X_XSS_PROTECTION_VALUE)
        handler.set_header("Referrer-Policy", "strict-origin-when-cross-origin")
        handler.set_header(
            "Permissions-Policy",
            SecurityHeadersMiddleware._build_permissions_policy(),
        )
        handler.set_header("Cross-Origin-Opener-Policy", _COOP_VALUE)
        handler.set_header("Cross-Origin-Resource-Policy", _CORP_VALUE)

        if handler.request.protocol == "https":
            handler.set_header(
                "Strict-Transport-Security",
                f"max-age={_HSTS_MAX_AGE_SECONDS}; includeSubDomains; preload",
            )

        SecurityHeadersMiddleware._apply_cache_control(handler)

        logger.debug("Security headers appliqués: %s", handler.request.path)

    @staticmethod
    def _generate_csp_nonce(handler: RequestHandler) -> str:
        """Génère un nonce CSP aléatoire et le stocke sur handler.csp_nonce."""
        nonce = secrets.token_urlsafe(_CSP_NONCE_BYTES)
        handler.csp_nonce = nonce
        return nonce

    @staticmethod
    def _build_csp(nonce: str) -> str:
        """Construit la directive CSP complète avec nonce par requête.

        ``report-uri /api/csp-report`` (CSP2 legacy, compat tous navigateurs)
        et ``report-to csp-endpoint`` (CSP3 / Reporting API, Chrome moderne)
        désignent l'endpoint qui reçoit les violations. L'endpoint est géré
        par :class:`app.handlers.csp_report.CSPReportHandler` (rate-limit,
        JSONL audit, log warning). Sans ces directives, les violations CSP
        sont invisibles côté serveur — le bug se manifeste seulement comme
        "rien ne marche" côté utilisateur, sans trace exploitable.

        Le ``Reporting-Endpoints`` header (associé à ``report-to``) est
        posé séparément dans :meth:`apply_security_headers` ; ici on
        référence juste le nom du group (``csp-endpoint``).
        """
        # Préfixe d'un espace seulement si des sources tierces existent (évite
        # un double espace dans la directive quand le tuple est vide).
        _script_extra = " ".join(_SCRIPT_TRUSTED_SOURCES)
        script_sources = f" {_script_extra}" if _script_extra else ""
        style_sources = " ".join(_STYLE_TRUSTED_SOURCES)
        font_sources = " ".join(_FONT_TRUSTED_SOURCES)
        return (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'{script_sources}; "
            f"style-src 'self' 'unsafe-inline' {style_sources}; "
            f"font-src 'self' {font_sources}; "
            "img-src 'self' https: data:; "
            "connect-src 'self' ws: wss:; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "report-uri /api/csp-report; "
            "report-to csp-endpoint"
        )

    @staticmethod
    def _build_permissions_policy() -> str:
        """Construit la Permissions-Policy (fail-closed : tout désactivé)."""
        disabled_features = (
            "geolocation",
            "microphone",
            "camera",
            "payment",
            "usb",
            "magnetometer",
            "gyroscope",
            "accelerometer",
        )
        return ", ".join(f"{feature}=()" for feature in disabled_features)

    @staticmethod
    def _is_sensitive_path(path: str) -> bool:
        """Retourne True si path appartient à une route sensible (/api/*, /admin*)."""
        return any(path.startswith(prefix) for prefix in _SENSITIVE_PATH_PREFIXES)

    @staticmethod
    def _set_no_store(handler: RequestHandler) -> None:
        """Pose les headers anti-cache cross-user (no-store + Vary:Cookie).

        ``Vary: Cookie`` : un cache intermédiaire/partagé (proxy d'entreprise)
        doit différencier la réponse par session, sinon il peut servir la page
        d'un utilisateur à un autre. Complète ``no-store`` côté navigateur.
        """
        handler.set_header("Cache-Control", _CACHE_CONTROL_NO_STORE)
        handler.set_header("Pragma", "no-cache")
        handler.set_header("Vary", "Cookie")

    @staticmethod
    def _apply_cache_control(handler: RequestHandler) -> None:
        """No-store sur routes sensibles par CHEMIN (``/api/*``, ``/admin*``).

        Appelé tôt dans ``prepare()`` — avant résolution de ``current_user`` —
        donc ne dépend QUE du path. Les pages HTML authentifiées hors
        ``/admin`` (``/dashboard``, ``/contacts``, ``/reports``, ``/iris``...)
        sont couvertes en complément par
        :meth:`apply_authenticated_cache_control` une fois l'user résolu.
        """
        if SecurityHeadersMiddleware._is_sensitive_path(handler.request.path):
            SecurityHeadersMiddleware._set_no_store(handler)

    @staticmethod
    def apply_authenticated_cache_control(handler: RequestHandler) -> None:
        """No-store + Vary:Cookie sur TOUTE réponse servie à un user authentifié.

        Anti-fuite cross-user (review loop F4) : les pages HTML par-user
        (``/dashboard``, ``/contacts``, ``/reports``, ``/email-history``,
        ``/iris``, ``/settings``, ``/datastore``, ``/dashboards``,
        ``/data/privacy``...) contiennent des données privées qui ne doivent
        jamais être rejouées depuis le bfcache / disk-cache du navigateur après
        un changement de compte sur un poste partagé.

        **Générique** (anti-drift) : aucune liste de routes à maintenir — dès
        qu'un ``current_user`` est résolu, la réponse est privée. Les assets
        statiques (``/static/*``) ne passent PAS par ``BaseHandler.prepare``
        (servis par ``StaticFileHandler``) → leur cache long n'est pas impacté.
        Un handler qui cache volontairement (ex: ``/api/dashboard/charts`` en
        privé 60 s) réécrit ``Cache-Control`` APRÈS ``prepare()`` et l'emporte.

        À appeler dans ``BaseHandler.prepare()`` APRÈS la résolution de
        ``current_user`` (sinon l'attribut n'est pas encore posé : l'ordre de
        ``prepare`` pose les security headers avant de charger l'utilisateur).
        """
        if getattr(handler, "current_user", None) is not None:
            SecurityHeadersMiddleware._set_no_store(handler)


def _contains_spoofing_chars(value: str) -> bool:
    """True si value contient des caractères Unicode invisibles dangereux."""
    return any(char in value for char in _UNICODE_SPOOFING_CHARS)


def _has_dangerous_scheme(candidate: str) -> bool:
    """Détecte les schémas dangereux (URLs absolues, javascript:, data:, etc.)."""
    stripped = candidate.lstrip().lower()
    if stripped.startswith(("http://", "https://", "//")):
        return True
    for scheme in _DANGEROUS_SCHEMES:
        if stripped.startswith(f"{scheme}:"):
            return True
    try:
        split = urlsplit(candidate)
    except ValueError:
        return True
    return bool(split.scheme and split.scheme.lower() in _DANGEROUS_SCHEMES)


def is_safe_redirect_url(url: str | None, allowed_hosts: list[str] | None = None) -> bool:
    """
    Vérifie qu'une URL de redirection est sûre (anti open-redirect, CWE-601).

    Règles fail-closed (voir doctrine module §10 pour la justification détaillée).

    Args:
        url: URL à vérifier (peut être None).
        allowed_hosts: Liste de hosts autorisés. Accepté pour compat ascendante,
            non utilisé en mode "relative-only" actuel. Pour supporter
            host-whitelist un jour, ajouter la vérification urlsplit().netloc.

    Returns:
        True si l'URL est sûre pour redirection, False sinon.

    Refs: OWASP ASVS v5 V5.1.5, CWE-601, WHATWG URL spec §4.4.1.
    """
    _ = allowed_hosts  # réservé pour futur mode multi-host

    if not url or not isinstance(url, str):
        return False

    if _contains_spoofing_chars(url):
        return False

    try:
        decoded = unquote(url)
    except (UnicodeDecodeError, ValueError):
        return False

    for candidate in (url, decoded):
        if _CONTROL_CHARS_PATTERN.search(candidate):
            return False
        if _contains_spoofing_chars(candidate):
            return False
        if _has_dangerous_scheme(candidate):
            return False

    if not url.startswith("/") or url.startswith("//"):
        return False

    path_only = url.split("?", 1)[0].split("#", 1)[0]
    decoded_path = unquote(path_only)
    for candidate_path in (path_only, decoded_path):
        if ".." in candidate_path.split("/"):
            return False

    normalized = posixpath.normpath(decoded_path)
    if not normalized.startswith("/"):
        return False

    return True
