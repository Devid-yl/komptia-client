"""Handlers pour la page ``/email-history`` et son API JSON.

Deux surfaces (toutes ``@authenticated``) :

* :class:`EmailHistoryPageHandler` — page HTML ``/email-history``. Rend
  le template Jinja : l'UI charge la liste par AJAX via l'API.
* :class:`EmailHistoryAPIHandler` — ``GET /api/email-history``. JSON
  paginé scoped RBAC (admin ↔ tout, utilisateur ↔ ses propres envois).

Choix de design (équipe sénior) :

* **Service dédié** — toute la logique métier (filtres, stats, SQL) vit
  dans :mod:`app.services.email.email_history_service`. Le handler se
  contente de valider les paramètres HTTP, exécuter le rate-limit et
  sérialiser la réponse.
* **Validation fail-closed** — les filtres ``status`` / ``period`` hors
  domaine retournent ``400`` plutôt qu'un fallback silencieux (ancien
  code : ``period`` inconnu → 30 jours par défaut, comportement
  surprenant et non-auditable).
* **Bornes applicatives** — ``page`` et ``per_page`` sont clampés dans
  ``[1, _PAGE_MAX]`` / ``[1, _PER_PAGE_MAX]`` pour empêcher les ``OFFSET``
  massifs (DoS via deep pagination — ``sqlakeyset`` 2026 rappelle que
  ``OFFSET`` > 10k est quadratique sur la plupart des moteurs).
* **Rate-limit** — :class:`RateLimiter` partagé, aligné sur le pattern
  ``_check_rate_limit`` de ``contacts.py``/``datastore.py``. Protège
  l'API contre le hammering AJAX (bug front ou scraping).
* **Aucun hardcoding métier** — bornes exposées comme constantes
  ``Final[int]`` ; les valeurs d'énumération (``STATUS_*``, ``PERIOD_*``)
  sont ré-exportées par le service, **source de vérité unique**.

Sécurité (OWASP ASVS + Top 10 2025) :

* A01 Broken Access Control — le scoping viewer ↔ admin est **dans le
  service** : aucun chemin du handler ne contourne la restriction.
* A03 Injection — ``ILIKE`` bindé + ``escape="\\"`` (voir service).
* A05 Security Misconfiguration — messages FR centralisés (``_Msg``) ;
  aucun détail d'implémentation ne fuite dans les réponses d'erreur.

Ce module ne contient **aucun** nom de BDD source, d'organisation ou de collaborateur.
"""

from __future__ import annotations

from typing import Final

from tornado.web import HTTPError

from app.handlers.base import BaseHandler, authenticated
from app.models.user import UserRole
from app.services.email.email_history_service import (
    PERIOD_ALL,
    PERIOD_VALUES,
    STATUS_ALL,
    STATUS_VALUES,
    EmailHistoryFilters,
    fetch_email_history,
)
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


# ── Bornes de pagination & recherche (zéro magic number) ─────────────────

#: Page par défaut quand ``?page=`` est absent ou non parseable.
_PAGE_DEFAULT: Final[int] = 1
#: Numéro de page maximum accepté. Au-delà, le serveur clamp au lieu de
#: lancer une requête ``OFFSET`` qui scannerait 250k lignes pour rien.
#: 10_000 × 100 = 1 M d'emails max adressables — largement suffisant et
#: coupe les bots qui essayent ``?page=9999999``.
_PAGE_MAX: Final[int] = 10_000
#: Taille de page par défaut (aligné sur le template — voir le bloc
#: ``<script>`` de ``email_history.html``).
_PER_PAGE_DEFAULT: Final[int] = 25
#: Taille de page minimum. ``0`` ne rime à rien en UI.
_PER_PAGE_MIN: Final[int] = 1
#: Taille de page maximum. Borne conjointe ``len(emails) * to_dict()`` ;
#: garde la réponse < ~1 MiB pour un page full-JSON.
_PER_PAGE_MAX: Final[int] = 100
#: Longueur maximale d'une recherche ``?q=``. Au-delà, on renvoie 400 :
#: un ``ILIKE '%...200k chars...%'`` n'a aucun sens métier et sert juste
#: à faire tourner le moteur SQL à vide (DoS via regex catastrophique).
_SEARCH_MAX_LEN: Final[int] = 200


# ── Rate-limit (quota partagé entre listing + détail) ────────────────────

#: Quota ``(max_requests, window_seconds)`` pour l'API listing. 60 req/min
#: suffit largement au JS qui debounce (cf. template) — tout ce qui
#: dépasse signifie un bug client ou un scraping.
_RATE_LIMIT_LISTING: Final[tuple[int, int]] = (60, 60)

#: Instance module-scope, aligné sur ``datastore.py``/``contacts.py``.
_listing_limiter = RateLimiter()


# ── Messages FR user-facing centralisés ──────────────────────────────────


class _Msg:
    """Messages d'erreur publiés par ce handler (FR, ton neutre)."""

    INVALID_STATUS: Final[str] = (
        "Le filtre de statut doit être l'une des valeurs suivantes : "
        f"{', '.join(sorted(STATUS_VALUES))}."
    )
    INVALID_PERIOD: Final[str] = (
        "Le filtre de période doit être l'une des valeurs suivantes : "
        f"{', '.join(sorted(PERIOD_VALUES))}."
    )
    SEARCH_TOO_LONG: Final[str] = f"La recherche est limitée à {_SEARCH_MAX_LEN} caractères."
    RATE_LIMITED: Final[str] = (
        "Trop de requêtes vers l'historique. Veuillez patienter quelques secondes."
    )


# ── Helpers privés ───────────────────────────────────────────────────────


def _check_rate_limit(user_id: int) -> None:
    """Lève ``HTTPError(429)`` si le user dépasse le quota listing.

    Clé ``user:<id>`` : le rate-limit est par utilisateur, pas par IP
    (plusieurs collaborateurs derrière le même NAT).
    """
    max_requests, window_seconds = _RATE_LIMIT_LISTING
    if not _listing_limiter.check(
        f"user:{user_id}",
        max_requests=max_requests,
        window_seconds=window_seconds,
    ):
        raise HTTPError(429, _Msg.RATE_LIMITED)


def _clamp_int(raw: str, *, default: int, minimum: int, maximum: int) -> int:
    """Parse un entier clampé ``[minimum, maximum]``.

    Raison du clamp (vs 400) : la pagination est un paramètre d'UI ;
    un bouton « page suivante » ne doit pas casser quand l'utilisateur
    atteint la dernière page (``?page=total_pages + 1`` est possible
    lors d'un refresh après suppression). Le clamp silencieux donne
    une meilleure UX qu'un 400 bloquant, cohérent avec
    ``app/handlers/admin.py::_parse_positive_int``.
    """
    if not raw:
        return default
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        logger.debug("Paramètre numérique invalide %r, fallback %d", raw, default)
        return default
    if parsed < minimum:
        return minimum
    if parsed > maximum:
        return maximum
    return parsed


# ── Handlers ─────────────────────────────────────────────────────────────


class EmailHistoryPageHandler(BaseHandler):
    """Rend la page HTML ``/email-history`` (ensuite l'UI charge l'API AJAX).

    Accessible à tous les utilisateurs connectés — le scoping (admin ↔
    utilisateur) est appliqué côté API.
    """

    @authenticated
    async def get(self) -> None:
        self.render("email_history.html", page_title="Historique des emails")


class EmailHistoryAPIHandler(BaseHandler):
    """API JSON ``GET /api/email-history?page=&per_page=&status=&period=&q=``.

    Retourne la page + les stats globales (scopées viewer). Validation
    HTTP + rate-limit ici, logique métier dans le service.
    """

    @authenticated
    async def get(self) -> None:
        user = self.current_user
        assert user is not None  # garanti par @authenticated — fail-fast typing
        _check_rate_limit(user.id)

        filters = self._parse_filters()
        payload = await fetch_email_history(
            filters=filters,
            viewer_id=user.id,
            viewer_is_admin=user.role == UserRole.ADMIN,
        )
        self.write_json(payload)

    def _parse_filters(self) -> EmailHistoryFilters:
        """Extrait et valide les paramètres de query string.

        Un status/period hors domaine produit un ``400`` explicite : on
        préfère signaler un bug client plutôt que de masquer la donnée
        par un fallback arbitraire (cohérent avec ``admin.py`` qui
        refuse un ``role`` inconnu en 400).
        """
        page = _clamp_int(
            self.get_argument("page", ""),
            default=_PAGE_DEFAULT,
            minimum=1,
            maximum=_PAGE_MAX,
        )
        per_page = _clamp_int(
            self.get_argument("per_page", ""),
            default=_PER_PAGE_DEFAULT,
            minimum=_PER_PAGE_MIN,
            maximum=_PER_PAGE_MAX,
        )

        status = self.get_argument("status", STATUS_ALL)
        if status not in STATUS_VALUES:
            raise HTTPError(400, _Msg.INVALID_STATUS)

        period = self.get_argument("period", PERIOD_ALL)
        if period not in PERIOD_VALUES:
            raise HTTPError(400, _Msg.INVALID_PERIOD)

        search = self.get_argument("q", "").strip()
        if len(search) > _SEARCH_MAX_LEN:
            raise HTTPError(400, _Msg.SEARCH_TOO_LONG)

        return EmailHistoryFilters(
            page=page,
            per_page=per_page,
            status=status,
            period=period,
            search=search,
        )
