"""Service métier pour l'historique des emails envoyés.

Responsabilités isolées du handler HTTP :

* Construire une requête ``EmailLog`` scoped RBAC (admin voit tout,
  utilisateur voit uniquement ses propres envois).
* Appliquer les filtres (statut succès/erreur, période, recherche ``ILIKE``
  échappée) de façon déterministe et testable sans réseau.
* Produire la page de résultats + les stats globales en **deux** allers-
  retours BDD (au lieu de quatre dans l'ancien handler), via un agrégat
  ``SUM(CASE WHEN success THEN 1 ELSE 0 END)``.

Choix de design (équipe sénior) :

* **Pure / testable** — aucune dépendance au handler Tornado ; une
  ``dataclass`` ``EmailHistoryFilters`` isole les paramètres d'entrée.
* **Escape LIKE** — les caractères ``%``, ``_`` et ``\\`` de la saisie
  utilisateur sont échappés (Postgres/SQLite/MSSQL acceptent tous un
  escape explicite via ``escape=``). On refuse implicitement le wildcard
  abusé et on reste compatible multi-dialecte.
* **Tri stable** — ``ORDER BY sent_at DESC, id DESC`` : le tie-break
  par ``id`` garantit un ordre déterministe entre lignes émises à la
  même microseconde (paginer sans doublon ni saut).
* **Fail-closed** — les valeurs de filtre inconnues sont rejetées
  (``ValueError``) avant toute exécution SQL. Le handler traduit en
  ``HTTP 400`` avec un message FR.
* **Aucune valeur hardcodée métier** — les bornes de pagination et la
  taille max de recherche sont injectées par le caller (handler).

Sécurité :

* Scope RBAC appliqué à la fois aux résultats *et* aux stats : un
  utilisateur non-admin ne peut jamais compter les lignes des autres.
* Les paramètres ``ILIKE`` sont bindés (pas de ``f"..."``), prévient
  toute injection (A03 OWASP 2025 — cheat sheet SQL Injection).
* Pas de log du contenu des emails (``subject``, ``recipients``), qui
  peut être confidentiel — seul le compte de lignes retournées est logué.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from types import MappingProxyType
from typing import Any, Final, Mapping

from sqlalchemy import Select, case, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import clock
from app.core.database import get_session
from app.models.email_log import EmailLog
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ── Valeurs acceptées pour les filtres ────────────────────────────────────

#: Valeur ``status`` signifiant « pas de filtre sur succès ».
STATUS_ALL: Final[str] = "all"
#: Valeur ``status`` : ne garder que les emails délivrés avec succès.
STATUS_SUCCESS: Final[str] = "success"
#: Valeur ``status`` : ne garder que les emails en échec.
STATUS_ERROR: Final[str] = "error"

#: Ensemble figé des valeurs valides pour ``status``. Utilisé en validation
#: fail-closed côté service. L'ordre est figé pour que
#: :class:`frozenset` garantisse un hash stable sur des imports croisés.
STATUS_VALUES: Final[frozenset[str]] = frozenset({STATUS_ALL, STATUS_SUCCESS, STATUS_ERROR})

#: Valeur ``period`` signifiant « pas de filtre temporel ».
PERIOD_ALL: Final[str] = "all"

#: Mapping ``period → nombre de jours``. ``MappingProxyType`` rend la table
#: effectivement immuable (``dict`` seul serait mutable par erreur).
PERIOD_DAYS: Final[Mapping[str, int]] = MappingProxyType({"7d": 7, "30d": 30, "90d": 90})

#: Ensemble des valeurs acceptées pour ``period`` (inclut ``all`` + les clés
#: de :data:`PERIOD_DAYS`).
PERIOD_VALUES: Final[frozenset[str]] = frozenset({PERIOD_ALL, *PERIOD_DAYS.keys()})


# ── Escape LIKE ───────────────────────────────────────────────────────────

#: Caractère d'échappement pour ``ILIKE``. ``\`` est l'échappement par
#: défaut en ANSI SQL ; on l'explicite en ``escape="\\"`` dans chaque
#: appel pour ne pas dépendre de la config dialect du driver.
_LIKE_ESCAPE: Final[str] = "\\"


def _escape_like(value: str) -> str:
    r"""Échappe les wildcards ``LIKE`` dans une saisie utilisateur.

    L'ordre importe : on remplace **d'abord** ``\`` pour ne pas double-
    échapper les ``\%`` introduits ensuite.

    >>> _escape_like("50%")
    '50\\%'
    >>> _escape_like("C:\\\\temp")
    'C:\\\\\\\\temp'
    """
    return (
        value.replace(_LIKE_ESCAPE, _LIKE_ESCAPE * 2)
        .replace("%", _LIKE_ESCAPE + "%")
        .replace("_", _LIKE_ESCAPE + "_")
    )


# ── Dataclass de filtres ──────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class EmailHistoryFilters:
    """Paramètres de la requête historique emails.

    Immuable (``frozen=True``) : on ne modifie pas les filtres en place
    pour éviter les effets de bord entre appelants. ``slots=True`` réduit
    l'empreinte mémoire (Python 3.10+).

    Attributs
    ---------
    page
        Numéro de page (1-indexé). Doit être >= 1.
    per_page
        Taille de page. Doit être >= 1.
    status
        L'une de :data:`STATUS_VALUES`.
    period
        L'une de :data:`PERIOD_VALUES`.
    search
        Chaîne de recherche libre (déjà ``strip``-ée). Les ``LIKE`` wild-
        cards seront échappés automatiquement — aucune pré-sanitization
        attendue du caller.
    """

    page: int
    per_page: int
    status: str
    period: str
    search: str

    def __post_init__(self) -> None:
        # Validation fail-closed — on préfère une exception très tôt plutôt
        # qu'un comportement silencieux inattendu en BDD.
        if self.page < 1:
            raise ValueError(f"page doit être >= 1, reçu {self.page!r}")
        if self.per_page < 1:
            raise ValueError(f"per_page doit être >= 1, reçu {self.per_page!r}")
        if self.status not in STATUS_VALUES:
            raise ValueError(f"status invalide: {self.status!r}. Valeurs: {sorted(STATUS_VALUES)}")
        if self.period not in PERIOD_VALUES:
            raise ValueError(f"period invalide: {self.period!r}. Valeurs: {sorted(PERIOD_VALUES)}")

    @property
    def offset(self) -> int:
        """Décalage SQL à appliquer (``(page - 1) * per_page``)."""
        return (self.page - 1) * self.per_page


# ── Helpers privés de construction de requête ────────────────────────────


def _apply_scope(query: Select[Any], viewer_id: int, viewer_is_admin: bool) -> Select[Any]:
    """Restreint ``query`` aux lignes visibles par le viewer.

    Un admin voit tout ; un non-admin ne voit que ses propres envois.
    Cette garde est appliquée *à la fois* aux résultats et aux stats :
    ne pas la dupliquer dans le caller évite un oubli (RBAC leak A01
    OWASP 2025).
    """
    if viewer_is_admin:
        return query
    return query.where(EmailLog.sent_by_user_id == viewer_id)


def _apply_filters(query: Select[Any], filters: EmailHistoryFilters) -> Select[Any]:
    """Applique statut, période et recherche — dans cet ordre."""
    if filters.status == STATUS_SUCCESS:
        query = query.where(EmailLog.success.is_(True))
    elif filters.status == STATUS_ERROR:
        query = query.where(EmailLog.success.is_(False))

    days = PERIOD_DAYS.get(filters.period)
    if days is not None:
        since = clock.now() - timedelta(days=days)
        query = query.where(EmailLog.sent_at >= since)

    if filters.search:
        pattern = f"%{_escape_like(filters.search)}%"
        # Recherche sur les TROIS canaux de destinataires, pas seulement
        # ``recipients`` (le To:). Raison : pour les envois contacts/rapports,
        # le To: ne contient QUE l'expéditeur (design privacy S-04 : vrais
        # destinataires en BCC pour ne pas divulguer le carnet d'adresses
        # entre clients). Chercher uniquement ``recipients`` renverrait donc
        # 0 résultat quand l'utilisateur cherche un vrai destinataire — la
        # barre annonce pourtant « sujets ou destinataires ». ``cc_recipients``
        # / ``bcc_recipients`` sont nullable : ``ILIKE`` sur NULL renvoie NULL
        # (non-match), donc safe. Cohérent avec l'affichage qui concatène
        # déjà to+cc+bcc (email_history.html).
        query = query.where(
            or_(
                EmailLog.subject.ilike(pattern, escape=_LIKE_ESCAPE),
                EmailLog.recipients.ilike(pattern, escape=_LIKE_ESCAPE),
                EmailLog.cc_recipients.ilike(pattern, escape=_LIKE_ESCAPE),
                EmailLog.bcc_recipients.ilike(pattern, escape=_LIKE_ESCAPE),
            )
        )

    return query


async def _count_filtered(
    session: AsyncSession,
    filters: EmailHistoryFilters,
    viewer_id: int,
    viewer_is_admin: bool,
) -> int:
    """Compte les lignes correspondant aux filtres (pour la pagination)."""
    scoped = _apply_filters(_apply_scope(select(EmailLog.id), viewer_id, viewer_is_admin), filters)
    total = (await session.execute(select(func.count()).select_from(scoped.subquery()))).scalar()
    return int(total or 0)


async def _compute_stats(
    session: AsyncSession, viewer_id: int, viewer_is_admin: bool
) -> dict[str, Any]:
    """Calcule les stats globales (total / succès / erreurs / taux) du viewer.

    **Un seul aller-retour BDD** grâce à ``SUM(CASE WHEN success THEN 1
    ELSE 0 END)`` — pattern déjà utilisé dans
    ``app/services/performance_stats_service.py`` pour la même raison.
    """
    stmt = select(
        func.count(EmailLog.id),
        func.coalesce(func.sum(case((EmailLog.success.is_(True), 1), else_=0)), 0),
    )
    stmt = _apply_scope(stmt, viewer_id, viewer_is_admin)
    row = (await session.execute(stmt)).one()
    total_sent = int(row[0] or 0)
    total_success = int(row[1] or 0)
    total_errors = total_sent - total_success
    success_rate = round(total_success / total_sent * 100, 1) if total_sent else 0.0
    return {
        "total_sent": total_sent,
        "total_success": total_success,
        "total_errors": total_errors,
        "success_rate": success_rate,
    }


# ── API publique ─────────────────────────────────────────────────────────


async def fetch_email_history(
    *,
    filters: EmailHistoryFilters,
    viewer_id: int,
    viewer_is_admin: bool,
) -> dict[str, Any]:
    """Retourne la page d'historique + stats globales scopées au viewer.

    Paramètres
    ----------
    filters
        Filtres validés (voir :class:`EmailHistoryFilters`). Le caller
        (handler) est responsable de la validation HTTP ; ce service
        refusera de toute façon les valeurs hors domaine via le
        ``__post_init__`` de la dataclass.
    viewer_id
        Identifiant numérique du user courant. Sert à scopier la requête
        quand ``viewer_is_admin`` est faux.
    viewer_is_admin
        ``True`` uniquement pour les administrateurs ; sinon les stats
        ET la liste sont bornées aux envois de ``viewer_id``.

    Retour
    ------
    dict avec clés ``emails``, ``total``, ``page``, ``per_page``,
    ``total_pages``, ``stats``. Sérialisé tel quel en JSON par le
    handler. ``stats`` contient toujours ``total_sent``, ``total_success``,
    ``total_errors``, ``success_rate``.

    Notes
    -----
    On effectue **deux** allers-retours BDD :

    1. ``COUNT(*)`` pour la pagination filtrée + stats agrégées (un seul
       ``SELECT`` via ``func.coalesce(func.sum(case(...)))``).
    2. ``SELECT ... ORDER BY ... LIMIT ... OFFSET ...`` pour la page.

    Le ``COUNT(*)`` filtré et les stats globales sont deux requêtes
    distinctes car leurs scopes diffèrent (filtré vs non-filtré).
    """
    async with get_session() as session:
        total = await _count_filtered(session, filters, viewer_id, viewer_is_admin)
        total_pages = max(1, (total + filters.per_page - 1) // filters.per_page)

        # A4-F4 : clamp la page demandée à total_pages. Sans ça, page=999 sur 3
        # pages renvoyait une liste vide SILENCIEUSE (cul-de-sac trompeur :
        # « Aucun email trouvé » alors que des emails existent). On renvoie la
        # page effective pour que le JS resynchronise les contrôles de pagination.
        effective_page = min(filters.page, total_pages)
        effective_offset = (effective_page - 1) * filters.per_page

        stats = await _compute_stats(session, viewer_id, viewer_is_admin)

        page_query = _apply_filters(
            _apply_scope(select(EmailLog), viewer_id, viewer_is_admin), filters
        )
        page_query = (
            page_query.order_by(desc(EmailLog.sent_at), desc(EmailLog.id))
            .offset(effective_offset)
            .limit(filters.per_page)
        )
        rows = (await session.execute(page_query)).scalars().all()
        emails = [row.to_dict() for row in rows]

    logger.debug(
        "email_history fetched",
        extra={
            "viewer_id": viewer_id,
            "viewer_is_admin": viewer_is_admin,
            "page": filters.page,
            "per_page": filters.per_page,
            "returned": len(emails),
            "total": total,
            "status": filters.status,
            "period": filters.period,
            "has_search": bool(filters.search),
        },
    )

    return {
        "emails": emails,
        "total": total,
        # A4-F4 : page EFFECTIVE (clampée à total_pages) — le front resynchronise
        # ses contrôles dessus au lieu de rester sur une page hors borne vide.
        "page": effective_page,
        "per_page": filters.per_page,
        "total_pages": total_pages,
        "stats": stats,
    }
