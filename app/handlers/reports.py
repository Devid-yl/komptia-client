"""Handlers HTTP pour le module « Rapports » (US-4.5 Stockage & Archivage).

Surface HTTP exposée
--------------------
* ``GET  /reports``                               — page HTML (liste + filtres)
* ``GET  /api/reports``                           — liste JSON paginée
* ``POST /api/reports``                           — upload d'un rapport
* ``GET  /api/reports/<id>``                      — métadonnées JSON
* ``DELETE /api/reports/<id>``                    — suppression (propriétaire / admin)
* ``GET  /api/reports/<id>/download``             — téléchargement authentifié (streamé)
* ``POST /api/reports/<id>/share``                — crée un lien de partage (token TTL)
* ``DELETE /api/reports/<id>/share``              — révoque le lien
* ``POST /api/reports/<id>/archive``              — (dés)archive (toggle ou bool explicite)
* ``GET  /share/report/<token>``                  — téléchargement public via token
* ``POST /api/reports/send-email``                — envoi des rapports en pièces jointes
* ``GET  /api/reports/classeurs``                 — liste des classeurs ``.afz.json``
* ``GET  /api/reports/classeurs/tabs``            — métadonnées des onglets + budget tokens
* ``GET  /api/reports/llm-limits``                — budget tokens du modèle actif
* ``POST /api/reports/generate-llm``              — génération IA d'un rapport PDF

Garanties transverses (doctrine équipe sénior)
----------------------------------------------
1. **Fail-closed** — toutes les mutations passent :func:`_fetch_owned_report`
   qui rejette 404 (inexistant) **puis** 403 (propriétaire ≠ admin).
   Le pattern est centralisé et testé, pas dispersé dans six handlers.
2. **Defense-in-depth CRLF** — chaque ``Content-Disposition`` passe par
   :func:`_set_download_security_headers` qui délègue à
   :func:`~app.utils.validators.assert_no_crlf` — aucun nom de fichier
   arrivant de BDD ne peut injecter un second header (CWE-93, CVE-2026-*
   MimeKit / Plunk / .NET SmtpClient).
3. **Referrer-Policy: no-referrer** sur TOUS les téléchargements — le
   Referer d'un PDF affiché ``?inline=true`` contenant un lien externe ou
   d'un partage public fuite autrement l'URL du token (CWE-200).
4. **Rate-limiting explicite** à TROIS endpoints :
   * ``GET /share/report/<token>`` — brute-force du token (IP).
   * ``POST /api/reports/send-email`` — anti-spam interne (user).
   * ``POST /api/reports/generate-llm`` — coût $ (user).
5. **Imports top-level uniquement** — la doctrine de
   :mod:`app.handlers.base` interdit les ``import`` à l'intérieur des
   fonctions. Toutes les dépendances sont résolues au chargement du
   module, ce qui rend les cycles visibles à ``python -c "import app"``.
6. **Streaming de fichiers mutualisé** — :func:`~app.utils.http_streaming.stream_file_to_handler`
   est appelé par ``reports.py``, ``datastore.py`` et ``automations.py``.
   Aucune duplication de la boucle ``read(chunk)`` + ``write`` + ``flush``.
7. **Silent-skip interdit** — :meth:`ReportEmailHandler._validate_and_fetch_reports`
   lève un 404 explicite si un ``report_id`` demandé n'existe pas, au
   lieu de l'ignorer silencieusement (« données fausses silencieusement »
   est la pire classe de bug — cf. ``rules/consequences.md``).

Pourquoi ce fichier reste-t-il volumineux ?
-------------------------------------------
Toutes les responsabilités (CRUD, download, share, archive, email,
génération LLM) cohabitent car elles partagent le même modèle ``Report``
et les mêmes règles d'autorisation. Scinder en plusieurs modules
obligerait à dupliquer :func:`_fetch_owned_report` et ses dépendances,
ou à créer un module « commun » qui re-concentrerait le couplage.
Les *handlers LLM* (``ReportGenerate*``, ``ReportClasseurs*``) partagent
également les helpers de cache classeur et de validation de sources,
ce qui justifie la co-localisation. Ce qui a été découpé : les
*helpers purs* sortis en fonctions module-level (``_parse_report_id``,
``_sanitize_download_filename``, ``_set_download_security_headers``,
``_email_html_body``) et les fonctions de la pipeline LLM extraites en
méthodes privées de :class:`ReportGenerateLLMHandler` (chacune < 80 LOC).
"""

from __future__ import annotations

import asyncio
import html as html_module
import re
import smtplib
from pathlib import Path
from typing import Any, Final, Literal, TypedDict

import tornado.web

from app.constants import (
    DEFAULT_PER_PAGE,
    DEFAULT_RETENTION_DAYS,
    SHARE_LINK_EXPIRY_HOURS,
)
from app.core.database import get_session
from app.handlers.base import BaseHandler, authenticated, require_role
from app.handlers.datastore import _user_dir
from app.handlers.workbooks import _resolve_user_path
from app.models.user import User, UserRole
from app.services.classeur.reader import (
    extract_source_data as _extract_source_data,
    list_classeurs_sync as _list_classeurs_sync,
    read_classeur as _read_classeur,
    rows_to_dicts as _rows_to_dicts,
)
from app.services.external_sheets import load_csv_file, load_excel_sheet
from app.services.reporting.llm_limits import (
    estimate_tokens,
    get_active_model_limits,
)
from app.services.reporting.llm_report_executor import build_pdf_from_plan
from app.services.reporting.llm_report_planner import (
    ReportPlanError,
    plan_report,
)
from app.services.reporting.report_storage import (
    ALLOWED_FORMATS,
    get_report_storage,
)
from app.utils.http_streaming import (
    sanitize_download_filename,
    set_download_security_headers,
    stream_file_to_handler,
)
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter
from app.utils.template_helpers import to_dict_object
from app.utils.validators import is_valid_email

logger = get_logger(__name__)


# ── Constantes locales au domaine « reports » ────────────────────────────

#: MIME types par format. Source de vérité pour les headers Content-Type
#: des endpoints download/share ; aligné sur l'enum ``ALLOWED_FORMATS`` du
#: service. Un nouveau format ajouté côté service **doit** apparaître ici
#: ou les téléchargements tombent sur ``application/octet-stream``.
FORMAT_MIME: Final[dict[str, str]] = {
    "pdf": "application/pdf",
    "csv": "text/csv; charset=utf-8",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

#: Pagination : plafond conservateur pour éviter un DoS read-amplification
#: (un admin curieux qui demande 10 000 lignes tuerait la sérialisation JSON).
_MAX_PER_PAGE: Final[int] = 100
#: Nombre max de classeurs retournés en un listing — évite une réponse
#: énorme si un user stocke 10 k classeurs (improbable mais OWASP « limit
#: resource consumption »).
_MAX_CLASSEURS_LISTED: Final[int] = 200

#: Rate-limit ÉCHECS de validation token (brute-force). 10 ÉCHECS/min/IP — un
#: token 32 bytes urlsafe a ~192 bits d'entropie, donc 10/min ne peut jamais
#: deviner, mais bloque les scanners qui testent des listes connues. Ce compteur
#: ne décompte QUE les 404 (tokens invalides) : un téléchargement légitime (token
#: valide) ne consomme pas ce budget — sinon une org entière derrière un même NAT
#: se bloquerait elle-même en téléchargeant ses propres liens (#24).
_SHARE_RATE_MAX: Final[int] = 10
_SHARE_RATE_WINDOW_S: Final[int] = 60
#: Plafond GLOBAL anti-DoS par IP (toutes requêtes confondues, succès inclus).
#: Généreux pour ne pas pénaliser le NAT, mais borné pour couper un flood (ex.
#: re-téléchargements en boucle d'un même token valide, que le compteur d'échecs
#: ci-dessus ne verrait pas). 120/min/IP = 2 req/s soutenu.
_SHARE_GLOBAL_RATE_MAX: Final[int] = 120

#: Rate-limit email : anti-spam interne. Un user compromis ou malveillant
#: peut tenter d'envoyer 1 000 emails (via SMTP de l'organisation = fuite de
#: réputation IP). 20/h/user couvre un usage légitime (rapports
#: mensuels × 5 destinataires) tout en bloquant l'abuse.
_EMAIL_RATE_MAX: Final[int] = 20
_EMAIL_RATE_WINDOW_S: Final[int] = 3600

#: Rate-limit génération LLM : coût $ par appel. 10/5 min par user
#: empêche qu'un user distrait grille le budget API en bouclant.
_GENERATE_RATE_MAX: Final[int] = 10
_GENERATE_RATE_WINDOW_S: Final[int] = 300
# A3-F7 : listing classeurs — parité avec /api/workbooks (60/min) ; scan de
# répertoire peu coûteux mais borné (anti-abus / DoS léger).
_CLASSEURS_RATE_MAX: Final[int] = 60
_CLASSEURS_RATE_WINDOW_S: Final[int] = 60

#: Défense-in-depth sur les strings arrivant du JSON body. Les services
#: downstream bornent aussi mais le caller borne d'abord pour éviter de
#: faire transiter 1 Mo de JSON inutile à travers tout le handler.
_MAX_USER_PROMPT_LEN: Final[int] = 4_000
_MAX_FILE_PATH_LEN: Final[int] = 260  # limite historique Windows MAX_PATH
_MAX_CELL_KEY_LEN: Final[int] = 128
_MAX_SHEET_NAME_LEN: Final[int] = 255
_MAX_ENCODING_LEN: Final[int] = 32
_MAX_SEPARATOR_LEN: Final[int] = 4
_MAX_EXTERNAL_ROWS: Final[int] = 50_000
_MAX_REPORT_FILE_NAME_BASE: Final[int] = 80
# Cap du TOTAL des pièces jointes d'un envoi de rapports par email. Le
# ``SMTPClient`` borne déjà chaque pièce à 50 Mo, mais PAS l'agrégat : N
# rapports sont tous lus en mémoire puis encodés base64 dans UN MIME avant
# l'envoi — un envoi multi-rapports volumineux ferait gonfler la RAM (OOM
# pendant le build, AVANT que le serveur SMTP ne puisse rejeter) → indispo
# côté serveur (≠ un seul user). On échoue fail-fast en 400 AVANT le build,
# à partir de ``Report.file_size`` (déjà stocké, aucune lecture disque).
# Aligné sur le cap par-pièce du SMTPClient (50 Mo) ; un email > 50 Mo est
# de toute façon rejeté par la plupart des serveurs SMTP.
_MAX_EMAIL_ATTACHMENTS_TOTAL_BYTES: Final[int] = 50 * 1024 * 1024

#: Bornes durée de rétention d'un rapport.
#:
#: Bug d'origine — ``retention_days=-1`` créait un rapport instantanément
#: expiré (``Report.is_expired`` calcule ``created_at + timedelta(days=N)``
#: ; si ``N <= 0`` alors ``expiry <= created_at`` donc ``now() > expiry``
#: dès la première microseconde post-création → purge silencieuse). Le fix
#: refuse 400 sur ``< 1``.
#:
#: Pourquoi ``min=1`` et non ``min=0`` ? ``retention_days=0`` reproduit le
#: même bug : ``expiry = created_at`` ; à la microseconde suivante,
#: ``datetime.now() > expiry == True`` → ``is_expired == True`` → scheduler
#: purge. La distinction n'a aucune valeur métier (1 jour = la durée minimale
#: pendant laquelle un rapport reste accessible à son auteur).
#:
#: Cap haut à 10 ans — au-delà, c'est probablement une faute de frappe
#: (« 9999 jours »).
_MIN_RETENTION_DAYS: Final[int] = 1
_MAX_RETENTION_DAYS: Final[int] = 3650

#: Bornes durée de validité d'un lien de partage. Au moins 1 heure (un
#: lien qui expire à la création est inutile et masque l'erreur côté UX).
#: Cap à 30 jours — au-delà, on suggère un compte authentifié plutôt qu'un
#: lien public éternel.
_MIN_SHARE_EXPIRES_HOURS: Final[int] = 1
_MAX_SHARE_EXPIRES_HOURS: Final[int] = 720

#: Rate limiters partagés — une instance unique par process.
_share_rate_limiter: Final[RateLimiter] = RateLimiter()
_email_rate_limiter: Final[RateLimiter] = RateLimiter()
_generate_rate_limiter: Final[RateLimiter] = RateLimiter()
_classeurs_rate_limiter: Final[RateLimiter] = RateLimiter()


# ── Messages client centralisés (français, ton cohérent avec le projet) ──


class _Messages:
    """Chaînes FR exposées au client. Centralisées pour l'audit / i18n."""

    REPORT_NOT_FOUND: Final[str] = "Rapport introuvable"
    FILE_NOT_ON_DISK: Final[str] = "Fichier introuvable sur le disque"
    SHARE_INVALID_OR_EXPIRED: Final[str] = "Lien de partage invalide ou expiré"
    FORBIDDEN: Final[str] = "Non autorisé"
    ID_INVALID: Final[str] = "ID invalide"
    INVALID_JSON: Final[str] = "JSON invalide"
    NO_FILE_PROVIDED: Final[str] = "Aucun fichier fourni"
    FILE_TOO_LARGE: Final[str] = "Fichier trop volumineux."
    NO_REPORT_SPECIFIED: Final[str] = "Aucun rapport spécifié"
    EMAIL_ATTACHMENTS_TOO_LARGE: Final[str] = (
        "Le total des pièces jointes dépasse la limite de {mb} Mo par envoi. "
        "Sélectionnez moins de rapports ou envoyez-les en plusieurs fois."
    )
    NO_RECIPIENT_SPECIFIED: Final[str] = "Aucun destinataire spécifié"
    NO_VALID_EMAIL_FOUND: Final[str] = "Aucune adresse email valide trouvée"
    AT_LEAST_ONE_SOURCE: Final[str] = "Au moins une feuille source est requise"
    INVALID_SOURCE: Final[str] = "Source invalide"
    SMTP_NOT_CONFIGURED: Final[str] = (
        "Configuration SMTP non configurée. "
        "Veuillez demander à un administrateur de configurer le SMTP."
    )
    EMAIL_SEND_ERROR: Final[str] = "Une erreur est survenue lors de l'envoi de l'email."
    LLM_PLAN_UNAVAILABLE: Final[str] = "IA indisponible ou plan invalide"
    LLM_PLAN_UNEXPECTED_ERROR: Final[str] = "Erreur lors de la planification du rapport"
    PDF_BUILD_ERROR: Final[str] = "Erreur lors de la génération du PDF"
    TOO_MANY_SHARE_ATTEMPTS: Final[str] = "Trop de tentatives. Réessayez dans quelques minutes."
    TOO_MANY_EMAILS: Final[str] = "Vous avez envoyé trop d'emails récemment. Réessayez plus tard."
    TOO_MANY_GENERATIONS: Final[str] = "Trop de rapports générés. Patientez quelques minutes."


# ── Typed dicts pour les sources du générateur LLM ────────────────────────


class _WorkbookSource(TypedDict):
    """Source "workbook" : un onglet (ou une cellule drill-down) d'un .afz.json."""

    type: Literal["workbook"]
    classeur: str
    tab_index: int
    cell_key: str | None


class _ExcelSource(TypedDict):
    """Source "excel" : un onglet d'un fichier .xlsx/.xls du datastore."""

    type: Literal["excel"]
    path: str
    sheet_name: str | None
    first_row_as_header: bool


class _CsvSource(TypedDict):
    """Source "csv" : un fichier .csv du datastore."""

    type: Literal["csv"]
    path: str
    encoding: str | None
    separator: str | None


_NormalizedSource = _WorkbookSource | _ExcelSource | _CsvSource


# ── Helpers purs (module-level) ───────────────────────────────────────────


def _parse_report_id(value: str) -> int:
    """Parse un ``report_id`` ou lève 400 (``HTTPError``) en cas d'invalidité.

    Volontairement **un helper module-level** plutôt qu'une méthode de
    :class:`BaseHandler` : la conversion est nécessaire depuis des closures
    (ex. :meth:`ReportEmailHandler._validate_and_fetch_reports`) sans
    ``self`` sous la main. ``BaseHandler._parse_int_or_400`` reste utilisé
    pour les paramètres de query string classiques.
    """
    try:
        return int(value)
    except (ValueError, TypeError) as exc:
        raise tornado.web.HTTPError(400, _Messages.ID_INVALID) from exc


# Aliases historiques. Les tests ``test_handlers_deep_review`` et certains
# imports legacy référencent les noms courts ``_parse_id`` / ``_validate_email``.
# On garde les alias plutôt que de réécrire les tests, pour éviter une rupture
# avec d'éventuels appels externes.
_parse_id = _parse_report_id


def _validate_email(value: object) -> bool:
    """Wrapper autour de :func:`app.utils.validators.is_valid_email`.

    Conserve l'API ``_validate_email`` attendue par les tests legacy
    (``test_handlers_deep_review``). La SSoT reste ``is_valid_email`` —
    cette fonction délègue pour ne pas dupliquer la regex de validation.
    """
    return is_valid_email(value)


# Ces deux helpers de téléchargement sûr ont migré vers la SSoT
# ``app.utils.http_streaming`` (partagée avec les guides d'aide servis par
# ``help_docs.py`` — même invariant Referrer-Policy/nosniff/anti-CRLF). On
# conserve les noms privés historiques pour ne casser ni les call-sites de ce
# module ni ``tests/unit/test_reports.py`` qui les importe nommément.
_sanitize_download_filename = sanitize_download_filename
_set_download_security_headers = set_download_security_headers


async def _fetch_owned_report(handler: BaseHandler, report_id: int):
    """Lit un rapport et vérifie `ownership`. Lève 404 puis 403, dans cet ordre.

    La séquence 404-puis-403 est **délibérée** : renvoyer 403 sur un ID
    inexistant divulguerait l'existence de rapports d'autres users
    (oracle d'énumération). Les deux codes finissent en message client
    générique via :meth:`BaseHandler.write_error` en prod, donc pas de
    leak côté externe.

    Fail-closed : si ``current_user`` est ``None`` (ce qui ne devrait
    jamais arriver ici grâce aux décorateurs), on lève 403.
    """
    user = handler.current_user
    if user is None:
        raise tornado.web.HTTPError(403, _Messages.FORBIDDEN)

    storage = get_report_storage()
    report = await storage.get_report(report_id)
    if not report:
        raise tornado.web.HTTPError(404, _Messages.REPORT_NOT_FOUND)
    if report.created_by_user_id != user.id and user.role != UserRole.ADMIN:
        raise tornado.web.HTTPError(403, _Messages.FORBIDDEN)
    return report


def _clip(value: object, max_len: int) -> str | None:
    """Retourne ``str(value)[:max_len]`` si truthy, sinon ``None``.

    Utilitaire pour normaliser les champs optionnels d'un JSON body LLM
    (``sheet_name``, ``encoding``, ``separator``) sans dupliquer
    ``"foo"[:255] or None`` partout.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:max_len]


# ── Handlers ──────────────────────────────────────────────────────────────


class ReportsPageHandler(BaseHandler):
    """``GET /reports`` — page HTML listant les rapports de l'utilisateur."""

    @authenticated
    async def get(self) -> None:
        user = self.current_user
        storage = get_report_storage()
        # Filtrage par user : mêmes règles que ``_write_list`` ci-dessous (la
        # liste API filtre par ``created_by_user_id``, admin voit tout). Sans
        # ce filtre, le bandeau "Total / Taille totale / Partagés / Archivés"
        # exposait l'agrégat de TOUS les rapports tous comptes confondus à un
        # user fraîchement créé — leak quantitatif d'activité cross-user.
        stats = await storage.get_storage_stats(
            user_id=None if user.role == UserRole.ADMIN else user.id,
        )
        # A3-F3 : cap d'upload réel (admin-configurable) injecté dans la modale —
        # plus de « Max 50 Mo » hardcodé qui mentait quand l'admin changeait le cap.
        from app.services.ai.config_service import get_max_upload_size_bytes

        max_upload_mo = (await get_max_upload_size_bytes()) // (1024 * 1024)
        self.render(
            "reports/list.html",
            page_title="Rapports",
            user=user,
            stats=to_dict_object(stats),
            max_upload_mo=max_upload_mo,
        )


class ReportsAPIHandler(BaseHandler):
    """CRUD REST : liste paginée, détail, upload, suppression."""

    @authenticated
    async def get(self, report_id: str | None = None) -> None:
        """``GET /api/reports[/<id>]`` — liste paginée ou détail."""
        if report_id:
            await self._write_detail(_parse_report_id(report_id))
            return
        await self._write_list()

    async def _write_detail(self, report_id: int) -> None:
        report = await _fetch_owned_report(self, report_id)
        self.write_json(report.to_dict())

    async def _write_list(self) -> None:
        user = self.current_user
        storage = get_report_storage()

        page = max(1, self._parse_int_or_400(self.get_argument("page", "1"), "page"))
        per_page_raw = self._parse_int_or_400(
            self.get_argument("per_page", str(DEFAULT_PER_PAGE)), "per_page"
        )
        per_page = min(max(1, per_page_raw), _MAX_PER_PAGE)

        status = self.get_argument("status", "all")
        is_archived: bool | None = None
        if status == "active":
            is_archived = False
        elif status == "archived":
            is_archived = True

        reports, total = await storage.list_reports(
            user_id=None if user.role == UserRole.ADMIN else user.id,
            report_type=self.get_argument("type", None),
            file_format=self.get_argument("format", None),
            search=self.get_argument("q", None),
            is_archived=is_archived,
            page=page,
            per_page=per_page,
            sort_by=self.get_argument("sort_by", "created_at"),
            sort_order=self.get_argument("sort_order", "desc"),
        )

        self.write_json(
            {
                "reports": [r.to_dict() for r in reports],
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": (total + per_page - 1) // per_page,
            }
        )

    @require_role("admin", "user")
    async def post(self, report_id: str | None = None) -> None:
        """``POST /api/reports`` — upload d'un fichier de rapport."""
        user = self.current_user

        if "file" not in self.request.files:
            raise tornado.web.HTTPError(400, _Messages.NO_FILE_PROVIDED)

        file_info = self.request.files["file"][0]
        file_name = file_info["filename"]
        file_body = file_info["body"]

        ext = Path(file_name).suffix.lstrip(".").lower()
        if ext not in ALLOWED_FORMATS:
            raise tornado.web.HTTPError(
                400,
                f"Format non autorisé : .{ext}. Autorisés : {', '.join(sorted(ALLOWED_FORMATS))}",
            )
        # Taille max upload rapport = SSoT admin (/admin/performance), résolue
        # au runtime. Avant : MAX_FILE_SIZE = 1 TiB (« pratiquement infini »).
        from app.services.ai.config_service import get_max_upload_size_bytes

        max_upload = await get_max_upload_size_bytes()
        if len(file_body) > max_upload:
            raise tornado.web.HTTPError(
                400, f"Fichier trop volumineux (max {max_upload // (1024 * 1024)} Mo)."
            )

        title = self.get_argument("title", file_name)
        description = self.get_argument("description", None)
        report_type = self.get_argument("report_type", "custom")
        retention = self._parse_int_with_bounds_or_400(
            self.get_argument("retention_days", str(DEFAULT_RETENTION_DAYS)),
            "retention_days",
            min_value=_MIN_RETENTION_DAYS,
            max_value=_MAX_RETENTION_DAYS,
        )

        storage = get_report_storage()
        try:
            report = await storage.save_report(
                file_content=file_body,
                file_name=file_name,
                title=title,
                file_format=ext,
                description=description,
                report_type=report_type,
                user_id=user.id,
                retention_days=retention,
            )
        except ValueError as exc:
            logger.warning("Erreur validation upload rapport: %s", exc)
            raise tornado.web.HTTPError(400, "Paramètres de rapport invalides") from exc

        self.write_json(report.to_dict(), status=201)

    @require_role("admin", "user")
    async def delete(self, report_id: str) -> None:
        """``DELETE /api/reports/<id>`` — suppression (propriétaire / admin)."""
        rid = _parse_report_id(report_id)
        await _fetch_owned_report(self, rid)  # 404 / 403 avant mutation

        storage = get_report_storage()
        await storage.delete_report(rid)
        self.write_json({"success": True, "message": "Rapport supprimé"})


class ReportDownloadHandler(BaseHandler):
    """``GET /api/reports/<id>/download`` — téléchargement authentifié streamé."""

    @authenticated
    async def get(self, report_id: str) -> None:
        report = await _fetch_owned_report(self, _parse_report_id(report_id))

        storage = get_report_storage()
        file_path = storage.get_file_path(report)
        if not file_path:
            raise tornado.web.HTTPError(410, _Messages.FILE_NOT_ON_DISK)

        inline = self.get_argument("inline", "false").lower() == "true"
        content_type = FORMAT_MIME.get(report.file_format, "application/octet-stream")

        _set_download_security_headers(
            self,
            content_type=content_type,
            filename=report.file_name,
            inline=inline,
            content_length=report.file_size or 0,
        )
        await stream_file_to_handler(self, file_path)
        self.finish()


class ReportShareHandler(BaseHandler):
    """Trois actions autour du partage :

    * ``POST /api/reports/<id>/share``    — créer un lien de partage.
    * ``DELETE /api/reports/<id>/share``  — révoquer.
    * ``GET /share/report/<token>``       — téléchargement **public** via token.
    """

    async def get(self, token: str) -> None:
        """Téléchargement public — protégé par rate-limit IP (anti-scan).

        Deux compteurs distincts par IP (#24) :
        * ``share-all`` — plafond global anti-DoS (toutes requêtes), généreux pour
          ne pas bloquer une org légitime derrière un même NAT.
        * ``share-fail`` — plafond STRICT des ÉCHECS de validation (404 = tokens
          invalides = brute-force). Un téléchargement légitime ne le consomme pas.
        """
        client_ip = self.request.remote_ip
        # 1) Plafond global anti-flood (toutes requêtes confondues).
        if not _share_rate_limiter.check(
            f"share-all:{client_ip}", _SHARE_GLOBAL_RATE_MAX, _SHARE_RATE_WINDOW_S
        ):
            raise tornado.web.HTTPError(429, _Messages.TOO_MANY_SHARE_ATTEMPTS)

        storage = get_report_storage()
        report = await storage.get_report_by_share_token(token)
        if not report or not report.is_share_valid:
            # Token invalide = tentative de brute-force → compteur STRICT par IP,
            # séparé des téléchargements légitimes. Au-delà du seuil : 429.
            if not _share_rate_limiter.check(
                f"share-fail:{client_ip}", _SHARE_RATE_MAX, _SHARE_RATE_WINDOW_S
            ):
                raise tornado.web.HTTPError(429, _Messages.TOO_MANY_SHARE_ATTEMPTS)
            raise tornado.web.HTTPError(404, _Messages.SHARE_INVALID_OR_EXPIRED)

        file_path = storage.get_file_path(report)
        if not file_path:
            raise tornado.web.HTTPError(410, _Messages.FILE_NOT_ON_DISK)

        await storage.increment_download_count(report.id)

        content_type = FORMAT_MIME.get(report.file_format, "application/octet-stream")
        _set_download_security_headers(
            self,
            content_type=content_type,
            filename=report.file_name,
            inline=False,
        )
        await stream_file_to_handler(self, file_path)
        self.finish()

    @require_role("admin", "user")
    async def post(self, report_id: str) -> None:
        rid = _parse_report_id(report_id)
        await _fetch_owned_report(self, rid)

        expires_hours = self._parse_int_with_bounds_or_400(
            self.get_argument("expires_hours", str(SHARE_LINK_EXPIRY_HOURS)),
            "expires_hours",
            min_value=_MIN_SHARE_EXPIRES_HOURS,
            max_value=_MAX_SHARE_EXPIRES_HOURS,
        )

        storage = get_report_storage()
        token = await storage.create_share_link(rid, expires_hours)

        share_url = f"{self.request.protocol}://{self.request.host}/share/report/{token}"
        self.write_json(
            {
                "success": True,
                "share_token": token,
                "share_url": share_url,
                "expires_hours": expires_hours,
            }
        )

    @require_role("admin", "user")
    async def delete(self, report_id: str) -> None:
        rid = _parse_report_id(report_id)
        await _fetch_owned_report(self, rid)

        storage = get_report_storage()
        await storage.revoke_share_link(rid)
        self.write_json({"success": True, "message": "Lien de partage révoqué"})


class ReportArchiveHandler(BaseHandler):
    """``POST /api/reports/<id>/archive`` — (dés)archive un rapport.

    Body JSON optionnel ``{"archive": true|false}`` ; absence du champ →
    bascule l'état courant (toggle).
    """

    @require_role("admin", "user")
    async def post(self, report_id: str) -> None:
        rid = _parse_report_id(report_id)
        await _fetch_owned_report(self, rid)

        try:
            body = self.get_json_body()
            desired = body.get("archive")
        except tornado.web.HTTPError:
            # Body vide = toggle. Le base handler a déjà loggé l'erreur.
            desired = None

        storage = get_report_storage()
        if desired is None:
            is_archived = await storage.toggle_archive(rid)
        else:
            is_archived = await storage.set_archive(rid, bool(desired))

        self.write_json(
            {
                "success": True,
                "is_archived": is_archived,
                "message": "Rapport archivé" if is_archived else "Rapport désarchivé",
            }
        )


class ReportEmailHandler(BaseHandler):
    """``POST /api/reports/send-email`` — envoi de rapports en pièces jointes.

    Séquence :
    1. Rate-limit (20 emails/h/user — anti-spam interne).
    2. Fetch rapports + vérification ownership (404 si un ID manque).
    3. Résolution des destinataires (contacts + listes) avec validation email.
    4. Chargement de la config SMTP (table DB ou fallback ``.env``).
    5. Génération du corps HTML (escape Jinja-like côté handler).
    6. Envoi + log ``EmailLog`` (l'audit est centralisé dans
       ``SMTPClient.send_email`` ; cf. ``services/email/smtp_client.py``).
    """

    async def _validate_and_fetch_reports(self, report_ids: list[int], user: User) -> list:
        """Lit chaque rapport, vérifie ownership, **refuse les IDs inconnus**.

        La version précédente utilisait ``continue`` sur un rapport
        introuvable : l'utilisateur envoyait donc un email avec 2
        rapports sur les 3 demandés, sans aucun signalement. Violation
        directe de la règle *consequences.md* point 5. On remplace par
        un 404 explicite qui liste les IDs manquants.
        """
        storage = get_report_storage()
        fetched = []
        missing: list[int] = []
        for report_id in report_ids:
            report = await storage.get_report(report_id)
            if not report:
                missing.append(report_id)
                continue
            if report.created_by_user_id != user.id and user.role != UserRole.ADMIN:
                raise tornado.web.HTTPError(403, f"Non autorisé pour le rapport {report_id}")
            fetched.append(report)

        if missing:
            raise tornado.web.HTTPError(404, f"Rapports introuvables : {missing}")
        if not fetched:
            raise tornado.web.HTTPError(404, _Messages.REPORT_NOT_FOUND)
        return fetched

    async def _collect_recipients(
        self,
        session,
        contact_ids: list[int],
        list_ids: list[int],
        user: User,
    ) -> tuple[list[str], int]:
        """Résout les emails destinataires — SSoT partagé avec ``/contacts``.

        Délègue à ``resolve_recipient_emails`` (``contact_mailer_service``)
        qui applique le filtre multi-tenant + RGPD (``is_active`` +
        ``unsubscribed_at`` AU NIVEAU SQL) et la dédup case-insensitive.
        Avant ce refactor ``/reports`` résolvait les contacts filtrés
        UNIQUEMENT par ``user_id`` → emailait les désabonnés (violation RGPD)
        et exposait toutes les adresses dans ``To:``.

        Returns:
            ``(emails, skipped_unsubscribed)`` — ``skipped_unsubscribed`` est
            remonté à l'UI pour ne pas masquer les exclusions.
        """
        from app.services.email.contact_mailer_service import (
            MAX_RECIPIENTS_PER_SEND,
            resolve_recipient_emails,
        )

        emails, skipped_unsubscribed, _skipped_invalid = await resolve_recipient_emails(
            session, user, contact_ids, list_ids
        )
        if not emails:
            raise tornado.web.HTTPError(400, _Messages.NO_VALID_EMAIL_FOUND)
        if len(emails) > MAX_RECIPIENTS_PER_SEND:
            raise tornado.web.HTTPError(
                400,
                f"Trop de destinataires ({len(emails)}). Maximum "
                f"{MAX_RECIPIENTS_PER_SEND} par envoi — utilisez les "
                "automatisations pour des envois plus volumineux.",
            )
        return emails, skipped_unsubscribed

    async def _load_smtp_config(self, session) -> dict[str, Any]:
        """Lit la config SMTP depuis la BDD (si activée) ou fallback ``.env``.

        Cycle 17 #12 : passe par le helper unifié ``load_smtp_config_dict``
        au lieu de dupliquer la logique. Le seul point spécifique à
        reports.py : on transforme le `None` retourné en HTTPError 400 pour
        que le user voie un message clair quand il essaie d'envoyer un mail
        sans config SMTP."""
        from app.services.email.smtp_factory import load_smtp_config_dict

        cfg = await load_smtp_config_dict(session=session)
        if cfg is None:
            raise tornado.web.HTTPError(400, _Messages.SMTP_NOT_CONFIGURED)
        return cfg

    def _build_email_body(self, reports: list, subject: str, message: str | None) -> str:
        """Génère le corps HTML — escape Jinja-like anti-XSS."""
        if message:
            safe_message = html_module.escape(message).replace("\n", "<br/>")
            content_block = f"<p>{safe_message}</p>"
        else:
            list_items = "".join(
                "<li>{title} ({fmt})</li>".format(
                    title=html_module.escape(r.title),
                    fmt=html_module.escape(r.file_format.upper()),
                )
                for r in reports
            )
            content_block = (
                "<p>Veuillez trouver ci-joint les rapports suivants :</p>"
                f"<ul>{list_items}</ul>"
                "<p>Cordialement,<br/>L'équipe Komptia</p>"
            )

        return "<html><body>" "<h2>Rapports Komptia</h2>" f"{content_block}" "</body></html>"

    @staticmethod
    def _assert_attachments_within_limit(reports: list) -> None:
        """Borne le TOTAL des pièces jointes d'un envoi (anti-OOM) AVANT le
        build du MIME. Somme ``Report.file_size`` (déjà en BDD → zéro lecture
        disque). Lève ``HTTPError(400)`` si le total dépasse
        :data:`_MAX_EMAIL_ATTACHMENTS_TOTAL_BYTES`.

        Le ``SMTPClient`` borne déjà CHAQUE pièce (50 Mo) mais pas l'agrégat :
        sans cette garde, N rapports volumineux sont tous chargés en mémoire
        et encodés dans un seul MIME → OOM pendant le build (indispo serveur,
        pas seulement pour l'expéditeur), AVANT même que le serveur SMTP ne
        puisse rejeter le message.
        """
        total_attach_bytes = sum(int(getattr(r, "file_size", 0) or 0) for r in reports)
        if total_attach_bytes > _MAX_EMAIL_ATTACHMENTS_TOTAL_BYTES:
            raise tornado.web.HTTPError(
                400,
                _Messages.EMAIL_ATTACHMENTS_TOO_LARGE.format(
                    mb=_MAX_EMAIL_ATTACHMENTS_TOTAL_BYTES // (1024 * 1024)
                ),
            )

    def _prepare_attachments(self, reports: list) -> list[dict[str, str]]:
        """Lit les chemins disque, skip silencieusement si manquant.

        *Skip* est acceptable ici : le rapport est en BDD mais le fichier
        a été purgé/cleanup. Log explicite pour traçabilité.
        """
        storage = get_report_storage()
        attachments: list[dict[str, str]] = []
        for report in reports:
            file_path = storage.get_file_path(report)
            if not (file_path and file_path.exists()):
                logger.warning(
                    "Pièce jointe introuvable pour report_id=%s (fichier purgé ?)",
                    report.id,
                )
                continue
            attachments.append({"path": str(file_path), "filename": report.file_name})
        return attachments

    async def _send_and_log(
        self,
        session: Any,  # ignoré — kept-for-compat avec patches éventuels
        smtp_config: dict[str, Any],
        recipient_emails: list[str],
        subject: str,
        body_html: str,
        attachments: list[dict[str, str]],
        user: User,
    ) -> dict[str, Any]:
        """Envoie l'email — l'audit ``EmailLog`` est désormais centralisé
        dans ``SMTPClient.send_email`` (cf. ``app/services/email/smtp_client.py``).

        ``session`` est passé mais **non utilisé** : le caller doit fermer
        sa session AVANT d'appeler cette méthode (le SMTP send peut durer
        plusieurs secondes avec retries, et tenir le pool ouvert pendant ce
        temps starve les autres requêtes — cf. revue Logic 2026-05-22).
        """
        del session  # explicite : ne pas garder la connexion BDD pendant SMTP
        # Q2 cycle 15 : factory unique. from_name reflète l'expéditeur humain
        # (username) tout en gardant l'identité branding admin. Adversarial #2 :
        # si admin n'a pas configuré from_name, fallback sur app_name au lieu
        # d'envoyer un email signé `"alice via None"` (chaîne littérale).
        from app.config import config
        from app.services.email.smtp_factory import build_smtp_client_from_dict

        product_name = smtp_config.get("from_name") or config.app_name
        from_name = f"{user.username} via {product_name}"
        smtp_client = build_smtp_client_from_dict(
            smtp_config,
            from_name_override=from_name,
        )

        # Noms de pièces jointes affichés dans l'audit : on log le
        # ``filename`` displayable (cf. ``_prepare_attachments``) plutôt
        # que le ``Path.name`` interne, pour conserver le libellé que
        # l'utilisateur a vu.
        audit_attachment_names = [a["filename"] for a in attachments] if attachments else []

        # PRIVACY : on envoie À l'expéditeur (To:) et tous les destinataires
        # en BCC — sinon chaque client voit en clair les adresses des autres
        # dans ``To:`` (divulgation de carnet d'adresses). Même doctrine que
        # ``contact_mailer_service`` (fix adversarial S-04).
        return await smtp_client.send_email(
            to_emails=[user.email],
            bcc_emails=recipient_emails,
            subject=subject,
            body_html=body_html,
            attachments=attachments or None,
            reply_to=user.email,
            sent_by_user_id=user.id,
            audit_attachment_names=audit_attachment_names,
        )

    @staticmethod
    def _format_send_outcome(
        result: dict[str, Any],
        recipients: list[str],
        skipped_unsubscribed: int,
    ) -> dict[str, Any]:
        """Interprète le résultat SMTP du point de vue des VRAIS destinataires.

        Le sender est en ``To:`` (copie d'archive) et les destinataires réels
        en BCC. ``refused_recipients`` renvoyé par le SMTP peut donc inclure
        l'adresse du sender : on ne compte comme « refusés » que les
        destinataires réels (intersection avec ``recipients``). Sinon un refus
        de la copie sender fausserait le compteur (voire le rendrait négatif)
        ou masquerait un envoi pourtant réussi aux destinataires.

        Lève ``HTTPError(500)`` si aucun destinataire réel n'a été livré
        (échec total ou tous refusés).
        """
        if result["success"]:
            refused_count = 0
            delivered = len(recipients)
        elif result.get("partial_success"):
            # Le serveur SMTP peut canonicaliser/minusculiser l'adresse RCPT
            # refusée (RFC) alors que ``recipients`` garde la casse d'origine.
            # Comparaison en lowercase : sinon on raterait un refus et on
            # rapporterait un destinataire refusé comme livré (donnée fausse).
            refused = result.get("refused_recipients") or []
            refused_lower = {str(r).lower() for r in refused}
            refused_count = sum(1 for r in recipients if r.lower() in refused_lower)
            delivered = len(recipients) - refused_count
            if delivered <= 0:
                logger.error(
                    "Erreur envoi email rapport: tous les destinataires refusés (%s)",
                    ", ".join(refused) or result.get("error"),
                )
                raise tornado.web.HTTPError(500, _Messages.EMAIL_SEND_ERROR)
            logger.warning(
                "Envoi email partiel : %s/%s destinataire(s) refusé(s)",
                refused_count,
                len(recipients),
            )
        else:
            # Échec total (connexion/auth SMTP, aucun destinataire livré).
            logger.error(
                "Erreur envoi email rapport: %s",
                result.get("error") or "échec total de l'envoi",
            )
            raise tornado.web.HTTPError(500, _Messages.EMAIL_SEND_ERROR)

        message = f"Email envoyé à {delivered} destinataire(s)"
        if refused_count:
            message += f". {refused_count} refusé(s) par le serveur SMTP."
        if skipped_unsubscribed:
            message += f" ({skipped_unsubscribed} exclu(s) : désabonné(s) ou inactif(s))"
        return {
            "success": True,
            "partial_success": bool(refused_count),
            "message": message,
            "recipients_count": delivered,
            "refused_count": refused_count,
            "skipped_unsubscribed": skipped_unsubscribed,
        }

    @require_role("admin", "user")
    async def post(self) -> None:
        user = self.current_user

        # 1. Rate-limit — anti-spam interne (cf. commentaire constantes).
        if not _email_rate_limiter.check(
            f"email_send:{user.id}", _EMAIL_RATE_MAX, _EMAIL_RATE_WINDOW_S
        ):
            raise tornado.web.HTTPError(429, _Messages.TOO_MANY_EMAILS)

        body = self.get_json_body()
        report_ids = body.get("report_ids") or []
        contact_ids = body.get("contact_ids") or []
        list_ids = body.get("list_ids") or []
        subject = body.get("subject") or "Rapport Komptia"
        message = body.get("message") or ""

        # Validation type STRICT (mirroir de /api/contacts/send-email) : un body
        # malformé (id non-entier ou pas une liste) doit produire un 400 propre
        # — pas un 500 sur le ``sorted`` de la clé d'idempotence ni sur le
        # ``in_()`` SQL en aval (taxonomie erreurs, axe 5).
        if not (
            isinstance(report_ids, list)
            and isinstance(contact_ids, list)
            and isinstance(list_ids, list)
        ):
            raise tornado.web.HTTPError(
                400, "report_ids, contact_ids et list_ids doivent être des listes"
            )
        try:
            report_ids = [int(x) for x in report_ids]
            contact_ids = [int(x) for x in contact_ids]
            list_ids = [int(x) for x in list_ids]
        except (ValueError, TypeError):
            raise tornado.web.HTTPError(400, "Identifiants invalides (entiers attendus)")

        if not report_ids:
            raise tornado.web.HTTPError(400, _Messages.NO_REPORT_SPECIFIED)
        if not contact_ids and not list_ids:
            raise tornado.web.HTTPError(400, _Messages.NO_RECIPIENT_SPECIFIED)

        # Idempotence : dédoublonne un double-submit rapproché (2 onglets, ou
        # retry réseau après un succès serveur). Clé = contenu + destinataires
        # + rapports + user. Sur doublon dans la fenêtre, on répond
        # explicitement « non renvoyé » (jamais un faux succès silencieux).
        from app.utils.idempotency import email_send_guard, make_idempotency_key

        idem_key = make_idempotency_key(
            kind="report_email",
            user_id=user.id,
            subject=subject,
            body=message,
            recipient_ids=[*contact_ids, *list_ids, *report_ids],
        )
        if not email_send_guard.claim(idem_key):
            self.write_json(
                {
                    "success": True,
                    "duplicate": True,
                    "message": (
                        "Un envoi identique est déjà en cours ou vient d'être "
                        "effectué — non renvoyé (protection anti-doublon). "
                        "Vérifiez l'historique des envois."
                    ),
                }
            )
            return

        try:
            # 2. Fetch rapports + 3. destinataires — même transaction lecture
            # pour un résultat cohérent (pas de TOCTOU entre les deux).
            reports = await self._validate_and_fetch_reports(report_ids, user)

            # Garde agrégat anti-OOM AVANT de construire le MIME (chaque pièce
            # est lue en mémoire + base64). Un 400 ici est attrapé par le
            # ``except Exception`` plus bas qui libère la clé d'idempotence
            # → retry légitime possible.
            self._assert_attachments_within_limit(reports)

            async with get_session() as session:
                recipients, skipped_unsubscribed = await self._collect_recipients(
                    session, contact_ids, list_ids, user
                )

            body_html = self._build_email_body(reports, subject, message)
            attachments = self._prepare_attachments(reports)

            # 4 + 5 + 6 — charger SMTP (transaction courte BDD), PUIS envoyer.
            # On ferme la session AVANT le ``send_email`` (retries SMTP ~30s+)
            # pour ne pas starve le pool. L'audit ``EmailLog`` se fait dans
            # ``SMTPClient.send_email`` via sa propre session courte.
            async with get_session() as session:
                smtp_config = await self._load_smtp_config(session)
            try:
                result = await self._send_and_log(
                    None,  # session non-utilisée (audit centralisé)
                    smtp_config,
                    recipients,
                    subject,
                    body_html,
                    attachments,
                    user,
                )
            except (smtplib.SMTPException, OSError) as exc:
                logger.error("Erreur envoi email (SMTP/OS): %s", exc, exc_info=True)
                raise tornado.web.HTTPError(500, _Messages.EMAIL_SEND_ERROR) from exc

            outcome = self._format_send_outcome(result, recipients, skipped_unsubscribed)
        except Exception:
            # Tout échec (400/404/500/SMTP) → libère la clé pour autoriser un
            # retry légitime (sinon le 1er échec bloquerait le 2e essai).
            email_send_guard.release(idem_key)
            raise

        self.write_json(outcome)


# ── Génération de rapport LLM à partir d'un classeur ──────────────────────


class ReportClasseursListHandler(BaseHandler):
    """``GET /api/reports/classeurs`` — liste des classeurs ``.afz.json``."""

    @authenticated
    async def get(self) -> None:
        user = self.current_user
        # A3-F7 : rate-limit listing (parité /api/workbooks 60/min).
        if not _classeurs_rate_limiter.check(
            f"classeurs_list:{user.id}", _CLASSEURS_RATE_MAX, _CLASSEURS_RATE_WINDOW_S
        ):
            raise tornado.web.HTTPError(429, "Trop de requêtes, réessayez dans un instant.")
        user_dir = _user_dir(user.id)

        classeurs = await asyncio.to_thread(_list_classeurs_sync, user_dir)
        classeurs.sort(key=lambda c: c["modified"], reverse=True)
        classeurs = classeurs[:_MAX_CLASSEURS_LISTED]
        self.write_json({"success": True, "classeurs": classeurs})


class ReportClasseurTabsHandler(BaseHandler):
    """``GET /api/reports/classeurs/tabs`` — onglets + budget tokens."""

    @authenticated
    async def get(self) -> None:
        user = self.current_user
        filename = self.get_argument("filename", "").strip()
        if not filename:
            raise tornado.web.HTTPError(400, "filename requis")

        data = await _read_classeur(user.id, filename)

        tabs_meta = [self._tab_metadata(idx, tab) for idx, tab in enumerate(data.get("tabs", []))]

        self.write_json({"success": True, "filename": filename, "tabs": tabs_meta})

    @staticmethod
    def _tab_metadata(index: int, tab: dict[str, Any]) -> dict[str, Any]:
        """Construit la fiche métadata d'un onglet (extraction pour clarté)."""
        cell_details = tab.get("cellDetails") or {}
        has_rows = bool(tab.get("rows"))
        has_cells = bool(cell_details)

        tab_tokens = 0
        if has_rows:
            tab_tokens = estimate_tokens(
                {
                    "columns": tab.get("columns") or [],
                    "rows": tab.get("rows") or [],
                }
            )

        cells_meta: list[dict[str, Any]] = []
        for cell_key, cell in cell_details.items():
            if not isinstance(cell, dict):
                continue
            cell_tokens = estimate_tokens(
                {
                    "columns": cell.get("columns") or [],
                    "rows": cell.get("rows") or [],
                }
            )
            cells_meta.append(
                {
                    "key": cell_key,
                    "row_count": cell.get("row_count", len(cell.get("rows", []))),
                    "estimated_tokens": cell_tokens,
                }
            )

        return {
            "index": index,
            "label": tab.get("label", f"Feuille {index + 1}"),
            "has_sql": bool(tab.get("sql")),
            "row_count": tab.get("totalRowCount", len(tab.get("rows", []))),
            "columns": tab.get("columns", []),
            "is_blank": tab.get("isBlankSheet", False),
            "is_unusable": not has_rows and not has_cells,
            "estimated_tokens": tab_tokens,
            "cells": cells_meta,
            "cell_drill_count": len(cells_meta),
            # Back-compat : le client web parse ``cell_drill_keys`` comme
            # liste de strings. Conservé tant que la v1 de l'UI vit.
            "cell_drill_keys": [c["key"] for c in cells_meta],
        }


class ReportLLMLimitsHandler(BaseHandler):
    """``GET /api/reports/llm-limits`` — budget tokens du modèle actif.

    Champs supplémentaires (au-delà de ``get_active_model_limits``) :
    - ``absolute_max_tokens`` : cap absolu au-delà duquel même le mode agent
      ne tient pas en RAM serveur. Le frontend l'utilise pour le vrai
      blocage strict.
    - ``agent_mode_threshold`` : seuil au-delà duquel le backend bascule
      en mode agent (tool-loop) au lieu du mode oneshot. Le frontend
      l'utilise pour informer l'utilisateur (« sera généré en mode
      étendu, peut prendre plus de temps »).
    """

    @authenticated
    async def get(self) -> None:
        # Importe le ratio depuis le module planner (single source of truth —
        # review #13 du 2026-05-09 : avant ça le ``* 0.7`` apparaissait
        # dupliqué ici ET dans _check_token_budget ET dans le planner).
        from app.services.reporting.llm_report_planner import (
            _AGENT_MODE_TOKEN_THRESHOLD_RATIO,
        )

        limits = await get_active_model_limits()
        max_input = int(limits.get("max_input_tokens") or 0)
        agent_threshold = int(max_input * _AGENT_MODE_TOKEN_THRESHOLD_RATIO) if max_input > 0 else 0
        self.write_json(
            {
                "success": True,
                "absolute_max_tokens": ReportGenerateLLMHandler._ABSOLUTE_TOKEN_HARD_CAP,
                "agent_mode_threshold": agent_threshold,
                **limits,
            }
        )


class ReportGenerateLLMHandler(BaseHandler):
    """``POST /api/reports/generate-llm`` — génération IA d'un rapport PDF.

    Body JSON :
        * ``sources`` — liste de descripteurs (``workbook`` / ``excel`` / ``csv``).
        * ``title`` — titre proposé (le planner peut en choisir un autre).
        * ``user_prompt`` — consignes libres pour le planner.

    La méthode ``post`` orchestre 6 étapes extraites en méthodes privées ;
    aucune ne dépasse 80 LOC.
    """

    def initialize(self) -> None:
        # Cancel signal partagé entre on_connection_close (set par Tornado
        # quand le client ferme) et la boucle agent (qui le check à chaque
        # tour). Sans ça, un client qui ferme son onglet pendant un mode
        # agent (5+ min) laisse le serveur brûler du LLM jusqu'à
        # finalize_report ou MAX_TURNS — coût $$ + worker bloqué.
        # Pattern aligné app/handlers/ai_config.py:609.
        self._cancel_event: asyncio.Event = asyncio.Event()
        super().initialize() if hasattr(super(), "initialize") else None

    def on_connection_close(self) -> None:
        """Tornado l'appelle quand le client HTTP ferme la connexion."""
        if hasattr(self, "_cancel_event"):
            self._cancel_event.set()
        super().on_connection_close()

    @require_role("admin", "user")
    async def post(self) -> None:
        user = self.current_user

        # 0. Rate-limit (coût $).
        if not _generate_rate_limiter.check(
            f"gen_report_llm:{user.id}",
            _GENERATE_RATE_MAX,
            _GENERATE_RATE_WINDOW_S,
        ):
            raise tornado.web.HTTPError(429, _Messages.TOO_MANY_GENERATIONS)

        # 1. Parse + validate body.
        body = self.get_json_body()
        sources_raw = body.get("sources") or []
        user_title_hint = _clip(body.get("title"), _MAX_USER_PROMPT_LEN)
        user_prompt = _clip(body.get("user_prompt"), _MAX_USER_PROMPT_LEN)
        if not isinstance(sources_raw, list) or not sources_raw:
            raise tornado.web.HTTPError(400, _Messages.AT_LEAST_ONE_SOURCE)

        # 2. Normalisation + 3. expansion workbook + 4. dedup.
        normalized = self._normalize_sources(sources_raw)
        classeur_cache: dict[str, dict[str, Any]] = {}
        expanded = await self._expand_workbook_sources(normalized, user.id, classeur_cache)
        deduped = self._dedup_sources(expanded)

        # 5. Construction des datasets (I/O lourd — off the event loop).
        datasets = await self._build_datasets(deduped, user.id, classeur_cache)

        # 5b. Avertissements qualité des sources (review loop A3-F1/F2) — anti
        # données fausses silencieuses. Le caveat est injecté EN TÊTE du prompt
        # LLM (atteint le planner dans les 2 modes oneshot/agent) pour qu'il ne
        # présente jamais un agrégat tronqué comme exhaustif ; les warnings
        # lisibles sont renvoyés au front (toast) et loggés.
        dataset_warnings, llm_caveat = self._dataset_quality_warnings(datasets)
        effective_user_prompt = user_prompt
        if llm_caveat:
            effective_user_prompt = f"{llm_caveat}\n\n{user_prompt or ''}".strip()
            logger.warning(
                "Rapport LLM généré sur source(s) tronquée(s)/réencodée(s)",
                extra={"user_id": user.id, "warnings": dataset_warnings},
            )

        # 6. Vérification budget tokens.
        limits = await self._check_token_budget(datasets)

        # 7. Plan LLM → PDF → sauvegarde.
        plan = await self._run_planner(
            datasets,
            effective_user_prompt,
            user_title_hint,
            user_id=user.id,
            cancel_event=self._cancel_event,
        )
        pdf_bytes = await self._render_pdf(plan, datasets, user)
        report = await self._persist_report(pdf_bytes, plan, len(sources_raw), user)

        logger.info(
            "Rapport LLM généré",
            extra={
                "user_id": user.id,
                "report_id": report.id,
                "source_count": len(sources_raw),
                "section_count": len(plan.sections),
                "input_tokens_est": limits["input_tokens_est"],
                "input_tokens_max": limits["max_input_tokens"],
            },
        )

        self.write_json(
            {
                "success": True,
                "report": {
                    "id": report.id,
                    "title": report.title,
                    "file_name": report.file_name,
                    "file_format": report.file_format,
                    "download_url": f"/api/reports/{report.id}/download",
                },
                "plan": {
                    "title": plan.title,
                    "section_count": len(plan.sections),
                },
                # A3-F1/F2 : avertissements qualité (troncature 50k / décodage
                # fallback) → le front affiche un toast d'alerte non bloquant.
                "warnings": dataset_warnings,
            }
        )

    # -- étapes extraites (toutes < 80 LOC pour respecter la doctrine archi) --

    @staticmethod
    def _normalize_sources(raw: list) -> list[_NormalizedSource]:
        """Valide la forme de chaque source et la normalise par type."""
        normalized: list[_NormalizedSource] = []
        for src in raw:
            if not isinstance(src, dict):
                raise tornado.web.HTTPError(400, _Messages.INVALID_SOURCE)

            src_type = str(src.get("type") or "workbook").strip().lower()

            if src_type == "workbook":
                filename = _clip(src.get("classeur"), _MAX_FILE_PATH_LEN)
                if not filename:
                    raise tornado.web.HTTPError(400, "classeur manquant dans une source workbook")
                try:
                    tab_index = int(src.get("tab_index", -1))
                except (TypeError, ValueError) as exc:
                    raise tornado.web.HTTPError(400, "tab_index invalide") from exc
                normalized.append(
                    _WorkbookSource(
                        type="workbook",
                        classeur=filename,
                        tab_index=tab_index,
                        cell_key=_clip(src.get("cell_key"), _MAX_CELL_KEY_LEN),
                    )
                )
            elif src_type == "excel":
                path_rel = _clip(src.get("path"), _MAX_FILE_PATH_LEN)
                if not path_rel:
                    raise tornado.web.HTTPError(400, "path manquant dans une source excel")
                normalized.append(
                    _ExcelSource(
                        type="excel",
                        path=path_rel,
                        sheet_name=_clip(src.get("sheet_name"), _MAX_SHEET_NAME_LEN),
                        first_row_as_header=bool(src.get("first_row_as_header", False)),
                    )
                )
            elif src_type == "csv":
                path_rel = _clip(src.get("path"), _MAX_FILE_PATH_LEN)
                if not path_rel:
                    raise tornado.web.HTTPError(400, "path manquant dans une source csv")
                normalized.append(
                    _CsvSource(
                        type="csv",
                        path=path_rel,
                        encoding=_clip(src.get("encoding"), _MAX_ENCODING_LEN),
                        separator=_clip(src.get("separator"), _MAX_SEPARATOR_LEN),
                    )
                )
            else:
                raise tornado.web.HTTPError(400, f"Type de source inconnu: {src_type}")
        return normalized

    async def _expand_workbook_sources(
        self,
        sources: list[_NormalizedSource],
        user_id: int,
        classeur_cache: dict[str, dict[str, Any]],
    ) -> list[_NormalizedSource]:
        """Éclate les sources workbook sans ``cell_key`` en onglet + drill-downs.

        Les sources non-workbook sont passées tel quel. Utilise un cache
        local au request pour ne jamais relire le même ``.afz.json``.
        """
        expanded: list[_NormalizedSource] = []
        for src in sources:
            if src["type"] != "workbook" or src.get("cell_key"):
                expanded.append(src)
                continue

            tab = await self._load_tab(user_id, src["classeur"], src["tab_index"], classeur_cache)
            has_rows = bool(tab.get("rows"))
            cell_details = tab.get("cellDetails") or {}
            has_cells = bool(cell_details)

            if not has_rows and not has_cells:
                raise tornado.web.HTTPError(
                    400,
                    f"Feuille '{tab.get('label', '?')}' entièrement vide",
                )

            if has_rows:
                expanded.append({**src, "cell_key": None})
            for cell_key in cell_details.keys():
                expanded.append({**src, "cell_key": cell_key})
        return expanded

    @staticmethod
    def _dedup_sources(sources: list[_NormalizedSource]) -> list[_NormalizedSource]:
        """Dédoublonne en préservant l'ordre d'apparition (seen-set)."""
        seen: set[tuple] = set()
        deduped: list[_NormalizedSource] = []
        for src in sources:
            if src["type"] == "workbook":
                key: tuple = (
                    "workbook",
                    src["classeur"],
                    src["tab_index"],
                    src["cell_key"] or "",
                )
            elif src["type"] == "excel":
                key = ("excel", src["path"], src.get("sheet_name") or "")
            else:  # csv
                key = ("csv", src["path"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(src)
        return deduped

    @staticmethod
    async def _load_tab(
        user_id: int,
        filename: str,
        tab_index: int,
        cache: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        """Lit un onglet d'un classeur ; mise en cache dans ``cache``."""
        if filename not in cache:
            cache[filename] = await _read_classeur(user_id, filename)
        tabs = cache[filename].get("tabs", [])
        if tab_index < 0 or tab_index >= len(tabs):
            raise tornado.web.HTTPError(400, "tab_index hors limites")
        return tabs[tab_index]

    async def _build_datasets(
        self,
        sources: list[_NormalizedSource],
        user_id: int,
        classeur_cache: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Charge chaque source et retourne les datasets prêts pour le planner."""
        datasets: list[dict[str, Any]] = []
        for idx, src in enumerate(sources):
            dataset = await self._build_one_dataset(idx, src, user_id, classeur_cache)
            datasets.append(dataset)
        return datasets

    async def _build_one_dataset(
        self,
        idx: int,
        src: _NormalizedSource,
        user_id: int,
        classeur_cache: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        """Matérialise un dataset (columns + rows dict) à partir d'une source."""
        if src["type"] == "workbook":
            tab = await self._load_tab(user_id, src["classeur"], src["tab_index"], classeur_cache)
            cell_key = src["cell_key"]
            if cell_key and cell_key not in (tab.get("cellDetails") or {}):
                raise tornado.web.HTTPError(400, f"Source #{idx}: tableau drill-down introuvable")
            if not cell_key and not tab.get("rows"):
                raise tornado.web.HTTPError(400, f"Source #{idx}: feuille sans données tab-level")
            columns, rows, label, _sql = _extract_source_data(tab, cell_key)
            return {
                "id": idx,
                "label": label,
                "columns": columns,
                "rows": _rows_to_dicts(rows, columns),
                "row_count": len(rows),
                # A3-F1 (adversarial) : un onglet de classeur est SOUVENT un SELECT
                # capé — hardcoder ``False`` laissait passer un agrégat partiel
                # SILENCIEUX sur la source de rapport la plus courante.
                "truncated": self._workbook_truncated(tab, cell_key, len(rows)),
            }

        if src["type"] == "excel":
            target = _resolve_user_path(user_id, src["path"])
            if target.suffix.lower() not in (".xlsx", ".xls"):
                raise tornado.web.HTTPError(
                    400,
                    f"Source #{idx}: format non supporté (attendu .xlsx ou .xls)",
                )
            loaded = await asyncio.to_thread(
                load_excel_sheet,
                target,
                src.get("sheet_name"),
                _MAX_EXTERNAL_ROWS,
                src.get("first_row_as_header", False),
            )
            self._require_non_empty_and_unique_columns(idx, loaded, "excel")
            label = f"{Path(src['path']).name} — {loaded.get('sheet_name', '?')}"
            return {
                "id": idx,
                "label": label,
                "columns": loaded["columns"],
                "rows": _rows_to_dicts(loaded["rows"], loaded["columns"]),
                "row_count": len(loaded["rows"]),
                # A3-F1 : propage la troncature (>_MAX_EXTERNAL_ROWS) pour ne pas
                # présenter un agrégat partiel comme exhaustif (données fausses).
                "truncated": bool(loaded.get("truncated")),
            }

        # csv
        target = _resolve_user_path(user_id, src["path"])
        if target.suffix.lower() != ".csv":
            raise tornado.web.HTTPError(400, f"Source #{idx}: format non supporté (attendu .csv)")
        loaded = await asyncio.to_thread(
            load_csv_file,
            target,
            src.get("encoding"),
            src.get("separator"),
            _MAX_EXTERNAL_ROWS,
        )
        self._require_non_empty_and_unique_columns(idx, loaded, "csv")
        return {
            "id": idx,
            "label": Path(src["path"]).name,
            "columns": loaded["columns"],
            "rows": _rows_to_dicts(loaded["rows"], loaded["columns"]),
            "row_count": len(loaded["rows"]),
            # A3-F1/F2 : propage la troncature + l'encodage/séparateur réellement
            # utilisés (fallback latin-1/cp1252 = risque de garbling silencieux).
            "truncated": bool(loaded.get("truncated")),
            "detected_encoding": loaded.get("detected_encoding"),
            "detected_separator": loaded.get("detected_separator"),
        }

    @staticmethod
    def _require_non_empty_and_unique_columns(idx: int, loaded: dict[str, Any], kind: str) -> None:
        columns = loaded.get("columns") or []
        rows = loaded.get("rows") or []
        if not columns or not rows:
            raise tornado.web.HTTPError(
                400,
                f"Source #{idx}: {'onglet Excel' if kind == 'excel' else 'fichier CSV'} vide",
            )
        if len(columns) != len(set(columns)):
            raise tornado.web.HTTPError(
                400,
                f"Source #{idx}: colonnes dupliquées dans "
                f"{'onglet Excel' if kind == 'excel' else 'le CSV'}",
            )

    # Cap absolu (plusieurs ordres de grandeur au-dessus du context window
    # du plus gros modèle). Au-delà, même le mode agent risque l'OOM côté
    # serveur (les agrégations Python tiennent en mémoire). C'est une vraie
    # protection DoS, à distinguer du seuil de bascule oneshot→agent qui,
    # lui, vit côté ``plan_report`` (registre BDD, dynamique).
    #
    # **Statut** (review #9 du 2026-05-09) : protection serveur, pas
    # user-tunable. ~50M tokens = ~200 MB de markdown brut. Ajustement = revue
    # de design, pas option admin. Cohérent avec
    # ``report_planner_agent.MEMORY_HARD_CAP_BYTES`` (100 MB rows estimés).
    _ABSOLUTE_TOKEN_HARD_CAP = 50_000_000

    @staticmethod
    def _workbook_truncated(tab: dict[str, Any], cell_key: str | None, n_rows: int) -> bool:
        """A3-F1 (adversarial) : un onglet/cellule de classeur est-il un snapshot
        SQL TRONQUÉ ? La grille Iris persiste ``truncated`` + ``totalRowCount``
        (et ``row_count`` complet par cellule pour les drill-down). Sans ça, un
        rapport agrégeant 100/5000 lignes était présenté comme exhaustif.
        """
        if cell_key:
            cell = (tab.get("cellDetails") or {}).get(cell_key) or {}
            total = cell.get("row_count")
            return isinstance(total, int) and total > n_rows
        total = tab.get("totalRowCount")
        return bool(tab.get("truncated")) or (isinstance(total, int) and total > n_rows)

    @staticmethod
    def _dataset_quality_warnings(
        datasets: list[dict[str, Any]],
    ) -> tuple[list[str], str | None]:
        """Avertissements qualité des sources (review loop A3-F1/F2).

        Retourne ``(user_warnings, llm_caveat)`` :
        - ``user_warnings`` : messages lisibles (vrai libellé) renvoyés au front
          (toast) — troncature à ``_MAX_EXTERNAL_ROWS`` lignes et/ou décodage CSV
          en fallback (latin-1/cp1252, risque de garbling silencieux).
        - ``llm_caveat`` : consigne injectée EN TÊTE du prompt LLM (référence les
          sources par ``#id``, donc sans PII) pour qu'il ne présente JAMAIS un
          total/agrégat comme exhaustif sur une source tronquée. ``None`` si RAS.

        Anti « données fausses silencieuses » : avant ce fix, un fichier de
        200 000 lignes tronqué à 50 000 produisait un PDF « CA total = X » faux
        sans aucun signal — ni pour l'utilisateur ni pour le LLM.
        """
        user_warnings: list[str] = []
        truncated_ids: list[int] = []
        for ds in datasets:
            label = ds.get("label") or f"Source {ds.get('id')}"
            if ds.get("truncated"):
                truncated_ids.append(ds.get("id"))
                user_warnings.append(
                    f"⚠️ La source « {label} » dépasse {_MAX_EXTERNAL_ROWS} lignes : le "
                    f"rapport ne porte QUE sur les {_MAX_EXTERNAL_ROWS} premières lignes "
                    "chargées — les totaux et agrégats ne sont PAS exhaustifs."
                )
            enc = (ds.get("detected_encoding") or "").lower()
            if enc and enc not in ("utf-8", "utf-8-sig", "ascii"):
                sep = ds.get("detected_separator") or ","
                user_warnings.append(
                    f"La source « {label} » a été décodée en {enc} (séparateur « {sep} ») — "
                    "vérifiez l'absence de caractères mal interprétés."
                )
        llm_caveat = None
        if truncated_ids:
            ids = ", ".join(f"#{i}" for i in truncated_ids)
            llm_caveat = (
                f"AVERTISSEMENT DONNÉES : la/les source(s) {ids} ont été TRONQUÉES à "
                f"{_MAX_EXTERNAL_ROWS} lignes (le fichier d'origine en contient davantage). "
                "Tu ne dois JAMAIS présenter un total, une somme, une moyenne ni aucun autre "
                "agrégat comme exhaustif : précise EXPLICITEMENT dans le texte qu'il ne porte "
                f"que sur les {_MAX_EXTERNAL_ROWS} premières lignes chargées."
            )
        return user_warnings, llm_caveat

    @staticmethod
    async def _check_token_budget(datasets: list[dict[str, Any]]) -> dict[str, Any]:
        limits = await get_active_model_limits()
        # Fail-closed : refuser la génération si aucun provider LLM n'est
        # configuré. Sans ce garde, on tomberait plus loin sur une erreur
        # opaque côté planner (« Aucun provider LLM configuré »).
        if not limits.get("configured"):
            raise tornado.web.HTTPError(
                400,
                "Aucun modèle IA configuré. Renseignez une clé API et un "
                "modèle dans /admin/ai-config avant de générer un rapport.",
            )
        total = sum(
            estimate_tokens({"columns": ds["columns"], "rows": ds["rows"]}) for ds in datasets
        )
        # On ne refuse PLUS sur ``max_input_tokens`` — quand le payload
        # dépasse le budget oneshot, ``plan_report`` bascule vers le mode
        # agent (tool-loop) qui scale à des datasets bien plus gros.
        # Cf. ``llm_report_planner._should_use_agent_mode`` pour la logique
        # de bascule (seuil 70% du context window du modèle actif).
        #
        # On garde toutefois un cap absolu (50M tokens estimés) comme
        # protection DoS — au-delà, même le mode agent ne tient pas en RAM.
        if total > ReportGenerateLLMHandler._ABSOLUTE_TOKEN_HARD_CAP:
            raise tornado.web.HTTPError(
                413,
                f"Volume de données extrême (~{total} tokens estimés > "
                f"{ReportGenerateLLMHandler._ABSOLUTE_TOKEN_HARD_CAP} max). "
                "Réduisez la sélection ou pré-agrégez les données en amont.",
            )
        # Le mode utilisé sera décidé par plan_report() — on retourne juste
        # la projection pour info (le frontend peut l'afficher). On lit
        # le ratio depuis llm_report_planner (single source of truth — pas
        # de magic ``0.7`` qui dériverait de la décision de bascule réelle).
        from app.services.reporting.llm_report_planner import (
            _AGENT_MODE_TOKEN_THRESHOLD_RATIO,
        )

        oneshot_max = int(limits.get("max_input_tokens") or 0)
        agent_threshold = (
            int(oneshot_max * _AGENT_MODE_TOKEN_THRESHOLD_RATIO) if oneshot_max > 0 else 0
        )
        return {
            **limits,
            "input_tokens_est": total,
            "agent_mode_threshold": agent_threshold,
            "would_use_agent_mode": agent_threshold > 0 and total > agent_threshold,
        }

    @staticmethod
    async def _run_planner(
        datasets: list[dict[str, Any]],
        user_prompt: str | None,
        user_title_hint: str | None,
        user_id: int | None = None,
        cancel_event: asyncio.Event | None = None,
    ):
        try:
            return await plan_report(
                datasets,
                user_prompt=user_prompt,
                user_title_hint=user_title_hint,
                user_id=user_id,
                cancel_event=cancel_event,
            )
        except ReportPlanError as exc:
            logger.warning("Plan generation failed: %s", exc)
            raise tornado.web.HTTPError(502, f"{_Messages.LLM_PLAN_UNAVAILABLE} : {exc}") from exc
        except Exception as exc:  # noqa: BLE001 — dernière barrière
            logger.error("Unexpected planner error: %s", exc, exc_info=True)
            raise tornado.web.HTTPError(500, _Messages.LLM_PLAN_UNEXPECTED_ERROR) from exc

    @staticmethod
    async def _render_pdf(plan, datasets: list[dict[str, Any]], user: User) -> bytes:
        """Génère le PDF sur un thread pool (opération CPU-bound)."""
        datasets_by_id = {ds["id"]: ds for ds in datasets}
        try:
            return await asyncio.to_thread(build_pdf_from_plan, plan, datasets_by_id, user)
        except Exception as exc:  # noqa: BLE001 — dernière barrière
            logger.error("PDF generation failed: %s", exc, exc_info=True)
            raise tornado.web.HTTPError(500, _Messages.PDF_BUILD_ERROR) from exc

    @staticmethod
    async def _persist_report(pdf_bytes: bytes, plan, source_count: int, user: User):
        """Nettoie le titre pour en faire un nom de fichier et persiste."""
        safe_base = re.sub(r"[^\w\s\-]", "", plan.title, flags=re.UNICODE).strip()
        safe_base = re.sub(r"\s+", "_", safe_base)[:_MAX_REPORT_FILE_NAME_BASE]
        if not safe_base:
            safe_base = "rapport"
        file_name = f"{safe_base}.pdf"

        storage = get_report_storage()
        try:
            return await storage.save_report(
                file_content=pdf_bytes,
                file_name=file_name,
                title=plan.title,
                file_format="pdf",
                description=(f"Rapport IA généré à partir de {source_count} feuille(s)"),
                report_type="from_classeur_llm",
                user_id=user.id,
            )
        except ValueError as exc:
            logger.warning("save_report validation error: %s", exc)
            raise tornado.web.HTTPError(400, str(exc)) from exc
