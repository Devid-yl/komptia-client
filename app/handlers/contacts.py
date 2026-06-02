"""Handlers REST pour les contacts et listes de diffusion.

Conventions équipe sénior :

* **Thin handler** : parser → ``ContactService`` → response. Aucune logique
  métier ici (testée séparément dans ``test_contacts.py`` côté service).
* **Pas de module-singleton** : ``get_contact_service()`` retourne UNE
  instance partagée mais initialisée à la demande. Avantages : (a) test
  isole peut ``reset_contact_service()`` entre cas, (b) pas d'init au
  module-import (anti-cycle, anti-side-effect au module-load), (c) si
  l'instance prend un état futur (cache local, métriques), elle reste
  swap-able sans toucher les handlers.
* **``self.db_session()``** (BaseHandler) plutôt que ``get_session()``
  brut : commit borné par ``config.server.db_session_timeout_s`` qui
  retourne HTTP 504 propre si SQLite est lock-saturé, plutôt que de
  bloquer l'event-loop indéfiniment.
* **Rate-limit** sur les endpoints coûteux (import CSV, batch members)
  via le pattern ``_check_rate_limit(limiter, user_id, *quota)`` aligné
  sur ``app/handlers/automations.py`` (session B itér 1).
* **Response shape** uniforme via ``_write_service_result`` : succès =
  ``result.data`` direct, erreur = ``{"success": false, "error": ...}``
  avec ``status_code`` issu du service.
* **Pré-validation Content-Length** sur upload CSV : reject 413 avant
  de matérialiser un body de 50 MiB en mémoire si l'utilisateur fournit
  un fichier qui dépasse la borne ``MAX_CSV_IMPORT_BYTES``.
"""

from __future__ import annotations

import logging
from typing import Final

import tornado.web

from app.constants import CONTACTS_MAX_PER_PAGE, MAX_BATCH_MEMBERS, MAX_CSV_IMPORT_BYTES
from app.handlers.base import BaseHandler, authenticated, require_role
from app.services.contacts import ContactService
from app.services.contacts.contact_service import ServiceResult
from app.services.email.contact_mailer_service import (
    MAX_EMAIL_BODY_LENGTH,
    MAX_EMAIL_SUBJECT_LENGTH,
    send_email_to_contacts,
)
from app.utils.rate_limiter import RateLimiter
from app.utils.request_context import current_log_extra

logger = logging.getLogger(__name__)


# ── Pagination defaults ───────────────────────────────────────────────
# Le plafond ``per_page`` n'est PAS redéfini ici : on réutilise la SSoT
# ``app.constants.CONTACTS_MAX_PER_PAGE`` (la même que le service clampe),
# pour éviter un double-cap qui divergerait silencieusement si on change
# la borne canonique sans toucher ce handler.
_DEFAULT_PAGE: Final[int] = 1
_DEFAULT_PER_PAGE: Final[int] = 25


# ── Rate-limit quotas (par utilisateur, fenêtre glissante en secondes) ─
# Import et batch-add sont les deux endpoints mutateurs lourds : on les
# isole pour ne pas bloquer un user via un script de scrap des stats.
RATE_LIMIT_IMPORT_CSV: Final[tuple[int, int]] = (5, 60)
RATE_LIMIT_BATCH_MEMBERS: Final[tuple[int, int]] = (10, 60)
# Send-email : aligné sur ``ReportEmailHandler`` (20 emails/h) — anti-spam
# interne, pas une borne SMTP. Le SMTPClient a son propre retry/backoff.
RATE_LIMIT_SEND_EMAIL: Final[tuple[int, int]] = (20, 3600)

# Limiters au module-scope : une instance par endpoint sensible. Thread-safe.
_import_limiter = RateLimiter()
_batch_limiter = RateLimiter()
_send_email_limiter = RateLimiter()


# ── Service factory (anti-singleton) ──────────────────────────────────

_contact_service: ContactService | None = None


def get_contact_service() -> ContactService:
    """Retourne le ``ContactService`` partagé (init à la demande).

    Évite le module-singleton ``_service = ContactService()`` à l'import,
    qui (a) déclenche un init au module-load — pénible en test, (b)
    interdit le swap pour mock/fake, (c) cache une dépendance globale.
    """
    global _contact_service
    if _contact_service is None:
        _contact_service = ContactService()
    return _contact_service


def reset_contact_service() -> None:
    """Vide l'instance partagée — réservé aux tests qui veulent un service neuf."""
    global _contact_service
    _contact_service = None


# ── Helpers ───────────────────────────────────────────────────────────


def _check_rate_limit(
    limiter: RateLimiter, user_id: int, max_requests: int, window_seconds: int
) -> None:
    """Lève ``HTTPError(429)`` si le rate-limit utilisateur est dépassé.

    Pattern aligné sur ``app/handlers/automations.py`` — un seul endroit
    où décider du status, du message et du format de la clé limiter.
    """
    key = f"user:{user_id}"
    if not limiter.check(key, max_requests=max_requests, window_seconds=window_seconds):
        raise tornado.web.HTTPError(
            429,
            "Trop de requêtes. Veuillez patienter quelques secondes.",
        )


def _parse_pagination(handler: BaseHandler) -> tuple[int, int]:
    """Extrait ``page`` / ``per_page`` depuis les query-params, fail-soft."""
    try:
        page = max(1, int(handler.get_argument("page", str(_DEFAULT_PAGE))))
    except ValueError:
        page = _DEFAULT_PAGE
    try:
        per_page = min(
            CONTACTS_MAX_PER_PAGE,
            max(1, int(handler.get_argument("per_page", str(_DEFAULT_PER_PAGE)))),
        )
    except ValueError:
        per_page = _DEFAULT_PER_PAGE
    return page, per_page


def _coerce_int_id_or_400(value: object, field: str) -> int:
    """Cast un id reçu en JSON body vers ``int`` ou lève HTTPError 400.

    Centralise la conversion (les endpoints REST passent par
    ``_parse_int_or_400`` côté path-param ; côté body on a besoin du même
    contrat).
    """
    if value is None or value == "":
        raise tornado.web.HTTPError(400, f"Champ obligatoire manquant : {field}")
    try:
        return int(value)
    except (ValueError, TypeError) as exc:
        raise tornado.web.HTTPError(400, f"{field} invalide") from exc


def _write_service_result(handler: BaseHandler, result: ServiceResult) -> None:
    """Écrit la réponse JSON cohérente quel que soit le résultat service.

    * Succès → ``result.data`` tel quel + ``status_code`` (200/201).
    * Échec → ``{"success": false, "error": result.error}`` + status code.

    Avant ce helper, chaque handler ré-implémentait
    ``result.data if result.success else {"error": result.error}`` →
    quatre formats clients différents en tout, drift garanti à
    chaque ajout d'endpoint.
    """
    if result.success:
        handler.write_json(result.data, result.status_code)
    else:
        handler.write_json({"success": False, "error": result.error}, result.status_code)


# =====================================================================
# Pages HTML
# =====================================================================


class ContactsPageHandler(BaseHandler):
    """Page de gestion des contacts."""

    @authenticated
    async def get(self) -> None:
        self.render("contacts.html", page_title="Gestion des contacts")


# =====================================================================
# API REST Contacts
# =====================================================================


class ContactsAPIHandler(BaseHandler):
    """API CRUD contacts — GET list / POST create."""

    @authenticated
    async def get(self) -> None:
        page, per_page = _parse_pagination(self)
        # ``sort`` et ``order`` sont validés côté service contre une
        # whitelist (anti-injection + anti-DoS). On laisse passer le
        # paramètre brut, le service tranche.
        sort_arg = self.get_argument("sort", "").strip()
        order_arg = self.get_argument("order", "asc").strip().lower()
        if order_arg not in ("asc", "desc"):
            order_arg = "asc"
        async with self.db_session() as session:
            result = await get_contact_service().list_contacts(
                session,
                self.current_user.id,
                query=self.get_argument("q", "").strip(),
                status=self.get_argument("status", "all"),
                page=page,
                per_page=per_page,
                sort=sort_arg,
                order=order_arg,
            )
        _write_service_result(self, result)

    @require_role("admin", "user")
    async def post(self) -> None:
        data = self.get_json_body()
        async with self.db_session() as session:
            result = await get_contact_service().create_contact(session, self.current_user.id, data)
        _write_service_result(self, result)


class ContactDetailAPIHandler(BaseHandler):
    """API contact unitaire — GET / PUT / DELETE."""

    @authenticated
    async def get(self, contact_id: str) -> None:
        cid = self._parse_int_or_400(contact_id, "contact_id")
        async with self.db_session() as session:
            result = await get_contact_service().get_contact(session, self.current_user.id, cid)
        _write_service_result(self, result)

    @require_role("admin", "user")
    async def put(self, contact_id: str) -> None:
        cid = self._parse_int_or_400(contact_id, "contact_id")
        data = self.get_json_body()
        async with self.db_session() as session:
            result = await get_contact_service().update_contact(
                session, self.current_user.id, cid, data
            )
        _write_service_result(self, result)

    @require_role("admin", "user")
    async def delete(self, contact_id: str) -> None:
        cid = self._parse_int_or_400(contact_id, "contact_id")
        async with self.db_session() as session:
            result = await get_contact_service().delete_contact(session, self.current_user.id, cid)
        _write_service_result(self, result)


class ContactImportAPIHandler(BaseHandler):
    """Import CSV de contacts.

    Garde-fous :
    * Rate-limit (``RATE_LIMIT_IMPORT_CSV``) — anti-DoS sur le parser CSV
      qui appelle ``email_validator`` sur chaque ligne (coûteux).
    * Pre-check ``Content-Length`` → 413 avant de matérialiser le body.
      Tornado ``max_body_size`` est un dernier rempart au niveau IO ;
      ici on évite d'allouer les bytes en mémoire.
    * Validation Content-Type : on accepte ``text/csv`` ou
      ``application/vnd.ms-excel`` ou ``text/plain`` (Excel et certains
      OS publient de drôles de mime-types pour les .csv).
    """

    @require_role("admin", "user")
    async def post(self) -> None:
        _check_rate_limit(_import_limiter, self.current_user.id, *RATE_LIMIT_IMPORT_CSV)

        # Pre-check taille via Content-Length (économise une copie en RAM
        # si l'utilisateur essaie un upload monstrueux). Le contrôle final
        # est dans le service (defense-in-depth).
        content_length_raw = self.request.headers.get("Content-Length")
        if content_length_raw:
            try:
                if int(content_length_raw) > MAX_CSV_IMPORT_BYTES:
                    self.write_json(
                        {
                            "success": False,
                            "error": (
                                f"Fichier trop volumineux "
                                f"(max {MAX_CSV_IMPORT_BYTES // (1024 * 1024)} Mo)"
                            ),
                        },
                        413,
                    )
                    return
            except ValueError:
                pass  # Content-Length non-numeric : laisser passer, le check service tranchera

        if "file" not in self.request.files or not self.request.files["file"]:
            self.write_json({"success": False, "error": "Aucun fichier CSV fourni"}, 400)
            return

        file_info = self.request.files["file"][0]
        filename = file_info.get("filename", "")
        # ``repr(filename)`` évite la log-injection (CWE-117) : un attaquant
        # qui upload ``evil\r\nFAKE LOG ENTRY\r\n.csv`` créerait sinon une
        # fausse entrée dans le journal.
        if filename and not filename.lower().endswith(".csv"):
            logger.warning(
                "CSV upload with non-.csv extension",
                extra=current_log_extra(operation="csv_import", uploaded_filename=repr(filename)),
            )

        # Audit handler-level : trace l'upload accepté avec taille et user.
        # ``current_log_extra()`` hérite request_id + user_id du contexte (DRY).
        logger.info(
            "CSV upload accepted",
            extra=current_log_extra(
                operation="csv_import",
                uploaded_filename=repr(filename),
                size_bytes=len(file_info.get("body", b"")),
            ),
        )

        async with self.db_session() as session:
            result = await get_contact_service().import_csv(
                session, self.current_user.id, file_info["body"]
            )
        _write_service_result(self, result)


class ContactStatsAPIHandler(BaseHandler):
    """Statistiques des contacts."""

    @authenticated
    async def get(self) -> None:
        async with self.db_session() as session:
            result = await get_contact_service().get_stats(session, self.current_user.id)
        _write_service_result(self, result)


# =====================================================================
# API REST Listes de diffusion
# =====================================================================


class DistributionListsAPIHandler(BaseHandler):
    """API listes de diffusion — GET list / POST create."""

    @authenticated
    async def get(self) -> None:
        async with self.db_session() as session:
            result = await get_contact_service().list_distribution_lists(
                session, self.current_user.id
            )
        _write_service_result(self, result)

    @require_role("admin", "user")
    async def post(self) -> None:
        data = self.get_json_body()
        async with self.db_session() as session:
            result = await get_contact_service().create_distribution_list(
                session, self.current_user.id, data
            )
        _write_service_result(self, result)


class DistributionListDetailAPIHandler(BaseHandler):
    """API liste unitaire — GET / PUT / DELETE."""

    @authenticated
    async def get(self, list_id: str) -> None:
        lid = self._parse_int_or_400(list_id, "list_id")
        async with self.db_session() as session:
            result = await get_contact_service().get_distribution_list(
                session, self.current_user.id, lid
            )
        _write_service_result(self, result)

    @require_role("admin", "user")
    async def put(self, list_id: str) -> None:
        lid = self._parse_int_or_400(list_id, "list_id")
        data = self.get_json_body()
        async with self.db_session() as session:
            result = await get_contact_service().update_distribution_list(
                session, self.current_user.id, lid, data
            )
        _write_service_result(self, result)

    @require_role("admin", "user")
    async def delete(self, list_id: str) -> None:
        lid = self._parse_int_or_400(list_id, "list_id")
        async with self.db_session() as session:
            result = await get_contact_service().delete_distribution_list(
                session, self.current_user.id, lid
            )
        _write_service_result(self, result)


class DistributionListMembersAPIHandler(BaseHandler):
    """Gestion des membres d'une liste : POST add / DELETE remove."""

    @require_role("admin", "user")
    async def post(self, list_id: str) -> None:
        lid = self._parse_int_or_400(list_id, "list_id")
        data = self.get_json_body()
        contact_id = _coerce_int_id_or_400(data.get("contact_id"), "contact_id")
        async with self.db_session() as session:
            result = await get_contact_service().add_member(
                session, self.current_user.id, lid, contact_id
            )
        _write_service_result(self, result)

    @require_role("admin", "user")
    async def delete(self, list_id: str, contact_id: str) -> None:
        lid = self._parse_int_or_400(list_id, "list_id")
        cid = self._parse_int_or_400(contact_id, "contact_id")
        async with self.db_session() as session:
            result = await get_contact_service().remove_member(
                session, self.current_user.id, lid, cid
            )
        _write_service_result(self, result)


class DistributionListMembersBatchAPIHandler(BaseHandler):
    """Ajout de membres en batch — rate-limité (lourd côté SQL)."""

    @require_role("admin", "user")
    async def post(self, list_id: str) -> None:
        _check_rate_limit(_batch_limiter, self.current_user.id, *RATE_LIMIT_BATCH_MEMBERS)
        lid = self._parse_int_or_400(list_id, "list_id")
        data = self.get_json_body()
        contact_ids = data.get("contact_ids", [])
        if not isinstance(contact_ids, list):
            self.write_json({"success": False, "error": "contact_ids doit être une liste"}, 400)
            return
        if len(contact_ids) > MAX_BATCH_MEMBERS:
            # Validation rapide côté handler — évite un round-trip BDD inutile.
            self.write_json(
                {
                    "success": False,
                    "error": f"Maximum {MAX_BATCH_MEMBERS} contacts par batch",
                },
                400,
            )
            return

        async with self.db_session() as session:
            result = await get_contact_service().batch_add_members(
                session, self.current_user.id, lid, contact_ids
            )
        _write_service_result(self, result)


# =====================================================================
# API REST Envoi d'email aux contacts
# =====================================================================


class ContactsSendEmailAPIHandler(BaseHandler):
    """``POST /api/contacts/send-email`` — envoi d'un email libre.

    Accepte ``contact_ids`` ET/OU ``list_ids`` pour résoudre les
    destinataires (multi-tenant strict + filtre RGPD ``unsubscribed_at``).
    Pas de pièce jointe — pour de l'envoi avec rapport, utiliser
    ``/api/reports/send-email``. Rate-limited à 20 envois/heure/user.

    Validation côté handler (cohérence + early-return) :
    * Body JSON valide.
    * ``contact_ids`` / ``list_ids`` doivent être des listes d'entiers.
    * ``subject`` et ``body`` non vides, bornés.
    * Au moins un destinataire spécifié (les détails de résolution +
      filtres unsubscribed sont gérés dans le service).
    """

    @require_role("admin", "user")
    async def post(self) -> None:
        _check_rate_limit(_send_email_limiter, self.current_user.id, *RATE_LIMIT_SEND_EMAIL)

        data = self.get_json_body()

        # Type-check STRICT (fix L-02) : ``data.get("contact_ids") or []``
        # accepterait silencieusement ``contact_ids: 0`` / ``"" `` / ``False``
        # comme "missing" et fail-closed avec un message générique. On veut
        # un retour explicite "doit être une liste" sur les types invalides.
        contact_ids_raw = data.get("contact_ids", [])
        list_ids_raw = data.get("list_ids", [])
        if contact_ids_raw is None:
            contact_ids_raw = []
        if list_ids_raw is None:
            list_ids_raw = []
        if not isinstance(contact_ids_raw, list) or not isinstance(list_ids_raw, list):
            self.write_json(
                {"success": False, "error": "contact_ids et list_ids doivent être des listes"},
                400,
            )
            return
        contact_ids = contact_ids_raw
        list_ids = list_ids_raw

        # Cast int + filter — refuse les valeurs non-entières (sécurité).
        try:
            contact_ids_int = [int(x) for x in contact_ids]
            list_ids_int = [int(x) for x in list_ids]
        except (ValueError, TypeError):
            self.write_json(
                {"success": False, "error": "contact_ids et list_ids doivent contenir des entiers"},
                400,
            )
            return

        subject = (data.get("subject") or "").strip()
        body = (data.get("body") or "").strip()

        # Validation longueur côté handler (le service revalide en defense-
        # in-depth, mais on coupe court ici pour ne pas charger les contacts
        # inutilement si la requête est invalide).
        if not subject:
            self.write_json({"success": False, "error": "L'objet est requis"}, 400)
            return
        if len(subject) > MAX_EMAIL_SUBJECT_LENGTH:
            self.write_json(
                {
                    "success": False,
                    "error": f"L'objet dépasse {MAX_EMAIL_SUBJECT_LENGTH} caractères",
                },
                400,
            )
            return
        if not body:
            self.write_json({"success": False, "error": "Le message est requis"}, 400)
            return
        if len(body) > MAX_EMAIL_BODY_LENGTH:
            self.write_json(
                {
                    "success": False,
                    "error": f"Le message dépasse {MAX_EMAIL_BODY_LENGTH} caractères",
                },
                400,
            )
            return
        if not contact_ids_int and not list_ids_int:
            self.write_json({"success": False, "error": "Au moins un destinataire est requis"}, 400)
            return

        # Idempotence : dédoublonne un double-submit rapproché (2 onglets, retry
        # réseau après un succès serveur). Sur doublon dans la fenêtre, on
        # répond explicitement « non renvoyé » (jamais un faux succès silencieux).
        from app.utils.idempotency import email_send_guard, make_idempotency_key

        idem_key = make_idempotency_key(
            kind="contact_email",
            user_id=self.current_user.id,
            subject=subject,
            body=body,
            recipient_ids=[*contact_ids_int, *list_ids_int],
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
            async with self.db_session() as session:
                result = await send_email_to_contacts(
                    session,
                    self.current_user,
                    contact_ids=contact_ids_int,
                    list_ids=list_ids_int,
                    subject=subject,
                    body=body,
                )
        except Exception:
            email_send_guard.release(idem_key)
            raise
        if not result.success:
            # Échec métier → libère la clé pour autoriser un retry légitime.
            email_send_guard.release(idem_key)

        if result.success:
            message = f"Email envoyé à {result.recipients_count} destinataire(s)"
            if result.refused_count:
                message += f". {result.refused_count} refusé(s) par le serveur SMTP."
            self.write_json(
                {
                    "success": True,
                    "message": message,
                    "recipients_count": result.recipients_count,
                    "refused_count": result.refused_count,
                    "skipped_unsubscribed": result.skipped_unsubscribed,
                    "skipped_invalid_email": result.skipped_invalid_email,
                }
            )
        else:
            self.write_json(
                {
                    "success": False,
                    "error": result.error or "Erreur lors de l'envoi",
                    "skipped_unsubscribed": result.skipped_unsubscribed,
                    "skipped_invalid_email": result.skipped_invalid_email,
                },
                result.status_code,
            )
