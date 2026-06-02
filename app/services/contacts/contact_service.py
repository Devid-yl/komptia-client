"""Service contacts & listes de diffusion.

Toute la logique métier vit ici (handlers = thin). Couvre :

* CRUD contacts avec unicité ``(user_id, email)`` et validation/normalisation
  email (``email_validator``, lower-case).
* Recherche paginée avec **escape LIKE** ``\\``, ``%``, ``_`` (sinon un
  ``q="100%"`` matchait n'importe quoi).
* Import CSV avec :
  - Décodage **fail-closed** UTF-8 → cp1252 → reject (Latin-1 décoderait
    n'importe quoi sans erreur, on perd le signal d'encodage cassé).
  - **Sniff dialect** (CSV anglais ``,`` vs Excel FR ``;``).
  - Parsing offload via ``asyncio.to_thread`` — un CSV 5 MiB en synchrone
    peut bloquer l'event-loop plusieurs centaines de ms.
  - **Savepoint par batch** de 200 lignes : une erreur dans le batch N
    rollback uniquement ce batch, pas tout l'import déjà commité.
  - Per-field truncation reportée dans ``stats["truncated"]`` (avant : silent
    truncation cachée à l'utilisateur).
* Distribution lists CRUD + members atomiques :
  - ``add_member`` : INSERT direct + capture d'``IntegrityError`` UNIQUE
    constraint → idempotent sans race condition (ancien check-then-insert
    laissait passer une double insertion si deux clics arrivaient en
    parallèle).
  - ``remove_member`` : check ``rowcount`` post-DELETE → 404 si rien n'a
    bougé (ancien code retournait ``success: true`` même quand le contact
    n'appartenait pas à la liste — info disclosure faible mais surtout
    UX trompeuse).
  - ``batch_add_members`` : dedup ids du request, report de
    ``duplicates_in_request`` séparé de ``skipped_existing``, et
    refus des contacts ``is_unsubscribed`` (RGPD : on ne ré-engage pas
    un désabonné par batch silencieux).

Garde-fous globaux :
* ``ServiceResult.error`` est un message **utilisateur** (FR) — jamais un
  ``str(exc)`` brut qui pourrait fuiter du SQL ou un email tiers.
* Validation : ``strict_bool`` pour les booléens (``"false"`` truanderait
  ``True`` sinon), longueur explicite par champ via
  ``CONTACT_FIELD_LIMITS``.
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Final

from email_validator import EmailNotValidError, validate_email
from sqlalchemy import case, delete, func, insert, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import (
    CONTACT_EMAIL_MAX_LENGTH,
    CONTACT_SEARCH_MAX_LENGTH,
    CONTACT_FIELD_LIMITS,
    CONTACTS_MAX_PER_PAGE,
    CONTACTS_PER_PAGE,
    MAX_BATCH_MEMBERS,
    MAX_CSV_IMPORT_BYTES,
    MAX_CSV_IMPORT_ROWS,
    MAX_DISTRIBUTION_LIST_DESCRIPTION,
    MAX_DISTRIBUTION_LIST_NAME,
)
from app.models.contact import Contact, DistributionList, contact_list_association
from app.utils.request_context import current_log_extra, hash_pii
from app.utils.validators import strict_bool

logger = logging.getLogger(__name__)

# ── CSV constants ─────────────────────────────────────────────────────

# Caractères de début qui déclenchent l'exécution de formules dans
# Excel/Sheets/LibreOffice. Cf. OWASP "CSV Injection" :
# https://owasp.org/www-community/attacks/CSV_Injection
_CSV_FORMULA_PREFIXES: Final[tuple[str, ...]] = ("=", "+", "-", "@", "\t", "\r", "\n")
# Cap "défensif" pour les champs sans limite explicite dans CONTACT_FIELD_LIMITS.
# Pour les champs connus, le cap réel vient du mapping (ex: phone=50, first_name=100).
_CSV_FALLBACK_FIELD_LENGTH: Final[int] = CONTACT_EMAIL_MAX_LENGTH
_CSV_BATCH_FLUSH_SIZE: Final[int] = 200
# Borne csv.field_size_limit : anti-OOM sur une ligne CSV pathologique
# (header géant ou champ unique de plusieurs MiB). 1 MiB est largement
# suffisant pour une cellule notes longue tout en bornant l'allocation.
_CSV_FIELD_SIZE_LIMIT_BYTES: Final[int] = 1 * 1024 * 1024
# ``csv.field_size_limit`` est un état PROCESS-GLOBAL (pas d'override par reader).
# ``_parse_csv_text`` tourne via ``asyncio.to_thread`` (cf. import_csv) : deux
# imports concurrents s'exécutent dans deux threads du pool → sans ce lock, le
# save/restore du global se chevauche (capture imbriquée → pollution persistante,
# OU reset du limit en plein parse du thread voisin = anti-OOM défait / csv.Error
# parasite sur un import VALIDE). Le lock sérialise set→parse→restore entre
# threads. Les autres parsers CSV (datastore, external_sheets) ne touchent pas
# au global, donc on ne change pas leur comportement.
_field_size_limit_lock: Final = threading.Lock()

# Encodages testés dans l'ordre. **Pas** de Latin-1 : ce dernier décode
# n'importe quel byte stream sans lever, donc swallow silencieusement
# les fichiers UTF-8 mal détectés et on récupère du mojibake stocké en BDD.
_CSV_ENCODINGS: Final[tuple[str, ...]] = ("utf-8-sig", "utf-8", "cp1252")

# Champs PUT explicitement modifiables. Tout autre clé du body est ignorée
# (anti mass-assignment).
_CONTACT_PATCHABLE_FIELDS: Final[frozenset[str]] = frozenset(
    {"first_name", "last_name", "company", "phone", "notes", "is_active", "email"}
)
_DISTRIBUTION_LIST_PATCHABLE_FIELDS: Final[frozenset[str]] = frozenset(
    {"name", "description", "is_active"}
)

# Whitelist explicite des colonnes triables côté API. Tout autre ``sort``
# est ignoré (fallback sur le défaut ``created_at desc``). Sans whitelist,
# un user peut trier par n'importe quelle colonne (info-disclosure ou
# DoS via colonne non indexée).
_CONTACT_SORTABLE_FIELDS: Final[frozenset[str]] = frozenset(
    {"email", "first_name", "last_name", "company", "phone", "created_at", "updated_at"}
)

# Headers CSV reconnus (FR + EN). Mapping vers le champ Contact final.
_CSV_HEADER_ALIASES: Final[dict[str, tuple[str, ...]]] = {
    "email": ("email", "courriel", "mail", "adresse_email"),
    "first_name": ("first_name", "prenom", "prénom", "firstname"),
    "last_name": ("last_name", "nom", "lastname", "surname"),
    "company": ("company", "entreprise", "société", "societe"),
    "phone": ("phone", "telephone", "téléphone", "tel", "mobile"),
    "notes": ("notes", "note", "commentaire", "comment"),
}


# ── Result type ───────────────────────────────────────────────────────


@dataclass
class ServiceResult:
    """Retour standardisé d'une opération de service.

    ``status_code`` mappe directement sur la réponse HTTP — décider du
    code dans le service garde la couche handler triviale.
    """

    success: bool
    data: Any = None
    error: str | None = None
    status_code: int = 200


@dataclass
class _CsvImportStats:
    """Compteurs internes d'un import CSV. Sérialisé via ``to_dict``."""

    imported: int = 0
    skipped: int = 0
    errors: int = 0
    truncated: int = 0
    rows_read: int = 0
    truncation_details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "imported": self.imported,
            "skipped": self.skipped,
            "errors": self.errors,
            "truncated": self.truncated,
            "rows_read": self.rows_read,
        }
        # On expose un échantillon (5 max) — pas la liste entière qui peut
        # exploser sur 10 000 lignes truncated.
        if self.truncation_details:
            d["truncation_sample"] = self.truncation_details[:5]
        return d


# ── Helpers purs (testables sans BDD) ─────────────────────────────────


def _decode_csv_body(body: bytes) -> tuple[str, str] | None:
    """Décode des bytes CSV en string. Retourne ``(text, encoding)`` ou ``None``.

    Tente UTF-8-sig (BOM strip), UTF-8 strict, puis cp1252 (Excel
    Windows). Aucun ``latin-1`` : il décoderait n'importe quoi sans
    lever, ce qui transforme un encodage cassé en mojibake silencieux.
    """
    for enc in _CSV_ENCODINGS:
        try:
            return body.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return None


def _sniff_dialect(sample: str) -> csv.Dialect:
    """Détecte le séparateur (``,`` ``;`` ``\\t``). Fallback sur ``,``."""
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        return csv.excel  # défaut "," — comportement pré-refactor


def _normalize_csv_headers(reader_fieldnames: list[str] | None) -> dict[str, str]:
    """Mappe les fieldnames du CSV vers les noms canoniques de Contact.

    Retourne ``{header_in_csv: canonical_field}`` — utiliser pour lire
    chaque row : ``row[mapping[header]]``. Permet d'accepter
    ``"prenom"``, ``"prénom"``, ``"first_name"``, ``"FirstName"`` etc.
    sans conditionnels en boucle hot path.
    """
    if not reader_fieldnames:
        return {}
    mapping: dict[str, str] = {}
    for header in reader_fieldnames:
        normalized = header.strip().lower()
        for canonical, aliases in _CSV_HEADER_ALIASES.items():
            if normalized in aliases:
                mapping[header] = canonical
                break
    return mapping


# ── Service ───────────────────────────────────────────────────────────


class ContactService:
    """Logique métier contacts + listes de diffusion."""

    # ── Validation helpers (statiques, testables sans BDD) ─────────

    @staticmethod
    def validate_email(email: str) -> str | None:
        """Valide et normalise un email. Retourne la forme canonique ou ``None``.

        Pré-borne la longueur AVANT d'appeler ``email_validator`` : une
        chaîne de 1 MB passée au lib peut déclencher un parsing coûteux
        (REDoS faible mais réel). RFC 5321 = 254 octets max sur l'enveloppe
        SMTP — au-delà c'est invalide de toute façon.
        """
        if not email:
            return None
        candidate = email.strip()
        if not candidate or len(candidate) > CONTACT_EMAIL_MAX_LENGTH:
            return None
        try:
            result = validate_email(candidate, check_deliverability=False)
            return result.normalized.lower()
        except EmailNotValidError:
            return None

    @staticmethod
    def validate_contact_fields(data: dict) -> str | None:
        """Vérifie les longueurs des champs contact. Retourne un message FR ou ``None``."""
        for field_name, max_len in CONTACT_FIELD_LIMITS.items():
            value = data.get(field_name)
            if value and isinstance(value, str) and len(value) > max_len:
                return f"Le champ '{field_name}' dépasse la limite de {max_len} caractères"
        return None

    @staticmethod
    def _sanitize_csv_field(
        value: str | None, max_length: int = _CSV_FALLBACK_FIELD_LENGTH
    ) -> tuple[str | None, bool]:
        """Nettoie un champ CSV avec un cap **par champ**.

        Retourne ``(valeur_clean, was_truncated)``. ``max_length`` doit venir
        de ``CONTACT_FIELD_LIMITS`` pour le champ correspondant — un nom
        tronqué à 255 alors que la BDD borne à 100 produirait une
        ``DataError`` à l'INSERT (Postgres) ou un mojibake silencieux
        (SQLite, qui ignore les caps). La caller est responsable
        d'incrémenter le compteur de truncation pour ne pas cacher la
        perte de donnée à l'utilisateur.

        Ordre : strip → formula-escape → truncate. Si on tronquait avant
        l'escape, un champ ``"=SUM(...)" * 100`` (250+ chars) tronqué à
        100 puis prefixé ``'`` ferait 101 chars → DataError Postgres.
        """
        if value is None:
            return None, False
        value = value.strip()
        if value and value[0] in _CSV_FORMULA_PREFIXES:
            # Escape AVANT truncate pour que le ``'`` soit comptabilisé
            # dans la borne max_length. Sinon truncate(N) + prefix(1) = N+1.
            value = "'" + value
        was_truncated = False
        if len(value) > max_length:
            value = value[:max_length]
            was_truncated = True
        return (value or None), was_truncated

    @staticmethod
    def _strip_field(data: dict, field_name: str) -> str | None:
        """Extrait + strip un champ string. Retourne ``None`` si vide après strip."""
        val = (data.get(field_name) or "").strip()
        return val or None

    @staticmethod
    def _escape_like_pattern(pattern: str) -> str:
        """Escape les wildcards LIKE/ILIKE (``\\`` ``%`` ``_``).

        Sans ça, ``q="50%"`` matcherait n'importe quel email, et
        ``q="a_b"`` confondrait avec ``"acb"`` etc.
        """
        return pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    # ── Contacts CRUD ──────────────────────────────────────────────

    async def list_contacts(
        self,
        session: AsyncSession,
        user_id: int,
        query: str = "",
        status: str = "all",
        page: int = 1,
        per_page: int = CONTACTS_PER_PAGE,
        sort: str = "",
        order: str = "asc",
    ) -> ServiceResult:
        """Liste paginée des contacts, recherche multi-champs + filtre statut + tri.

        ``sort`` est validé contre ``_CONTACT_SORTABLE_FIELDS`` (anti
        SQL-injection ET anti-DoS : un tri sur colonne non indexée peut
        scanner la table). ``order`` accepte ``asc`` ou ``desc``.
        Recherche multi-colonnes : email + first_name + last_name + company.
        """
        page = max(1, page)
        per_page = min(CONTACTS_MAX_PER_PAGE, max(1, per_page))

        q = select(Contact).where(Contact.user_id == user_id)

        if query:
            # F5 (review loop) : cap la longueur de la recherche côté SERVEUR
            # (SSoT) — le ``maxlength`` HTML est contournable via l'API/curl. Un
            # terme de 200+ chars n'a aucun sens métier ; on tronque pour borner
            # le coût du LIKE multi-colonnes.
            query = query[:CONTACT_SEARCH_MAX_LENGTH]
            like = f"%{self._escape_like_pattern(query)}%"
            q = q.where(
                or_(
                    Contact.email.ilike(like, escape="\\"),
                    Contact.first_name.ilike(like, escape="\\"),
                    Contact.last_name.ilike(like, escape="\\"),
                    Contact.company.ilike(like, escape="\\"),
                )
            )

        if status == "active":
            q = q.where(Contact.is_active.is_(True))
        elif status == "inactive":
            q = q.where(Contact.is_active.is_(False))

        count_q = select(func.count()).select_from(q.subquery())
        total = (await session.execute(count_q)).scalar() or 0
        total_pages = max(1, (total + per_page - 1) // per_page)

        # Tri whitelisté : ``sort`` doit être dans la liste autorisée,
        # sinon fallback sur le défaut ``created_at desc``.
        if sort and sort in _CONTACT_SORTABLE_FIELDS:
            sort_col = getattr(Contact, sort)
            sort_col = sort_col.desc() if order == "desc" else sort_col.asc()
            # Tie-breaker : id stable, sinon ordre arbitraire entre rows
            # avec valeur identique sur la colonne triée.
            q = q.order_by(sort_col, Contact.id.asc())
        else:
            q = q.order_by(Contact.created_at.desc(), Contact.id.asc())

        q = q.offset((page - 1) * per_page).limit(per_page)
        rows = (await session.execute(q)).scalars().all()

        return ServiceResult(
            success=True,
            data={
                "contacts": [c.to_dict() for c in rows],
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": total_pages,
                "sort": sort if sort in _CONTACT_SORTABLE_FIELDS else "",
                "order": order if order in ("asc", "desc") else "asc",
            },
        )

    async def create_contact(
        self, session: AsyncSession, user_id: int, data: dict
    ) -> ServiceResult:
        """Crée un nouveau contact (unique par ``(user_id, email)``)."""
        raw_email = (data.get("email") or "").strip()
        if not raw_email:
            return ServiceResult(False, error="L'email est requis", status_code=400)

        email = self.validate_email(raw_email)
        if not email:
            return ServiceResult(False, error="Format d'email invalide", status_code=400)

        field_err = self.validate_contact_fields(data)
        if field_err:
            return ServiceResult(False, error=field_err, status_code=400)

        existing = (
            await session.execute(
                select(Contact).where(Contact.user_id == user_id, Contact.email == email)
            )
        ).scalar_one_or_none()
        if existing:
            return ServiceResult(
                False, error="Un contact avec cet email existe déjà", status_code=409
            )

        contact = Contact(
            user_id=user_id,
            email=email,
            first_name=self._strip_field(data, "first_name"),
            last_name=self._strip_field(data, "last_name"),
            company=self._strip_field(data, "company"),
            phone=self._strip_field(data, "phone"),
            notes=self._strip_field(data, "notes"),
        )
        # Savepoint plutôt que ``session.rollback()`` direct : sur un
        # IntegrityError causé par une race UNIQUE (deux POST simultanés
        # avec le même email), un rollback global annulerait toute la
        # transaction de la requête. Le savepoint isole l'INSERT.
        # IMPORTANT : on catch toute Exception (pas que IntegrityError)
        # pour ne PAS laisser le savepoint dangling en cas de
        # ``OperationalError`` (BDD lock), ``CancelledError``, etc.
        # Sinon le prochain ``session.refresh()`` lève PendingRollbackError.
        savepoint = await session.begin_nested()
        session.add(contact)
        try:
            await session.flush()
            await savepoint.commit()
        except IntegrityError:
            await savepoint.rollback()
            logger.info(
                "Contact create rejected: duplicate email",
                extra=current_log_extra(operation="contact_create", reason="duplicate_email"),
            )
            return ServiceResult(
                False, error="Un contact avec cet email existe déjà", status_code=409
            )
        except Exception:
            # Garde-fou : tout autre échec (DB locked, cancelled, etc.)
            # → rollback savepoint puis re-raise pour que le caller (ou
            # ``db_session()``) traite l'erreur. Sans ça, le savepoint
            # reste ouvert et corrompt la session.
            await savepoint.rollback()
            raise
        await session.refresh(contact)

        logger.info(
            "Contact created",
            extra=current_log_extra(operation="contact_create", contact_id=contact.id),
        )
        return ServiceResult(True, data={"contact": contact.to_dict()}, status_code=201)

    async def update_contact(
        self, session: AsyncSession, user_id: int, contact_id: int, data: dict
    ) -> ServiceResult:
        """Met à jour un contact. Whitelist explicite + ``strict_bool``."""
        contact = (
            await session.execute(
                select(Contact).where(Contact.id == contact_id, Contact.user_id == user_id)
            )
        ).scalar_one_or_none()
        if not contact:
            return ServiceResult(False, error="Contact introuvable", status_code=404)

        field_err = self.validate_contact_fields(data)
        if field_err:
            return ServiceResult(False, error=field_err, status_code=400)

        # Audit : si le caller envoie un champ inconnu (ex: ``user_id``,
        # ``id``, faute de frappe…), on logue pour aider le debug. Aligne
        # le comportement avec ``update_distribution_list``.
        unknown = set(data.keys()) - _CONTACT_PATCHABLE_FIELDS
        if unknown:
            logger.info(
                "Update contact %s : champs ignorés (whitelist) : %s",
                contact_id,
                sorted(unknown),
            )

        # Whitelist : tout champ non-listé est ignoré (mass-assignment defense).
        for field_name in _CONTACT_PATCHABLE_FIELDS - {"email", "is_active"}:
            if field_name in data:
                value = data[field_name]
                if isinstance(value, str):
                    value = value.strip() or None
                setattr(contact, field_name, value)

        if "is_active" in data:
            try:
                contact.is_active = strict_bool(data["is_active"], "is_active")
            except ValueError as exc:
                return ServiceResult(False, error=str(exc), status_code=400)

        # Email : revalidation + check d'unicité avant flush.
        if "email" in data and data["email"] != contact.email:
            new_email = self.validate_email(data["email"])
            if not new_email:
                return ServiceResult(False, error="Format d'email invalide", status_code=400)
            dup = (
                await session.execute(
                    select(Contact).where(Contact.user_id == user_id, Contact.email == new_email)
                )
            ).scalar_one_or_none()
            if dup:
                return ServiceResult(
                    False, error="Email déjà utilisé par un autre contact", status_code=409
                )
            contact.email = new_email

        # Savepoint pour isoler le flush du UPDATE. Cf. ``create_contact``.
        savepoint = await session.begin_nested()
        try:
            await session.flush()
            await savepoint.commit()
        except IntegrityError:
            await savepoint.rollback()
            logger.info(
                "Contact update rejected: duplicate email",
                extra=current_log_extra(
                    operation="contact_update", contact_id=contact_id, reason="duplicate_email"
                ),
            )
            return ServiceResult(
                False, error="Email déjà utilisé par un autre contact", status_code=409
            )
        except Exception:
            await savepoint.rollback()
            raise
        await session.refresh(contact)

        logger.info(
            "Contact updated",
            extra=current_log_extra(operation="contact_update", contact_id=contact_id),
        )
        return ServiceResult(True, data={"contact": contact.to_dict()})

    async def delete_contact(
        self, session: AsyncSession, user_id: int, contact_id: int
    ) -> ServiceResult:
        """Supprime un contact. 404 silencieux si non-owner (anti-énumération)."""
        contact = (
            await session.execute(
                select(Contact).where(Contact.id == contact_id, Contact.user_id == user_id)
            )
        ).scalar_one_or_none()
        if not contact:
            return ServiceResult(False, error="Contact introuvable", status_code=404)

        # Capture les valeurs AVANT delete (sinon l'objet est expiré).
        deleted_email = contact.email
        await session.delete(contact)
        # Audit trail RGPD-safe : on logue un HASH de l'email (pas l'email
        # lui-même). Permet de corréler "create puis delete du même contact"
        # sans stocker la PII en clair pendant 30 jours de rétention logs.
        logger.info(
            "Contact deleted",
            extra=current_log_extra(
                operation="contact_delete",
                contact_id=contact_id,
                deleted_email_hash=hash_pii(deleted_email),
            ),
        )
        return ServiceResult(True, data={"message": "Contact supprimé"})

    async def get_contact(
        self, session: AsyncSession, user_id: int, contact_id: int
    ) -> ServiceResult:
        """Récupère un contact par id (404 anti-énumération si non-owner)."""
        contact = (
            await session.execute(
                select(Contact).where(Contact.id == contact_id, Contact.user_id == user_id)
            )
        ).scalar_one_or_none()
        if not contact:
            return ServiceResult(False, error="Contact introuvable", status_code=404)
        return ServiceResult(True, data={"contact": contact.to_dict()})

    async def get_stats(self, session: AsyncSession, user_id: int) -> ServiceResult:
        """Compteurs ``total/active/inactive`` en une seule passe SQL."""
        # CASE WHEN pour le count actif : portable SQLite + Postgres,
        # évite un 2ᵉ round-trip pour un dashboard sollicité à chaque page.
        result = await session.execute(
            select(
                func.count(Contact.id),
                func.coalesce(func.sum(case((Contact.is_active.is_(True), 1), else_=0)), 0),
            ).where(Contact.user_id == user_id)
        )
        total, active = result.one()
        total = int(total or 0)
        active = int(active or 0)
        return ServiceResult(
            True, data={"total": total, "active": active, "inactive": total - active}
        )

    # ── CSV import ─────────────────────────────────────────────────

    async def import_csv(
        self, session: AsyncSession, user_id: int, file_body: bytes
    ) -> ServiceResult:
        """Importe des contacts depuis un body CSV.

        Pipeline : sizecheck → decode → sniff → parse (off-thread) →
        boucle insert avec savepoint par batch → stats détaillées.
        """
        if len(file_body) > MAX_CSV_IMPORT_BYTES:
            return ServiceResult(
                False,
                error=f"Fichier trop volumineux (max {MAX_CSV_IMPORT_BYTES // (1024 * 1024)} Mo)",
                status_code=400,
            )

        decoded = _decode_csv_body(file_body)
        if decoded is None:
            return ServiceResult(
                False,
                error="Encodage du fichier non supporté (UTF-8 ou Windows-1252 attendu)",
                status_code=400,
            )
        text, encoding_used = decoded
        # cp1252 décode tout octet entre 0x00-0xFF sans lever — utile
        # pour les CSV Excel FR mais piège silencieux si le vrai encoding
        # est UTF-16/UTF-32. On loggue un warning audit-friendly.
        if encoding_used == "cp1252":
            logger.warning(
                "Import CSV decoded as cp1252 (Excel FR fallback) — verify no mojibake",
                extra=current_log_extra(operation="csv_import", encoding="cp1252"),
            )

        # Le parsing CSV est CPU-bound + alloue beaucoup → off-thread.
        # Sur un fichier 5 MiB, ça libère l'event-loop pour les autres
        # requêtes pendant ~100-300 ms.
        try:
            rows = await asyncio.to_thread(_parse_csv_text, text)
        except csv.Error as exc:
            return ServiceResult(False, error=f"CSV invalide : {exc}", status_code=400)

        if not rows:
            return ServiceResult(True, data=_CsvImportStats(rows_read=0).to_dict())

        header_mapping = _normalize_csv_headers(list(rows[0].keys()))
        if "email" not in header_mapping.values():
            return ServiceResult(
                False,
                error="Le fichier CSV doit contenir une colonne 'email' (ou 'mail', 'courriel')",
                status_code=400,
            )

        stats = _CsvImportStats()

        # Pre-load des emails existants (évite N+1 SELECT sur l'unicité).
        existing_emails_result = await session.execute(
            select(Contact.email).where(Contact.user_id == user_id)
        )
        existing_emails: set[str] = {row[0] for row in existing_emails_result}
        seen_emails: set[str] = set()

        # Buffer batch : on stage en mémoire, on flush par paquet de 200
        # avec savepoint, pour qu'une erreur SQL au row N ne rollback que
        # le batch courant (200 rows max perdus, pas tout l'import).
        batch: list[Contact] = []

        def _get_field(row: dict, canonical: str) -> str:
            """Retrouve la valeur depuis le row CSV via le mapping canonique."""
            for raw_header, canon in header_mapping.items():
                if canon == canonical:
                    return row.get(raw_header) or ""
            return ""

        for i, row in enumerate(rows):
            stats.rows_read += 1
            if i >= MAX_CSV_IMPORT_ROWS:
                logger.warning(
                    "CSV import truncated at row limit",
                    extra=current_log_extra(
                        operation="csv_import",
                        max_rows=MAX_CSV_IMPORT_ROWS,
                        total_rows=len(rows),
                    ),
                )
                stats.errors += len(rows) - i  # comptabiliser les rows abandonnées
                break

            email_raw = _get_field(row, "email")
            email = self.validate_email(email_raw) if email_raw else None
            if not email:
                stats.errors += 1
                continue

            if email in existing_emails or email in seen_emails:
                stats.skipped += 1
                continue
            seen_emails.add(email)

            try:
                # Cap par champ depuis CONTACT_FIELD_LIMITS pour éviter
                # les DataError au flush Postgres et le mojibake silencieux
                # SQLite. Aligne import CSV ↔ schéma SQL ↔ validation JSON.
                first_name, t1 = self._sanitize_csv_field(
                    _get_field(row, "first_name"), CONTACT_FIELD_LIMITS["first_name"]
                )
                last_name, t2 = self._sanitize_csv_field(
                    _get_field(row, "last_name"), CONTACT_FIELD_LIMITS["last_name"]
                )
                company, t3 = self._sanitize_csv_field(
                    _get_field(row, "company"), CONTACT_FIELD_LIMITS["company"]
                )
                phone, t4 = self._sanitize_csv_field(
                    _get_field(row, "phone"), CONTACT_FIELD_LIMITS["phone"]
                )
                notes, t5 = self._sanitize_csv_field(
                    _get_field(row, "notes"), CONTACT_FIELD_LIMITS["notes"]
                )
            except (ValueError, TypeError) as exc:
                # Mauvaise donnée user, pas un échec serveur : warning suffit.
                logger.warning(
                    "CSV row sanitize failed",
                    extra=current_log_extra(
                        operation="csv_import_sanitize",
                        row=i + 1,
                        exc_type=type(exc).__name__,
                    ),
                )
                stats.errors += 1
                continue

            if any((t1, t2, t3, t4, t5)):
                stats.truncated += 1
                if len(stats.truncation_details) < 5:
                    stats.truncation_details.append(f"ligne {i + 1} ({email})")

            batch.append(
                Contact(
                    user_id=user_id,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    company=company,
                    phone=phone,
                    notes=notes,
                )
            )

            if len(batch) >= _CSV_BATCH_FLUSH_SIZE:
                await self._flush_batch(session, batch, stats)
                batch = []

        # Flush du dernier batch incomplet.
        if batch:
            await self._flush_batch(session, batch, stats)

        logger.info(
            "CSV import completed",
            extra=current_log_extra(
                operation="csv_import",
                encoding=encoding_used,
                imported=stats.imported,
                skipped=stats.skipped,
                errors=stats.errors,
                truncated=stats.truncated,
                rows_read=stats.rows_read,
            ),
        )
        result_data = stats.to_dict()
        if encoding_used == "cp1252":
            # cp1252 décode n'importe quel octet sans lever → un vrai fichier
            # UTF-8/UTF-16 mal détecté passe en mojibake SILENCIEUX. On
            # prévient l'utilisateur pour qu'il vérifie les accents plutôt que
            # de stocker des données corrompues sans aucun signal.
            result_data["warning"] = (
                "Fichier décodé en Windows-1252 (fallback Excel FR). "
                "Vérifiez l'absence de caractères corrompus (accents) dans les "
                "contacts importés ; ré-enregistrez en UTF-8 si besoin."
            )
        return ServiceResult(True, data=result_data)

    @staticmethod
    async def _flush_batch(
        session: AsyncSession, batch: list[Contact], stats: _CsvImportStats
    ) -> None:
        """Flush un batch dans un savepoint isolé.

        Si une erreur d'intégrité (rare ici grâce au pre-check des emails
        existants, mais possible si race ou contrainte autre) survient,
        on rollback uniquement le savepoint et on ré-essaie row-par-row
        pour identifier les rows fautives.
        """
        savepoint = await session.begin_nested()
        try:
            session.add_all(batch)
            await session.flush()
            await savepoint.commit()
            stats.imported += len(batch)
        except IntegrityError as exc:
            await savepoint.rollback()
            logger.warning(
                "CSV batch rollback — fallback row-by-row",
                extra=current_log_extra(
                    operation="csv_import_batch",
                    batch_size=len(batch),
                    exc_type=type(exc).__name__,
                ),
            )
            # Fallback : retry row-par-row pour ne pas perdre les bons
            # rows du batch à cause d'un seul mauvais.
            for contact in batch:
                inner = await session.begin_nested()
                try:
                    session.add(contact)
                    await session.flush()
                    await inner.commit()
                    stats.imported += 1
                except (IntegrityError, SQLAlchemyError):
                    await inner.rollback()
                    stats.errors += 1
        except SQLAlchemyError as exc:
            await savepoint.rollback()
            logger.error(
                "CSV batch SQL error",
                extra=current_log_extra(
                    operation="csv_import_batch",
                    batch_size=len(batch),
                    exc_type=type(exc).__name__,
                ),
            )
            stats.errors += len(batch)

    # ── Distribution Lists ─────────────────────────────────────────

    async def list_distribution_lists(self, session: AsyncSession, user_id: int) -> ServiceResult:
        """Liste les listes de diffusion + count membres (sans lazy-load)."""
        count_subq = (
            select(
                contact_list_association.c.distribution_list_id,
                func.count(contact_list_association.c.contact_id).label("member_count"),
            )
            .group_by(contact_list_association.c.distribution_list_id)
            .subquery()
        )

        result = await session.execute(
            select(DistributionList, func.coalesce(count_subq.c.member_count, 0))
            .outerjoin(count_subq, DistributionList.id == count_subq.c.distribution_list_id)
            .where(DistributionList.user_id == user_id)
            .order_by(DistributionList.name)
        )

        data = [dl.to_dict(contact_count=count) for dl, count in result.all()]
        return ServiceResult(True, data={"lists": data})

    async def create_distribution_list(
        self, session: AsyncSession, user_id: int, data: dict
    ) -> ServiceResult:
        """Crée une nouvelle liste de diffusion (unique par ``(user_id, name)``)."""
        name = (data.get("name") or "").strip()
        if not name:
            return ServiceResult(False, error="Le nom est requis", status_code=400)
        if len(name) > MAX_DISTRIBUTION_LIST_NAME:
            return ServiceResult(
                False,
                error=f"Le nom dépasse la limite de {MAX_DISTRIBUTION_LIST_NAME} caractères",
                status_code=400,
            )

        description = (data.get("description") or "").strip() or None
        if description and len(description) > MAX_DISTRIBUTION_LIST_DESCRIPTION:
            return ServiceResult(
                False,
                error=f"La description dépasse {MAX_DISTRIBUTION_LIST_DESCRIPTION} caractères",
                status_code=400,
            )

        existing = (
            await session.execute(
                select(DistributionList).where(
                    DistributionList.user_id == user_id, DistributionList.name == name
                )
            )
        ).scalar_one_or_none()
        if existing:
            return ServiceResult(False, error="Une liste avec ce nom existe déjà", status_code=409)

        dl = DistributionList(user_id=user_id, name=name, description=description)
        savepoint = await session.begin_nested()
        session.add(dl)
        try:
            await session.flush()
            await savepoint.commit()
        except IntegrityError:
            await savepoint.rollback()
            logger.info(
                "List create rejected: duplicate name",
                extra=current_log_extra(operation="list_create", reason="duplicate_name"),
            )
            return ServiceResult(False, error="Une liste avec ce nom existe déjà", status_code=409)
        except Exception:
            await savepoint.rollback()
            raise
        await session.refresh(dl)

        logger.info(
            "List created",
            extra=current_log_extra(operation="list_create", list_id=dl.id),
        )
        return ServiceResult(True, data={"list": dl.to_dict(contact_count=0)}, status_code=201)

    async def get_distribution_list(
        self, session: AsyncSession, user_id: int, list_id: int
    ) -> ServiceResult:
        """Récupère une liste avec ses contacts (1 round-trip JOIN explicite)."""
        dl = (
            await session.execute(
                select(DistributionList).where(
                    DistributionList.id == list_id, DistributionList.user_id == user_id
                )
            )
        ).scalar_one_or_none()
        if not dl:
            return ServiceResult(False, error="Liste introuvable", status_code=404)

        contacts_q = (
            select(Contact)
            .join(contact_list_association)
            .where(contact_list_association.c.distribution_list_id == dl.id)
            .order_by(Contact.email)
        )
        contacts = (await session.execute(contacts_q)).scalars().all()

        return ServiceResult(
            True,
            data={
                "list": dl.to_dict(contact_count=len(contacts)),
                "contacts": [c.to_dict() for c in contacts],
            },
        )

    async def update_distribution_list(
        self, session: AsyncSession, user_id: int, list_id: int, data: dict
    ) -> ServiceResult:
        """Met à jour une liste. Whitelist + validation longueur + strict_bool."""
        dl = (
            await session.execute(
                select(DistributionList).where(
                    DistributionList.id == list_id, DistributionList.user_id == user_id
                )
            )
        ).scalar_one_or_none()
        if not dl:
            return ServiceResult(False, error="Liste introuvable", status_code=404)

        # Whitelist : ignore tout champ hors {name, description, is_active}.
        unknown = set(data.keys()) - _DISTRIBUTION_LIST_PATCHABLE_FIELDS
        if unknown:
            logger.info(
                "List update: ignored fields (whitelist)",
                extra=current_log_extra(
                    operation="list_update", list_id=list_id, ignored_fields=sorted(unknown)
                ),
            )

        if "name" in data:
            name = (data.get("name") or "").strip()
            if not name:
                return ServiceResult(False, error="Le nom ne peut pas être vide", status_code=400)
            if len(name) > MAX_DISTRIBUTION_LIST_NAME:
                return ServiceResult(
                    False,
                    error=f"Le nom dépasse la limite de {MAX_DISTRIBUTION_LIST_NAME} caractères",
                    status_code=400,
                )
            dl.name = name

        if "description" in data:
            description = data["description"]
            if description is None:
                dl.description = None
            elif isinstance(description, str):
                description = description.strip()
                if len(description) > MAX_DISTRIBUTION_LIST_DESCRIPTION:
                    return ServiceResult(
                        False,
                        error=f"La description dépasse {MAX_DISTRIBUTION_LIST_DESCRIPTION} caractères",
                        status_code=400,
                    )
                dl.description = description or None
            else:
                return ServiceResult(
                    False, error="description doit être une chaîne ou null", status_code=400
                )

        if "is_active" in data:
            try:
                dl.is_active = strict_bool(data["is_active"], "is_active")
            except ValueError as exc:
                return ServiceResult(False, error=str(exc), status_code=400)

        savepoint = await session.begin_nested()
        try:
            await session.flush()
            await savepoint.commit()
        except IntegrityError:
            await savepoint.rollback()
            logger.info(
                "List update rejected: duplicate name",
                extra=current_log_extra(
                    operation="list_update", list_id=list_id, reason="duplicate_name"
                ),
            )
            return ServiceResult(False, error="Une liste avec ce nom existe déjà", status_code=409)
        except Exception:
            await savepoint.rollback()
            raise
        await session.refresh(dl)

        count_q = (
            select(func.count())
            .select_from(contact_list_association)
            .where(contact_list_association.c.distribution_list_id == dl.id)
        )
        contact_count = (await session.execute(count_q)).scalar() or 0

        logger.info(
            "List updated",
            extra=current_log_extra(operation="list_update", list_id=list_id),
        )
        return ServiceResult(True, data={"list": dl.to_dict(contact_count=contact_count)})

    async def delete_distribution_list(
        self, session: AsyncSession, user_id: int, list_id: int
    ) -> ServiceResult:
        """Supprime une liste (404 anti-énumération si non-owner)."""
        dl = (
            await session.execute(
                select(DistributionList).where(
                    DistributionList.id == list_id, DistributionList.user_id == user_id
                )
            )
        ).scalar_one_or_none()
        if not dl:
            return ServiceResult(False, error="Liste introuvable", status_code=404)

        # Capture du nom AVANT delete (pas de lazy-load après cascade).
        # Hash plutôt que clear : un nom de liste peut révéler un client
        # ("Liste M. Dupont" — RGPD).
        deleted_name = dl.name
        await session.delete(dl)
        logger.info(
            "List deleted",
            extra=current_log_extra(
                operation="list_delete",
                list_id=list_id,
                deleted_name_hash=hash_pii(deleted_name),
            ),
        )
        return ServiceResult(True, data={"message": "Liste supprimée"})

    # ── Members ────────────────────────────────────────────────────

    async def add_member(
        self, session: AsyncSession, user_id: int, list_id: int, contact_id: int
    ) -> ServiceResult:
        """Ajoute un contact à une liste, atomique + RGPD-safe.

        * Vérifie ownership de la liste ET du contact (404 si l'un manque).
        * Refuse les contacts ``is_unsubscribed`` (RGPD : pas de
          ré-engagement silencieux d'un désabonné).
        * INSERT direct + capture d'``IntegrityError`` UNIQUE constraint
          (composite PK) → idempotent même si deux clics arrivent en
          parallèle (ancien check-then-insert avait une race).
        """
        dl = (
            await session.execute(
                select(DistributionList).where(
                    DistributionList.id == list_id, DistributionList.user_id == user_id
                )
            )
        ).scalar_one_or_none()
        contact = (
            await session.execute(
                select(Contact).where(Contact.id == contact_id, Contact.user_id == user_id)
            )
        ).scalar_one_or_none()

        if not dl or not contact:
            return ServiceResult(False, error="Liste ou contact introuvable", status_code=404)

        if contact.is_unsubscribed:
            return ServiceResult(
                False,
                error="Ce contact s'est désabonné et ne peut plus être ajouté à une liste",
                status_code=409,
            )

        savepoint = await session.begin_nested()
        try:
            await session.execute(
                insert(contact_list_association).values(
                    distribution_list_id=list_id, contact_id=contact_id
                )
            )
            await savepoint.commit()
            return ServiceResult(
                True,
                data={
                    "message": "Contact ajouté à la liste",
                    "was_already_member": False,
                },
            )
        except IntegrityError:
            # Contrainte UNIQUE composite (PK) → déjà membre. Idempotent.
            # ``was_already_member`` permet au frontend d'afficher "déjà
            # membre" en jaune au lieu de "ajouté" en vert sans parser le
            # message FR (qui peut changer en i18n).
            await savepoint.rollback()
            return ServiceResult(
                True,
                data={
                    "message": "Contact déjà membre de la liste",
                    "was_already_member": True,
                },
            )

    async def remove_member(
        self, session: AsyncSession, user_id: int, list_id: int, contact_id: int
    ) -> ServiceResult:
        """Retire un contact d'une liste. 404 si rien n'a bougé."""
        dl = (
            await session.execute(
                select(DistributionList).where(
                    DistributionList.id == list_id, DistributionList.user_id == user_id
                )
            )
        ).scalar_one_or_none()
        if not dl:
            return ServiceResult(False, error="Liste introuvable", status_code=404)

        # Garde-fou ownership : on ne peut retirer qu'un contact qui
        # appartient à l'utilisateur (sinon un user pourrait deviner les
        # ids des contacts d'autrui en testant le retrait).
        contact = (
            await session.execute(
                select(Contact.id).where(Contact.id == contact_id, Contact.user_id == user_id)
            )
        ).scalar_one_or_none()
        if contact is None:
            return ServiceResult(False, error="Contact introuvable", status_code=404)

        result = await session.execute(
            delete(contact_list_association).where(
                contact_list_association.c.distribution_list_id == list_id,
                contact_list_association.c.contact_id == contact_id,
            )
        )
        if result.rowcount == 0:
            return ServiceResult(
                False, error="Le contact n'appartient pas à cette liste", status_code=404
            )
        return ServiceResult(True, data={"message": "Contact retiré de la liste"})

    async def batch_add_members(
        self, session: AsyncSession, user_id: int, list_id: int, contact_ids: list
    ) -> ServiceResult:
        """Ajoute plusieurs contacts à une liste, dedup + RGPD + report détaillé.

        Compteurs retournés :
        * ``added`` — réellement insérés.
        * ``skipped_existing`` — déjà membres (idempotent).
        * ``skipped_invalid`` — id inconnu, mauvais owner, ou non-int.
        * ``skipped_unsubscribed`` — contacts désabonnés (RGPD).
        * ``duplicates_in_request`` — ids dupliqués dans le body.
        """
        if not isinstance(contact_ids, list) or not contact_ids:
            return ServiceResult(
                False, error="contact_ids doit être un tableau non vide", status_code=400
            )

        if len(contact_ids) > MAX_BATCH_MEMBERS:
            return ServiceResult(
                False,
                error=f"Maximum {MAX_BATCH_MEMBERS} contacts par batch",
                status_code=400,
            )

        dl = (
            await session.execute(
                select(DistributionList).where(
                    DistributionList.id == list_id, DistributionList.user_id == user_id
                )
            )
        ).scalar_one_or_none()
        if not dl:
            return ServiceResult(False, error="Liste introuvable", status_code=404)

        # Dedup et cast int en un seul passe.
        try:
            requested_ids = [int(cid) for cid in contact_ids]
        except (ValueError, TypeError):
            return ServiceResult(
                False, error="contact_ids doit contenir des entiers valides", status_code=400
            )

        unique_ids = list(dict.fromkeys(requested_ids))  # preserve order, dedup
        duplicates_in_request = len(requested_ids) - len(unique_ids)

        # Charge les contacts valides + flag unsubscribed (RGPD).
        contacts_rows = (
            await session.execute(
                select(Contact.id, Contact.unsubscribed_at).where(
                    Contact.id.in_(unique_ids),
                    Contact.user_id == user_id,
                )
            )
        ).all()
        valid_ids = {row[0] for row in contacts_rows}
        unsubscribed_ids = {row[0] for row in contacts_rows if row[1] is not None}
        eligible_ids = valid_ids - unsubscribed_ids

        # Associations existantes parmi les valides.
        existing_ids: set[int] = set()
        if eligible_ids:
            existing = (
                (
                    await session.execute(
                        select(contact_list_association.c.contact_id).where(
                            contact_list_association.c.distribution_list_id == list_id,
                            contact_list_association.c.contact_id.in_(eligible_ids),
                        )
                    )
                )
                .scalars()
                .all()
            )
            existing_ids = set(existing)

        to_add = eligible_ids - existing_ids
        added = 0
        # ``racy_conflicts`` distinct de ``existing_ids`` : on ne MIX PAS
        # "déjà membre avant l'appel" et "racé en cours d'appel". Sans
        # cette distinction, l'utilisateur recevait "X déjà membres"
        # alors qu'aucun ne l'était au moment du POST — UX trompeuse +
        # audit faussé.
        racy_conflicts = 0
        if to_add:
            # Itérable stable : si on tombe en fallback, on parcourt
            # ``to_add`` de nouveau — un set se réordonne.
            to_add_list = sorted(to_add)
            values = [{"distribution_list_id": list_id, "contact_id": cid} for cid in to_add_list]
            # Savepoint + fallback : si un autre batch concurrent a inséré
            # un des contacts entre notre SELECT existing et notre INSERT,
            # le bulk insert lèverait IntegrityError (PK composite) et
            # rollback le batch entier — perte de TOUS les ajouts. On
            # isole via savepoint, et en cas d'erreur on re-essaie row par
            # row pour identifier les conflits sans perdre les valides.
            savepoint = await session.begin_nested()
            try:
                await session.execute(insert(contact_list_association), values)
                await savepoint.commit()
                added = len(to_add_list)
            except IntegrityError:
                await savepoint.rollback()
                logger.warning(
                    "Batch members concurrent conflict — fallback row-by-row",
                    extra=current_log_extra(
                        operation="list_batch_add", list_id=list_id, batch_size=len(to_add_list)
                    ),
                )
                for cid in to_add_list:
                    inner = await session.begin_nested()
                    try:
                        await session.execute(
                            insert(contact_list_association).values(
                                distribution_list_id=list_id, contact_id=cid
                            )
                        )
                        await inner.commit()
                        added += 1
                    except IntegrityError:
                        # Conflit racy : un autre processus a inséré ce membre
                        # PENDANT notre appel. Compté SÉPARÉMENT.
                        await inner.rollback()
                        racy_conflicts += 1
                    except Exception:
                        # Garde-fou : tout autre échec (DB locked, cancelled)
                        # rollback le savepoint inner pour éviter dangling
                        # (sinon ``InvalidRequestError: A transaction is
                        # already begun`` à la prochaine itération), puis
                        # remontée propre.
                        await inner.rollback()
                        raise
            except Exception:
                # IntegrityError déjà géré ; toute autre erreur sur l'INSERT
                # bulk → rollback savepoint avant re-raise.
                await savepoint.rollback()
                raise
        skipped_existing = len(existing_ids)
        skipped_unsubscribed = len(unsubscribed_ids)
        skipped_invalid = len(unique_ids) - len(valid_ids)

        logger.info(
            "Batch members add",
            extra=current_log_extra(
                operation="list_batch_add",
                list_id=list_id,
                added=added,
                skipped_existing=skipped_existing,
                skipped_invalid=skipped_invalid,
                skipped_unsubscribed=skipped_unsubscribed,
                racy_conflicts=racy_conflicts,
                duplicates_in_request=duplicates_in_request,
            ),
        )

        return ServiceResult(
            True,
            data={
                "message": f"{added} contact(s) ajouté(s)",
                "added": added,
                "skipped_existing": skipped_existing,
                "skipped_invalid": skipped_invalid,
                "skipped_unsubscribed": skipped_unsubscribed,
                "racy_conflicts": racy_conflicts,
                "duplicates_in_request": duplicates_in_request,
            },
        )


# ── Module helpers (testables sans BDD) ───────────────────────────────


def _parse_csv_text(text: str) -> list[dict]:
    """Parse le texte CSV en liste de dicts (off-thread friendly).

    Sniff le dialecte sur les 16 KB d'en-tête (un header très long peut
    pousser au-delà de 4 KB), puis ``DictReader``. Une erreur ``csv.Error``
    (séparateur introuvable, champ qui dépasse le ``field_size_limit``,
    fichier corrompu…) propage à l'appelant qui décide du status code.

    Anti-OOM : ``csv.field_size_limit`` est borné à
    ``_CSV_FIELD_SIZE_LIMIT_BYTES`` (1 MiB) **uniquement le temps du parse**.
    On save/restore la valeur précédente pour ne PAS polluer le process
    global (un autre service qui parse un CSV plus permissif derrière
    aurait soudain un ``csv.Error`` non explicable). La valeur par défaut
    Python est ``sys.maxsize`` — pratiquement illimitée.
    """
    # Lock : sérialise la mutation du global ``csv.field_size_limit`` entre les
    # threads du pool ``to_thread`` (cf. ``_field_size_limit_lock`` ci-dessus).
    with _field_size_limit_lock:
        previous_limit = csv.field_size_limit()
        csv.field_size_limit(_CSV_FIELD_SIZE_LIMIT_BYTES)
        try:
            sample = text[: 16 * 1024]
            dialect = _sniff_dialect(sample)
            reader = csv.DictReader(io.StringIO(text), dialect=dialect)
            return list(reader)
        finally:
            # Restoration garantie même sur csv.Error / MemoryError.
            csv.field_size_limit(previous_limit)
