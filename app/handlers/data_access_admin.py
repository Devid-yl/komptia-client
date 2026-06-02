"""Handlers admin pour la gestion des règles d'accès aux données BDD source.

Surfaces :

* :class:`DataAccessPageHandler` — rendu de la page HTML
  ``admin/data_access.html`` (GET only).
* :class:`DataAccessRulesAPIHandler` — CRUD JSON des règles d'un user
  (GET liste, PUT bulk replace).
* :class:`DataAccessRuleAPIHandler` — opérations unitaires (POST create,
  DELETE).
* :class:`DataAccessTablesAPIHandler` — liste des tables/colonnes connues
  pour les autocompletes du formulaire.

Tous protégés par ``@admin_required``. Le PUT bulk a un rate-limit
(prévention de bruit en cas de boucle frontend buggy).
"""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy import select as sa_select

from app.core.database import get_session
from app.handlers.base import BaseHandler, admin_required
from app.models.audit import AuditAction, AuditLog
from app.models.data_access_rule import DataAccessScope, validate_rule_payload
from app.models.training_data import TrainingData, TrainingDataType
from app.models.user import User
from app.services.data_access import enforcer as data_access_enforcer
from app.services.data_access import repository as data_access_repo
from app.services.data_access.notifier import schedule_notification
from app.services.data_access.schema_utils import extract_columns_from_ddl
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


async def _validate_table_exists_with_suggestions(
    session,
    table_name: str,
    column_name: Optional[str],
) -> dict:
    """**P0 (#126)** — Valide qu'une table/colonne existe dans le DDL synchronisé.

    Si la table ou la colonne n'existe pas, retourne des **suggestions
    fuzzy** (Levenshtein via `difflib.get_close_matches`, lib stdlib, pas
    de nouvelle dep). Permet à l'admin de corriger une typo sans
    deviner le bon nom.

    **Comportement caller** (`DataAccessRuleAPIHandler.post`/`put`) :

    - Si table inexistante → 422 ``{code: "table_not_found", suggestions: [...]}``.
    - Si colonne inexistante → 422 ``{code: "column_not_found", suggestions: [...]}``.
    - Si l'admin confirme volontairement (cas "table à venir") → passer
      ``force_create=True`` dans le body, qui court-circuite cette vérif.

    Args:
        session: AsyncSession ouverte.
        table_name: nom de la table à vérifier (case-insensitive sur SQL Server).
        column_name: optionnel — si fourni et table existe, vérifie aussi
            l'existence de cette colonne.

    Returns:
        dict ``{
            "table_exists": bool,
            "column_exists": bool | None,  # None si pas demandé
            "table_suggestions": list[str],
            "column_suggestions": list[str],
        }``
    """
    import difflib

    # Charger toutes les tables actives du training_store.
    stmt = sa_select(TrainingData.table_name, TrainingData.content).where(
        TrainingData.data_type == TrainingDataType.DDL.value,
        TrainingData.is_active.is_(True),
        TrainingData.table_name.isnot(None),
    )
    rows = (await session.execute(stmt)).all()

    all_table_names = [r[0] for r in rows if r[0]]
    # Match exact case-insensitive (SQL Server est case-insensitive).
    matching_rows = [
        (name, content)
        for (name, content) in rows
        if name and name.upper() == (table_name or "").upper()
    ]
    table_exists = len(matching_rows) > 0

    result = {
        "table_exists": table_exists,
        "column_exists": None,
        "table_suggestions": [],
        "column_suggestions": [],
    }

    if not table_exists:
        # Fuzzy match — top 3 suggestions, similarité >= 0.6.
        result["table_suggestions"] = difflib.get_close_matches(
            table_name or "", all_table_names, n=3, cutoff=0.6
        )
        return result

    if not column_name:
        return result

    # Table existe + on cherche la colonne → vérif fuzzy aussi.
    # ``extract_columns_from_ddl`` retourne ``List[str]`` directement
    # (pas des dicts), cf. ``app/services/data_access/schema_utils.py:44``.
    table_ddl = matching_rows[0][1] or ""
    column_names = [c for c in extract_columns_from_ddl(table_ddl) if c]
    column_exists = any(c.upper() == column_name.upper() for c in column_names)
    result["column_exists"] = column_exists
    if not column_exists:
        result["column_suggestions"] = difflib.get_close_matches(
            column_name, column_names, n=3, cutoff=0.6
        )
    return result


def _record_data_access_audit(
    handler: BaseHandler,
    *,
    action: str,
    target_user_id: int,
    rule_id: int | None,
    details: dict,
) -> None:
    """**Phase P1-8 (#24)** — Persiste un audit BDD queryable d'une
    mutation de règle data_access.

    Pattern aligné sur :func:`app.handlers.db_config._record_audit` :
    fire-and-forget via :func:`asyncio.create_task`, best-effort
    (un échec de log ne masque PAS la réponse au client). Le
    ``logger.info "[AUDIT]"`` reste en parallèle comme filet debug
    (cf. CLAUDE.md règle générique : ne pas casser le legacy).

    Args:
        handler: handler Tornado courant (pour l'IP + UA + admin user).
        action: une des constantes ``AuditAction.DATA_ACCESS_RULE_*``.
        target_user_id: ID de l'user impacté par la règle (≠ admin).
        rule_id: ID de la règle (None pour bulk replace / copy).
        details: champs structurés (``scope_type``, ``table_name``,
            ``effect``, ``mode``, ``inserted``, ``deleted``, etc.).
            ``by_admin`` et ``target_user_id`` sont auto-ajoutés.
    """
    try:
        admin_id = getattr(handler.current_user, "id", None)
        ip = handler.request.remote_ip
        ua = handler.request.headers.get("User-Agent")
        merged_details = {
            "target_user_id": target_user_id,
            "by_admin": admin_id,
            **details,
        }

        async def _persist() -> None:
            # Try/except interne : un échec d'INSERT (FK violation, BDD
            # down, etc.) doit logger un warning au lieu d'être avalé
            # silencieusement par l'event loop (la task fire-and-forget
            # consume les exceptions sans les remonter au caller).
            try:
                async with get_session() as session:
                    session.add(
                        AuditLog.log_action(
                            action=action,
                            user_id=admin_id,
                            entity_type="data_access_rule",
                            entity_id=rule_id,
                            details=merged_details,
                            ip_address=ip,
                            user_agent=ua,
                        )
                    )
            except Exception:  # noqa: BLE001 — audit best-effort
                logger.warning(
                    "Échec INSERT audit data_access (task fire-and-forget)",
                    exc_info=True,
                    extra={"action": action, "rule_id": rule_id},
                )

        import asyncio

        loop = asyncio.get_event_loop()
        loop.create_task(_persist())
    except Exception:  # noqa: BLE001 — audit best-effort
        logger.warning(
            "Échec persistance audit data_access",
            exc_info=True,
            extra={"action": action},
        )


# ── Limites & rate-limiting ────────────────────────────────────────


#: Body cap pour les PUT/POST de règles (defense-in-depth contre payload
#: manipulés). Aligné sur le pattern anonymization (1 Mo).
_BODY_CAP_BYTES: int = 1 * 1024 * 1024

#: **#143 — Rate-limits par opération** (au lieu d'un seul 30/min global).
#:
#: Stratégie : tuner par **sévérité** de l'opération (volume de mutations
#: en jeu, coût BDD, risque de wipe-out massif).
#:
#: - **CREATE** : 30/min — création unitaire, fréquente pendant config.
#: - **UPDATE** : 60/min — édition inline d'1 ligne, opération cheap.
#: - **DELETE** : 120/min — était **illimité** avant #143 (vrai trou : un
#:   admin pouvait wipe N règles en boucle sans frein). Limite calibrée
#:   pour couvrir le bulk-delete UI (loop de N appels DELETE par chunks
#:   de 8 en parallèle dans ``data_access.html::bulkDeleteSelected``)
#:   sans hit 429 jusqu'à ~100 règles d'un coup, tout en bornant le wipe
#:   massif scripté (7200/h reste détectable par audit log + lent).
#:   Tradeoff : pour bulks > 120 règles, l'admin verra 429 sur le reste
#:   et devra patienter — UX dégradée acceptable pour cas marginal. V2
#:   idéal = endpoint bulk-DELETE serveur rate-limité comme REPLACE.
#: - **REPLACE** (bulk PUT delete-all + insert) : 10/min — opération
#:   destructive massive, ne devrait pas être appelée à la chaîne dans
#:   un usage normal (1× par session de config par user cible).
#: - **COPY** (bulk INSERT depuis un autre user) : 10/min — opération
#:   destructive massive même rationale que REPLACE.
#:
#: Tuple ``(max_requests, window_seconds)`` pour rester compact et que
#: le compilateur statique vérifie l'arité.
_RATE_LIMIT_CREATE: tuple[int, int] = (30, 60)
_RATE_LIMIT_UPDATE: tuple[int, int] = (60, 60)
_RATE_LIMIT_DELETE: tuple[int, int] = (120, 60)
_RATE_LIMIT_REPLACE: tuple[int, int] = (10, 60)
_RATE_LIMIT_COPY: tuple[int, int] = (10, 60)
_bulk_rate_limiter: RateLimiter = RateLimiter()


# ── Helpers ──────────────────────────────────────────────────────


async def _get_target_user(session, user_id: int) -> Optional[User]:
    """Charge l'utilisateur cible par ID (sans password_hash)."""
    if user_id is None:
        return None
    return await session.get(User, user_id)



# ── Page HTML ────────────────────────────────────────────────────


class DataAccessPageHandler(BaseHandler):
    """Page admin : configuration des règles d'accès aux données par user."""

    @admin_required
    async def get(self) -> None:
        # On ne pré-charge pas les users ici : la page les charge via API
        # (paginé / filtrable côté JS). Évite un dump de 1000 users dans
        # le HTML à chaque rafraîchissement.
        self.render(
            "admin/data_access.html",
            page_title="Accès aux données",
        )


# ── Liste tables/colonnes (autocomplete) ─────────────────────────


class DataAccessTablesAPIHandler(BaseHandler):
    """Retourne la liste compacte ``[{table_name, columns: [..]}, ...]``
    pour alimenter les autocompletes de l'UI admin."""

    @admin_required
    async def get(self) -> None:
        async with get_session() as session:
            stmt = (
                sa_select(TrainingData.table_name, TrainingData.content)
                .where(
                    TrainingData.data_type == TrainingDataType.DDL.value,
                    TrainingData.is_active.is_(True),
                )
                .order_by(TrainingData.table_name)
            )
            rows = (await session.execute(stmt)).all()

        tables: List[dict] = []
        for table_name, ddl in rows:
            if not table_name:
                continue
            tables.append(
                {
                    "table_name": table_name,
                    "columns": extract_columns_from_ddl(ddl or ""),
                }
            )

        self.write_json({"tables": tables, "count": len(tables)})


# ── Liste users (pour le dropdown admin) ─────────────────────────


class DataAccessUsersAPIHandler(BaseHandler):
    """Retourne la liste compacte des users actifs pour le dropdown
    de la page admin."""

    @admin_required
    async def get(self) -> None:
        async with get_session() as session:
            stmt = (
                sa_select(User.id, User.username, User.email, User.role, User.is_active)
                .where(User.is_active.is_(True))
                .order_by(User.username)
            )
            rows = (await session.execute(stmt)).all()

        users: List[dict] = []
        for row in rows:
            role_value = getattr(row.role, "value", row.role) if row.role else "user"
            users.append(
                {
                    "id": int(row.id),
                    "username": row.username,
                    "email": row.email,
                    "role": role_value,
                    "is_active": bool(row.is_active),
                }
            )

        self.write_json({"users": users, "count": len(users)})


# ── CRUD règles d'un user ─────────────────────────────────────────


class DataAccessRulesAPIHandler(BaseHandler):
    """GET / PUT : règles d'un utilisateur cible.

    URL : ``/api/admin/data-access/users/<user_id>/rules``
    """

    @admin_required
    async def get(self, user_id: str) -> None:
        try:
            target_id = int(user_id)
        except (TypeError, ValueError):
            self.write_json({"success": False, "error": "user_id invalide"}, 400)
            return

        async with get_session() as session:
            target = await _get_target_user(session, target_id)
            if target is None:
                self.write_json({"success": False, "error": "Utilisateur introuvable"}, 404)
                return
            rules = await data_access_repo.list_rules_for_user(session, target_id)
            # Capture pour avoid MissingGreenlet
            data = [r.to_dict() for r in rules]

        self.write_json(
            {
                "success": True,
                "user_id": target_id,
                "rules": data,
                "count": len(data),
            }
        )

    @admin_required
    async def put(self, user_id: str) -> None:
        """Bulk replace des règles d'un user (delete-all + bulk insert)."""
        admin_user = self.current_user
        try:
            target_id = int(user_id)
        except (TypeError, ValueError):
            self.write_json({"success": False, "error": "user_id invalide"}, 400)
            return

        # Rate-limit
        if not _bulk_rate_limiter.check(
            f"data_access_put:user:{getattr(admin_user, 'id', 'anon')}",
            *_RATE_LIMIT_REPLACE,
        ):
            self.write_json(
                {
                    "success": False,
                    "error": "Trop de modifications consécutives. Patientez.",
                },
                429,
            )
            return

        # Body cap
        cl = self.request.headers.get("Content-Length")
        if cl and cl.isdigit() and int(cl) > _BODY_CAP_BYTES:
            self.write_json({"success": False, "error": "Payload trop volumineux."}, 413)
            return

        body = self.get_json_body()
        if not isinstance(body, dict):
            self.write_json({"success": False, "error": "Body JSON invalide."}, 400)
            return
        rules_payload = body.get("rules")
        if not isinstance(rules_payload, list):
            self.write_json(
                {
                    "success": False,
                    "error": "Le champ 'rules' doit être une liste.",
                },
                400,
            )
            return

        # Validation amont structurelle
        all_errors: List[dict] = []
        for idx, rule in enumerate(rules_payload):
            errs = validate_rule_payload(rule if isinstance(rule, dict) else {})
            if errs:
                all_errors.append({"index": idx, "errors": errs})
        if all_errors:
            self.write_json(
                {
                    "success": False,
                    "error": "Une ou plusieurs règles sont invalides.",
                    "validation_errors": all_errors,
                },
                400,
            )
            return

        # Exécution atomique
        async with get_session() as session:
            target = await _get_target_user(session, target_id)
            if target is None:
                self.write_json({"success": False, "error": "Utilisateur introuvable"}, 404)
                return
            try:
                stats = await data_access_repo.replace_rules_for_user(
                    session,
                    target_id,
                    rules_payload,
                    created_by=getattr(admin_user, "id", None),
                )
            except ValueError as exc:
                # Cap dépassé ou règle invalide post-validation.
                # B2-F1 (defense-in-depth, fail-closed) : même pattern que le
                # merge de copy-rules — ``return`` depuis l'intérieur du
                # ``async with get_session()`` ⇒ get_session COMMIT à la sortie
                # normale. Aujourd'hui ``replace_rules_for_user`` ne lève
                # ``ValueError`` qu'en pré-vol (taille) AVANT toute mutation,
                # donc rien n'est flushé ; mais si une validation ``ValueError``
                # post-snapshot était ajoutée, le COMMIT figerait un wipe RLS
                # partiel (audit_row + DELETE sans les INSERT). On rollback par
                # cohérence avec le merge pour fermer la classe de bug.
                await session.rollback()
                self.write_json({"success": False, "error": str(exc)}, 422)
                return

        # Invalidation event-based du cache enforcer
        data_access_enforcer.invalidate_user(target_id)

        logger.info(
            "[AUDIT] data_access PUT user=%s by_admin=%s deleted=%s " "inserted=%s",
            target_id,
            getattr(admin_user, "id", None),
            stats.get("deleted"),
            stats.get("inserted"),
        )
        # **#24 — Audit BDD queryable** (parallèle au logger.info legacy).
        _record_data_access_audit(
            self,
            action=AuditAction.DATA_ACCESS_RULES_REPLACED,
            target_user_id=target_id,
            rule_id=None,
            details={
                "deleted": stats.get("deleted"),
                "inserted": stats.get("inserted"),
            },
        )
        # **#74 — Notif fire-and-forget** (throttle 60s). Le bulk replace
        # peut toucher des dizaines de règles d'un coup ; le throttle
        # garantit qu'on n'envoie qu'1 mail par user dans la fenêtre.
        schedule_notification(
            target_id,
            admin_username=getattr(admin_user, "username", None),
            action="replaced",
        )
        self.write_json({"success": True, **stats})


class DataAccessRuleAPIHandler(BaseHandler):
    """POST (create one) / DELETE (one) sur une règle individuelle.

    URLs :
      - POST   ``/api/admin/data-access/users/<user_id>/rules/single``
      - DELETE ``/api/admin/data-access/rules/<rule_id>``
    """

    @admin_required
    async def post(self, user_id: str) -> None:
        admin_user = self.current_user
        try:
            target_id = int(user_id)
        except (TypeError, ValueError):
            self.write_json({"success": False, "error": "user_id invalide"}, 400)
            return

        if not _bulk_rate_limiter.check(
            f"data_access_create:user:{getattr(admin_user, 'id', 'anon')}",
            *_RATE_LIMIT_CREATE,
        ):
            self.write_json(
                {"success": False, "error": "Trop de créations consécutives."},
                429,
            )
            return

        body = self.get_json_body()
        if not isinstance(body, dict):
            self.write_json({"success": False, "error": "Body JSON invalide."}, 400)
            return
        errors = validate_rule_payload(body)
        if errors:
            self.write_json(
                {
                    "success": False,
                    "error": "Règle invalide.",
                    "validation_errors": errors,
                },
                400,
            )
            return

        async with get_session() as session:
            target = await _get_target_user(session, target_id)
            if target is None:
                self.write_json({"success": False, "error": "Utilisateur introuvable"}, 404)
                return

            # **P0 (#126)** — Validation existence + fuzzy did-you-mean.
            # Si l'admin pose une règle sur une table/colonne inexistante
            # (typo), on retourne 422 + suggestions. L'admin peut soit
            # corriger, soit forcer (cas "table à venir") en renvoyant
            # ``force_create=True`` dans le body. Court-circuit explicite
            # pour ne pas frustrer un cas légitime.
            if not body.get("force_create"):
                check = await _validate_table_exists_with_suggestions(
                    session,
                    table_name=body.get("table_name", ""),
                    column_name=body.get("column_name"),
                )
                if not check["table_exists"]:
                    self.write_json(
                        {
                            "success": False,
                            "code": "table_not_found",
                            "error": (
                                f"La table « {body.get('table_name')} » n'existe "
                                "pas dans le schéma actuellement synchronisé. "
                                "Vérifie le nom (sensible aux fautes de frappe) "
                                "ou renvoie avec « force_create: true » si la "
                                "table sera créée plus tard."
                            ),
                            "suggestions": check["table_suggestions"],
                        },
                        422,
                    )
                    return
                if check["column_exists"] is False:
                    self.write_json(
                        {
                            "success": False,
                            "code": "column_not_found",
                            "error": (
                                f"La colonne « {body.get('column_name')} » "
                                f"n'existe pas dans la table "
                                f"« {body.get('table_name')} ». Vérifie le nom "
                                "ou renvoie avec « force_create: true » si la "
                                "colonne sera ajoutée plus tard."
                            ),
                            "suggestions": check["column_suggestions"],
                        },
                        422,
                    )
                    return

            try:
                rule = await data_access_repo.create_rule(
                    session,
                    target_id,
                    body,
                    created_by=getattr(admin_user, "id", None),
                )
            except data_access_repo.DuplicateRuleError as exc:
                # **P0 (#125)** — Doublon détecté en amont (anti-bug
                # silencieux). 409 Conflict + message FR explicite.
                self.write_json(
                    {"success": False, "error": str(exc), "code": "duplicate_rule"},
                    409,
                )
                return
            except ValueError as exc:
                self.write_json({"success": False, "error": str(exc)}, 422)
                return
            data = rule.to_dict()

        data_access_enforcer.invalidate_user(target_id)

        logger.info(
            "[AUDIT] data_access CREATE rule_id=%s user=%s by_admin=%s "
            "scope=%s table=%s effect=%s",
            data["id"],
            target_id,
            getattr(admin_user, "id", None),
            data["scope_type"],
            data["table_name"],
            data["effect"],
        )
        # **#24 — Audit BDD queryable** (parallèle au logger.info legacy).
        _record_data_access_audit(
            self,
            action=AuditAction.DATA_ACCESS_RULE_CREATED,
            target_user_id=target_id,
            rule_id=data["id"],
            details={
                "scope_type": data["scope_type"],
                "table_name": data["table_name"],
                "column_name": data.get("column_name"),
                "effect": data["effect"],
            },
        )
        # **#74 — Notif fire-and-forget**. Le user est prévenu que ses
        # accès ont changé. Throttle 60s + fail-safe interne (cf. notifier).
        schedule_notification(
            target_id,
            admin_username=getattr(admin_user, "username", None),
            action="added",
        )
        self.set_status(201)
        self.write_json({"success": True, "rule": data})

    @admin_required
    async def delete(self, rule_id: str) -> None:
        admin_user = self.current_user
        try:
            rid = int(rule_id)
        except (TypeError, ValueError):
            self.write_json({"success": False, "error": "rule_id invalide"}, 400)
            return

        # **#143** — Rate-limit DELETE (était illimité avant). Un admin
        # malveillant ou bug script pouvait wipe N règles en boucle. 60/min
        # par admin reste large pour un usage légitime (suppression au
        # clic dans l'UI), mais bornée pour éviter le wipe massif.
        if not _bulk_rate_limiter.check(
            f"data_access_delete:user:{getattr(admin_user, 'id', 'anon')}",
            *_RATE_LIMIT_DELETE,
        ):
            self.write_json(
                {"success": False, "error": "Trop de suppressions consécutives. Patientez."},
                429,
            )
            return

        async with get_session() as session:
            rule = await data_access_repo.get_rule(session, rid)
            if rule is None:
                self.write_json({"success": False, "error": "Règle introuvable"}, 404)
                return
            target_id = rule.user_id
            ok = await data_access_repo.delete_rule(session, rid)

        if ok:
            data_access_enforcer.invalidate_user(target_id)
            logger.info(
                "[AUDIT] data_access DELETE rule_id=%s user=%s by_admin=%s",
                rid,
                target_id,
                getattr(admin_user, "id", None),
            )
            # **#24 — Audit BDD queryable** (parallèle au logger.info legacy).
            _record_data_access_audit(
                self,
                action=AuditAction.DATA_ACCESS_RULE_DELETED,
                target_user_id=target_id,
                rule_id=rid,
                details={},
            )
            # **#74 — Notif fire-and-forget** (throttle 60s).
            schedule_notification(
                target_id,
                admin_username=getattr(admin_user, "username", None),
                action="deleted",
            )
            self.write_json({"success": True})
        else:
            self.write_json({"success": False, "error": "Suppression échouée"}, 500)

    @admin_required
    async def put(self, rule_id: str) -> None:
        """**Phase P2 (#31) — Edit inline d'une règle.**

        URL : ``PUT /api/admin/data-access/rules/<rule_id>``

        Met à jour les champs mutables (scope_type, table_name, column_name,
        effect, allowed_values, note) d'une règle existante. Le ``user_id``
        d'origine n'est PAS mutable (cf. ``data_access_repo.update_rule``)
        — pour déplacer une règle, supprimer + recréer côté front.

        Body JSON : même format que le POST single (validate_rule_payload).

        Rate-limit aligné avec POST single (30/min par admin).
        """
        admin_user = self.current_user
        try:
            rid = int(rule_id)
        except (TypeError, ValueError):
            self.write_json({"success": False, "error": "rule_id invalide"}, 400)
            return

        if not _bulk_rate_limiter.check(
            f"data_access_update:user:{getattr(admin_user, 'id', 'anon')}",
            *_RATE_LIMIT_UPDATE,
        ):
            self.write_json(
                {"success": False, "error": "Trop de mises à jour consécutives."},
                429,
            )
            return

        body = self.get_json_body()
        if not isinstance(body, dict):
            self.write_json({"success": False, "error": "Body JSON invalide."}, 400)
            return
        errors = validate_rule_payload(body)
        if errors:
            self.write_json(
                {
                    "success": False,
                    "error": "Règle invalide.",
                    "validation_errors": errors,
                },
                400,
            )
            return

        async with get_session() as session:
            existing = await data_access_repo.get_rule(session, rid)
            if existing is None:
                self.write_json({"success": False, "error": "Règle introuvable"}, 404)
                return
            target_id = existing.user_id
            try:
                updated = await data_access_repo.update_rule(session, rid, body)
            except ValueError as exc:
                self.write_json({"success": False, "error": str(exc)}, 422)
                return
            if updated is None:
                # Race condition : règle supprimée entre le get et l'update.
                self.write_json({"success": False, "error": "Règle introuvable"}, 404)
                return
            data = updated.to_dict()

        data_access_enforcer.invalidate_user(target_id)

        logger.info(
            "[AUDIT] data_access UPDATE rule_id=%s user=%s by_admin=%s "
            "scope=%s table=%s effect=%s",
            rid,
            target_id,
            getattr(admin_user, "id", None),
            data["scope_type"],
            data["table_name"],
            data["effect"],
        )
        # **#24 — Audit BDD queryable** (parallèle au logger.info legacy).
        _record_data_access_audit(
            self,
            action=AuditAction.DATA_ACCESS_RULE_UPDATED,
            target_user_id=target_id,
            rule_id=rid,
            details={
                "scope_type": data["scope_type"],
                "table_name": data["table_name"],
                "column_name": data.get("column_name"),
                "effect": data["effect"],
            },
        )
        # **#74 — Notif fire-and-forget** (throttle 60s).
        schedule_notification(
            target_id,
            admin_username=getattr(admin_user, "username", None),
            action="modified",
        )
        self.write_json({"success": True, "rule": data})


class DataAccessRuleRestoreAPIHandler(BaseHandler):
    """**#139** — POST ``/api/admin/data-access/rules/<rule_id>/restore``.

    Restaure une règle soft-deleted (set ``deleted_at = NULL``). Appelé
    par le toast undo qui apparaît 8s après un DELETE — fenêtre UX
    standard pour rattraper une suppression accidentelle (W3 textarea
    à 500 valeurs perdues sinon).

    Réponses :
        - 200 : restauré, retourne la règle ``{"success": true, "rule": ...}``.
        - 404 : règle introuvable OU déjà active OU hard-deleted par cleanup.
        - 409 : conflit unique (admin a recréé une règle identique entre
          le DELETE et le clic Undo — message admin-actionnable).
        - 429 : rate-limit aligné sur UPDATE (60/min, opération cheap).
    """

    @admin_required
    async def post(self, rule_id: str) -> None:
        admin_user = self.current_user
        try:
            rid = int(rule_id)
        except (TypeError, ValueError):
            self.write_json({"success": False, "error": "rule_id invalide"}, 400)
            return

        if not _bulk_rate_limiter.check(
            f"data_access_update:user:{getattr(admin_user, 'id', 'anon')}",
            *_RATE_LIMIT_UPDATE,
        ):
            self.write_json(
                {"success": False, "error": "Trop d'opérations consécutives. Patientez."},
                429,
            )
            return

        from sqlalchemy.exc import IntegrityError

        try:
            async with get_session() as session:
                # Lire avec ``include_deleted=True`` pour récupérer la
                # règle soft-deleted (autrement get_rule la masque).
                rule = await data_access_repo.get_rule(
                    session, rid, include_deleted=True
                )
                if rule is None:
                    self.write_json(
                        {
                            "success": False,
                            "error": "Règle introuvable (ID inconnu ou purge cleanup).",
                        },
                        404,
                    )
                    return
                if rule.deleted_at is None:
                    # Idempotent : pas un état d'erreur, mais on log pour
                    # détecter les UI qui spamment restore.
                    self.write_json(
                        {
                            "success": False,
                            "error": "Règle déjà active — rien à restaurer.",
                        },
                        404,
                    )
                    return
                target_id = rule.user_id
                restored = await data_access_repo.restore_rule(session, rid)
                if restored is None:
                    self.write_json(
                        {"success": False, "error": "Restauration échouée."},
                        500,
                    )
                    return
                # Capture des données AVANT commit pour éviter MissingGreenlet.
                rule_dict = restored.to_dict()
                await session.commit()
        except IntegrityError:
            # **#139** — Race : admin a recréé une règle identique entre le
            # DELETE et le clic Undo. UNIQUE constraint violation → 409
            # admin-actionnable (l'admin doit supprimer la nouvelle pour
            # restaurer l'ancienne, ou abandonner l'undo).
            self.write_json(
                {
                    "success": False,
                    "error": (
                        "Une règle identique a été créée entre-temps. "
                        "Supprimez-la d'abord, ou abandonnez la restauration."
                    ),
                },
                409,
            )
            return

        data_access_enforcer.invalidate_user(target_id)
        logger.info(
            "[AUDIT] data_access RESTORE rule_id=%s user=%s by_admin=%s",
            rid,
            target_id,
            getattr(admin_user, "id", None),
        )
        # **#24 — Audit BDD queryable** : trace la restauration séparément
        # du DELETE original (action ``DATA_ACCESS_RULE_CREATED`` réutilisée
        # car la sémantique côté audit = "règle redevenue active").
        _record_data_access_audit(
            self,
            action=AuditAction.DATA_ACCESS_RULE_CREATED,
            target_user_id=target_id,
            rule_id=rid,
            details={"restored": True},
        )
        schedule_notification(
            target_id,
            admin_username=getattr(admin_user, "username", None),
            action="added",
        )
        self.write_json({"success": True, "rule": rule_dict})


# ---------------------------------------------------------------------------
# Preview Impact (Phase α.7 — #73) — read-only, calcule l'impact d'une
# règle proposée AVANT sa pose.
# ---------------------------------------------------------------------------


class DataAccessPreviewImpactAPIHandler(BaseHandler):
    """POST ``/api/admin/data-access/users/<user_id>/preview-impact``.

    Body JSON : ``{scope, table_name, column_name?}``. Identique au
    body de création d'une règle, sauf qu'on ne persiste rien — on
    retourne juste l'impact estimé (automations / dashboards / Q-SQL
    pairs / conversations).

    Usage frontend : appeler cet endpoint AVANT le POST de création,
    afficher l'impact à l'admin, demander confirmation explicite, puis
    POSTer la règle.
    """

    @admin_required
    async def post(self, user_id: str) -> None:
        try:
            target_id = int(user_id)
        except (TypeError, ValueError):
            self.write_json({"success": False, "error": "user_id invalide"}, 400)
            return

        body = self.get_json_body()
        if not isinstance(body, dict):
            self.write_json({"success": False, "error": "Body JSON invalide."}, 400)
            return

        scope = str(body.get("scope", "")).strip().lower()
        table_name = str(body.get("table_name", "")).strip()
        column_name_raw = body.get("column_name")
        column_name = (
            str(column_name_raw).strip()
            if column_name_raw is not None and str(column_name_raw).strip()
            else None
        )

        # SSoT : utilise les .value de l'enum ``DataAccessScope`` au lieu d'un
        # littéral hardcodé. Bug 2026-05-26 (DA-M6) : la liste était dupliquée
        # ici + template ``data_access.html`` (2 endroits) + (techniquement)
        # ``data_access_rule.py``. Si on ajoute un scope ``"function"``, on
        # le déclare une fois dans l'enum et tous les sites suivent.
        _allowed_scopes = tuple(s.value for s in DataAccessScope)
        if scope not in _allowed_scopes:
            _allowed_str = " / ".join(f"'{s}'" for s in _allowed_scopes)
            self.write_json(
                {
                    "success": False,
                    "error": f"scope invalide. Attendu : {_allowed_str}.",
                },
                400,
            )
            return
        if not table_name:
            self.write_json(
                {"success": False, "error": "table_name requis."},
                400,
            )
            return

        # Vérifier que l'user cible existe (sinon le rapport sera nul mais
        # l'API doit retourner 404 pour cohérence avec POST rule).
        async with get_session() as session:
            target = await _get_target_user(session, target_id)
            if target is None:
                self.write_json({"success": False, "error": "Utilisateur introuvable"}, 404)
                return

        try:
            from app.services.data_access.impact_analyzer import compute_impact

            report = await compute_impact(
                user_id=target_id,
                scope=scope,
                table_name=table_name,
                column_name=column_name,
            )
        except ValueError as exc:
            self.write_json({"success": False, "error": str(exc)}, 422)
            return
        except Exception as exc:  # noqa: BLE001 — endpoint admin, log + 500
            logger.error(
                "preview-impact failed for user=%s table=%s: %s",
                target_id,
                table_name,
                exc,
                exc_info=True,
            )
            self.write_json(
                {
                    "success": False,
                    "error": "Erreur de calcul d'impact (logs admin pour détail).",
                },
                500,
            )
            return

        self.write_json({"success": True, "impact": report.to_dict()})


# ──────────────────────────────────────────────────────────────────
# Copy rules to another user (#30 — P2)
# ──────────────────────────────────────────────────────────────────


class DataAccessCopyRulesAPIHandler(BaseHandler):
    """**#30 — Dupliquer les règles d'un user vers un autre.**

    URL : ``POST /api/admin/data-access/users/<from_id>/copy-rules-to/<to_id>``

    Body JSON optionnel : ``{"mode": "merge"|"replace"}``. Défaut ``merge``.

    - **merge** (défaut) : ajoute les règles de ``from_id`` aux règles existantes
      de ``to_id``. Cap ``MAX_RULES_PER_USER`` vérifié sur le total cible.
    - **replace** : remplace TOUTES les règles de ``to_id`` par celles de
      ``from_id``. Atomique via ``replace_rules_for_user``.

    Usage typique : un admin onboarde un nouveau collaborateur et veut lui
    appliquer le même profil d'accès qu'un user existant.

    Garde-fous :
    - ``from_id == to_id`` → 400 (no-op suspect).
    - ``to_id`` admin → autorisé techniquement mais inutile (les admins ne sont
      jamais filtrés). Un WARNING log est posé.
    - Rate-limited (aligné avec PUT bulk : 30/min par admin).
    """

    @admin_required
    async def post(self, from_id: str, to_id: str) -> None:
        admin_user = self.current_user
        try:
            src_id = int(from_id)
            dst_id = int(to_id)
        except (TypeError, ValueError):
            self.write_json({"success": False, "error": "user_id invalide"}, 400)
            return

        if src_id == dst_id:
            self.write_json(
                {
                    "success": False,
                    "error": "Source et destination identiques — opération inutile.",
                },
                400,
            )
            return

        if not _bulk_rate_limiter.check(
            f"data_access_copy:user:{getattr(admin_user, 'id', 'anon')}",
            *_RATE_LIMIT_COPY,
        ):
            self.write_json(
                {"success": False, "error": "Trop de duplications consécutives."},
                429,
            )
            return

        body = self.get_json_body() or {}
        if not isinstance(body, dict):
            self.write_json({"success": False, "error": "Body JSON invalide."}, 400)
            return
        mode = body.get("mode", "merge")
        if mode not in ("merge", "replace"):
            self.write_json(
                {
                    "success": False,
                    "error": "mode invalide : doit être 'merge' ou 'replace'.",
                },
                400,
            )
            return

        async with get_session() as session:
            # 1. Vérifier que les 2 users existent.
            src_user = await _get_target_user(session, src_id)
            dst_user = await _get_target_user(session, dst_id)
            if src_user is None or dst_user is None:
                self.write_json(
                    {
                        "success": False,
                        "error": "Utilisateur source ou destination introuvable.",
                    },
                    404,
                )
                return

            if getattr(dst_user.role, "value", dst_user.role) == "admin":
                logger.warning(
                    "[AUDIT] data_access COPY vers un admin (user_id=%s) — "
                    "les admins ne sont jamais filtrés, opération inutile.",
                    dst_id,
                )

            # 2. Récupérer les règles source.
            src_rules = await data_access_repo.list_rules_for_user(session, src_id)
            if not src_rules:
                self.write_json(
                    {
                        "success": False,
                        "error": "L'utilisateur source n'a aucune règle à dupliquer.",
                    },
                    400,
                )
                return

            # 3. Convertir en payloads (drop id, user_id, created_by, timestamps).
            payloads = []
            for r in src_rules:
                payloads.append(
                    {
                        "scope_type": r.scope_type.value,
                        "table_name": r.table_name,
                        "column_name": r.column_name,
                        "effect": r.effect.value,
                        "allowed_values": r.allowed_values,
                        "note": r.note,
                    }
                )

            try:
                if mode == "replace":
                    stats = await data_access_repo.replace_rules_for_user(
                        session,
                        dst_id,
                        payloads,
                        created_by=getattr(admin_user, "id", None),
                    )
                    inserted = stats["inserted"]
                    deleted = stats["deleted"]
                else:
                    # merge : create_rule individuellement (cap vérifié dans le
                    # repository — lève ValueError si dépassement).
                    inserted = 0
                    for payload in payloads:
                        await data_access_repo.create_rule(
                            session,
                            dst_id,
                            payload,
                            created_by=getattr(admin_user, "id", None),
                        )
                        inserted += 1
                    deleted = 0
            except ValueError as exc:
                # B2-F1 (atomicité / données fausses sécurité) : le mode MERGE
                # appelle ``create_rule`` individuellement (chacun ``add`` +
                # ``flush``). Une ``ValueError``/``DuplicateRuleError`` au k-ième
                # payload laisse les k-1 précédents flushés dans la session. Le
                # ``return`` ci-dessous sort du ``async with get_session()`` SANS
                # exception → ``get_session`` COMMIT-erait l'état partiel : une
                # copie PARTIELLE de règles RLS, alors que l'admin reçoit un 422
                # « échec ». Octroyer/retirer un accès à moitié sans le savoir est
                # une faille silencieuse. On rollback explicitement pour garantir
                # le tout-ou-rien. (Pour le mode ``replace``, ce rollback est un
                # no-op : ``replace_rules_for_user`` ne lève ``ValueError`` qu'en
                # pré-vol — taille du batch — AVANT toute mutation ; ses échecs
                # post-mutation sont des ``IntegrityError`` qui se propagent et
                # sont rollback par ``get_session`` lui-même.)
                await session.rollback()
                self.write_json({"success": False, "error": str(exc)}, 422)
                return

        # 4. Invalidation cache enforcer (uniquement sur le DST — la source
        # n'est pas modifiée).
        data_access_enforcer.invalidate_user(dst_id)

        logger.info(
            "[AUDIT] data_access COPY from_user=%s to_user=%s by_admin=%s "
            "mode=%s inserted=%d deleted=%d",
            src_id,
            dst_id,
            getattr(admin_user, "id", None),
            mode,
            inserted,
            deleted,
        )
        # **#24 — Audit BDD queryable** (parallèle au logger.info legacy).
        # rule_id=None car la copie touche N règles à la fois ; on
        # stocke la source dans details pour permettre des requêtes du
        # type "qui a copié les règles de marc vers qui ?".
        _record_data_access_audit(
            self,
            action=AuditAction.DATA_ACCESS_RULES_COPIED,
            target_user_id=dst_id,
            rule_id=None,
            details={
                "from_user_id": src_id,
                "mode": mode,
                "inserted": inserted,
                "deleted": deleted,
            },
        )
        # **#74 — Notif fire-and-forget** sur le DST (la source n'a pas
        # bougé). Throttle 60s + fail-safe interne. La notif ne révèle pas
        # qu'il s'agissait d'une copie (mode invisible).
        schedule_notification(
            dst_id,
            admin_username=getattr(admin_user, "username", None),
            action="copied",
        )
        self.write_json(
            {
                "success": True,
                "mode": mode,
                "inserted": inserted,
                "deleted": deleted,
            }
        )


# ──────────────────────────────────────────────────────────────────
# Vue d'ensemble matrice (#29 — P2)
# ──────────────────────────────────────────────────────────────────


class DataAccessMatrixAPIHandler(BaseHandler):
    """**#29 — Vue d'ensemble matrice (users × tables).**

    URL : ``GET /api/admin/data-access/matrix``

    Retourne une vue agrégée des règles **sur tables entières** (``scope=table``)
    pour tous les utilisateurs non-admin de la base. Format ::

        {
          "users": [{"id": 1, "username": "alice", "email": "..."}],
          "tables": ["F_DOSSIER", "F_CLIENT", ...],
          "denied": {
            "1": ["F_DOSSIER", "F_SALAIRES"],
            "2": ["F_SALAIRES"]
          },
          "stats": {"user_count": 2, "table_count": 17, "total_denies": 3}
        }

    Limitations V1 (assumées) :
    - **Seulement les `scope=table` avec `effect=deny`** dans la matrice.
      Les règles de colonne/lignes existent mais ne sont pas représentées
      visuellement (UI séparée plus complexe).
    - Les admins ne sont pas inclus (ils ne sont jamais filtrés).
    - Les tables affichées sont l'union de toutes les tables référencées
      au moins une fois dans une règle ``table`` (pour ne pas exploser la
      grille avec 200 tables Sage dont 95 % sont vides de règles).
    """

    #: Bug 2026-05-26 (Agent 4 DA-C4 critique) : caps durs pour éviter
    #: que 2000 users × 200 tables × cellule DOM = 400K éléments → crash
    #: navigateur. Au-delà du cap, on tronque + signale "truncated" dans
    #: la réponse. L'admin doit utiliser la recherche par username pour
    #: zoomer sur un sous-ensemble (UI existante).
    _MAX_USERS_IN_MATRIX: int = 200
    _MAX_TABLES_IN_MATRIX: int = 50

    @admin_required
    async def get(self) -> None:
        from app.models.data_access_rule import DataAccessScope, DataAccessEffect
        from app.models.user import User, UserRole

        async with get_session() as session:
            # 1. Tous les non-admins (cap dur _MAX_USERS_IN_MATRIX pour éviter
            # le crash navigateur sur 2000+ users).
            user_stmt = (
                sa_select(User.id, User.username, User.email, User.role)
                .where(User.role != UserRole.ADMIN)
                .order_by(User.username)
                .limit(self._MAX_USERS_IN_MATRIX + 1)  # +1 pour détecter truncation
            )
            user_rows = (await session.execute(user_stmt)).all()
            users_truncated = len(user_rows) > self._MAX_USERS_IN_MATRIX
            if users_truncated:
                user_rows = user_rows[: self._MAX_USERS_IN_MATRIX]
            users = [{"id": r.id, "username": r.username, "email": r.email} for r in user_rows]
            user_ids = [u["id"] for u in users]

            if not user_ids:
                # Pas de non-admin → matrice vide propre.
                self.write_json(
                    {
                        "success": True,
                        "users": [],
                        "tables": [],
                        "denied": {},
                        "stats": {
                            "user_count": 0,
                            "table_count": 0,
                            "total_denies": 0,
                            "users_truncated": False,
                            "tables_truncated": False,
                            "users_max": self._MAX_USERS_IN_MATRIX,
                            "tables_max": self._MAX_TABLES_IN_MATRIX,
                        },
                    }
                )
                return

            # 2. Toutes les règles table-deny pour ces users.
            from app.models.data_access_rule import DataAccessRule

            rule_stmt = sa_select(DataAccessRule.user_id, DataAccessRule.table_name).where(
                DataAccessRule.user_id.in_(user_ids),
                DataAccessRule.scope_type == DataAccessScope.TABLE,
                DataAccessRule.effect == DataAccessEffect.DENY,
            )
            rule_rows = (await session.execute(rule_stmt)).all()

        # 3. Agréger côté Python.
        denied: dict = {}
        all_tables: set = set()
        for r in rule_rows:
            denied.setdefault(str(r.user_id), []).append(r.table_name)
            all_tables.add(r.table_name)

        # 4. Cap tables (au-delà de _MAX_TABLES_IN_MATRIX colonnes,
        # la grille devient inutilisable). On garde les N tables les plus
        # référencées (tri par nombre de denied) — celles qui posent le
        # plus de friction pour l'admin.
        tables_sorted = sorted(all_tables)
        tables_truncated = len(tables_sorted) > self._MAX_TABLES_IN_MATRIX
        if tables_truncated:
            # Compte par table puis garde le top N (les tables avec le plus
            # de denied — les plus sensibles pour l'admin).
            from collections import Counter

            table_counts: Counter = Counter()
            for u_denies in denied.values():
                for t in u_denies:
                    table_counts[t] += 1
            top_tables = {t for t, _ in table_counts.most_common(self._MAX_TABLES_IN_MATRIX)}
            tables_sorted = sorted(top_tables)
            # Filtre ``denied`` pour ne garder que les tables retenues.
            denied = {
                uid: [t for t in tlist if t in top_tables]
                for uid, tlist in denied.items()
            }

        total_denies = sum(len(v) for v in denied.values())

        self.write_json(
            {
                "success": True,
                "users": users,
                "tables": tables_sorted,
                "denied": denied,
                "stats": {
                    "user_count": len(users),
                    "table_count": len(tables_sorted),
                    "total_denies": total_denies,
                    # Bug DA-C4 : signaux truncation pour que l'UI puisse
                    # afficher un banner « X users non affichés, utilisez la
                    # recherche ».
                    "users_truncated": users_truncated,
                    "tables_truncated": tables_truncated,
                    "users_max": self._MAX_USERS_IN_MATRIX,
                    "tables_max": self._MAX_TABLES_IN_MATRIX,
                },
            }
        )
