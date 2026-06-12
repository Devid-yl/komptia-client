"""Handlers d'administration — CRUD utilisateurs, invariants, révocation de sessions.

Responsabilités
---------------
Le handler fait *uniquement* :

1. **Parser** la requête HTTP (JSON body, query-args) et valider les **types**.
2. **Déléguer** la logique métier à :mod:`app.services.admin_service`
   (invariants admin, révocation de sessions, compteurs).
3. **Formater** la réponse (HTTP status + JSON), en mappant les exceptions
   structurées :class:`AdminError` sur ``exc.http_status`` / ``exc.code``.

Tout ce qui ressemble à une règle métier (« ne pas retirer le dernier admin »,
« invalider les sessions actives lors d'une perte de privilège », « vérifier
les quotas d'utilisateurs ») vit dans le service, pas ici. Le handler reste
volontairement fin pour faciliter les tests unitaires et les changements de
transport (Tornado → FastAPI hypothétique, par exemple).

Conventions
-----------

- Les mutations passent toutes par un ``async with get_session()`` unique — pas
  de pré-check dans une session, mutation dans une autre (TOCTOU évitable).
- Pour l'unicité (``username`` / ``email``), on s'appuie sur les contraintes
  ``UNIQUE`` de la base : un :class:`sqlalchemy.exc.IntegrityError` est
  attrapé et converti en :class:`UsernameExistsError` /
  :class:`EmailExistsError` (par introspection de ``err.orig``, pas par
  pattern-matching sur ``str(err)``).
- Le mot de passe **n'est jamais trimé** — ASVS 2.1.3 (un utilisateur qui
  choisit intentionnellement un mot de passe à trailing space doit pouvoir le
  reproduire). Seuls les identifiants (username / email) sont trimés.
- ``is_active`` est **strictement booléen** côté API : ``True`` / ``False``
  JSON uniquement. On refuse les chaînes « vides », les entiers, etc. pour
  éviter les activations silencieuses par erreur de sérialisation côté
  client.

Sécurité
--------

- Toute perte de privilège (demote, désactivation, hard-delete, changement
  de mot de passe) révoque atomiquement les sessions actives de la cible.
- L'admin connecté ne peut ni se démote ni se désactiver lui-même (la guarde
  « dernier admin » le couvre dans la plupart des cas, mais un admin peut
  avoir un pair et vouloir se supprimer — on refuse explicitement pour éviter
  l'auto-lockout accidentel).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, Final

import tornado.web
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.config import get_config
from app.core.database import get_session
from app.handlers.base import BaseHandler, admin_required
from app.models.base import ensure_utc, iso_or_none
from app.models.session import Session as SessionModel
from app.models.user import User, UserRole
from app.services.admin_service import (
    EmailExistsError,
    LastAdminError,
    UsernameExistsError,
    active_user_count,
    ensure_not_last_admin,
    purge_user_owned_data,
    revoke_user_sessions,
)
from app.core.constants_auth import PASSWORD_MAX_BYTES, password_exceeds_bcrypt_limit
from app.models.audit import AuditAction
from app.services.audit import audit_event, record_audit_best_effort
from app.services.auth.password_hasher import PasswordHasher
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constantes de module — toute valeur hors configuration utilisateur
# ---------------------------------------------------------------------------


_USERNAME_MIN_LEN: Final[int] = 3
_USERNAME_MAX_LEN: Final[int] = 50
_PASSWORD_MIN_LEN: Final[int] = 8

_PER_PAGE_DEFAULT: Final[int] = 20
_PER_PAGE_MAX: Final[int] = 100
_PER_PAGE_MIN: Final[int] = 1
_PAGE_MIN: Final[int] = 1

_SESSIONS_HISTORY_LIMIT: Final[int] = 50

_SORT_ALLOWED: Final[frozenset[str]] = frozenset(
    {"username", "email", "role", "is_active", "last_login", "created_at"}
)
_SORT_ORDER_ALLOWED: Final[frozenset[str]] = frozenset({"asc", "desc"})

# Statut textuel — « active » / « inactive » / vide
_STATUS_ACTIVE: Final[str] = "active"
_STATUS_INACTIVE: Final[str] = "inactive"


# ---------------------------------------------------------------------------
# Helpers de coercion — fail-closed, JAMAIS de cast silencieux
# ---------------------------------------------------------------------------


#: Plafond de longueur défensif pour les query-params textuels (search,
#: filtres, etc.). Bug 2026-05-26 (F13) : sans cap, un crafted URL avec
#: 100 KB de ``?search=...`` déclenchait un full-scan SQLite + log spam.
#: Cap raisonnable : 200 chars (déjà au-delà de tout cas légitime —
#: username 100, email 254).
_QUERY_PARAM_MAX_LEN: Final[int] = 200


def _coerce_str(value: Any, *, strip: bool = True, max_len: int | None = None) -> str:
    """Coerce une valeur JSON/query-param en ``str``. Non-string → ``""``.

    ``strip=True`` (défaut) trime les bords — OK pour username/email/role.
    ``strip=False`` préserve les espaces — OBLIGATOIRE pour les mots de passe
    (ASVS 2.1.3). Voir le docstring module pour la justification.

    ``max_len`` (kwarg-only) : si donné, tronque silencieusement à
    ``max_len`` chars APRÈS strip. Utile pour les query-params (DoS via
    long search) — pas pour les body fields (le validateur de body
    rejette ``> max_len`` proprement avec 400). Bug 2026-05-26 (F13) :
    avant, ``search`` accepté de 100KB → full-scan SQLite + log spam.
    """
    if not isinstance(value, str):
        return ""
    result = value.strip() if strip else value
    if max_len is not None and len(result) > max_len:
        result = result[:max_len]
    return result


def _coerce_bool_strict(value: Any) -> bool | None:
    """Coerce une valeur JSON en ``bool`` strict. Retourne ``None`` si ambigu.

    Volontairement plus strict que ``bool(value)`` : ``bool("False") == True``
    et ``bool(0) == False``, deux sémantiques surprenantes qui ont déjà
    produit des activations involontaires dans d'autres projets. On n'accepte
    QUE les booléens JSON natifs (``true`` / ``false``).
    """
    if isinstance(value, bool):
        return value
    return None


def _parse_positive_int(
    raw: str, *, name: str, default: int, minimum: int, maximum: int | None = None
) -> int:
    """Parse un entier positif clampé dans ``[minimum, maximum]``.

    - ``raw`` vide ou non numérique → ``default``.
    - Entier < ``minimum`` → ``minimum`` (clamp, pas d'erreur 400).
    - Entier > ``maximum`` (si fourni) → ``maximum`` (clamp).

    Choix du clamp plutôt que 400 : la pagination est un paramètre d'UI, un
    clamp silencieux est plus tolérant qu'une erreur bloquante pour un GET.
    Pour les champs critiques (IDs de ressource), :meth:`BaseHandler._parse_int_or_400`
    reste appelé dans les URLs elles-mêmes.
    """
    if not raw:
        return default
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        logger.debug("Param %s invalide (%r), fallback sur %d", name, raw, default)
        return default
    if parsed < minimum:
        return minimum
    if maximum is not None and parsed > maximum:
        return maximum
    return parsed


def _validate_create_user(data: dict[str, Any]) -> list[dict[str, str]]:
    """Valide le payload JSON de création d'utilisateur.

    Retourne une liste d'erreurs homogène ``[{field, error, message}, ...]``
    — vide si tout est valide. Ne lève pas : le caller accumule les erreurs
    pour les renvoyer en une fois (UX formulaires).

    *Note — le mot de passe est vérifié SANS strip*. Les espaces en bord de
    mot de passe font partie du secret (ASVS 2.1.3).
    """
    errors: list[dict[str, str]] = []

    username = _coerce_str(data.get("username"))
    if not username or len(username) < _USERNAME_MIN_LEN:
        errors.append(
            {
                "field": "username",
                "error": "Invalid username",
                "message": (
                    f"Le nom d'utilisateur doit faire au moins {_USERNAME_MIN_LEN} caractères"
                ),
            }
        )
    elif len(username) > _USERNAME_MAX_LEN:
        errors.append(
            {
                "field": "username",
                "error": "Invalid username",
                "message": (
                    f"Le nom d'utilisateur ne peut pas dépasser {_USERNAME_MAX_LEN} caractères"
                ),
            }
        )

    email = _coerce_str(data.get("email"))
    if not email or "@" not in email:
        errors.append({"field": "email", "error": "Invalid email", "message": "Email invalide"})

    # Mot de passe : pas de strip — l'espace fait partie du secret.
    password = _coerce_str(data.get("password"), strip=False)
    if not password or len(password) < _PASSWORD_MIN_LEN:
        errors.append(
            {
                "field": "password",
                "error": "Invalid password",
                "message": (f"Le mot de passe doit faire au moins {_PASSWORD_MIN_LEN} caractères"),
            }
        )
    elif password_exceeds_bcrypt_limit(password):
        # bcrypt n'utilise que les 72 premiers octets — au-delà, rejet explicite
        # (cf. app.core.constants_auth.PASSWORD_MAX_BYTES, SSoT).
        errors.append(
            {
                "field": "password",
                "error": "Invalid password",
                "message": (f"Le mot de passe ne peut pas dépasser {PASSWORD_MAX_BYTES} octets."),
            }
        )

    role_raw = _coerce_str(data.get("role", "user")).lower() or "user"
    try:
        UserRole(role_raw)
    except ValueError:
        errors.append(
            {
                "field": "role",
                "error": "Invalid role",
                "message": f"Rôle invalide: {role_raw}",
            }
        )

    return errors


# ---------------------------------------------------------------------------
# Mapping IntegrityError → exception métier (conflit unicité DB)
# ---------------------------------------------------------------------------


def _integrity_error_to_business(err: IntegrityError) -> Exception:
    """Convertit une contrainte UNIQUE violée en :class:`AdminError` parlante.

    On inspecte ``err.orig`` (message SQLite brut) pour savoir SI c'est le
    conflit ``username`` ou ``email``. Pas de pattern-matching sur
    ``str(err)`` — le format varie entre dialectes SQL et versions de pilotes.
    Si l'inspection échoue, on relève l'original (meilleur que mentir à
    l'utilisateur avec un message arbitraire).
    """
    orig = str(getattr(err, "orig", err)).lower()
    if "users.username" in orig or ".username" in orig:
        return UsernameExistsError(
            "Ce nom d'utilisateur existe déjà.", context={"field": "username"}
        )
    if "users.email" in orig or ".email" in orig:
        return EmailExistsError("Cet email est déjà utilisé.", context={"field": "email"})
    # Contrainte inconnue — on ne devine pas.
    return err


# ---------------------------------------------------------------------------
# Handlers — un rôle par handler, méthodes HTTP explicites
# ---------------------------------------------------------------------------


class AdminHandler(BaseHandler):
    """Page SSR d'administration : liste paginée + filtres + stats globales."""

    @admin_required
    async def get(self) -> None:
        """Rend la page d'administration."""
        current_user = self.current_user

        page = _parse_positive_int(
            self.get_argument("page", ""),
            name="page",
            default=1,
            minimum=_PAGE_MIN,
        )
        per_page = _parse_positive_int(
            self.get_argument("per_page", ""),
            name="per_page",
            default=_PER_PAGE_DEFAULT,
            minimum=_PER_PAGE_MIN,
            maximum=_PER_PAGE_MAX,
        )

        # Plafond défensif pour query-params textuels (anti-DoS F13).
        # Le ``search`` est ensuite envoyé comme ``%search%`` à SQLite ;
        # sans cap, 100KB → full-scan + log spam.
        search = _coerce_str(self.get_argument("search", ""), max_len=_QUERY_PARAM_MAX_LEN)
        role_filter = _coerce_str(
            self.get_argument("role", ""), max_len=_QUERY_PARAM_MAX_LEN
        ).lower()
        status_filter = _coerce_str(
            self.get_argument("status", ""), max_len=_QUERY_PARAM_MAX_LEN
        ).lower()

        sort_by = _coerce_str(self.get_argument("sort", "created_at"))
        if sort_by not in _SORT_ALLOWED:
            sort_by = "created_at"

        sort_order = _coerce_str(self.get_argument("order", "desc")).lower()
        if sort_order not in _SORT_ORDER_ALLOWED:
            sort_order = "desc"

        # Filtre rôle : 400 explicite plutôt que silent-ignore. Un front-end
        # qui envoie une valeur inconnue a un bug qu'il vaut mieux remonter.
        role_enum: UserRole | None = None
        if role_filter:
            try:
                role_enum = UserRole(role_filter)
            except ValueError:
                raise tornado.web.HTTPError(400, f"Rôle invalide: {role_filter}")

        # Bug 2026-05-26 (Agent 2 F9) : timeout par-SELECT + flag dégradé.
        # Avant, 4 SELECT séquentiels sans timeout → BDD locked = page bloquée
        # ou 5xx. Maintenant chaque SELECT a un timeout 3s ; si dépassé,
        # fallback dégradé (users=[], total=0, banner UI via ``stats_degraded``).
        _ADMIN_SELECT_TIMEOUT_S: float = 3.0
        stats_degraded = False
        status_filter_canonical = ""

        async with get_session() as session:
            sort_col = getattr(User, sort_by)
            order = sort_col.asc() if sort_order == "asc" else sort_col.desc()
            query = select(User)

            if search:
                # LIKE avec escape de %, _ et \ pour éviter les injections de
                # wildcards par l'utilisateur.
                escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                pattern = f"%{escaped}%"
                query = query.where(
                    (User.username.like(pattern, escape="\\"))
                    | (User.email.like(pattern, escape="\\"))
                )

            if role_enum is not None:
                query = query.where(User.role == role_enum)

            if status_filter == _STATUS_ACTIVE:
                query = query.where(User.is_active.is_(True))
                status_filter_canonical = _STATUS_ACTIVE
            elif status_filter == _STATUS_INACTIVE:
                query = query.where(User.is_active.is_(False))
                status_filter_canonical = _STATUS_INACTIVE

            # COUNT sur la sous-requête filtrée : on retire l'ORDER BY avant
            # de compter (inutile + coûteux sur certains backends ; sur
            # SQLite ça ne casse pas mais c'est un best-practice universel).
            count_subquery = query.order_by(None).subquery()
            try:
                total_users = int(
                    (
                        await asyncio.wait_for(
                            session.execute(select(func.count()).select_from(count_subquery)),
                            timeout=_ADMIN_SELECT_TIMEOUT_S,
                        )
                    ).scalar()
                    or 0
                )
            except (asyncio.TimeoutError, SQLAlchemyError):
                logger.warning(
                    "AdminHandler.get: COUNT total_users a timeout/error — " "dégradé total_users=0"
                )
                stats_degraded = True
                total_users = 0

            offset = (page - 1) * per_page
            paged_query = query.order_by(order).offset(offset).limit(per_page)

            try:
                users_orm = (
                    (
                        await asyncio.wait_for(
                            session.execute(paged_query),
                            timeout=_ADMIN_SELECT_TIMEOUT_S,
                        )
                    )
                    .scalars()
                    .all()
                )
            except (asyncio.TimeoutError, SQLAlchemyError):
                logger.warning(
                    "AdminHandler.get: SELECT users a timeout/error — " "dégradé liste vide"
                )
                stats_degraded = True
                users_orm = []

            # SimpleNamespace : on capture les valeurs DANS la session pour
            # éviter MissingGreenlet sur les lazy-loads depuis le template.
            # ``ensure_utc`` : la BDD stocke les datetimes en naïf (DateTime
            # sans timezone=True) → on force ``+00:00`` ici pour que le
            # template puisse rendre un ``<time datetime="...">`` ISO non
            # ambigu (le JS local convertit ensuite vers le fuseau du user).
            users = [
                SimpleNamespace(
                    id=u.id,
                    username=u.username,
                    email=u.email,
                    role=u.role,
                    is_active=u.is_active,
                    last_login=ensure_utc(u.last_login),
                    created_at=ensure_utc(u.created_at),
                )
                for u in users_orm
            ]

            # Bug 2026-05-26 (Agent 2 F1) : SSoT via
            # ``admin_service.count_basic_user_stats`` — partagé avec
            # ``dashboard/admin_stats.py``. Les 3 compteurs (total/active/admins)
            # restent calculés en 3 SELECT mais sortis dans un service unique
            # → drift impossible avec le dashboard.
            # Bug 2026-05-26 (F9) : timeout 3s avec fallback dégradé.
            from app.services.admin_service import count_basic_user_stats

            try:
                _basic_stats = await asyncio.wait_for(
                    count_basic_user_stats(session),
                    timeout=_ADMIN_SELECT_TIMEOUT_S,
                )
                total_active = _basic_stats["active"]
                total_admins = _basic_stats["admins"]
                total_all_users = _basic_stats["total"]
            except (asyncio.TimeoutError, SQLAlchemyError):
                logger.warning(
                    "AdminHandler.get: count_basic_user_stats timeout/error — "
                    "dégradé total/active/admins=0"
                )
                stats_degraded = True
                total_active = 0
                total_admins = 0
                total_all_users = 0

        total_pages = (total_users + per_page - 1) // per_page if per_page else 0

        self.render(
            "admin/users.html",
            # Bug 2026-05-26 (Agent 2 F8) : page_title aligné sur le
            # label sidebar (« Utilisateurs ») pour cohérence
            # breadcrumb. Le préfixe « Administration » est déjà rendu
            # par la sidebar section title — pas besoin de doubler.
            page_title="Utilisateurs",
            users=users,
            current_page=page,
            total_pages=total_pages,
            total_users=total_users,
            per_page=per_page,
            search=search,
            role_filter=role_filter,
            status_filter=status_filter_canonical,
            sort_by=sort_by,
            sort_order=sort_order,
            user=current_user,
            UserRole=UserRole,
            total_all_users=total_all_users,
            total_active=total_active,
            total_admins=total_admins,
            stats_degraded=stats_degraded,
        )


class UsersAPIHandler(BaseHandler):
    """API REST de la collection ``/api/users`` (liste + création)."""

    # Exposée pour rétro-compatibilité des tests unitaires qui appellent
    # ``handler._validate_user_data(...)`` — délègue au helper module.
    def _validate_user_data(self, data: dict[str, Any]) -> list[dict[str, str]]:
        """Valide un payload de création d'utilisateur (voir :func:`_validate_create_user`)."""
        return _validate_create_user(data)

    @admin_required
    async def get(self) -> None:
        """Liste paginée des utilisateurs.

        Toujours paginée — une collection potentiellement illimitée ne doit
        jamais être renvoyée en une seule réponse (DoS par taille, lenteur
        progressive en N). ``page`` et ``per_page`` sont clampés comme pour
        :meth:`AdminHandler.get`.
        """
        page = _parse_positive_int(
            self.get_argument("page", ""),
            name="page",
            default=1,
            minimum=_PAGE_MIN,
        )
        per_page = _parse_positive_int(
            self.get_argument("per_page", ""),
            name="per_page",
            default=_PER_PAGE_DEFAULT,
            minimum=_PER_PAGE_MIN,
            maximum=_PER_PAGE_MAX,
        )

        async with get_session() as session:
            total = int(
                (await session.execute(select(func.count()).select_from(User))).scalar() or 0
            )
            offset = (page - 1) * per_page
            result = await session.execute(
                select(User).order_by(User.created_at.desc()).offset(offset).limit(per_page)
            )
            users = result.scalars().all()

            users_data = [
                {
                    "id": u.id,
                    "username": u.username,
                    "email": u.email,
                    "role": u.role.value,
                    "is_active": u.is_active,
                    # ``ensure_utc`` ajoute ``+00:00`` à l'ISO, condition pour
                    # que JS ``new Date(...)`` interprète correctement comme
                    # UTC plutôt que comme heure locale.
                    "last_login": (ensure_utc(u.last_login).isoformat() if u.last_login else None),
                    "created_at": ensure_utc(u.created_at).isoformat(),
                }
                for u in users
            ]

            total_pages = (total + per_page - 1) // per_page if per_page else 0
            self.write(
                {
                    "success": True,
                    "users": users_data,
                    "total": total,
                    "page": page,
                    "per_page": per_page,
                    "total_pages": total_pages,
                }
            )

    @admin_required
    async def post(self) -> None:
        """Crée un utilisateur.

        Flux :
        1. Valide les types et contraintes de format (length, @ dans email,
           rôle dans enum).
        2. Vérifie le quota ``max_users`` (service layer).
        3. Insère ; l'unicité ``UNIQUE`` est vérifiée par la base — on catch
           :class:`IntegrityError` et on le convertit en réponse 409 avec
           le bon champ mappé.
        """
        current_user = self.current_user
        config = get_config()
        data = self.get_json_body()

        errors = _validate_create_user(data)
        if errors:
            self.set_status(400)
            self.write({"errors": errors})
            return

        username = _coerce_str(data.get("username"))
        email = _coerce_str(data.get("email"))
        password = _coerce_str(data.get("password"), strip=False)
        role_str = _coerce_str(data.get("role", "user")).lower() or "user"
        user_role = UserRole(role_str)

        # ``is_active`` absent → True. Présent mais type invalide → 400.
        is_active_raw = data.get("is_active", True)
        is_active = _coerce_bool_strict(is_active_raw)
        if is_active is None:
            self.set_status(400)
            self.write(
                {
                    "error": "Invalid is_active",
                    "message": "`is_active` doit être un booléen JSON (true/false).",
                }
            )
            return

        try:
            async with get_session() as session:
                current_active = await active_user_count(session)
                max_users = config.limits.max_users
                if current_active >= max_users:
                    if not config.limits.allow_admin_override:
                        self.set_status(403)
                        self.write(
                            {
                                "error": "User limit reached",
                                "message": (
                                    f"Limite maximale d'utilisateurs atteinte "
                                    f"({max_users} utilisateurs actifs)."
                                ),
                            }
                        )
                        return
                    logger.warning(
                        "Quota max_users dépassé — override admin actif (%d/%d)",
                        current_active,
                        max_users,
                        extra={"admin_username": current_user.username},
                    )
                elif current_active >= config.limits.max_users_warning_at:
                    logger.warning(
                        "Approche du quota max_users (%d/%d)",
                        current_active,
                        max_users,
                        extra={"admin_username": current_user.username},
                    )

                password_hash = PasswordHasher().hash_password(password)
                new_user = User(
                    username=username,
                    email=email,
                    password_hash=password_hash,
                    role=user_role,
                    is_active=is_active,
                )
                session.add(new_user)
                try:
                    await session.commit()
                except IntegrityError as exc:
                    await session.rollback()
                    raise _integrity_error_to_business(exc) from exc

                await session.refresh(new_user)

                logger.info(
                    "Utilisateur créé par admin",
                    extra={
                        "admin_id": current_user.id,
                        "admin_username": current_user.username,
                        "new_user_id": new_user.id,
                        "new_username": new_user.username,
                        "role": new_user.role.value,
                    },
                )

                # Audit légal : création d'utilisateur tracée dans ``audit_logs``
                # (compliance RGPD / audit cabinet comptable). Best-effort BORNÉ
                # (≤ timeout) via le helper SSoT — identique au login : un lock
                # transitoire ne casse pas la création déjà committée (ligne ~621)
                # et ne retient pas la réponse 201 au-delà du timeout ; un bug de
                # construction de l'audit reste visible (ERROR, cf. le helper).
                await record_audit_best_effort(
                    user_id=current_user.id,
                    action=AuditAction.USER_CREATE,
                    entity_type="user",
                    entity_id=new_user.id,
                    details={
                        "new_username": new_user.username,
                        "role": new_user.role.value,
                        "is_active": new_user.is_active,
                    },
                    ip_address=self.request.remote_ip,
                    user_agent=self.request.headers.get("User-Agent"),
                )

                self.set_status(201)
                self.write(
                    {
                        "success": True,
                        "message": "Utilisateur créé avec succès",
                        "user": {
                            "id": new_user.id,
                            "username": new_user.username,
                            "email": new_user.email,
                            "role": new_user.role.value,
                            "is_active": new_user.is_active,
                        },
                    }
                )
        except (UsernameExistsError, EmailExistsError) as exc:
            self.set_status(exc.http_status)
            self.write(
                {
                    "error": "Conflict",
                    "code": exc.code,
                    "message": exc.message,
                }
            )
        except SQLAlchemyError as exc:
            logger.error(
                "Erreur base de données lors de la création utilisateur: %s", exc, exc_info=True
            )
            self.set_status(500)
            self.write(
                {
                    "error": "Server error",
                    "message": "Erreur lors de la création de l'utilisateur",
                }
            )


class UserAPIHandler(BaseHandler):
    """API REST d'une ressource ``/api/users/<id>`` (modification + suppression)."""

    @admin_required
    async def put(self, user_id: str) -> None:
        """Met à jour un utilisateur.

        Règles critiques :

        - L'admin connecté ne peut ni se démote (change ``role``) ni se
          désactiver (``is_active=False``) lui-même — protection
          anti-auto-lockout distincte de la guarde « dernier admin ».
        - Toute **perte de privilège** (demote, désactivation, changement
          de mot de passe) révoque atomiquement les sessions actives.
        - La guarde « au moins un admin actif » est vérifiée dans la MÊME
          transaction que la mutation (:func:`ensure_not_last_admin`).
        """
        current_user = self.current_user
        user_id_int = self._parse_int_or_400(user_id, "user_id")
        data = self.get_json_body()

        try:
            async with get_session() as session:
                result = await session.execute(select(User).where(User.id == user_id_int))
                user = result.scalar_one_or_none()
                if not user:
                    self.set_status(404)
                    self.write({"error": "Not found", "message": "Utilisateur introuvable"})
                    return

                privilege_lost = False

                if "email" in data:
                    new_email = _coerce_str(data.get("email"))
                    if not new_email or "@" not in new_email:
                        self.set_status(400)
                        self.write({"error": "Invalid email", "message": "Email invalide"})
                        return
                    # Unicité : on laisse la base trancher via IntegrityError
                    # sur le commit final — pas de pré-check TOCTOU-able.
                    user.email = new_email

                if "role" in data:
                    role_val = data.get("role")
                    if not isinstance(role_val, str):
                        self.set_status(400)
                        self.write(
                            {
                                "error": "Invalid role",
                                "message": "Le rôle doit être une chaîne.",
                            }
                        )
                        return
                    try:
                        new_role = UserRole(role_val.lower())
                    except ValueError:
                        self.set_status(400)
                        self.write(
                            {
                                "error": "Invalid role",
                                "message": f"Rôle invalide: {role_val}",
                            }
                        )
                        return

                    if (
                        user.role == UserRole.ADMIN
                        and new_role != UserRole.ADMIN
                        and user.id == current_user.id
                    ):
                        self.set_status(400)
                        self.write(
                            {
                                "error": "Bad request",
                                "message": ("Vous ne pouvez pas retirer votre propre rôle admin."),
                            }
                        )
                        return

                    if user.role == UserRole.ADMIN and new_role != UserRole.ADMIN:
                        await ensure_not_last_admin(
                            session,
                            target_user_id=user.id,
                            operation="demote",
                        )
                        privilege_lost = True
                    user.role = new_role

                if "is_active" in data:
                    new_active = _coerce_bool_strict(data.get("is_active"))
                    if new_active is None:
                        self.set_status(400)
                        self.write(
                            {
                                "error": "Invalid is_active",
                                "message": "`is_active` doit être un booléen JSON.",
                            }
                        )
                        return
                    if user.is_active and not new_active and user.id == current_user.id:
                        self.set_status(400)
                        self.write(
                            {
                                "error": "Bad request",
                                "message": "Vous ne pouvez pas désactiver votre propre compte.",
                            }
                        )
                        return
                    if user.is_active and not new_active and user.role == UserRole.ADMIN:
                        await ensure_not_last_admin(
                            session,
                            target_user_id=user.id,
                            operation="deactivate",
                        )
                    if user.is_active and not new_active:
                        privilege_lost = True
                    user.is_active = new_active

                if "password" in data:
                    # Pas de strip — espaces significatifs (ASVS 2.1.3).
                    password = _coerce_str(data.get("password"), strip=False)
                    if password:
                        if len(password) < _PASSWORD_MIN_LEN:
                            self.set_status(400)
                            self.write(
                                {
                                    "error": "Invalid password",
                                    "message": (
                                        f"Le mot de passe doit faire au moins "
                                        f"{_PASSWORD_MIN_LEN} caractères"
                                    ),
                                }
                            )
                            return
                        if password_exceeds_bcrypt_limit(password):
                            # bcrypt ignore les octets au-delà du 72e (SSoT :
                            # app.core.constants_auth.PASSWORD_MAX_BYTES).
                            self.set_status(400)
                            self.write(
                                {
                                    "error": "Invalid password",
                                    "message": (
                                        f"Le mot de passe ne peut pas dépasser "
                                        f"{PASSWORD_MAX_BYTES} octets."
                                    ),
                                }
                            )
                            return
                        user.password_hash = PasswordHasher().hash_password(password)
                        # Changement de mot de passe ⇒ sessions à révoquer
                        # (best practice OWASP : forcer re-login après rotation).
                        privilege_lost = True

                if privilege_lost:
                    revoked = await revoke_user_sessions(session, user.id)
                    if revoked:
                        logger.info(
                            "Sessions révoquées suite à une perte de privilège (%d)",
                            revoked,
                            extra={
                                "target_user_id": user.id,
                                "admin_id": current_user.id,
                            },
                        )

                try:
                    await session.commit()
                except IntegrityError as exc:
                    await session.rollback()
                    raise _integrity_error_to_business(exc) from exc

                await session.refresh(user)

                logger.info(
                    "Utilisateur modifié par admin",
                    extra={
                        "admin_id": current_user.id,
                        "admin_username": current_user.username,
                        "modified_user_id": user.id,
                        "modified_username": user.username,
                    },
                )

                self.write(
                    {
                        "success": True,
                        "message": "Utilisateur modifié avec succès",
                        "user": {
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "role": user.role.value,
                            "is_active": user.is_active,
                        },
                    }
                )
        except LastAdminError as exc:
            self.set_status(exc.http_status)
            self.write({"error": "Bad request", "code": exc.code, "message": exc.message})
        except (UsernameExistsError, EmailExistsError) as exc:
            self.set_status(exc.http_status)
            self.write({"error": "Conflict", "code": exc.code, "message": exc.message})
        except SQLAlchemyError as exc:
            logger.error("Erreur modification utilisateur: %s", exc, exc_info=True)
            self.set_status(500)
            self.write({"error": "Server error", "message": "Erreur lors de la modification"})

    @admin_required
    async def delete(self, user_id: str) -> None:
        """Désactive (soft) ou supprime (hard) un utilisateur.

        ``?permanent=true`` → hard delete (CASCADE sur ``sessions`` via FK).
        Par défaut, soft-delete (``is_active=False``) + révocation explicite
        des sessions actives (la FK CASCADE ne s'applique qu'au hard-delete).
        """
        current_user = self.current_user
        permanent = self.get_argument("permanent", "false").lower() == "true"
        user_id_int = self._parse_int_or_400(user_id, "user_id")

        if user_id_int == current_user.id:
            self.set_status(400)
            self.write(
                {
                    "error": "Bad request",
                    "message": "Vous ne pouvez pas supprimer votre propre compte",
                }
            )
            return

        try:
            async with get_session() as session:
                result = await session.execute(select(User).where(User.id == user_id_int))
                user = result.scalar_one_or_none()
                if not user:
                    self.set_status(404)
                    self.write({"error": "Not found", "message": "Utilisateur introuvable"})
                    return

                # Capture AVANT toute mutation — les attrs sont expirés après commit.
                target_user_id = user.id
                target_username = user.username
                target_is_admin = user.role == UserRole.ADMIN
                target_was_active = user.is_active

                if permanent:
                    if target_is_admin:
                        await ensure_not_last_admin(
                            session, target_user_id=target_user_id, operation="delete"
                        )
                    # Révocation explicite avant delete : même si CASCADE le
                    # ferait via FK, on veut tracer le nombre de sessions
                    # révoquées dans les logs.
                    await revoke_user_sessions(session, target_user_id)
                    # Nettoyage des données rattachées AVANT le delete (SSoT :
                    # ``purge_user_owned_data``) — supprime contacts/listes (FK
                    # user-owned) et nulle les attributions (FK SET NULL) pour que
                    # ``session.delete`` ne lève pas d'IntegrityError sous FK ON,
                    # y compris sur les BDD antérieures à l'ajout du CASCADE/SET
                    # NULL. Défense en profondeur + suppression déterministe.
                    await purge_user_owned_data(session, target_user_id)
                    await session.delete(user)
                    await session.commit()
                    logger.info(
                        "Utilisateur supprimé définitivement par admin",
                        extra={
                            "admin_id": current_user.id,
                            "admin_username": current_user.username,
                            "deleted_user_id": target_user_id,
                            "deleted_username": target_username,
                        },
                    )
                    self.write({"success": True, "message": "Utilisateur supprimé définitivement"})
                else:
                    if target_is_admin and target_was_active:
                        await ensure_not_last_admin(
                            session, target_user_id=target_user_id, operation="deactivate"
                        )
                    user.is_active = False
                    revoked = await revoke_user_sessions(session, target_user_id)
                    await session.commit()
                    logger.info(
                        "Utilisateur désactivé par admin (%d sessions révoquées)",
                        revoked,
                        extra={
                            "admin_id": current_user.id,
                            "admin_username": current_user.username,
                            "disabled_user_id": target_user_id,
                            "disabled_username": target_username,
                        },
                    )
                    self.write({"success": True, "message": "Utilisateur désactivé avec succès"})
        except LastAdminError as exc:
            self.set_status(exc.http_status)
            self.write({"error": "Bad request", "code": exc.code, "message": exc.message})
        except SQLAlchemyError as exc:
            logger.error("Erreur suppression/désactivation utilisateur: %s", exc, exc_info=True)
            self.set_status(500)
            self.write({"error": "Server error", "message": "Erreur lors de l'opération"})


# ---------------------------------------------------------------------------
# Bulk actions sur /admin/users
# ---------------------------------------------------------------------------

#: Cap dur sur la taille d'un batch — au-delà, la transaction unique devient
#: risquée (timeout, locks longs, OOM). 100 = couvre les usages normaux de
#: l'admin sans permettre un DoS via un payload géant.
_USER_BULK_MAX_IDS: Final[int] = 100

#: Allow-list des actions bulk supportées. Toute autre valeur → 400.
_USER_BULK_ACTIONS: Final[frozenset[str]] = frozenset({"deactivate", "delete"})


class UserBulkAPIHandler(BaseHandler):
    """``POST /api/users/bulk`` — bulk désactivation / suppression atomique.

    Bug 2026-05-26 (F3 CRITIQUE) : avant ce handler, le frontend bouclait
    sur N appels DELETE individuels (``templates/admin/users.html::bulkAction``).
    Si l'appel 5/10 plantait (last-admin guard, BDD lock, réseau), les 4
    premiers étaient committés et les 6 derniers laissés intacts — l'état UI
    affichait alors un mélange incohérent, sans rollback possible.

    Politique nouvelle :

    - **Atomique** : toutes les mutations dans une seule transaction. Un
      seul commit en fin de batch. Erreur → ``rollback`` de TOUT le batch.
    - **Fail-fast sur invariants** : last-admin, self-target, ghost user
      → 400 avec contexte (``failed_user_id``) AVANT toute mutation.
    - **Idempotent côté UI** : si le batch fail, rien n'a changé en BDD
      → l'UI peut réafficher la liste sans craindre un état partiel.
    """

    @admin_required
    async def post(self) -> None:
        current_user = self.current_user

        try:
            body = self.load_json_body(max_bytes=64 * 1024)
        except ValueError as exc:
            self.set_status(400)
            self.write({"error": "Bad request", "message": str(exc)})
            return

        action = body.get("action")
        if action not in _USER_BULK_ACTIONS:
            self.set_status(400)
            self.write(
                {
                    "error": "Bad request",
                    "message": (f"Action invalide. Attendu : {sorted(_USER_BULK_ACTIONS)}."),
                }
            )
            return

        raw_ids = body.get("user_ids")
        if not isinstance(raw_ids, list) or not raw_ids:
            self.set_status(400)
            self.write(
                {
                    "error": "Bad request",
                    "message": "user_ids doit être une liste non vide.",
                }
            )
            return

        if len(raw_ids) > _USER_BULK_MAX_IDS:
            self.set_status(400)
            self.write(
                {
                    "error": "Bad request",
                    "message": (
                        f"Trop d'identifiants ({len(raw_ids)}). "
                        f"Maximum {_USER_BULK_MAX_IDS} par batch."
                    ),
                }
            )
            return

        # Validation des types + dédup. Un seul ID invalide → 400 (pas de
        # silent skip ; l'admin doit savoir ce qui n'a pas été pris).
        try:
            user_ids = sorted({int(x) for x in raw_ids})
        except (TypeError, ValueError):
            self.set_status(400)
            self.write(
                {
                    "error": "Bad request",
                    "message": "user_ids doit contenir uniquement des entiers.",
                }
            )
            return

        if current_user.id in user_ids:
            self.set_status(400)
            self.write(
                {
                    "error": "Bad request",
                    "message": "Vous ne pouvez pas vous inclure dans une action bulk.",
                    "failed_user_id": current_user.id,
                }
            )
            return

        permanent = bool(body.get("permanent", False))
        # "delete" + permanent=False = soft-delete (alias de "deactivate").
        # On laisse l'UI choisir explicitement ; on n'invente pas de défaut.

        try:
            async with get_session() as session:
                rows = (
                    (await session.execute(select(User).where(User.id.in_(user_ids))))
                    .scalars()
                    .all()
                )
                found_map = {u.id: u for u in rows}

                missing = [uid for uid in user_ids if uid not in found_map]
                if missing:
                    self.set_status(404)
                    self.write(
                        {
                            "error": "Not found",
                            "message": (f"{len(missing)} utilisateur(s) introuvable(s)."),
                            "missing_user_ids": missing,
                        }
                    )
                    return

                # Pré-check global : last-admin. On compte les admins actifs
                # qui SERAIENT touchés ; si on en supprime/désactive tous, on
                # garde au moins 1 admin actif après le batch. ``ensure_not_last_admin``
                # est par-row, donc on doit l'orchestrer ici.
                admin_targets = [u for u in rows if u.role == UserRole.ADMIN and u.is_active]
                if admin_targets:
                    total_active_admins = (
                        await session.execute(
                            select(func.count())
                            .select_from(User)
                            .where(User.role == UserRole.ADMIN, User.is_active.is_(True))
                        )
                    ).scalar() or 0
                    if total_active_admins - len(admin_targets) < 1:
                        self.set_status(400)
                        self.write(
                            {
                                "error": "Bad request",
                                "code": "last_admin",
                                "message": (
                                    "Le batch retirerait le dernier administrateur "
                                    "actif. Conservez au moins un admin actif."
                                ),
                                "admin_targets": [u.id for u in admin_targets],
                            }
                        )
                        return

                # Application des mutations. Pas de commit intermédiaire —
                # tout en un seul commit en fin pour atomicité réelle.
                #
                # B1-F1 : sous ``PRAGMA foreign_keys = ON`` (cf. database.py), un
                # ``session.delete(u)`` sur un user qui possède des contacts/listes
                # (FK NOT NULL) ou des attributions en RESTRICT lèverait une
                # IntegrityError au commit → rollback du batch ENTIER → 500. On
                # pré-nettoie via la MÊME SSoT que le chemin unitaire
                # (``purge_user_owned_data``) : suppression contacts/listes + null
                # des attributions, AVANT le delete.
                affected: list[int] = []
                revoked_total = 0
                for u in rows:
                    if action == "delete" and permanent:
                        await purge_user_owned_data(session, u.id)
                        revoked_total += await revoke_user_sessions(session, u.id)
                        await session.delete(u)
                    else:
                        u.is_active = False
                        revoked_total += await revoke_user_sessions(session, u.id)
                    affected.append(u.id)

                await session.commit()

                logger.info(
                    "Bulk %s appliqué par admin (%d users, %d sessions révoquées)",
                    action,
                    len(affected),
                    revoked_total,
                    extra={
                        "admin_id": current_user.id,
                        "admin_username": current_user.username,
                        "bulk_action": action,
                        "bulk_permanent": permanent,
                        "bulk_user_ids": affected,
                    },
                )

            # ADV-18 (2026-05-26) : audit_event en BDD pour traçabilité long
            # terme. ``logger.info`` ci-dessus va dans le log applicatif (sujet
            # à rotation), alors que ``audit_logs`` est conservé selon le TTL
            # admin. Convention Komptia (cf. ai_admin.AIFeedbackExportHandler,
            # automations) : actions sensibles → audit_event + logger.
            # Best-effort : un échec d'audit ne doit pas casser le success path.
            try:
                async with get_session() as audit_session:
                    await audit_event(
                        audit_session,
                        user_id=current_user.id,
                        action=(
                            "users.bulk_delete_permanent"
                            if action == "delete" and permanent
                            else f"users.bulk_{action}"
                        ),
                        entity_type="user",
                        entity_id=None,
                        details={
                            "action": action,
                            "permanent": permanent,
                            "affected_count": len(affected),
                            "affected_user_ids": affected,
                            "revoked_sessions": revoked_total,
                        },
                        ip_address=self.request.remote_ip,
                        user_agent=self.request.headers.get("User-Agent"),
                    )
                    await audit_session.commit()
            except (SQLAlchemyError, Exception) as exc:  # noqa: BLE001 - best-effort
                logger.warning("Bulk %s: audit_event a échoué: %s", action, exc)

            self.write(
                {
                    "success": True,
                    "affected_count": len(affected),
                    "revoked_sessions": revoked_total,
                    "action": action,
                    "permanent": permanent,
                }
            )
        except LastAdminError as exc:
            # Filet de secours : si la guard locale rate-row (revoke_user_sessions
            # a son propre ensure), on bascule sur le code structuré sans laisser
            # passer en 500.
            self.set_status(exc.http_status)
            self.write(
                {
                    "error": "Bad request",
                    "code": exc.code,
                    "message": exc.message,
                }
            )
        except SQLAlchemyError as exc:
            logger.error("Bulk %s: erreur BDD: %s", action, exc, exc_info=True)
            self.set_status(500)
            self.write(
                {
                    "error": "Server error",
                    "message": "Erreur lors du batch. Aucune modification appliquée.",
                }
            )


class UserSessionsAPIHandler(BaseHandler):
    """API REST ``/api/users/<id>/sessions`` — historique + révocation."""

    @admin_required
    async def get(self, user_id: str) -> None:
        """Retourne les N dernières sessions d'un utilisateur (404 si ghost)."""
        user_id_int = self._parse_int_or_400(user_id, "user_id")

        try:
            async with get_session() as session:
                user_exists = (
                    await session.execute(
                        select(func.count()).select_from(User).where(User.id == user_id_int)
                    )
                ).scalar() or 0
                if not user_exists:
                    self.set_status(404)
                    self.write({"error": "Not found", "message": "Utilisateur introuvable"})
                    return

                result = await session.execute(
                    select(SessionModel)
                    .where(SessionModel.user_id == user_id_int)
                    .order_by(SessionModel.created_at.desc())
                    .limit(_SESSIONS_HISTORY_LIMIT)
                )
                sessions = result.scalars().all()

                sessions_data = [
                    {
                        "id": s.id,
                        "created_at": iso_or_none(s.created_at),
                        "expires_at": iso_or_none(s.expires_at),
                        "last_activity": iso_or_none(s.last_activity),
                        "ip_address": s.ip_address,
                        "user_agent": s.user_agent,
                        "is_active": s.is_active,
                        "is_expired": s.is_expired,
                    }
                    for s in sessions
                ]

                self.write(
                    {"success": True, "sessions": sessions_data, "total": len(sessions_data)}
                )
        except SQLAlchemyError as exc:
            logger.error("Erreur récupération sessions: %s", exc, exc_info=True)
            self.set_status(500)
            self.write(
                {
                    "error": "Server error",
                    "message": "Erreur lors de la récupération des sessions",
                }
            )

    @admin_required
    async def delete(self, user_id: str) -> None:
        """Révoque une session ciblée (``?session_id=...``) ou toutes."""
        current_user = self.current_user
        user_id_int = self._parse_int_or_400(user_id, "user_id")
        session_id = _coerce_str(self.get_argument("session_id", ""))

        try:
            async with get_session() as session:
                user_exists = (
                    await session.execute(
                        select(func.count()).select_from(User).where(User.id == user_id_int)
                    )
                ).scalar() or 0
                if not user_exists:
                    self.set_status(404)
                    self.write({"error": "Not found", "message": "Utilisateur introuvable"})
                    return

                from sqlalchemy import update

                if session_id:
                    result = await session.execute(
                        update(SessionModel)
                        .where(
                            SessionModel.id == session_id,
                            SessionModel.user_id == user_id_int,
                            SessionModel.is_active.is_(True),
                        )
                        .values(is_active=False)
                    )
                    count = int(result.rowcount or 0)
                    msg = (
                        "Session révoquée" if count > 0 else "Session introuvable ou déjà inactive"
                    )
                else:
                    count = await revoke_user_sessions(session, user_id_int)
                    msg = f"{count} session(s) révoquée(s)"

                await session.commit()

                logger.info(
                    "Sessions révoquées par admin",
                    extra={
                        "admin_id": current_user.id,
                        "admin_username": current_user.username,
                        "target_user_id": user_id_int,
                        "revoked_count": count,
                        "specific_session": session_id or "all",
                    },
                )

                self.write({"success": True, "message": msg, "revoked_count": count})
        except SQLAlchemyError as exc:
            logger.error("Erreur révocation sessions: %s", exc, exc_info=True)
            self.set_status(500)
            self.write(
                {
                    "error": "Server error",
                    "message": "Erreur lors de la révocation des sessions",
                }
            )
