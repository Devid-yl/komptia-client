"""Handlers admin pour la configuration des connexions BDD source.

Cinq surfaces (toutes ``admin_required``) :

* :class:`DatabaseConfigHandler` — page HTML ``/admin/database`` (GET).
* :class:`DatabaseConfigAPIHandler` — ``GET /api/db-config`` liste,
  ``POST /api/db-config`` création.
* :class:`DatabaseConfigDetailAPIHandler` — détail / update / delete.
* :class:`DatabaseConfigActivateHandler` — activation / désactivation.
* :class:`DatabaseConfigTestHandler` — test de connexion (existante ou
  ad-hoc avant sauvegarde) avec garde SSRF + rate-limit.
* :class:`SageModeHandler` — switch SQL Server ↔ SQLite copie locale.

Choix de design (équipe sénior) :

* **Réponse unifiée** — tous les endpoints utilisent
  :py:meth:`BaseHandler.write_json` ; jamais ``self.write({...})`` brut
  (cohérence Content-Type + UTF-8 + ``ensure_ascii=False`` pour les
  messages FR).
* **Validation centralisée** — ``_coerce_field`` borne port/timeout/
  max_rows et string lengths, refuse les CRLF (defense CWE-93). Les
  bornes sont aussi posées au niveau BDD (CheckConstraint) — défense
  en profondeur.
* **Rate-limit** — test de connexion + activation soumis à
  :class:`RateLimiter` pour éviter le port-scanning interne via le
  formulaire admin et le bash dance « activate / deactivate / activate »
  qui claque le sage_connector.
* **SSRF guard** — :func:`assert_safe_host` refuse les IP privées et
  les ports interdits avant tout I/O réseau (cf. ``app/utils/network_safety.py``).
* **Audit log** — chaque mutation (create/update/delete/activate/
  deactivate/test/sage-mode) génère une entrée :class:`AuditLog` pour
  pouvoir reconstruire qui a pointé l'app vers quel SQL Server quand.
* **Messages centralisés** — ``_Msg`` regroupe les messages FR
  user-facing pour faciliter l'audit + la future i18n.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Final, Mapping

from app.core import clock

from sqlalchemy.exc import OperationalError, SQLAlchemyError
from tornado.web import HTTPError

from app.config import config
from app.handlers.base import BaseHandler, admin_required
from app.models.audit import AuditAction, AuditLog
from app.services.database.db_config_service import (
    ConnectionInUseError,
    DuplicateConnectionError,
    activate_connection,
    create_connection,
    deactivate_connection,
    decrypt_password,
    delete_connection,
    get_connection,
    list_connections,
    test_connection,
    update_connection,
)
from app.services.database.sage_connector import (
    SAGE_SQLITE_COPY_PATH,
    get_current_sage_mode,
    switch_sage_mode,
)
from app.utils.logger import get_logger
from app.utils.network_safety import UnsafeHostError
from app.utils.rate_limiter import RateLimiter
from app.utils.template_helpers import to_dict_object
from app.utils.validators import assert_no_crlf, clean_input

logger = get_logger(__name__)


# --- Limites applicatives (zéro magic number éparpillé) --------------------

# Bornes serveur, doublent les bornes HTML — fail-closed pour qui contourne
# le front (curl, Postman, scraping). Cohérent avec les CheckConstraint
# du modèle ``app.models.db_config.DatabaseConnection``.
_PORT_MIN: Final[int] = 1
_PORT_MAX: Final[int] = 65535
_TIMEOUT_MIN: Final[int] = 1
_TIMEOUT_MAX: Final[int] = 600
_MAX_ROWS_MIN: Final[int] = 1
# Borne supérieure UI : très haute pour laisser l'admin saisir ce qu'il veut.
# Convention Komptia : pas de hard cap technique côté handlers SQL — la
# valeur saisie ici est l'UNIQUE source de vérité du plafond global.
# Borne fixée à 1 milliard juste pour éviter des entrées absurdes (texte,
# overflow int32 dans le check constraint BDD).
_MAX_ROWS_MAX: Final[int] = 1_000_000_000
_NAME_MAX_LEN: Final[int] = 100
_HOST_MAX_LEN: Final[int] = 255
_DATABASE_MAX_LEN: Final[int] = 255
_USERNAME_MAX_LEN: Final[int] = 255
# Cap défensif anti-body géant. Le mdp de connexion est chiffré Fernet (pas
# bcrypt) → aucune limite d'algorithme ; sans rapport avec la borne bcrypt 72o.
_PASSWORD_MAX_LEN: Final[int] = 1024

# Rate-limits — protections contre l'abus du formulaire admin.
# Test = (5 par 60s) : un admin légitime n'enchaîne pas 5 tests/sec ;
# sinon = port-scan interne.
# Activate = (5 par 5min) : changer la BDD active casse le sage_connector
# global → pas besoin d'en faire 100/min.
# Mutation = (20 par 60s) : large pour scripting CLI propre, refuse les
# loops bots.
_RATE_LIMIT_TEST: Final[tuple[int, int]] = (5, 60)
_RATE_LIMIT_ACTIVATE: Final[tuple[int, int]] = (5, 300)
_RATE_LIMIT_MUTATION: Final[tuple[int, int]] = (20, 60)
_RATE_LIMIT_SAGE_SWITCH: Final[tuple[int, int]] = (10, 60)

_test_limiter: Final[RateLimiter] = RateLimiter()
_activate_limiter: Final[RateLimiter] = RateLimiter()
_mutation_limiter: Final[RateLimiter] = RateLimiter()
_sage_switch_limiter: Final[RateLimiter] = RateLimiter()

# Sentinel ``conn_id`` utilisé par le formulaire de création pour signifier
# « teste les paramètres ad-hoc, pas une connexion enregistrée ». Documenté
# côté front (``static/js/db_config.js``) — ne jamais changer en silence.
_AD_HOC_TEST_SENTINEL: Final[str] = "0"

# Modes Sage acceptés par :class:`SageModeHandler`. ``frozenset`` pour
# bloquer toute mutation accidentelle.
_VALID_SAGE_MODES: Final[frozenset[str]] = frozenset({"sqlite", "sqlserver"})

# Chemin de la copie SQLite — SSoT importée depuis sage_connector (dérivée de
# DATA_DIR) pour que le pré-check ``.exists()`` ici et le guard du service
# partagent EXACTEMENT le même chemin (pas de dérivation divergente).
_SAGE_SQLITE_PATH: Final[Path] = SAGE_SQLITE_COPY_PATH


class _Msg:
    """Messages FR user-facing (centralisation pour audit + i18n future)."""

    NAME_REQUIRED: Final[str] = "Le nom est requis."
    NAME_TOO_LONG: Final[str] = f"Le nom est trop long (max {_NAME_MAX_LEN} caractères)."
    HOST_REQUIRED: Final[str] = "L'adresse du serveur est requise."
    HOST_TOO_LONG: Final[str] = f"L'adresse du serveur est trop longue (max {_HOST_MAX_LEN})."
    DATABASE_REQUIRED: Final[str] = "Le nom de la base est requis."
    DATABASE_TOO_LONG: Final[str] = f"Le nom de la base est trop long (max {_DATABASE_MAX_LEN})."
    USERNAME_REQUIRED: Final[str] = "Le nom d'utilisateur est requis."
    USERNAME_TOO_LONG: Final[str] = f"Le nom d'utilisateur est trop long (max {_USERNAME_MAX_LEN})."
    PASSWORD_REQUIRED: Final[str] = "Le mot de passe est requis."
    PASSWORD_TOO_LONG: Final[str] = (
        f"Le mot de passe est trop long (max {_PASSWORD_MAX_LEN} caractères)."
    )
    PORT_INVALID: Final[str] = f"Le port doit être un entier entre {_PORT_MIN} et {_PORT_MAX}."
    TIMEOUT_INVALID: Final[str] = (
        f"Le timeout doit être un entier entre {_TIMEOUT_MIN} et {_TIMEOUT_MAX} secondes."
    )
    MAX_ROWS_INVALID: Final[str] = (
        f"Le nombre maximum de lignes doit être entre {_MAX_ROWS_MIN} et {_MAX_ROWS_MAX}."
    )
    INVALID_CHARS: Final[str] = "Caractère invalide détecté dans un des champs."
    NOT_FOUND: Final[str] = "Connexion introuvable."
    CONFLICT_NAME: Final[str] = "Une connexion avec ce nom existe déjà."
    CANNOT_DELETE_ACTIVE: Final[str] = (
        "Impossible de supprimer la connexion active. Désactivez-la d'abord."
    )
    INTERNAL_ERROR: Final[str] = "Erreur interne du serveur."
    RATE_LIMIT_TEST: Final[str] = (
        "Trop de tests de connexion consécutifs. Réessayez dans une minute."
    )
    RATE_LIMIT_ACTIVATE: Final[str] = (
        "Trop d'activations consécutives. Réessayez dans quelques minutes."
    )
    RATE_LIMIT_MUTATION: Final[str] = "Trop d'opérations consécutives. Réessayez dans une minute."
    RATE_LIMIT_SAGE_SWITCH: Final[str] = (
        "Trop de changements de mode consécutifs. Réessayez dans une minute."
    )
    INVALID_SAGE_MODE: Final[str] = "Mode invalide. Utilisez 'sqlite' ou 'sqlserver'."
    SAGE_SQLITE_MISSING: Final[str] = (
        "Fichier de copie SQLite introuvable. Lancez d'abord la copie depuis SQL Server."
    )


# --- Helpers communs ------------------------------------------------------


def _check_rate_limit(
    limiter: RateLimiter, user_id: int, max_requests: int, window_seconds: int
) -> bool:
    """Wrapper unique pour la vérification rate-limit (clé = ``user:<id>``)."""
    return limiter.check(f"user:{user_id}", max_requests, window_seconds)


def _coerce_str_field(value: Any, field: str, max_len: int, required: bool) -> str | None:
    """Coerce un champ string : NBSP/trim, refus CRLF, bornage longueur.

    Retourne ``None`` si ``value`` est absent/vide ET ``required=False``.
    Lève ``ValueError`` (message FR) sinon.
    """
    cleaned = clean_input(value) if value is not None else None
    if not isinstance(cleaned, str) or not cleaned:
        if required:
            raise ValueError(_Msg.field_required(field))
        return None
    if len(cleaned) > max_len:
        raise ValueError(_Msg.field_too_long(field, max_len))
    assert_no_crlf(cleaned, field)
    return cleaned


def _coerce_int_field(
    value: Any, field: str, min_v: int, max_v: int, default: int | None = None
) -> int | None:
    """Coerce un champ int : refuse bool, borne min/max, default si absent."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return default
    if isinstance(value, bool):
        raise ValueError(f"Le champ '{field}' ne peut pas être un booléen.")
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Le champ '{field}' doit être un entier.") from exc
    if not min_v <= n <= max_v:
        raise ValueError(f"Le champ '{field}' doit être entre {min_v} et {max_v}.")
    return n


# Patch _Msg avec helpers (résout la circularité d'import).
def _field_required(field: str) -> str:
    mapping = {
        "name": _Msg.NAME_REQUIRED,
        "host": _Msg.HOST_REQUIRED,
        "database": _Msg.DATABASE_REQUIRED,
        "username": _Msg.USERNAME_REQUIRED,
        "password": _Msg.PASSWORD_REQUIRED,
    }
    return mapping.get(field, f"Le champ '{field}' est requis.")


def _field_too_long(field: str, max_len: int) -> str:
    mapping = {
        "name": _Msg.NAME_TOO_LONG,
        "host": _Msg.HOST_TOO_LONG,
        "database": _Msg.DATABASE_TOO_LONG,
        "username": _Msg.USERNAME_TOO_LONG,
        "password": _Msg.PASSWORD_TOO_LONG,
    }
    return mapping.get(field, f"Le champ '{field}' est trop long (max {max_len}).")


_Msg.field_required = staticmethod(_field_required)  # type: ignore[attr-defined]
_Msg.field_too_long = staticmethod(_field_too_long)  # type: ignore[attr-defined]


def _validate_create_payload(data: Mapping[str, Any]) -> dict[str, Any]:
    """Valide l'intégralité du body POST /api/db-config (création).

    Tous les champs sont obligatoires. Lève ``ValueError`` (message
    user-facing FR) si invalide. Retourne un dict prêt à passer en
    kwargs au service.
    """
    return {
        "name": _coerce_str_field(data.get("name"), "name", _NAME_MAX_LEN, required=True),
        "host": _coerce_str_field(data.get("host"), "host", _HOST_MAX_LEN, required=True),
        "database": _coerce_str_field(
            data.get("database"), "database", _DATABASE_MAX_LEN, required=True
        ),
        "username": _coerce_str_field(
            data.get("username"), "username", _USERNAME_MAX_LEN, required=True
        ),
        "password": _coerce_password(data.get("password"), required=True),
        "port": _coerce_int_field(data.get("port"), "port", _PORT_MIN, _PORT_MAX, default=1433),
        "timeout": _coerce_int_field(
            data.get("timeout"), "timeout", _TIMEOUT_MIN, _TIMEOUT_MAX, default=30
        ),
        "max_rows": _coerce_int_field(
            data.get("max_rows"), "max_rows", _MAX_ROWS_MIN, _MAX_ROWS_MAX, default=1000
        ),
    }


def _validate_update_payload(data: Mapping[str, Any]) -> dict[str, Any]:
    """Valide PATCH partiel — seuls les champs présents sont validés.

    Retourne un dict des champs effectivement présents (pour le service
    qui les applique en update incrémental).
    """
    out: dict[str, Any] = {}
    for field, max_len in (
        ("name", _NAME_MAX_LEN),
        ("host", _HOST_MAX_LEN),
        ("database", _DATABASE_MAX_LEN),
        ("username", _USERNAME_MAX_LEN),
    ):
        if field in data:
            v = _coerce_str_field(data.get(field), field, max_len, required=False)
            if v is not None:
                out[field] = v
    if "password" in data and data["password"]:
        out["password"] = _coerce_password(data.get("password"), required=False)
    if "port" in data:
        v = _coerce_int_field(data.get("port"), "port", _PORT_MIN, _PORT_MAX)
        if v is not None:
            out["port"] = v
    if "timeout" in data:
        v = _coerce_int_field(data.get("timeout"), "timeout", _TIMEOUT_MIN, _TIMEOUT_MAX)
        if v is not None:
            out["timeout"] = v
    if "max_rows" in data:
        v = _coerce_int_field(data.get("max_rows"), "max_rows", _MAX_ROWS_MIN, _MAX_ROWS_MAX)
        if v is not None:
            out["max_rows"] = v
    return out


def _coerce_password(value: Any, required: bool) -> str | None:
    """Coerce password : refuse les types autres que str, borne, refuse CRLF.

    Pas de ``trim`` (un password peut légitimement commencer/finir par un
    espace dans certains coffres-forts).
    """
    if value is None or value == "":
        if required:
            raise ValueError(_Msg.PASSWORD_REQUIRED)
        return None
    if not isinstance(value, str):
        raise ValueError(_Msg.PASSWORD_REQUIRED)
    if len(value) > _PASSWORD_MAX_LEN:
        raise ValueError(_Msg.PASSWORD_TOO_LONG)
    # Refus CRLF même dans le password — protection contre le smuggling
    # de paramètres ODBC additionnels via password.
    return assert_no_crlf(value, "password")


# Conteneur de refs fortes pour les tasks d'audit fire-and-forget : sans ça,
# une task créée par create_task peut être GC'd avant complétion (Python 3.12+)
# → entrée d'audit perdue silencieusement. Le done_callback la libère à la fin.
_audit_tasks: set = set()

# Timeout du persist d'audit fire-and-forget. Sans borne, si la BDD locale est
# lockée et que get_session/commit hang, la task reste pending pour toujours
# (tenue par la strong-ref _audit_tasks) → fuite mémoire (1 task bloquée par
# audit qui hang). Doctrine DB-locked Komptia : borner par asyncio.wait_for.
# 10s = très large pour un seul INSERT mais garantit la libération de la task ;
# au-delà l'audit best-effort est simplement ignoré (logué).
_AUDIT_PERSIST_TIMEOUT_S: float = 10.0


def _record_audit(
    handler: BaseHandler,
    *,
    action: str,
    entity_id: int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Fire-and-forget audit log via session indépendante.

    Best-effort : un échec de log ne doit pas masquer la réponse au
    client. Le log applicatif (via ``logger.warning``) sert de filet.
    """
    try:
        import asyncio

        from app.core.database import get_session

        # Capturer les attributs du handler SYNCHRONEMENT (avant le create_task) :
        # la task différée peut tourner jusqu'à _AUDIT_PERSIST_TIMEOUT_S plus tard,
        # potentiellement après teardown du handler Tornado → lire handler.request
        # dans la coroutine serait fragile (ip/ua périmés). Doctrine Komptia :
        # capturer les valeurs AVANT la frontière async (cf. CLAUDE.md règle #6).
        user_id = getattr(handler.current_user, "id", None)
        ip = handler.request.remote_ip
        ua = handler.request.headers.get("User-Agent")

        async def _persist() -> None:
            async def _do() -> None:
                async with get_session() as session:
                    session.add(
                        AuditLog.log_action(
                            action=action,
                            user_id=user_id,
                            entity_type="db_connection",
                            entity_id=entity_id,
                            details=details or {},
                            ip_address=ip,
                            user_agent=ua,
                        )
                    )

            # Borne dure : si la BDD est lockée et que get_session/commit hang,
            # on annule au lieu de laisser la task fuiter indéfiniment (tenue
            # par _audit_tasks). Audit best-effort → on logue et on abandonne.
            try:
                await asyncio.wait_for(_do(), timeout=_AUDIT_PERSIST_TIMEOUT_S)
            except asyncio.TimeoutError:
                logger.warning(
                    "Audit db-config: persist timeout (%.0fs, BDD lockée ?), audit ignoré",
                    _AUDIT_PERSIST_TIMEOUT_S,
                )

        # Fire-and-forget : on lance la persistance sans bloquer la réponse.
        # ``get_running_loop`` (toujours appelé depuis un handler async) +
        # référence forte dans ``_audit_tasks`` : sans ça la task peut être
        # GC'd avant complétion (Python 3.12+) → audit perdu silencieusement.
        task = asyncio.get_running_loop().create_task(_persist())
        _audit_tasks.add(task)
        task.add_done_callback(_audit_tasks.discard)
    except Exception:  # noqa: BLE001 — audit best-effort
        logger.warning("Échec persistance audit log", exc_info=True, extra={"action": action})


# --- Handlers -------------------------------------------------------------


class DatabaseConfigHandler(BaseHandler):
    """Page admin de configuration des connexions BDD (HTML)."""

    @admin_required
    async def get(self) -> None:
        """Affiche la page de configuration des connexions."""
        connections = await list_connections()
        self.render(
            "admin/database.html",
            page_title="Configuration Base de Données",
            connections=to_dict_object(connections),
            user=self.current_user,
            # Bascule SQL Server <-> copie SQLite locale : outil de dev/test
            # offline (BDD source injoignable / comparaison de jeux de
            # donnees). Affichee UNIQUEMENT en environnement "development"
            # (fail-closed : production client, staging, ou valeur ENVIRONMENT
            # inattendue/typo -> carte masquee). Un deploiement client tourne
            # en production (Docker injecte ENVIRONMENT=production) et n'a pas
            # de copie SQLite locale. Masquage UI uniquement -- le backend
            # /api/sage-mode reste actif (pilotable via env USE_SQLITE_COPY).
            show_sage_mode_switch=config.is_development(),
        )


class DatabaseConfigAPIHandler(BaseHandler):
    """API REST : liste (GET) + création (POST)."""

    @admin_required
    async def get(self) -> None:
        """Liste toutes les connexions enregistrées (sans mot de passe)."""
        try:
            connections = await list_connections()
        except SQLAlchemyError:
            logger.error("Erreur lecture liste connexions BDD", exc_info=True)
            self.write_json({"success": False, "error": _Msg.INTERNAL_ERROR}, status=500)
            return
        self.write_json({"success": True, "connections": connections})

    @admin_required
    async def post(self) -> None:
        """Crée une nouvelle connexion."""
        user = self.current_user
        if not _check_rate_limit(_mutation_limiter, user.id, *_RATE_LIMIT_MUTATION):
            self.write_json({"success": False, "error": _Msg.RATE_LIMIT_MUTATION}, status=429)
            return

        data = self.get_json_body()
        try:
            payload = _validate_create_payload(data)
        except ValueError as exc:
            self.write_json({"success": False, "error": str(exc)}, status=400)
            return

        try:
            conn = await create_connection(created_by=user.id, **payload)
        except DuplicateConnectionError:
            self.write_json({"success": False, "error": _Msg.CONFLICT_NAME}, status=409)
            return
        except SQLAlchemyError:
            logger.error(
                "Erreur création connexion BDD",
                exc_info=True,
                extra={"user_id": user.id},
            )
            self.write_json({"success": False, "error": _Msg.INTERNAL_ERROR}, status=500)
            return

        _record_audit(
            self,
            action=AuditAction.DB_CONFIG_CREATE,
            entity_id=conn.id,
            details={"name": conn.name, "host": conn.host, "port": conn.port},
        )
        self.write_json(
            {
                "success": True,
                "message": "Connexion créée avec succès.",
                "connection": conn.to_dict(),
            },
            status=201,
        )


class DatabaseConfigDetailAPIHandler(BaseHandler):
    """API REST : détail / update / delete d'une connexion."""

    @admin_required
    async def get(self, conn_id: str) -> None:
        """Récupère le détail d'une connexion (sans mot de passe)."""
        cid = self._parse_int_or_400(conn_id, "conn_id")
        try:
            conn = await get_connection(cid)
        except SQLAlchemyError:
            logger.error("Erreur lecture connexion BDD", exc_info=True)
            self.write_json({"success": False, "error": _Msg.INTERNAL_ERROR}, status=500)
            return
        if not conn:
            self.write_json({"success": False, "error": _Msg.NOT_FOUND}, status=404)
            return
        self.write_json({"success": True, "connection": conn.to_dict()})

    @admin_required
    async def put(self, conn_id: str) -> None:
        """Met à jour une connexion (PATCH partiel)."""
        user = self.current_user
        if not _check_rate_limit(_mutation_limiter, user.id, *_RATE_LIMIT_MUTATION):
            self.write_json({"success": False, "error": _Msg.RATE_LIMIT_MUTATION}, status=429)
            return

        cid = self._parse_int_or_400(conn_id, "conn_id")
        data = self.get_json_body()
        try:
            payload = _validate_update_payload(data)
        except ValueError as exc:
            self.write_json({"success": False, "error": str(exc)}, status=400)
            return

        try:
            conn = await update_connection(cid, updated_by=user.id, **payload)
        except DuplicateConnectionError:
            self.write_json({"success": False, "error": _Msg.CONFLICT_NAME}, status=409)
            return
        except SQLAlchemyError:
            logger.error(
                "Erreur modification connexion BDD",
                exc_info=True,
                extra={"user_id": user.id, "connection_id": cid},
            )
            self.write_json({"success": False, "error": _Msg.INTERNAL_ERROR}, status=500)
            return

        if not conn:
            self.write_json({"success": False, "error": _Msg.NOT_FOUND}, status=404)
            return

        _record_audit(
            self,
            action=AuditAction.DB_CONFIG_UPDATE,
            entity_id=cid,
            details={"changed_fields": sorted(payload.keys())},
        )
        self.write_json(
            {
                "success": True,
                "message": "Connexion mise à jour.",
                "connection": conn.to_dict(),
            }
        )

    @admin_required
    async def delete(self, conn_id: str) -> None:
        """Supprime une connexion (refuse si active)."""
        user = self.current_user
        if not _check_rate_limit(_mutation_limiter, user.id, *_RATE_LIMIT_MUTATION):
            self.write_json({"success": False, "error": _Msg.RATE_LIMIT_MUTATION}, status=429)
            return

        cid = self._parse_int_or_400(conn_id, "conn_id")
        try:
            deleted = await delete_connection(cid)
        except ConnectionInUseError:
            self.write_json({"success": False, "error": _Msg.CANNOT_DELETE_ACTIVE}, status=409)
            return
        except SQLAlchemyError:
            logger.error(
                "Erreur suppression connexion BDD",
                exc_info=True,
                extra={"user_id": user.id, "connection_id": cid},
            )
            self.write_json({"success": False, "error": _Msg.INTERNAL_ERROR}, status=500)
            return

        if not deleted:
            self.write_json({"success": False, "error": _Msg.NOT_FOUND}, status=404)
            return

        _record_audit(self, action=AuditAction.DB_CONFIG_DELETE, entity_id=cid)
        self.write_json({"success": True, "message": "Connexion supprimée."})


class DatabaseConfigActivateHandler(BaseHandler):
    """Active (POST) ou désactive (DELETE) une connexion."""

    @admin_required
    async def post(self, conn_id: str) -> None:
        """Active une connexion (désactive les autres atomiquement)."""
        user = self.current_user
        if not _check_rate_limit(_activate_limiter, user.id, *_RATE_LIMIT_ACTIVATE):
            self.write_json({"success": False, "error": _Msg.RATE_LIMIT_ACTIVATE}, status=429)
            return

        cid = self._parse_int_or_400(conn_id, "conn_id")
        try:
            conn = await activate_connection(cid, activated_by=user.id)
        except ValueError:
            self.write_json({"success": False, "error": _Msg.NOT_FOUND}, status=404)
            return
        except SQLAlchemyError:
            logger.error(
                "Erreur activation connexion BDD",
                exc_info=True,
                extra={"user_id": user.id, "connection_id": cid},
            )
            self.write_json({"success": False, "error": _Msg.INTERNAL_ERROR}, status=500)
            return

        _record_audit(
            self,
            action=AuditAction.DB_CONFIG_ACTIVATE,
            entity_id=cid,
            details={"name": conn.name, "host": conn.host, "port": conn.port},
        )
        self.write_json(
            {
                "success": True,
                "message": f"Connexion '{conn.name}' activée.",
                "connection": conn.to_dict(),
            }
        )

    @admin_required
    async def delete(self, conn_id: str) -> None:
        """Désactive une connexion (retour à .env)."""
        user = self.current_user
        if not _check_rate_limit(_activate_limiter, user.id, *_RATE_LIMIT_ACTIVATE):
            self.write_json({"success": False, "error": _Msg.RATE_LIMIT_ACTIVATE}, status=429)
            return

        cid = self._parse_int_or_400(conn_id, "conn_id")
        try:
            success = await deactivate_connection(cid)
        except SQLAlchemyError:
            logger.error(
                "Erreur désactivation connexion BDD",
                exc_info=True,
                extra={"user_id": user.id, "connection_id": cid},
            )
            self.write_json({"success": False, "error": _Msg.INTERNAL_ERROR}, status=500)
            return

        if not success:
            self.write_json({"success": False, "error": _Msg.NOT_FOUND}, status=404)
            return

        _record_audit(self, action=AuditAction.DB_CONFIG_DEACTIVATE, entity_id=cid)
        self.write_json(
            {
                "success": True,
                "message": (
                    "Connexion désactivée — exécution SQL refusée jusqu'à "
                    "(ré)activation d'une connexion sur cette page."
                ),
            }
        )


class DatabaseConfigTestHandler(BaseHandler):
    """Teste une connexion (existante via ``conn_id`` ou ad-hoc via body JSON)."""

    @admin_required
    async def post(self, conn_id: str | None = None) -> None:
        user = self.current_user

        # Rate-limit fort : test = établit une vraie connexion réseau.
        # Sans rate-limit, le formulaire admin = port-scanner gratuit du
        # réseau interne. NB : le SSRF guard est volontairement DÉSACTIVÉ ici
        # (``enforce_ssrf_guard=False`` dans ``_test_existing`` / ``_test_ad_hoc``
        # — la BDD source est par construction sur un réseau privé RFC 1918 et
        # le test doit matcher ``SageConnector.connect()`` qui ne guarde pas).
        # Le rate-limit est donc la SEULE protection anti-abus de cet endpoint.
        if not _check_rate_limit(_test_limiter, user.id, *_RATE_LIMIT_TEST):
            self.write_json(
                {
                    "success": False,
                    "message": _Msg.RATE_LIMIT_TEST,
                    "tables_count": 0,
                },
                status=429,
            )
            return

        try:
            if conn_id and conn_id != _AD_HOC_TEST_SENTINEL:
                result = await self._test_existing(conn_id)
            else:
                result = await self._test_ad_hoc()
        except HTTPError:
            raise  # propagé par _parse_int_or_400 / get_json_body
        except (ValueError, UnsafeHostError) as exc:
            # ValueError = champ invalide (str/coerce) ; UnsafeHostError =
            # SSRF guard. Dans les deux cas → 400 + message neutre user-facing.
            self.write_json(
                {"success": False, "message": str(exc), "tables_count": 0},
                status=400,
            )
            return
        except SQLAlchemyError:
            logger.error(
                "Erreur DB lors du test de connexion",
                exc_info=True,
                extra={"user_id": user.id},
            )
            self.write_json(
                {
                    "success": False,
                    "message": _Msg.INTERNAL_ERROR,
                    "tables_count": 0,
                },
                status=500,
            )
            return

        if result is None:
            # _test_existing a déjà écrit la réponse 404 (connexion inexistante). #28
            return
        self.write_json(result)

    async def _test_existing(self, conn_id: str) -> dict[str, Any] | None:
        """Teste une connexion enregistrée (lit la conf, déchiffre le mdp).

        Retourne ``None`` quand la connexion n'existe pas — la réponse 404 a
        alors DÉJÀ été écrite ici (le caller ne doit pas réécrire). #28 : écrire
        le 404 via ``write_json(status=404)`` plutôt que ``set_status(404)`` +
        un ``write_json(result)`` caller sans status (qui ré-appliquerait 200).
        """
        cid = self._parse_int_or_400(conn_id, "conn_id")
        conn = await get_connection(cid)
        if not conn:
            self.write_json(
                {"success": False, "message": _Msg.NOT_FOUND, "tables_count": 0},
                status=404,
            )
            return None

        try:
            password = decrypt_password(conn.encrypted_password)
        except ValueError as exc:
            logger.warning(
                "Déchiffrement password échoué pour test",
                extra={"connection_id": cid},
            )
            return {"success": False, "message": str(exc), "tables_count": 0}

        # SOURCE UNIQUE de vrit : ce test DOIT reflter ce que fait
        # ``SageConnector.connect()`` exactement -- sinon le bouton
        # "Tester" ment  l'admin (test KO mais Iris OK ou inverse).
        #
        # Deux dcisions dlibres ici :
        #
        # 1. ``enforce_ssrf_guard=False`` : la BDD source de Komptia est
        #    PAR CONSTRUCTION sur un reseau prive (serveur SQL Server
        #    interne du client). Le SSRF guard refuserait toute
        #    IP RFC 1918 (192.168.x, 10.x, 172.16-31.x) -- alors que c'est
        #    le cas d'usage NORMAL. ``SageConnector.connect()`` ne fait
        #    aucun guard, donc le test ne doit pas non plus, sinon test
        #    et runtime divergent. La protection SSRF reste pertinente
        #    pour d'autres endpoints (webhooks, fetch externe) o un
        #    user non-admin contrle le host -- pas ici (admin_required).
        #
        # 2. ``timeout=conn.timeout`` (pas tronqu  10s) : le test doit
        #    avoir le mme timeout que le runtime, sinon un Sage lent
        #    fait fail le test alors qu'Iris passerait.
        result = await test_connection(
            host=conn.host,
            port=conn.port,
            database=conn.database,
            username=conn.username,
            password=password,
            timeout=conn.timeout,
            conn_id=cid,
            enforce_ssrf_guard=False,
        )
        _record_audit(
            self,
            action=AuditAction.DB_CONFIG_TEST,
            entity_id=cid,
            details={
                "host": conn.host,
                "port": conn.port,
                "success": result.get("success"),
            },
        )
        return result

    async def _test_ad_hoc(self) -> dict[str, Any]:
        """Teste les paramètres fournis dans le body (création / aperçu)."""
        data = self.get_json_body()
        host = _coerce_str_field(data.get("host"), "host", _HOST_MAX_LEN, required=True)
        database = _coerce_str_field(
            data.get("database"), "database", _DATABASE_MAX_LEN, required=True
        )
        username = _coerce_str_field(
            data.get("username"), "username", _USERNAME_MAX_LEN, required=True
        )
        password = _coerce_password(data.get("password"), required=True)
        port = _coerce_int_field(data.get("port"), "port", _PORT_MIN, _PORT_MAX, default=1433)
        timeout = _coerce_int_field(
            data.get("timeout"), "timeout", _TIMEOUT_MIN, _TIMEOUT_MAX, default=10
        )

        # Pas de SSRF guard ici : la BDD source est par construction sur
        # un reseau prive (serveur SQL Server interne du client). Le
        # SSRF guard refuserait toute IP RFC 1918 -- alors
        # que c'est le cas d'usage NORMAL. ``SageConnector.connect()``
        # ne fait aucun guard, donc le test ne doit pas non plus, sinon
        # divergence entre test admin et runtime Iris/datastore. Le
        # SSRF guard reste pertinent pour d'autres endpoints (webhooks,
        # fetch externe) o un user non-admin contrle le host.
        result = await test_connection(
            host=host or "",
            port=port or 1433,
            database=database or "",
            username=username or "",
            password=password or "",
            timeout=timeout or 10,
            enforce_ssrf_guard=False,
        )
        _record_audit(
            self,
            action=AuditAction.DB_CONFIG_TEST_AD_HOC,
            entity_id=None,
            details={
                "host": host,
                "port": port,
                "database": database,
                "success": result.get("success"),
            },
        )
        return result


class SageModeHandler(BaseHandler):
    """Switch entre SQL Server et SQLite (copie locale) à chaud."""

    @admin_required
    async def get(self) -> None:
        """Retourne le mode actif et l'état de la copie SQLite."""
        sqlite_info = await self._sqlite_status()
        self.write_json(
            {
                "mode": get_current_sage_mode(),
                "sqlite_copy": sqlite_info,
            }
        )

    @admin_required
    async def post(self) -> None:
        """Switch le mode : body ``{"mode": "sqlite"|"sqlserver"}``."""
        user = self.current_user
        if not _check_rate_limit(_sage_switch_limiter, user.id, *_RATE_LIMIT_SAGE_SWITCH):
            self.write_json({"status": "error", "message": _Msg.RATE_LIMIT_SAGE_SWITCH}, status=429)
            return

        data = self.get_json_body()
        target_mode = data.get("mode", "")
        if target_mode not in _VALID_SAGE_MODES:
            self.write_json({"status": "error", "message": _Msg.INVALID_SAGE_MODE}, status=400)
            return

        use_sqlite = target_mode == "sqlite"
        if use_sqlite and not _SAGE_SQLITE_PATH.exists():
            # Fail-fast sur copie absente : le service le ferait aussi mais
            # on évite un swap partiel + retour error.
            self.write_json({"status": "error", "message": _Msg.SAGE_SQLITE_MISSING}, status=409)
            return

        try:
            result = await switch_sage_mode(use_sqlite)
        except (SQLAlchemyError, OperationalError):
            logger.error(
                "Erreur switch mode Sage",
                exc_info=True,
                extra={"user_id": user.id, "target_mode": target_mode},
            )
            self.write_json({"status": "error", "message": _Msg.INTERNAL_ERROR}, status=500)
            return

        # Mystère B 2026-05-26 : cache mémoire supprimé. La BDD est SSoT,
        # le prochain getter relira automatiquement le label. Aucune
        # invalidation explicite nécessaire.

        _record_audit(
            self,
            action=AuditAction.SAGE_MODE_SWITCH,
            details={"target_mode": target_mode, "result_status": result.get("status")},
        )

        status_http = 200 if result.get("status") != "error" else 500
        self.write_json(result, status=status_http)

    @staticmethod
    async def _sqlite_status() -> dict[str, Any]:
        """Lecture stat du fichier SQLite copie. Retourne dict sérialisable."""
        if not _SAGE_SQLITE_PATH.exists():
            return {"exists": False, "size_mb": 0, "last_modified": None}
        stat = os.stat(_SAGE_SQLITE_PATH)
        return {
            "exists": True,
            "size_mb": round(stat.st_size / (1024 * 1024), 1),
            "last_modified": clock.local_from_timestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        }


__all__ = [
    "DatabaseConfigActivateHandler",
    "DatabaseConfigAPIHandler",
    "DatabaseConfigDetailAPIHandler",
    "DatabaseConfigHandler",
    "DatabaseConfigTestHandler",
    "SageModeHandler",
]
