"""Endpoint public DBA pour approuver/refuser une écriture SQL proposée
par Iris.

Le DBA externe reçoit un mail avec un lien de la forme
``/iris/sql-write/dba/<token_public>``. Cliquer le lien ouvre une page
HTML qui affiche le SQL proposé + 2 boutons (Confirmer l'exécution /
Refuser). Le clic Confirm est un POST (anti-prefetch des clients mail).

Sécurité :
    - Pas d'auth Komptia requise (DBA externe).
    - XSRF désactivé (pas de cookie de session sur ces endpoints).
    - Token HMAC + lookup par hash → un attaquant qui n'a pas le mail
      ne peut pas forger un lien.
    - Rate-limit par IP : 30 GET/min, 5 POST/min.
    - Idempotent : un token déjà consommé renvoie une page "déjà traité".
"""

from __future__ import annotations

from app.core import clock
from app.handlers.base import BaseHandler
from app.services.ai.iris_write_session import (
    ConfirmResult,
    dba_confirm,
    dba_reject,
)
from app.utils.client_ip import client_ip_for_rate_limit
from app.utils.iris_write_token_codec import parse_and_verify
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter

logger = get_logger(__name__)

_GET_RATE_LIMITER: RateLimiter = RateLimiter()
_POST_RATE_LIMITER: RateLimiter = RateLimiter()
_GET_RATE_MAX: int = 30
_POST_RATE_MAX: int = 5
_RATE_WINDOW_S: int = 60


# SSoT IP rate-limit : cf. app/utils/client_ip.py (ne PAS lire X-Real-IP brut —
# contournable par rotation de header sur cet endpoint public).
_client_ip = client_ip_for_rate_limit


class IrisSqlWriteDbaHandler(BaseHandler):
    """Handler public DBA approve/reject."""

    def check_xsrf_cookie(self) -> None:  # type: ignore[override]
        return None

    def get_current_user(self) -> None:  # type: ignore[override]
        return None

    async def get(self, token: str) -> None:
        ip = _client_ip(self)
        if not _GET_RATE_LIMITER.check(f"iris_sql_write_get:{ip}", _GET_RATE_MAX, _RATE_WINDOW_S):
            self.set_status(429)
            self.write("Trop de requêtes. Réessayez dans 1 minute.")
            return

        # Validation HMAC pré-lookup (rejette les tokens forgés sans la clé)
        token_hash = parse_and_verify(token)
        if token_hash is None:
            await self._render_state("invalid_token")
            return

        # Lookup BDD pour afficher les détails
        from app.core.database import get_session
        from app.models.sql_write_audit import SqlWriteAuditLog, SqlWriteStatus
        from sqlalchemy import select

        async with get_session() as session:
            res = await session.execute(
                select(SqlWriteAuditLog).where(SqlWriteAuditLog.approval_token_hash == token_hash)
            )
            audit = res.scalar_one_or_none()

        if audit is None:
            await self._render_state("invalid_token")
            return

        if audit.status != SqlWriteStatus.AWAITING_DBA.value:
            await self._render_state(
                "already_handled",
                status=audit.status,
                operation=audit.parsed_operation or "?",
                actual_rows=audit.actual_rows,
                error=audit.error_message,
            )
            return

        # Check expiration explicite (cron pas encore passé peut-être)
        from app.models.base import ensure_utc

        if clock.now() > ensure_utc(audit.expires_at):
            await self._render_state("expired")
            return

        # Affiche la page de confirmation
        await self._render_state(
            "pending",
            token=token,
            audit=audit,
            sql=audit.generated_sql or "",
            operation=audit.parsed_operation or "?",
            tables=", ".join(audit.parsed_tables or []),
            estimated_rows=audit.estimated_rows or 0,
            intent=audit.intent or "(non précisée)",
            expires_str=ensure_utc(audit.expires_at).strftime("%d/%m/%Y à %H:%M UTC"),
        )

    async def post(self, token: str) -> None:
        ip = _client_ip(self)
        if not _POST_RATE_LIMITER.check(
            f"iris_sql_write_post:{ip}", _POST_RATE_MAX, _RATE_WINDOW_S
        ):
            self.set_status(429)
            self.write("Trop de requêtes. Réessayez dans 1 minute.")
            return

        action = (self.get_argument("action", "") or "").strip().lower()
        reason = (self.get_argument("reason", "") or "").strip()

        if action == "confirm":
            result: ConfirmResult = await dba_confirm(token_public=token, ip=ip)
        elif action == "reject":
            result = await dba_reject(token_public=token, ip=ip, reason=reason)
        else:
            self.set_status(400)
            self.write("Action manquante (confirm ou reject).")
            return

        # Page résultat
        if result.status == "executed":
            state = "executed"
        elif result.status == "aborted":
            state = "aborted"
        elif result.status == "failed":
            state = "failed"
        elif result.status == "expired":
            state = "expired"
        elif result.error == "invalid_token":
            state = "invalid_token"
        elif result.error == "already_handled":
            state = "already_handled"
        elif result.error == "not_found":
            state = "invalid_token"
        else:
            state = "failed"

        await self._render_state(
            state,
            actual_rows=result.actual_rows,
            error=result.error,
            user_message=result.user_message,
        )

    async def _render_state(self, state: str, **ctx: object) -> None:
        """Render the DBA approval template with a state flag."""
        self.render("iris_sql_write_dba.html", state=state, **ctx)


class IrisSqlWriteAuditAPIHandler(BaseHandler):
    """``GET /api/iris/sql-write/audit`` — vue paginée pour l'admin.

    Renvoie un JSON avec les dernières propositions, leurs statuts, et
    le total. Pas de ``generated_sql`` complet dans la liste (cap taille
    payload) — voir ``IrisSqlWriteAuditDetailAPIHandler`` pour le détail
    d'une row.
    """

    async def prepare(self) -> None:  # type: ignore[override]
        await super().prepare()  # type: ignore[misc]
        if self._finished:
            return
        user = self.current_user
        role = getattr(user, "role", None)
        is_admin = role == "admin" or getattr(role, "value", None) == "admin"
        if not is_admin:
            self.set_status(403)
            self.write({"error": "Réservé aux administrateurs."})
            self.finish()

    async def get(self) -> None:
        from app.core.database import get_session
        from app.models.sql_write_audit import SqlWriteAuditLog
        from sqlalchemy import desc, func, select

        try:
            page = max(1, int(self.get_argument("page", "1")))
            page_size = min(100, max(1, int(self.get_argument("page_size", "25"))))
        except ValueError:
            page = 1
            page_size = 25

        async with get_session() as session:
            total = (await session.execute(select(func.count(SqlWriteAuditLog.id)))).scalar_one()
            stmt = (
                select(SqlWriteAuditLog)
                .order_by(desc(SqlWriteAuditLog.created_at))
                .limit(page_size)
                .offset((page - 1) * page_size)
            )
            res = await session.execute(stmt)
            rows = list(res.scalars().all())

        # Vue résumée (pas le SQL complet pour économiser bande passante)
        items = []
        for r in rows:
            d = r.to_dict()
            sql_preview = (d.get("generated_sql") or "")[:200]
            d["generated_sql"] = sql_preview + (
                "…" if len(d.get("generated_sql") or "") > 200 else ""
            )
            d.pop("original_nl_request", None)  # dispo dans le détail
            items.append(d)

        self.write(
            {
                "page": page,
                "page_size": page_size,
                "total": int(total),
                "items": items,
            }
        )


class IrisSqlWriteAuditDetailAPIHandler(BaseHandler):
    """``GET /api/iris/sql-write/audit/<id>`` — détail d'une demande.

    Visible :
        - Pour l'admin demandeur (``audit.user_id == current_user.id``)
        - Pour tout admin global

    Permet à l'admin demandeur de suivre le statut de SA demande sans
    attendre le mail de notif (best-effort) et sans avoir à scanner la
    liste paginée.
    """

    async def prepare(self) -> None:  # type: ignore[override]
        await super().prepare()  # type: ignore[misc]

    async def get(self, audit_id: str) -> None:
        from app.services.ai.iris_write_session import get_audit_by_id

        try:
            audit_id_int = int(audit_id)
        except (TypeError, ValueError):
            self.set_status(404)
            self.write({"error": "Demande introuvable."})
            return

        user = self.current_user
        role = getattr(user, "role", None)
        is_admin = role == "admin" or getattr(role, "value", None) == "admin"
        user_id = getattr(user, "id", None)
        if user_id is None:
            self.set_status(401)
            self.write({"error": "Authentification requise."})
            return

        audit = await get_audit_by_id(audit_id_int, user_id, is_admin=is_admin)
        if audit is None:
            self.set_status(404)
            self.write({"error": "Demande introuvable."})
            return

        self.write(audit.to_dict())


__all__ = [
    "IrisSqlWriteDbaHandler",
    "IrisSqlWriteAuditAPIHandler",
    "IrisSqlWriteAuditDetailAPIHandler",
]
