"""Handlers HTTP onboarding — endpoints REST minces qui délèguent à
``app.services.onboarding``.

Routes exposées (toutes en JSON, XSRF token Tornado natif appliqué sur les
POST via le cookie ``_xsrf`` + header ``X-Xsrftoken``) :

User-scoped (``@authenticated``) :

- ``GET  /api/onboarding/state``
- ``POST /api/onboarding/tour/start``      body ``{"tour_key": "..."}``
- ``POST /api/onboarding/tour/step``       body ``{"tour_key": "...", "step": N}``
- ``POST /api/onboarding/tour/complete``   body ``{"tour_key": "..."}``
- ``POST /api/onboarding/tour/skip``       body ``{"tour_key": "..."}``

Admin-only (``@admin_required``) :

- ``GET  /api/admin/tenant-setup``
- ``POST /api/admin/tenant-setup/milestone``  body ``{"milestone": "database"}``
- ``POST /api/admin/tenant-setup/dismiss``
- ``POST /api/admin/tenant-setup/resume``

Doctrine :

1. **Owner-scope strict** — toutes les lectures/écritures user-scoped
   passent ``self.current_user.id`` au service. Un user ne peut jamais
   accéder/modifier l'état d'un autre user, même en forgeant un body.

2. **Validation au boundary** — les handlers ne valident rien eux-mêmes
   au-delà du parsing JSON ; toute logique de validation vit dans le
   service (``validate_tour_key`` / ``validate_step`` / ``validate_milestone``)
   qui lève ``OnboardingValidationError`` → mappée ici en HTTP 400.

3. **Audit log systématique** sur chaque écriture — l'action est
   identifiée par un string action stable (``onboarding_tour_start`` etc.)
   pour faciliter le tracking des taux de complétion sans coupler à un
   enum centralisé.
"""

from __future__ import annotations

import logging
from typing import Any

import tornado.web

from app.handlers.base import BaseHandler, admin_required, authenticated
from app.models.audit import AuditLog
from app.services.onboarding import (
    OnboardingValidationError,
    complete_tour,
    dismiss_tenant_setup,
    extract_milestone,
    extract_step,
    extract_tour_key,
    get_or_create_tenant_setup,
    get_user_state,
    record_step,
    reset_user_onboarding,
    resume_tenant_setup,
    set_milestone,
    skip_tour,
    start_tour,
    validate_tour_key,
)

logger = logging.getLogger("komptia." + __name__)


def _validation_error_to_400(exc: OnboardingValidationError) -> tornado.web.HTTPError:
    """Mappe une erreur de validation service vers une HTTP 400 propre."""
    return tornado.web.HTTPError(400, str(exc))


async def _audit(
    handler: BaseHandler,
    *,
    action: str,
    entity_id: int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Écrit une entrée d'audit en best-effort.

    L'opération métier est déjà commitée avant l'appel à ``_audit`` (chaque
    handler a refermé sa ``db_session`` principale). On ouvre ici une
    session séparée dédiée à l'audit pour ne pas allonger le hot path.

    **Fail-soft volontaire** : si la session d'audit échoue (BDD locked
    momentanément, timeout, ``SQLAlchemyError``), on log l'erreur côté
    serveur mais on ne propage JAMAIS l'exception. Sinon le client
    recevrait un 5xx alors que l'opération métier a réussi → re-clic →
    duplicats. La perte d'une entrée d'audit ponctuelle est moins grave
    qu'un état BDD désynchronisé du retour HTTP.
    """
    try:
        async with handler.db_session() as session:
            entry = AuditLog.log_action(
                action=action,
                user_id=handler.current_user.id if handler.current_user else None,
                entity_type="onboarding",
                entity_id=entity_id,
                details=details,
                ip_address=handler.request.remote_ip,
                user_agent=handler.request.headers.get("User-Agent", ""),
            )
            session.add(entry)
    except Exception:  # noqa: BLE001 — fail-soft volontaire (cf. docstring)
        logger.warning(
            "audit onboarding non-écrit pour action=%s entity_id=%s — "
            "opération métier déjà commitée, état BDD cohérent",
            action,
            entity_id,
            exc_info=True,
        )


# =====================================================================
# User-scoped — tours d'onboarding
# =====================================================================


class OnboardingStateHandler(BaseHandler):
    """``GET /api/onboarding/state`` — renvoie l'état complet du user."""

    @authenticated
    async def get(self) -> None:
        user_id = self.current_user.id
        async with self.db_session() as session:
            state = await get_user_state(session, user_id)
        self.write_json(state)


class BaseOnboardingTourActionHandler(BaseHandler):
    """Base partagée pour les 4 endpoints d'action de tour (start/step/complete/skip).

    Chaque sous-classe override ``_action_name`` et ``_apply(session, user_id,
    body, tour_key)`` qui retourne la ligne modifiée. La base s'occupe de
    parser le body, valider, écrire l'audit et formater la réponse.
    """

    _action_name: str  # 'start' / 'step' / 'complete' / 'skip'

    @authenticated
    async def post(self) -> None:
        body = self.get_json_body()
        try:
            tour_key = extract_tour_key(body)
            row = await self._dispatch(body, tour_key)
        except OnboardingValidationError as exc:
            raise _validation_error_to_400(exc) from exc

        payload = row.to_dict()
        await _audit(
            self,
            action=f"onboarding_tour_{self._action_name}",
            entity_id=row.id,
            details={"tour_key": tour_key, "last_step_seen": row.last_step_seen},
        )
        self.write_json(payload)

    async def _dispatch(self, body: dict, tour_key: str):
        """Appelle la bonne fonction service selon ``_action_name``."""
        user_id = self.current_user.id
        async with self.db_session() as session:
            if self._action_name == "start":
                return await start_tour(session, user_id, tour_key)
            if self._action_name == "step":
                step = extract_step(body)
                return await record_step(session, user_id, tour_key, step)
            if self._action_name == "complete":
                return await complete_tour(session, user_id, tour_key)
            if self._action_name == "skip":
                return await skip_tour(session, user_id, tour_key)
            raise tornado.web.HTTPError(500, f"action inconnue : {self._action_name}")


class OnboardingTourStartHandler(BaseOnboardingTourActionHandler):
    _action_name = "start"


class OnboardingTourStepHandler(BaseOnboardingTourActionHandler):
    _action_name = "step"


class OnboardingTourCompleteHandler(BaseOnboardingTourActionHandler):
    _action_name = "complete"


class OnboardingTourSkipHandler(BaseOnboardingTourActionHandler):
    _action_name = "skip"


# =====================================================================
# Admin-only — singleton tenant setup
# =====================================================================


class TenantSetupStateHandler(BaseHandler):
    """``GET /api/admin/tenant-setup`` — renvoie le singleton (lazy-create)."""

    @admin_required
    async def get(self) -> None:
        async with self.db_session() as session:
            row = await get_or_create_tenant_setup(session)
            payload = row.to_dict()
        self.write_json(payload)


class TenantSetupMilestoneHandler(BaseHandler):
    """``POST /api/admin/tenant-setup/milestone`` — pose un jalon."""

    @admin_required
    async def post(self) -> None:
        body = self.get_json_body()
        try:
            milestone = extract_milestone(body)
        except OnboardingValidationError as exc:
            raise _validation_error_to_400(exc) from exc

        async with self.db_session() as session:
            row = await set_milestone(session, milestone)
            payload = row.to_dict()

        await _audit(
            self,
            action="tenant_setup_milestone",
            entity_id=row.id,
            details={"milestone": milestone},
        )
        self.write_json(payload)


class TenantSetupDismissHandler(BaseHandler):
    """``POST /api/admin/tenant-setup/dismiss`` — masque le bandeau."""

    @admin_required
    async def post(self) -> None:
        async with self.db_session() as session:
            row = await dismiss_tenant_setup(session)
            payload = row.to_dict()

        await _audit(
            self,
            action="tenant_setup_dismiss",
            entity_id=row.id,
            details=None,
        )
        self.write_json(payload)


class TenantSetupResumeHandler(BaseHandler):
    """``POST /api/admin/tenant-setup/resume`` — réaffiche le bandeau."""

    @admin_required
    async def post(self) -> None:
        async with self.db_session() as session:
            row = await resume_tenant_setup(session)
            payload = row.to_dict()

        await _audit(
            self,
            action="tenant_setup_resume",
            entity_id=row.id,
            details=None,
        )
        self.write_json(payload)


class OnboardingResetHandler(BaseHandler):
    """``POST /api/admin/onboarding/reset`` — utilitaire admin pour
    réinitialiser l'onboarding d'un user (le sien ou un compte test).

    Body : ``{"user_id": int, "tour_key": str?}``. Si ``tour_key`` absent,
    supprime TOUS les tours du user. Aucun toucher à ``user_activity_summary``
    (cf. doctrine ``reset_user_onboarding``).

    Réservé admin. Pensé pour faciliter le test utilisateur réel : un admin
    peut rejouer un tour sans devoir recréer un compte ou vider le localStorage.
    """

    @admin_required
    async def post(self) -> None:
        body = self.get_json_body()
        target_user_id = body.get("user_id")
        if not isinstance(target_user_id, int) or target_user_id <= 0:
            raise tornado.web.HTTPError(400, "user_id obligatoire (entier positif)")

        tour_key_raw = body.get("tour_key")
        if tour_key_raw is not None:
            try:
                validate_tour_key(tour_key_raw)
            except OnboardingValidationError as exc:
                raise _validation_error_to_400(exc) from exc

        async with self.db_session() as session:
            try:
                deleted = await reset_user_onboarding(session, target_user_id, tour_key_raw)
            except OnboardingValidationError as exc:
                raise _validation_error_to_400(exc) from exc

        await _audit(
            self,
            action="onboarding_admin_reset",
            entity_id=target_user_id,
            details={
                "target_user_id": target_user_id,
                "tour_key": tour_key_raw,
                "deleted_count": deleted,
            },
        )
        self.write_json({"deleted_count": deleted})


__all__ = (
    "OnboardingStateHandler",
    "OnboardingTourStartHandler",
    "OnboardingTourStepHandler",
    "OnboardingTourCompleteHandler",
    "OnboardingTourSkipHandler",
    "TenantSetupStateHandler",
    "TenantSetupMilestoneHandler",
    "TenantSetupDismissHandler",
    "TenantSetupResumeHandler",
    "OnboardingResetHandler",
)
