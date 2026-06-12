"""
Handlers admin pour la gestion des feature flags globaux.

Endpoints :
- GET  /api/admin/feature-flags          -> liste tous les flags
- GET  /api/admin/feature-flags/:name    -> lecture d'un flag
- POST /api/admin/feature-flags/:name    -> upsert d'un flag (body JSON {value, description})

Use case principal : kill-switch automatisations.
Admin uniquement (check `@admin_required`).
"""

from __future__ import annotations

from typing import Any

import tornado.web
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.handlers.base import BaseHandler, admin_required
from app.models.feature_flag import FeatureFlag
from app.services.automation.feature_flag_service import (
    get_flag_value,
    set_flag_value,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

#: #71 — borne de la description d'un feature flag. Au-delà, on REFUSE (400)
#: comme le `name` trop long, au lieu de tronquer EN SILENCE : sinon la doc du
#: flag (pourquoi/quand le couper) revenait amputée au GET sans que le POST
#: l'ait signalé. DOIT rester égal à la longueur de colonne
#: ``FeatureFlag.description = String(500)`` (sinon une valeur acceptée ici
#: déborderait la colonne BDD) — SSoT couplée au modèle.
_MAX_DESCRIPTION_LEN = 500


class FeatureFlagsListHandler(BaseHandler):
    """GET /api/admin/feature-flags — liste tous les flags."""

    @admin_required
    async def get(self) -> None:
        try:
            async with self.db_session() as session:
                result = await session.execute(select(FeatureFlag).order_by(FeatureFlag.name))
                flags = [f.to_dict() for f in result.scalars().all()]
            self.write({"success": True, "flags": flags})
        except SQLAlchemyError:
            logger.error("Erreur lecture feature flags", exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur de lecture."})


class FeatureFlagDetailHandler(BaseHandler):
    """GET/POST /api/admin/feature-flags/:name — lecture/upsert d'un flag."""

    @admin_required
    async def get(self, name: str) -> None:
        try:
            async with self.db_session() as session:
                value = await get_flag_value(session, name, default=None)
            self.write({"success": True, "name": name, "value": value})
        except SQLAlchemyError:
            logger.error("Erreur lecture flag %s", name, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur de lecture."})

    @admin_required
    async def post(self, name: str) -> None:
        body = self.get_json_body()
        if not isinstance(body, dict):
            self.set_status(400)
            self.write({"success": False, "error": "Corps JSON requis."})
            return

        value: Any = body.get("value")
        description = body.get("description")
        if description is not None and not isinstance(description, str):
            description = None
        elif isinstance(description, str):
            description = description.strip()
            # #71 — fail-loud (cohérent avec le rejet du `name` trop long
            # ci-dessous) au lieu de tronquer en silence.
            if len(description) > _MAX_DESCRIPTION_LEN:
                self.set_status(400)
                _err = f"Description trop longue (max {_MAX_DESCRIPTION_LEN} caractères)."
                self.write({"success": False, "error": _err})
                return

        # Sanity : name de URL doit matcher une convention stricte.
        # Deja filtre par la regex de route (voir app/routes.py), mais
        # defense-in-depth : max 100 chars, kebab-case uniquement.
        if len(name) > 100:
            self.set_status(400)
            self.write({"success": False, "error": "Nom de flag trop long."})
            return

        try:
            async with self.db_session() as session:
                await set_flag_value(
                    session,
                    name,
                    value,
                    updated_by=self.current_user.email,
                    description=description,
                )
                await session.commit()
            logger.info(
                "Feature flag '%s' modifie par %s: %r",
                name,
                self.current_user.email,
                value,
            )
            self.write({"success": True, "name": name, "value": value})
        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error("Erreur upsert flag %s", name, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur lors de l'ecriture."})
