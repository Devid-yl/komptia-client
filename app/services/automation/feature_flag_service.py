"""
Service d'acces aux feature flags globaux.

Expose deux helpers :
- `get_flag_value(name, default)` : lecture, fallback au defaut si absent.
- `set_flag_value(name, value, updated_by)` : upsert.

Les flags sont stockes en DB (table F_FEATURE_FLAG). Pour le kill-switch
automatisations en particulier, on lit le flag en debut d'execution.
Pas de cache en memoire : les flags changent rarement, on tolere la
requete DB par execution (quelques ms).
"""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.feature_flag import FeatureFlag
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def get_flag_value(session: AsyncSession, name: str, default: Any = None) -> Any:
    """Lit la valeur d'un flag. Retourne `default` si absent.

    Utilise `scalar_one_or_none` car la contrainte UNIQUE sur `name` garantit
    au plus une ligne — semantique exacte + compat avec les mocks de tests.
    """
    result = await session.execute(select(FeatureFlag).where(FeatureFlag.name == name))
    flag = result.scalar_one_or_none()
    if flag is None:
        return default
    return flag.value


async def set_flag_value(
    session: AsyncSession,
    name: str,
    value: Any,
    *,
    updated_by: Optional[str] = None,
    description: Optional[str] = None,
) -> FeatureFlag:
    """Upsert d'un flag. Cree s'il n'existe pas, met a jour sinon."""
    result = await session.execute(select(FeatureFlag).where(FeatureFlag.name == name))
    flag = result.scalar_one_or_none()
    if flag is None:
        flag = FeatureFlag(name=name, value=value, description=description, updated_by=updated_by)
        session.add(flag)
    else:
        flag.value = value
        if updated_by is not None:
            flag.updated_by = updated_by
        if description is not None:
            flag.description = description
    await session.flush()
    logger.info("Feature flag '%s' set to %r by %s", name, value, updated_by or "system")
    return flag


# Tokens string interprétés comme False par ``is_truthy``. Sans ça, ``bool("false")``
# vaut True (en Python TOUTE string non-vide est truthy) → un admin qui POST
# ``{"value": "false"}`` (ou "0"/"no"/"off") pour DÉSACTIVER le kill-switch
# automatisations l'ACTIVERAIT au contraire (intention inversée silencieusement,
# données fausses). ``FeatureFlag.value`` étant un JSON ``Any`` non typé côté
# handler admin, ce cas est atteignable via l'API. Les autres strings non-vides
# restent truthy (compat ``bool(str)``).
_FALSY_FLAG_STRINGS = frozenset({"false", "0", "no", "off", "non", "", "none", "null"})


def _coerce_flag_truthy(val: Any, default: bool) -> bool:
    """Interprète une valeur de flag JSON (bool/str/int/dict) en booléen robuste.

    SSoT de l'interprétation booléenne des feature flags. Corrige le footgun
    ``bool("false") is True`` (cf. ``_FALSY_FLAG_STRINGS``).
    """
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, dict):
        # Convention modèle : scalaire enveloppé dans ``{"value": ...}``.
        return _coerce_flag_truthy(val.get("value", default), default)
    if isinstance(val, str):
        return val.strip().lower() not in _FALSY_FLAG_STRINGS
    return bool(val)


async def is_truthy(session: AsyncSession, name: str, default: bool = False) -> bool:
    """Helper pour flags booléens. Interprète ``{"value": True}``, ``True``, et
    coerce correctement les strings falsy ("false"/"0"/"no"/…) → False."""
    val = await get_flag_value(session, name, default=default)
    return _coerce_flag_truthy(val, default)
