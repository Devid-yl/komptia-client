"""Shared utilities for dashboard services."""

import importlib
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.constants import DAY_NAMES_SHORT_FR
from app.models.base import ensure_utc
from app.utils.logger import get_logger

logger = get_logger(__name__)


def get_business_timezone() -> ZoneInfo:
    """TZ métier du déploiement = ``config.timezone`` (IANA auto-détecté au
    boot, ex. ``Europe/Paris``). **Source de vérité unique** des bornes
    calendaires du dashboard ; déjà utilisée par le scheduler APScheduler.

    Fallback UTC si la valeur config est absente/invalide — on ne fait
    JAMAIS crasher le dashboard pour un nom de TZ corrompu (fail-safe :
    UTC au pire, jamais une exception remontée à l'utilisateur).
    """
    from app.config import config

    tz_name = getattr(config, "timezone", None) or "UTC"
    try:
        return ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        logger.warning(
            "config.timezone invalide (%r) — fallback UTC pour les bornes dashboard",
            tz_name,
        )
        return ZoneInfo("UTC")


def local_today_start_utc(now_utc: datetime) -> datetime:
    """Instant **UTC** correspondant à **minuit LOCAL** (TZ métier) du jour
    courant.

    ``created_at`` étant stocké en UTC, comparer ``created_at >= retour``
    compte « aujourd'hui » au sens du calendrier **métier** (et non minuit
    UTC, qui décale le bucket de 1-2 h pour un déploiement non-UTC →
    « recherches aujourd'hui » silencieusement faux autour de minuit local).
    """
    tz = get_business_timezone()
    midnight_local = now_utc.astimezone(tz).replace(hour=0, minute=0, second=0, microsecond=0)
    return midnight_local.astimezone(timezone.utc)


def local_window_start_utc(now_utc: datetime, days: int) -> datetime:
    """Instant UTC de minuit LOCAL il y a ``days`` jours (borne basse de la
    fenêtre du graphe quotidien). Sert à filtrer ``created_at`` côté SQL
    avant le bucketing local (cf. :func:`bucket_daily_local`)."""
    tz = get_business_timezone()
    start_local = (now_utc.astimezone(tz) - timedelta(days=days)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return start_local.astimezone(timezone.utc)


def bucket_daily_local(timestamps: Iterable[Optional[datetime]], now_utc: datetime) -> List[int]:
    """Compte les ``timestamps`` (UTC) par **jour calendaire LOCAL** sur les
    7 derniers jours (J-6 → J0), aligné sur :func:`_build_daily_searches`.

    Conversion **par timestamp** dans la TZ métier → correct même autour
    d'une transition DST (un offset fixe SQL serait faux ces jours-là). Le
    volume (fenêtre 7 j) est petit : bucketer en Python est négligeable et
    évite un ``GROUP BY`` par date UTC qui re-décalerait les colonnes.
    """
    tz = get_business_timezone()
    now_local = now_utc.astimezone(tz)
    wanted = [(now_local - timedelta(days=i)).date() for i in range(6, -1, -1)]
    counts: Dict[Any, int] = {d: 0 for d in wanted}
    for ts in timestamps:
        ts_utc = ensure_utc(ts)
        if ts_utc is None:
            continue
        local_date = ts_utc.astimezone(tz).date()
        if local_date in counts:
            counts[local_date] += 1
    return [counts[d] for d in wanted]


# Cache des modèles déjà résolus — évite de re-payer le coût d'``importlib``
# à chaque appel. Les imports SQLAlchemy ne sont pas idempotent-cheap : ils
# réenregistrent les classes au registry à chaque évaluation. Mémoiser ici.
_DEFERRED_MODELS: Dict[str, Any] = {}

# CamelCase → snake_case avec gestion correcte des **acronymes consécutifs**.
# La version naïve ``(?<!^)(?=[A-Z])`` casse sur ``HTTPLog`` → ``h_t_t_p_log``,
# ``LLMModel`` → ``l_l_m_model``, ``XMLReport`` → ``x_m_l_report`` (modules
# inexistants). La version actuelle gère :
#
# * ``EmailLog`` → ``email_log``        (lowercase puis uppercase = insère _)
# * ``HTTPLog``  → ``http_log``         (uppercase puis uppercase+lowercase = insère _)
# * ``LLMModel`` → ``llm_model``        (idem)
# * ``URL2Path`` → ``url2_path``        (digit puis uppercase = insère _)
#
# Pattern explicite : on cherche les **frontières** entre :
#   1. Une minuscule/digit suivie d'une majuscule (``aB`` ou ``2B``)
#   2. Une majuscule suivie d'une majuscule + minuscule (``ABc``)
# Cf. review adversariale finding B2.
_CAMEL_TO_SNAKE_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _camel_to_snake(name: str) -> str:
    """Convertit ``CamelCase`` en ``snake_case`` (gère les acronymes).

    Exemples :

    >>> _camel_to_snake("Automation")
    'automation'
    >>> _camel_to_snake("EmailLog")
    'email_log'
    >>> _camel_to_snake("HTTPLog")
    'http_log'
    >>> _camel_to_snake("LLMModel")
    'llm_model'
    >>> _camel_to_snake("URL2Path")
    'url2_path'

    Convention Komptia : ``app.models.<snake>`` contient la classe
    ``<Camel>``. Test garde-fou dans ``tests/unit/test_dashboard_helpers.py``.
    """
    return _CAMEL_TO_SNAKE_RE.sub("_", name).lower()


def _get_model(name: str):
    """Import différé d'un modèle ORM par nom — évite les cycles d'import.

    Convention : ``name`` est le nom CamelCase de la classe (ex.
    ``"Automation"``). Le module est dérivé via :func:`_camel_to_snake`
    (``app.models.automation``). Si la convention de nommage n'est pas
    respectée pour un futur modèle, ajouter une exception explicite ici
    plutôt que de réintroduire un dict hardcode (qui devait être maintenu
    à chaque ajout).

    Auparavant : ``if name == "Automation": from app.models.automation
    import Automation; ...`` répété pour 6 noms — chaque ajout nécessitait
    une PR. Maintenant : générique, zero hardcode, défaut intelligent.
    """
    if name in _DEFERRED_MODELS:
        return _DEFERRED_MODELS[name]
    try:
        module = importlib.import_module(f"app.models.{_camel_to_snake(name)}")
    except ImportError as exc:
        raise ValueError(
            f"Unknown model name: {name!r} — "
            f"module app.models.{_camel_to_snake(name)} introuvable"
        ) from exc
    try:
        cls = getattr(module, name)
    except AttributeError as exc:
        raise ValueError(
            f"Unknown model name: {name!r} — " f"classe {name} absente du module {module.__name__}"
        ) from exc
    _DEFERRED_MODELS[name] = cls
    return cls


def _build_daily_searches(
    now: datetime,
    daily_counts: Optional[List[int]] = None,
) -> List[Dict[str, Any]]:
    """Construit la liste des recherches quotidiennes sur 7 jours."""
    result = []
    for i in range(6, -1, -1):
        day = (now - timedelta(days=i)).date()
        count = daily_counts[6 - i] if daily_counts else 0
        result.append(
            {
                "label": day.strftime("%d/%m"),
                "short_label": DAY_NAMES_SHORT_FR[day.weekday()],
                "count": count,
            }
        )
    return result
