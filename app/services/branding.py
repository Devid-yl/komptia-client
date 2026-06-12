"""Helper de branding global — single source of truth pour le nom d'organisation.

Ce module remplace tous les hardcodes d'un nom particulier qui rôdaient dans
les templates email, le générateur PDF et la config SMTP. Le nom d'organisation
est désormais stocké dans la BDD locale (table ``smtp_global_config.company_name``)
et configurable via ``/admin/settings``.

**Fallback explicite** : si la BDD est inaccessible OU si aucun nom n'est
configuré, on retourne le placeholder ``"[Entreprise à configurer]"`` (pas
un vrai nom). Ce placeholder est volontairement BIZARRE pour qu'un admin le
repère immédiatement comme "config manquante" et le configure (anti-fallback
silencieux : on ne déguise jamais une config manquante en valeur plausible).

**Cache léger 60s** : `get_company_name()` est appelé à chaque rendering
de template email (`EmailTemplateRenderer._enrich_with_branding`) et à
chaque envoi SMTP. Pour éviter d'ouvrir un engine BDD à chaque appel, on
mémorise la valeur 60s. Une modif admin via `/admin/settings` peut
appeler `invalidate_company_name_cache()` pour propager immédiatement —
sinon, propagation au pire dans 60s.
"""

from __future__ import annotations

import logging
import time
from threading import Lock
from typing import Optional

logger = logging.getLogger(__name__)

#: Placeholder visible affiché si aucun nom d'organisation n'est configuré.
#: Volontairement bizarre (crochets) pour qu'un admin le repère et
#: configure le vrai nom via ``/admin/settings``. La formulation reste
#: neutre — Komptia se déploie chez n'importe quel type d'organisation
#: (services, industrie, retail, etc.), aucune supposition métier.
PLACEHOLDER_COMPANY_NAME = "[Entreprise à configurer]"

#: TTL du cache en secondes (60s). Compromis : un admin qui change le
#: nom d'entreprise voit la propagation en moins d'1 minute (acceptable),
#: et on évite des centaines de queries BDD/seconde en hot-path
#: (rendering email).
_CACHE_TTL_SECONDS = 60.0

#: Cache simple : (timestamp_expiry, company_name, smtp_from_name).
#: ``threading.Lock`` (pas asyncio) car la lecture BDD est sync (engine
#: Sync sur SQLite local) — Tornado event-loop tolère un Lock court.
_cache_lock: Lock = Lock()
_cache_expiry: float = 0.0
_cache_company_name: Optional[str] = None
_cache_smtp_from_name: Optional[str] = None


def invalidate_company_name_cache() -> None:
    """Force le rafraîchissement du cache au prochain appel.

    À appeler depuis les handlers admin qui modifient
    ``smtp_global_config`` (ex: `/admin/settings`).
    """
    global _cache_expiry, _cache_company_name, _cache_smtp_from_name
    with _cache_lock:
        _cache_expiry = 0.0
        _cache_company_name = None
        _cache_smtp_from_name = None
    logger.debug("Branding cache invalidated")


def _refresh_cache_from_db() -> None:
    """Recharge le cache depuis ``smtp_global_config``.

    Lit en UNE query les deux champs (``company_name`` + ``from_name``)
    pour réduire le coût. Sous le lock pour éviter une double-lecture.
    """
    global _cache_expiry, _cache_company_name, _cache_smtp_from_name

    company_name: Optional[str] = None
    smtp_from_name: Optional[str] = None
    try:
        from sqlalchemy import select
        from sqlalchemy.orm import Session

        from app.core.database import make_sync_engine
        from app.models.smtp_global_config import SMTPGlobalConfig

        engine = make_sync_engine()
        try:
            with Session(engine) as session:
                # ORDER BY id DESC LIMIT 1 — cohérent avec
                # ``admin_smtp._get_latest_config``. Sans cet ORDER BY,
                # SQLite renvoie une row arbitraire (généralement
                # rowid ASC) ; pendant la fenêtre ``flush → purge``
                # d'un POST handler, la table peut avoir 2 rows, et
                # cette lecture tomberait sur l'ancienne ligne. Le
                # cache serait alors repeuplé avec la mauvaise valeur
                # avant que l'invalidation finale n'intervienne.
                row = session.execute(
                    select(
                        SMTPGlobalConfig.company_name,
                        SMTPGlobalConfig.from_name,
                    )
                    .order_by(SMTPGlobalConfig.id.desc())
                    .limit(1)
                ).first()
                if row:
                    cn, fn = row
                    if cn and cn.strip():
                        company_name = cn.strip()
                    if fn and fn.strip():
                        smtp_from_name = fn.strip()
        finally:
            engine.dispose()
    except Exception:  # noqa: BLE001 — branding ne doit jamais crasher l'app
        logger.warning(
            "Lecture branding depuis smtp_global_config a échoué — "
            "fallback placeholder. Configurer via /admin/settings.",
            exc_info=True,
        )
    # Mise à jour du cache même en cas d'échec (None reste comme tel
    # → get_*_name() tombe sur le placeholder). Le TTL repart : on évite
    # une tempête de retry BDD pendant la fenêtre.
    _cache_company_name = company_name
    _cache_smtp_from_name = smtp_from_name
    _cache_expiry = time.monotonic() + _CACHE_TTL_SECONDS


def _get_cached_or_refresh() -> tuple[Optional[str], Optional[str]]:
    """Lecture cache si frais, sinon refresh sous lock.

    Pattern double-checked locking : on vérifie l'expiration sans lock
    d'abord (lecture atomique d'un float = OK CPython), puis on prend
    le lock et on re-vérifie avant le refresh (autre thread peut avoir
    rafraîchi entre nos deux checks).
    """
    if time.monotonic() < _cache_expiry:
        return _cache_company_name, _cache_smtp_from_name
    with _cache_lock:
        if time.monotonic() >= _cache_expiry:
            _refresh_cache_from_db()
        return _cache_company_name, _cache_smtp_from_name


def get_company_name() -> str:
    """Retourne le nom d'entreprise configuré, ou le placeholder visible.

    Utilisé par :
    * ``EmailTemplateRenderer`` pour injecter ``{{ company_name }}`` dans
      tous les templates email.
    * ``PDFGenerator`` pour le pied de page des rapports PDF.
    * ``SMTPClient`` pour le ``From: <name>`` quand ``from_name`` n'est pas
      explicitement défini.

    Returns:
        Le nom configuré, ou ``PLACEHOLDER_COMPANY_NAME``
        (``"[Entreprise à configurer]"``) si aucun n'est configuré.
    """
    company_name, _ = _get_cached_or_refresh()
    return company_name or PLACEHOLDER_COMPANY_NAME


def get_smtp_from_name() -> str:
    """Retourne le ``from_name`` SMTP — ``smtp_from_name`` ou ``company_name``.

    Convention : si l'admin a explicitement défini un ``from_name`` distinct
    du ``company_name`` (par exemple « Notifications <nom> » pour les
    rapports automatisés), on le respecte. Sinon on tombe sur
    ``company_name``.
    """
    company_name, smtp_from_name = _get_cached_or_refresh()
    if smtp_from_name:
        return smtp_from_name
    if company_name:
        return company_name
    return PLACEHOLDER_COMPANY_NAME
