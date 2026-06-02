"""Compteur in-process des modes d'attachement Iris (Task #43c, cycle #33).

Module SSoT pour tracker en mémoire combien de messages Iris ont utilisé
le mode ``legacy`` (file_id + lecture disque) vs ``ephemeral``
(attachment_stats calculées navigateur).

**Pourquoi in-process et pas en BDD** :
- L'objectif est le monitoring de transition, pas l'audit RGPD.
- Reset au boot acceptable — David observe sur quelques jours pour
  voir le ratio. Si reboot, on recommence (pas de perte critique).
- Pas de nouvelle migration BDD, pas de table à provisionner, pas
  de retention TTL à gérer (cf. axe Komptia 21).

**Thread-safety** : ``threading.Lock`` sur les writes. Les reads
peuvent retourner un snapshot pas tout à fait à jour (Python GIL
suffit en pratique, mais on n'a pas besoin de l'exactitude absolue
pour du monitoring).

**Privacy** : le module ne stocke AUCUNE PII — juste des compteurs
incrémentés par mode. Aucun user_id, aucun file_id, aucun timestamp
de message.
"""

from __future__ import annotations

import logging
import threading
from typing import Dict, Optional

logger = logging.getLogger(__name__)


# ── Mode constants (SSoT) ────────────────────────────────────────────


#: Modes valides — synchronisé avec ``_classify_attachment_mode`` dans
#: ``app/handlers/iris.py``. ``none`` exclu (pas d'attachement = pas
#: d'intérêt monitoring).
_VALID_MODES: frozenset[str] = frozenset({"legacy", "ephemeral", "both"})


# ── State (in-process, thread-safe via lock) ────────────────────────


_lock = threading.Lock()
_counters: Dict[str, int] = {mode: 0 for mode in _VALID_MODES}
_start_ts: Optional[float] = None


def record_mode(mode: str) -> None:
    """Incrémente le compteur pour ``mode``.

    Args:
        mode: ``"legacy"``, ``"ephemeral"`` ou ``"both"``. Tout autre
            valeur est ignorée (fail-soft — un classifieur buggé ne
            doit pas crasher le flow message).
    """
    global _start_ts
    if mode not in _VALID_MODES:
        logger.debug("record_mode: mode inconnu ignoré: %r", mode)
        return
    with _lock:
        _counters[mode] += 1
        if _start_ts is None:
            import time as _time
            _start_ts = _time.time()


def get_snapshot() -> Dict[str, object]:
    """Retourne un snapshot des compteurs actuels.

    Format :
        {
            "counters": {"legacy": N, "ephemeral": M, "both": K},
            "total": N + M + K,
            "ephemeral_ratio": M / (N+M+K),  # 0..1, None si total=0
            "uptime_seconds": <float ou None>,
        }

    Thread-safe : lit sous le lock.
    """
    import time as _time

    with _lock:
        counters = dict(_counters)
        start = _start_ts

    total = sum(counters.values())
    ratio: Optional[float] = None
    if total > 0:
        ratio = counters.get("ephemeral", 0) / total

    uptime: Optional[float] = None
    if start is not None:
        uptime = _time.time() - start

    return {
        "counters": counters,
        "total": total,
        "ephemeral_ratio": ratio,
        "uptime_seconds": uptime,
    }


def reset() -> None:
    """Reset les compteurs à 0. Réservé aux tests + endpoint admin
    explicite si un jour exposé (#43c sub-task future)."""
    global _start_ts
    with _lock:
        for mode in _VALID_MODES:
            _counters[mode] = 0
        _start_ts = None
