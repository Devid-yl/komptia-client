"""Moniteur de latence de l'event loop asyncio — observabilité production.

POURQUOI
--------
Komptia est mono-thread asyncio (Tornado). Tout code SYNCHRONE long (CPU lourd,
I/O bloquant, sandbox sqlite, run pipeline NL→SQL in-process — cf. tâche H1 du
backlog) gèle l'event loop : pendant ce temps AUCUNE autre coroutine ne progresse
(WebSocket Iris, requêtes HTTP de TOUS les users). Ce gel est invisible dans les
logs applicatifs habituels — d'où ce moniteur.

MÉCANISME (mesure de RETARD D'ORDONNANCEMENT)
---------------------------------------------
On planifie un tick via ``IOLoop.call_later(interval, tick)`` en mémorisant
l'instant ATTENDU de réveil. Au tick, ``retard = maintenant − instant_attendu``.
Si le loop tourne smain, le tick arrive ~à l'heure (retard ≈ 0). Si du code sync a
bloqué le loop, le call_later ne peut pas être servi à temps → le retard mesuré ≈
durée du blocage. On **re-planifie depuis le tick** (pas un ``PeriodicCallback``
qui recale sa cadence sur une grille fixe et MASQUERAIT la magnitude du gel, cf.
``PeriodicCallback._update_next`` « skip cycles to get back to a multiple of the
original schedule »). Horloge ``time.monotonic()`` → immunisé NTP/DST.

CE QUE LE MONITEUR NE FAIT PAS (honnêteté)
------------------------------------------
- Il ne dit PAS quel code a bloqué (le bloc est déjà fini quand le tick refire).
  Pour pinpointer, un watchdog échantillonnant la stack du thread principal PENDANT
  le gel serait nécessaire (suivi séparé, hors scope).
- Plancher de détection ≈ ``interval`` : un gel plus court qu'un intervalle, entre
  deux ticks, peut passer inaperçu.
- Un retard ÉNORME (> ``suspend_cap``) est traité comme une PAUSE PROCESSUS probable
  (sommeil laptop, SIGSTOP, migration VM) et loggé en INFO, pas comme un blocage code.

GARANTIES
---------
- **Zéro changement de comportement applicatif** : pure mesure + log.
- **Borné** : un seul timeout en vol + quelques floats ; WARN THROTTLÉ (anti-flood,
  axe 21) avec compteur des suppressions.
- **Fail-safe** : ``_tick`` n'élève jamais ; re-planifie même si l'évaluation lève.

Activation/config via env (cf. :func:`start_loop_lag_monitor`).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable, Optional

import tornado.ioloop

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers env (locaux : pas de SSoT partagée aujourd'hui ; un futur
# ``app/utils/env.py`` consoliderait ces helpers dupliqués à travers la codebase
# — noté comme cleanup basse priorité, hors scope de ce module).
# ---------------------------------------------------------------------------
def _int_env(name: str, default: int, *, min_: int, max_: int) -> int:
    """Var d'env entière, fallback ``default`` si absente/invalide, clampée."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    if value < min_:
        logger.warning("env %s=%d < min %d — clampé", name, value, min_)
        return min_
    if value > max_:
        logger.warning("env %s=%d > max %d — clampé", name, value, max_)
        return max_
    return value


def _bool_env(name: str, default: bool) -> bool:
    """Var d'env booléenne (``1/true/yes/on`` → True), fallback ``default``."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class LoopLagMonitor:
    """Mesure le retard d'ordonnancement de l'event loop et logue au-delà d'un seuil.

    Parameters
    ----------
    interval_ms:
        Cadence des ticks de sonde (ms). Plancher de détection ≈ cet intervalle.
    threshold_ms:
        Retard à partir duquel on considère le loop « bloqué » et on logue.
    warn_cooldown_ms:
        Délai minimal entre deux WARN (anti-flood). Les blocages survenus pendant
        le cooldown sont COMPTÉS et annoncés au prochain WARN. 0 = pas de throttle.
    suspend_cap_ms:
        Retard au-delà duquel on suppose une PAUSE PROCESSUS (sommeil/SIGSTOP) et
        non un blocage code → loggé en INFO, pas en WARN.
    time_fn:
        Source d'horloge MONOTONE (secondes). Injectable pour les tests ; défaut
        :func:`time.monotonic`.
    """

    def __init__(
        self,
        interval_ms: int,
        threshold_ms: int,
        *,
        warn_cooldown_ms: int = 10_000,
        suspend_cap_ms: int = 30_000,
        time_fn: Optional[Callable[[], float]] = None,
    ) -> None:
        self._interval_s = interval_ms / 1000.0
        self._interval_ms = interval_ms
        self._threshold_ms = threshold_ms
        self._cooldown_s = warn_cooldown_ms / 1000.0
        self._suspend_cap_s = suspend_cap_ms / 1000.0
        self._time_fn = time_fn or time.monotonic
        self._loop: Optional[tornado.ioloop.IOLoop] = None
        self._handle: Any = None
        self._stopped = True
        self._expected_fire_s: float = 0.0
        self._last_warn_s: Optional[float] = None
        self._suppressed = 0

    def _now(self) -> float:
        return self._time_fn()

    def start(self, io_loop: Optional[tornado.ioloop.IOLoop] = None) -> "LoopLagMonitor":
        """Démarre la sonde. Idempotent (un start déjà actif est d'abord stoppé)."""
        if not self._stopped:
            self.stop()
        self._loop = io_loop or tornado.ioloop.IOLoop.current()
        self._stopped = False
        # Restart propre (review Faible) : ne pas hériter du cooldown / compteur
        # d'une session précédente, sinon le 1er blocage post-restart pourrait être
        # supprimé à tort (``_last_warn_s`` encore dans la fenêtre de cooldown).
        self._last_warn_s = None
        self._suppressed = 0
        self._schedule_next()
        return self

    def stop(self) -> None:
        """Arrête la sonde. No-op si non démarrée (idempotent)."""
        self._stopped = True
        if self._handle is not None and self._loop is not None:
            try:
                self._loop.remove_timeout(self._handle)
            except Exception:  # noqa: BLE001 — défensif, ne jamais lever au shutdown
                logger.debug("remove_timeout a levé (ignoré)", exc_info=True)
        self._handle = None

    def _schedule_next(self) -> None:
        if self._stopped or self._loop is None:
            return
        # Instant ATTENDU de réveil = maintenant + intervalle. Le tick comparera
        # son instant réel à cette valeur → le retard = durée de blocage du loop.
        self._expected_fire_s = self._now() + self._interval_s
        self._handle = self._loop.call_later(self._interval_s, self._tick)

    def _tick(self) -> None:
        """Un tick : mesure le retard d'ordonnancement, logue si > seuil. Ne lève jamais."""
        try:
            now = self._now()
            lag_s = now - self._expected_fire_s
            self._evaluate(lag_s, now)
        except Exception:  # noqa: BLE001 — un moniteur ne doit jamais crasher l'IOLoop
            logger.exception("LoopLagMonitor._tick a levé (ignoré)")
        finally:
            self._schedule_next()

    def _evaluate(self, lag_s: float, now: float) -> None:
        """Décide quoi logger pour un retard donné (testable sans IOLoop)."""
        lag_ms = lag_s * 1000.0
        if lag_ms < self._threshold_ms:
            return
        # Retard énorme → pause processus probable (sommeil/SIGSTOP/migration VM),
        # PAS un blocage code. Loggé en INFO pour ne pas crier au loup.
        if lag_s >= self._suspend_cap_s:
            logger.info(
                "Réveil après pause processus probable (~%.1f s) — non compté comme "
                "blocage event-loop",
                lag_s,
            )
            # Une pause processus casse la continuité « depuis le dernier WARN » →
            # on repart d'un compteur propre (évite une attribution « +N » trompeuse).
            self._suppressed = 0
            return
        # Throttle anti-flood : un seul WARN par cooldown, on compte les autres.
        if (
            self._cooldown_s > 0
            and self._last_warn_s is not None
            and (now - self._last_warn_s) < self._cooldown_s
        ):
            self._suppressed += 1
            return
        extra = f" (+{self._suppressed} autre(s) blocage(s) depuis le dernier WARN)" if self._suppressed else ""
        logger.warning(
            "Event loop bloqué ~%.0f ms (seuil %d ms) — code SYNCHRONE sur le loop "
            "(CPU/I-O bloquant, sandbox sqlite, run pipeline in-process ; cf. tâche H1)%s",
            lag_ms,
            self._threshold_ms,
            extra,
        )
        self._last_warn_s = now
        self._suppressed = 0


#: Noms d'env (préfixe neutre KOMPTIA — la sonde est app-wide, pas Iris-spécifique).
_ENV_ENABLED = "KOMPTIA_LOOP_LAG_MONITOR"
_ENV_INTERVAL_MS = "KOMPTIA_LOOP_LAG_INTERVAL_MS"
_ENV_THRESHOLD_MS = "KOMPTIA_LOOP_LAG_THRESHOLD_MS"
_ENV_COOLDOWN_MS = "KOMPTIA_LOOP_LAG_WARN_COOLDOWN_MS"
_ENV_SUSPEND_CAP_MS = "KOMPTIA_LOOP_LAG_SUSPEND_CAP_MS"


def start_loop_lag_monitor(
    io_loop: Optional[tornado.ioloop.IOLoop] = None,
) -> Optional[LoopLagMonitor]:
    """Démarre le moniteur si activé par env. Retourne l'instance ou ``None``.

    Env :
    - ``KOMPTIA_LOOP_LAG_MONITOR`` (bool, défaut ``True``) — activation.
    - ``KOMPTIA_LOOP_LAG_INTERVAL_MS`` (défaut 500, clamp [50, 60000]).
    - ``KOMPTIA_LOOP_LAG_THRESHOLD_MS`` (défaut 250, clamp [10, 600000]).
    - ``KOMPTIA_LOOP_LAG_WARN_COOLDOWN_MS`` (défaut 10000, clamp [0, 600000]).
    - ``KOMPTIA_LOOP_LAG_SUSPEND_CAP_MS`` (défaut 30000, clamp [1000, 3600000]).
    """
    if not _bool_env(_ENV_ENABLED, True):
        logger.info("Moniteur de latence event-loop désactivé (%s)", _ENV_ENABLED)
        return None
    interval_ms = _int_env(_ENV_INTERVAL_MS, 500, min_=50, max_=60_000)
    threshold_ms = _int_env(_ENV_THRESHOLD_MS, 250, min_=10, max_=600_000)
    cooldown_ms = _int_env(_ENV_COOLDOWN_MS, 10_000, min_=0, max_=600_000)
    suspend_cap_ms = _int_env(_ENV_SUSPEND_CAP_MS, 30_000, min_=1_000, max_=3_600_000)
    monitor = LoopLagMonitor(
        interval_ms,
        threshold_ms,
        warn_cooldown_ms=cooldown_ms,
        suspend_cap_ms=suspend_cap_ms,
    ).start(io_loop)
    logger.info(
        "Moniteur de latence event-loop activé (intervalle=%d ms, seuil=%d ms, "
        "cooldown=%d ms, cap pause=%d ms)",
        interval_ms,
        threshold_ms,
        cooldown_ms,
        suspend_cap_ms,
    )
    return monitor
