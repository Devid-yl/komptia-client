"""Watchdog de liveness de la boucle d'événements Tornado.

Détecte un **gel de l'IOLoop** (boucle mono-thread bloquée par un appel
synchrone, un deadlock, ou une famine de ressources) et force la sortie du
process pour que l'orchestrateur le relance automatiquement
(Docker ``restart: unless-stopped``, systemd ``Restart=always``, k8s).

Pourquoi c'est nécessaire (incident prod 2026-06-08)
----------------------------------------------------
Docker **ne redémarre PAS** un conteneur marqué ``unhealthy`` — il ne
relance qu'un conteneur qui *sort*. Sans ce watchdog, un gel de l'IOLoop =
panne **infinie** : toutes les requêtes pendent (y compris ``/health`` qui
ne fait pourtant aucune I/O), le conteneur reste « Up (unhealthy) » et rien
ne le récupère jusqu'à une intervention manuelle.

Mécanisme (volontairement HORS asyncio)
---------------------------------------
* Un :class:`~tornado.ioloop.PeriodicCallback` sur l'IOLoop met à jour un
  battement (``_last_beat``) à intervalle régulier. Si la boucle est gelée,
  le callback ne s'exécute plus → le battement stagne.
* Un **thread OS daemon, indépendant de l'IOLoop**, se réveille
  périodiquement et compare ``monotonic() - _last_beat``. Au-delà du seuil
  ``stall_threshold_s``, il :

  1. **dumpe les stacks de tous les threads** sur ``stderr`` (capturé par
     ``docker logs``) — on voit ENFIN *où* la boucle est bloquée ;
  2. appelle ``os._exit(1)`` — sortie dure, sans cleanup (la boucle est
     morte ; un arrêt « propre » via l'IOLoop pendrait lui aussi).

Le thread étant hors IOLoop, il survit même quand la boucle est 100 %
bloquée — c'est précisément l'intérêt.

Configuration (env, génériques — aucun hardcode applicatif)
-----------------------------------------------------------
* ``KOMPTIA_WATCHDOG_DISABLE=1`` — désactive complètement le watchdog.
* ``KOMPTIA_WATCHDOG_STALL_S`` — seuil de gel en secondes (défaut 60).
  Une coroutine correcte ne bloque JAMAIS la boucle plus de quelques ms ;
  60 s de boucle figée est toujours un bug, jamais un fonctionnement normal
  (les requêtes Sage lentes sont *awaited*, elles ne bloquent pas la boucle).
* ``KOMPTIA_WATCHDOG_CHECK_S`` — période de battement/sondage (défaut 10).
"""

from __future__ import annotations

import faulthandler
import os
import sys
import threading
import time
from typing import Callable, Optional

from tornado.ioloop import IOLoop, PeriodicCallback

from app.utils.logger import get_logger

logger = get_logger(__name__)

_DEFAULT_STALL_THRESHOLD_S = 60.0
_DEFAULT_CHECK_INTERVAL_S = 10.0
# Backstop : délai après lequel ``faulthandler.dump_traceback_later`` force la
# sortie en C (immune au GIL) si le dump manuel pend (gel tenant le GIL).
_DUMP_BACKSTOP_S = 5.0
_TRUE_VALUES = {"1", "true", "yes", "on"}


def _safe_float_env(name: str, default: float) -> float:
    """Lit un float positif depuis l'env, fail-safe sur le défaut.

    Une valeur absente, vide, non numérique ou <= 0 retombe sur ``default``
    avec un warning — un watchdog mal configuré ne doit jamais ni crasher le
    boot ni se transformer en faux positif (seuil 0 → exit immédiat).
    """
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        val = float(raw)
    except (TypeError, ValueError):
        logger.warning("%s=%r invalide (float attendu) — défaut %.0fs conservé.", name, raw, default)
        return default
    if val <= 0:
        logger.warning("%s=%r <= 0 invalide — défaut %.0fs conservé.", name, raw, default)
        return default
    return val


class IOLoopWatchdog:
    """Détecteur de gel de l'IOLoop → sortie process pour auto-restart.

    ``on_stall`` est injectable pour les tests (par défaut : dump des stacks
    + ``os._exit(1)``). Il reçoit la durée de gel mesurée en secondes.
    """

    def __init__(
        self,
        *,
        stall_threshold_s: float = _DEFAULT_STALL_THRESHOLD_S,
        check_interval_s: float = _DEFAULT_CHECK_INTERVAL_S,
        on_stall: Optional[Callable[[float], None]] = None,
    ) -> None:
        # ``check`` doit rester strictement < ``stall`` pour garantir au moins
        # une mesure dans la fenêtre de gel (sinon faux négatifs).
        if check_interval_s >= stall_threshold_s:
            check_interval_s = max(1.0, stall_threshold_s / 4.0)
        self.stall_threshold_s = stall_threshold_s
        self.check_interval_s = check_interval_s
        self._on_stall = on_stall or self._default_on_stall
        self._last_beat = time.monotonic()
        self._beat_cb: Optional[PeriodicCallback] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._fired = False
        # True dès le 1er battement réel. Tant que False, le monitor ne déclare
        # PAS de gel (boucle pas encore démarrée ≠ gel) — robustesse au boot.
        self._beat_seen = False

    # ── Battement (exécuté SUR l'IOLoop) ──────────────────────────────────
    def _beat(self) -> None:
        """Marque la boucle comme vivante. No-op si la boucle est gelée."""
        self._last_beat = time.monotonic()
        self._beat_seen = True

    # ── Surveillance (exécutée HORS IOLoop, dans un thread daemon) ─────────
    def _default_on_stall(self, stalled_for: float) -> None:
        # Backstop C-level immune au GIL (finding adversarial #4) : si le gel tient
        # le GIL (extension C type pyodbc/SQLCipher en boucle), le ``dump_traceback``
        # ci-dessous peut LUI-MÊME pendre et ``os._exit`` ne serait jamais atteint
        # → le watchdog raterait sa mission. ``dump_traceback_later(..., exit=True)``
        # arme un timer EN C qui dump puis ``_exit`` indépendamment de l'état de
        # l'interpréteur. Armé AVANT le dump manuel ; en nominal ``os._exit`` part
        # immédiatement (le timer ne sert que si le dump manuel pend).
        try:
            faulthandler.dump_traceback_later(_DUMP_BACKSTOP_S, exit=True)
        except Exception:  # noqa: BLE001 — best-effort, ne jamais empêcher l'exit
            pass
        try:
            sys.stderr.write(
                f"\n[IOLoopWatchdog] IOLoop figée depuis {stalled_for:.1f}s "
                f"(seuil {self.stall_threshold_s:.0f}s) — dump des threads puis exit(1):\n"
            )
            sys.stderr.flush()
            # all_threads=True : on veut voir le thread bloquant (Sage, SQLite,
            # rendu Jinja, etc.) ET la pile de l'IOLoop.
            faulthandler.dump_traceback(all_threads=True)
            sys.stderr.flush()
        except Exception:  # noqa: BLE001 — l'error path ne doit jamais empêcher l'exit
            pass
        # Sortie dure : bypass atexit/cleanup (la boucle est morte). Docker
        # ``restart: unless-stopped`` voit le code de sortie ≠ 0 et relance.
        os._exit(1)

    def _monitor(self) -> None:
        # ``Event.wait`` rend la boucle interruptible par ``stop()`` (tests)
        # et évite un ``time.sleep`` non réveillable.
        while not self._stop.wait(self.check_interval_s):
            # Ne rien déclarer tant que la boucle n'a pas battu AU MOINS une fois :
            # un battement jamais survenu = boucle pas encore démarrée (boot), PAS
            # un gel. Rend le watchdog robuste à un repositionnement de l'appel
            # avant ``io_loop.start()`` (finding adversarial #5 — sinon faux-kill
            # au boot). Le boot-hang reste couvert par le healthcheck Docker
            # (start_period) + les timeouts des run_sync.
            if not self._beat_seen:
                continue
            stalled_for = time.monotonic() - self._last_beat
            if stalled_for > self.stall_threshold_s and not self._fired:
                self._fired = True
                logger.critical(
                    "IOLoop figée depuis %.1fs (seuil %.0fs) — sortie process "
                    "pour auto-restart par l'orchestrateur",
                    stalled_for,
                    self.stall_threshold_s,
                )
                self._on_stall(stalled_for)
                return

    # ── Cycle de vie ──────────────────────────────────────────────────────
    def start(self, loop: Optional[IOLoop] = None) -> None:
        """Arme le battement sur ``loop`` et lance le thread de surveillance.

        À appeler APRÈS le boot synchrone (les ``io_loop.run_sync`` de
        démarrage ne font pas tourner le ``PeriodicCallback``, ce qui
        fausserait le battement initial).
        """
        loop = loop or IOLoop.current()
        self._last_beat = time.monotonic()
        # PeriodicCallback s'attache à la boucle courante au moment du start ;
        # on l'instancie/démarre dans le contexte de ``loop`` via add_callback
        # pour éviter toute ambiguïté de boucle courante au boot.
        self._beat_cb = PeriodicCallback(self._beat, self.check_interval_s * 1000.0)
        loop.add_callback(self._beat_cb.start)
        self._thread = threading.Thread(
            target=self._monitor, name="ioloop-watchdog", daemon=True
        )
        self._thread.start()
        logger.info(
            "IOLoop watchdog actif (seuil gel=%.0fs, sondage=%.0fs).",
            self.stall_threshold_s,
            self.check_interval_s,
        )

    def stop(self) -> None:
        """Arrête proprement (tests / shutdown). Idempotent."""
        self._stop.set()
        if self._beat_cb is not None:
            try:
                self._beat_cb.stop()
            except Exception:  # noqa: BLE001 — best-effort
                pass


_watchdog: Optional[IOLoopWatchdog] = None


def start_io_loop_watchdog(loop: Optional[IOLoop] = None) -> Optional[IOLoopWatchdog]:
    """Démarre le watchdog global (idempotent).

    Opt-out via ``KOMPTIA_WATCHDOG_DISABLE``. Retourne l'instance active, ou
    ``None`` si désactivé.
    """
    global _watchdog
    if os.getenv("KOMPTIA_WATCHDOG_DISABLE", "").strip().lower() in _TRUE_VALUES:
        logger.info("IOLoop watchdog désactivé (KOMPTIA_WATCHDOG_DISABLE).")
        return None
    if _watchdog is not None:
        return _watchdog
    wd = IOLoopWatchdog(
        stall_threshold_s=_safe_float_env("KOMPTIA_WATCHDOG_STALL_S", _DEFAULT_STALL_THRESHOLD_S),
        check_interval_s=_safe_float_env("KOMPTIA_WATCHDOG_CHECK_S", _DEFAULT_CHECK_INTERVAL_S),
    )
    wd.start(loop)
    _watchdog = wd
    return wd
