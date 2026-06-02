"""
Rate limiter en mémoire avec fenêtre glissante.

Utilisé pour protéger les endpoints coûteux (appels IA, etc.)
contre les abus et l'épuisement des crédits API.
"""

import time
import threading
import weakref
from collections import defaultdict
from typing import Dict, List


class RateLimiter:
    """
    Rate limiter avec sliding window en mémoire.

    Thread-safe grâce à un lock. Les entrées expirées sont nettoyées
    automatiquement à chaque vérification.

    Usage:
        limiter = RateLimiter()
        if not limiter.check("user:42", max_requests=10, window_seconds=60):
            raise HTTPError(429, "Trop de requêtes")
    """

    #: Registre FAIBLE de toutes les instances — permet un cleanup global
    #: périodique (cf. ``cleanup_all`` + ``app/main.py``). WeakSet : les
    #: instances de test GC'd se retirent seules ; les singletons
    #: module-level persistent tant que leur module les référence.
    _instances: "weakref.WeakSet[RateLimiter]" = weakref.WeakSet()

    def __init__(self) -> None:
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
        RateLimiter._instances.add(self)

    def check(self, key: str, max_requests: int, window_seconds: int) -> bool:
        """
        Vérifie si une requête est autorisée pour la clé donnée.

        Args:
            key: Identifiant unique (ex: "user:42", "ip:192.168.1.1")
            max_requests: Nombre max de requêtes autorisées dans la fenêtre
            window_seconds: Taille de la fenêtre en secondes

        Returns:
            True si la requête est autorisée, False si le rate limit est atteint
        """
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            # Nettoyer les entrées expirées
            self._requests[key] = [ts for ts in self._requests[key] if ts > cutoff]

            if len(self._requests[key]) >= max_requests:
                return False

            self._requests[key].append(now)
            return True

    def remaining(self, key: str, max_requests: int, window_seconds: int) -> int:
        """Retourne le nombre de requêtes restantes pour la clé."""
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            current = [ts for ts in self._requests[key] if ts > cutoff]
            return max(0, max_requests - len(current))

    def cleanup(self, max_age_seconds: int = 3600) -> int:
        """
        Nettoie les entrées expirées de toutes les clés.

        Args:
            max_age_seconds: Age max avant suppression (défaut: 1 heure)

        Returns:
            Nombre de clés supprimées
        """
        now = time.time()
        cutoff = now - max_age_seconds
        removed = 0

        with self._lock:
            keys_to_remove = [
                key
                for key, timestamps in self._requests.items()
                if not timestamps or max(timestamps) < cutoff
            ]
            for key in keys_to_remove:
                del self._requests[key]
                removed += 1

        return removed

    @classmethod
    def cleanup_all(cls, max_age_seconds: int = 3600) -> int:
        """Purge les clés expirées de TOUTES les instances enregistrées.

        ``cleanup()`` existait par instance mais n'était jamais appelé → le
        dict ``_requests`` accumulait une clé par IP/user sans éviction
        (croissance non bornée — axe 21 Komptia). Ce hook, appelé
        périodiquement au runtime (cf. ``app/main.py``), borne la mémoire.
        Thread-safe : chaque ``cleanup()`` prend son propre lock.

        INVARIANT : ``max_age_seconds`` DOIT rester >= la plus longue fenêtre
        de rate-limit utilisée dans l'app. Sinon, une clé encore DANS sa
        fenêtre (compteur actif) serait purgée → réinitialisation = bypass.
        L'éviction se base sur ``max(timestamps)`` (le plus récent), donc tant
        que ``max_age >= window`` aucune clé active n'est évincée. Le caller
        passe 24h, bien au-dessus de la plus longue fenêtre (1h aujourd'hui).
        """
        total = 0
        for inst in list(cls._instances):
            total += inst.cleanup(max_age_seconds)
        return total
