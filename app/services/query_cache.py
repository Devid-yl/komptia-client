"""
Cache LRU pour les requêtes SQL générées.
Améliore les performances en évitant de régénérer le même SQL.
"""

import hashlib
import threading
import time
from typing import Optional, Dict, Any
from collections import OrderedDict
import logging

logger = logging.getLogger(__name__)


class QueryCache:
    """
    Cache LRU pour les requêtes SQL.

    Stocke les résultats de génération SQL avec TTL.
    Utilise OrderedDict pour implémenter LRU.
    """

    def __init__(self, max_size: int = 100, ttl_seconds: int = 3600):
        """
        Args:
            max_size: Nombre maximum d'entrées dans le cache
            ttl_seconds: Durée de vie en secondes (défaut: 1h)
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def _generate_key(self, question: str, schema_context: str = "") -> str:
        """
        Génère une clé de cache unique.

        Args:
            question: Question en langage naturel
            schema_context: Contexte du schéma (optionnel)

        Returns:
            Hash MD5 comme clé
        """
        content = f"{question.lower().strip()}:{schema_context}"
        return hashlib.md5(content.encode()).hexdigest()

    def get(self, question: str, schema_context: str = "") -> Optional[str]:
        """
        Récupère le SQL depuis le cache.

        Args:
            question: Question en langage naturel
            schema_context: Contexte du schéma

        Returns:
            SQL généré ou None si absent/expiré
        """
        key = self._generate_key(question, schema_context)

        with self._lock:
            if key not in self._cache:
                self._misses += 1
                logger.debug("Cache MISS: %s...", question[:50])
                return None

            entry = self._cache[key]

            # Vérifier expiration
            if time.time() - entry["timestamp"] > self.ttl_seconds:
                del self._cache[key]
                self._misses += 1
                logger.debug("Cache EXPIRED: %s...", question[:50])
                return None

            # Move to end (LRU)
            self._cache.move_to_end(key)
            self._hits += 1

            logger.debug(
                "Cache HIT: %s... (hit rate: %.1f%%)", question[:50], self.hit_rate() * 100
            )
            return entry["sql"]

    def set(self, question: str, sql: str, schema_context: str = "") -> None:
        """
        Stocke le SQL dans le cache.

        Args:
            question: Question en langage naturel
            sql: SQL généré
            schema_context: Contexte du schéma
        """
        key = self._generate_key(question, schema_context)

        with self._lock:
            # Si cache plein, supprimer le plus ancien (LRU)
            if len(self._cache) >= self.max_size and key not in self._cache:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                logger.debug("Cache EVICTED: %s", oldest_key)

            self._cache[key] = {"sql": sql, "timestamp": time.time(), "question": question}

            # Move to end
            self._cache.move_to_end(key)

            logger.debug(
                "Cache SET: %s... (size: %d/%d)", question[:50], len(self._cache), self.max_size
            )

    def clear(self) -> None:
        """Vide tout le cache."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
        logger.info("Cache cleared")

    def hit_rate(self) -> float:
        """
        Calcule le taux de succès du cache.

        Returns:
            Ratio hits/(hits+misses) entre 0 et 1
        """
        with self._lock:
            total = self._hits + self._misses
            if total == 0:
                return 0.0
            return self._hits / total

    def stats(self) -> Dict[str, Any]:
        """
        Retourne les statistiques du cache.

        Returns:
            Dict avec hits, misses, size, hit_rate
        """
        with self._lock:
            return {
                "hits": self._hits,
                "misses": self._misses,
                "size": len(self._cache),
                "max_size": self.max_size,
                "hit_rate": self._hits / max(self._hits + self._misses, 1),
                "ttl_seconds": self.ttl_seconds,
            }


# Instance globale du cache
_global_cache: Optional[QueryCache] = None


def get_cache() -> QueryCache:
    """
    Retourne l'instance globale du cache.
    Crée l'instance si elle n'existe pas.

    Returns:
        Instance QueryCache
    """
    global _global_cache
    if _global_cache is None:
        _global_cache = QueryCache(max_size=100, ttl_seconds=3600)
        logger.info("QueryCache initialized (max_size=100, ttl=1h)")
    return _global_cache


def clear_cache() -> None:
    """Vide le cache global."""
    cache = get_cache()
    cache.clear()
