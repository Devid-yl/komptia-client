"""
Service d'embeddings vectoriels pour Komptia.

Utilise sentence-transformers en LOCAL (aucun appel API, aucun coût, aucune fuite de données).
Modèle : paraphrase-multilingual-MiniLM-L12-v2 (384 dims, multilingue/français).
~440 Mo de téléchargement au premier lancement, ~500 Mo RAM.

Le modèle est synchrone (PyTorch) → exécuté via run_in_executor()
pour ne pas bloquer l'event loop Tornado.
"""

import asyncio
import hashlib
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import numpy as np

from app.constants_ai import EMBEDDING_MODEL, EMBEDDING_BATCH_SIZE, EMBEDDING_DIMENSIONS

logger = logging.getLogger(__name__)

# Cache en mémoire (text_hash -> embedding)
# hashlib.md5 = stable et sans collision (contrairement à hash())
_embedding_cache: dict[str, np.ndarray] = {}
_CACHE_MAX_SIZE = 2000
_cache_lock = threading.Lock()

# ThreadPool dédié aux embeddings (évite de bloquer l'event loop Tornado)
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="embedding")


def _cache_key(text: str) -> str:
    """Clé de cache stable et sans collision."""
    return hashlib.md5(text.encode()).hexdigest()


class EmbeddingService:
    """
    Génère des embeddings via sentence-transformers en local.

    Modèle chargé une seule fois (lazy init au premier appel).
    Exécution dans un ThreadPool pour ne pas bloquer Tornado.
    Aucun appel API, aucun coût, aucune donnée envoyée à l'extérieur.
    """

    def __init__(self, model_name: str = EMBEDDING_MODEL):
        self._model_name = model_name
        self._model = None  # Lazy init
        self._available: Optional[bool] = None

    def _load_model(self):
        """Charge le modèle sentence-transformers (synchrone, appelé dans le thread pool)."""
        if self._model is not None:
            return self._model

        try:
            from sentence_transformers import SentenceTransformer

            logger.info("Chargement du modèle d'embeddings: %s...", self._model_name)
            self._model = SentenceTransformer(self._model_name)
            self._available = True

            actual_dims = self._model.get_sentence_embedding_dimension()
            if actual_dims != EMBEDDING_DIMENSIONS:
                logger.error(
                    "DIMENSIONS MISMATCH: modèle %s produit %d dims, "
                    "EMBEDDING_DIMENSIONS=%d. Embeddings désactivés.",
                    self._model_name,
                    actual_dims,
                    EMBEDDING_DIMENSIONS,
                )
                self._model = None
                self._available = False
                return None

            logger.info(
                "Modèle d'embeddings chargé: %s (%d dims)",
                self._model_name,
                actual_dims,
            )
            return self._model
        except ImportError:
            logger.warning(
                "sentence-transformers non installé — embeddings désactivés. "
                "Installer avec: pip install sentence-transformers"
            )
            self._available = False
            return None
        except Exception as e:
            logger.warning("Chargement modèle embeddings échoué: %s", e)
            self._available = False
            return None

    def _encode_sync(self, texts: list[str]) -> Optional[np.ndarray]:
        """Encode les textes de manière synchrone (appelé dans le thread pool)."""
        model = self._load_model()
        if model is None:
            return None

        # Tronquer les textes trop longs (256 tokens max pour MiniLM ≈ 1000 chars)
        truncated = [t[:2000] for t in texts]

        return model.encode(
            truncated,
            batch_size=EMBEDDING_BATCH_SIZE,
            convert_to_numpy=True,
            normalize_embeddings=True,  # L2 normalisé → cosine = dot product
            show_progress_bar=False,
        )

    async def embed(self, texts: list[str]) -> Optional[list[np.ndarray]]:
        """
        Génère des embeddings pour une liste de textes.

        Exécuté dans un ThreadPool pour ne pas bloquer l'event loop.

        Args:
            texts: Liste de textes à embedder

        Returns:
            Liste de numpy arrays (384 dims), ou None si le modèle est indisponible
        """
        if not texts:
            return []

        if self._available is False:
            return None

        # Vérifier le cache d'abord (thread-safe)
        results: list[Optional[np.ndarray]] = [None] * len(texts)
        uncached_indices: list[int] = []

        with _cache_lock:
            for i, txt in enumerate(texts):
                key = _cache_key(txt)
                cached = _embedding_cache.get(key)
                if cached is not None:
                    results[i] = cached.copy()  # Copie pour éviter les mutations externes
                else:
                    uncached_indices.append(i)

        # Si tout est en cache, retourner directement
        if not uncached_indices:
            return results  # type: ignore

        # Encoder dans le thread pool (ne bloque pas l'event loop)
        uncached_texts = [texts[i] for i in uncached_indices]
        try:
            loop = asyncio.get_running_loop()
            embeddings_array = await loop.run_in_executor(
                _executor, self._encode_sync, uncached_texts
            )
            if embeddings_array is None:
                return None

            # Remplir le cache et les résultats (thread-safe)
            with _cache_lock:
                dim_mismatch = False
                for batch_idx, original_idx in enumerate(uncached_indices):
                    emb = embeddings_array[batch_idx]

                    # Validation des dimensions
                    if len(emb) != EMBEDDING_DIMENSIONS:
                        logger.error(
                            "Embedding dimension mismatch: got %d, expected %d. "
                            "Aborting batch — model may have changed.",
                            len(emb),
                            EMBEDDING_DIMENSIONS,
                        )
                        dim_mismatch = True
                        break

                    results[original_idx] = emb.copy()
                    key = _cache_key(texts[original_idx])
                    _embedding_cache[key] = emb

                if dim_mismatch:
                    self._available = False
                    return None

                # Éviction FIFO (thread-safe sous le même lock)
                if len(_embedding_cache) > _CACHE_MAX_SIZE:
                    keys = list(_embedding_cache.keys())
                    for k in keys[: len(keys) - _CACHE_MAX_SIZE]:
                        del _embedding_cache[k]

            return results  # type: ignore

        except Exception as e:
            logger.warning("Embedding encode error (fallback TF-IDF): %s", e)
            self._available = False
            return None

    async def embed_single(self, text: str) -> Optional[np.ndarray]:
        """Embed un seul texte. Raccourci pour embed([text])."""
        result = await self.embed([text])
        if result is None or not result:
            return None
        return result[0]

    async def health_check(self) -> bool:
        """Vérifie si le service d'embeddings est disponible."""
        result = await self.embed_single("test")
        return result is not None


# Singleton
_embedding_service: Optional[EmbeddingService] = None


def get_embedding_service() -> EmbeddingService:
    """Récupère le singleton EmbeddingService."""
    global _embedding_service
    if _embedding_service is None:
        _embedding_service = EmbeddingService()
    return _embedding_service


def shutdown_embedding_service():
    """Arrête proprement le ThreadPoolExecutor. Appeler au shutdown de l'app."""
    _executor.shutdown(wait=True)
    with _cache_lock:
        _embedding_cache.clear()
    logger.info("Service d'embeddings arrêté")
