"""Pré-télécharge les modèles ML embarqués dans l'image Docker.

Exécuté AU BUILD (voir Dockerfile) pour que le modèle d'embeddings soit présent
dans l'image. Conséquences voulues :

  - Iris fonctionne sur un serveur **isolé / sans accès Internet** (cabinet) —
    le modèle n'est plus téléchargé depuis HuggingFace Hub au premier usage.
  - Pas de re-téléchargement de ~440 Mo à chaque recreate de conteneur (le cache
    HF vit dans l'image via HF_HOME, pas dans un cache éphémère du HOME).

Le nom du modèle vient de ``app.constants_ai`` (source unique de vérité) — il
n'est jamais dupliqué ici.

Comportement :
  - ``sentence-transformers`` absent  → skip silencieux (exit 0). Cohérent avec
    ``EmbeddingService`` qui désactive simplement les embeddings dans ce cas.
  - dimensions du modèle ≠ ``EMBEDDING_DIMENSIONS`` → échec (exit 1) pour
    détecter une incohérence AU BUILD plutôt qu'au runtime (fail-fast).
  - erreur réseau (HF injoignable au build) → l'exception remonte et fait
    échouer le build, signal honnête qu'on shipperait une image incomplète.

Lançable aussi en local : ``python -m scripts.prefetch_models``.
"""

import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("prefetch_models")


def main() -> int:
    # Imports tardifs : garder l'import du module léger (test/collecte pytest).
    from app.constants_ai import EMBEDDING_DIMENSIONS, EMBEDDING_MODEL

    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        logger.warning(
            "sentence-transformers absent — pré-téléchargement ignoré "
            "(les embeddings seront désactivés au runtime)."
        )
        return 0

    logger.info("Pré-téléchargement du modèle d'embeddings : %s …", EMBEDDING_MODEL)
    model = SentenceTransformer(EMBEDDING_MODEL)

    dims = model.get_sentence_embedding_dimension()
    if dims != EMBEDDING_DIMENSIONS:
        logger.error(
            "Incohérence dimensions : le modèle %s produit %d dims, "
            "mais constants_ai.EMBEDDING_DIMENSIONS=%d. "
            "Aligner EMBEDDING_MODEL/EMBEDDING_DIMENSIONS avant de builder.",
            EMBEDDING_MODEL,
            dims,
            EMBEDDING_DIMENSIONS,
        )
        return 1

    logger.info("Modèle pré-téléchargé et vérifié (%d dims) — image offline-ready.", dims)
    return 0


if __name__ == "__main__":
    sys.exit(main())
