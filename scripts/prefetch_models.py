"""Pré-télécharge le modèle d'embeddings dans le volume de données.

Le modèle n'est **PAS** embarqué dans l'image Docker (image allégée). Il vit
sous le volume via ``HF_HOME=/opt/komptia/data/hf_cache``. Ce script le
télécharge **au déploiement** (appelé par ``make first-run`` et ``make reset``,
DANS le conteneur en cours d'exécution → le download atterrit dans le volume et
persiste aux ``make update``/recreate). Conséquences voulues :

  - Le modèle est prêt **avant le premier usage Iris** — pas de latence de
    ~440 Mo subie par le premier utilisateur en plein run.
  - Le volume étant persistant, aucun re-téléchargement aux recreate de conteneur.

Repli gracieux (les embeddings ne bloquent JAMAIS Iris) :
  - Si ce script n'est pas lancé, ou si le serveur est hors-ligne au déploiement,
    ``EmbeddingService`` re-tente le téléchargement à la demande au 1er usage,
    et dégrade en **TF-IDF** tant que ``huggingface.co`` est injoignable.

Le nom du modèle vient de ``app.constants_ai`` (source unique de vérité) — il
n'est jamais dupliqué ici.

Codes de sortie (sémantique « déploiement », pas « build ») :
  - ``sentence-transformers`` absent → skip + exit 0. Cohérent avec
    ``EmbeddingService`` qui désactive simplement les embeddings dans ce cas.
  - ``huggingface.co`` injoignable → warning clair + **exit 0** (repli TF-IDF au
    runtime ; le déploiement ne doit pas échouer pour une feature non bloquante).
  - dimensions du modèle ≠ ``EMBEDDING_DIMENSIONS`` → échec (exit 1) : vraie
    incohérence de config à corriger (fail-fast).

Lançable aussi à la main sur un serveur isolé qui a un accès réseau ponctuel :
``docker compose exec app python -m scripts.prefetch_models``.
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
    try:
        model = SentenceTransformer(EMBEDDING_MODEL)
    except Exception as e:  # noqa: BLE001 — réseau/HF Hub injoignable, disque, etc.
        # Déploiement : ne JAMAIS faire échouer l'installation pour une feature
        # non bloquante. EmbeddingService re-tentera le download au 1er usage et
        # dégrade en TF-IDF en attendant. On signale clairement le repli.
        logger.warning(
            "Téléchargement du modèle d'embeddings impossible (%s : %s). "
            "Iris fonctionnera en repli TF-IDF jusqu'à ce que huggingface.co soit "
            "joignable ; relancer 'docker compose exec app python -m "
            "scripts.prefetch_models' quand le réseau est rétabli.",
            type(e).__name__,
            e,
        )
        return 0

    dims = model.get_sentence_embedding_dimension()
    if dims != EMBEDDING_DIMENSIONS:
        logger.error(
            "Incohérence dimensions : le modèle %s produit %d dims, "
            "mais constants_ai.EMBEDDING_DIMENSIONS=%d. "
            "Aligner EMBEDDING_MODEL/EMBEDDING_DIMENSIONS avant de redéployer.",
            EMBEDDING_MODEL,
            dims,
            EMBEDDING_DIMENSIONS,
        )
        return 1

    logger.info("Modèle pré-téléchargé et vérifié (%d dims) — prêt dans le volume.", dims)
    return 0


if __name__ == "__main__":
    sys.exit(main())
