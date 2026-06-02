"""
Training Store pour Komptia — RAG (Retrieval Augmented Generation).

Inspiré directement de Vanna.ai:
- Stocke DDL, documentation métier et paires question-SQL
- Recherche par similarité (TF-IDF simple, sans dépendance vectorielle)
- Construit des prompts enrichis avec le contexte pertinent

Ce module est le cœur de la précision NL→SQL.
Plus il y a de données d'entraînement, plus les requêtes sont précises.
"""

import re
import json
import logging
import math
from typing import List, Dict, Any, Optional
from collections import Counter

import numpy as np
from sqlalchemy import delete, select, func, text, update

from app.core import clock
from app.models.training_data import TrainingData, TrainingDataType
from app.core.database import get_session
from app.services.ai.sql_validator import check_sql_dangerous
from app.services.data_access.enforcer import should_filter_for
from app.utils.redaction import redact_pii_best_effort
from app.constants_ai import (
    RAG_SCORE_THRESHOLD,
    RAG_QUESTION_SQL_THRESHOLD,
    RAG_DEFAULT_N_RESULTS,
    RAG_MAX_CONTEXT_ITEMS,
    RAG_MIN_EXAMPLES,
    VECTOR_SEARCH_TOP_K,
    EMBEDDING_DIMENSIONS,
    estimate_token_count,
)

logger = logging.getLogger(__name__)


# Cache des paramètres RAG admin (60s TTL). Évite un hit BDD à chaque call
# RAG, tout en restant frais après un save admin (qui invalide le cache du
# config_service global, qui se reload au TTL suivant).
_RAG_CONFIG_CACHE_TTL = 60.0
_rag_config_cache: dict = {}
_rag_config_cache_loaded_at: float = 0.0


def _safe_cast(value: Any, kind: type, fallback: Any, *, bounds: Optional[tuple] = None) -> Any:
    """Cast best-effort + bornes optionnelles. Retourne ``fallback`` si :

    - ``value is None`` (clé absente côté BDD)
    - cast échoue (TypeError/ValueError)
    - la valeur cast est hors bornes (si ``bounds`` fourni)

    Sémantique boolean : accepte les strings sqlite "true"/"false"/"1"/"0"/etc.
    """
    if value is None:
        return fallback
    try:
        if kind is bool:
            if isinstance(value, bool):
                casted: Any = value
            elif isinstance(value, str):
                casted = value.strip().lower() in ("true", "1", "yes", "on")
            else:
                casted = bool(value)
        else:
            casted = kind(value)
    except (TypeError, ValueError):
        return fallback
    if bounds is not None:
        lo, hi = bounds
        if lo is not None and casted < lo:
            return fallback
        if hi is not None and casted > hi:
            return fallback
    return casted


async def _get_rag_runtime_config() -> dict:
    """Source unique de vérité (SSoT) pour TOUS les paramètres RAG d'Iris.

    Lit depuis ``/admin/ai-config`` (BDD) avec fallback sur les constantes
    static si la BDD est indisponible. Cache 60s.

    Doctrine : aucun caller runtime ne doit lire les constantes
    ``constants_ai`` directement — tout passe par ce helper. Tests d'invariant
    dans ``tests/unit/test_no_hardcoded_rag.py`` empêchent la régression.

    Returns:
        dict avec les clés :
        - ``n_results``      : nb max d'exemples Q/SQL (alias rag_example_count)
        - ``min_score``      : seuil score paires Q/SQL (alias confidence_threshold)
        - ``ddl_count``      : nb max DDL servis
        - ``doc_count``      : nb max docs métier servies — fusionné UI 2026-05-27 :
          dérivé de ``n_results`` (un seul slider pilote les deux dans
          ``/admin/ai-config``). La clé BDD ``rag_doc_count`` reste seedée
          mais n'est plus lue runtime (zombie key).
        - ``ddl_doc_min_score``: seuil min scores DDL/docs
        - ``min_examples``   : filet sécurité few-shot
        - ``max_scan``       : cap RAM scoring paires Q/SQL
        - ``reusable_score`` : seuil réutilisation SQL antérieur
    """
    import time as _t

    global _rag_config_cache, _rag_config_cache_loaded_at

    if _rag_config_cache and (_t.time() - _rag_config_cache_loaded_at) < _RAG_CONFIG_CACHE_TTL:
        return _rag_config_cache
    try:
        from app.services.ai.config_service import get_ai_config_service

        cs = get_ai_config_service()
        # Lecture parallèle pour minimiser la latence.
        # ``rag_doc_count`` n'est PLUS lue : dérivée de ``n_results`` (fusion
        # UI 2026-05-27). La clé reste seedée en BDD pour compat migrations
        # mais aucune lecture runtime — modifier sa valeur n'a aucun effet.
        n_raw = await cs.get("rag_example_count")
        th_raw = await cs.get("confidence_threshold")
        ddl_count_raw = await cs.get("rag_ddl_count")
        ddl_doc_min_raw = await cs.get("rag_ddl_doc_min_score")
        min_ex_raw = await cs.get("rag_min_examples")
        max_scan_raw = await cs.get("rag_max_scan")
        reusable_raw = await cs.get("rag_reusable_score")

        _n_results = _safe_cast(n_raw, int, RAG_DEFAULT_N_RESULTS, bounds=(1, 100))
        _rag_config_cache = {
            "n_results": _n_results,
            "min_score": _safe_cast(th_raw, float, RAG_QUESTION_SQL_THRESHOLD, bounds=(0.0, 1.0)),
            "ddl_count": _safe_cast(ddl_count_raw, int, RAG_DEFAULT_N_RESULTS, bounds=(0, 50)),
            # FUSION 2026-05-27 : doc_count = n_results (même slider UI).
            "doc_count": _n_results,
            "ddl_doc_min_score": _safe_cast(
                ddl_doc_min_raw, float, RAG_SCORE_THRESHOLD, bounds=(0.0, 1.0)
            ),
            "min_examples": _safe_cast(min_ex_raw, int, RAG_MIN_EXAMPLES, bounds=(0, 100)),
            "max_scan": _safe_cast(
                max_scan_raw, int, _RAG_QUESTION_SQL_MAX_SCAN_FALLBACK, bounds=(100, 100000)
            ),
            "reusable_score": _safe_cast(
                reusable_raw, float, _REUSABLE_SCORE_FALLBACK, bounds=(0.0, 1.0)
            ),
        }
        _rag_config_cache_loaded_at = _t.time()
    except Exception as exc:  # noqa: BLE001 — fail-soft, garde les defaults static
        logger.debug("RAG runtime config load failed (using statics): %s", exc)
        _rag_config_cache = {
            "n_results": RAG_DEFAULT_N_RESULTS,
            "min_score": RAG_QUESTION_SQL_THRESHOLD,
            "ddl_count": RAG_DEFAULT_N_RESULTS,
            "doc_count": RAG_DEFAULT_N_RESULTS,
            "ddl_doc_min_score": RAG_SCORE_THRESHOLD,
            "min_examples": RAG_MIN_EXAMPLES,
            "max_scan": _RAG_QUESTION_SQL_MAX_SCAN_FALLBACK,
            "reusable_score": _REUSABLE_SCORE_FALLBACK,
        }
        _rag_config_cache_loaded_at = _t.time()
    return _rag_config_cache


def invalidate_rag_runtime_cache() -> None:
    """Appelé par le handler de save config admin pour forcer un reload."""
    global _rag_config_cache, _rag_config_cache_loaded_at
    _rag_config_cache = {}
    _rag_config_cache_loaded_at = 0.0


# Alias public pour usage cross-module (agent_service, deja_vu_prefetch,
# etc.). La fonction privée ``_get_rag_runtime_config`` reste pour la
# rétro-compat interne ; les nouveaux callers utilisent ``get_rag_runtime_config``.
# Single source of truth : /admin/ai-config -> table ai_config en BDD.
# Cf. doctrine ``feedback_no_double_cap`` (mémoire) — un seul cap admin,
# pas de hard-cap applicatif caché en aval.
get_rag_runtime_config = _get_rag_runtime_config


# Taille max pour la documentation (10 Mo — pas de limite pratique)
_MAX_DOC_SIZE = 10_000_000
# Les modèles mappent ces champs sur des VARCHAR — on vérifie la longueur
# nous-mêmes car SQLite ignore silencieusement la borne, ce qui cause une
# data loss à la migration vers PostgreSQL / SQL Server.
_MAX_CATEGORY_LEN = 100  # TrainingData.category : String(100)
_MAX_TABLE_NAME_LEN = 100  # TrainingData.table_name : String(100)
_MAX_TAGS_LEN = 500  # TrainingData.tags : String(500)

# ── Business Context (contexte métier injecté par tables, pas par keywords) ──
# Catégorie exacte stockée dans TrainingData.category.
# Le matching se fait en STRICT equality (pas LIKE) pour éviter collisions
# avec d'éventuelles catégories préfixées du type "business_context:xxx".
BUSINESS_CONTEXT_CATEGORY = "business_context"

# Fallback de dernier recours (utilisé uniquement quand la BDD AIConfig est
# inaccessible — au boot avant ``ensure_seed_configs`` ou panne SQLite).
# La SSoT runtime est ``AIConfigKey.RAG_MAX_SCAN`` lu via
# ``_get_rag_runtime_config()["max_scan"]``. Renommé en ``_FALLBACK`` pour
# rendre l'intention claire dans les call sites.
#
# Bug 2026-05-26 (Agent 4 brainstorm AT-C3 critique) : cap dur sur le
# nombre de paires Q/SQL chargées en RAM pour le scoring RAG. Avant,
# la table ENTIÈRE était chargée à chaque appel ``get_similar_question_sql``.
# À 50K paires (objectif « 10/10 queries »), RAM linéaire avec le store.
# Cap à 5000 : recall-IDF est statistiquement stable au-delà ; on garde
# les paires les plus récentes (ORDER BY created_at DESC) — les plus
# représentatives des conventions actuelles.
_RAG_QUESTION_SQL_MAX_SCAN_FALLBACK: int = 5000

# Fallback de dernier recours pour le score min de réutilisation d'un SQL
# antérieur. SSoT runtime = ``AIConfigKey.RAG_REUSABLE_SCORE`` lu via
# ``_get_rag_runtime_config()["reusable_score"]``. Au-dessus de 0.95 ET
# schéma intact, l'agent peut réutiliser le SQL antérieur tel quel.
_REUSABLE_SCORE_FALLBACK: float = 0.95

# Bug 2026-05-26 (Agent 4 brainstorm AT-C1 critique) : sources de training
# considérées « user-driven » (le contenu vient d'un texte libre tapé par un
# utilisateur final, pas d'un admin qui curate ni du sync programmatique).
# Pour ces sources, on applique ``redact_pii_best_effort`` (masque emails +
# longs blocs numériques, SANS troncature → on préserve le matching RAG) au
# moment de l'écriture pour éviter le leak PII vers :
#   1. La BDD locale en cleartext (SQLCipher couvre l'at-rest mais pas la
#      RAM ni les exports CSV).
#   2. Le RAG indexé en vec_question_sql / recall-IDF, qui sera réexposé à
#      d'AUTRES utilisateurs via le contexte LLM.
#   3. La surface admin (/admin/ai-training) qui liste les paires Q/SQL
#      à TOUS les admins (l'auteur d'origine n'est pas forcément l'admin
#      qui consulte).
# Les sources ``manual`` et ``sync`` sont exemptées : l'admin sait ce qu'il
# écrit, le sync ne traite que du schéma.
_USER_DRIVEN_TRAINING_SOURCES: frozenset[str] = frozenset(
    {"feedback", "feedback_adjust", "feedback_positive", "auto_learn"}
)

# Préfixe de source pour les docs générées automatiquement par view_miner.
# Permet de les distinguer des docs saisies manuellement (source="manual" par défaut)
# et de les désactiver proprement lors d'un re-sync.
VIEW_MINING_SOURCE_PREFIX = "view_mining:"

# Sources identifiant les vues générées automatiquement (exclues du RAG DDL
# seulement si des tables existent — sinon fallback). Les vues synchronisées
# depuis Sage (auto_sync_view) sont INCLUSES car elles contiennent souvent
# les jointures pré-faites dont le LLM a besoin.
_VIEW_SOURCES = {"database_view"}

# Regex pour splitter le camelCase AVANT tokenisation TF-IDF.
# Sans ça, "dopNoEnregColExpertComptableSignataire" est UN token de 42 chars
# et ne matche jamais la requête "expert comptable".
# Avec : dop, No, Enreg, Col, Expert, Comptable, Signataire → matchable.
_CAMEL_SPLIT_RE = re.compile(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


class SimpleTextSearch:
    """
    Recherche par similarité textuelle simple (TF-IDF cosine).

    Alternative légère à ChromaDB/FAISS de Vanna.ai.
    Suffisant pour un corpus de quelques centaines d'entrées.
    Pas de dépendance externe.
    """

    # Mots vides français pour meilleure pertinence
    STOP_WORDS = {
        "le",
        "la",
        "les",
        "de",
        "du",
        "des",
        "un",
        "une",
        "et",
        "ou",
        "en",
        "à",
        "au",
        "aux",
        "par",
        "pour",
        "sur",
        "dans",
        "avec",
        "qui",
        "que",
        "est",
        "sont",
        "a",
        "ont",
        "ce",
        "cette",
        "ces",
        "je",
        "tu",
        "il",
        "nous",
        "vous",
        "ils",
        "se",
        "ne",
        "pas",
        "mon",
        "ton",
        "son",
        "ma",
        "ta",
        "sa",
        "mes",
        "tes",
        "ses",
        "tout",
        "tous",
        "toutes",
        "mais",
        "donc",
        "car",
        "ni",
        "si",
        "plus",
        "moins",
        "très",
        "bien",
        "aussi",
        "encore",
        "the",
        "a",
        "an",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "of",
        "in",
        "to",
        "for",
        "with",
        "on",
        "at",
        "by",
        "from",
        "all",
        "me",
        "my",
        "liste",
        "lister",
        "afficher",
        "montrer",
        "donner",
        "quels",
        "quelles",
        "quel",
        "quelle",
        "combien",
    }

    @staticmethod
    def tokenize(text: str) -> List[str]:
        """Tokenise et nettoie le texte.

        Split le camelCase avant tokenisation pour que les noms Sage Coala
        (dopNoEnregColExpertComptableSignataire) deviennent cherchables
        par mots individuels (expert, comptable, signataire).
        """
        # Split camelCase AVANT lowercasing (a besoin des majuscules)
        text = _CAMEL_SPLIT_RE.sub(" ", text)
        text = text.lower()
        # Garder les mots et nombres
        tokens = re.findall(r"[a-zàâäéèêëïîôùûüÿç0-9_]+", text)
        return [t for t in tokens if t not in SimpleTextSearch.STOP_WORDS and len(t) > 1]

    @staticmethod
    def compute_tfidf(query_tokens: List[str], documents: List[List[str]]) -> List[float]:
        """
        Calcule la similarité TF-IDF cosine entre la query et chaque document.

        Utilisé pour du retrieval documentaire classique (DDL, documentation)
        où on cherche LE document qui ressemble le plus à la query. La
        normalisation par la norme du doc pénalise la verbosité — ce qui est
        correct quand tous les documents sont de nature similaire.
        """
        if not documents:
            return []

        n_docs = len(documents)

        # IDF pour chaque terme
        df = Counter()
        for doc in documents:
            for term in set(doc):
                df[term] += 1

        idf = {}
        for term, count in df.items():
            idf[term] = math.log((n_docs + 1) / (count + 1)) + 1

        # TF-IDF du query
        query_tf = Counter(query_tokens)
        query_tfidf = {}
        for term, count in query_tf.items():
            query_tfidf[term] = count * idf.get(term, 1.0)

        # Cosine similarity avec chaque document
        scores = []
        query_norm = math.sqrt(sum(v**2 for v in query_tfidf.values())) or 1.0

        for doc in documents:
            doc_tf = Counter(doc)
            doc_tfidf = {}
            for term, count in doc_tf.items():
                doc_tfidf[term] = count * idf.get(term, 1.0)

            doc_norm = math.sqrt(sum(v**2 for v in doc_tfidf.values())) or 1.0

            # Dot product
            dot = sum(
                query_tfidf.get(term, 0) * doc_tfidf.get(term, 0)
                for term in set(list(query_tfidf.keys()) + list(doc_tfidf.keys()))
            )

            score = dot / (query_norm * doc_norm) if (query_norm * doc_norm) > 0 else 0
            scores.append(score)

        return scores

    @staticmethod
    def compute_query_recall_idf(
        query_tokens: List[str], documents: List[List[str]]
    ) -> List[float]:
        """Score de RAPPEL pondéré par IDF, dans [0, 1].

        Répond à la question : « quelle proportion des mots discriminants
        de la query est présente dans ce document ? ». C'est la bonne
        métrique pour du **few-shot retrieval** (on cherche l'EXEMPLE le
        plus applicable à notre besoin), au contraire du TF-IDF cosine qui
        est adapté au retrieval documentaire classique.

        Propriétés qui corrigent la pathologie du cosine sur ce cas :

        - Insensible à la verbosité du document : un doc qui contient des
          tokens rares en plus de ce que la query demande ne voit PAS son
          score chuter (le dénominateur ne dépend que de la query).
        - Pondération naturelle par rareté : un token query fréquent dans
          le corpus pèse peu, un token rare pèse beaucoup. Pas de liste de
          stopwords à maintenir pour les tokens discriminants — l'IDF s'en
          charge.
        - Échelle intuitive : 1.0 = toute la query est couverte (quasi-
          identique), 0.0 = aucun mot discriminant partagé.

        Un token de la query absent du corpus reçoit l'IDF maximum
        théorique : il compte dans le total à couvrir, et une paire qui
        ne le contient pas sera pénalisée. C'est cohérent — un token
        inconnu est par définition très discriminant.
        """
        if not documents:
            return []
        query_terms = set(t for t in query_tokens if t)
        if not query_terms:
            return [0.0] * len(documents)

        n_docs = len(documents)

        # DF (document frequency) sur le corpus actuel
        df = Counter()
        for doc in documents:
            for term in set(doc):
                df[term] += 1

        # Smoothed IDF, aligné sur la formule de compute_tfidf pour la
        # cohérence entre les deux métriques.
        def _idf(term: str) -> float:
            return math.log((n_docs + 1) / (df.get(term, 0) + 1)) + 1.0

        # Poids de chaque terme de la query (tokens uniques).
        query_weights = {t: _idf(t) for t in query_terms}
        total_weight = sum(query_weights.values()) or 1.0

        scores: List[float] = []
        for doc in documents:
            doc_terms = set(doc)
            covered = sum(w for term, w in query_weights.items() if term in doc_terms)
            scores.append(covered / total_weight)
        return scores


_ALLOWED_VEC_TABLES = frozenset({"vec_ddl", "vec_documentation", "vec_question_sql"})


def _validate_vec_table(vec_table: str) -> str:
    """Valide le nom de table vectorielle contre l'allowlist (prévient injection SQL)."""
    if vec_table not in _ALLOWED_VEC_TABLES:
        raise ValueError(f"Table vectorielle invalide: {vec_table}")
    return vec_table


class VectorSearch:
    """
    Recherche par similarité vectorielle via sqlite-vec.

    Utilise les embeddings pré-calculés stockés dans les tables virtuelles vec0.
    Fallback sur TF-IDF si sqlite-vec n'est pas disponible.
    """

    _vec_available: Optional[bool] = None

    @classmethod
    async def is_available(cls) -> bool:
        """Vérifie si sqlite-vec est chargé dans la BDD."""
        if cls._vec_available is not None:
            return cls._vec_available
        try:
            async with get_session() as session:
                await session.execute(text("SELECT vec_version()"))
                cls._vec_available = True
        except Exception:
            cls._vec_available = False
        return cls._vec_available

    @staticmethod
    async def search_similar(
        vec_table: str,
        query_embedding: np.ndarray,
        top_k: int = VECTOR_SEARCH_TOP_K,
    ) -> List[Dict[str, Any]]:
        """
        Recherche KNN dans une table vectorielle sqlite-vec.

        Args:
            vec_table: Nom de la table vec0 (vec_ddl, vec_documentation, vec_question_sql)
            query_embedding: Embedding de la requête (numpy array)
            top_k: Nombre max de résultats

        Returns:
            Liste de {"id": int, "distance": float, "score": float}
            score = 1 / (1 + distance) → entre 0 et 1, 1 = identique
        """
        table = _validate_vec_table(vec_table)

        # Validation des dimensions avant requête
        if len(query_embedding) != EMBEDDING_DIMENSIONS:
            logger.warning(
                "search_similar: dimension mismatch (%d vs %d attendu)",
                len(query_embedding),
                EMBEDDING_DIMENSIONS,
            )
            return []

        embedding_json = json.dumps(query_embedding.tolist())

        async with get_session() as session:
            result = await session.execute(
                text(
                    f"SELECT id, distance FROM {table} "
                    f"WHERE embedding MATCH :query "
                    f"ORDER BY distance LIMIT :k"
                ),
                {"query": embedding_json, "k": top_k},
            )
            rows = result.fetchall()

        return [
            {
                "id": row[0],
                "distance": row[1],
                "score": 1.0 / (1.0 + row[1]),  # Distance L2 → score similarité
            }
            for row in rows
        ]

    @staticmethod
    async def upsert_embedding(
        vec_table: str,
        record_id: int,
        embedding: np.ndarray,
    ) -> bool:
        """
        Insère ou met à jour un embedding dans une table vec0.

        Atomique : DELETE + INSERT dans la même transaction.
        Rollback complet si l'INSERT échoue.

        Args:
            vec_table: Table vectorielle cible
            record_id: ID du training_data associé
            embedding: Vecteur numpy

        Returns:
            True si succès
        """
        table = _validate_vec_table(vec_table)

        # Validation des dimensions avant stockage
        if len(embedding) != EMBEDDING_DIMENSIONS:
            logger.warning(
                "upsert_embedding: dimension mismatch (%d vs %d attendu) pour id=%d",
                len(embedding),
                EMBEDDING_DIMENSIONS,
                record_id,
            )
            return False

        embedding_json = json.dumps(embedding.tolist())

        async with get_session() as session:
            try:
                # sqlite-vec: DELETE + INSERT pour upsert (pas de ON CONFLICT sur virtual tables)
                # Les deux opérations sont dans la même session/transaction
                await session.execute(
                    text(f"DELETE FROM {table} WHERE id = :id"),
                    {"id": record_id},
                )
                await session.execute(
                    text(f"INSERT INTO {table}(id, embedding) VALUES (:id, :emb)"),
                    {"id": record_id, "emb": embedding_json},
                )
                await session.commit()
            except Exception as e:
                await session.rollback()
                logger.warning("Upsert embedding failed for id=%d: %s", record_id, e)
                return False
        return True

    @staticmethod
    async def delete_embedding(vec_table: str, record_id: int):
        """Supprime un embedding d'une table vec0."""
        table = _validate_vec_table(vec_table)
        try:
            async with get_session() as session:
                await session.execute(
                    text(f"DELETE FROM {table} WHERE id = :id"),
                    {"id": record_id},
                )
                await session.commit()
        except Exception as e:
            logger.debug("delete_embedding failed for id=%d: %s", record_id, e)


class TrainingStore:
    """
    Store de données d'entraînement pour le RAG.

    API inspirée de Vanna.ai VannaBase:
    - add_ddl(ddl) / get_related_ddl(question)
    - add_documentation(doc) / get_related_documentation(question)
    - add_question_sql(q, sql) / get_similar_question_sql(question)

    Recherche hybride : embeddings vectoriels (primaire) + TF-IDF (fallback).
    """

    def __init__(self, max_context_items: int = RAG_MAX_CONTEXT_ITEMS):
        """
        Args:
            max_context_items: Nombre max d'éléments à retourner par type
        """
        self.max_context_items = max_context_items
        self.search = SimpleTextSearch()
        self.vector_search = VectorSearch()
        self._embedding_service = None  # Lazy init

    async def _get_embedding_service(self):
        """Lazy init du service d'embeddings."""
        if self._embedding_service is None:
            from app.services.ai.embedding_service import get_embedding_service

            self._embedding_service = get_embedding_service()
        return self._embedding_service

    async def _embed_and_store(self, record_id: int, text_content: str, vec_table: str) -> bool:
        """
        Calcule l'embedding d'un texte et le stocke dans sqlite-vec.

        Appel non-bloquant : si l'API embedding est down, log et continue.
        """
        if not await VectorSearch.is_available():
            return False

        try:
            svc = await self._get_embedding_service()
            embedding = await svc.embed_single(text_content)
            if embedding is not None:
                await VectorSearch.upsert_embedding(vec_table, record_id, embedding)
                return True
        except Exception as e:
            logger.debug("Embedding storage failed for id=%d: %s", record_id, e)
        return False

    # ==========================================
    # API d'ajout (style Vanna.ai train())
    # ==========================================

    async def add_ddl(
        self,
        ddl: str,
        table_name: Optional[str] = None,
        source: str = "manual",
        user_id: Optional[int] = None,
    ) -> int:
        """
        Ajoute un DDL (CREATE TABLE) aux données d'entraînement.

        Args:
            ddl: Le DDL SQL (CREATE TABLE ...)
            table_name: Nom de la table (auto-détecté si None)
            source: Source (manual, auto_sync)
            user_id: ID de l'utilisateur qui ajoute

        Returns:
            ID du training data créé
        """
        if table_name is None:
            # Auto-détecter le nom de table depuis le DDL
            match = re.search(r"CREATE\s+TABLE\s+(?:\w+\.)?(\w+)", ddl, re.IGNORECASE)
            table_name = match.group(1) if match else None

        async with get_session() as session:
            # Vérifier si un DDL existe déjà pour cette table
            if table_name:
                existing = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type == TrainingDataType.DDL,
                        TrainingData.table_name == table_name,
                        TrainingData.is_active == True,  # noqa: E712
                    )
                )
                existing_record = existing.scalar_one_or_none()

                if existing_record:
                    # Mettre à jour le DDL existant
                    existing_record.content = ddl
                    existing_record.updated_at = clock.now()
                    existing_record.source = source
                    record_id = existing_record.id
                    await session.commit()
                    logger.info("DDL mis à jour pour %s", table_name)
                    # Mettre à jour l'embedding
                    await self._embed_and_store(record_id, f"{table_name} {ddl}", "vec_ddl")
                    return record_id

            record = TrainingData(
                data_type=TrainingDataType.DDL,
                content=ddl,
                table_name=table_name,
                source=source,
                created_by=user_id,
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)

            logger.info("DDL ajouté: %s (id=%s)", table_name, record.id)
            # Stocker l'embedding
            await self._embed_and_store(record.id, f"{table_name} {ddl}", "vec_ddl")
            return record.id

    async def add_view(
        self,
        definition: str,
        view_name: Optional[str] = None,
        source: str = "auto_sync_view",
        user_id: Optional[int] = None,
        depends_on: Optional[List[str]] = None,
    ) -> int:
        """Ajoute une vue SQL aux données d'entraînement.

        Phase 1.4 (#16) — pendant que add_function/add_synonym ont été
        ajoutés en Phase 1.2/1.3, add_view manquait. Pour homogénéiser
        les types et préparer le closure transitif (Phase 2.1), on
        l'ajoute ici. Aujourd'hui le sync stocke les vues via add_ddl
        (legacy) — la migration vers add_view se fait en Phase 1.6 (#43)
        avec le sync incrémentiel.

        Args:
            definition: ``CREATE VIEW ...`` complet.
            view_name: Nom de la vue (auto-détecté si None).
            source: Marqueur de source.
            user_id: ID utilisateur (audit).
            depends_on: Liste des tables/vues référencées par cette vue.
                ``None`` = sera peuplé par Phase 1.5 (#17) via parsing
                sqlglot.

        Returns:
            ID du training data créé/mis à jour.
        """
        if view_name is None:
            match = re.search(
                r"CREATE\s+VIEW\s+(?:\[?\w+\]?\.)?\[?([\w]+)\]?",
                definition,
                re.IGNORECASE,
            )
            view_name = match.group(1) if match else None

        async with get_session() as session:
            if view_name:
                existing = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type == TrainingDataType.VIEW,
                        TrainingData.table_name == view_name,
                        TrainingData.is_active == True,  # noqa: E712
                    )
                )
                existing_record = existing.scalar_one_or_none()

                if existing_record:
                    existing_record.content = definition
                    existing_record.updated_at = clock.now()
                    existing_record.source = source
                    if depends_on is not None:
                        existing_record.depends_on = list(depends_on)
                    record_id = existing_record.id
                    await session.commit()
                    logger.info("Vue mise à jour: %s (id=%s)", view_name, record_id)
                    await self._embed_and_store(record_id, f"{view_name} {definition}", "vec_ddl")
                    return record_id

            record = TrainingData(
                data_type=TrainingDataType.VIEW,
                content=definition,
                table_name=view_name,
                source=source,
                created_by=user_id,
                depends_on=list(depends_on) if depends_on else None,
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)
            logger.info("Vue ajoutée: %s (id=%s)", view_name, record.id)
            await self._embed_and_store(record.id, f"{view_name} {definition}", "vec_ddl")
            return record.id

    async def add_function(
        self,
        definition: str,
        function_name: Optional[str] = None,
        source: str = "auto_sync_function",
        user_id: Optional[int] = None,
        depends_on: Optional[List[str]] = None,
    ) -> int:
        """Ajoute une fonction SQL (TVF / scalaire) aux données d'entraînement.

        Phase 1.2 (#14) — pour le closure transitif du mode invisible :
        catalog les fonctions définies dans SQL Server pour qu'on puisse
        ensuite (Phase 1.5 + 2.1) résoudre leurs dépendances vers les
        tables atomiques et bloquer les fonctions qui dépendent de tables
        interdites.

        Args:
            definition: La définition complète (``CREATE FUNCTION ...``).
            function_name: Nom de la fonction (auto-détecté si None).
                Format ``schema.name`` ou ``name`` accepté.
            source: Marqueur de source (par défaut ``auto_sync_function``).
            user_id: ID de l'utilisateur qui ajoute (pour audit).
            depends_on: Phase 1.4 (#16) — liste de noms d'objets BDD
                référencés par la fonction. Stocké dans la colonne
                dédiée pour le closure transitif. ``None`` (défaut) à
                ce stade : la Phase 1.5 (#17) parsera la définition avec
                sqlglot pour peupler automatiquement.

        Returns:
            ID du training data créé (ou mis à jour si déjà présent).

        Si une fonction du même nom existe déjà comme ``data_type=FUNCTION``,
        elle est mise à jour (upsert). Aligné sur le comportement de
        :meth:`add_ddl`.
        """
        if function_name is None:
            # Auto-détecter le nom depuis ``CREATE FUNCTION schema.name(...)``.
            # SQL Server : "CREATE FUNCTION [dbo].[fn_name](...)" ou
            # "CREATE FUNCTION dbo.fn_name(...)". Le regex prend le dernier
            # segment après le point optionnel et strippe les crochets.
            match = re.search(
                r"CREATE\s+FUNCTION\s+(?:\[?\w+\]?\.)?\[?([\w]+)\]?",
                definition,
                re.IGNORECASE,
            )
            function_name = match.group(1) if match else None

        async with get_session() as session:
            # Upsert : si la fonction existe déjà (même name + type=FUNCTION),
            # mettre à jour. Sinon, créer.
            if function_name:
                existing = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type == TrainingDataType.FUNCTION,
                        TrainingData.table_name == function_name,
                        TrainingData.is_active == True,  # noqa: E712
                    )
                )
                existing_record = existing.scalar_one_or_none()

                if existing_record:
                    existing_record.content = definition
                    existing_record.updated_at = clock.now()
                    existing_record.source = source
                    # Phase 1.4 (#16) — mettre à jour depends_on si fourni.
                    # ``None`` explicite préserve l'existant (le caller n'a
                    # pas recalculé).
                    if depends_on is not None:
                        existing_record.depends_on = list(depends_on)
                    record_id = existing_record.id
                    await session.commit()
                    logger.info("Fonction mise à jour: %s (id=%s)", function_name, record_id)
                    # L'embedding réutilise le vec_ddl (même usage : code SQL
                    # indexé pour la recherche). Pas de table vec séparée
                    # nécessaire en V1.
                    await self._embed_and_store(
                        record_id, f"{function_name} {definition}", "vec_ddl"
                    )
                    return record_id

            record = TrainingData(
                data_type=TrainingDataType.FUNCTION,
                content=definition,
                table_name=function_name,
                source=source,
                created_by=user_id,
                depends_on=list(depends_on) if depends_on else None,
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)

            logger.info("Fonction ajoutée: %s (id=%s)", function_name, record.id)
            await self._embed_and_store(record.id, f"{function_name} {definition}", "vec_ddl")
            return record.id

    async def add_synonym(
        self,
        synonym_name: str,
        target: str,
        source: str = "auto_sync_synonym",
        user_id: Optional[int] = None,
    ) -> int:
        """Ajoute un synonyme SQL Server aux données d'entraînement.

        Phase 1.3 (#15) — pour le closure transitif : un synonyme est un
        alias qui redirige vers une autre table/vue/fonction. Si le
        synonyme cible est une table interdite, le synonyme lui-même
        doit être interdit (Phase 2.1 le calcule via ``depends_on``).

        Args:
            synonym_name: Nom complet du synonyme (``schema.name``).
            target: Cible du synonyme (``base_object_name`` SQL Server).
            source: Marqueur de source (par défaut ``auto_sync_synonym``).
            user_id: ID de l'utilisateur qui ajoute (audit).

        Returns:
            ID du training data créé ou mis à jour.

        La cible est stockée immédiatement dans ``extra_metadata`` :
        ``{"target": "<base_object_name>"}``. Pas de parsing nécessaire —
        sys.synonyms expose la cible directement. Pour #16, cette cible
        sera promue vers la colonne ``depends_on`` dédiée.
        """
        if not synonym_name:
            raise ValueError("add_synonym: synonym_name vide.")

        # Le content est un pseudo-DDL pour cohérence avec les autres
        # types. Permet à un parser éventuel de relire et confirmer la
        # cible (defense-in-depth).
        content = f"CREATE SYNONYM {synonym_name} FOR {target};"

        async with get_session() as session:
            existing = await session.execute(
                select(TrainingData).where(
                    TrainingData.data_type == TrainingDataType.SYNONYM,
                    TrainingData.table_name == synonym_name,
                    TrainingData.is_active == True,  # noqa: E712
                )
            )
            existing_record = existing.scalar_one_or_none()

            if existing_record:
                existing_record.content = content
                existing_record.updated_at = clock.now()
                existing_record.source = source
                # Mettre à jour la cible dans extra_metadata (rétro-compat
                # lecture) ET dans depends_on (source de vérité Phase 1.4).
                meta = dict(existing_record.extra_metadata or {})
                meta["target"] = target
                existing_record.extra_metadata = meta
                existing_record.depends_on = [target]  # Phase 1.4 (#16)
                record_id = existing_record.id
                await session.commit()
                logger.info(
                    "Synonyme mis à jour: %s → %s (id=%s)",
                    synonym_name,
                    target,
                    record_id,
                )
                await self._embed_and_store(record_id, f"{synonym_name} {target}", "vec_ddl")
                return record_id

            record = TrainingData(
                data_type=TrainingDataType.SYNONYM,
                content=content,
                table_name=synonym_name,
                source=source,
                created_by=user_id,
                extra_metadata={"target": target},  # rétro-compat lecture
                depends_on=[target],  # Phase 1.4 (#16) — source de vérité
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)

            logger.info(
                "Synonyme ajouté: %s → %s (id=%s)",
                synonym_name,
                target,
                record.id,
            )
            await self._embed_and_store(record.id, f"{synonym_name} {target}", "vec_ddl")
            return record.id

    async def add_documentation(
        self,
        doc: str,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        source: str = "manual",
        user_id: Optional[int] = None,
    ) -> int:
        """
        Ajoute de la documentation métier (avec déduplication par catégorie+contenu).

        Si une documentation existe déjà avec la même catégorie et le même contenu,
        met à jour l'enregistrement existant au lieu de créer un doublon.

        Args:
            doc: Texte de documentation métier
            category: Catégorie (ex: "comptabilité", "clients")
            tags: Tags pour filtrage
            source: Source
            user_id: Utilisateur

        Returns:
            ID créé ou existant

        Raises:
            ValueError: Si le contenu est vide ou trop volumineux
        """
        if not doc or not doc.strip():
            raise ValueError("La documentation ne peut pas être vide")
        if len(doc) > _MAX_DOC_SIZE:
            raise ValueError(
                f"Documentation trop volumineuse ({len(doc)} chars, max {_MAX_DOC_SIZE})"
            )

        # Bug 2026-05-26 (Agent 4 brainstorm AT-C1) : même politique que
        # add_question_sql pour les flux user-driven. La documentation
        # ajoutée par le sync programmatique ou un admin ne passe pas par
        # cette branche. Voir ``_USER_DRIVEN_TRAINING_SOURCES``.
        if source in _USER_DRIVEN_TRAINING_SOURCES:
            doc = redact_pii_best_effort(doc, truncate=False) or doc

        async with get_session() as session:
            # Déduplication : chercher un document existant avec même catégorie et contenu
            if category:
                existing = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.category == category,
                        TrainingData.content == doc,
                        TrainingData.is_active.is_(True),
                    )
                )
                existing_record = existing.scalar_one_or_none()
                if existing_record:
                    # Mettre à jour les tags et source si fournis
                    if tags:
                        existing_record.tags = ",".join(tags)
                    existing_record.source = source
                    record_id = existing_record.id
                    await session.commit()
                    logger.info(
                        "Documentation existante mise à jour: %s (id=%s)", category, record_id
                    )
                    await self._embed_and_store(
                        record_id, f"{category or ''} {doc}", "vec_documentation"
                    )
                    return record_id

            record = TrainingData(
                data_type=TrainingDataType.DOCUMENTATION,
                content=doc,
                category=category,
                tags=",".join(tags) if tags else None,
                source=source,
                created_by=user_id,
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)

            logger.info("Documentation ajoutée: %s (id=%s)", category, record.id)
            await self._embed_and_store(record.id, f"{category or ''} {doc}", "vec_documentation")
            return record.id

    async def _validate_training_sql(
        self,
        sql: str,
        *,
        validate_on_sage: bool,
        rls_source: str = "training_sql_dryrun",
    ) -> None:
        """Valide un SQL avant stockage/activation dans le RAG (SSoT).

        Partagé par add_question_sql, update_question_sql et
        approve_training_data : un SQL dangereux ou qui ne tourne pas ne doit
        JAMAIS entrer dans le RAG actif (empoisonnement = SQL faux pour TOUS
        les users).

        1. ``check_sql_dangerous`` → ``ValueError`` si opération interdite
           (write/DDL). Toujours exécuté (gratuit, sans réseau).
        2. Si ``validate_on_sage`` : dry-run TOP 1 sur le serveur actif →
           ``SQLValidationError`` si le serveur refuse. À appeler HORS d'une
           session SQLite ouverte (le dry-run peut durer jusqu'au timeout →
           anti "database is locked").

        Raises:
            ValueError: SQL contient une opération interdite.
            SQLValidationError: le dry-run sur le serveur actif échoue.
        """
        found_dangerous = check_sql_dangerous(sql)
        if found_dangerous:
            raise ValueError(
                f"SQL rejeté : contient des opérations interdites ({', '.join(found_dangerous)}). "
                f"Seules les requêtes SELECT sont autorisées comme données d'entraînement."
            )
        if not validate_on_sage:
            return
        # Imports tardifs : évite cycle (query_executor → data_access →
        # training_store) et garde le path silencieux pour les tests mockés.
        from app.core.exceptions import (
            SQLValidationError as _SQLValidationError,
            QueryError as _QueryError,
            SageConnectionError as _SageConnectionError,
            ValidationError as _ValidationError,
        )
        from app.services.database.query_executor import get_query_executor

        try:
            # add_limit=True → wrap TOP N : force parse + plan sans ramener un
            # gros résultat. timeout=15 : cap dur (slow plan, lock wait).
            executor = get_query_executor()
            await executor.execute(
                sql,
                max_rows=1,
                add_limit=True,
                timeout=15,
                rls_source=rls_source,
            )
        except _SageConnectionError:
            # Serveur source INJOIGNABLE (réseau / circuit-breaker), PAS un SQL
            # invalide : on laisse propager tel quel → le handler renvoie 503
            # (≠ 422 "SQL refusé"). Sinon l'admin croit que SA requête est fausse
            # alors que c'est un problème d'infra (cas c de la taxonomie 4-cas).
            raise
        except (_QueryError, _ValidationError) as exc:
            raise _SQLValidationError(
                f"Le SQL ne s'exécute pas sur le serveur actif : "
                f"{exc}. Vérifie la syntaxe/la version compat du "
                f"serveur cible (cf. /admin/database)."
            ) from exc
        except Exception as exc:  # noqa: BLE001
            raise _SQLValidationError(
                f"Validation du SQL impossible sur le serveur actif : "
                f"{type(exc).__name__}: {exc}."
            ) from exc

    async def add_question_sql(
        self,
        question: str,
        sql: str,
        tags: Optional[List[str]] = None,
        quality_score: float = 1.0,
        source: str = "manual",
        user_id: Optional[int] = None,
        pending_review: bool = False,
        validate_on_sage: Optional[bool] = None,
    ) -> int:
        """
        Ajoute une paire question-SQL validée (avec déduplication).

        C'est le type de training le plus important pour la précision.
        Valide le SQL contre les keywords dangereux avant stockage.
        Si une paire identique (même question) existe, met à jour le SQL.

        Bug n°4 fix (2026-05-26) — Validation à l'insertion : si
        ``validate_on_sage`` est True (auto-True quand
        ``source='manual'``), exécute un dry-run du SQL sur le serveur
        actif AVANT l'insertion. Une paire ``manual`` qui ne tourne pas
        sur le serveur cible est refusée — c'est exactement le scénario
        de la paire 8741 (STRING_AGG WITHIN GROUP rejeté par SQL Server
        2014) qui s'est retrouvée ``is_active=1`` sans n'avoir jamais
        tourné, puis a déclenché un faux positif déjà-vu le matin du
        2026-05-26 (cf. mémoire ``project_iris_audit_apex_sessions``).

        Args:
            question: Question en langage naturel
            sql: SQL validé correspondant
            tags: Tags
            quality_score: Score qualité (1.0 = parfait)
            source: Source (manual, feedback)
            user_id: Utilisateur
            pending_review: Si True, marqué en attente de validation admin
            validate_on_sage: Si True, dry-run le SQL sur le serveur
                actif avant insertion. ``None`` (défaut) → auto-True
                quand ``source='manual'``, False sinon. False = skip
                (le caller a déjà exécuté le SQL, ex: feedback ✅ Iris).

        Returns:
            ID créé ou existant

        Raises:
            ValueError: Si le SQL contient des opérations dangereuses
            SQLValidationError: Si le dry-run sur Sage échoue (le serveur
                cible refuse la syntaxe ou la sémantique). Le message
                contient l'erreur exacte du serveur pour debug user/admin.
        """
        # Résout le défaut : dry-run quand source='manual' (paire tapée à la
        # main, pas garantie d'avoir tourné) ; skip quand source='feedback'
        # (le SQL a déjà tourné dans Iris pour produire le résultat ✅).
        if validate_on_sage is None:
            validate_on_sage = source == "manual"
        # Validation SSoT (check_sql_dangerous + dry-run optionnel), partagée
        # avec update_question_sql / approve_training_data / auto-rewrite.
        await self._validate_training_sql(
            sql, validate_on_sage=validate_on_sage, rls_source="add_question_sql_dryrun"
        )

        # Borner le quality_score
        quality_score = max(0.0, min(1.0, quality_score))

        # Bug 2026-05-26 (Agent 4 brainstorm AT-C1) : masque la PII triviale
        # dans la question NL avant indexation RAG quand la source est un flux
        # automatique (feedback user). Sources ``manual``/``sync`` exemptées :
        # ce sont des contenus déjà vérifiés par l'admin. ``truncate=False``
        # préserve la longueur pour ne pas casser le matching recall-IDF.
        # ⚠️ Plug COMPLÉMENTAIRE de la pseudonymisation user-scoped runtime
        # (proxy.pseudonymize_for_llm) — pas un remplacement.
        #
        # Bug 2026-05-26 (ADV-4 — adversarial review) : avant ce fix, SEUL
        # ``question`` était redacté. Le ``sql`` (notamment ``corrected_sql``
        # du feedback) pouvait contenir des littéraux PII (ex: ``WHERE
        # email='alice@x.fr'``) → leak via RAG few-shot vers d'autres users.
        # Maintenant : SQL également redacté en cohérence avec la doctrine
        # « Q + SQL » de AT-C1.
        if source in _USER_DRIVEN_TRAINING_SOURCES:
            question = redact_pii_best_effort(question, truncate=False) or question
            sql = redact_pii_best_effort(sql, truncate=False) or sql

        async with get_session() as session:
            # Déduplication : chercher une paire existante avec la même question
            existing = await session.execute(
                select(TrainingData).where(
                    TrainingData.data_type == TrainingDataType.QUESTION_SQL,
                    TrainingData.question == question,
                    TrainingData.is_active.is_(True),
                )
            )
            existing_record = existing.scalar_one_or_none()
            if existing_record:
                record_id = existing_record.id
                # CRITIQUE 2026-05-31 (review adversariale du snapshot 20b8902) :
                # le CONTENU (sql/content/quality_score) ne doit PAS être écrasé
                # par un incoming NON approuvé (typiquement un non-admin,
                # ``pending_review=True``) quand une version APPROUVÉE existe déjà
                # (``pending_review=False``, ex: SQL validé par un admin). Sinon un
                # non-admin re-validant la même question empoisonne la paire servie
                # à TOUS via le RAG global (``get_similar_question_sql`` ne filtre
                # que ``pending_review==False``, sans ``created_by``). Le fix
                # monotone du seul FLAG (2026-05-30) ne suffisait pas : le ``sql``
                # était écrasé quand même. On préserve donc la version approuvée
                # (no-op contenu). Isolation axe 18. Un admin
                # (``pending_review=False``) reste libre de mettre à jour une paire
                # approuvée ; une paire en attente (``pending_review=True``) reste
                # écrasable (dernier write gagne).
                if not existing_record.pending_review and bool(pending_review):
                    logger.debug(
                        "Paire Q/SQL approuvée préservée (id=%s) : écrasement par "
                        "incoming non-approuvé ignoré : %s...",
                        record_id,
                        question[:50],
                    )
                    return record_id

                existing_record.sql = sql
                existing_record.content = f"Question: {question}\nSQL: {sql}"
                existing_record.quality_score = quality_score
                existing_record.source = source
                # Approbation MONOTONE (« collante ») : une paire déjà approuvée
                # (pending_review=False) ne peut PAS être renvoyée en attente par
                # un simple ré-upsert — ex: un non-admin re-👍 une question qu'un
                # admin a déjà validée ne doit pas la retirer du RAG global. Seul
                # le endpoint reject explicite dé-approuve. Isolation axe 18
                # (review adversariale 2026-05-30). L'approbation (incoming
                # pending=False) reste possible : si l'un des deux est approuvé,
                # le résultat l'est.
                existing_record.pending_review = bool(pending_review) and bool(
                    existing_record.pending_review
                )
                await session.commit()
                # debug-only (Bug 2026-05-26 AT-M5) : ce log est hot-path du
                # store RAG (1 ligne par paire write), il alimentait ``llm_log.md``
                # sans rotation (43k lignes au 2026-04-30). L'admin a déjà
                # l'historique des paires dans /admin/ai-training.
                logger.debug("Paire Q/SQL mise à jour (id=%s): %s...", record_id, question[:50])
                await self._embed_and_store(record_id, f"{question} {sql}", "vec_question_sql")
                return record_id

            record = TrainingData(
                data_type=TrainingDataType.QUESTION_SQL,
                content=f"Question: {question}\nSQL: {sql}",
                question=question,
                sql=sql,
                tags=",".join(tags) if tags else None,
                quality_score=quality_score,
                source=source,
                created_by=user_id,
                pending_review=pending_review,
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)

            # debug-only (Bug 2026-05-26 AT-M5) : ce log est hot-path RAG —
            # une paire = un log INFO sans rotation = bruit. Démoter en debug,
            # garder l'audit via /admin/ai-training (qui liste les paires).
            logger.debug("Paire Q/SQL ajoutée (id=%s): %s...", record.id, question[:50])
            await self._embed_and_store(record.id, f"{question} {sql}", "vec_question_sql")
            return record.id

    async def add_correction_rule(
        self,
        question_pattern: str,
        bad_sql: str,
        good_sql: str,
        error_type: str,
        explanation: str = "",
        user_id: Optional[int] = None,
        pending_review: bool = False,
    ) -> Optional[int]:
        """
        Stocke une règle de correction (pattern MAGIC).

        Quand une erreur est corrigée, on stocke le pattern pour éviter
        de reproduire la même erreur.

        Args:
            question_pattern: Question ou pattern qui déclenche cette règle
            bad_sql: Le SQL qui a échoué
            good_sql: Le SQL corrigé
            error_type: Catégorie d'erreur (de la taxonomie)
            explanation: Explication de la correction
            user_id: Auteur du feedback (NULL si inconnu).
            pending_review: True (typiquement non-admin) → la règle attend une
                validation admin et n'est PAS servie au RAG global (cohérence
                modération avec ``add_question_sql`` ; ``get_related_documentation``
                ne sert que ``pending_review=False``). Défaut False (admin/système).

        Returns:
            ID du training data créé, ou None en cas d'erreur
        """
        # Valider bad_sql contre les patterns dangereux
        found_dangerous = check_sql_dangerous(bad_sql)
        if found_dangerous:
            logger.warning(
                "bad_sql refusé dans add_correction_rule : "
                "contient des opérations interdites (%s)",
                ", ".join(found_dangerous),
            )
            return None

        content = (
            f"Erreur: {error_type}\n"
            f"SQL incorrect:\n{bad_sql}\n\n"
            f"SQL corrigé:\n{good_sql}\n\n"
            f"Explication: {explanation}"
        )

        try:
            record = TrainingData(
                data_type=TrainingDataType.DOCUMENTATION,
                content=content,
                question=question_pattern,
                category=f"correction:{error_type}",
                tags=f"magic,correction,{error_type}",
                source="correction_rule",
                created_by=user_id,
                pending_review=pending_review,
            )

            async with get_session() as session:
                session.add(record)
                await session.commit()
                await session.refresh(record)

                logger.info(
                    "Règle de correction ajoutée (id=%s): %s / %s...",
                    record.id,
                    error_type,
                    question_pattern[:50],
                )
                await self._embed_and_store(
                    record.id,
                    f"{error_type} {question_pattern} {bad_sql} {good_sql}",
                    "vec_documentation",
                )
                return record.id
        except Exception as e:
            logger.warning("Erreur ajout correction rule: %s", e)
            return None

    # ==========================================
    # API de recherche (RAG retrieval)
    # ==========================================

    async def _try_vector_search(
        self, question: str, vec_table: str, top_k: int
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Tente une recherche vectorielle. Retourne None si indisponible (fallback TF-IDF).
        """
        if not await VectorSearch.is_available():
            return None

        try:
            svc = await self._get_embedding_service()
            query_embedding = await svc.embed_single(question)
            if query_embedding is None:
                return None
            return await VectorSearch.search_similar(vec_table, query_embedding, top_k)
        except Exception as e:
            logger.debug("Vector search failed, falling back to TF-IDF: %s", e)
            return None

    async def get_related_ddl(
        self,
        question: str,
        n_results: Optional[int] = None,
        *,
        user: Any = None,
    ) -> List[Dict[str, Any]]:
        """
        Récupère les DDL les plus pertinents pour une question.

        Stratégie hybride : embeddings vectoriels (primaire) → TF-IDF (fallback).

        Args:
            question: Question en langage naturel
            n_results: Nombre max de résultats. Si ``None`` (recommandé),
                lit ``AIConfigKey.RAG_DDL_COUNT`` depuis l'admin BDD
                (SSoT). Passer une valeur explicite pour override ponctuel
                (ex: outils admin qui veulent forcer un large fetch).
            user: optionnel — si fourni ET que cet utilisateur a au moins
                une règle ``DataAccessRule`` active, les DDL des tables
                interdites sont exclus du résultat (mode invisible —
                Phase α.1). Le filtrage se fait APRÈS le scoring pour
                que les n_results renvoyés soient les top-N parmi les
                tables visibles, pas top-N puis filtré (sinon le top-N
                pourrait se retrouver vide si toutes les tables top
                sont interdites). ``user=None`` (défaut) = comportement
                legacy, aucune restriction.

        Returns:
            Liste de DDL triés par pertinence (filtrée par user si fourni).
        """
        _rag_cfg = await _get_rag_runtime_config()
        if n_results is None:
            n_results = _rag_cfg["ddl_count"]
        _min_score = _rag_cfg["ddl_doc_min_score"]
        async with get_session() as session:
            # Priorité aux DDL de tables (moins bruités que les définitions de vues)
            result = await session.execute(
                select(TrainingData).where(
                    TrainingData.data_type == TrainingDataType.DDL,
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.source.notin_(_VIEW_SOURCES),
                )
            )
            all_ddl = result.scalars().all()

            # Fallback: si aucun DDL table n'existe, inclure les vues
            # mais les marquer pour que agent_knowledge ajoute l'avertissement alias.
            # Phase 1.6 (#43) : vues stockées maintenant comme data_type=VIEW —
            # on les inclut en fallback ici (pré-#43, elles étaient en DDL
            # avec source='auto_sync_view' ; post-#43 migration backfill,
            # elles sont en VIEW).
            if not all_ddl:
                fallback_result = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type.in_((TrainingDataType.DDL, TrainingDataType.VIEW)),
                        TrainingData.is_active == True,  # noqa: E712
                    )
                )
                all_ddl = fallback_result.scalars().all()
                logger.warning("Aucun DDL table trouvé, fallback sur DDL incluant les vues")

        if not all_ddl:
            return []

        # Index par ID pour lookup rapide
        ddl_by_id = {d.id: d for d in all_ddl}

        # Éviter le bruit des tables techniques (Temp/Params/Sys) pour les questions métier
        technical_keywords = {
            "param",
            "parametre",
            "paramètres",
            "numerotation",
            "numérotation",
            "temp",
            "temporaire",
            "config",
            "configuration",
            "system",
            "système",
        }
        query_tokens = set(self.search.tokenize(question))
        allow_technical_tables = any(token in technical_keywords for token in query_tokens)

        # ── Tentative recherche vectorielle ──
        vec_results = await self._try_vector_search(question, "vec_ddl", n_results * 2)

        use_vector = vec_results is not None and len(vec_results) > 0
        if use_vector:
            # Utiliser les résultats vectoriels
            scored_ddl: List[tuple] = []
            for vr in vec_results:
                ddl = ddl_by_id.get(vr["id"])
                if ddl is None:
                    continue

                table_name = (ddl.table_name or "").upper()

                # Filtrer tables techniques
                if not allow_technical_tables and re.match(
                    r"^(TEMP|TMP|PARAMS?|SYS|ZZ|Z_)", table_name
                ):
                    continue

                # Bonus/penalty comme avant
                bonus = 0.0
                if re.match(r"^(TEMP|TMP|PARAMS?|SYS|ZZ|Z_)", table_name):
                    bonus -= 0.20
                table_tokens = set(self.search.tokenize(table_name))
                overlap = len(table_tokens.intersection(query_tokens))
                if overlap > 0:
                    bonus += 0.08 * overlap

                scored_ddl.append((ddl, vr["score"] + bonus))

            scored_ddl.sort(key=lambda x: x[1], reverse=True)
            logger.debug("Vector search DDL: %d results", len(scored_ddl))

        # Fallback TF-IDF : si vec indisponible (None), retourne vide ([]), ou filtré à 0
        if not use_vector or len(scored_ddl) == 0:
            # ── Fallback TF-IDF ──
            filtered_ddl = all_ddl
            if not allow_technical_tables:
                filtered_ddl = [
                    ddl
                    for ddl in all_ddl
                    if not re.match(
                        r"^(TEMP|TMP|PARAMS?|SYS|ZZ|Z_)", (ddl.table_name or "").upper()
                    )
                ]
            if filtered_ddl:
                all_ddl = filtered_ddl

            query_tokens_list = list(query_tokens)
            doc_tokens = [
                self.search.tokenize(f"{d.content} {d.table_name or ''} {d.tags or ''}")
                for d in all_ddl
            ]
            scores = self.search.compute_tfidf(query_tokens_list, doc_tokens)

            scored_ddl = []
            for ddl, score in zip(all_ddl, scores):
                table_name = (ddl.table_name or "").upper()
                bonus = 0.0
                if re.match(r"^(TEMP|TMP|PARAMS?|SYS|ZZ|Z_)", table_name):
                    bonus -= 0.20
                table_tokens = set(self.search.tokenize(table_name))
                overlap = len(table_tokens.intersection(query_tokens))
                if overlap > 0:
                    bonus += 0.08 * overlap
                scored_ddl.append((ddl, score + bonus))

            scored_ddl.sort(key=lambda x: x[1], reverse=True)

        # Phase α.1 — Mode invisible : retirer les DDL des tables non
        # visibles AVANT le slice top-N. Sinon, si les 5 meilleures tables
        # sont toutes interdites, on ne retournerait rien.
        # FAIL-CLOSED : sur erreur du filtrage, on retourne [] plutôt que
        # tout — le risque de leak via prompt LLM est plus grave que la
        # perte de qualité de réponse pour cet user (cf. review Phase α.1
        # finding CRITICAL #4).
        ddl_rewriter = None
        view_for_filter = None
        if await should_filter_for(user):
            try:
                from app.services.data_access.llm_context import (
                    rewrite_ddl_for_view,
                )
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view_for_filter = await build_user_schema_view(user)
                if view_for_filter.has_restrictions:
                    before = len(scored_ddl)
                    scored_ddl = [
                        (ddl, score)
                        for (ddl, score) in scored_ddl
                        if (ddl.table_name or "").upper() in view_for_filter.visible_tables
                    ]
                    if before != len(scored_ddl):
                        logger.debug(
                            "RAG DDL: %d/%d entrées filtrées (mode invisible)",
                            before - len(scored_ddl),
                            before,
                        )
                    ddl_rewriter = rewrite_ddl_for_view
            except Exception as exc:
                # FAIL-CLOSED : retourner liste vide plutôt que le DDL brut.
                # Le LLM n'a pas accès au schéma pour cette requête → la
                # qualité de réponse se dégrade mais le mode invisible
                # reste tenu (cf. finding CRITICAL #4 de la review α.1).
                logger.error(
                    "RAG DDL: filtrage mode invisible échoué (fail-closed, "
                    "[] retourné — qualité réponse dégradée): %s",
                    exc,
                    exc_info=True,
                )
                return []

        # Filtrer et retourner. Seuil min SSoT admin (``rag_ddl_doc_min_score``).
        results = []
        result_ids = []
        for ddl, score in scored_ddl[:n_results]:
            if score > _min_score:
                content = ddl.content
                # Phase α.1 fix BLOCKING #1 — Réécriture du DDL pour retirer
                # les FK référençant des tables interdites + les colonnes
                # interdites du corps. Sans ça, F_ECRITURE peut leaker
                # "REFERENCES F_SALAIRES(id)" alors que F_SALAIRES est denied.
                if ddl_rewriter is not None and view_for_filter is not None:
                    rewritten = ddl_rewriter(content or "", view_for_filter, ddl.table_name)
                    if not rewritten:
                        # rewriter a fail-closed (table devenue invisible
                        # ou parse failed) → skip cette entrée.
                        continue
                    content = rewritten
                results.append(
                    {
                        "id": ddl.id,
                        "content": content,
                        "table_name": ddl.table_name,
                        "score": score,
                    }
                )
                result_ids.append(ddl.id)

        # Incrémenter usage_count en batch (une seule session au lieu de N)
        if result_ids:
            async with get_session() as session:
                await session.execute(
                    update(TrainingData)
                    .where(TrainingData.id.in_(result_ids))
                    .values(usage_count=TrainingData.usage_count + 1)
                )
                await session.commit()

        return results

    async def get_related_documentation(
        self, question: str, n_results: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Récupère la documentation métier pertinente.

        Stratégie hybride : embeddings vectoriels (primaire) → TF-IDF (fallback).

        Args:
            question: Question en langage naturel
            n_results: Nombre max de résultats. Si ``None`` (recommandé),
                lit ``AIConfigKey.RAG_DOC_COUNT`` depuis l'admin BDD (SSoT).

        Returns:
            Liste de docs triées par pertinence
        """
        _rag_cfg = await _get_rag_runtime_config()
        if n_results is None:
            n_results = _rag_cfg["doc_count"]
        _min_score = _rag_cfg["ddl_doc_min_score"]

        async with get_session() as session:
            result = await session.execute(
                select(TrainingData).where(
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.is_active == True,  # noqa: E712
                    # Modération RAG (2026-05-31, review snapshot 20b8902) : ne
                    # servir que les docs APPROUVÉES. Une règle de correction
                    # issue d'un feedback NON-admin est ``pending_review=True``
                    # → exclue du RAG global tant qu'un admin ne l'a pas validée
                    # (cohérent avec le read Q/SQL get_similar_question_sql). Les
                    # docs admin/sync (pending_review=False par défaut, colonne
                    # non-nullable) restent servies.
                    TrainingData.pending_review == False,  # noqa: E712
                )
            )
            all_docs = result.scalars().all()

        if not all_docs:
            return []

        doc_by_id = {d.id: d for d in all_docs}

        # ── Tentative recherche vectorielle ──
        vec_results = await self._try_vector_search(question, "vec_documentation", n_results * 2)

        scored = []
        if vec_results is not None and len(vec_results) > 0:
            scored = [
                (doc_by_id[vr["id"]], vr["score"]) for vr in vec_results if vr["id"] in doc_by_id
            ]
            scored.sort(key=lambda x: x[1], reverse=True)
            logger.debug("Vector search docs: %d results", len(scored))

        # Fallback TF-IDF si vec indisponible ou vide
        if not scored:
            query_tokens = self.search.tokenize(question)
            doc_tokens = [
                self.search.tokenize(f"{d.content} {d.category or ''} {d.tags or ''}")
                for d in all_docs
            ]
            scores = self.search.compute_tfidf(query_tokens, doc_tokens)
            scored = sorted(zip(all_docs, scores), key=lambda x: x[1], reverse=True)

        results = []
        for doc, score in scored[:n_results]:
            if score > _min_score:
                results.append(
                    {
                        "id": doc.id,
                        "content": doc.content,
                        "category": doc.category,
                        "score": score,
                    }
                )

        return results

    async def get_all_table_names(self, *, user: Any = None) -> List[str]:
        """
        Récupère la liste de TOUTES les tables disponibles.
        Utilisé pour que l'IA sache quelles tables existent.

        Args:
            user: optionnel — si fourni ET que cet user a au moins une
                règle ``DataAccessRule`` active, les tables interdites
                sont retirées du résultat (mode invisible — Phase α.1).
                ``user=None`` (défaut) = comportement legacy.

        Returns:
            Liste des noms de tables (sans DDL complets), filtrée si user
            avec restrictions.
        """
        async with get_session() as session:
            # Phase 1.6 (#43) : inclure VIEW pour que les vues syncées soient
            # listées comme "tables connues" exposées à Iris (sinon Iris ne
            # saurait pas qu'elles existent).
            result = await session.execute(
                select(TrainingData.table_name)
                .where(
                    TrainingData.data_type.in_((TrainingDataType.DDL, TrainingDataType.VIEW)),
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.table_name.isnot(None),
                )
                .distinct()
            )
            table_names = [row[0] for row in result.fetchall()]

        all_sorted = sorted(table_names)

        # Phase α.1 — Filtre mode invisible
        if not await should_filter_for(user):
            return all_sorted
        try:
            from app.services.data_access.visible_schema import (
                build_user_schema_view,
            )

            view = await build_user_schema_view(user)
            if not view.has_restrictions:
                return all_sorted
            return [t for t in all_sorted if t and t.upper() in view.visible_tables]
        except Exception as exc:
            logger.warning(
                "training_store.get_all_table_names: filtrage mode invisible "
                "échoué (fail-open, enforcer SQL bloque la suite): %s",
                exc,
            )
            return all_sorted

    async def get_documented_table_names(self, *, user: Any = None) -> set[str]:
        """
        Retourne les noms des tables qui ont une documentation sémantique (table_role).
        Utilisé pour distinguer les tables enrichies des tables brutes dans le catalogue.

        Args:
            user: optionnel — si fourni avec restrictions, retire les tables
                interdites (mode invisible Phase α.1). ``user=None`` =
                comportement legacy.
        """
        async with get_session() as session:
            result = await session.execute(
                select(func.substr(TrainingData.category, len("table_role:") + 1)).where(
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.category.like("table_role:%"),
                )
            )
            documented = {row[0] for row in result.fetchall()}

        # Phase α.1 — Filtre mode invisible
        if not await should_filter_for(user):
            return documented
        try:
            from app.services.data_access.visible_schema import (
                build_user_schema_view,
            )

            view = await build_user_schema_view(user)
            if not view.has_restrictions:
                return documented
            return {t for t in documented if t and t.upper() in view.visible_tables}
        except Exception as exc:
            logger.warning(
                "training_store.get_documented_table_names: filtrage mode "
                "invisible échoué (fail-open): %s",
                exc,
            )
            return documented

    async def deactivate_by_table(self, table_name: str) -> int:
        """
        Désactive tous les training data (DDL, knowledge, etc.) liés à une table.

        Utilisé lors du schema sync pour nettoyer les tables qui n'existent
        plus dans la base source.

        Args:
            table_name: Nom de la table à désactiver

        Returns:
            Nombre d'enregistrements désactivés
        """
        async with get_session() as session:
            result = await session.execute(
                select(TrainingData).where(
                    TrainingData.table_name == table_name,
                    TrainingData.is_active == True,  # noqa: E712
                )
            )
            records = result.scalars().all()
            count = 0
            for record in records:
                record.is_active = False
                record.updated_at = clock.now()
                count += 1
            if count:
                await session.commit()
                logger.info("Désactivé %s enregistrements pour table %s", count, table_name)
            return count

    async def deactivate_by_source(self, source: str) -> int:
        """
        Désactive tous les training data provenant d'une source spécifique.
        Utilisé pour nettoyer les anciennes relations inférées avant un nouveau sync.
        """
        async with get_session() as session:
            result = await session.execute(
                select(TrainingData).where(
                    TrainingData.source == source,
                    TrainingData.is_active == True,  # noqa: E712
                )
            )
            records = result.scalars().all()
            count = 0
            for record in records:
                record.is_active = False
                record.updated_at = clock.now()
                count += 1
            if count:
                await session.commit()
                logger.info("Désactivé %d enregistrements source=%s", count, source)
            return count

    async def deactivate_by_category(self, category_prefix: str) -> int:
        """
        Désactive tous les training data dont la catégorie commence par le préfixe donné.
        Utilisé pour nettoyer les anciennes suggestions avant régénération.
        """
        async with get_session() as session:
            result = await session.execute(
                select(TrainingData).where(
                    TrainingData.category.startswith(category_prefix),
                    TrainingData.is_active == True,  # noqa: E712
                )
            )
            records = result.scalars().all()
            count = 0
            for record in records:
                record.is_active = False
                record.updated_at = clock.now()
                count += 1
            if count:
                await session.commit()
                logger.info("Désactivé %d enregistrements catégorie=%s*", count, category_prefix)
            return count

    async def get_welcome_suggestions(self) -> List[Dict[str, str]]:
        """
        Récupère les suggestions d'accueil générées lors du dernier sync.
        Returns: liste de {"prompt": "...", "label": "..."} triée par index.
        """
        async with get_session() as session:
            result = await session.execute(
                select(TrainingData)
                .where(
                    TrainingData.category.startswith("welcome_suggestions:"),
                    TrainingData.is_active == True,  # noqa: E712
                )
                .order_by(TrainingData.category)
            )
            records = result.scalars().all()
            suggestions = []
            for record in records:
                try:
                    data = json.loads(record.content)
                    if "prompt" in data and "label" in data:
                        suggestions.append(data)
                except (json.JSONDecodeError, TypeError):
                    continue
            return suggestions

    async def get_user_table_usage(self, user_id: int) -> Dict[str, int]:
        """
        Agrège les tables utilisées par un utilisateur à travers ses conversations.
        Lit le champ discoveries.tables de chaque conversation.
        Returns: {table_name: nombre_de_conversations} trié par fréquence décroissante.
        """
        from app.models.conversation import Conversation

        usage: Dict[str, int] = {}
        async with get_session() as session:
            result = await session.execute(
                select(Conversation.discoveries).where(
                    Conversation.user_id == user_id,
                    Conversation.discoveries.isnot(None),
                )
            )
            for (discoveries_json,) in result.all():
                try:
                    data = json.loads(discoveries_json)
                    tables = data.get("tables", {})
                    for table_name in tables:
                        usage[table_name] = usage.get(table_name, 0) + 1
                except (json.JSONDecodeError, TypeError):
                    continue
        return dict(sorted(usage.items(), key=lambda x: x[1], reverse=True))

    async def get_table_column_names(self, table_name: str) -> List[str]:
        """
        Extrait les noms de colonnes d'une table depuis son DDL stocké.

        Parse le CREATE TABLE pour en extraire les noms de colonnes.
        Format attendu (généré par schema_sync) :
            CREATE TABLE dbo.TableName (
                ColName type NULL/NOT NULL,
                ...
            );

        Args:
            table_name: Nom de la table

        Returns:
            Liste des noms de colonnes, ou liste vide si pas de DDL
        """
        ddls = await self.get_ddl_by_table_names([table_name], n_results=1)
        if not ddls:
            return []

        ddl_content = ddls[0].get("content", "")
        if not ddl_content:
            return []

        # Pattern identique à agent_tools._extract_columns_from_ddl :
        # colonnes = lignes indentées (2+ espaces) commençant par un identifiant suivi d'un type
        _SQL_KEYWORDS = frozenset(
            {
                "CONSTRAINT",
                "PRIMARY",
                "FOREIGN",
                "KEY",
                "INDEX",
                "UNIQUE",
                "CHECK",
            }
        )
        col_pattern = re.compile(r"^\s{2,}(\w+)\s+\w+", re.MULTILINE)
        columns = []
        for match in col_pattern.finditer(ddl_content):
            col_name = match.group(1)
            if col_name.upper() not in _SQL_KEYWORDS:
                columns.append(col_name)

        return columns

    async def get_ddl_by_table_names(
        self,
        table_names: List[str],
        n_results: int = RAG_DEFAULT_N_RESULTS,
        *,
        user: Any = None,
    ) -> List[Dict[str, Any]]:
        """
        Récupère les DDL correspondant à une liste de tables.

        Args:
            table_names: Noms de tables cibles
            n_results: Nombre max de DDL retournés
            user: optionnel — si fourni avec restrictions, retire les
                DDL des tables interdites pour cet user (mode invisible
                Phase α.1). ``user=None`` (défaut) = comportement legacy.

        Returns:
            Liste de DDL correspondant aux tables demandées (filtrée par
            ``user`` si fourni).
        """
        if not table_names:
            return []

        target_names = [name.upper() for name in table_names if name]
        if not target_names:
            return []

        # Phase α.1 — Pré-filtre la liste cible avant la requête BDD.
        # Cas typique : un caller demande [F_ECRITURE, F_SECRET] pour un
        # user qui ne voit pas F_SECRET → on retire F_SECRET AVANT de
        # construire le SELECT pour ne pas faire un round-trip inutile
        # ET pour ne pas exposer l'existence de F_SECRET dans les logs SQL.
        if await should_filter_for(user):
            try:
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view = await build_user_schema_view(user)
                if view.has_restrictions:
                    target_names = [t for t in target_names if t in view.visible_tables]
                    if not target_names:
                        return []
            except Exception as exc:
                logger.warning(
                    "training_store.get_ddl_by_table_names: filtrage mode "
                    "invisible échoué (fail-open): %s",
                    exc,
                )

        async with get_session() as session:
            # Phase 1.6 (#43) : inclure VIEW pour qu'une demande explicite
            # par nom de vue retourne la définition (et non pas vide).
            result = await session.execute(
                select(TrainingData).where(
                    TrainingData.data_type.in_((TrainingDataType.DDL, TrainingDataType.VIEW)),
                    TrainingData.is_active == True,  # noqa: E712
                    func.upper(TrainingData.table_name).in_(target_names),
                )
            )
            records = result.scalars().all()

        ddls = []
        for record in records[:n_results]:
            ddls.append(
                {
                    "id": record.id,
                    "content": record.content,
                    "table_name": record.table_name,
                    "score": 1.0,
                }
            )

        return ddls

    async def get_similar_question_sql(
        self,
        question: str,
        n_results: Optional[int] = None,
        question_only: bool = False,
        user: Any = None,
    ) -> List[Dict[str, Any]]:
        """
        Récupère les paires question-SQL les plus similaires.

        C'est le few-shot learning de Vanna.ai.
        Stratégie hybride : embeddings vectoriels (primaire) → TF-IDF (fallback).

        Args:
            question: Question en langage naturel
            n_results: Nombre max de résultats
            question_only: Si True, la similarité est calculée uniquement
                sur le champ question (pas le SQL), utile pour le raccourci RAG.
            user: optionnel — si fourni ET que l'enforcement RLS est ON,
                les paires Q/SQL qui référencent une table interdite pour
                cet user sont exclues du résultat (mode invisible — Phase
                5.1). Sans ce filtre, un exemple RAG pourrait fuiter
                ``F_SALAIRES`` dans le prompt LLM même quand le schéma
                principal est filtré. ``user=None`` = comportement legacy
                (pas de filtrage, pour compat tests / call-sites pas encore
                migrés).

        Returns:
            Liste de paires Q/SQL triées par pertinence (filtrée si user fourni).
        """
        # Bug 2026-05-26 (Agent 4 brainstorm AT-C3 critique) : avant le
        # fix, ce SELECT chargeait la TABLE COMPLÈTE en RAM à chaque
        # appel ``get_similar_question_sql``. À 50K paires (objectif
        # « 10/10 queries » Komptia), 50K rows × ~5 colonnes par appel =
        # mémoire qui grimpe linéairement avec le store. Cap dur lu via
        # SSoT admin (``AIConfigKey.RAG_MAX_SCAN``, défaut 5000).
        _rag_cfg = await _get_rag_runtime_config()
        _max_scan = _rag_cfg["max_scan"]
        # BLOCKING fix (adversarial review 2026-05-27) — résoudre
        # ``n_results`` AVANT la recherche vectorielle (``vec_results``
        # utilise ``n_results * 2``). Si on attend la résolution ligne
        # ~2125, ``None * 2`` crash en TypeError. SSoT BDD via cfg.
        if n_results is None:
            n_results = _rag_cfg["n_results"]
        async with get_session() as session:
            result = await session.execute(
                select(TrainingData)
                .where(
                    TrainingData.data_type == TrainingDataType.QUESTION_SQL,
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.pending_review == False,  # noqa: E712
                )
                .order_by(TrainingData.created_at.desc())
                .limit(_max_scan)
            )
            all_pairs = result.scalars().all()

        if not all_pairs:
            return []

        pair_by_id = {p.id: p for p in all_pairs}

        # ── Tentative recherche vectorielle ──
        # Note: les embeddings Q/SQL sont stockés sur question+SQL, donc question_only
        # n'affecte que le fallback TF-IDF. En vectoriel, la sémantique de la question
        # domine naturellement (le SQL est du bruit lexical pour les embeddings).
        vec_results = await self._try_vector_search(question, "vec_question_sql", n_results * 2)

        scored = []
        engine_used = "none"
        if vec_results is not None and len(vec_results) > 0:
            # #84/D1-F15 — la recherche KNN vectorielle porte sur le STORE
            # COMPLET ; ses IDs peuvent être HORS du window récent ``_max_scan``
            # (chargé plus haut UNIQUEMENT pour le cap RAM du fallback TF-IDF).
            # Avant, ``if vr["id"] in pair_by_id`` jetait silencieusement les
            # matches hors-window → au-delà de ``_max_scan`` paires,
            # ``1 - _max_scan/total`` du store devenait INATTEIGNABLE par le
            # vectoriel même pour un match parfait (données fausses : Iris rate
            # le meilleur exemple few-shot existant). On fetch les paires
            # manquantes (bornées à ``n_results*2``, mêmes filtres actif /
            # non-pending que le window) pour rendre tout le store atteignable.
            _missing_ids = [vr["id"] for vr in vec_results if vr["id"] not in pair_by_id]
            if _missing_ids:
                async with get_session() as session:
                    _extra = await session.execute(
                        select(TrainingData).where(
                            TrainingData.id.in_(_missing_ids),
                            TrainingData.data_type == TrainingDataType.QUESTION_SQL,
                            TrainingData.is_active == True,  # noqa: E712
                            TrainingData.pending_review == False,  # noqa: E712
                        )
                    )
                    for _p in _extra.scalars().all():
                        pair_by_id[_p.id] = _p
            scored = [
                (pair_by_id[vr["id"]], vr["score"]) for vr in vec_results if vr["id"] in pair_by_id
            ]
            scored.sort(key=lambda x: x[1], reverse=True)
            engine_used = "vector"
            logger.debug("Vector search Q/SQL: %d results", len(scored))

        # Fallback TF-IDF — scoring adapté au FEW-SHOT retrieval.
        #
        # On utilise ``compute_query_recall_idf`` plutôt que ``compute_tfidf``
        # (cosine). Justification : ici on ne cherche pas « le doc qui
        # ressemble le plus à la query » mais « l'EXEMPLE Q/SQL qui couvre
        # le mieux le besoin exprimé ». Le cosine pénalise les paires
        # verbeuses (plus de règles métier = plus de tokens rares non
        # partagés = norme doc gonflée = score chute). Le rappel pondéré
        # par IDF ne dépend que de la couverture des tokens discriminants
        # de la query — la verbosité d'une paire ne la pénalise plus.
        if not scored:
            query_tokens = self.search.tokenize(question)
            if question_only:
                doc_tokens = [
                    self.search.tokenize(f"{p.question or ''} {p.tags or ''}") for p in all_pairs
                ]
            else:
                doc_tokens = [
                    self.search.tokenize(f"{p.question or ''} {p.sql or ''} {p.tags or ''}")
                    for p in all_pairs
                ]
            scores = self.search.compute_query_recall_idf(query_tokens, doc_tokens)
            scored = sorted(zip(all_pairs, scores), key=lambda x: x[1], reverse=True)
            if scored:
                engine_used = "tfidf"

        # SSoT admin /admin/ai-config (confidence_threshold, rag_min_examples).
        # ``_rag_cfg`` + ``n_results`` déjà résolus en début de méthode pour
        # ``vec_results = n_results * 2``.
        min_score = _rag_cfg["min_score"]
        min_examples = min(_rag_cfg["min_examples"], n_results)

        # ── Filtrage RAG mode invisible (Phase 5.1 + α.1) ──
        # Si l'user a des restrictions actives, on retire les paires dont
        # le SQL référence une table interdite. Le filtrage se fait AVANT
        # la sélection top-N pour ne pas réduire artificiellement le
        # nombre de résultats sous le seuil min_examples (un résultat
        # vide est pire qu'un fallback générique côté LLM).
        # ``should_filter_for`` court-circuite en O(1) si user None /
        # admin / sans règle → 0 surcoût pour les 95% d'utilisateurs.
        # FAIL-CLOSED : sur erreur de filtrage, retour [] (les paires Q/SQL
        # sont injectées dans le prompt LLM comme few-shot examples → un
        # leak ferait apparaître le NOM d'une table interdite dans la
        # réponse texte de l'IA, même si l'enforcer SQL bloquerait
        # ensuite. cf. review α.1 finding CRITICAL #4).
        if await should_filter_for(user):
            try:
                from app.services.data_access.llm_context import (
                    is_sql_safe_for_view,
                )
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view = await build_user_schema_view(user)
                if view.has_restrictions:
                    before = len(scored)
                    scored = [
                        (pair, score)
                        for (pair, score) in scored
                        if is_sql_safe_for_view(pair.sql or "", view)
                    ]
                    if before != len(scored):
                        logger.debug(
                            "RAG Q/SQL: %d/%d paires filtrées (mode invisible)",
                            before - len(scored),
                            before,
                        )
            except Exception as exc:
                # FAIL-CLOSED : retourner liste vide. Le LLM se retrouve
                # sans few-shot examples pour cet user → qualité réponse
                # dégradée mais mode invisible tenu.
                logger.error(
                    "RAG Q/SQL: filtrage mode invisible échoué (fail-closed, "
                    "[] retourné — qualité réponse dégradée): %s",
                    exc,
                    exc_info=True,
                )
                return []

        results = []
        selected_ids = set()

        # 1) D'abord les exemples réellement pertinents
        for pair, score in scored:
            if score > min_score:
                results.append(
                    {
                        "id": pair.id,
                        "question": pair.question,
                        "sql": pair.sql,
                        "quality_score": pair.quality_score,
                        "score": score,
                        # Le caller a besoin du moteur pour comparer le score au bon
                        # seuil : embeddings et TF-IDF ne produisent pas les mêmes
                        # valeurs absolues pour « similaire ».
                        "engine": engine_used,
                    }
                )
                selected_ids.add(pair.id)
            if len(results) >= n_results:
                break

        # 2) Filet de sécurité: garantir un minimum d'exemples few-shot
        if len(results) < min_examples:
            for pair, score in scored:
                if pair.id in selected_ids:
                    continue
                results.append(
                    {
                        "id": pair.id,
                        "question": pair.question,
                        "sql": pair.sql,
                        "quality_score": pair.quality_score,
                        "score": score,
                        "engine": engine_used,
                    }
                )
                selected_ids.add(pair.id)
                if len(results) >= min_examples or len(results) >= n_results:
                    break

        return results

    async def get_phase_hints(
        self,
        question: str,
        *,
        n_results: Optional[int] = None,
        schema_tables: Optional[set] = None,
        question_only: bool = False,
        reusable_threshold: Optional[float] = None,
        user: Any = None,
    ):
        """Récupère des hints structurés par phase à partir des paires Q/SQL similaires.

        Principe « L'apprentissage informe, ne décide pas » (T29★).
        Contrairement à ``get_similar_question_sql`` qui retourne le SQL prêt à
        être affiché, cette méthode décompose les paires en SIGNAUX par phase
        pipeline Iris :

        - **concept_hints** (Phase 1.1+1.2) — tokens discriminants des questions
          similaires.
        - **table_hints** + **column_hints** (Phase 2 rerank) — identifiants
          structurels extraits des SQL (sqlglot + fallback regex). JAMAIS les
          valeurs littérales (anti-fuite confidentialité).
        - **ir_structure_hints** (Phase 4 IR composer) — forme agrégée
          (nb colonnes SELECT, GROUP BY présent, agrégats utilisés…).
        - **reusable_as_is** — flag informatif quand score ≥ ``reusable_threshold``
          ET (optionnellement) toutes les tables référencées présentes dans
          ``schema_tables``. C'est un signal de prompt, JAMAIS un raccourci
          de code.

        Args:
            question: requête NL utilisateur.
            n_results: nb max de paires à considérer.
            schema_tables: si fourni (case-insensitive), filtre le flag
                ``reusable_as_is`` aux tables existantes dans le schéma actuel.
                Si une table référencée par la meilleure paire est absente,
                le flag retombe à False.
            question_only: passé tel quel à ``get_similar_question_sql``.
            reusable_threshold: score minimal pour autoriser le flag
                ``reusable_as_is``.
            user: optionnel — propagé à ``get_similar_question_sql`` pour
                exclure les paires Q/SQL référençant des tables interdites
                pour cet user (mode invisible Phase α.1). ``user=None`` =
                comportement legacy.

        Returns: ``PhaseHints`` (dataclass frozen). Vide si aucune paire.
        """
        from app.services.ai.rag_hints import PhaseHints, compute_phase_hints

        # SSoT admin /admin/ai-config — reusable_threshold et n_results.
        _rag_cfg = await _get_rag_runtime_config()
        if reusable_threshold is None:
            reusable_threshold = _rag_cfg["reusable_score"]
        if n_results is None:
            n_results = _rag_cfg["n_results"]

        try:
            pairs = await self.get_similar_question_sql(
                question,
                n_results=n_results,
                question_only=question_only,
                user=user,
            )
        except Exception as exc:  # noqa: BLE001 — fail-soft, on dégrade en hints vides
            logger.warning("get_phase_hints retrieval failed: %s", exc)
            return PhaseHints()

        return compute_phase_hints(
            pairs,
            schema_tables=schema_tables,
            reusable_threshold=reusable_threshold,
        )

    async def get_correction_rules(
        self,
        question: str,
        error_type: str = "",
        n_results: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Récupère les règles de correction pertinentes pour une question.

        Args:
            question: Question utilisateur actuelle
            error_type: Optionnel, filtrer par type d'erreur
            n_results: Nombre max de résultats

        Returns:
            Liste de dicts avec content, score, category, question
        """
        try:
            # Récupérer les documentations candidates (utilise la recherche existante)
            candidates = await self.get_related_documentation(question, n_results=n_results * 2)

            if not candidates:
                return []

            # Filtrer les résultats pour ne garder que les correction rules
            category_prefix = f"correction:{error_type}" if error_type else "correction:"
            filtered = [
                {
                    "id": c.get("id"),
                    "content": c.get("content"),
                    "category": c.get("category"),
                    "score": c.get("score"),
                }
                for c in candidates
                if c.get("category", "").startswith(category_prefix)
            ]

            return filtered[:n_results]
        except Exception as e:
            logger.warning("Erreur récupération correction rules: %s", e)
            return []

    async def get_related_ddl_with_roles(
        self,
        table_names: List[str],
        n_results: int = 10,
        *,
        user: Any = None,
    ) -> List[Dict[str, Any]]:
        """
        Retourne DDL + rôles sémantiques pour une liste de tables.

        Pour chaque table, récupère :
        - Le DDL (CREATE TABLE)
        - La documentation avec catégorie "table_role:{table}"
        - Les documentations avec catégories "column_role:{table}.*"

        Args:
            table_names: noms de tables cibles.
            n_results: limite supérieure du nombre d'entrées retournées.
            user: optionnel — si fourni avec restrictions, retire les
                tables interdites avant la requête BDD (mode invisible
                Phase α.1). ``user=None`` (défaut) = comportement legacy.

        Returns:
            Liste de dicts: {"table_name": "TABLE_NAME", "ddl": "...",
                             "table_role": "...", "column_roles": {"COL1": "...", ...}}
            Filtrée selon ``user`` si fourni.
        """
        if not table_names:
            return []

        target_names = [name.upper() for name in table_names if name]
        if not target_names:
            return []

        # Phase α.1 — Filtre mode invisible : retirer les tables interdites
        # AVANT les SELECTs BDD pour ne pas révéler leur existence dans les
        # logs SQL. FAIL-CLOSED : sur erreur, retour [] (le contenu sert à
        # construire des prompts LLM, fuite garantie sinon).
        view_for_filter = None
        if await should_filter_for(user):
            try:
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view_for_filter = await build_user_schema_view(user)
                if view_for_filter.has_restrictions:
                    target_names = [t for t in target_names if t in view_for_filter.visible_tables]
                    if not target_names:
                        return []
            except Exception as exc:
                logger.error(
                    "training_store.get_related_ddl_with_roles: filtrage "
                    "mode invisible échoué (fail-closed, [] retourné): %s",
                    exc,
                    exc_info=True,
                )
                return []

        # Import lazy du rewriter (utilisé seulement si view active).
        rewrite_ddl_for_view = None
        if view_for_filter is not None and view_for_filter.has_restrictions:
            from app.services.data_access.llm_context import (
                rewrite_ddl_for_view as _rewriter,
            )

            rewrite_ddl_for_view = _rewriter

        results = []
        async with get_session() as session:
            for tname in target_names[:n_results]:
                # Récupérer le DDL pour cette table
                # Phase 1.6 (#43) : inclure VIEW pour récupérer aussi les
                # rôles des vues.
                ddl_result = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type.in_((TrainingDataType.DDL, TrainingDataType.VIEW)),
                        TrainingData.is_active == True,  # noqa: E712
                        func.upper(TrainingData.table_name) == tname,
                    )
                )
                ddl_record = ddl_result.scalar_one_or_none()

                # Récupérer la documentation table_role
                role_result = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.is_active == True,  # noqa: E712
                        TrainingData.category == f"table_role:{tname}",
                    )
                )
                role_record = role_result.scalar_one_or_none()

                # Récupérer les documentations column_role pour cette table
                esc_tname = tname.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                col_result = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.is_active == True,  # noqa: E712
                        TrainingData.category.like(f"column_role:{esc_tname}.%", escape="\\"),
                    )
                )
                col_records = col_result.scalars().all()

                # Extraire les rôles colonnes
                column_roles = {}
                for cr in col_records:
                    # Catégorie format: "column_role:TABLE.COLUMN"
                    parts = (cr.category or "").split(".", 1)
                    if len(parts) == 2:
                        column_roles[parts[1]] = cr.content

                # Phase α.1 fix CRITICAL #6 — Filtrer column_roles aux
                # colonnes visibles. Sinon SALAIRE_BRUT (denied_column de
                # F_ECRITURE) leak dans le prompt LLM même si F_ECRITURE
                # est techniquement visible.
                ddl_content = ddl_record.content if ddl_record else None
                if view_for_filter is not None and view_for_filter.has_restrictions:
                    # Filtrer column_roles
                    column_roles = {
                        col: role
                        for col, role in column_roles.items()
                        if view_for_filter.can_see_column(tname, col)
                    }
                    # Réécriture DDL pour retirer FK croisées + colonnes interdites
                    if ddl_content and rewrite_ddl_for_view is not None:
                        rewritten = rewrite_ddl_for_view(ddl_content, view_for_filter, tname)
                        # fail-closed à "" si rewrite échoue → on n'expose
                        # pas le DDL brut. On laisse passer l'entry avec
                        # ddl=None pour que le caller sache "doc présente
                        # mais DDL filtré".
                        ddl_content = rewritten or None

                entry = {
                    "table_name": tname,
                    "ddl": ddl_content,
                    "table_role": role_record.content if role_record else None,
                    "column_roles": column_roles,
                }
                results.append(entry)

        return results

    async def detect_knowledge_gaps(
        self, required_tables: List[str], required_columns: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Détecte les lacunes de connaissance dans le training store.

        Vérifie :
        - Quels tables requises ont un DDL stocké
        - Quels tables requises ont une documentation "table_role:"
        - Quels colonnes requises ont une documentation "column_role:"

        Returns:
            {
                "missing_ddl": [...tables sans DDL],
                "missing_table_roles": [...tables sans table_role],
                "missing_column_roles": [...colonnes sans column_role],
                "schema_coverage": float (0-1),
                "has_gaps": bool
            }
            schema_coverage = % de tables requises ayant BOTH DDL et table_role
        """
        if not required_tables:
            return {
                "missing_ddl": [],
                "missing_table_roles": [],
                "missing_column_roles": [],
                "schema_coverage": 0.0,
                "has_gaps": False,
            }

        target_tables = [name.upper() for name in required_tables if name]
        if not target_tables:
            return {
                "missing_ddl": [],
                "missing_table_roles": [],
                "missing_column_roles": [],
                "schema_coverage": 0.0,
                "has_gaps": False,
            }

        async with get_session() as session:
            # Récupérer tous les DDL pour les tables cibles
            ddl_result = await session.execute(
                select(func.upper(TrainingData.table_name))
                .where(
                    TrainingData.data_type == TrainingDataType.DDL,
                    TrainingData.is_active == True,  # noqa: E712
                    func.upper(TrainingData.table_name).in_(target_tables),
                )
                .distinct()
            )
            tables_with_ddl = set(row[0] for row in ddl_result.fetchall())

            # Récupérer les tables avec table_role
            role_result = await session.execute(
                select(func.substr(TrainingData.category, len("table_role:") + 1))
                .where(
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.category.like("table_role:%"),
                )
                .distinct()
            )
            tables_with_role = set(row[0] for row in role_result.fetchall())

            # Récupérer les colonnes avec column_role
            col_result = await session.execute(
                select(TrainingData.category).where(
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.category.like("column_role:%"),
                )
            )
            columns_with_role = set(row[0] for row in col_result.fetchall())

        # Calculer les lacunes
        missing_ddl = [t for t in target_tables if t not in tables_with_ddl]
        missing_table_roles = [t for t in target_tables if t not in tables_with_role]

        # Pour les colonnes : si requises, vérifier lesquelles manquent
        missing_column_roles = []
        if required_columns:
            for col in required_columns:
                # Format attendu dans la BD: "column_role:TABLE.COLUMN"
                col_upper = col.upper()
                # Chercher si cette colonne existe dans les rôles
                col_found = any(
                    role.endswith(f".{col_upper}") or role == f"column_role:{col_upper}"
                    for role in columns_with_role
                )
                if not col_found:
                    missing_column_roles.append(col_upper)

        # Couverture du schéma = % de tables ayant BOTH DDL et table_role
        tables_with_both = len(tables_with_ddl.intersection(tables_with_role))
        schema_coverage = tables_with_both / len(target_tables) if len(target_tables) > 0 else 0.0

        has_gaps = len(missing_ddl) > 0 or len(missing_table_roles) > 0

        return {
            "missing_ddl": missing_ddl,
            "missing_table_roles": missing_table_roles,
            "missing_column_roles": missing_column_roles,
            "schema_coverage": schema_coverage,
            "has_gaps": has_gaps,
        }

    async def get_enrichment_for_tables(
        self, table_names: List[str], *, user: Any = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Retourne l'enrichissement sémantique complet pour les tables données.

        Pour chaque table, récupère :
        - table_role: documentation avec catégorie "table_role:{table}"
        - column_roles: dict de colonnes avec "column_role:{table}.*"
        - relations: liste de relations entrantes/sortantes

        **Phase α.1.bis (#86) — Filtrage user**. Si ``user`` est fourni
        ET que ce user a des règles ``deny`` actives, les tables denied
        (atomiques + closure transitive) sont retirées du résultat AVANT
        retour. Defense-in-depth : si le caller a un bug et passe une
        table denied dans ``table_names``, on ne fuit pas son
        enrichissement.

        ``user=None`` (cas système / sync / admin) = bypass (comportement
        legacy).

        Returns:
            {
                "TABLE_NAME": {
                    "table_role": "...",
                    "column_roles": {"COL1": "...", ...},
                    "relations": [...]
                },
                ...
            }
        """
        if not table_names:
            return {}

        target_names = [name.upper() for name in table_names if name]
        if not target_names:
            return {}

        # **#86 — Filtrage user à la source.** On charge la vue user et on
        # retire les tables denied (atomique + closure) AVANT d'exécuter
        # les queries d'enrichissement. Économise aussi un round-trip BDD
        # par table denied.
        if user is not None and getattr(user, "role", None) != "admin":
            try:
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view = await build_user_schema_view(user)
                if view is not None and view.denied_tables_with_closure:
                    denied = view.denied_tables_with_closure
                    filtered = [n for n in target_names if n not in denied]
                    if len(filtered) < len(target_names):
                        logger.info(
                            "get_enrichment_for_tables: filtré %d table(s) " "denied pour user=%s",
                            len(target_names) - len(filtered),
                            getattr(user, "id", None),
                        )
                    target_names = filtered
                    if not target_names:
                        return {}
            except Exception:  # noqa: BLE001 — fail-safe : on continue sans filtrage
                logger.warning(
                    "get_enrichment_for_tables: build_user_schema_view a "
                    "crashé pour user=%s — pas de filtrage applied (le "
                    "caller doit avoir filtré en amont)",
                    getattr(user, "id", None),
                    exc_info=True,
                )

        result_map = {}

        async with get_session() as session:
            for tname in target_names:
                # Récupérer table_role
                role_result = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.is_active == True,  # noqa: E712
                        TrainingData.category == f"table_role:{tname}",
                    )
                )
                role_record = role_result.scalar_one_or_none()

                # Récupérer column_roles
                esc_tname = tname.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                col_result = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.is_active == True,  # noqa: E712
                        TrainingData.category.like(f"column_role:{esc_tname}.%", escape="\\"),
                    )
                )
                col_records = col_result.scalars().all()

                column_roles = {}
                for cr in col_records:
                    parts = (cr.category or "").split(".", 1)
                    if len(parts) == 2:
                        column_roles[parts[1]] = cr.content

                # Récupérer les relations (entrantes et sortantes)
                # Format: "relation:{source}→{target}" ou "relation:{source}→{target}:{comment}"
                esc_tname = tname.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                relation_result = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.is_active == True,  # noqa: E712
                        (
                            TrainingData.category.like(f"relation:{esc_tname}→%", escape="\\")
                            | TrainingData.category.like(f"relation:%→{esc_tname}", escape="\\")
                        ),
                    )
                )
                relation_records = relation_result.scalars().all()

                relations = [
                    {
                        "category": r.category,
                        "content": r.content,
                    }
                    for r in relation_records
                ]

                # Récupérer les valeurs distinctes par colonne
                esc_tname = tname.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                values_result = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.is_active == True,  # noqa: E712
                        TrainingData.category.like(f"column_values:{esc_tname}.%", escape="\\"),
                    )
                )
                values_records = values_result.scalars().all()

                column_values: Dict[str, List[str]] = {}
                for vr in values_records:
                    parts = (vr.category or "").split(".", 1)
                    if len(parts) == 2:
                        col_name = parts[1]
                        content = vr.content or ""
                        # Format JSON (nouveau) ou CSV legacy
                        try:
                            parsed_values = json.loads(content)
                            if isinstance(parsed_values, list):
                                column_values[col_name] = [str(v) for v in parsed_values]
                            else:
                                column_values[col_name] = [str(parsed_values)]
                        except (json.JSONDecodeError, TypeError):
                            # Fallback CSV legacy : "val1, val2, ..."
                            column_values[col_name] = [
                                v.strip() for v in content.split(", ") if v.strip()
                            ]

                # Récupérer les stats colonnes (cardinalité, % NULL, min/max)
                column_stats: Dict[str, Any] = {}
                stats_result = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.is_active == True,  # noqa: E712
                        TrainingData.category == f"column_stats:{tname}",
                    )
                )
                stats_record = stats_result.scalars().first()
                stats_data: Dict[str, Any] = {}
                if stats_record:
                    try:
                        stats_data = json.loads(stats_record.content or "{}")
                        column_stats = stats_data.get("columns", {})
                    except (json.JSONDecodeError, TypeError):
                        pass

                result_map[tname] = {
                    "table_role": role_record.content if role_record else None,
                    "column_roles": column_roles,
                    "relations": relations,
                    "column_values": column_values,
                    "column_stats": column_stats,
                    "row_count": stats_data.get("row_count", 0),
                }

        return result_map

    async def get_fk_linked_tables(self, table_names: List[str]) -> List[str]:
        """
        Retourne les noms des tables liées par FK aux tables données.

        Parse les catégories relation:{A}→{B} et relation:{A}←{B}
        pour extraire les tables voisines.

        Args:
            table_names: Tables sources (déjà dans le contexte)

        Returns:
            Liste de noms de tables liées (sans doublons, sans les sources)
        """
        if not table_names:
            return []

        source_set = {t.upper() for t in table_names}
        linked: set[str] = set()

        async with get_session() as session:
            for tname in source_set:
                # Échapper _ et % pour que LIKE les traite littéralement
                esc = tname.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                result = await session.execute(
                    select(TrainingData.category).where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.is_active == True,  # noqa: E712
                        (
                            TrainingData.category.like(f"relation:{esc}→%", escape="\\")
                            | TrainingData.category.like(f"relation:%→{esc}", escape="\\")
                            | TrainingData.category.like(f"relation:{esc}←%", escape="\\")
                            | TrainingData.category.like(f"relation:%←{esc}", escape="\\")
                        ),
                    )
                )
                categories = result.scalars().all()

                for cat in categories:
                    # Parse "relation:A→B" ou "relation:A←B"
                    rel_part = cat.replace("relation:", "")
                    for sep in ("→", "←"):
                        if sep in rel_part:
                            parts = rel_part.split(sep)
                            if len(parts) == 2:
                                for p in parts:
                                    p_upper = p.strip().upper()
                                    if p_upper and p_upper not in source_set:
                                        linked.add(p_upper)

        return sorted(linked)

    # ==========================================
    # Stats et gestion
    # ==========================================

    async def has_any_ddl(self) -> bool:
        """Check rapide : le training store a-t-il au moins 1 DDL actif ?"""
        async with get_session() as session:
            result = await session.execute(
                select(func.count())
                .select_from(TrainingData)
                .where(
                    TrainingData.data_type == TrainingDataType.DDL,
                    TrainingData.is_active == True,  # noqa: E712
                )
                .limit(1)
            )
            return (result.scalar() or 0) > 0

    async def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du training store."""
        async with get_session() as session:
            # Compter les DDL (tables)
            tables_count = await session.execute(
                select(func.count()).where(
                    TrainingData.data_type == TrainingDataType.DDL,
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.source.in_(["auto_sync", "manual"]),
                )
            )

            # Compter les vues SQL
            views_count = await session.execute(
                select(func.count()).where(
                    TrainingData.data_type == TrainingDataType.DDL,
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.source == "auto_sync_view",
                )
            )

            doc_count = await session.execute(
                select(func.count()).where(
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.is_active == True,  # noqa: E712
                )
            )
            pair_count = await session.execute(
                select(func.count()).where(
                    TrainingData.data_type == TrainingDataType.QUESTION_SQL,
                    TrainingData.is_active == True,  # noqa: E712
                )
            )
            # Contexte métier (docs de catégorie business_context)
            bc_count = await session.execute(
                select(func.count()).where(
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.category == BUSINESS_CONTEXT_CATEGORY,
                    TrainingData.is_active == True,  # noqa: E712
                )
            )

            # Extraire les valeurs
            tables_val = tables_count.scalar() or 0
            views_val = views_count.scalar() or 0
            doc_val = doc_count.scalar() or 0
            pair_val = pair_count.scalar() or 0
            bc_val = bc_count.scalar() or 0

            return {
                "tables_count": tables_val,
                "views_count": views_val,
                "ddl_count": tables_val + views_val,  # Total DDL
                "documentation_count": doc_val,
                "question_sql_count": pair_val,
                "business_context_count": bc_val,
                "total": tables_val + views_val + doc_val + pair_val,
            }

    async def count_training_data(
        self,
        data_type: Optional[TrainingDataType] = None,
        active_only: bool = True,
        category: Optional[str] = None,
    ) -> int:
        """Compte le nombre total de donnees d'entrainement (pour pagination).

        Args:
            data_type: Type à filtrer (DDL, DOCUMENTATION, QUESTION_SQL).
            active_only: Si True (défaut), ne compte que les items actifs.
            category: Si fourni, filtre sur category == cette valeur (STRICT equality).
                Permet notamment de compter uniquement les business_context
                (category="business_context") sans les autres docs.
        """
        async with get_session() as session:
            query = select(func.count()).select_from(TrainingData)
            if data_type:
                query = query.where(TrainingData.data_type == data_type)
            if active_only:
                query = query.where(TrainingData.is_active == True)  # noqa: E712
            if category is not None:
                query = query.where(TrainingData.category == category)
            result = await session.execute(query)
            return result.scalar() or 0

    async def get_all_training_data(
        self,
        data_type: Optional[TrainingDataType] = None,
        active_only: bool = True,
        limit: int = 100,
        offset: int = 0,
        category: Optional[str] = None,
        *,
        user: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Liste toutes les donnees d'entrainement avec pagination.

        Args:
            data_type, active_only, limit, offset : filtres standards.
            category: Filtre STRICT sur category == cette valeur.
                Utile pour isoler les business_context dans l'UI admin.
            user (kwarg-only): si fourni ET non-admin, applique le filtrage
                mode invisible (DataAccessRule.denied_tables ∪ closure
                transitive via ``build_user_schema_view``). Si user=None
                ou admin → bypass (comportement legacy admin).

        Bug 2026-05-26 (Agent 4 brainstorm AT-C2 critique) : avant ce
        kwarg, ``AITrainingDataAPIHandler.get`` et ``AITrainingPageHandler``
        consommaient cette méthode sans filtrer par user — OK aujourd'hui
        (``@admin_required`` upstream) mais une régression future qui
        assouplirait la garde (ex: lecture seule pour role=consultant)
        exposerait l'intégralité des DDL/Q-SQL, dont ceux référençant des
        tables interdites pour ce rôle. Defense-in-depth : on accepte
        maintenant un ``user`` kwarg pour permettre le filtrage à la
        source. Aujourd'hui les call-sites admin passent ``user=None``
        (bypass explicite et tracé), le test garde-fou ``test_admin_apis
        _require_admin_decorator`` empêche tout call-site sans ``@admin
        _required`` ni ``user=`` propagation.
        """
        async with get_session() as session:
            query = select(TrainingData)
            if data_type:
                query = query.where(TrainingData.data_type == data_type)
            if active_only:
                query = query.where(TrainingData.is_active == True)  # noqa: E712
            if category is not None:
                query = query.where(TrainingData.category == category)

            # Mode invisible — uniquement si user fourni ET non-admin.
            # Pattern aligné sur ``get_similar_question_sql`` (Phase 5.1).
            if user is not None:
                from app.services.data_access.enforcer import should_filter_for

                if await should_filter_for(user):
                    from app.services.data_access.visible_schema import (
                        build_user_schema_view,
                    )

                    view = await build_user_schema_view(user)
                    if view.denied_tables_with_closure:
                        # Exclut les DDL/VIEW dont le ``table_name`` matche
                        # une table denied (atomique ou closure transitive).
                        # NULL passe (DOCUMENTATION/QUESTION_SQL sans table_name).
                        denied_up = {t.strip().upper() for t in view.denied_tables_with_closure}
                        # SQLite n'a pas une bonne NOT IN avec UPPER() sur
                        # null-safe — on filtre en Python après load (cap limit
                        # déjà appliqué).
                        query = query.order_by(TrainingData.created_at.desc())
                        query = query.offset(offset).limit(limit)
                        result = await session.execute(query)
                        records = [
                            r
                            for r in result.scalars().all()
                            if not (r.table_name and r.table_name.strip().upper() in denied_up)
                        ]
                        return [r.to_dict() for r in records]

            query = query.order_by(TrainingData.created_at.desc())
            query = query.offset(offset).limit(limit)

            result = await session.execute(query)
            records = result.scalars().all()

            return [r.to_dict() for r in records]

    async def find_data_access_references(self, training_id: int) -> List[Dict[str, Any]]:
        """Retourne les ``DataAccessRule`` actives qui référencent un
        ``TrainingData`` (DDL/VIEW/FUNCTION/SYNONYM) par ``table_name``.

        Bug 2026-05-26 (Agent 4 brainstorm DA-C3 critique) : avant ce
        helper, un admin pouvait soft-delete un DDL via ``/admin/ai-training``
        sans signal — alors que ce DDL était référencé dans une règle
        ``DataAccessRule`` (deny F_SALAIRES par exemple). Conséquence :
        la closure transitive ``visible_schema._compute_transitive_closure``
        perdait silencieusement le nœud, et toute vue dérivée ``V_SALAIRES``
        n'était plus bloquée pour les users denied. Bypass invisible du
        mode invisible.

        Le handler ``AITrainingDataItemHandler.delete`` doit appeler ce
        helper AVANT de supprimer et renvoyer 409 Conflict si la liste
        n'est pas vide — l'admin doit retirer les règles bloquantes
        d'abord (ou re-créer le DDL après le delete s'il sait ce qu'il fait).

        Note rétrocompat : retourne ``[]`` si le record n'existe pas
        OU n'a pas de ``table_name`` (cas QUESTION_SQL, DOCUMENTATION sans
        rattachement table → pas de référence schéma possible).
        """
        async with get_session() as session:
            record = await session.get(TrainingData, training_id)
            if record is None or not record.table_name:
                return []
            target_name = record.table_name.strip().upper()

            # Import local pour éviter une dépendance circulaire avec
            # le module data_access (qui peut importer training_store via
            # visible_schema._load_schema_inventory).
            from app.models.data_access_rule import DataAccessRule

            rules_q = await session.execute(
                select(DataAccessRule)
                .where(DataAccessRule.deleted_at.is_(None))
                .where(func.upper(DataAccessRule.table_name) == target_name)
            )
            return [
                {
                    "rule_id": r.id,
                    "user_id": r.user_id,
                    "scope_type": r.scope_type.value if r.scope_type else None,
                    "effect": r.effect.value if r.effect else None,
                    "table_name": r.table_name,
                    "column_name": r.column_name,
                }
                for r in rules_q.scalars().all()
            ]

    async def delete_training_data(self, training_id: int) -> bool:
        """Désactive (soft delete) une donnée d'entraînement.

        Retourne ``True`` si au moins un enregistrement a été désactivé,
        ``False`` si l'``id`` est inconnu ou si l'enregistrement était déjà
        inactif. Permet au handler de renvoyer 404 plutôt que de laisser
        croire à la UI qu'une suppression a bien eu lieu.

        **Important** (Bug 2026-05-26 DA-C3) : ce service NE VÉRIFIE PAS
        les références ``DataAccessRule`` qui pourraient pointer sur ce
        record. Le handler ``AITrainingDataItemHandler.delete`` est
        responsable d'appeler ``find_data_access_references`` AVANT cette
        méthode et de retourner 409 si non-vide. Sans cela, la closure
        transitive du mode invisible perd silencieusement le nœud et
        toute vue dérivée n'est plus bloquée.
        """
        async with get_session() as session:
            result = await session.execute(
                update(TrainingData)
                .where(TrainingData.id == training_id)
                .where(TrainingData.is_active == True)  # noqa: E712
                .values(is_active=False)
            )
            # Capturer le rowcount AVANT commit — sur SQLAlchemy async il
            # peut être remis à 0 après commit selon le dialecte.
            deleted = result.rowcount > 0
            await session.commit()
            if deleted:
                logger.info("Training data désactivé: id=%s", training_id)
            else:
                logger.info("Training data déjà inactif ou inconnu: id=%s", training_id)
            return deleted

    async def get_pending_reviews(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Liste les données en attente de validation admin."""
        async with get_session() as session:
            query = (
                select(TrainingData)
                .where(TrainingData.is_active == True)  # noqa: E712
                .where(TrainingData.pending_review == True)  # noqa: E712
                .order_by(TrainingData.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            result = await session.execute(query)
            return [r.to_dict() for r in result.scalars().all()]

    async def count_pending_reviews(self) -> int:
        """Compte les données en attente de validation."""
        async with get_session() as session:
            query = (
                select(func.count())
                .select_from(TrainingData)
                .where(TrainingData.is_active == True)  # noqa: E712
                .where(TrainingData.pending_review == True)  # noqa: E712
            )
            result = await session.execute(query)
            return result.scalar() or 0

    async def approve_training_data(self, training_id: int) -> bool:
        """Approuve une donnée en attente (pending_review -> False).

        Re-valide le SQL AVANT d'activer la paire : les items pending viennent
        souvent du feedback non-admin (``validate_on_sage=False`` à l'ajout) →
        un SQL jamais exécuté / faux / périmé ne doit pas entrer dans le RAG
        actif d'un clic (empoisonnement = SQL faux pour TOUS les users).

        Raises:
            ValueError: le SQL de la paire contient une opération interdite.
            SQLValidationError: le dry-run du SQL échoue sur le serveur actif.
        """
        # 1. Charger le SQL à valider (session courte, colonnes ciblées → pas
        #    de lazy-load hors session).
        async with get_session() as session:
            row = (
                await session.execute(
                    select(TrainingData.data_type, TrainingData.sql)
                    .where(TrainingData.id == training_id)
                    .where(TrainingData.pending_review == True)  # noqa: E712
                )
            ).one_or_none()
        if row is None:
            return False

        # 2. Re-valider HORS session (le dry-run Sage peut durer → ne pas
        #    tenir la session SQLite ouverte, anti "database is locked").
        if row.data_type == TrainingDataType.QUESTION_SQL and row.sql:
            await self._validate_training_sql(
                row.sql,
                validate_on_sage=True,
                rls_source="approve_training_data_dryrun",
            )

        # 3. Flip pending_review (session courte) — re-check pending pour
        #    l'idempotence (un autre admin a pu approuver entre-temps).
        async with get_session() as session:
            result = await session.execute(
                update(TrainingData)
                .where(TrainingData.id == training_id)
                .where(TrainingData.pending_review == True)  # noqa: E712
                .values(pending_review=False)
            )
            # Capture rowcount BEFORE commit (invalid after commit in async SQLAlchemy)
            approved = result.rowcount > 0
            await session.commit()
        if approved:
            logger.info("Training data approuvé: id=%d", training_id)
        return approved

    # ==========================================
    # Alias métier et grappes
    # ==========================================

    async def resolve_aliases(self, question: str) -> List[Dict[str, Any]]:
        """
        Résout les termes métier de la question en tables/colonnes canoniques.

        Cherche dans les alias business (catégorie "alias:*") les termes
        qui matchent la question de l'utilisateur. Retourne les tables/colonnes
        correspondantes pour enrichir le contexte RAG.

        Args:
            question: Question en langage naturel de l'utilisateur

        Returns:
            Liste de dicts avec alias, table, column (optionnel), description
        """
        if not question or not question.strip():
            return []

        matches: List[Dict[str, Any]] = []
        q_lower = question.lower()

        async with get_session() as session:
            # Récupérer tous les alias actifs
            result = await session.execute(
                select(TrainingData).where(
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.category.like("alias:%"),
                )
            )
            alias_records = result.scalars().all()

            for record in alias_records:
                # Extraire le terme alias de la catégorie "alias:xxx"
                alias_term = (record.category or "").replace("alias:", "", 1).strip()
                if not alias_term:
                    continue

                # Vérifier si le terme alias apparaît dans la question
                if alias_term in q_lower:
                    # Extraire table/colonne depuis les tags
                    tags = [t.strip() for t in (record.tags or "").split(",")]
                    table_name = None
                    column_name = None
                    for tag in tags:
                        tag_upper = tag.upper()
                        if self._is_known_table(tag_upper):
                            if not table_name:
                                table_name = tag_upper
                            elif not column_name:
                                column_name = tag
                        elif "." in tag:
                            parts = tag.split(".", 1)
                            table_name = parts[0].upper()
                            column_name = parts[1]

                    matches.append(
                        {
                            "alias": alias_term,
                            "table": table_name,
                            "column": column_name,
                            "description": record.content,
                        }
                    )

        return matches

    def _is_known_table(self, name: str) -> bool:
        """Vérifie si un nom correspond à une table connue dans le schéma."""
        try:
            from app.services.ai.schema_loader import get_schema_loader

            tables = get_schema_loader().get_tables()
            return name in tables or name.upper() in {t.upper() for t in tables}
        except Exception:
            return False

    async def get_cluster_documentation(self, table_name: str) -> Optional[str]:
        """
        Retourne la documentation de grappe pour une table donnée.

        Cherche d'abord si la table est membre d'une grappe (cluster_member:TABLE),
        puis récupère la doc complète de la grappe (cluster:HUB).

        Args:
            table_name: Nom de la table

        Returns:
            Description de la grappe, ou None si non trouvée
        """
        if not table_name:
            return None

        tname = table_name.strip().upper()

        async with get_session() as session:
            # Chercher l'appartenance à une grappe
            member_result = await session.execute(
                select(TrainingData).where(
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.category == f"cluster_member:{tname}",
                )
            )
            member_record = member_result.scalar_one_or_none()
            if member_record:
                return member_record.content

            # Peut-être que la table est elle-même le hub
            hub_result = await session.execute(
                select(TrainingData).where(
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.category == f"cluster:{tname}",
                )
            )
            hub_record = hub_result.scalar_one_or_none()
            if hub_record:
                return hub_record.content

            return None

    async def get_readiness_stats(self) -> Dict[str, Any]:
        """
        Calcule les statistiques de readiness de la base de connaissances.

        Returns:
            Dict avec :
            - total_tables: nombre de tables DDL
            - tables_with_roles: nombre de tables avec table_role
            - tables_with_clusters: nombre de tables dans une grappe
            - aliases_count: nombre d'alias métier
            - examples_count: nombre de paires Q/SQL
            - readiness_score: score 0-100
        """
        async with get_session() as session:
            # Tables DDL
            ddl_count = (
                await session.execute(
                    select(func.count())
                    .select_from(TrainingData)
                    .where(
                        TrainingData.data_type == TrainingDataType.DDL,
                        TrainingData.is_active == True,  # noqa: E712
                    )
                )
            ).scalar() or 0

            # Tables avec rôle sémantique
            roles_count = (
                await session.execute(
                    select(func.count())
                    .select_from(TrainingData)
                    .where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.is_active == True,  # noqa: E712
                        TrainingData.category.like("table_role:%"),
                    )
                )
            ).scalar() or 0

            # Tables dans une grappe
            cluster_count = (
                await session.execute(
                    select(func.count())
                    .select_from(TrainingData)
                    .where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.is_active == True,  # noqa: E712
                        TrainingData.category.like("cluster_member:%"),
                    )
                )
            ).scalar() or 0

            # Alias métier
            aliases_count = (
                await session.execute(
                    select(func.count())
                    .select_from(TrainingData)
                    .where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.is_active == True,  # noqa: E712
                        TrainingData.category.like("alias:%"),
                    )
                )
            ).scalar() or 0

            # Paires Q/SQL
            examples_count = (
                await session.execute(
                    select(func.count())
                    .select_from(TrainingData)
                    .where(
                        TrainingData.data_type == TrainingDataType.QUESTION_SQL,
                        TrainingData.is_active == True,  # noqa: E712
                    )
                )
            ).scalar() or 0

        # Score de readiness : pondéré
        # 40% DDL avec rôles, 25% grappes, 20% alias, 15% exemples
        role_pct = (roles_count / max(ddl_count, 1)) * 100
        cluster_pct = (cluster_count / max(ddl_count, 1)) * 100
        alias_score = min(aliases_count / 50, 1.0) * 100  # 50 alias = 100%
        example_score = min(examples_count / 20, 1.0) * 100  # 20 exemples = 100%

        readiness = role_pct * 0.40 + cluster_pct * 0.25 + alias_score * 0.20 + example_score * 0.15

        return {
            "total_tables": ddl_count,
            "tables_with_roles": roles_count,
            "tables_with_clusters": cluster_count,
            "aliases_count": aliases_count,
            "examples_count": examples_count,
            "readiness_score": round(min(readiness, 100), 1),
        }

    async def reset_all(self) -> Dict[str, int]:
        """Supprime TOUT ce que /admin/ai-training affiche + tout ce que le
        sync schéma a généré en BDD. Hard delete cascade :

        - ``training_data`` (DDL, doc, Q/SQL examples, agent_memory)
        - ``schema_syncs`` (historique syncs schéma)
        - ``SCHEMA_SYNC_LAST_RUN`` config remise à NULL (re-sync au boot)
        - Cache RAG runtime invalidé (n_results / threshold lus à nouveau)

        Garde INTACTES (pas de la "documentation Iris") :
        - ``ai_performance_logs`` (historique conso facturation)
        - ``conversation_messages`` (historique user)
        - ``audit_logs`` (audit immutable)

        Returns: ``{"training_data": N, "schema_syncs": M}``.
        """
        from app.models.ai_performance import SchemaSync

        counts: Dict[str, int] = {"training_data": 0, "schema_syncs": 0}
        async with get_session() as session:
            res_td = await session.execute(delete(TrainingData))
            counts["training_data"] = res_td.rowcount or 0
            res_ss = await session.execute(delete(SchemaSync))
            counts["schema_syncs"] = res_ss.rowcount or 0
            await session.commit()

        # Reset le timestamp last-run pour qu'un sync auto se redéclenche au
        # prochain tick scheduler (sinon il pense que c'est tout neuf et
        # attend l'intervalle complet).
        try:
            from app.services.ai.config_service import get_ai_config_service
            from app.models.ai_config import AIConfigKey

            await get_ai_config_service().set(AIConfigKey.SCHEMA_SYNC_LAST_RUN.value, None)
        except Exception:  # noqa: BLE001 — non-critique
            logger.debug("reset_all: clear SCHEMA_SYNC_LAST_RUN failed")

        # Invalide le cache mémoire RAG (n_results / threshold).
        try:
            invalidate_rag_runtime_cache()
        except Exception:  # noqa: BLE001
            pass

        logger.info("Training store reset: %s", counts)
        return counts

    # ==========================================
    # Embeddings: reindexation et auto-promotion
    # ==========================================

    async def reindex_embeddings(self, force: bool = False) -> Dict[str, int]:
        """
        Recalcule les embeddings manquants pour toutes les données d'entraînement.

        Ne recalcule que les entrées sans embedding (delta), sauf si force=True.
        Appelé au démarrage et après sync schéma.

        Returns:
            {"ddl": N, "documentation": N, "question_sql": N} — nombre d'embeddings créés
        """
        if not await VectorSearch.is_available():
            logger.info("sqlite-vec non disponible — reindex annulé")
            return {"ddl": 0, "documentation": 0, "question_sql": 0}

        svc = await self._get_embedding_service()
        counts = {"ddl": 0, "documentation": 0, "question_sql": 0}

        type_config = [
            (TrainingDataType.DDL, "vec_ddl", "ddl", lambda d: f"{d.table_name or ''} {d.content}"),
            (
                TrainingDataType.DOCUMENTATION,
                "vec_documentation",
                "documentation",
                lambda d: f"{d.category or ''} {d.content}",
            ),
            (
                TrainingDataType.QUESTION_SQL,
                "vec_question_sql",
                "question_sql",
                lambda d: f"{d.question or ''} {d.sql or ''}",
            ),
        ]

        for data_type, vec_table, count_key, text_fn in type_config:
            async with get_session() as session:
                result = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type == data_type,
                        TrainingData.is_active == True,  # noqa: E712
                    )
                )
                records = result.scalars().all()

            if not records:
                continue

            # Filtrer les records déjà indexés (sauf si force)
            if not force:
                existing_ids = set()
                try:
                    async with get_session() as session:
                        result = await session.execute(text(f"SELECT id FROM {vec_table}"))
                        existing_ids = {row[0] for row in result.fetchall()}
                except Exception as e:
                    logger.debug("Vec table %s not found or empty: %s", vec_table, e)
                records = [r for r in records if r.id not in existing_ids]

            if not records:
                continue

            # Embedder par batch
            from app.constants_ai import EMBEDDING_BATCH_SIZE

            for i in range(0, len(records), EMBEDDING_BATCH_SIZE):
                batch = records[i : i + EMBEDDING_BATCH_SIZE]
                texts = [text_fn(r) for r in batch]

                embeddings = await svc.embed(texts)
                if embeddings is None:
                    logger.warning("Embedding API down — arrêt reindex pour %s", count_key)
                    break

                for record, emb in zip(batch, embeddings):
                    if emb is not None:
                        try:
                            await VectorSearch.upsert_embedding(vec_table, record.id, emb)
                            counts[count_key] += 1
                        except Exception as e:
                            logger.debug("Embedding upsert failed id=%d: %s", record.id, e)

            logger.info("Reindex %s: %d embeddings créés", count_key, counts[count_key])

        return counts

    async def try_auto_promote(self, record_id: int) -> bool:
        """
        Tente de promouvoir un auto_candidate en donnée validée.

        Utilise un UPDATE atomique conditionnel pour éviter les race conditions.

        Conditions de promotion :
        - source == "auto_candidate"
        - pending_review == True
        - usage_count >= AUTO_PROMOTE_USAGE_THRESHOLD
        - quality_score >= AUTO_PROMOTE_MIN_QUALITY

        Si les conditions sont remplies :
        - pending_review → False
        - quality_score → AUTO_PROMOTE_FINAL_QUALITY

        Returns:
            True si promu
        """
        from app.constants_ai import (
            AUTO_PROMOTE_USAGE_THRESHOLD,
            AUTO_PROMOTE_MIN_QUALITY,
            AUTO_PROMOTE_FINAL_QUALITY,
        )

        async with get_session() as session:
            # UPDATE atomique conditionnel — pas de race condition possible
            result = await session.execute(
                update(TrainingData)
                .where(
                    TrainingData.id == record_id,
                    TrainingData.source == "auto_candidate",
                    TrainingData.pending_review == True,  # noqa: E712
                    TrainingData.usage_count >= AUTO_PROMOTE_USAGE_THRESHOLD,
                    TrainingData.quality_score >= AUTO_PROMOTE_MIN_QUALITY,
                )
                .values(
                    pending_review=False,
                    quality_score=AUTO_PROMOTE_FINAL_QUALITY,
                    updated_at=clock.now(),
                )
            )
            promoted = result.rowcount > 0
            await session.commit()

            if promoted:
                logger.info(
                    "Auto-promoted Q/SQL id=%d → quality=%.2f",
                    record_id,
                    AUTO_PROMOTE_FINAL_QUALITY,
                )
            return promoted

    async def increment_candidate_quality(self, record_id: int) -> float:
        """
        Incrémente le quality_score d'un auto_candidate après réutilisation réussie.

        Utilise un UPDATE atomique pour éviter les race conditions (pas de read-modify-write).

        Returns:
            Nouveau quality_score (0.0 si le record n'est pas un auto_candidate)
        """
        from app.constants_ai import AUTO_PROMOTE_QUALITY_INCREMENT

        async with get_session() as session:
            # UPDATE atomique — MIN(1.0, ...) calculé côté SQL
            result = await session.execute(
                update(TrainingData)
                .where(
                    TrainingData.id == record_id,
                    TrainingData.source == "auto_candidate",
                )
                .values(
                    quality_score=func.min(
                        1.0,
                        func.coalesce(TrainingData.quality_score, 0)
                        + AUTO_PROMOTE_QUALITY_INCREMENT,
                    ),
                    updated_at=clock.now(),
                )
            )
            await session.commit()

            if result.rowcount == 0:
                return 0.0

            # Relire la valeur mise à jour
            refreshed = await session.execute(
                select(TrainingData.quality_score).where(TrainingData.id == record_id)
            )
            new_quality = refreshed.scalar_one_or_none()
            return float(new_quality) if new_quality is not None else 0.0

    # ── Méthodes bulk pour construction d'index 4D (orchestrator_search) ──

    async def get_all_column_stats(self) -> Dict[str, Any]:
        """Retourne toutes les stats de colonnes.

        Returns:
            {table_name: {row_count, columns: {col: {distinct, null_pct, type, ...}}}}
        """
        async with get_session() as session:
            result = await session.execute(
                select(TrainingData.content, TrainingData.category).where(
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.category.like("column_stats:%"),
                )
            )
            rows = result.fetchall()

        stats: Dict[str, Any] = {}
        for content, category in rows:
            table = category.split(":", 1)[1] if ":" in category else ""
            if not table:
                continue
            try:
                stats[table] = json.loads(content)
            except (json.JSONDecodeError, TypeError):
                pass
        return stats

    async def get_all_table_stats(self) -> Dict[str, int]:
        """Retourne toutes les stats de tables.

        Returns:
            {table_name: row_count}
        """
        async with get_session() as session:
            result = await session.execute(
                select(TrainingData.content, TrainingData.category).where(
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.category.like("table_stats:%"),
                )
            )
            rows = result.fetchall()

        stats: Dict[str, int] = {}
        for content, category in rows:
            table = category.split(":", 1)[1] if ":" in category else ""
            if not table:
                continue
            try:
                data = json.loads(content)
                stats[table] = data.get("row_count", 0)
            except (json.JSONDecodeError, TypeError):
                pass
        return stats

    async def get_all_ddl_contents(self, *, user: Any = None) -> List[Dict[str, Any]]:
        """Retourne tous les DDL actifs.

        Args:
            user: optionnel — si fourni avec restrictions, retire les
                tables interdites (mode invisible Phase α.1).
                ``user=None`` (défaut) = comportement legacy.

        Returns:
            [{table_name, content, source}] filtrés selon ``user``.
        """
        async with get_session() as session:
            # Phase 1.6 (#43) : inclure VIEW pour retourner aussi les
            # définitions de vues (Iris doit les voir comme "tables connues").
            result = await session.execute(
                select(
                    TrainingData.table_name,
                    TrainingData.content,
                    TrainingData.source,
                ).where(
                    TrainingData.data_type.in_((TrainingDataType.DDL, TrainingDataType.VIEW)),
                    TrainingData.is_active == True,  # noqa: E712
                )
            )
            rows = result.fetchall()

        all_ddls = [
            {"table_name": r[0], "content": r[1], "source": r[2] or ""} for r in rows if r[0]
        ]

        # Phase α.1 — Filtre mode invisible
        if not await should_filter_for(user):
            return all_ddls
        # FAIL-CLOSED : sur erreur du filtrage, retourner [] plutôt que
        # tout (les callers de cette méthode injectent le contenu dans
        # des contextes LLM — fuite garantie sinon).
        try:
            from app.services.data_access.llm_context import (
                rewrite_ddl_for_view,
            )
            from app.services.data_access.visible_schema import (
                build_user_schema_view,
            )

            view = await build_user_schema_view(user)
            if not view.has_restrictions:
                return all_ddls
            # Filtrer les tables invisibles ET réécrire les DDL pour
            # retirer les FK croisées et colonnes interdites (fix BLOCKING
            # finding #1 review α.1).
            filtered: List[Dict[str, Any]] = []
            for d in all_ddls:
                tname = d["table_name"]
                if not tname or tname.upper() not in view.visible_tables:
                    continue
                rewritten_content = rewrite_ddl_for_view(d["content"] or "", view, tname)
                if not rewritten_content:
                    continue  # rewriter fail-closed → on skippe
                filtered.append(
                    {
                        "table_name": tname,
                        "content": rewritten_content,
                        "source": d["source"],
                    }
                )
            return filtered
        except Exception as exc:
            logger.error(
                "training_store.get_all_ddl_contents: filtrage mode invisible "
                "échoué (fail-closed, [] retourné): %s",
                exc,
                exc_info=True,
            )
            return []

    # ==========================================
    # API Business Context (injection par tables, pas par keywords)
    # ==========================================

    @staticmethod
    def _normalize_table_name(raw: Any) -> Optional[str]:
        """Normalise un nom de table pour comparaison case-insensitive.

        - None / non-string / vide → None (ignoré par l'appelant)
        - strip + UPPER()
        Générique, sans aucune connaissance de la BDD source.
        """
        if not isinstance(raw, str):
            return None
        cleaned = raw.strip()
        if not cleaned:
            return None
        return cleaned.upper()

    @classmethod
    def _normalize_tags_tables(cls, raw: Any) -> List[str]:
        """Parse défensivement une liste de tags_tables.

        Accepte : list[str], tuple[str], str séparé par virgule (fallback).
        Filtre null/vides, dedupe, retourne une liste triée (pour stockage stable).
        """
        if raw is None:
            return []
        if isinstance(raw, str):
            raw = raw.split(",")
        if not isinstance(raw, (list, tuple, set)):
            return []
        seen = set()
        for item in raw:
            norm = cls._normalize_table_name(item)
            if norm:
                seen.add(norm)
        return sorted(seen)

    async def add_business_context(
        self,
        content: str,
        tags_tables: List[str],
        priority: int = 0,
        source: str = BUSINESS_CONTEXT_CATEGORY,
        user_id: Optional[int] = None,
        primary_table: Optional[str] = None,
    ) -> int:
        """Crée (ou met à jour si dédupe) un business_context.

        Stocke les tags_tables normalisés (UPPER, dedupe) dans extra_metadata,
        pour un matching case-insensitive ultérieur et sans migration schema.

        Args:
            content: Texte de la règle métier (non vide)
            tags_tables: Tables concernées (au moins 1, case-insensitive)
            priority: Priorité (int, plus grand = plus prioritaire). 0 par défaut
                pour les docs manuelles ; view_miner utilise 1 pour les auto.
            source: Source d'origine (défaut = "business_context" = manuel).
                Les docs auto utilisent "view_mining:{view_name}".
            user_id: ID de l'utilisateur qui ajoute (optionnel).
            primary_table: Optionnel. Nom de la table réellement ambiguë (pour
                les règles multi-rôles). Normalisé en UPPER. Utilisé par le
                guard `coexistent_role_not_justified` pour scoper le tracker
                uniquement sur cette table (pas toute `tags_tables`). Si
                absent, les consommateurs retombent sur extraction depuis
                `content` puis `tags_tables`.

        Returns:
            ID du record créé ou mis à jour.

        Raises:
            ValueError: content vide ou tags_tables vide après normalisation.
        """
        if not content or not content.strip():
            raise ValueError("Le contenu business_context ne peut pas être vide")
        if len(content) > _MAX_DOC_SIZE:
            raise ValueError(f"Contenu trop volumineux ({len(content)} chars, max {_MAX_DOC_SIZE})")

        normalized_tables = self._normalize_tags_tables(tags_tables)
        if not normalized_tables:
            raise ValueError("tags_tables doit contenir au moins un nom de table valide")

        try:
            priority_int = int(priority)
        except (TypeError, ValueError):
            priority_int = 0

        metadata = {
            "tags_tables": normalized_tables,
            "priority": priority_int,
            "auto_generated": source.startswith(VIEW_MINING_SOURCE_PREFIX),
        }
        if primary_table:
            normalized_primary = self._normalize_table_name(primary_table)
            if normalized_primary:
                metadata["primary_table"] = normalized_primary

        async with get_session() as session:
            # Déduplication : même catégorie + même contenu + même source → update
            existing = await session.execute(
                select(TrainingData).where(
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.category == BUSINESS_CONTEXT_CATEGORY,
                    TrainingData.content == content,
                    TrainingData.source == source,
                    TrainingData.is_active.is_(True),
                )
            )
            existing_record = existing.scalar_one_or_none()

            if existing_record:
                existing_record.extra_metadata = metadata
                existing_record.updated_at = clock.now()
                record_id = existing_record.id
                await session.commit()
                logger.info(
                    "business_context mis à jour (id=%s, tables=%s, source=%s)",
                    record_id,
                    normalized_tables,
                    source,
                )
                return record_id

            record = TrainingData(
                data_type=TrainingDataType.DOCUMENTATION,
                content=content,
                category=BUSINESS_CONTEXT_CATEGORY,
                source=source,
                created_by=user_id,
                extra_metadata=metadata,
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)
            logger.info(
                "business_context ajouté (id=%s, tables=%s, source=%s, priority=%s)",
                record.id,
                normalized_tables,
                source,
                priority_int,
            )
            return record.id

    async def get_business_context_for_tables(
        self,
        tables: Optional[List[str]],
        token_budget: int = 1500,
    ) -> List[Dict[str, Any]]:
        """Retourne les business_context dont tags_tables recoupe `tables`.

        Déclencheur = présence d'UNE table taggée dans `tables`. Case-insensitive.
        Priorisation : (match_count DESC, priority DESC, usage_count DESC, recency DESC).
        Respecte le token_budget : chaque doc est entièrement incluse ou pas du tout
        (pas de troncature milieu de phrase qui casserait le sens).

        Fail-closed : toute exception → warning + [] (jamais propagée).

        Args:
            tables: Liste de noms de tables à matcher (case-insensitive).
                None ou vide → [].
            token_budget: Plafond total de tokens estimés (défaut 1500).
                0 ou négatif → [].

        Returns:
            Liste de dicts {id, content, tags_tables, priority, source,
            match_count, auto_generated}. Vide si aucun match.
        """
        # Guards — REQ-1 (empty/none) + REQ-5 (budget<=0)
        if not tables:
            return []
        try:
            budget = int(token_budget)
        except (TypeError, ValueError):
            return []
        if budget <= 0:
            return []

        try:
            scope = {self._normalize_table_name(t) for t in tables}
            scope.discard(None)
            if not scope:
                return []

            async with get_session() as session:
                # Query STRICT sur category (pas LIKE) — REQ-3
                result = await session.execute(
                    select(TrainingData).where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.category == BUSINESS_CONTEXT_CATEGORY,
                        TrainingData.is_active.is_(True),
                    )
                )
                records = result.scalars().all()

            # Matching + scoring
            candidates = []
            for rec in records:
                metadata = rec.extra_metadata if isinstance(rec.extra_metadata, dict) else {}
                rec_tables = self._normalize_tags_tables(metadata.get("tags_tables"))
                if not rec_tables:
                    continue  # doc sans tags → ignorée pour ne pas polluer
                overlap = [t for t in rec_tables if t in scope]
                if not overlap:
                    continue
                try:
                    rec_priority = int(metadata.get("priority", 0))
                except (TypeError, ValueError):
                    rec_priority = 0
                # Dérive une priorité "minimum" depuis la source pour que les
                # règles sémantiques fortes (multiple_aliases, column_alias)
                # passent DEVANT les cooccurrences même quand les docs déjà
                # stockées ont toutes priority=1 (ancienne version).
                # On prend MAX(stored, derived) pour respecter les overrides admin.
                effective_priority = max(
                    rec_priority,
                    self._derive_priority_from_source(rec.source or ""),
                )
                candidates.append(
                    {
                        "record": rec,
                        "match_count": len(overlap),
                        "priority": effective_priority,
                        "stored_priority": rec_priority,
                        "tags_tables": rec_tables,
                    }
                )

            if not candidates:
                return []

            # Tri — REQ-4 : priority DESC d'abord (les règles sémantiques
            # fortes priment sur les cooccurrences bavardes), puis match_count,
            # usage_count, recency.
            candidates.sort(
                key=lambda c: (
                    -c["priority"],
                    -c["match_count"],
                    -(c["record"].usage_count or 0),
                    -(c["record"].created_at.timestamp() if c["record"].created_at else 0),
                )
            )

            # Accumulation avec token_budget — REQ-5 (doc entière ou rien)
            output: List[Dict[str, Any]] = []
            tokens_used = 0
            for cand in candidates:
                rec = cand["record"]
                doc_tokens = estimate_token_count(rec.content)
                if output and tokens_used + doc_tokens > budget:
                    # Plus de place — on s'arrête plutôt que de tronquer milieu
                    break
                if not output and doc_tokens > budget:
                    # Une seule doc qui dépasse → on la met quand même
                    # (le plafond est indicatif, préserver le sens prime)
                    output.append(
                        self._format_business_context_record(
                            rec, cand["tags_tables"], cand["priority"], cand["match_count"]
                        )
                    )
                    break
                output.append(
                    self._format_business_context_record(
                        rec, cand["tags_tables"], cand["priority"], cand["match_count"]
                    )
                )
                tokens_used += doc_tokens

            logger.info(
                "business_context: %d/%d docs injectés pour tables %s (tokens≈%d/%d)",
                len(output),
                len(candidates),
                sorted(scope),
                tokens_used,
                budget,
            )
            return output

        except Exception as exc:  # REQ-2 : fail-closed absolu
            logger.warning(
                "business_context lookup failed for tables=%s: %s",
                tables,
                exc,
                exc_info=True,
            )
            return []

    @staticmethod
    def _derive_priority_from_source(source: str) -> int:
        """Priorité sémantique dérivée de la source d'un business_context.

        Permet de hiérarchiser les règles **même quand les docs déjà stockées
        ont toutes priority=1** (ancienne version du view_miner), sans nécessiter
        un re-sync pour profiter de la nouvelle hiérarchie.

        Échelle :
        - `view_mining:cooccurrence`  → 1  (info faible, souvent redondante avec FK)
        - `view_mining:fk_analysis`   → 3  (rôles spécialisés via FK suffixes)
        - `view_mining:<view_name>`   → 5  (règles sémantiques fortes —
                                            multiple_aliases + column_alias
                                            extraits d'une vue précise)
        - autre (`manual_override:…`, `business_context`, source custom) → 0
          (la priorité stockée décide — permet à l'admin de surclasser si besoin)

        Les valeurs retournées sont des PLANCHERS : la logique appelante fait
        `max(stored_priority, _derive_priority_from_source(source))` pour
        respecter les overrides manuels (priority=10 par un admin gagne).
        """
        if not source:
            return 0
        if source == "view_mining:cooccurrence":
            return 1
        if source == "view_mining:fk_analysis":
            return 3
        if source.startswith(VIEW_MINING_SOURCE_PREFIX):
            # "view_mining:viewXxx" → règles multiple_aliases/column_alias
            return 5
        return 0

    @staticmethod
    def _format_business_context_record(
        rec: TrainingData,
        tags_tables: List[str],
        priority: int,
        match_count: int,
    ) -> Dict[str, Any]:
        """Sérialise un record business_context pour injection/UI."""
        metadata = rec.extra_metadata if isinstance(rec.extra_metadata, dict) else {}
        out: Dict[str, Any] = {
            "id": rec.id,
            "content": rec.content,
            "tags_tables": tags_tables,
            "priority": priority,
            "match_count": match_count,
            "source": rec.source,
            "auto_generated": bool(metadata.get("auto_generated", False)),
        }
        primary = metadata.get("primary_table")
        if primary:
            out["primary_table"] = primary
        return out

    async def list_business_contexts(
        self,
        limit: int = 100,
        offset: int = 0,
        source_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Liste les business_context pour l'admin UI (pagination simple).

        Args:
            limit: Max résultats.
            offset: Décalage pour pagination.
            source_filter: Si fourni, filtre sur source exacte
                (ex: "business_context" pour ne voir que le manuel).

        Returns:
            Liste de dicts sérialisés (à_dict + tags_tables + priority).
        """
        async with get_session() as session:
            stmt = select(TrainingData).where(
                TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                TrainingData.category == BUSINESS_CONTEXT_CATEGORY,
                TrainingData.is_active.is_(True),
            )
            if source_filter:
                stmt = stmt.where(TrainingData.source == source_filter)
            stmt = stmt.order_by(
                TrainingData.updated_at.desc().nullslast(), TrainingData.created_at.desc()
            )
            stmt = stmt.offset(offset).limit(limit)
            result = await session.execute(stmt)
            records = result.scalars().all()

        output = []
        for rec in records:
            metadata = rec.extra_metadata if isinstance(rec.extra_metadata, dict) else {}
            tags_tables = self._normalize_tags_tables(metadata.get("tags_tables"))
            try:
                priority = int(metadata.get("priority", 0))
            except (TypeError, ValueError):
                priority = 0
            output.append(
                {
                    "id": rec.id,
                    "content": rec.content,
                    "tags_tables": tags_tables,
                    "priority": priority,
                    "source": rec.source,
                    "auto_generated": bool(metadata.get("auto_generated", False)),
                    "created_at": rec.created_at.isoformat() if rec.created_at else None,
                    "updated_at": rec.updated_at.isoformat() if rec.updated_at else None,
                }
            )
        return output

    async def update_business_context(
        self,
        record_id: int,
        content: Optional[str] = None,
        tags_tables: Optional[List[str]] = None,
        priority: Optional[int] = None,
        promote_to_manual: bool = False,
    ) -> bool:
        """Met à jour un business_context existant.

        Args:
            record_id: ID du record à modifier.
            content: Nouveau contenu (optionnel, conserve sinon).
            tags_tables: Nouvelles tables (optionnel, conserve sinon).
            priority: Nouvelle priorité (optionnel).
            promote_to_manual: Si True et que le record était auto (view_mining:*),
                bascule source vers "manual_override:{view}" pour le figer
                (ne sera plus regénéré au prochain sync).

        Returns:
            True si modifié, False si introuvable.
        """
        async with get_session() as session:
            # Symétrie avec update_documentation / update_ddl / update_question_sql :
            # on refuse les records soft-deleted ET on exige explicitement le type
            # DOCUMENTATION. Sans cette garde, un PUT sur un BC déjà supprimé
            # « ressuscitait » silencieusement son contenu tout en laissant
            # is_active=False — incohérence invisible jusqu'au prochain read.
            result = await session.execute(
                select(TrainingData).where(
                    TrainingData.id == record_id,
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.category == BUSINESS_CONTEXT_CATEGORY,
                    TrainingData.is_active.is_(True),
                )
            )
            rec = result.scalar_one_or_none()
            if rec is None:
                return False

            if content is not None:
                stripped = content.strip()
                if not stripped:
                    raise ValueError("Le contenu ne peut pas être vide")
                if len(stripped) > _MAX_DOC_SIZE:
                    raise ValueError(f"Contenu trop volumineux ({len(stripped)} chars)")
                rec.content = stripped

            metadata = dict(rec.extra_metadata) if isinstance(rec.extra_metadata, dict) else {}
            if tags_tables is not None:
                normalized = self._normalize_tags_tables(tags_tables)
                if not normalized:
                    raise ValueError("tags_tables doit contenir au moins une table")
                metadata["tags_tables"] = normalized
            if priority is not None:
                try:
                    metadata["priority"] = int(priority)
                except (TypeError, ValueError):
                    pass

            if promote_to_manual and rec.source.startswith(VIEW_MINING_SOURCE_PREFIX):
                suffix = rec.source[len(VIEW_MINING_SOURCE_PREFIX) :]
                rec.source = f"manual_override:{suffix}"
                metadata["auto_generated"] = False

            rec.extra_metadata = metadata
            rec.updated_at = clock.now()
            await session.commit()
            logger.info("business_context mis à jour (id=%s)", record_id)
            return True

    @staticmethod
    def _normalize_tags(tags: Optional[List[str]]) -> Optional[str]:
        """Convertit une liste de tags en chaîne CSV stockée, ou ``None``.

        Lève ``ValueError`` si la longueur dépasse la borne SQL (``String(500)``).
        SQLite n'applique PAS cette limite au runtime — on la vérifie nous-mêmes
        pour éviter une data loss silencieuse lors d'une migration vers un
        backend strict (PostgreSQL, SQL Server).
        """
        if tags is None:
            return None
        if not isinstance(tags, (list, tuple)):
            raise ValueError("tags doit être une liste de chaînes")
        cleaned = [str(t).strip() for t in tags if str(t).strip()]
        if not cleaned:
            return None
        joined = ",".join(cleaned)
        if len(joined) > _MAX_TAGS_LEN:
            raise ValueError(f"tags trop longs ({len(joined)} chars, max {_MAX_TAGS_LEN})")
        return joined

    async def update_documentation(
        self,
        record_id: int,
        content: Optional[str] = None,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> bool:
        """Met à jour une documentation existante (type=DOCUMENTATION, non business_context).

        Args:
            record_id: ID du record.
            content: Nouveau texte (optionnel — conserve si None).
            category: Nouvelle catégorie (optionnel). Ne peut PAS devenir
                ``business_context`` via ce chemin (il faut passer par
                ``update_business_context`` pour les champs métadonnées).
            tags: Nouvelle liste de tags (optionnel). Liste vide = retrait.

        Returns:
            True si mis à jour, False si introuvable ou si c'est un business_context
            (route séparée pour garder la logique métadonnées).
        """
        async with get_session() as session:
            result = await session.execute(
                select(TrainingData).where(
                    TrainingData.id == record_id,
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.is_active.is_(True),
                )
            )
            rec = result.scalar_one_or_none()
            if rec is None:
                return False
            # Le business_context a sa propre route pour ne pas perdre ses
            # métadonnées (tags_tables, priority). Si l'appelant veut vraiment
            # éditer un BC, il doit passer par update_business_context.
            if rec.category == BUSINESS_CONTEXT_CATEGORY:
                return False

            if content is not None:
                stripped = content.strip()
                if not stripped:
                    raise ValueError("Le contenu ne peut pas être vide")
                if len(stripped) > _MAX_DOC_SIZE:
                    raise ValueError(
                        f"Contenu trop volumineux ({len(stripped)} chars, max {_MAX_DOC_SIZE})"
                    )
                rec.content = stripped

            if category is not None:
                cat = category.strip() or None
                # Interdit de transformer une doc normale en business_context
                # par ce chemin (changerait la sémantique de stockage).
                if cat == BUSINESS_CONTEXT_CATEGORY:
                    raise ValueError(
                        "Impossible de transformer une documentation en business_context"
                        " via cette route — utiliser update_business_context."
                    )
                if cat is not None and len(cat) > _MAX_CATEGORY_LEN:
                    raise ValueError(
                        f"category trop longue ({len(cat)} chars, max {_MAX_CATEGORY_LEN})"
                    )
                rec.category = cat

            if tags is not None:
                rec.tags = self._normalize_tags(tags)

            rec.updated_at = clock.now()
            await session.commit()
            logger.info("documentation mise à jour (id=%s)", record_id)
            return True

    async def update_ddl(
        self,
        record_id: int,
        content: Optional[str] = None,
        table_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> bool:
        """Met à jour un record DDL existant.

        Args:
            record_id: ID du record.
            content: Nouveau DDL (optionnel).
            table_name: Nouveau nom de table (optionnel — chaîne vide = retrait).
            tags: Nouvelle liste de tags (optionnel, liste vide = retrait).

        Returns:
            True si mis à jour, False si introuvable.
        """
        async with get_session() as session:
            result = await session.execute(
                select(TrainingData).where(
                    TrainingData.id == record_id,
                    TrainingData.data_type == TrainingDataType.DDL,
                    TrainingData.is_active.is_(True),
                )
            )
            rec = result.scalar_one_or_none()
            if rec is None:
                return False

            if content is not None:
                stripped = content.strip()
                if not stripped:
                    raise ValueError("Le DDL ne peut pas être vide")
                if len(stripped) > _MAX_DOC_SIZE:
                    raise ValueError(
                        f"DDL trop volumineux ({len(stripped)} chars, max {_MAX_DOC_SIZE})"
                    )
                rec.content = stripped

            if table_name is not None:
                name = table_name.strip() or None
                if name is not None and len(name) > _MAX_TABLE_NAME_LEN:
                    raise ValueError(
                        f"table_name trop long ({len(name)} chars, max {_MAX_TABLE_NAME_LEN})"
                    )
                rec.table_name = name

            if tags is not None:
                rec.tags = self._normalize_tags(tags)

            rec.updated_at = clock.now()
            await session.commit()
            logger.info("DDL mis à jour (id=%s, table=%s)", record_id, rec.table_name)
            return True

    async def update_question_sql(
        self,
        record_id: int,
        question: Optional[str] = None,
        sql: Optional[str] = None,
        tags: Optional[List[str]] = None,
        quality_score: Optional[float] = None,
        validate_on_sage: bool = True,
    ) -> bool:
        """Met à jour une paire question/SQL existante.

        Args:
            record_id: ID du record.
            question: Nouvelle question (optionnel).
            sql: Nouveau SQL (optionnel).
            tags: Nouvelle liste de tags (optionnel, liste vide = retrait).
            quality_score: Score qualité 0.0-1.0 (optionnel).

        Returns:
            True si mis à jour, False si introuvable.

        Raises:
            ValueError: SQL/question vide, trop volumineux, ou SQL contenant
                une opération interdite (validation SSoT _validate_training_sql).
            SQLValidationError: le dry-run du SQL échoue sur le serveur actif
                (``validate_on_sage=True``, défaut).
        """
        # Valide le SQL AVANT d'ouvrir la session : le dry-run Sage peut durer
        # (timeout 15s) → ne pas tenir la session SQLite ouverte (anti
        # "database is locked"). Même validation SSoT que add_question_sql :
        # une édition admin ne doit pas injecter un SQL dangereux/cassé.
        stripped_sql: Optional[str] = None
        if sql is not None:
            stripped_sql = sql.strip()
            if not stripped_sql:
                raise ValueError("Le SQL ne peut pas être vide")
            if len(stripped_sql) > _MAX_DOC_SIZE:
                raise ValueError(
                    f"SQL trop volumineux ({len(stripped_sql)} chars, max {_MAX_DOC_SIZE})"
                )
            await self._validate_training_sql(
                stripped_sql,
                validate_on_sage=validate_on_sage,
                rls_source="update_question_sql_dryrun",
            )

        async with get_session() as session:
            result = await session.execute(
                select(TrainingData).where(
                    TrainingData.id == record_id,
                    TrainingData.data_type == TrainingDataType.QUESTION_SQL,
                    TrainingData.is_active.is_(True),
                )
            )
            rec = result.scalar_one_or_none()
            if rec is None:
                return False

            if question is not None:
                stripped = question.strip()
                if not stripped:
                    raise ValueError("La question ne peut pas être vide")
                rec.question = stripped

            if stripped_sql is not None:
                rec.sql = stripped_sql
                # content reste synchrone avec sql pour cohérence avec add_question_sql
                rec.content = stripped_sql

            if tags is not None:
                rec.tags = self._normalize_tags(tags)

            if quality_score is not None:
                # bool est une sous-classe de int en Python — on rejette
                # explicitement sinon True/False seraient convertis en 1.0/0.0
                # et stockés comme un score réel.
                if isinstance(quality_score, bool):
                    raise ValueError("quality_score doit être un nombre, pas un booléen")
                try:
                    qs = float(quality_score)
                except (TypeError, ValueError) as exc:
                    raise ValueError("quality_score doit être un nombre entre 0 et 1") from exc
                # math.isnan attrape NaN (qui passe silencieusement les bornes
                # < 0 et > 1 sinon)
                if qs != qs or qs < 0.0 or qs > 1.0:  # qs != qs detects NaN
                    raise ValueError("quality_score doit être entre 0.0 et 1.0")
                rec.quality_score = qs

            rec.updated_at = clock.now()
            await session.commit()
            logger.info("question_sql mis à jour (id=%s)", record_id)
            return True

    async def delete_business_context(self, record_id: int) -> bool:
        """Soft-delete un business_context (is_active = False)."""
        async with get_session() as session:
            result = await session.execute(
                select(TrainingData).where(
                    TrainingData.id == record_id,
                    TrainingData.category == BUSINESS_CONTEXT_CATEGORY,
                )
            )
            rec = result.scalar_one_or_none()
            if rec is None:
                return False
            rec.is_active = False
            rec.updated_at = clock.now()
            await session.commit()
            logger.info("business_context désactivé (id=%s)", record_id)
            return True

    async def upsert_auto_business_contexts(
        self,
        drafts: List[Dict[str, Any]],
        source_key: str,
    ) -> int:
        """Régénère les business_context auto pour une source donnée.

        Utilisée par view_miner au moment du sync. Idempotent :
        1. Désactive TOUS les business_context actifs avec source == source_key
           (permet de "refaire" la mine de la même vue proprement).
        2. Insère les nouveaux drafts avec cette source.
        3. Ne touche JAMAIS aux docs source != source_key
           (donc aucune doc manuelle ni venant d'une AUTRE vue n'est impactée).

        Args:
            drafts: Liste de dicts avec au moins {content, tags_tables, priority}.
            source_key: Identifiant de source (ex: "view_mining:viewLignesFactures05").
                Doit commencer par VIEW_MINING_SOURCE_PREFIX pour rester cohérent
                avec le flag auto_generated.

        Returns:
            Nombre de drafts effectivement insérés (dédupe exclusivement par contenu).
        """
        if not drafts:
            # Cas particulier : vue vide de patterns → on désactive simplement l'ancien
            try:
                async with get_session() as session:
                    await session.execute(
                        update(TrainingData)
                        .where(
                            TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                            TrainingData.category == BUSINESS_CONTEXT_CATEGORY,
                            TrainingData.source == source_key,
                            TrainingData.is_active.is_(True),
                        )
                        .values(is_active=False, updated_at=clock.now())
                    )
                    await session.commit()
            except Exception as exc:
                logger.warning("upsert_auto: deactivate failed for %s: %s", source_key, exc)
            return 0

        try:
            # 1. Désactive tout l'existant pour cette source
            async with get_session() as session:
                await session.execute(
                    update(TrainingData)
                    .where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.category == BUSINESS_CONTEXT_CATEGORY,
                        TrainingData.source == source_key,
                        TrainingData.is_active.is_(True),
                    )
                    .values(is_active=False, updated_at=clock.now())
                )
                await session.commit()
        except Exception as exc:
            logger.warning("upsert_auto: deactivate failed for %s: %s", source_key, exc)
            return 0

        # 2. Insère les nouveaux drafts (dédupe par content à l'intérieur du batch)
        seen_contents = set()
        created = 0
        for draft in drafts:
            content = draft.get("content")
            tags = draft.get("tags_tables")
            priority = draft.get("priority", 1)
            if not content or not tags:
                continue
            content = content.strip()
            if not content or content in seen_contents:
                continue
            seen_contents.add(content)
            try:
                await self.add_business_context(
                    content=content,
                    tags_tables=tags,
                    priority=priority,
                    source=source_key,
                    user_id=None,
                    primary_table=draft.get("primary_table"),
                )
                created += 1
            except ValueError as exc:
                logger.warning("upsert_auto: skip invalid draft (%s): %s", source_key, exc)
            except Exception as exc:
                logger.warning(
                    "upsert_auto: insert failed for %s: %s",
                    source_key,
                    exc,
                    exc_info=True,
                )
        logger.info(
            "upsert_auto_business_contexts: %d docs créés pour source=%s",
            created,
            source_key,
        )
        return created


# Singleton
_training_store: Optional[TrainingStore] = None


def get_training_store() -> TrainingStore:
    """Récupère le singleton TrainingStore."""
    global _training_store
    if _training_store is None:
        _training_store = TrainingStore()
    return _training_store
