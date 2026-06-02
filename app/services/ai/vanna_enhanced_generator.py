"""
VannaEnhancedGenerator - Générateur SQL IA.

Architecture:
- RAG (Retrieval Augmented Generation) avec TF-IDF
- Auto-correction itérative (2 tentatives)
- Raccourci RAG direct pour les requêtes connues (score >= 0.45)
- Validation pre-execution (tables, CTEs, vues)
- Configuration dynamique via GUI
"""

import re
import time
import json
import asyncio
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from enum import Enum

from sqlalchemy.exc import SQLAlchemyError

from app.core import clock
from app.services.ai.llm_providers import LLMRequest, get_llm_manager
from app.services.ai.sql_validator import SQLValidator, ValidationError
from app.services.ai.training_store import get_training_store
from app.services.query_cache import get_cache
from app.constants_ai import (
    DEFAULT_TEMPERATURE,
    GENERATOR_MAX_RETRIES,
    GENERATOR_MAX_RESULTS,
    GENERATOR_TIMEOUT,
    GENERATOR_CONFIDENCE_THRESHOLD,
    GENERATOR_DEFAULT_LANGUAGE,
    RAG_SHORTCUT_THRESHOLD,
    RAG_COVERAGE_THRESHOLD,
    SQL_CANDIDATES_COUNT,
    SQL_CANDIDATE_TEMPERATURES,
)
from app.services.ai.confidence_calibrator import (
    calibrate,
    SQLCandidate,
)

from app.utils.logger import get_logger
from app.utils.sql_scan import skip_sql_string

logger = get_logger(__name__)

# Taille max d'une question utilisateur
_MAX_QUESTION_LENGTH = 5000

# Patterns de prompt injection à détecter
_INJECTION_PATTERNS = [
    r"ignore\s+(previous|all|above|prior)\s+instructions",
    r"(system|assistant|user)\s*:",
    r"###\s*(system|instruction|prompt)",
    r"<\s*(system|prompt|instruction)",
    r"you\s+are\s+now\s+",
    r"forget\s+(everything|all|your)",
    r"new\s+instructions?\s*:",
    r"do\s+not\s+follow",
    r"disregard\s+(all|previous|the)",
]
_INJECTION_RE = re.compile("|".join(_INJECTION_PATTERNS), re.IGNORECASE)


def _sanitize_question(question: str) -> str:
    """Valide et nettoie la question utilisateur contre le prompt injection."""
    if len(question) > _MAX_QUESTION_LENGTH:
        raise ValueError(
            f"Question trop longue ({len(question)} chars, max {_MAX_QUESTION_LENGTH})"
        )

    if _INJECTION_RE.search(question):
        logger.warning("Prompt injection détecté dans la question: %.100s...", question)
        raise ValueError("Question rejetée : contenu suspect détecté")

    return question.strip()


class GenerationStatus(str, Enum):
    """Statut de génération SQL."""

    SUCCESS = "success"
    VALIDATION_ERROR = "validation_error"
    EXECUTION_ERROR = "execution_error"
    SYNTAX_ERROR = "syntax_error"
    TIMEOUT = "timeout"
    LLM_ERROR = "llm_error"
    MAX_RETRIES = "max_retries"
    NO_SCHEMA = "no_schema"


@dataclass
class GenerationAttempt:
    """Enregistrement d'une tentative de génération."""

    sql: str
    status: GenerationStatus
    error: Optional[str] = None
    duration_seconds: float = 0.0
    model: str = ""
    provider: str = ""

    # Tokens
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None


@dataclass
class GenerationResult:
    """Résultat complet de la génération SQL."""

    question: str
    sql: str
    status: GenerationStatus

    # Métriques
    total_attempts: int = 1
    total_duration_seconds: float = 0.0
    from_cache: bool = False

    # Contexte
    model_provider: str = ""
    model_name: str = ""
    temperature: float = DEFAULT_TEMPERATURE

    # RAG
    rag_ddl_count: int = 0
    rag_doc_count: int = 0
    rag_example_count: int = 0
    confidence_score: float = 0.0

    # Tokens (agrégés sur toutes les tentatives)
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None

    # Historique des tentatives (pour debug)
    attempts: List[GenerationAttempt] = field(default_factory=list)

    # Multi-candidats
    candidates: List[Any] = field(default_factory=list)
    consensus_score: float = 0.0
    confidence_action: str = ""  # "execute", "confirm", "clarify"

    # Erreurs
    error_message: Optional[str] = None

    # Timestamp
    generated_at: str = ""


# System prompt concis pour modèle capable
def _get_system_prompt() -> str:
    """Génère le system prompt dynamiquement avec le label de la BDD."""
    try:
        from app.config import get_config

        db_label = get_config().sage.label
    except Exception:
        db_label = "SQL Server"
    return f"""Tu es un expert SQL Server / T-SQL spécialisé dans la base {db_label}.
Génère UNIQUEMENT une requête SELECT (ou WITH ... SELECT pour les CTEs).
Pas de markdown, pas d'explication, juste le SQL."""


CORRECTION_PROMPT = """La requête précédente a produit une erreur:
{error}

SQL rejeté:
{previous_sql}
{rag_tables}
Corrige en respectant exactement les noms de tables/colonnes fournis dans le schéma.
Question: {question}

SQL corrigé:"""


class VannaEnhancedGenerator:
    """
    Générateur SQL IA.

    1. RAG shortcut pour requêtes connues (score >= 0.45)
    2. Génération LLM avec contexte RAG (DDL + docs + few-shot)
    3. Auto-correction itérative (2 tentatives max)
    4. Validation pre-execution (tables, CTEs, vues)
    5. Apprentissage automatique des corrections
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialise le générateur.

        Args:
            config: Configuration optionnelle (sinon chargée depuis la BDD)
        """
        # Configuration par défaut
        self.config = config or {}
        self._config_loaded = bool(config)  # True si config fournie explicitement
        self._load_default_config()

        # Composants
        self.validator = SQLValidator(
            default_top=self.config["max_results"], max_results=self.config["max_results"]
        )
        self._llm_manager = None
        self._training_store = None
        self._cache = None

        logger.info("VannaEnhancedGenerator initialisé (config BDD chargée au premier appel)")

    async def _ensure_config_loaded(self):
        """Charge la configuration depuis la BDD au premier appel."""
        if self._config_loaded:
            return
        self._config_loaded = True

        try:
            from app.services.ai.config_service import get_ai_config_service

            config_service = get_ai_config_service()
            db_config = await config_service.get_all()

            if db_config:
                # Mapper les clés de la BDD vers les clés internes du générateur
                key_mapping = {
                    "primary_provider": "primary_provider",
                    "primary_model": "primary_model",
                    "temperature": "temperature",
                    "max_retries": "max_retries",
                    "max_results": "max_results",
                    "timeout_seconds": "timeout_seconds",
                    "confidence_threshold": "confidence_threshold",
                    "cache_enabled": "use_cache",
                    "use_cache": "use_cache",
                    "enable_auto_learning": "auto_learn",
                    "auto_learn": "auto_learn",
                    "log_performance": "log_performance",
                    "use_rag": "use_rag",
                }

                for db_key, internal_key in key_mapping.items():
                    if db_key in db_config and db_config[db_key] is not None:
                        value = db_config[db_key]
                        # Conversion de types
                        if internal_key in ("temperature", "confidence_threshold"):
                            value = float(value)
                        elif internal_key in ("max_retries", "max_results", "timeout_seconds"):
                            value = int(value)
                        elif internal_key in (
                            "use_cache",
                            "auto_learn",
                            "log_performance",
                            "use_rag",
                        ):
                            value = bool(value)
                        self.config[internal_key] = value

                # Mettre à jour le validateur avec max_results
                self.validator = SQLValidator(
                    default_top=self.config["max_results"], max_results=self.config["max_results"]
                )

                logger.info(
                    "Config chargée depuis la BDD: provider=%s, model=%s, temp=%s, "
                    "retries=%s, rag=%s",
                    self.config["primary_provider"],
                    self.config["primary_model"],
                    self.config["temperature"],
                    self.config["max_retries"],
                    self.config["use_rag"],
                )
        except (ConnectionError, asyncio.TimeoutError, OSError, SQLAlchemyError) as e:
            logger.warning(
                "Impossible de charger la config depuis la BDD, utilisation des défauts: %s", e
            )

    def _load_default_config(self):
        """Charge la configuration par défaut.

        ``primary_model`` est laissé vide ici — le ``llm_manager`` résout
        dynamiquement le modèle depuis le registre central (BDD ou défaut
        provider) si on ne lui passe rien. Hardcoder un nom de modèle ici
        deviendrait obsolète à chaque release et ignorerait le choix de
        l'admin via UI.
        """
        from app.constants_ai import ANTHROPIC_DEFAULT_MODEL

        defaults = {
            "primary_provider": "anthropic",
            "primary_model": ANTHROPIC_DEFAULT_MODEL,
            "temperature": DEFAULT_TEMPERATURE,
            "max_retries": GENERATOR_MAX_RETRIES,
            "max_results": GENERATOR_MAX_RESULTS,
            "use_rag": True,
            "use_cache": True,
            "log_performance": True,
            "auto_learn": True,
            "language": GENERATOR_DEFAULT_LANGUAGE,
            "timeout_seconds": GENERATOR_TIMEOUT,
            "confidence_threshold": GENERATOR_CONFIDENCE_THRESHOLD,
        }

        for key, default in defaults.items():
            if key not in self.config:
                self.config[key] = default

    async def _get_llm_manager(self):
        """Lazy load du LLM manager."""
        if self._llm_manager is None:
            from app.services.ai.llm_providers import ensure_providers_from_db

            await ensure_providers_from_db()
            self._llm_manager = get_llm_manager()
        return self._llm_manager

    async def _get_training_store(self):
        """Lazy load du training store."""
        if self._training_store is None and self.config["use_rag"]:
            try:
                self._training_store = get_training_store()
            except (json.JSONDecodeError, ValueError, KeyError) as e:
                logger.warning("TrainingStore non disponible: %s", e)
        return self._training_store

    def _get_cache(self):
        """Lazy load du cache."""
        if self._cache is None:
            self._cache = get_cache()
        return self._cache

    def _build_system_prompt(self) -> str:
        """Construit le system prompt (concis, pas de RAG ici)."""
        return _get_system_prompt()

    async def _try_rag_shortcut(
        self,
        question: str,
        user_id: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Vérifie si un exemple Q/SQL du RAG correspond suffisamment bien
        pour être utilisé directement sans passer par le LLM.

        Conditions:
         1. Score TF-IDF >= 0.45 (correspondance forte)
         2. Couverture >= 0.80 : les tokens significatifs de la question
            de l'utilisateur doivent être présents dans la question stockée.
            Sinon l'utilisateur demande quelque chose de plus spécifique
            (ex: filtre sur un exercice, un client…) et le SQL stocké
            ne couvrira pas la demande.
         3. SQL validé syntaxiquement.

        Returns:
            Dict avec 'sql', 'score', et 'all_candidates' si match, None sinon.
        """
        store = await self._get_training_store()
        if not store:
            return None

        # Phase α.4 (#60) — stub user pour mode invisible.
        user_stub: Any = None
        if user_id is not None:
            from types import SimpleNamespace

            user_stub = SimpleNamespace(id=user_id, role=None)

        try:
            examples = await store.get_similar_question_sql(
                question,
                n_results=SQL_CANDIDATES_COUNT,
                question_only=True,
                user=user_stub,
            )
            if not examples:
                return None

            best = examples[0]
            score = best.get("score", 0)
            sql = best.get("sql", "")

            if score < RAG_SHORTCUT_THRESHOLD or not sql:
                logger.debug("RAG shortcut: score %.3f < seuil %s", score, RAG_SHORTCUT_THRESHOLD)
                return None

            # Vérifier la couverture : les tokens de la question utilisateur
            # doivent être couverts par la question stockée.
            # Si l'utilisateur ajoute des termes spécifiques (date, exercice,
            # nom de client…) absents de la question stockée, le shortcut
            # ne doit pas se déclencher.
            from app.services.ai.training_store import SimpleTextSearch

            user_tokens = set(SimpleTextSearch.tokenize(question))
            stored_q = best.get("question", "")
            stored_tokens = set(SimpleTextSearch.tokenize(stored_q))

            if user_tokens:
                covered = len(user_tokens & stored_tokens)
                coverage = covered / len(user_tokens)
            else:
                coverage = 0.0

            if coverage < RAG_COVERAGE_THRESHOLD:
                uncovered = user_tokens - stored_tokens
                logger.info(
                    "RAG near-miss: couverture %.0f%% < %.0f%%, "
                    "tokens manquants: %s → template pour le LLM",
                    coverage * 100,
                    RAG_COVERAGE_THRESHOLD * 100,
                    uncovered,
                )
                # Retourner en mode near-miss : le LLM adaptera ce SQL
                all_candidates = []
                for ex in examples:
                    try:
                        ex_sql = ex.get("sql", "")
                        if ex_sql:
                            validation = self.validator.validate(
                                ex_sql, add_top=False, check_tables=True
                            )
                            if validation["valid"]:
                                all_candidates.append(
                                    SQLCandidate(
                                        sql=validation.get("corrected_sql", ex_sql),
                                        source="rag_example",
                                        validation_passed=True,
                                    )
                                )
                    except (ValueError, KeyError):
                        pass

                return {
                    "near_miss": True,
                    "sql": sql,
                    "score": score,
                    "question": stored_q,
                    "uncovered_tokens": uncovered,
                    "all_candidates": all_candidates,
                }

            # Valider le SQL avant de l'utiliser (pas de TOP ajouté: SQL de confiance)
            try:
                validation = self.validator.validate(sql, add_top=False, check_tables=True)
                if validation["valid"]:
                    validated_sql = validation.get("corrected_sql", sql)
                    logger.info(
                        "RAG shortcut match: score=%.3f, couverture=%.0f%%, question='%s'",
                        score,
                        coverage * 100,
                        stored_q[:80],
                    )
                    # Collecter tous les candidats valides du RAG
                    all_candidates = []
                    for ex in examples:
                        try:
                            ex_sql = ex.get("sql", "")
                            if ex_sql:
                                ex_validation = self.validator.validate(
                                    ex_sql, add_top=False, check_tables=True
                                )
                                if ex_validation["valid"]:
                                    all_candidates.append(
                                        SQLCandidate(
                                            sql=ex_validation.get("corrected_sql", ex_sql),
                                            source="rag_example",
                                            validation_passed=True,
                                        )
                                    )
                        except (ValueError, KeyError):
                            pass

                    return {
                        "sql": validated_sql,
                        "score": score,
                        "all_candidates": all_candidates,
                    }
                else:
                    logger.debug("RAG shortcut SQL invalide: %s", validation.get("errors", []))
                    return None
            except (ValueError, KeyError):
                return None

        except (ConnectionError, asyncio.TimeoutError, OSError) as e:
            logger.debug("RAG shortcut erreur: %s", e)
            return None

    async def _get_rag_context(
        self,
        question: str,
        user_id: Optional[int] = None,
    ) -> Tuple[str, Dict[str, int], float]:
        """
        Récupère le contexte RAG avec scoring de confiance.

        Returns:
            (contexte, counts, score_confiance)
        """
        store = await self._get_training_store()
        if not store:
            return "", {"ddl": 0, "doc": 0, "examples": 0}, 0.0

        parts = []
        counts = {"ddl": 0, "doc": 0, "examples": 0}
        total_score = 0.0

        # Phase α.4 (#60) — stub user pour mode invisible.
        user_stub: Any = None
        if user_id is not None:
            from types import SimpleNamespace

            user_stub = SimpleNamespace(id=user_id, role=None)

        try:
            # 1. DDL pertinents (schéma des tables) — max 5
            ddls = await store.get_related_ddl(question, n_results=5, user=user_stub)
            if ddls:
                parts.append("--- Schéma des tables pertinentes ---")
                for ddl in ddls:
                    content = ddl.get("content", str(ddl)) if isinstance(ddl, dict) else str(ddl)
                    parts.append(content)
                counts["ddl"] = len(ddls)
                total_score += len(ddls) * 0.1
                parts.append("")

            # 2. Documentation métier — max 3
            docs = await store.get_related_documentation(question, n_results=3)
            if docs:
                parts.append("--- Contexte métier ---")
                for doc in docs:
                    content = doc.get("content", str(doc)) if isinstance(doc, dict) else str(doc)
                    parts.append(content)
                counts["doc"] = len(docs)
                total_score += len(docs) * 0.15
                parts.append("")

            # 3. Exemples Q/SQL (few-shot) — max 5, dédupliqués
            # Phase α.4 (#60) — propager user.
            examples = await store.get_similar_question_sql(question, n_results=8, user=user_stub)
            if examples:
                parts.append("--- Exemples de requêtes similaires ---")
                seen_sql = set()
                unique_count = 0
                for ex in examples:
                    q = ex.get("question", "")
                    sql = ex.get("sql", "")
                    # Déduplication par contenu SQL normalisé
                    sql_key = " ".join(sql.split()).upper()
                    if sql_key in seen_sql:
                        continue
                    seen_sql.add(sql_key)
                    parts.append(f"Q: {q}")
                    parts.append(f"SQL: {sql}")
                    parts.append("")
                    unique_count += 1
                    if unique_count >= 5:
                        break
                counts["examples"] = unique_count
                total_score += unique_count * 0.2

            confidence = min(total_score, 1.0)

        except (ConnectionError, asyncio.TimeoutError, ValueError, SQLAlchemyError) as e:
            logger.warning("Erreur récupération RAG: %s", e)
            return "", counts, 0.0

        return "\n".join(parts), counts, confidence

    def _build_user_prompt(
        self,
        question: str,
        rag_context: str = "",
        error_context: Optional[str] = None,
        previous_sql: Optional[str] = None,
        sql_template: Optional[str] = None,
    ) -> str:
        """Construit le prompt utilisateur avec le contexte RAG.

        La question est sanitisée en amont par _sanitize_question().
        """

        # Mode correction (retry après erreur)
        if error_context and previous_sql:
            rag_tables = ""
            if rag_context:
                rag_tables = f"\nContexte disponible:\n{rag_context}\n"
            return CORRECTION_PROMPT.format(
                error=error_context,
                previous_sql=previous_sql,
                question=question,
                rag_tables=rag_tables,
            )

        parts = []

        # Mode template: un SQL très proche existe, le LLM doit juste
        # fournir la clause filtre à ajouter (pas reproduire le SQL)
        if sql_template:
            parts.append(
                "Une requête SQL de référence existe déjà (elle fait "
                f"{len(sql_template)} caractères, ne la reproduis PAS)."
            )
            parts.append("")
            parts.append("Génère UNIQUEMENT la clause SQL à ajouter " "(WHERE, AND, HAVING, etc.).")
            parts.append("Ne reproduis PAS la requête. Juste la clause filtre.")
            parts.append("")
            # Donner le schéma de la requête externe pour contexte
            # (colonnes disponibles dans le SELECT externe)
            outer_cols = self._extract_outer_columns(sql_template)
            if outer_cols:
                parts.append(f"Colonnes disponibles: {', '.join(outer_cols)}")
                parts.append("")
            parts.append(f"Question utilisateur: {question}")
            parts.append("")
            parts.append(
                "Exemples de formats attendus:\n"
                "WHERE colonne_filtrage = 'valeur'\n"
                "WHERE colonne1 = 'valeur1' AND colonne2 = 'valeur2'\n"
                "HAVING SUM(colonne_montant) > 1000"
            )
            parts.append("")
            parts.append("Clause à ajouter:")
            return "\n".join(parts)

        # Mode standard: contexte RAG + question
        if rag_context:
            parts.append(rag_context)
            parts.append("")

        parts.append(f"Question: {question}")
        parts.append("")
        parts.append("SQL:")

        return "\n".join(parts)

    @staticmethod
    def _extract_outer_columns(sql: str) -> List[str]:
        """
        Extrait les noms de colonnes du SELECT externe
        (après la fermeture de la dernière CTE).
        """
        # Trouver le SELECT principal (hors CTE)
        depth = 0
        main_select_pos = None
        sql_upper = sql.upper()
        for i in range(len(sql)):
            if sql[i] == "(":
                depth += 1
            elif sql[i] == ")":
                depth -= 1
            elif depth == 0 and sql_upper[i : i + 6] == "SELECT":
                before_ok = i == 0 or not sql[i - 1].isalnum()
                after_ok = i + 6 >= len(sql) or not sql[i + 6].isalnum()
                if before_ok and after_ok:
                    main_select_pos = i

        if main_select_pos is None:
            return []

        # Extraire entre SELECT et FROM
        from_match = re.search(r"\bFROM\b", sql[main_select_pos:], re.IGNORECASE)
        if not from_match:
            return []

        select_clause = sql[main_select_pos + 6 : main_select_pos + from_match.start()]

        # Parser les colonnes (alias AS ou dernier mot)
        cols = []
        for item in select_clause.split(","):
            item = item.strip()
            if not item:
                continue
            # Chercher alias: ... AS alias
            as_match = re.search(r"\bAS\s+(\w+)\s*$", item, re.IGNORECASE)
            if as_match:
                cols.append(as_match.group(1))
            else:
                # Dernière partie (nom de colonne)
                parts = item.split()
                if parts:
                    last = parts[-1].strip()
                    # Enlever qualifier (table.col)
                    if "." in last:
                        last = last.split(".")[-1]
                    cols.append(last)
        return cols

    @staticmethod
    def _inject_sql_clause(template_sql: str, clause: str) -> str:
        """
        Injecte une clause WHERE/HAVING/AND dans le template SQL.

        Stratégie:
        - Si clause commence par WHERE et le SQL n'a pas de WHERE
          → insérer avant GROUP BY / ORDER BY / fin
        - Si clause commence par WHERE et le SQL a déjà WHERE
          → ajouter comme AND
        - Si clause commence par HAVING
          → insérer avant ORDER BY / fin
        - Si clause commence par AND
          → ajouter dans le WHERE existant
        """
        clause = clause.strip().rstrip(";").strip()
        if not clause:
            return template_sql

        clause_upper = clause.upper()

        # Trouver les positions clés dans le SQL principal
        # (hors parenthèses pour éviter les sous-requêtes)
        def find_keyword_at_depth0(sql, keyword):
            depth = 0
            kw_upper = keyword.upper()
            kw_len = len(keyword)
            i = 0
            while i < len(sql):
                if sql[i] == "'":
                    i = skip_sql_string(sql, i)
                elif sql[i] == "(":
                    depth += 1
                    i += 1
                elif sql[i] == ")":
                    depth -= 1
                    i += 1
                elif depth == 0:
                    chunk = sql[i : i + kw_len].upper()
                    if chunk == kw_upper:
                        before_ok = i == 0 or not sql[i - 1].isalnum()
                        after_ok = i + kw_len >= len(sql) or not sql[i + kw_len].isalnum()
                        if before_ok and after_ok:
                            return i
                    i += 1
                else:
                    i += 1
            return -1

        where_pos = find_keyword_at_depth0(template_sql, "WHERE")
        group_pos = find_keyword_at_depth0(template_sql, "GROUP BY")
        order_pos = find_keyword_at_depth0(template_sql, "ORDER BY")
        having_pos = find_keyword_at_depth0(template_sql, "HAVING")

        if clause_upper.startswith("WHERE "):
            condition = clause[6:].strip()  # enlever "WHERE "
            if where_pos >= 0:
                # WHERE existe déjà → ajouter comme AND
                # Trouver la fin du WHERE (avant GROUP/HAVING/ORDER)
                end_pos = len(template_sql)
                for pos in [group_pos, having_pos, order_pos]:
                    if pos > where_pos and pos < end_pos:
                        end_pos = pos
                insert_at = end_pos
                return (
                    template_sql[:insert_at].rstrip()
                    + "\n    AND "
                    + condition
                    + "\n"
                    + template_sql[insert_at:]
                )
            else:
                # Pas de WHERE → insérer avant GROUP/ORDER/fin
                insert_before = len(template_sql)
                for pos in [group_pos, order_pos]:
                    if 0 <= pos < insert_before:
                        insert_before = pos
                return (
                    template_sql[:insert_before].rstrip()
                    + "\nWHERE "
                    + condition
                    + "\n"
                    + template_sql[insert_before:]
                )

        elif clause_upper.startswith("AND "):
            if where_pos >= 0:
                end_pos = len(template_sql)
                for pos in [group_pos, having_pos, order_pos]:
                    if pos > where_pos and pos < end_pos:
                        end_pos = pos
                return (
                    template_sql[:end_pos].rstrip()
                    + "\n    "
                    + clause
                    + "\n"
                    + template_sql[end_pos:]
                )
            else:
                # Pas de WHERE → convertir AND en WHERE
                condition = clause[4:].strip()
                insert_before = len(template_sql)
                for pos in [group_pos, order_pos]:
                    if 0 <= pos < insert_before:
                        insert_before = pos
                return (
                    template_sql[:insert_before].rstrip()
                    + "\nWHERE "
                    + condition
                    + "\n"
                    + template_sql[insert_before:]
                )

        elif clause_upper.startswith("HAVING "):
            insert_before = order_pos if order_pos >= 0 else len(template_sql)
            return (
                template_sql[:insert_before].rstrip()
                + "\n"
                + clause
                + "\n"
                + template_sql[insert_before:]
            )

        else:
            # Clause inconnue → traiter comme WHERE condition
            insert_before = len(template_sql)
            for pos in [group_pos, order_pos]:
                if 0 <= pos < insert_before:
                    insert_before = pos
            if where_pos >= 0:
                end_pos = len(template_sql)
                for pos in [group_pos, having_pos, order_pos]:
                    if pos > where_pos and pos < end_pos:
                        end_pos = pos
                return (
                    template_sql[:end_pos].rstrip()
                    + "\n    AND "
                    + clause
                    + "\n"
                    + template_sql[end_pos:]
                )
            return (
                template_sql[:insert_before].rstrip()
                + "\nWHERE "
                + clause
                + "\n"
                + template_sql[insert_before:]
            )

    def _extract_sql(self, response: str) -> str:
        """Extrait et nettoie le SQL de la réponse LLM."""
        sql = response.strip()

        # Markdown code blocks
        match = re.search(r"```(?:sql)?\s*(.*?)\s*```", sql, re.DOTALL | re.IGNORECASE)
        if match:
            sql = match.group(1).strip()

        # Trouver WITH (CTE) d'abord, sinon SELECT
        match = re.search(r"(WITH\s+\w+\s+AS\s*\(.*)", sql, re.DOTALL | re.IGNORECASE)
        if not match:
            match = re.search(r"(SELECT\s+.*)", sql, re.DOTALL | re.IGNORECASE)
        if match:
            sql = match.group(1)

        # Retirer point-virgule final
        sql = sql.rstrip(";").strip()

        # Retirer commentaires/texte avant le SQL
        lines = []
        found_sql = False
        for line in sql.split("\n"):
            stripped = line.strip()
            upper = stripped.upper()
            if not found_sql and (upper.startswith("SELECT") or upper.startswith("WITH")):
                found_sql = True
            if found_sql:
                lines.append(line)

        return "\n".join(lines) if lines else sql

    async def _generate_once(
        self,
        question: str,
        rag_context: str,
        error_context: Optional[str] = None,
        previous_sql: Optional[str] = None,
        provider_name: Optional[str] = None,
        model_name: Optional[str] = None,
        sql_template: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> GenerationAttempt:
        """
        Une seule tentative de génération.
        """
        start_time = time.time()

        provider_name = provider_name or self.config["primary_provider"]
        model_name = model_name or self.config["primary_model"]

        try:
            manager = await self._get_llm_manager()
            manager.get_provider(provider_name)

            # Construire les prompts
            system_prompt = self._build_system_prompt()
            user_prompt = self._build_user_prompt(
                question,
                rag_context=rag_context,
                error_context=error_context,
                previous_sql=previous_sql,
                sql_template=sql_template,
            )

            # Log des prompts (taille uniquement — ne pas logger le contenu sensible)
            logger.info(
                "=== Prompt LLM (%s/%s) system=%dchars user=%dchars ===",
                provider_name,
                model_name,
                len(system_prompt),
                len(user_prompt),
            )
            logger.debug("[USER PROMPT PREVIEW] %s...", user_prompt[:500])

            # Appel LLM via le runtime unifié (route via le manager → hook
            # llm_call_tracker → dashboard. ``provider_name_override`` préserve
            # le routing explicite vers le provider configuré).
            #
            # Proxy d'anonymisation : couche PII regex sur ``user_prompt``
            # (qui contient la ``question`` NL utilisateur + RAG context +
            # éventuels SQL templates). ``user_id=None`` :
            # **Périmètre actuel de Vanna = admin/health-check
            # uniquement** (cf. ``app/handlers/ai_config.py:622`` —
            # `AIHealthCheckHandler` est le seul caller production).
            # Les call sites user-facing du SQL gen passent par
            # ``iris_one_shot``/``agent_service``/``orchestrator`` qui
            # ont leur propre wiring proxy avec ``user_id`` threadé.
            # Si à l'avenir vanna est rebranché dans le path user, il
            # FAUDRA threader ``user_id`` (ajouter un param à
            # ``_generate_once`` + propager). ``SCHEMA_ENRICH`` car
            # vanna est text2SQL — le bloc proxy informe le LLM de
            # préserver les placeholders ``[TYPE_N]`` dans le SQL généré.
            from app.services.anonymization import anonymize_for_llm
            from app.services.anonymization.proxy import get_confidentiality_prompt
            from app.services.ai.llm_runtime import CallProfile, call_llm

            user_prompt_anon, restore_fn = await anonymize_for_llm(
                None, user_prompt, "SCHEMA_ENRICH"
            )
            # OUTPUT_STYLE_RULES — **non injecté ici** (exemption documentée
            # sur le scope de task #19 / adversarial fix #18) : Vanna est
            # un générateur SQL pur, l'output est parsé et exécuté côté
            # serveur (pas affiché en texte naturel à l'user). Risque
            # mockup ASCII / jargon technique non sollicité = nul.
            system_with_block = get_confidentiality_prompt("SCHEMA_ENRICH") + "\n\n" + system_prompt
            response = await call_llm(
                CallProfile(
                    caller="vanna_generate",
                    provider_name_override=provider_name,
                ),
                LLMRequest(
                    prompt=user_prompt_anon,
                    system=system_with_block,
                    model=model_name,
                    temperature=(
                        temperature if temperature is not None else self.config["temperature"]
                    ),
                ),
            )
            # Restore PII placeholders dans le SQL généré : sinon un
            # ``WHERE email = '[EMAIL_1]'`` ne match aucune row Sage.
            # On NE mute PAS ``response.content`` (cf. EPIC E5 — divergence
            # ``raw_response`` / ``completion_tokens``, risque cache
            # poisoning futur). Variable locale ``content_restored``.
            content_restored = (
                restore_fn(response.content)
                if response is not None and getattr(response, "content", None)
                else (response.content if response is not None else "")
            )

            # Capturer les tokens de la réponse
            resp_prompt_tokens = response.prompt_tokens
            resp_completion_tokens = response.completion_tokens
            resp_total_tokens = response.total_tokens

            logger.info(
                "[LLM RESPONSE] %.1fs, %s tokens, %d chars",
                response.duration_seconds,
                resp_total_tokens or "?",
                len(content_restored),
            )
            logger.debug("[LLM RESPONSE CONTENT] %s...", content_restored[:500])

            # Mode template: le LLM renvoie juste la clause filtre
            # → on l'injecte dans le template SQL
            if sql_template and not error_context:
                clause = content_restored.strip()
                # Nettoyer markdown éventuel
                clause = re.sub(r"```(?:sql)?\s*|```", "", clause).strip()
                # Enlever les éventuels commentaires/texte avant
                for prefix in ("WHERE", "AND", "HAVING"):
                    idx = clause.upper().find(prefix)
                    if idx >= 0:
                        clause = clause[idx:]
                        break
                clause = clause.rstrip(";").strip()

                logger.info("[TEMPLATE PATCH] clause='%s'", clause)
                sql = self._inject_sql_clause(sql_template, clause)
                logger.info("[TEMPLATE RESULT] SQL patché (%d chars)", len(sql))
            else:
                # Extraire le SQL complet
                sql = self._extract_sql(content_restored)

            # Valider
            # En mode near-miss template, le SQL de base vient du
            # training (deja valide) -> skip table/qualifier checks
            skip_table_check = sql_template is not None
            try:
                validation = self.validator.validate(
                    sql,
                    check_tables=not skip_table_check,
                )
                if not validation["valid"]:
                    return GenerationAttempt(
                        sql=sql,
                        status=GenerationStatus.VALIDATION_ERROR,
                        error=validation.get("error", "Validation échouée"),
                        duration_seconds=time.time() - start_time,
                        model=model_name,
                        provider=provider_name,
                        prompt_tokens=resp_prompt_tokens,
                        completion_tokens=resp_completion_tokens,
                        total_tokens=resp_total_tokens,
                    )

                # Appliquer les corrections (TOP, etc.)
                sql = validation.get("corrected_sql", sql)

            except ValidationError as e:
                logger.error("Validation SQL échouée", exc_info=True)
                return GenerationAttempt(
                    sql=sql,
                    status=GenerationStatus.VALIDATION_ERROR,
                    error=f"Erreur de validation SQL ({type(e).__name__})",
                    duration_seconds=time.time() - start_time,
                    model=model_name,
                    provider=provider_name,
                    prompt_tokens=resp_prompt_tokens,
                    completion_tokens=resp_completion_tokens,
                    total_tokens=resp_total_tokens,
                )

            return GenerationAttempt(
                sql=sql,
                status=GenerationStatus.SUCCESS,
                duration_seconds=time.time() - start_time,
                model=model_name,
                provider=provider_name,
                prompt_tokens=resp_prompt_tokens,
                completion_tokens=resp_completion_tokens,
                total_tokens=resp_total_tokens,
            )

        except (ConnectionError, asyncio.TimeoutError, OSError) as e:
            logger.error("Erreur communication LLM", exc_info=True)
            return GenerationAttempt(
                sql="",
                status=GenerationStatus.LLM_ERROR,
                error=f"Erreur de communication LLM ({type(e).__name__})",
                duration_seconds=time.time() - start_time,
                model=model_name,
                provider=provider_name,
            )

    async def _assert_sql_safe_for_user(
        self,
        sql: str,
        user_id: Optional[int],
        question: str,
        *,
        context_label: str,
    ) -> None:
        """**Phase 2.5.bis.9 (#109)** — Garde-fou fail-closed mode invisible.

        Détecte la présence d'un nom de table denied (atomique OU via closure
        transitive) dans un SQL sur le point d'être retourné au caller
        user-facing. Raise ``DataAccessLeakDetectedError`` si leak — le caller
        doit catcher et propager ``blocked_by="data_access_rule"`` au consumer
        pour déclencher ``DATA_ACCESS_GUIDANCE`` côté prompt copilot.

        No-op si ``user_id is None`` (path système, pas retour user-facing).
        No-op si ``sql`` est vide ou None.

        Appelé aux 3 points de return SUCCESS du ``generate()`` : cache hit,
        RAG shortcut, et final LLM return — pour empêcher cache poisoning
        cross-user et bypass via raccourci RAG (adversarial review #109).
        """
        if user_id is None or not sql:
            return

        from types import SimpleNamespace

        from app.services.data_access.error_messages import (
            DataAccessLeakDetectedError,
            assert_safe_llm_response,
        )

        user_stub: Any = SimpleNamespace(id=user_id, role=None)
        leak_msg = await assert_safe_llm_response(
            sql,
            user_stub,
            context_label=context_label,
        )
        if leak_msg is not None:
            logger.critical(
                "vanna_enhanced_generator: SQL fuite un nom denied "
                "user_id=%s context=%s question_excerpt=%s",
                user_id,
                context_label,
                question[:100],
            )
            raise DataAccessLeakDetectedError(leak_msg)

    async def generate(
        self,
        question: str,
        use_cache: bool = True,
        user_id: Optional[int] = None,
    ) -> GenerationResult:
        """
        Génère une requête SQL avec auto-correction itérative.

        Args:
            question: Question en langage naturel
            use_cache: Utiliser le cache
            user_id: ID utilisateur pour logging

        Returns:
            GenerationResult avec SQL et métriques
        """
        start_time = time.time()

        # 0. Sanitiser la question (prompt injection, longueur)
        question = _sanitize_question(question)

        # 0b. Charger la config depuis la BDD si pas encore fait
        await self._ensure_config_loaded()

        # 1. Vérifier le cache
        if use_cache and self.config["use_cache"]:
            cache = self._get_cache()
            cached = cache.get(question, "")
            if cached:
                # **Phase 2.5.bis.9 (#109) — Anti cache poisoning cross-user.**
                # Le cache n'inclut pas ``user_id`` dans sa clé : un user A
                # sans deny peut peupler le cache avec un SQL référençant
                # une table T, et un user B avec deny sur T (atomique ou via
                # closure transitive) hit ce cache au lieu de regénérer.
                # Sans ce check, le user B verrait le nom T en clair.
                await self._assert_sql_safe_for_user(
                    cached,
                    user_id,
                    question,
                    context_label="vanna_enhanced_generator.generate.cache_hit",
                )
                return GenerationResult(
                    question=question,
                    sql=cached,
                    status=GenerationStatus.SUCCESS,
                    total_attempts=0,
                    total_duration_seconds=time.time() - start_time,
                    from_cache=True,
                    model_provider=self.config["primary_provider"],
                    model_name=self.config["primary_model"],
                    generated_at=clock.now().isoformat(),
                )

        # 2. Récupérer le contexte RAG
        # Phase α.4 (#60) : propager user_id.
        rag_context, rag_counts, confidence = await self._get_rag_context(question, user_id=user_id)

        # 2a. Blocage si aucun schéma connu (jamais de SQL à l'aveugle)
        if rag_counts.get("ddl", 0) == 0 and rag_counts.get("examples", 0) == 0:
            logger.warning("Génération SQL refusée: 0 DDL et 0 exemples dans le RAG")
            return GenerationResult(
                question=question,
                sql="",
                status=GenerationStatus.NO_SCHEMA,
                error_message=(
                    "Base de connaissances vide : aucun schéma de table disponible. "
                    "Impossible de générer du SQL sans connaissance de la structure "
                    "de la base de données. Lancez d'abord une synchronisation du schéma."
                ),
                total_attempts=0,
                total_duration_seconds=time.time() - start_time,
                confidence_score=0.0,
                generated_at=clock.now().isoformat(),
            )

        # 2b. Raccourci RAG: si un exemple Q/SQL correspond très bien,
        # utiliser son SQL directement au lieu de demander au LLM de le réinventer.
        # C'est crucial pour les modèles petits (7B) qui ne peuvent pas reproduire
        # fidèlement des requêtes complexes de 200+ lignes depuis le contexte.
        # Phase α.4 (#60) : propager user_id.
        rag_shortcut = await self._try_rag_shortcut(question, user_id=user_id)
        sql_template = None  # Near-miss: SQL à adapter par le LLM
        if rag_shortcut and not rag_shortcut.get("near_miss"):
            logger.info("RAG shortcut: exemple direct utilisé (score=%.3f)", rag_shortcut["score"])
            # **Phase 2.5.bis.9 (#109) — Anti bypass via raccourci RAG.**
            # Un exemple training peut contenir une table denied pour ce user
            # (atomique ou via closure transitive). Sans check ici, le SQL
            # de l'exemple est retourné sans passer par le check final +
            # peut empoisonner le cache. Garde-fou AVANT cache.set + return.
            await self._assert_sql_safe_for_user(
                rag_shortcut["sql"],
                user_id,
                question,
                context_label="vanna_enhanced_generator.generate.rag_shortcut",
            )
            if use_cache:
                cache = self._get_cache()
                cache.set(question, rag_shortcut["sql"], "")
            return GenerationResult(
                question=question,
                sql=rag_shortcut["sql"],
                status=GenerationStatus.SUCCESS,
                total_attempts=0,
                total_duration_seconds=time.time() - start_time,
                from_cache=False,
                model_provider="rag_direct",
                model_name="training_example",
                rag_ddl_count=rag_counts.get("ddl", 0),
                rag_doc_count=rag_counts.get("doc", 0),
                rag_example_count=rag_counts.get("examples", 0),
                confidence_score=rag_shortcut["score"],
                generated_at=clock.now().isoformat(),
            )
        elif rag_shortcut and rag_shortcut.get("near_miss"):
            sql_template = rag_shortcut["sql"]
            logger.info(
                "RAG near-miss: template SQL fourni au LLM (score=%.3f, tokens manquants: %s)",
                rag_shortcut["score"],
                rag_shortcut.get("uncovered_tokens", set()),
            )

        # 3. Génération itérative avec auto-correction
        attempts: List[GenerationAttempt] = []
        max_retries = self.config["max_retries"]

        for attempt_num in range(1, max_retries + 1):
            logger.info("Génération tentative %d/%d", attempt_num, max_retries)

            # Contexte d'erreur pour correction
            error_context = None
            previous_sql = None
            if attempts and attempts[-1].status != GenerationStatus.SUCCESS:
                error_context = attempts[-1].error
                previous_sql = attempts[-1].sql

            # Utiliser le provider principal
            active_provider = self.config["primary_provider"]
            active_model = self.config["primary_model"]

            attempt = await self._generate_once(
                question=question,
                rag_context=rag_context,
                error_context=error_context,
                previous_sql=previous_sql,
                provider_name=active_provider,
                model_name=active_model,
                sql_template=sql_template,
                temperature=SQL_CANDIDATE_TEMPERATURES[0] if attempt_num == 1 else None,
            )
            attempts.append(attempt)

            if attempt.status == GenerationStatus.SUCCESS:
                break

            # Si le primary échoue en LLM_ERROR (API down, crédits, etc.)
            # → arrêt immédiat, pas de fallback automatique.
            # Le RAG shortcut (étape 2b) gère déjà les requêtes connues.
            # Un fallback sur un modèle moins capable ne fait que gaspiller
            # du temps (~100s) pour des résultats toujours incorrects.
            if attempt.status == GenerationStatus.LLM_ERROR:
                logger.warning(
                    "Provider %s en erreur (%s). "
                    "Arrêt de la génération (pas de fallback automatique).",
                    active_provider,
                    attempt.error,
                )
                break

        # 3b. Multi-candidats : générer des variantes pour consensus
        # Seulement si la première tentative a réussi
        final_attempt = next(
            (a for a in reversed(attempts) if a.status == GenerationStatus.SUCCESS),
            attempts[-1] if attempts else None,
        )

        candidates_for_calibration = []
        calibration = None
        if final_attempt and final_attempt.status == GenerationStatus.SUCCESS:
            candidates_for_calibration.append(
                SQLCandidate(
                    sql=final_attempt.sql,
                    source="primary",
                    validation_passed=True,
                )
            )

            # Générer des variantes supplémentaires (en parallèle)
            # Chaque variante utilise une température différente pour diversifier le consensus
            if SQL_CANDIDATES_COUNT > 1:
                variant_temps = SQL_CANDIDATE_TEMPERATURES[1:SQL_CANDIDATES_COUNT]
                variant_tasks = []
                for temp in variant_temps:
                    variant_tasks.append(
                        self._generate_once(
                            question=question,
                            rag_context=rag_context,
                            provider_name=self.config["primary_provider"],
                            model_name=self.config["primary_model"],
                            sql_template=sql_template,
                            temperature=temp,
                        )
                    )

                variant_results = await asyncio.gather(*variant_tasks, return_exceptions=True)

                # Valider les variantes en batch
                variant_sqls = [
                    vr.sql
                    for vr in variant_results
                    if isinstance(vr, GenerationAttempt) and vr.status == GenerationStatus.SUCCESS
                ]
                if variant_sqls:
                    batch_results = self.validator.validate_batch(variant_sqls, check_tables=True)
                    for vr_sql, val_result in zip(variant_sqls, batch_results):
                        candidates_for_calibration.append(
                            SQLCandidate(
                                sql=val_result.get("sql", vr_sql),
                                source="variant",
                                validation_passed=val_result["valid"],
                            )
                        )

            # Calibration de confiance
            if candidates_for_calibration:
                calibration = calibrate(
                    candidates=candidates_for_calibration,
                    rag_confidence=confidence,
                    schema_tables_found=rag_counts.get("ddl", 0),
                    schema_tables_expected=max(rag_counts.get("ddl", 1), 1),
                )

                # Utiliser le meilleur candidat selon le consensus
                if calibration.best_candidate:
                    final_attempt = GenerationAttempt(
                        sql=calibration.best_candidate.sql,
                        status=GenerationStatus.SUCCESS,
                        duration_seconds=final_attempt.duration_seconds,
                        model=final_attempt.model,
                        provider=final_attempt.provider,
                        prompt_tokens=final_attempt.prompt_tokens,
                        completion_tokens=final_attempt.completion_tokens,
                        total_tokens=final_attempt.total_tokens,
                    )

        # 4. Construire le résultat final
        total_duration = time.time() - start_time

        # final_attempt est déjà défini dans la section multi-candidats
        # Si pas défini, le prendre ici
        if not final_attempt:
            final_attempt = next(
                (a for a in reversed(attempts) if a.status == GenerationStatus.SUCCESS),
                attempts[-1] if attempts else None,
            )

        if not final_attempt:
            return GenerationResult(
                question=question,
                sql="",
                status=GenerationStatus.MAX_RETRIES,
                total_attempts=len(attempts),
                total_duration_seconds=total_duration,
                error_message="Aucune tentative effectuée",
                generated_at=clock.now().isoformat(),
            )

        # Agréger les tokens de toutes les tentatives
        agg_prompt = sum(a.prompt_tokens or 0 for a in attempts)
        agg_completion = sum(a.completion_tokens or 0 for a in attempts)
        agg_total = sum(a.total_tokens or 0 for a in attempts)

        result = GenerationResult(
            question=question,
            sql=final_attempt.sql,
            status=final_attempt.status,
            total_attempts=len(attempts),
            total_duration_seconds=total_duration,
            from_cache=False,
            model_provider=final_attempt.provider,
            model_name=final_attempt.model,
            temperature=self.config["temperature"],
            rag_ddl_count=rag_counts["ddl"],
            rag_doc_count=rag_counts["doc"],
            rag_example_count=rag_counts["examples"],
            confidence_score=confidence,
            prompt_tokens=agg_prompt or None,
            completion_tokens=agg_completion or None,
            total_tokens=agg_total or None,
            attempts=attempts,
            candidates=candidates_for_calibration,
            consensus_score=calibration.score if calibration else 0.0,
            confidence_action=calibration.action.value if calibration else "",
            error_message=(
                final_attempt.error if final_attempt.status != GenerationStatus.SUCCESS else None
            ),
            generated_at=clock.now().isoformat(),
        )

        # **Phase 2.5.bis.9 (#109) — Garde-fou final mode invisible.**
        # Le LLM Vanna peut halluciner un nom denied dans le SQL retourné.
        # Le helper raise ``DataAccessLeakDetectedError`` si leak ;
        # le caller user-facing catche et propage ``blocked_by="data_access_rule"``.
        # Couvre aussi le bypass cache+rag_shortcut via les checks faits plus
        # haut (adversarial review #109 — 2 BLOCKING fixés).
        if result.status == GenerationStatus.SUCCESS:
            await self._assert_sql_safe_for_user(
                result.sql,
                user_id,
                question,
                context_label="vanna_enhanced_generator.generate.llm_return",
            )

        # 5. Cache si succès
        if result.status == GenerationStatus.SUCCESS and use_cache:
            cache = self._get_cache()
            cache.set(question, result.sql, "")

        # 6. Log business metrics (SQL généré, RAG counts, statut métier).
        # ⚠️ La consommation TOKENS / cost est loggée séparément par le hook
        # ``llm_call_tracker`` au moment de l'appel LLM (caller="vanna_generate").
        # Ici on ajoute un row "business" complémentaire pour préserver le
        # drilldown SQL sur la page /admin/ai-performance — sans tokens
        # pour éviter le double-comptage côté dashboard de consommation.
        if self.config["log_performance"]:
            await self._log_performance(result, user_id)

        return result

    async def _log_performance(self, result: GenerationResult, user_id: Optional[int]):
        """Enregistre les méta business (SQL, RAG, statut) dans la BDD.

        ⚠️ Ne LOGGUE PAS les tokens / cost ici — ces champs sont déjà
        écrits par le hook central ``llm_call_tracker`` (avec
        ``caller="vanna_generate"``). Les laisser à NULL ici évite le
        double-comptage dans le dashboard de consommation API.
        """
        try:
            from app.core.database import get_session
            from app.models.ai_performance import AIPerformanceLog, QueryStatus

            status_map = {
                GenerationStatus.SUCCESS: QueryStatus.SUCCESS,
                GenerationStatus.VALIDATION_ERROR: QueryStatus.VALIDATION_ERROR,
                GenerationStatus.EXECUTION_ERROR: QueryStatus.EXECUTION_ERROR,
                GenerationStatus.SYNTAX_ERROR: QueryStatus.VALIDATION_ERROR,
                GenerationStatus.TIMEOUT: QueryStatus.TIMEOUT,
                GenerationStatus.LLM_ERROR: QueryStatus.LLM_ERROR,
                GenerationStatus.MAX_RETRIES: QueryStatus.LLM_ERROR,
                GenerationStatus.NO_SCHEMA: QueryStatus.VALIDATION_ERROR,
            }

            async with get_session() as session:
                log = AIPerformanceLog(
                    question=result.question,
                    sql_generated=result.sql,
                    model_provider=result.model_provider,
                    model_name=result.model_name,
                    temperature=result.temperature,
                    status=status_map.get(result.status, QueryStatus.SUCCESS),
                    error_message=result.error_message,
                    generation_time=result.total_duration_seconds,
                    total_time=result.total_duration_seconds,
                    rag_ddl_count=result.rag_ddl_count,
                    rag_doc_count=result.rag_doc_count,
                    rag_example_count=result.rag_example_count,
                    # NE PAS dupliquer les tokens — déjà loggés par le hook.
                    prompt_tokens=None,
                    completion_tokens=None,
                    total_tokens=None,
                    cost_usd_snapshot=None,
                    from_cache=result.from_cache,
                    user_id=user_id,
                    # Marqueur pour distinguer du row hook (tokens NULL) :
                    # le row business apparaît dans les pages métier
                    # mais est exclu des sommes "consommation".
                    caller="vanna_business_log",
                )
                session.add(log)
                await session.commit()

        except (SQLAlchemyError, OSError, ValueError) as e:
            logger.warning("Erreur logging performance: %s", e)

    async def learn_from_correction(
        self, question: str, corrected_sql: str, original_sql: str, user_id: Optional[int] = None
    ):
        """
        Apprend d'une correction utilisateur.

        Ajoute la paire question/SQL corrigé au training store.
        """
        if not self.config["auto_learn"]:
            return

        store = await self._get_training_store()
        if not store:
            return

        try:
            await store.add_question_sql(
                question=question,
                sql=corrected_sql,
                source="user_correction",
                quality_score=1.0,  # Validé par l'utilisateur
                user_id=user_id,
            )

            logger.info("Correction apprise pour: %s...", question[:50])

            # Invalider le cache pour cette question
            cache = self._get_cache()
            cache.invalidate(question)

        except (OSError, json.JSONDecodeError, ValueError) as e:
            logger.warning("Erreur apprentissage correction: %s", e)

    async def record_feedback(
        self,
        question: str,
        sql: str,
        feedback: str,  # 'positive' ou 'negative'
        comment: Optional[str] = None,
        user_id: Optional[int] = None,
    ):
        """
        Enregistre le feedback utilisateur.

        Si positif, ajoute au training store pour améliorer les futures générations.
        """
        if feedback == "positive" and self.config["auto_learn"]:
            store = await self._get_training_store()
            if store:
                try:
                    await store.add_question_sql(
                        question=question,
                        sql=sql,
                        source="positive_feedback",
                        quality_score=0.9,
                        user_id=user_id,
                    )
                    logger.info("Feedback positif enregistré pour: %s...", question[:50])
                except (OSError, json.JSONDecodeError, ValueError, SQLAlchemyError) as e:
                    logger.warning("Erreur enregistrement feedback: %s", e)

    async def get_config(self) -> Dict[str, Any]:
        """Retourne la configuration actuelle."""
        return self.config.copy()

    async def update_config(self, updates: Dict[str, Any]):
        """Met à jour la configuration (only known keys accepted)."""
        _VALID_KEYS = {
            "primary_provider",
            "primary_model",
            "temperature",
            "max_retries",
            "max_results",
            "use_rag",
            "use_cache",
            "log_performance",
            "auto_learn",
            "language",
            "timeout_seconds",
            "confidence_threshold",
        }
        filtered = {k: v for k, v in updates.items() if k in _VALID_KEYS}
        if not filtered:
            logger.warning("update_config: aucune clé valide dans %s", list(updates.keys()))
            return
        self.config.update(filtered)
        logger.info("Configuration mise à jour: %s", list(filtered.keys()))

    async def health_check(self) -> Dict[str, Any]:
        """Vérifie l'état du générateur."""
        await self._ensure_config_loaded()
        result = {
            "status": "ok",
            "providers": {},
            "training_store": False,
            "cache": False,
            "tables_count": 0,
            "views_count": 0,
        }

        try:
            manager = await self._get_llm_manager()
            result["providers"] = await manager.health_check_all()
        except (SQLAlchemyError, ValueError) as e:
            logger.error("Erreur vérification providers", exc_info=True)
            result["status"] = "degraded"
            result["providers"] = {"error": f"Erreur vérification providers ({type(e).__name__})"}

        try:
            store = await self._get_training_store()
            if store:
                stats = await store.get_stats()
                result["training_store"] = stats.get("total", 0) > 0
                result["tables_count"] = stats.get("tables_count", 0)
                result["views_count"] = stats.get("views_count", 0)
        except (SQLAlchemyError, ValueError):
            pass

        try:
            cache = self._get_cache()
            result["cache"] = cache is not None
        except (SQLAlchemyError, ValueError):
            pass

        return result

    async def close(self):
        """Libère les ressources."""
        if self._llm_manager:
            await self._llm_manager.close_all()


# Singleton
_generator: Optional[VannaEnhancedGenerator] = None


def get_enhanced_generator(config: Optional[Dict[str, Any]] = None) -> VannaEnhancedGenerator:
    """Retourne l'instance singleton du générateur."""
    global _generator
    if _generator is None:
        _generator = VannaEnhancedGenerator(config)
    return _generator


async def reset_generator():
    """Réinitialise le générateur (utile pour les tests ou changement de config)."""
    global _generator
    if _generator:
        await _generator.close()
    _generator = None
