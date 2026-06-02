"""Modèle ``AIConfig`` — configuration IA centralisée (provider, RAG, seuils, sync).

Doctrine sénior de ce module :

1. **Une seule source de vérité pour "quelle clé est un secret" (`SECRET_CONFIG_KEYS`)**.
   Le service de persistance (``app/services/ai/config_service.py``) importe ce
   même frozenset pour décider des clés à chiffrer (Fernet) et à masquer. Aucune
   duplication cross-module — un ajout de secret ici propage automatiquement
   chiffrement + masquage + exclusion d'export, conformément au principe
   OWASP Secrets Management Cheat Sheet.

2. **Redaction sérialisation = tout-ou-rien (CWE-200)**. ``AIConfig.to_dict``
   expose ``"***"`` (sentinelle constante) pour les clés secrètes — aucun
   préfixe / suffixe ni len-dépendant. L'affichage admin (avec préfixe pour
   reconnaissance visuelle d'une clé Anthropic vs OpenAI) est une
   responsabilité distincte du *service* (``mask_api_key``), pas du modèle.

3. **Drift guard enum** : ``AIConfigValueType`` et ``AIConfigCategory`` sont
   des enums ``(str, Enum)`` — toute métadonnée déclarée dans ``DEFAULT_AI_CONFIG``
   passe par ces constantes. Un typo silencieux ("boolean" au lieu de "bool")
   est impossible à introduire sans échec de type ou de test.

4. **Timestamps timezone-aware** : ``created_at`` / ``updated_at`` stockés en UTC
   via ``clock.now`` (source de vérité unique d'horloge). La sérialisation
   ``to_dict`` normalise via ``ensure_utc`` pour compenser SQLite qui efface
   les timezones.

5. **Pas de getter "raw"** : le service décrypte ; les consommateurs lisent
   ``config.value`` directement quand la donnée est publique, ou passent par
   ``AIConfigService.get(...)`` qui décrypte les secrets. Aucun helper mort.

Références :
- OWASP Top 10:2025 A01 Broken Access Control / CWE-200 (Exposure of Sensitive
  Information to Unauthorized Actor) — redaction sérialisation opaque.
- OWASP Secrets Management Cheat Sheet — secrets exclus des exports de config.
- OWASP Cryptographic Storage Cheat Sheet §4 — chiffrement au repos côté service.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Final, TypedDict

from sqlalchemy import JSON, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from typing_extensions import NotRequired, Required

from app.core import clock
from app.core.database import Base
from app.models.base import ensure_utc


class AIConfigKey(str, Enum):
    """Clés de configuration IA disponibles (source de vérité unique)."""

    # Provider principal
    PRIMARY_PROVIDER = "primary_provider"
    PRIMARY_MODEL = "primary_model"

    # Fallback
    FALLBACK_PROVIDER = "fallback_provider"
    FALLBACK_MODEL = "fallback_model"

    # API
    API_KEY = "api_key"
    API_BASE_URL = "api_base_url"

    # Génération
    TEMPERATURE = "temperature"
    MAX_RETRIES = "max_retries"
    MAX_RESULTS = "max_results"
    TIMEOUT_SECONDS = "timeout_seconds"

    # RAG
    USE_RAG = "use_rag"
    RAG_DDL_COUNT = "rag_ddl_count"
    # ► ZOMBIE KEY (fusion UI 2026-05-27) : ``rag_doc_count`` est dérivée
    # de ``rag_example_count`` côté runtime (cf. training_store.
    # ``_get_rag_runtime_config`` → ``doc_count = n_results``). Modifier
    # cette clé via SQL n'a aucun effet. Conservée pour compat migrations
    # existantes uniquement.
    RAG_DOC_COUNT = "rag_doc_count"
    RAG_EXAMPLE_COUNT = "rag_example_count"
    CONFIDENCE_THRESHOLD = "confidence_threshold"
    # Seuil min des scores DDL/documentation RAG (0.001 par défaut = quasi tout
    # garder, le tri par score suffit en pratique). Distinct de
    # ``confidence_threshold`` qui s'applique aux paires Q/SQL.
    RAG_DDL_DOC_MIN_SCORE = "rag_ddl_doc_min_score"
    # Nombre minimum d'exemples Q/SQL à servir comme few-shot même si leur
    # score est sous ``confidence_threshold`` (filet de sécurité).
    RAG_MIN_EXAMPLES = "rag_min_examples"
    # Cap dur sur le nombre de paires Q/SQL chargées en RAM pour le scoring.
    # Au-delà, on garde les paires les plus récentes (ORDER BY created_at).
    RAG_MAX_SCAN = "rag_max_scan"
    # Score min pour qu'une paire soit considérée comme "réutilisable à
    # l'identique" (le SQL antérieur peut être resservi tel quel si le
    # schéma est intact).
    RAG_REUSABLE_SCORE = "rag_reusable_score"

    # Apprentissage
    AUTO_LEARN = "auto_learn"
    # ► ZOMBIE KEY (2026-05-27) : retirée du UI ET aucune lecture runtime.
    # ``agent_service.run`` hardcode ``terminal_kind == 'done'``. Modifier
    # cette clé n'a aucun effet. Conservée uniquement pour éviter une
    # migration destructive sur les installations existantes. Test de
    # garde : ``test_auto_learn_positive_only_not_read_at_runtime``.
    AUTO_LEARN_POSITIVE_ONLY = "auto_learn_positive_only"
    AUTO_PROMOTE_ENABLED = "auto_promote_enabled"

    # Embeddings (sentence-transformers local, aucun appel API)
    EMBEDDING_ENABLED = "embedding_enabled"
    EMBEDDING_MODEL = "embedding_model"

    # Cache
    USE_CACHE = "use_cache"
    CACHE_TTL_HOURS = "cache_ttl_hours"

    # Sync schéma
    SCHEMA_SYNC_ENABLED = "schema_sync_enabled"
    SCHEMA_SYNC_INTERVAL_HOURS = "schema_sync_interval_hours"
    SCHEMA_SYNC_LAST_RUN = "schema_sync_last_run"
    # Heure préférée HH:MM (locale serveur). Vide = "dès qu'intervalle écoulé".
    SCHEMA_SYNC_START_TIME = "schema_sync_start_time"

    # Logging
    LOG_PERFORMANCE = "log_performance"
    LOG_LEVEL = "log_level"

    # LLM local (anonymiseur + fallback). Modèle léger genre Phi-3-mini /
    # Llama-3.2-3B servi via Ollama (OpenAI-compat). Désactivé par défaut.
    LOCAL_LLM_ENABLED = "local_llm_enabled"
    LOCAL_LLM_BASE_URL = "local_llm_base_url"
    LOCAL_LLM_MODEL = "local_llm_model"
    # Paramètres de génération propres au LLM local — distincts du primary
    # car les modèles locaux 3B ont des caractéristiques différentes
    # (température 0 plus stricte, retries plus élevés sur cold start, etc.)
    LOCAL_LLM_TEMPERATURE = "local_llm_temperature"
    LOCAL_LLM_MAX_RETRIES = "local_llm_max_retries"
    LOCAL_LLM_TIMEOUT_SECONDS = "local_llm_timeout_seconds"

    # Sécurité / contrôle d'accès aux données BDD source
    # Toggle global d'application des règles ``DataAccessRule``. Off par
    # défaut → comportement legacy préservé (compat des déploiements
    # existants). Quand ON, l'enforcer applique les règles à 3 niveaux
    # (filtrage contexte LLM, validation pre-flight, injection WHERE).
    DATA_ACCESS_ENFORCEMENT_ENABLED = "data_access_enforcement_enabled"

    # Iris-DBA-write (casquette write SQL) — admin only
    # ► Les 4 clés IRIS_WRITE_* (enabled, max_rows, approver_email,
    #   approval_ttl_hours) ont été RETIRÉES le 2026-05-15 sur demande
    #   utilisateur. Les valeurs sont maintenant hardcodées dans
    #   ``app/services/ai/iris_write_session.py::_get_iris_write_config``
    #   (enabled toujours True, TTL = 168h, pas de cap rows). L'approbateur
    #   réutilise l'« Email support » de /admin/smtp-config (SSoT
    #   ``resolve_support_email``), pas une clé dédiée. Pas de section UI
    #   dans /admin/ai-config — l'admin n'a rien à configurer ici.

    # T24 — Budget LLM par utilisateur sur fenêtre glissante (denial-of-wallet
    # protection). Cap commun à tous les utilisateurs (clé ``ai_config``
    # singleton globale, pas scopée par user) mais évalué séparément par user
    # — analogue à ``STORAGE_QUOTA_PER_USER_BYTES``. Configurable via
    # /admin/ai-config section "Paramètres de génération".
    #
    # Sémantique : ``SUM(cost_usd_snapshot)`` filtré par
    # ``AIPerformanceLog.user_id`` ET ``created_at >= NOW(UTC) -
    # timedelta(hours=BUDGET_WINDOW_HOURS)``. Au-delà de ``MAX_USD_PER_USER``
    # l'agent stoppe proprement avec un message clair. La fenêtre est
    # **glissante** (rolling), pas calendaire — un appel sort du cumul dès
    # que son ``created_at`` est antérieur à ``now - window``. Reset
    # automatique sans intervention utilisateur ni admin.
    #
    # ``MAX_USD_PER_USER`` = 0 désactive le cap. ``BUDGET_WINDOW_HOURS`` doit
    # être > 0 pour que le cap soit actif. Implémentation côté
    # ``_check_conversation_budget`` (agent_service) et ``get_user_cost_usd_window``
    # (llm_call_tracker).
    #
    # Note historique : avant le 2026-05-20 le cap était scopé par
    # ``conversation_id`` (clé ``max_usd_per_conversation``). Bug : SQLite
    # réutilise les IDs après hard-delete sans keyword ``AUTOINCREMENT`` →
    # nouvelle conv héritait des coûts orphelins. Remplacé par cette
    # sémantique user×fenêtre (plus simple, pas de bug d'id réutilisé,
    # reset automatique).
    MAX_USD_PER_USER = "max_usd_per_user"
    BUDGET_WINDOW_HOURS = "budget_window_hours"

    # Quota stockage par utilisateur (en octets) — UNIQUE source de vérité
    # globale, identique pour TOUS les users (ignore le rôle). Configurable
    # via l'UI admin /admin/performance section "Stockage local (SQLite)".
    # Couvre fichiers datastore + données BDD scopées user (cf. db_usage.py).
    # 500 MiB par défaut, dimensionné pour un usage individuel courant
    # (fichiers datastore + données BDD locale scopées user).
    STORAGE_QUOTA_PER_USER_BYTES = "storage_quota_per_user_bytes"

    # Taille maximale d'UN fichier uploadé (en octets) — SSoT globale pour les
    # points de RÉCEPTION d'upload utilisateur : trombone Iris, fichiers du
    # datastore, upload de rapport, réponse de collaborateur (wait_response).
    # Configurable via l'UI admin /admin/performance. 50 MiB par défaut.
    # Exclusions volontaires (limites dédiées distinctes) : fichiers GÉNÉRÉS en
    # interne (rapports), pièces jointes des mails sortants (limite SMTP),
    # import CSV de contacts (limite métier), import de configuration
    # d'automation, et le PARSING openpyxl/CSV (protection RAM, cf.
    # workbooks.py). Lue au runtime via config_service.get_max_upload_size_bytes().
    MAX_UPLOAD_SIZE_BYTES = "max_upload_size_bytes"


class AIConfigValueType(str, Enum):
    """Types valides pour la colonne ``value_type`` (drift guard).

    Le service ``_validate_value`` ne reconnaît que ces types. Toute métadonnée
    déclarée dans ``DEFAULT_AI_CONFIG`` passe obligatoirement par ces valeurs —
    un typo silencieux ("boolean" au lieu de "bool") ne peut pas échapper à la
    revue car l'enum refuse la valeur inconnue.
    """

    STRING = "string"
    INT = "int"
    FLOAT = "float"
    BOOL = "bool"
    JSON = "json"


class AIConfigCategory(str, Enum):
    """Catégories fonctionnelles des clés de config (drift guard).

    Utilisées pour regrouper l'affichage admin et pour la route
    ``AIConfigService.get_by_category``. Toute catégorie doit apparaître ici
    avant usage dans ``DEFAULT_AI_CONFIG``.
    """

    PROVIDER = "provider"
    GENERATION = "generation"
    RAG = "rag"
    LEARNING = "learning"
    CACHE = "cache"
    SCHEMA = "schema"
    LOGGING = "logging"
    SECURITY = "security"


# Sentinelle opaque pour la redaction sérialisation (CWE-200 tout-ou-rien).
# Le frontend qui reçoit cette valeur ne reconstruit rien : il affiche un
# placeholder. Le préfixe/suffixe "reconnaissable" reste la responsabilité du
# service (``mask_api_key``) pour l'UI interactive — pas du modèle.
_REDACTED_SENTINEL: Final[str] = "***"

# Sentinelle ``__repr__`` — distincte pour que l'opérateur qui lit les logs
# identifie immédiatement une redaction (vs un placeholder UI).
_REPR_REDACTED: Final[str] = "***REDACTED***"


# Clés dont la valeur est un secret : chiffrement au repos (Fernet côté service)
# + redaction systématique dans ``__repr__`` et ``to_dict``. Source de vérité
# unique — importée telle-quelle par le service pour éviter la duplication qui
# permettrait à un futur secret d'être chiffré mais pas redacté (ou l'inverse).
SECRET_CONFIG_KEYS: Final[frozenset[str]] = frozenset(
    {
        AIConfigKey.API_KEY.value,
    }
)


class AIConfigDefault(TypedDict):
    """Shape d'une entrée de ``DEFAULT_AI_CONFIG`` (self-documenting + mypy).

    **PEP 655 ``Required``/``NotRequired``** : ``value`` est *obligatoire* pour
    chaque clé (même ``None`` — le bootstrap doit savoir quoi insérer). Les
    métadonnées sont optionnelles : une clé booléenne n'a pas de ``min_value``,
    une string libre n'a pas d'``allowed_values``. Le drift guard
    ``_assert_default_config_invariants`` vérifie au chargement du module que
    chaque entrée respecte ce contrat — un ``NotRequired`` oublié est détecté
    avant que le premier test ne soit lancé.
    """

    value: Required[Any]
    description: NotRequired[str]
    category: NotRequired[str]
    value_type: NotRequired[str]
    min_value: NotRequired[float]
    max_value: NotRequired[float]
    allowed_values: NotRequired[list[Any]]


class AIConfig(Base):
    """Ligne de configuration IA persistante (clé ↔ valeur JSON + métadonnées).

    Chaque ligne mappe une clé de ``AIConfigKey`` vers sa valeur (scalaire,
    liste ou dict — le type est documenté par ``value_type``).

    Propriété des colonnes :
        - **Code-owned** (``description``, ``category``, ``value_type``,
          ``min_value``, ``max_value``, ``allowed_values``) : rafraîchies à
          chaque bootstrap par ``AIConfigService._ensure_defaults`` à partir de
          ``DEFAULT_AI_CONFIG``. L'utilisateur ne peut pas les modifier via
          l'API — toute édition admin porte uniquement sur ``value``.
        - **User-owned** (``value``, ``updated_by``, ``updated_at``) : modifiées
          par les handlers admin. ``created_at`` est posé une fois à l'insertion.
        - **Secret** (``key`` ∈ ``SECRET_CONFIG_KEYS``) : ``value`` chiffrée
          Fernet en BDD. Redactée en sortie (``__repr__``, ``to_dict``).

    Sérialisation (CWE-200) :
        - ``to_dict`` expose ``"***"`` pour les clés secrètes (sentinelle
          opaque, pas de partial-reveal ni d'indice de longueur).
        - ``__repr__`` expose ``"***REDACTED***"`` — sentinelle distincte pour
          qu'un opérateur qui grep les logs identifie immédiatement une
          redaction (vs un placeholder UI).
    """

    __tablename__ = "ai_config"

    id: Mapped[int] = mapped_column(primary_key=True)

    key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    # JSON ≠ dict uniquement : SQLAlchemy ``JSON`` stocke scalaires/listes/dicts/None.
    # Annoté ``Any`` pour ne pas mentir sur le runtime.
    value: Mapped[Any] = mapped_column(JSON, nullable=False)

    # Métadonnées
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # ``index=True`` — ``AIConfigService.get_by_category`` filtre sur cette
    # colonne pour l'affichage par onglets côté admin. Sans index, c'est un
    # full-scan ``ai_config`` à chaque ouverture de la page.
    category: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    value_type: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Contraintes (utilisées par ``_validate_value`` côté service)
    min_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    max_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Stocké comme JSON array (liste de valeurs autorisées) — ``value not in list``.
    allowed_values: Mapped[list[Any] | None] = mapped_column(JSON, nullable=True)

    # Audit
    updated_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        onupdate=clock.now,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
    )

    @classmethod
    def is_secret_key(cls, key: str | AIConfigKey | None) -> bool:
        """Teste si une clé appartient à l'ensemble des secrets (redaction + chiffrement).

        Accepte ``str``, ``AIConfigKey`` ou ``None`` (cas transitoires : instance
        ORM fraîchement créée avant ``flush``, ``__repr__`` appelé avant
        assignation, etc.).

        Un nom ∉ ``SECRET_CONFIG_KEYS`` renvoie ``False`` par design : la
        classification d'un secret est **explicite** (on étend le frozenset),
        jamais implicite (pas de détection par préfixe / heuristique). Ce
        choix évite les faux-positifs qui masqueraient à tort une clé publique
        et les faux-négatifs silencieux qui leakeraient un secret ajouté sans
        revue — le drift guard ``_assert_default_config_invariants`` garantit
        que tout membre de ``SECRET_CONFIG_KEYS`` est bien une valeur valide
        de ``AIConfigKey``.
        """
        if key is None:
            return False
        key_str = key.value if isinstance(key, AIConfigKey) else key
        return key_str in SECRET_CONFIG_KEYS

    def __repr__(self) -> str:
        # Une instance ORM juste construite (``AIConfig(key=...)`` avant
        # ``session.add``) peut appeler ``__repr__`` alors que les colonnes
        # ne sont pas encore posées. Fail-safe : on redacte dans le doute
        # pour ne jamais imprimer une valeur potentiellement sensible.
        if self.key is None or self.is_secret_key(self.key):
            return f"<AIConfig(key={self.key!r}, value={_REPR_REDACTED})>"
        return f"<AIConfig(key={self.key}, value={self.value!r})>"

    def to_dict(self) -> dict[str, Any]:
        """Sérialise l'entrée pour l'API / l'export admin.

        Comportement sécurité :
            - Clé secrète → ``value = "***"`` (sentinelle opaque, pas de partial-reveal).
            - Clé non-secrète → valeur brute telle que stockée.

        Timestamps normalisés en UTC via ``ensure_utc`` (SQLite peut rendre des
        datetimes naïfs selon la version du driver). ``updated_by`` est inclus
        pour permettre à l'UI admin de tracer qui a modifié chaque valeur —
        l'ID utilisateur seul n'est pas un secret (l'export en est déjà
        protégé côté service).
        """
        value: Any = _REDACTED_SENTINEL if self.is_secret_key(self.key) else self.value
        return {
            "id": self.id,
            "key": self.key,
            "value": value,
            "description": self.description,
            "category": self.category,
            "value_type": self.value_type,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "allowed_values": self.allowed_values,
            "updated_by": self.updated_by,
            "created_at": (ensure_utc(self.created_at).isoformat() if self.created_at else None),
            "updated_at": (ensure_utc(self.updated_at).isoformat() if self.updated_at else None),
        }


# ──────────────────────────────────────────────────────────────────────────
# Valeurs par défaut + métadonnées
#
# Utilisées par ``AIConfigService._ensure_defaults`` pour peupler la BDD au
# démarrage (upsert : les valeurs utilisateur sont préservées, seules les
# métadonnées ``description``/``category``/``value_type``/``min``/``max``/
# ``allowed_values`` sont rafraîchies).
# ──────────────────────────────────────────────────────────────────────────

DEFAULT_AI_CONFIG: Final[dict[AIConfigKey, AIConfigDefault]] = {
    AIConfigKey.PRIMARY_PROVIDER: {
        "value": None,
        "description": "Fournisseur LLM principal (auto-détecté depuis la clé API)",
        "category": AIConfigCategory.PROVIDER.value,
        "value_type": AIConfigValueType.STRING.value,
    },
    AIConfigKey.PRIMARY_MODEL: {
        "value": None,
        "description": "Modèle LLM principal",
        "category": AIConfigCategory.PROVIDER.value,
        "value_type": AIConfigValueType.STRING.value,
    },
    AIConfigKey.FALLBACK_PROVIDER: {
        "value": None,
        "description": "Fournisseur LLM de secours",
        "category": AIConfigCategory.PROVIDER.value,
        "value_type": AIConfigValueType.STRING.value,
    },
    AIConfigKey.FALLBACK_MODEL: {
        "value": None,
        "description": "Modèle LLM de secours",
        "category": AIConfigCategory.PROVIDER.value,
        "value_type": AIConfigValueType.STRING.value,
    },
    AIConfigKey.API_KEY: {
        "value": None,
        "description": "Clé API du provider (chiffrée au repos via Fernet)",
        "category": AIConfigCategory.PROVIDER.value,
        "value_type": AIConfigValueType.STRING.value,
    },
    AIConfigKey.API_BASE_URL: {
        "value": None,
        "description": "URL de base custom (providers OpenAI-compatibles, self-host)",
        "category": AIConfigCategory.PROVIDER.value,
        "value_type": AIConfigValueType.STRING.value,
    },
    AIConfigKey.TEMPERATURE: {
        "value": 0.1,
        "description": "Température de génération (0=déterministe, 1=créatif)",
        "category": AIConfigCategory.GENERATION.value,
        "value_type": AIConfigValueType.FLOAT.value,
        "min_value": 0.0,
        "max_value": 1.0,
    },
    AIConfigKey.MAX_RETRIES: {
        "value": 3,
        "description": "Nombre maximum de tentatives en cas d'erreur",
        "category": AIConfigCategory.GENERATION.value,
        "value_type": AIConfigValueType.INT.value,
        "min_value": 1,
        "max_value": 5,
    },
    AIConfigKey.MAX_RESULTS: {
        "value": 100,
        "description": "Limite par défaut des résultats (TOP N)",
        "category": AIConfigCategory.GENERATION.value,
        "value_type": AIConfigValueType.INT.value,
        "min_value": 10,
        "max_value": 10000,
    },
    AIConfigKey.TIMEOUT_SECONDS: {
        # 600s aligné sur ANTHROPIC_TIMEOUT — Iris peut faire de longues
        # conversations tool-use avec extended thinking. 600s couvre 95% des
        # cas. Slider UI étendu à 600 max en conséquence.
        "value": 600,
        "description": "Timeout en secondes pour la génération",
        "category": AIConfigCategory.GENERATION.value,
        "value_type": AIConfigValueType.INT.value,
        "min_value": 30,
        "max_value": 600,
    },
    AIConfigKey.USE_RAG: {
        "value": True,
        "description": "Activer le RAG (Retrieval Augmented Generation)",
        "category": AIConfigCategory.RAG.value,
        "value_type": AIConfigValueType.BOOL.value,
    },
    AIConfigKey.RAG_DDL_COUNT: {
        "value": 5,
        "description": "Nombre de DDL à inclure dans le contexte",
        "category": AIConfigCategory.RAG.value,
        "value_type": AIConfigValueType.INT.value,
        "min_value": 0,
        "max_value": 20,
    },
    AIConfigKey.RAG_DOC_COUNT: {
        # ZOMBIE KEY (fusion UI 2026-05-27) : valeur runtime = rag_example_count
        # (cf. training_store._get_rag_runtime_config). Modifier cette valeur
        # via SQL ou /admin/ai-config ne change absolument rien. Conservée
        # uniquement pour éviter migrations destructives. Valeur seedée
        # alignée sur RAG_EXAMPLE_COUNT (5) pour cohérence de l'export
        # config — sinon `rag_doc_count=3` apparaît dans l'export et confond.
        "value": 5,
        "description": "[ZOMBIE — IGNORÉ AU RUNTIME, voir rag_example_count] Nombre de documents métier à inclure",
        "category": AIConfigCategory.RAG.value,
        "value_type": AIConfigValueType.INT.value,
        "min_value": 0,
        "max_value": 10,
    },
    AIConfigKey.RAG_EXAMPLE_COUNT: {
        "value": 5,
        "description": "Nombre d'exemples Q/SQL à inclure",
        "category": AIConfigCategory.RAG.value,
        "value_type": AIConfigValueType.INT.value,
        "min_value": 0,
        "max_value": 20,
    },
    AIConfigKey.CONFIDENCE_THRESHOLD: {
        # 0.02 aligné sur RAG_QUESTION_SQL_THRESHOLD historique. Avec
        # ``compute_query_recall_idf``, les scores sont rarement > 0.5,
        # donc un seuil 0.7 retournerait un RAG vide en pratique.
        "value": 0.02,
        "description": "Seuil de confiance RAG (0-1)",
        "category": AIConfigCategory.RAG.value,
        "value_type": AIConfigValueType.FLOAT.value,
        "min_value": 0.0,
        "max_value": 1.0,
    },
    AIConfigKey.RAG_DDL_DOC_MIN_SCORE: {
        # 0.001 = quasi tout garder (le tri par score suffit en pratique).
        # Distinct de ``confidence_threshold`` qui s'applique aux paires
        # Q/SQL : ici on filtre les DDL et docs métier servis comme contexte.
        "value": 0.001,
        "description": "Seuil min des scores DDL/docs RAG (0-1)",
        "category": AIConfigCategory.RAG.value,
        "value_type": AIConfigValueType.FLOAT.value,
        "min_value": 0.0,
        "max_value": 1.0,
    },
    AIConfigKey.RAG_MIN_EXAMPLES: {
        # Si moins de N exemples Q/SQL ont un score >= confidence_threshold,
        # on complète quand même jusqu'à ce minimum avec les meilleurs
        # restants. Évite que l'IA travaille sans aucun few-shot quand
        # le RAG est encore pauvre.
        "value": 2,
        "description": "Nombre min d'exemples Q/SQL à servir même sous le seuil",
        "category": AIConfigCategory.RAG.value,
        "value_type": AIConfigValueType.INT.value,
        "min_value": 0,
        "max_value": 10,
    },
    AIConfigKey.RAG_MAX_SCAN: {
        # Cap RAM scoring RAG. À 5000 paires, le scoring recall-IDF reste
        # statistiquement stable. Au-delà, RAM linéaire avec la taille du
        # training store — risque OOM sur les longues sessions.
        "value": 5000,
        "description": "Cap RAM scoring RAG (nombre max de paires chargées)",
        "category": AIConfigCategory.RAG.value,
        "value_type": AIConfigValueType.INT.value,
        "min_value": 100,
        "max_value": 50000,
    },
    AIConfigKey.RAG_REUSABLE_SCORE: {
        # Au-dessus de 0.95 ET schéma intact, l'agent peut réutiliser le
        # SQL antérieur tel quel. Reste de la décision est laissée à
        # l'agent (le flag n'est pas un raccourci de code).
        "value": 0.95,
        "description": "Score min pour réutiliser un SQL antérieur tel quel",
        "category": AIConfigCategory.RAG.value,
        "value_type": AIConfigValueType.FLOAT.value,
        "min_value": 0.5,
        "max_value": 1.0,
    },
    AIConfigKey.AUTO_LEARN: {
        "value": True,
        "description": "Apprentissage automatique depuis les corrections",
        "category": AIConfigCategory.LEARNING.value,
        "value_type": AIConfigValueType.BOOL.value,
    },
    AIConfigKey.AUTO_LEARN_POSITIVE_ONLY: {
        # ZOMBIE KEY (2026-05-27) : retirée du UI ET aucune lecture runtime.
        # ``agent_service.run`` hardcode ``terminal_kind == 'done'`` (cf. test
        # ``test_auto_learn_positive_only_not_read_at_runtime``). Modifier
        # cette valeur via SQL ou /admin/ai-config ne change ABSOLUMENT
        # rien au comportement. Conservée uniquement pour éviter une
        # migration destructive sur les installations existantes —
        # suppression planifiée à la prochaine vague de nettoyage.
        "value": True,
        "description": "[ZOMBIE KEY — aucune lecture runtime] Apprendre uniquement les feedbacks positifs",
        "category": AIConfigCategory.LEARNING.value,
        "value_type": AIConfigValueType.BOOL.value,
    },
    AIConfigKey.AUTO_PROMOTE_ENABLED: {
        "value": True,
        "description": "Promouvoir auto les candidats Q/SQL après N utilisations réussies",
        "category": AIConfigCategory.LEARNING.value,
        "value_type": AIConfigValueType.BOOL.value,
    },
    AIConfigKey.EMBEDDING_ENABLED: {
        "value": True,
        "description": "Activer la recherche par embeddings vectoriels locaux (fallback TF-IDF si désactivé)",
        "category": AIConfigCategory.RAG.value,
        "value_type": AIConfigValueType.BOOL.value,
    },
    AIConfigKey.EMBEDDING_MODEL: {
        "value": "paraphrase-multilingual-MiniLM-L12-v2",
        "description": "Modèle sentence-transformers local (aucun appel API)",
        "category": AIConfigCategory.RAG.value,
        "value_type": AIConfigValueType.STRING.value,
    },
    AIConfigKey.USE_CACHE: {
        "value": True,
        "description": "Activer le cache des requêtes",
        "category": AIConfigCategory.CACHE.value,
        "value_type": AIConfigValueType.BOOL.value,
    },
    AIConfigKey.CACHE_TTL_HOURS: {
        "value": 24,
        "description": "Durée de vie du cache en heures",
        "category": AIConfigCategory.CACHE.value,
        "value_type": AIConfigValueType.INT.value,
        "min_value": 1,
        "max_value": 168,
    },
    AIConfigKey.SCHEMA_SYNC_ENABLED: {
        "value": True,
        "description": "Activer la synchronisation automatique du schéma",
        "category": AIConfigCategory.SCHEMA.value,
        "value_type": AIConfigValueType.BOOL.value,
    },
    AIConfigKey.SCHEMA_SYNC_INTERVAL_HOURS: {
        "value": 24,
        "description": "Intervalle de synchronisation en heures",
        "category": AIConfigCategory.SCHEMA.value,
        "value_type": AIConfigValueType.INT.value,
        "min_value": 1,
        "max_value": 168,
    },
    AIConfigKey.SCHEMA_SYNC_LAST_RUN: {
        "value": None,
        "description": "Dernière synchronisation du schéma (timestamp ISO, écrit par le scheduler)",
        "category": AIConfigCategory.SCHEMA.value,
        "value_type": AIConfigValueType.STRING.value,
    },
    AIConfigKey.SCHEMA_SYNC_START_TIME: {
        # 03:00 = heure creuse (aucun user actif sur Iris la nuit). Le sync
        # peut prendre plusieurs minutes selon le nombre de tables Sage —
        # l'overlay global ne dérangera personne.
        "value": "03:00",
        "description": (
            "Heure préférée du sync auto au format HH:MM (locale serveur). "
            "Vide = sync dès qu'intervalle écoulé. Ex: '03:00' = 3h du matin."
        ),
        "category": AIConfigCategory.SCHEMA.value,
        "value_type": AIConfigValueType.STRING.value,
    },
    AIConfigKey.LOG_PERFORMANCE: {
        "value": True,
        "description": "Logger les performances de génération",
        "category": AIConfigCategory.LOGGING.value,
        "value_type": AIConfigValueType.BOOL.value,
    },
    AIConfigKey.LOG_LEVEL: {
        "value": "INFO",
        "description": "Niveau de log",
        "category": AIConfigCategory.LOGGING.value,
        "value_type": AIConfigValueType.STRING.value,
        "allowed_values": ["DEBUG", "INFO", "WARNING", "ERROR"],
    },
    # LLM local (anonymiseur + fallback runtime). Section avancée pour
    # admin qui a un Ollama / LM Studio / TGI local.
    AIConfigKey.LOCAL_LLM_ENABLED: {
        "value": False,
        "description": "Activer un LLM local (Ollama, etc.) pour l'anonymisation et le fallback",
        "category": AIConfigCategory.PROVIDER.value,
        "value_type": AIConfigValueType.BOOL.value,
    },
    AIConfigKey.LOCAL_LLM_BASE_URL: {
        "value": "http://localhost:11434/v1",
        "description": "URL OpenAI-compatible du LLM local",
        "category": AIConfigCategory.PROVIDER.value,
        "value_type": AIConfigValueType.STRING.value,
    },
    AIConfigKey.LOCAL_LLM_MODEL: {
        "value": "",
        "description": "Nom du modèle local (ex: phi3:mini, llama3.2:3b, qwen2.5:3b)",
        "category": AIConfigCategory.PROVIDER.value,
        "value_type": AIConfigValueType.STRING.value,
    },
    AIConfigKey.LOCAL_LLM_TEMPERATURE: {
        "value": 0.0,
        "description": "Température LLM local (0 = déterministe, recommandé pour l'anonymisation)",
        "category": AIConfigCategory.GENERATION.value,
        "value_type": AIConfigValueType.FLOAT.value,
    },
    AIConfigKey.LOCAL_LLM_MAX_RETRIES: {
        # 1 retry suffit : le LLM local tourne sur la même machine, pas de
        # rate-limit ou réseau à compenser. Si Ollama refuse une fois, c'est
        # probablement un cold-start qui peut bénéficier d'1 seul retry.
        "value": 1,
        "description": "Tentatives max sur cold start (modèle pas encore chargé en RAM)",
        "category": AIConfigCategory.GENERATION.value,
        "value_type": AIConfigValueType.INT.value,
    },
    AIConfigKey.LOCAL_LLM_TIMEOUT_SECONDS: {
        # 300s = sécuritaire pour CPU faible (Ollama 3B sur CPU peut prendre
        # 1-3 min cold start). Si l'admin a un GPU, peut descendre à 60s.
        "value": 300,
        "description": "Timeout par appel LLM local (les modèles 3B sur CPU peuvent dépasser 60s)",
        "category": AIConfigCategory.GENERATION.value,
        "value_type": AIConfigValueType.INT.value,
    },
    # Sécurité / Row-Level Security par utilisateur
    AIConfigKey.DATA_ACCESS_ENFORCEMENT_ENABLED: {
        "value": False,
        "description": (
            "Activer l'application des règles d'accès aux données par "
            "utilisateur (page /admin/data-access). OFF = comportement "
            "legacy. ON = filtres pre-flight + injection WHERE + masquage "
            "tables interdites pour Iris."
        ),
        "category": AIConfigCategory.SECURITY.value,
        "value_type": AIConfigValueType.BOOL.value,
    },
    # Casquette Iris-DBA-write : 4 entrées DEFAULT_AI_CONFIG retirées
    # 2026-05-15 (cf. AIConfigKey.IRIS_WRITE_* commentaire pour le contexte).
    # Valeurs hardcodées dans iris_write_session._get_iris_write_config.
    # T24 — Cap budget LLM par utilisateur sur fenêtre glissante.
    AIConfigKey.MAX_USD_PER_USER: {
        "value": 1.00,
        "description": (
            "Budget LLM max en USD par utilisateur sur la fenêtre "
            "glissante (0 = désactivé). Cap commun à tous les utilisateurs, "
            "évalué séparément par user. Au-delà, la conversation stoppe "
            "avec un message clair indiquant le reset automatique. "
            "Cumul = SUM(cost_usd_snapshot) filtré par user_id et "
            "created_at >= NOW(UTC) - BUDGET_WINDOW_HOURS."
        ),
        "category": AIConfigCategory.GENERATION.value,
        "value_type": AIConfigValueType.FLOAT.value,
        "min_value": 0.0,
        "max_value": 1000.0,
    },
    AIConfigKey.BUDGET_WINDOW_HOURS: {
        "value": 24,
        "description": (
            "Durée de la fenêtre glissante du cap budget par utilisateur, "
            "en heures. Reset automatique : un appel LLM sort du cumul "
            "dès que son timestamp est antérieur à NOW - cette durée. "
            "Glissant (pas calendaire) — évite les pics à minuit. "
            "Min 1h, max 720h (30 jours)."
        ),
        "category": AIConfigCategory.GENERATION.value,
        "value_type": AIConfigValueType.INT.value,
        "min_value": 1,
        "max_value": 720,
    },
    # Quota stockage par utilisateur — SOURCE UNIQUE de vérité. Identique
    # pour TOUS les users (ignore rôles). Configurable via /admin/performance
    # section "Stockage local (SQLite)". Couvre fichiers datastore +
    # données BDD scopées user (cf. db_usage.py). 500 MiB par défaut.
    AIConfigKey.STORAGE_QUOTA_PER_USER_BYTES: {
        "value": 500 * 1024 * 1024,  # 500 MiB
        "description": (
            "Quota stockage en octets par utilisateur (global, identique "
            "pour tous les rôles). Couvre fichiers datastore + données "
            "BDD scopées (anonymisation, conversations, historique, audit, "
            "dashboards, etc.). Si quota dépassé, refus des uploads + "
            "warning UI. Modifiable via /admin/performance."
        ),
        "category": AIConfigCategory.SCHEMA.value,  # pas de catégorie "storage", schema convient
        "value_type": AIConfigValueType.INT.value,
        "min_value": 1024 * 1024,  # 1 MiB minimum
        "max_value": 1024 * 1024 * 1024 * 1024,  # 1 TiB max (= "pratiquement illimité")
    },
    # Taille max d'UN fichier uploadé — SOURCE UNIQUE de vérité pour tous les
    # uploads utilisateur (Iris, datastore, import Excel/CSV, upload rapport,
    # import CSV contacts). Lue via config_service.get_max_upload_size_bytes().
    # NE concerne PAS les fichiers générés en interne (rapports) ni les pièces
    # jointes email (limitées par le serveur SMTP). 50 MiB par défaut.
    AIConfigKey.MAX_UPLOAD_SIZE_BYTES: {
        "value": 50 * 1024 * 1024,  # 50 MiB
        "description": (
            "Taille maximale d'UN fichier uploadé (octets). S'applique aux "
            "points de réception d'upload utilisateur : trombone Iris, "
            "datastore, upload de rapport, réponse de collaborateur "
            "(wait_response). Ne s'applique PAS aux fichiers générés en interne "
            "(rapports), aux pièces jointes des mails sortants (limite serveur "
            "SMTP), à l'import CSV de contacts (limite métier dédiée), ni à "
            "l'import de configuration d'automation. Au-delà de la limite, "
            "l'upload est refusé (4xx). Modifiable via /admin/performance."
        ),
        "category": AIConfigCategory.SCHEMA.value,
        "value_type": AIConfigValueType.INT.value,
        "min_value": 1024 * 1024,  # 1 MiB minimum
        "max_value": 2 * 1024 * 1024 * 1024,  # 2 GiB (sous la limite HTTP Tornado 4 GiB)
    },
}
