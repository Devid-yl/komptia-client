"""Façade SQLAlchemy — enregistre l'ensemble des modèles dans ``Base.metadata``.

Doctrine sénior de ce module :

1. **Contrat d'enregistrement (CRITIQUE)**. ``app/core/database.py`` invoque
   ``import app.models`` juste avant ``Base.metadata.create_all`` pour garantir
   que toutes les classes ORM soient enregistrées. Tout ``mapped_column`` manquant
   ici produit un bug silencieux : la table n'est pas créée au bootstrap, et le
   premier handler qui la touche crashe sur ``OperationalError: no such table``
   (ou pire, une migration additive s'applique à une table fantôme). **Chaque
   nouveau module ``app/models/<name>.py`` contenant une classe qui hérite de
   ``Base`` DOIT être importé ici.** La garde est assurée par
   ``tests/unit/test_app_models_init.py``.

2. **Façade publique opposée à ``app.core``**. ``app/core/__init__.py`` proscrit
   les réexports (``pay-for-what-you-use`` — ne pas charger SQLAlchemy pour
   importer une exception). ``app.models`` sacrifie sciemment cet invariant :
   importer le package charge nécessairement SQLAlchemy puisque son rôle *est*
   d'enregistrer l'ORM. La façade liste alors explicitement chaque symbole
   public pour offrir une voie d'import lisible et stable
   (``from app.models import User``).

3. **Regroupement par domaine**. Les imports suivent le cycle métier : base
   ORM → authentification/utilisateur → configuration → IA/RAG → stockage →
   requêtes/recherche → automatisations → conversations → dashboards →
   webhooks → contacts/email → reporting. Ce plan reflète la chaîne
   ``app.core → app.models → app.services → app.handlers``.

4. **Pas d'alias compat (``One Obvious Way``)**. Un symbole = un chemin
   d'import. Les renommages passent par dépréciation explicite (cf.
   ``SMTPSettings`` conservé uniquement pour que ``create_all`` continue
   de gérer la table héritée ``smtp_settings`` sur les installations
   existantes — la configuration SMTP courante passe par
   ``SMTPGlobalConfig``. Aucun code applicatif n'instancie ``SMTPSettings`` ;
   son retrait n'est bloqué que par la présence de la table en BDD et
   par le test ``test_models_infrastructure`` qui vérifie son mapping).

5. **Zéro logique applicative ici**. La façade ne fait que ``import`` +
   ``__all__``. Toute logique (validation, defaults, migrations) vit dans les
   sous-modules correspondants ou dans ``app/services``. La garde est assurée
   par ``test_file_is_imports_and_all_only``.

Références :
- SQLAlchemy 2.0 ORM Quickstart §« Declarative Mapping » — exige le chargement
  des classes Base avant ``create_all``.
- PEP 328 (imports absolus) + PEP 8 §« Module Level Dunder Names » — ``__all__``
  après les imports.
- Zen of Python §« There should be one — and preferably only one — obvious way
  to do it. »
"""

from __future__ import annotations

# --- Infrastructure ORM (héritée par tous les autres modèles) -------------
from app.models.base import BaseModel, TimestampMixin, ensure_utc, iso_or_none

# --- Authentification et utilisateurs -------------------------------------
from app.models.audit import AuditAction, AuditLog
from app.models.login_attempt import LoginAttempt
from app.models.session import Session
from app.models.user import User, UserRole
from app.models.user_preference import UserPreference
from app.models.user_onboarding_progress import UserOnboardingProgress
from app.models.user_activity_summary import UserActivitySummary
from app.models.tenant_setup_progress import (
    SINGLETON_ROW_ID as TENANT_SETUP_SINGLETON_ID,
    TENANT_SETUP_MILESTONE_FIELDS,
    TenantSetupProgress,
)
from app.models.anonymization_audit import AnonymizationAudit
from app.models.anonymization_term import AnonymizationTerm
from app.models.data_access_rule import (
    DataAccessEffect,
    DataAccessRule,
    DataAccessScope,
)

# --- Configuration et connecteurs -----------------------------------------
from app.models.ai_config import (
    AIConfig,
    AIConfigCategory,
    AIConfigDefault,
    AIConfigKey,
    AIConfigValueType,
    DEFAULT_AI_CONFIG,
    SECRET_CONFIG_KEYS,
)
from app.models.llm_model import LlmModel
from app.models.db_config import DatabaseConnection, DatabaseType
from app.models.smtp_global_config import SMTPGlobalConfig
from app.models.smtp_settings import SMTPSettings  # Déprécié — préserve la table héritée

# --- IA (RAG NL→SQL, performance, apprentissage) --------------------------
from app.models.ai_performance import AIPerformanceLog, QueryStatus, SchemaSync
from app.models.concept_glossary import ConceptGlossary
from app.models.training_data import TrainingData, TrainingDataType
from app.models.value_mapping import ValueMapping
from app.models.value_mapping_archive import ValueMappingArchive
from app.models.inferred_foreign_key import (
    INFERRED_FK_KINDS,
    KIND_NAMING_AND_VALUE,
    KIND_NAMING_PATTERN,
    KIND_VALUE_OVERLAP,
    InferredForeignKey,
)

# --- Stockage utilisateur -------------------------------------------------
from app.models.user_storage import FileMetadata, UserStorage

# --- Recherche, requêtes et historique ------------------------------------
# SavedQuery (table BDD) supprime — la SSoT pour les requetes Iris est le
# datastore filesystem (.sql files via /api/datastore/sql/*). Cf. decision
# utilisateur du 2026-05-05 « casse net ».
from app.models.search_history import SearchHistory
from app.models.query_diff_history import QueryDiffHistory

# --- Automatisations (workflow engine) ------------------------------------
from app.models.automation import Automation
from app.models.automation_edge import EDGE_DATA_TYPES, AutomationEdge
from app.models.automation_step import (
    STEP_CATEGORIES,
    STEP_TYPE_META,
    AutomationStep,
    StepType,
)
from app.models.execution import Execution
from app.models.idempotency_log import IDEMPOTENCY_TTL_HOURS, IdempotencyLog
from app.models.step_execution import StepExecution
from app.models.wait_token import (
    WAIT_RESPONSE_KINDS,
    WAIT_TOKEN_STATUSES,
    WaitToken,
)

# --- Conversations Iris ---------------------------------------------------
from app.models.conversation import (
    Conversation,
    ConversationEvent,
    ConversationMessage,
    MessageRole,
)

# --- Audit des écritures SQL via Iris (admin only) ------------------------
from app.models.sql_write_audit import (
    SqlWriteAuditLog,
    SqlWriteOperation,
    SqlWriteStatus,
)

# --- Pipeline NL→SQL (lancée depuis l'agent SQL d'Iris) ------------------
from app.models.pipeline_run import (
    PipelineMode,
    PipelinePhaseExecution,
    PipelinePhaseStatus,
    PipelineRun,
    PipelineRunStatus,
    TriggeredVia,
)

# --- Tableaux de bord personnalisables ------------------------------------
from app.models.dashboard import (
    VALID_SCHEDULE_TYPES,
    Dashboard,
    DashboardFilter,
    DashboardSchedule,
    DashboardWidget,
)

# --- Webhooks et déclencheurs externes ------------------------------------
from app.models.webhook_trigger import WebhookTrigger

# --- Feature flags globaux (kill-switch admin, bypass cache, etc.) --------
from app.models.feature_flag import FLAG_AUTOMATIONS_DISABLED, FeatureFlag

# --- Contacts et listes de diffusion --------------------------------------
from app.models.contact import Contact, DistributionList, contact_list_association

# --- Journal emails et rapports archivés ----------------------------------
from app.models.email_log import EmailLog
from app.models.report import Report

__all__ = (
    # Infrastructure ORM
    "BaseModel",
    "TimestampMixin",
    "ensure_utc",
    "iso_or_none",
    # Authentification et utilisateurs
    "AuditAction",
    "AuditLog",
    "LoginAttempt",
    "Session",
    "User",
    "UserRole",
    "UserPreference",
    "UserOnboardingProgress",
    "UserActivitySummary",
    "TENANT_SETUP_SINGLETON_ID",
    "TENANT_SETUP_MILESTONE_FIELDS",
    "TenantSetupProgress",
    "AnonymizationAudit",
    "AnonymizationTerm",
    "DataAccessEffect",
    "DataAccessRule",
    "DataAccessScope",
    # Configuration et connecteurs
    "AIConfig",
    "AIConfigCategory",
    "AIConfigDefault",
    "AIConfigKey",
    "AIConfigValueType",
    "DEFAULT_AI_CONFIG",
    "SECRET_CONFIG_KEYS",
    "LlmModel",
    "DatabaseConnection",
    "DatabaseType",
    "SMTPGlobalConfig",
    "SMTPSettings",
    # IA (RAG NL→SQL)
    "AIPerformanceLog",
    "ConceptGlossary",
    "QueryStatus",
    "SchemaSync",
    "TrainingData",
    "TrainingDataType",
    "ValueMapping",
    "ValueMappingArchive",
    "INFERRED_FK_KINDS",
    "KIND_NAMING_AND_VALUE",
    "KIND_NAMING_PATTERN",
    "KIND_VALUE_OVERLAP",
    "InferredForeignKey",
    # Stockage utilisateur
    "FileMetadata",
    "UserStorage",
    # Recherche, requêtes et historique (SavedQuery supprime — datastore SSoT)
    "SearchHistory",
    "QueryDiffHistory",
    # Automatisations
    "Automation",
    "AutomationEdge",
    "AutomationStep",
    "EDGE_DATA_TYPES",
    "Execution",
    "IDEMPOTENCY_TTL_HOURS",
    "IdempotencyLog",
    "STEP_CATEGORIES",
    "STEP_TYPE_META",
    "StepExecution",
    "StepType",
    "WAIT_RESPONSE_KINDS",
    "WAIT_TOKEN_STATUSES",
    "WaitToken",
    # Conversations
    "Conversation",
    "ConversationEvent",
    "ConversationMessage",
    "MessageRole",
    # Audit écritures SQL via Iris
    "SqlWriteAuditLog",
    "SqlWriteOperation",
    "SqlWriteStatus",
    # Pipeline NL→SQL
    "PipelineMode",
    "PipelinePhaseExecution",
    "PipelinePhaseStatus",
    "PipelineRun",
    "PipelineRunStatus",
    "TriggeredVia",
    # Tableaux de bord
    "Dashboard",
    "DashboardFilter",
    "DashboardSchedule",
    "DashboardWidget",
    "VALID_SCHEDULE_TYPES",
    # Webhooks
    "WebhookTrigger",
    # Feature flags
    "FLAG_AUTOMATIONS_DISABLED",
    "FeatureFlag",
    # Contacts et listes de diffusion
    "Contact",
    "DistributionList",
    "contact_list_association",
    # Journal emails et rapports archivés
    "EmailLog",
    "Report",
)
