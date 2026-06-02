"""
Définition centralisée de toutes les routes de l'application.

Séparer les routes de main.py permet :
- De lire d'un coup toutes les URL de l'app
- De modifier les routes sans toucher au lifecycle de l'application
- De réduire main.py à sa responsabilité unique : orchestrer le démarrage
"""

from app.handlers.health import (
    HealthDetailedHandler,
    HealthHandler,
    HealthReadyHandler,
    SchedulerHealthHandler,
)
from app.handlers.auth import LoginHandler, LogoutHandler, XsrfTokenAPIHandler
from app.handlers.dashboard import DashboardHandler, DashboardChartsAPIHandler
from app.handlers.performance import (
    PerformanceStatsHandler,
    PerformanceStatsAPIHandler,
    CacheClearHandler,
    SourceDBPingHandler,
    LLMProvidersPingHandler,
)
from app.handlers.admin import (
    AdminHandler,
    UserAPIHandler,
    UserBulkAPIHandler,
    UserSessionsAPIHandler,
    UsersAPIHandler,
)
from app.handlers.db_config import (
    DatabaseConfigHandler,
    DatabaseConfigAPIHandler,
    DatabaseConfigDetailAPIHandler,
    DatabaseConfigActivateHandler,
    DatabaseConfigTestHandler,
    SageModeHandler,
)
from app.handlers.automations import (
    AutomationsListHandler,
    AutomationCreateHandler,
    AutomationToggleHandler,
    AutomationDeleteHandler,
    AutomationDuplicateHandler,
    AutomationExecuteHandler,
    AutomationHistoryHandler,
    AutomationExecutionsAPIHandler,
    AutomationDownloadHandler,
    AllExecutionsHandler,
    ExecutionDetailHandler,
    AutomationStepTypesAPIHandler,
    AutomationStepsAPIHandler,
    AutomationStepDetailAPIHandler,
    AutomationStepsReorderAPIHandler,
    AutomationEdgesAPIHandler,
    AutomationEdgeDetailAPIHandler,
    AutomationDAGAPIHandler,
    AutomationLayoutAPIHandler,
    AutomationValidateAPIHandler,
    AutomationScheduleAPIHandler,
    AutomationSchedulePreviewAPIHandler,
    AutomationEditHandler,
    AutomationNewHandler,
    AutomationTemplateDetailHandler,
    AutomationTemplateInstantiateHandler,
    AutomationTemplatesListHandler,
    AutomationTemplatesPageHandler,
    ExecutionReplayHandler,
    ExecutionLogsCSVHandler,
    RunningExecutionsAPIHandler,
    ExecutionStepDetailAPIHandler,
    ExecutionStepsAPIHandler,
    AutomationExportHandler,
    AutomationImportHandler,
    AutomationPreviewOutputHandler,
)
from app.handlers.automation_preview_ws import AutomationPreviewWebSocketHandler
from app.handlers.admin_feature_flags import (
    FeatureFlagDetailHandler,
    FeatureFlagsListHandler,
)
from app.handlers.templates import (
    TemplatesListHandler,
    TemplateDetailHandler,
    TemplatePreviewHandler,
)
from app.handlers.contacts import (
    ContactsPageHandler,
    ContactsAPIHandler,
    ContactDetailAPIHandler,
    ContactImportAPIHandler,
    ContactStatsAPIHandler,
    ContactsSendEmailAPIHandler,
    DistributionListsAPIHandler,
    DistributionListDetailAPIHandler,
    DistributionListMembersAPIHandler,
    DistributionListMembersBatchAPIHandler,
)
from app.handlers.email_history import EmailHistoryPageHandler, EmailHistoryAPIHandler
from app.handlers.privacy_page import PrivacyPageHandler
from app.handlers.feedback import FeedbackReportHandler
from app.handlers.csp_report import CSPReportHandler
from app.handlers.system_events import (
    SystemEventsSSEHandler,
    SystemSyncStatusHandler,
)
from app.handlers.iris import (
    IrisPageHandler,
    IrisWebSocketHandler,
    IrisClearAPIHandler,
    IrisFeedbackAPIHandler,
    IrisModeUsageStatsHandler,
    IrisParseAttachmentHandler,
    IrisUploadCancelHandler,
    IrisUploadHandler,
    IrisUsageStatsAPIHandler,
    IrisUserMemoryAPIHandler,
    IrisWelcomeSuggestionsAPIHandler,
    IrisWidgetConversationAPIHandler,
)
from app.handlers.iris_export import IrisAnonymizeTabsHandler, IrisExportXlsxFullHandler
from app.handlers.iris_pipeline_api import (
    IrisPipelineArchiveHandler,
    IrisPipelineArtifactHandler,
    IrisPipelineHistoryHandler,
    IrisPipelineRunCreateHandler,
    IrisPipelineStatusHandler,
)
from app.handlers.iris_pipeline_ws import IrisPipelineWebSocketHandler
from app.handlers.result_assistant import (
    CellSuggestHandler,
    CopilotCancelHandler,
    CopilotTaskProgressHandler,
    ResultModifyHandler,
)
from app.handlers.anonymization import (
    AnonymizationAddManualAPIHandler,
    AnonymizationAuditAPIHandler,
    AnonymizationAutoClassifyAPIHandler,
    AnonymizationAutoClassifyProbeAPIHandler,
    AnonymizationAutoClassifyRegexAPIHandler,
    AnonymizationImprovePseudoAPIHandler,
    AnonymizationImprovePseudoProbeAPIHandler,
    AnonymizationExportAPIHandler,
    AnonymizationScanAPIHandler,
    AnonymizationScanWorkbookAPIHandler,
    AnonymizationStatsAPIHandler,
    AnonymizationTermCoverageAPIHandler,
    AnonymizationTermDeleteAPIHandler,
    AnonymizationTermsAPIHandler,
    AnonymizationWipeAPIHandler,
)
from app.handlers.admin_smtp import (
    AdminSMTPConfigHandler,
    AdminSMTPConfigAPIHandler,
    AdminSMTPTestHandler,
)
from app.handlers.data_access_admin import (
    DataAccessCopyRulesAPIHandler,
    DataAccessMatrixAPIHandler,
    DataAccessPageHandler,
    DataAccessPreviewImpactAPIHandler,
    DataAccessRuleAPIHandler,
    DataAccessRuleRestoreAPIHandler,
    DataAccessRulesAPIHandler,
    DataAccessTablesAPIHandler,
    DataAccessUsersAPIHandler,
)
from app.handlers.reports import (
    ReportsPageHandler,
    ReportsAPIHandler,
    ReportDownloadHandler,
    ReportShareHandler,
    ReportArchiveHandler,
    ReportEmailHandler,
    ReportClasseursListHandler,
    ReportClasseurTabsHandler,
    ReportLLMLimitsHandler,
    ReportGenerateLLMHandler,
)
from app.handlers.workbooks import (
    ListWorkbooksHandler,
    WorkbookTabsHandler,
    WorkbookTabDataHandler,
    ListExcelSheetsHandler,
    LoadExcelSheetHandler,
    LoadCsvFileHandler,
)
from app.handlers.datastore import (
    DatastorePageHandler,
    DatastoreListAPIHandler,
    DatastoreUploadAPIHandler,
    DatastoreMkdirAPIHandler,
    DatastoreRenameAPIHandler,
    DatastoreDeleteAPIHandler,
    DatastoreDownloadAPIHandler,
    DatastorePreviewAPIHandler,
    DatastoreSqlExecuteAPIHandler,
    DatastoreSqlSaveAPIHandler,
    DatastoreFoldersAPIHandler,
    DatastoreMoveAPIHandler,
    SaveSearchAPIHandler,
    ContextFilesAPIHandler,
)
from app.handlers.ai_admin import (
    AIPerformanceDashboardHandler,
    AITrainingPageHandler,
    AIStatsAPIHandler,
    AIRecentQueriesAPIHandler,
    AITrainingDataAPIHandler,
    AITrainingDataDeleteHandler,
    AISchemaSyncAPIHandler,
    AISchemaTablesAPIHandler,
    AIModelsAPIHandler,
    LlmModelRegistryHandler,
    LlmModelRegistrySyncHandler,
    LlmModelRegistryLitellmSyncHandler,
    LlmModelOverrideHandler,
    LocalLlmStatusHandler,
    LocalLlmPullHandler,
    LocalLlmDeleteHandler,
    LocalLlmInstallStatusHandler,
    LocalLlmStartHandler,
    LocalLlmRestartHandler,
    LocalLlmUpgradeHandler,
    AIFeedbackAPIHandler,
    AIFeedbackExportHandler,
    AIUsageAPIHandler,
    AITrainingPendingAPIHandler,
    AITrainingApproveHandler,
    AITrainingRejectHandler,
    AITrainingAutoRewritesAPIHandler,
    AITrainingRollbackRewriteHandler,
)
from app.handlers.dashboard_builder import (
    DashboardBuilderPageHandler,
    DashboardBuilderViewHandler,
    DashboardAPIHandler,
    DashboardDetailAPIHandler,
    DashboardCloneAPIHandler,
    DashboardWidgetAPIHandler,
    DashboardWidgetLLMAPIHandler,
    DashboardWidgetDetailAPIHandler,
    DashboardWidgetReorderAPIHandler,
    DashboardCoherenceAPIHandler,
    DashboardDataAPIHandler,
    DashboardMetricsAPIHandler,
    DashboardFilterAPIHandler,
    DashboardFilterDetailAPIHandler,
    DashboardFilterOptionsAPIHandler,
    DashboardFilterReorderAPIHandler,
    DashboardScheduleAPIHandler,
    DashboardSendNowAPIHandler,
    DashboardTemplatesAPIHandler,
    DashboardTemplateCreateAPIHandler,
    DashboardSaveAsTemplateAPIHandler,
    DashboardUserTemplateCreateAPIHandler,
    DashboardUserTemplateDeleteAPIHandler,
)
from app.handlers.drilldown import (
    DrillDownHandler,
    DrillDownAnalyzeHandler,
    ExpandColumnsHandler,
    CellDetailExecuteHandler,
)
from app.handlers.webhooks import (
    WebhookInboundHandler,
    WebhookListAPIHandler,
    WebhookDetailAPIHandler,
    WebhookRegenerateAPIHandler,
)
from app.handlers.ai_config import (
    AIConfigPageHandler,
    AIConfigAPIHandler,
    AIConfigResetHandler,
    AIConfigExportHandler,
    AIConfigImportHandler,
    AISchemaSyncHandler,
    AISchemaSyncStreamHandler,
    AIHealthCheckHandler,
    AIDocResetHandler,
)
from app.handlers.settings import (
    SettingsBootstrapAPIHandler,
    SettingsPageHandler,
    SettingsProfileAPIHandler,
    SettingsPasswordAPIHandler,
    SettingsAppearanceAPIHandler,
    SettingsCompanyAPIHandler,
    SettingsIrisConsentAPIHandler,
)
from app.handlers.help_docs import HelpGuideDownloadHandler
from app.handlers.onboarding import (
    OnboardingResetHandler,
    OnboardingStateHandler,
    OnboardingTourCompleteHandler,
    OnboardingTourSkipHandler,
    OnboardingTourStartHandler,
    OnboardingTourStepHandler,
    TenantSetupDismissHandler,
    TenantSetupMilestoneHandler,
    TenantSetupResumeHandler,
    TenantSetupStateHandler,
)
from app.handlers.wait_response import WaitResponseHandler
from app.handlers.iris_sql_write_dba import (
    IrisSqlWriteAuditAPIHandler,
    IrisSqlWriteAuditDetailAPIHandler,
    IrisSqlWriteDbaHandler,
)


def get_routes() -> list:
    """Retourne la liste complète des routes de l'application."""
    return [
        # ── Health check ──
        (r"/health", HealthHandler),
        (r"/health/ready", HealthReadyHandler),
        (r"/health/detailed", HealthDetailedHandler),
        (r"/health/scheduler", SchedulerHealthHandler),
        # ── Authentication ──
        (r"/login", LoginHandler, {}, "login"),
        (r"/logout", LogoutHandler, {}, "logout"),
        (r"/api/auth/xsrf", XsrfTokenAPIHandler),
        # ── Signalement utilisateur (feedback / rapport d'erreur, anonyme OK) ──
        (r"/api/feedback/report", FeedbackReportHandler),
        # ── Rapports CSP du navigateur (anonyme, pas de XSRF — endpoint dédié) ──
        (r"/api/csp-report", CSPReportHandler),
        # ── Pages principales ──
        (r"/", DashboardHandler),
        (r"/dashboard", DashboardHandler),
        # ── Iris — Agent IA conversationnel ──
        (r"/iris", IrisPageHandler),
        (r"/ws/iris", IrisWebSocketHandler),
        (r"/api/iris/clear", IrisClearAPIHandler),
        (r"/api/iris/feedback", IrisFeedbackAPIHandler),
        (r"/api/iris/user-memory", IrisUserMemoryAPIHandler),
        (r"/api/iris/upload", IrisUploadHandler),
        # MED-8 — supprime un fichier uploadé que l'user retire avant
        # d'envoyer son message (évite fuite disque TTL window 30j).
        (r"/api/iris/upload/cancel", IrisUploadCancelHandler),
        # Task #34 / #8 Phase 2 — parse un fichier uploadé en JSON
        # tabs/rows pour affichage en grille iris-sql-card inline.
        (r"/api/iris/parse-attachment", IrisParseAttachmentHandler),
        # Admin instrumentation widget vs page (task #17). Pas d'UI pour
        # l'instant — appel via curl/script suffit pour la décision #16.
        (r"/api/admin/iris-usage-stats", IrisUsageStatsAPIHandler),
        # Task #43c (cycle #33) — monitoring usage modes legacy vs éphémère
        # pour préparer la décision #43d/#43e (suppression handler legacy).
        (r"/api/admin/iris-mode-usage", IrisModeUsageStatsHandler),
        # Suggestions d'accueil dynamiques (task #11). SSOT = même service
        # que la page /iris (sync_svc.generate_welcome_suggestions).
        (r"/api/iris/welcome-suggestions", IrisWelcomeSuggestionsAPIHandler),
        # Rehydratation overlay widget (2026-05-26). Pendant API du SSR
        # ``_rehydrate_conversation`` de la page /iris : le widget n'a
        # pas de SSR donc il appelle cet endpoint au boot / à la première
        # ouverture pour récupérer son historique persisté (source=widget).
        (r"/api/iris/widget/conversation", IrisWidgetConversationAPIHandler),
        (r"/api/iris/result-modify", ResultModifyHandler),
        (r"/api/iris/result-cancel", CopilotCancelHandler),
        (r"/api/iris/cell-suggest", CellSuggestHandler),
        (r"/api/iris/task-progress", CopilotTaskProgressHandler),
        (r"/api/iris/export-xlsx-full", IrisExportXlsxFullHandler),
        (r"/api/iris/anonymize-tabs", IrisAnonymizeTabsHandler),
        # ── Iris-DBA-write — approbation par DBA externe via mail ──
        # GET = page de confirmation (le DBA cliquant le lien dans le mail).
        # POST = action confirm/reject. Pas d'auth Komptia (token HMAC fait foi).
        (r"/iris/sql-write/dba/([A-Za-z0-9._\-]{20,200})", IrisSqlWriteDbaHandler),
        # Vue admin de l'historique d'audit (auth admin requise via prepare()).
        (r"/api/iris/sql-write/audit", IrisSqlWriteAuditAPIHandler),
        # Détail d'une demande pour l'admin demandeur (suivi sans attendre mail).
        (r"/api/iris/sql-write/audit/(\d+)", IrisSqlWriteAuditDetailAPIHandler),
        # ── Pipeline NL→SQL (lancée depuis l'agent SQL d'Iris) ──
        (r"/ws/iris/pipeline", IrisPipelineWebSocketHandler),
        (r"/api/iris/pipeline-run", IrisPipelineRunCreateHandler),
        (r"/api/iris/pipeline-history", IrisPipelineHistoryHandler),
        (r"/api/iris/pipeline/(\d+)", IrisPipelineStatusHandler),
        (r"/api/iris/pipeline/(\d+)/archive", IrisPipelineArchiveHandler),
        (
            r"/api/iris/pipeline/(\d+)/artifacts/([\w.-]+)",
            IrisPipelineArtifactHandler,
        ),
        # ── Anonymisation pilotée utilisateur (liste en BDD) ──
        (r"/api/anonymization/terms", AnonymizationTermsAPIHandler),
        # IMPORTANT: /terms/manual avant /terms/(\d+) pour que la route
        # littérale matche avant la regex numérique (Tornado route au
        # premier match). Sans ça, ``/terms/manual`` serait routé vers
        # ``AnonymizationTermDeleteAPIHandler`` avec ``"manual"`` interprété
        # comme un id invalide.
        (r"/api/anonymization/terms/manual", AnonymizationAddManualAPIHandler),
        (r"/api/anonymization/auto-classify", AnonymizationAutoClassifyAPIHandler),
        (
            r"/api/anonymization/auto-classify/probe",
            AnonymizationAutoClassifyProbeAPIHandler,
        ),
        # ── Amélioration des pseudonymes (LLM local enrichit les
        # pseudo_middle). Provider-agnostic (Ollama/LMStudio/TGI/vLLM/…).
        # Spécifique (/probe) AVANT générique pour matcher correctement.
        (
            r"/api/anonymization/improve-pseudo/probe",
            AnonymizationImprovePseudoProbeAPIHandler,
        ),
        (
            r"/api/anonymization/improve-pseudo",
            AnonymizationImprovePseudoAPIHandler,
        ),
        # ── Anonymisation — endpoints étendus (tâche #10) ──
        # Détail par ressource — IMPORTANT: spécifique avant générique pour
        # que /:id/coverage matche avant /:id (Tornado route au premier match).
        (
            r"/api/anonymization/terms/(\d+)/coverage",
            AnonymizationTermCoverageAPIHandler,
        ),
        (r"/api/anonymization/terms/(\d+)", AnonymizationTermDeleteAPIHandler),
        (r"/api/anonymization/audit", AnonymizationAuditAPIHandler),
        (r"/api/anonymization/export", AnonymizationExportAPIHandler),
        (r"/api/anonymization/wipe", AnonymizationWipeAPIHandler),
        (r"/api/anonymization/stats", AnonymizationStatsAPIHandler),
        (
            r"/api/anonymization/auto-classify/regex",
            AnonymizationAutoClassifyRegexAPIHandler,
        ),
        (r"/api/anonymization/scan", AnonymizationScanAPIHandler),
        (r"/api/anonymization/scan-workbook", AnonymizationScanWorkbookAPIHandler),
        # ── Drill-down SQL ──
        (r"/api/drilldown", DrillDownHandler),
        (r"/api/drilldown/analyze", DrillDownAnalyzeHandler),
        (r"/api/cell-detail/execute", CellDetailExecuteHandler),
        (r"/api/expand-columns", ExpandColumnsHandler),
        # ── Paramètres utilisateur ──
        (r"/settings", SettingsPageHandler),
        (r"/api/settings/profile", SettingsProfileAPIHandler),
        (r"/api/settings/password", SettingsPasswordAPIHandler),
        (r"/api/settings/appearance", SettingsAppearanceAPIHandler),
        (r"/api/settings/company", SettingsCompanyAPIHandler),
        (r"/api/settings/iris-consent", SettingsIrisConsentAPIHandler),
        # S-14 (2026-05-26) : agrégateur lecture des 4 endpoints en 1 RTT.
        (r"/api/settings/bootstrap", SettingsBootstrapAPIHandler),
        # ── Aide : guides PDF par rôle (whitelist + fail-closed admin) ──
        # Hors /api/ (comme /share/report/<token>) : ce sont des liens cliqués en
        # navigation top-level. Une erreur (404 fichier absent / session expirée)
        # rend ainsi error.html / redirige vers /login, au lieu d'un JSON brut
        # (write_error → _wants_json renvoie False hors /api/ pour un Accept HTML).
        # La clé est résolue contre la whitelist HELP_GUIDES côté handler ; le regex
        # limite déjà à [a-z0-9_-]+ (pas de point/slash → pas de traversal).
        (r"/help/guides/([a-z0-9_-]+)", HelpGuideDownloadHandler),
        # ── Onboarding (user-scoped — tours + activity summary) ──
        (r"/api/onboarding/state", OnboardingStateHandler),
        (r"/api/onboarding/tour/start", OnboardingTourStartHandler),
        (r"/api/onboarding/tour/step", OnboardingTourStepHandler),
        (r"/api/onboarding/tour/complete", OnboardingTourCompleteHandler),
        (r"/api/onboarding/tour/skip", OnboardingTourSkipHandler),
        # ── Administration ──
        (r"/admin", AdminHandler),
        (r"/admin/performance", PerformanceStatsHandler),
        # ── Setup admin (singleton — checklist déploiement) ──
        (r"/api/admin/tenant-setup", TenantSetupStateHandler),
        (r"/api/admin/tenant-setup/milestone", TenantSetupMilestoneHandler),
        (r"/api/admin/tenant-setup/dismiss", TenantSetupDismissHandler),
        (r"/api/admin/tenant-setup/resume", TenantSetupResumeHandler),
        (r"/api/admin/onboarding/reset", OnboardingResetHandler),
        # ── IA — Dashboard, Training, Config ──
        (r"/admin/ai-performance", AIPerformanceDashboardHandler),
        (r"/admin/ai-training", AITrainingPageHandler),
        (r"/admin/ai-config", AIConfigPageHandler),
        # ── Accès aux données (RLS par utilisateur) ──
        (r"/admin/data-access", DataAccessPageHandler),
        (r"/api/admin/data-access/users", DataAccessUsersAPIHandler),
        (r"/api/admin/data-access/tables", DataAccessTablesAPIHandler),
        (
            r"/api/admin/data-access/users/([0-9]+)/rules",
            DataAccessRulesAPIHandler,
        ),
        (
            r"/api/admin/data-access/users/([0-9]+)/rules/single",
            DataAccessRuleAPIHandler,
        ),
        (r"/api/admin/data-access/rules/([0-9]+)", DataAccessRuleAPIHandler),
        # **#139** — Toast undo post-delete : restore d'une règle soft-deleted.
        (
            r"/api/admin/data-access/rules/([0-9]+)/restore",
            DataAccessRuleRestoreAPIHandler,
        ),
        # Phase α.7 (#73) — Preview impact d'une règle proposée AVANT pose.
        (
            r"/api/admin/data-access/users/([0-9]+)/preview-impact",
            DataAccessPreviewImpactAPIHandler,
        ),
        # P2 (#30) — Dupliquer les règles d'un user vers un autre.
        (
            r"/api/admin/data-access/users/([0-9]+)/copy-rules-to/([0-9]+)",
            DataAccessCopyRulesAPIHandler,
        ),
        # P2 (#29) — Vue d'ensemble matrice (users × tables denied).
        (r"/api/admin/data-access/matrix", DataAccessMatrixAPIHandler),
        # ── Configuration BDD (admin) ──
        (r"/admin/database", DatabaseConfigHandler),
        (r"/api/db-config", DatabaseConfigAPIHandler),
        (r"/api/db-config/test", DatabaseConfigTestHandler),
        (r"/api/db-config/([0-9]+)", DatabaseConfigDetailAPIHandler),
        (r"/api/db-config/([0-9]+)/activate", DatabaseConfigActivateHandler),
        (r"/api/db-config/([0-9]+)/test", DatabaseConfigTestHandler),
        (r"/api/sage-mode", SageModeHandler),
        # ── Performance ──
        (r"/api/performance/stats", PerformanceStatsAPIHandler),
        (r"/api/performance/ping-source-db", SourceDBPingHandler),
        (r"/api/performance/ping-llm-providers", LLMProvidersPingHandler),
        (r"/api/cache/clear", CacheClearHandler),
        # ── API IA ──
        (r"/api/ai/stats", AIStatsAPIHandler),
        (r"/api/ai/queries", AIRecentQueriesAPIHandler),
        (r"/api/ai/training", AITrainingDataAPIHandler),
        (r"/api/ai/training/pending", AITrainingPendingAPIHandler),
        (r"/api/ai/training/auto-rewrites", AITrainingAutoRewritesAPIHandler),
        (r"/api/ai/training/([0-9]+)/approve", AITrainingApproveHandler),
        (r"/api/ai/training/([0-9]+)/reject", AITrainingRejectHandler),
        (
            r"/api/ai/training/([0-9]+)/rollback-rewrite",
            AITrainingRollbackRewriteHandler,
        ),
        (r"/api/ai/training/([0-9]+)", AITrainingDataDeleteHandler),
        (r"/api/ai/schema-sync", AISchemaSyncAPIHandler),
        (r"/api/ai/schema-sync/history", AISchemaSyncAPIHandler),
        # Autocomplete des noms de tables pour l'UI admin business_context
        (r"/api/ai/schema/tables", AISchemaTablesAPIHandler),
        (r"/api/ai/models", AIModelsAPIHandler),
        # Registre dynamique BDD-backed (Phase 2 refonte) — listing, sync,
        # override admin. ``AIModelsAPIHandler`` (au-dessus) reste l'API
        # legacy qui interroge directement les providers ; cette nouvelle
        # API expose les méta-données stockées en BDD.
        (r"/api/admin/llm/models", LlmModelRegistryHandler),
        (r"/api/admin/llm/models/sync", LlmModelRegistrySyncHandler),
        # ``sync-litellm`` enrichit context_window/max_output_tokens depuis le
        # registre public LiteLLM. Doit venir AVANT la route paramétrée
        # ``([A-Za-z0-9_.\-]+)`` qui matcherait sinon ``sync-litellm`` comme
        # un nom de modèle.
        (r"/api/admin/llm/models/sync-litellm", LlmModelRegistryLitellmSyncHandler),
        # SSE global pour broadcast d'événements système (overlay sync schéma
        # visible par tous les users authentifiés).
        (r"/api/system/events", SystemEventsSSEHandler),
        # Snapshot synchrone de la sync en cours (pour réafficher l'overlay
        # après un page refresh en plein milieu d'une sync — l'event bus
        # n'a pas de replay).
        (r"/api/system/sync-status", SystemSyncStatusHandler),
        (r"/api/admin/llm/models/([A-Za-z0-9_.\-]+)", LlmModelOverrideHandler),
        (r"/api/admin/llm-local/status", LocalLlmStatusHandler),
        (r"/api/admin/llm-local/pull", LocalLlmPullHandler),
        (r"/api/admin/llm-local/delete", LocalLlmDeleteHandler),
        (r"/api/admin/llm-local/install-status", LocalLlmInstallStatusHandler),
        (r"/api/admin/llm-local/start", LocalLlmStartHandler),
        (r"/api/admin/llm-local/restart", LocalLlmRestartHandler),
        (r"/api/admin/llm-local/upgrade", LocalLlmUpgradeHandler),
        (r"/api/ai/feedback/export", AIFeedbackExportHandler),
        (r"/api/ai/feedback/([0-9]+)", AIFeedbackAPIHandler),
        (r"/api/ai/usage", AIUsageAPIHandler),
        (r"/api/ai/config", AIConfigAPIHandler),
        (r"/api/ai/config/reset", AIConfigResetHandler),
        (r"/api/ai/config/export", AIConfigExportHandler),
        (r"/api/ai/config/import", AIConfigImportHandler),
        (r"/api/ai/schema/sync", AISchemaSyncHandler),
        (r"/api/ai/schema/sync/stream", AISchemaSyncStreamHandler),
        (r"/api/ai/health", AIHealthCheckHandler),
        (r"/api/ai/doc/reset", AIDocResetHandler),
        # Routes /api/saved-queries supprimees — la SSoT pour les
        # requetes Iris est le datastore filesystem (.sql files via
        # /api/datastore/sql/*). Cf. decision utilisateur 2026-05-05.
        # ── Dashboard search ──
        (r"/api/dashboard/charts", DashboardChartsAPIHandler),
        # ── Dashboard Builder (Visualisation Power BI) ──
        (r"/dashboards", DashboardBuilderPageHandler),
        (r"/dashboards/([0-9]+)", DashboardBuilderViewHandler),
        (r"/api/dashboards", DashboardAPIHandler),
        (r"/api/dashboards/templates", DashboardTemplatesAPIHandler),
        (r"/api/dashboards/templates/([a-z0-9-]+)/create", DashboardTemplateCreateAPIHandler),
        (r"/api/dashboards/user-templates/([0-9]+)/create", DashboardUserTemplateCreateAPIHandler),
        (r"/api/dashboards/user-templates/([0-9]+)", DashboardUserTemplateDeleteAPIHandler),
        (r"/api/dashboards/metrics", DashboardMetricsAPIHandler),
        (r"/api/dashboards/([0-9]+)", DashboardDetailAPIHandler),
        (r"/api/dashboards/([0-9]+)/clone", DashboardCloneAPIHandler),
        (r"/api/dashboards/([0-9]+)/save-as-template", DashboardSaveAsTemplateAPIHandler),
        (r"/api/dashboards/([0-9]+)/widgets", DashboardWidgetAPIHandler),
        (r"/api/dashboards/([0-9]+)/widgets/llm", DashboardWidgetLLMAPIHandler),
        (r"/api/dashboards/([0-9]+)/widgets/reorder", DashboardWidgetReorderAPIHandler),
        (r"/api/dashboards/([0-9]+)/widgets/([0-9]+)", DashboardWidgetDetailAPIHandler),
        (r"/api/dashboards/([0-9]+)/filters/options", DashboardFilterOptionsAPIHandler),
        (r"/api/dashboards/([0-9]+)/filters/reorder", DashboardFilterReorderAPIHandler),
        (r"/api/dashboards/([0-9]+)/filters/([0-9]+)", DashboardFilterDetailAPIHandler),
        (r"/api/dashboards/([0-9]+)/filters", DashboardFilterAPIHandler),
        (r"/api/dashboards/([0-9]+)/coherence", DashboardCoherenceAPIHandler),
        (r"/api/dashboards/([0-9]+)/data", DashboardDataAPIHandler),
        (r"/api/dashboards/([0-9]+)/schedule", DashboardScheduleAPIHandler),
        (r"/api/dashboards/([0-9]+)/send-now", DashboardSendNowAPIHandler),
        # ── Users (admin) ──
        (r"/api/users", UsersAPIHandler),
        # Bulk avant le suffix ``/<id>`` : sinon Tornado matche "bulk" comme
        # ID alphanumérique invalide (mais le pattern ``[0-9]+`` exclut déjà
        # "bulk" — l'ordre reste préférable pour la lisibilité de la route).
        (r"/api/users/bulk", UserBulkAPIHandler),
        (r"/api/users/([0-9]+)", UserAPIHandler),
        (r"/api/users/([0-9]+)/sessions", UserSessionsAPIHandler),
        # ── Webhooks (déclenchement externe d'automatisations) ──
        (
            r"/webhook/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
            WebhookInboundHandler,
        ),
        # ── Automatisations ──
        (r"/automations", AutomationsListHandler),
        # Phase 3b : nouveau canvas editor (remplace wizard)
        (r"/automations/new", AutomationNewHandler),
        (r"/automations/([0-9]+)/edit", AutomationEditHandler),
        # Preview live d'un step pendant la configuration de l'automation
        # (WebSocket — bouton "Apercu" du panel config dans /automations/N/edit).
        (r"/ws/automations/([0-9]+)/preview", AutomationPreviewWebSocketHandler),
        # B5 — sert les fichiers tmp generes par preview report/export.
        # Token HMAC en query param obligatoire (?token=v1.<exp>.<sig>).
        # Le filename inclut potentiellement des `.` (extension) donc on
        # accepte ([^/]+) au lieu de \w+.
        (
            r"/automations/([0-9]+)/preview/output/([0-9]+)/([^/]+)",
            AutomationPreviewOutputHandler,
        ),
        # U3 — wizard legacy supprime (cycle 3 APEX) : 30j de transition
        # ecoules. Le canvas DAG est le seul flow de creation
        # (POST /automations/new → /automations/:id/edit). Bookmark
        # /automations/wizard → 404 acceptable.
        (r"/automations/create", AutomationCreateHandler),
        (r"/automations/([0-9]+)/toggle", AutomationToggleHandler),
        (r"/automations/([0-9]+)/duplicate", AutomationDuplicateHandler),
        (r"/automations/([0-9]+)", AutomationDeleteHandler),
        (r"/automations/([0-9]+)/execute", AutomationExecuteHandler),
        # Q3 cycle 7 — /automations/preview legacy supprime (handler dead code,
        # 0 caller frontend apres suppression wizard cycle 3). Le preview live
        # passe par WS /ws/automations/N/preview (preview_service.py).
        (r"/automations/download/([0-9]+)", AutomationDownloadHandler),
        (r"/automations/history/([0-9]+)", AutomationHistoryHandler),
        (r"/api/automations/([0-9]+)/executions", AutomationExecutionsAPIHandler),
        # ── Endpoint public email_wait_response (sans auth) ──
        # Le destinataire externe (non-user Komptia) clique le lien
        # tokenise dans le mail → GET render le form, POST submit la
        # reponse. Auth = HMAC dans l'URL (cf. wait_token_codec.py),
        # XSRF Tornado desactive (pas de cookie de session).
        (r"/automations/wait/([A-Za-z0-9._-]{30,200})", WaitResponseHandler),
        (r"/api/automations/step-types", AutomationStepTypesAPIHandler),
        (r"/api/automations/([0-9]+)/steps", AutomationStepsAPIHandler),
        (r"/api/automations/([0-9]+)/steps/reorder", AutomationStepsReorderAPIHandler),
        (r"/api/automations/([0-9]+)/steps/([0-9]+)", AutomationStepDetailAPIHandler),
        # Phase 1 DAG : aretes du graphe
        (r"/api/automations/([0-9]+)/edges", AutomationEdgesAPIHandler),
        (r"/api/automations/([0-9]+)/edges/([0-9]+)", AutomationEdgeDetailAPIHandler),
        # Phase 3a DAG : hydratation canvas (nodes + edges + layout) + persistance positions
        (r"/api/automations/([0-9]+)/dag", AutomationDAGAPIHandler),
        (r"/api/automations/([0-9]+)/layout", AutomationLayoutAPIHandler),
        # Phase 3b-2 : validation non-mutante du DAG (bouton "Valider" canvas)
        (r"/api/automations/([0-9]+)/validate", AutomationValidateAPIHandler),
        # Schedule API : GET/PUT planification d'une automation + preview dry-run.
        # Le preview est un POST sans :id parce qu'il opere sur un payload arbitraire
        # (l'utilisateur edite avant d'avoir sauvegarde) — pas besoin d'ownership.
        # /preview AVANT /:id/schedule pour que la regex litterale matche d'abord.
        (r"/api/automations/schedule/preview", AutomationSchedulePreviewAPIHandler),
        (r"/api/automations/([0-9]+)/schedule", AutomationScheduleAPIHandler),
        # Phase 3d : galerie de templates d'automatisation (filesystem)
        (r"/automations/templates", AutomationTemplatesPageHandler),
        (r"/api/automation-templates", AutomationTemplatesListHandler),
        (
            r"/api/automation-templates/([a-zA-Z0-9_-]+)",
            AutomationTemplateDetailHandler,
        ),
        (
            r"/api/automation-templates/([a-zA-Z0-9_-]+)/instantiate",
            AutomationTemplateInstantiateHandler,
        ),
        # Phase 1 DAG : feature flags admin (kill-switch, etc.)
        (r"/api/admin/feature-flags", FeatureFlagsListHandler),
        (r"/api/admin/feature-flags/([a-z0-9_-]+)", FeatureFlagDetailHandler),
        (r"/api/automations/([0-9]+)/webhooks", WebhookListAPIHandler),
        (r"/api/automations/([0-9]+)/webhooks/([0-9]+)", WebhookDetailAPIHandler),
        (
            r"/api/automations/([0-9]+)/webhooks/([0-9]+)/regenerate",
            WebhookRegenerateAPIHandler,
        ),
        (r"/api/automations/([0-9]+)/export", AutomationExportHandler),
        (r"/api/automations/import", AutomationImportHandler),
        (r"/api/executions/running", RunningExecutionsAPIHandler),
        (r"/api/executions/([0-9]+)/steps", ExecutionStepsAPIHandler),
        # Phase 3c DAG viewer : detail complet d'une step_execution
        # (champs sensibles inclus — ownership 404 suffit pour autoriser).
        (
            r"/api/executions/([0-9]+)/steps/([0-9]+)",
            ExecutionStepDetailAPIHandler,
        ),
        # Phase 2b DAG : replay d'une execution + export CSV logs
        (r"/api/executions/([0-9]+)/replay", ExecutionReplayHandler),
        (r"/api/executions/([0-9]+)/logs\.csv", ExecutionLogsCSVHandler),
        (r"/executions", AllExecutionsHandler),
        (r"/executions/([0-9]+)", ExecutionDetailHandler),
        # ── Templates de rapports ──
        (r"/api/templates", TemplatesListHandler),
        (r"/api/templates/([a-z_]+)", TemplateDetailHandler),
        (r"/api/templates/([a-z_]+)/preview", TemplatePreviewHandler),
        # ── Contacts & Listes de diffusion ──
        (r"/contacts", ContactsPageHandler),
        (r"/api/contacts", ContactsAPIHandler),
        (r"/api/contacts/import", ContactImportAPIHandler),
        (r"/api/contacts/stats", ContactStatsAPIHandler),
        (r"/api/contacts/send-email", ContactsSendEmailAPIHandler),
        (r"/api/contacts/([0-9]+)", ContactDetailAPIHandler),
        (r"/api/distribution-lists", DistributionListsAPIHandler),
        (r"/api/distribution-lists/([0-9]+)", DistributionListDetailAPIHandler),
        (
            r"/api/distribution-lists/([0-9]+)/members/batch",
            DistributionListMembersBatchAPIHandler,
        ),
        (r"/api/distribution-lists/([0-9]+)/members", DistributionListMembersAPIHandler),
        (
            r"/api/distribution-lists/([0-9]+)/members/([0-9]+)",
            DistributionListMembersAPIHandler,
        ),
        # ── Datastore (gestionnaire de fichiers) ──
        (r"/datastore", DatastorePageHandler),
        (r"/api/datastore", DatastoreListAPIHandler),
        (r"/api/datastore/upload", DatastoreUploadAPIHandler),
        (r"/api/datastore/mkdir", DatastoreMkdirAPIHandler),
        (r"/api/datastore/rename", DatastoreRenameAPIHandler),
        (r"/api/datastore/delete", DatastoreDeleteAPIHandler),
        (r"/api/datastore/download", DatastoreDownloadAPIHandler),
        (r"/api/datastore/preview", DatastorePreviewAPIHandler),
        (r"/api/datastore/sql/execute", DatastoreSqlExecuteAPIHandler),
        (r"/api/datastore/sql/save", DatastoreSqlSaveAPIHandler),
        (r"/api/datastore/folders", DatastoreFoldersAPIHandler),
        (r"/api/datastore/move", DatastoreMoveAPIHandler),
        (r"/api/datastore/save-search", SaveSearchAPIHandler),
        (r"/api/datastore/context-files", ContextFilesAPIHandler),
        # ── Confidentialité (page utilisateur, pilote /api/anonymization/*) ──
        (r"/data/privacy", PrivacyPageHandler),
        # ── Historique emails ──
        (r"/email-history", EmailHistoryPageHandler),
        (r"/api/email-history", EmailHistoryAPIHandler),
        # ── SMTP (admin) ──
        (r"/admin/smtp-config", AdminSMTPConfigHandler),
        (r"/api/admin/smtp-config", AdminSMTPConfigAPIHandler),
        (r"/api/admin/smtp-config/test", AdminSMTPTestHandler),
        # ── Rapports ──
        (r"/reports", ReportsPageHandler),
        (r"/api/reports", ReportsAPIHandler),
        (r"/api/reports/send-email", ReportEmailHandler),
        (r"/api/reports/classeurs", ReportClasseursListHandler),
        (r"/api/reports/classeurs/tabs", ReportClasseurTabsHandler),
        (r"/api/reports/llm-limits", ReportLLMLimitsHandler),
        (r"/api/reports/generate-llm", ReportGenerateLLMHandler),
        (r"/api/workbooks", ListWorkbooksHandler),
        (r"/api/workbooks/tabs", WorkbookTabsHandler),
        (r"/api/workbooks/tab-data", WorkbookTabDataHandler),
        (r"/api/external-sheets/excel/sheets", ListExcelSheetsHandler),
        (r"/api/external-sheets/excel/load", LoadExcelSheetHandler),
        (r"/api/external-sheets/csv/load", LoadCsvFileHandler),
        (r"/api/reports/([0-9]+)", ReportsAPIHandler),
        (r"/api/reports/([0-9]+)/download", ReportDownloadHandler),
        (r"/api/reports/([0-9]+)/share", ReportShareHandler),
        (r"/api/reports/([0-9]+)/archive", ReportArchiveHandler),
        (r"/share/report/([a-zA-Z0-9_-]+)", ReportShareHandler),
    ]
