"""
Modèle AuditLog - Journal d'audit des actions
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import String, Integer, Text, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.core import clock
from app.core.database import Base


class AuditLog(Base):
    """
    Journal d'audit pour tracer toutes les actions importantes

    Attributs:
        user_id: ID de l'utilisateur (peut être null pour actions système)
        action: Type d'action (login, logout, search, create_automation, etc.)
        entity_type: Type d'entité concernée (user, automation, report, etc.)
        entity_id: ID de l'entité concernée
        details: Détails JSON de l'action
        ip_address: Adresse IP
        user_agent: User-Agent
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Utilisateur (peut être null pour actions système)
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Action
    action: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # Entité concernée
    entity_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    entity_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Détails (JSON)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Métadonnées connexion
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=clock.now, nullable=False, index=True
    )

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, action='{self.action}', user_id={self.user_id})>"

    @classmethod
    def log_action(
        cls,
        action: str,
        user_id: Optional[int] = None,
        entity_type: Optional[str] = None,
        entity_id: Optional[int] = None,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> "AuditLog":
        """
        Factory pour créer une entrée de log
        """
        import json

        return cls(
            user_id=user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=json.dumps(details) if details else None,
            ip_address=ip_address,
            user_agent=user_agent,
        )


# Actions prédéfinies pour cohérence
class AuditAction:
    """Constantes pour les types d'actions"""

    # Auth
    LOGIN = "login"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"

    # Users
    USER_CREATE = "user_create"
    USER_UPDATE = "user_update"
    USER_DELETE = "user_delete"
    USER_DEACTIVATE = "user_deactivate"

    # Search
    SEARCH = "search"
    SEARCH_FEEDBACK = "search_feedback"

    # Automations — opérations sur l'entité Automation elle-même
    AUTOMATION_CREATE = "automation_create"
    AUTOMATION_UPDATE = "automation_update"
    AUTOMATION_DELETE = "automation_delete"
    AUTOMATION_EXECUTE = "automation_execute"
    # Cluster-B 2026-05-26 — couverture compliance complète CRUD/lifecycle
    AUTOMATION_TOGGLE = "automation_toggle"  # is_active flip
    AUTOMATION_DUPLICATE = "automation_duplicate"
    AUTOMATION_IMPORT = "automation_import"
    AUTOMATION_EXPORT = "automation_export"  # GET sans mutation BDD, audité quand même
    AUTOMATION_REPLAY = "automation_replay"  # ré-exécution d'une exec précédente
    AUTOMATION_SCHEDULE_CHANGE = "automation_schedule_change"
    AUTOMATION_LAYOUT_UPDATE = "automation_layout_update"  # repositionnement canvas
    # Structure DAG (cluster-B 2026-05-26)
    STEP_CREATE = "step_create"
    STEP_UPDATE = "step_update"
    STEP_DELETE = "step_delete"
    STEP_REORDER = "step_reorder"
    EDGE_CREATE = "edge_create"
    EDGE_UPDATE = "edge_update"  # toggle trigger/data type
    EDGE_DELETE = "edge_delete"

    # Task #33 (2026-05-27) — Audit log atomique des décisions Iris-in-automation.
    # Chaque step ``iris`` exécuté logge sa décision (instruction, summary,
    # variables, abort, turns) pour forensics + compliance cabinet comptable.
    # Retention via ``db_retention._get_retention_days("AUDIT_LOG_IRIS_RETENTION_DAYS")``
    # (default 90j, override ENV — décision P0 Q8).
    IRIS_AUTOMATION_DECISION = "iris_automation_decision"

    # Reports
    REPORT_GENERATE = "report_generate"
    REPORT_DOWNLOAD = "report_download"

    # Emails
    EMAIL_SEND = "email_send"

    # Admin
    SETTINGS_UPDATE = "settings_update"

    # Datastore / Files
    FILE_UPLOAD = "file_upload"
    FILE_DELETE = "file_delete"
    FILE_MOVE = "file_move"
    FILE_RENAME = "file_rename"
    FILE_DOWNLOAD = "file_download"
    FILE_SEARCH_EXPORT = "file_search_export"

    # Database connection configuration (admin) — chaque mutation est tracée
    # pour pouvoir reconstruire qui a pointé l'app vers quel SQL Server et
    # quand ; le test_connection est tracé pour détecter une énumération
    # réseau (port scan via le formulaire admin).
    DB_CONFIG_CREATE = "db_config_create"
    DB_CONFIG_UPDATE = "db_config_update"
    DB_CONFIG_DELETE = "db_config_delete"
    DB_CONFIG_ACTIVATE = "db_config_activate"
    DB_CONFIG_DEACTIVATE = "db_config_deactivate"
    DB_CONFIG_TEST = "db_config_test"
    DB_CONFIG_TEST_AD_HOC = "db_config_test_ad_hoc"
    SAGE_MODE_SWITCH = "sage_mode_switch"

    # **Data access rules (Phase P1-8, #24)** — chaque mutation de règle
    # data_access est tracée pour audit prod queryable (avant : uniquement
    # ``logger.info "[AUDIT]"`` non requêtable). entity_type="data_access_rule",
    # entity_id=rule_id (sauf REPLACED bulk où rule_id=None, target_user_id
    # dans details).
    DATA_ACCESS_RULE_CREATED = "data_access_rule_created"
    DATA_ACCESS_RULE_UPDATED = "data_access_rule_updated"
    DATA_ACCESS_RULE_DELETED = "data_access_rule_deleted"
    DATA_ACCESS_RULES_REPLACED = "data_access_rules_replaced"
    DATA_ACCESS_RULES_COPIED = "data_access_rules_copied"

    # Feature #7 (2026-05-26) — auto-rewrite des paires Q/SQL stockées
    # quand le serveur SQL Server connecté change de version (downgrade
    # de compat_level cassant des capabilities utilisées). Une entry
    # par paire réécrite, status dans details (success / needs_review /
    # failed) avec old_sql + new_sql + model + capabilities cassées.
    TRAINING_DATA_AUTO_REWRITE = "training_data_auto_rewrite"
