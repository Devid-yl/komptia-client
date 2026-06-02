"""Service d'onboarding — persistance BDD de l'état des tours utilisateur
et du setup admin singleton.

API publique exposée par ``onboarding_service``. Les handlers HTTP
(``app/handlers/onboarding.py``) restent fins et délèguent ici la logique
de validation, les UPSERT et les écritures d'audit.
"""

from __future__ import annotations

from app.services.onboarding.activity_tracker import (
    cleanup_orphan_activity_summaries_sync,
    get_dormant_users,
    mark_nudged,
    should_update_last_seen,
    track_automation_created,
    track_automation_run,
    track_dashboard_viewed,
    track_iris_query,
    track_report_generated,
    update_last_seen,
)
from app.services.onboarding.behavioral_triggers import (
    evaluate_admin_no_user_invited,
    evaluate_dormant_general,
    evaluate_dormant_iris,
    run_daily_triggers,
    run_daily_triggers_sync,
)
from app.services.onboarding.onboarding_service import (
    MILESTONE_TO_FIELD,
    OnboardingValidationError,
    complete_tour,
    dismiss_tenant_setup,
    extract_milestone,
    extract_step,
    extract_tour_key,
    get_or_create_tenant_setup,
    get_user_state,
    record_step,
    reset_user_onboarding,
    resume_tenant_setup,
    set_milestone,
    skip_tour,
    start_tour,
    validate_milestone,
    validate_step,
    validate_tour_key,
)

__all__ = (
    # Onboarding service
    "MILESTONE_TO_FIELD",
    "OnboardingValidationError",
    "complete_tour",
    "dismiss_tenant_setup",
    "extract_milestone",
    "extract_step",
    "extract_tour_key",
    "get_or_create_tenant_setup",
    "reset_user_onboarding",
    "get_user_state",
    "record_step",
    "resume_tenant_setup",
    "set_milestone",
    "skip_tour",
    "start_tour",
    "validate_milestone",
    "validate_step",
    "validate_tour_key",
    # Activity tracker (T3.1)
    "cleanup_orphan_activity_summaries_sync",
    "get_dormant_users",
    "mark_nudged",
    "should_update_last_seen",
    "track_automation_created",
    "track_automation_run",
    "track_dashboard_viewed",
    "track_iris_query",
    "track_report_generated",
    "update_last_seen",
    # Behavioral triggers (T3.2)
    "evaluate_admin_no_user_invited",
    "evaluate_dormant_general",
    "evaluate_dormant_iris",
    "run_daily_triggers",
    "run_daily_triggers_sync",
)
