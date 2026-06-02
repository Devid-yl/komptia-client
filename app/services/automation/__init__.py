"""Module automation pour Komptia."""

from app.services.automation.scheduler import (
    AutomationScheduler,
    get_scheduler,
    start_scheduler,
    shutdown_scheduler,
)
from app.services.automation.executor import AutomationExecutor, get_executor, execute_automation
from app.services.automation.loader import (
    load_active_automations,
    schedule_automation,
    unschedule_automation,
)
from app.services.automation.workflow_engine import (
    WorkflowEngine,
    WorkflowContext,
    StepResult,
    get_workflow_engine,
)

__all__ = [
    "AutomationScheduler",
    "get_scheduler",
    "start_scheduler",
    "shutdown_scheduler",
    "AutomationExecutor",
    "get_executor",
    "execute_automation",
    "load_active_automations",
    "schedule_automation",
    "unschedule_automation",
    "WorkflowEngine",
    "WorkflowContext",
    "StepResult",
    "get_workflow_engine",
]
