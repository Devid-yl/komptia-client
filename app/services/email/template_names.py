"""Catalogue des ``template_name`` utilisés dans l'audit ``EmailLog``.

Single source of truth pour les libellés persistés en BDD via
``EmailLog.template_name`` (col ``String(100)``). Permet :

* Validation à l'IDE (mypy / pylance) — typo détectée à la compilation.
* Filtrage cohérent dans ``/email-history`` (sinon les magic strings
  drift entre fichiers : ``"automation_report"`` vs
  ``"automation-report"`` vs ``"automation_report_v2"``).
* Liste explicite des cas d'usage email de Komptia — facilite
  l'onboarding et la review.

Convention : kebab/snake-case, ASCII pur, ``< 100`` chars (cap modèle).
"""

from __future__ import annotations

from enum import Enum
from typing import Final


class EmailTemplate(str, Enum):
    """Identifiants des templates email connus.

    Hérite de ``str`` pour que ``str(EmailTemplate.X) == EmailTemplate.X.value``
    soit utilisable directement comme valeur pour ``EmailLog.template_name``.

    Si un nouveau site d'envoi est ajouté : créer une nouvelle valeur ICI
    plutôt que passer une chaîne brute au site. La grille de garde
    ``tests/unit/test_send_email_audit_metadata_grep.py`` ne force pas
    l'usage de cette enum (passer ``template_name="foo"`` brut continue
    de marcher) — l'enum est une bonne pratique, pas une contrainte
    structurelle.
    """

    # ── Automations ────────────────────────────────────────────────────
    AUTOMATION_REPORT = "automation_report"
    EXECUTION_NOTIFICATION = "execution_notification"
    DAG_EMAIL_STEP = "dag_email_step"

    # ── Wait tokens (email_wait_response) ──────────────────────────────
    WAIT_REQUEST = "wait_request"
    WAIT_REMINDER = "wait_reminder"
    WAIT_EXPIRED_NOTIF = "wait_expired_notif"
    WAIT_CANCELLATION = "wait_cancellation"

    # ── Iris / Agent ──────────────────────────────────────────────────
    IRIS_DBA_APPROVAL_REQUEST = "iris_dba_approval_request"
    IRIS_DBA_ADMIN_NOTIFICATION = "iris_dba_admin_notification"

    # ── Dashboards / Reporting ────────────────────────────────────────
    DASHBOARD_DELIVERY = "dashboard_delivery"

    # ── Système ───────────────────────────────────────────────────────
    DATA_ACCESS_RULES_CHANGED = "data_access_rules_changed"
    FEEDBACK_REPORT = "feedback_report"


#: Ensemble des valeurs valides (utile pour validation tierce).
ALL_TEMPLATE_NAMES: Final[frozenset[str]] = frozenset(
    t.value for t in EmailTemplate
)
