"""Helpers d'audit pour le journal ``audit_logs``.

Exporte :

* ``audit_event`` — audit **atomique** (add+flush dans la session de la
  mutation parente, le caller commit ; rollback ensemble).
* ``record_audit_best_effort`` — audit **best-effort** (session dédiée,
  borné par timeout, ne propage jamais) pour les flux où l'audit ne doit
  pas bloquer ni casser l'appelant (login, création d'utilisateur…).

Point d'entrée unique pour les call-sites des handlers HTTP/WS qui veulent
tracer une opération compliance (RGPD/ISO 27001).
"""

from app.services.audit.audit_log import audit_event, record_audit_best_effort

__all__ = ["audit_event", "record_audit_best_effort"]
