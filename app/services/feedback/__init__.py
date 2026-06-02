"""Service de feedback utilisateur — rapports d'erreurs et suggestions.

Surface publique :

* :func:`get_feedback_service` — accès au singleton.
* :class:`FeedbackService` — logique d'envoi (mail SMTP + persistance
  fallback en cas d'absence de SMTP configuré).
* :class:`FeedbackPayload` — DTO validé.
"""

from .feedback_service import FeedbackPayload, FeedbackService, get_feedback_service

__all__ = ("FeedbackPayload", "FeedbackService", "get_feedback_service")
