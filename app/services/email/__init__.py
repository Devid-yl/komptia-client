"""
Module de gestion des emails.
Envoi d'emails avec support SMTP, templates et pièces jointes, et
consultation de l'historique des envois.
"""

from .email_history_service import EmailHistoryFilters, fetch_email_history
from .smtp_client import SMTPClient
from .smtp_factory import (
    build_smtp_client_from_db,
    build_smtp_client_from_dict,
    load_smtp_config_dict,
)
from .template_renderer import EmailTemplateRenderer, get_renderer

__all__ = [
    "EmailHistoryFilters",
    "EmailTemplateRenderer",
    "SMTPClient",
    "build_smtp_client_from_db",
    "build_smtp_client_from_dict",
    "load_smtp_config_dict",
    "fetch_email_history",
    "get_renderer",
]
