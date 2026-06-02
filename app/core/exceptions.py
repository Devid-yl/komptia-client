"""Hiérarchie d'exceptions personnalisées de Komptia.

Toutes les erreurs métier dérivent de :class:`KomptiaError`. La hiérarchie est
organisée par domaine (auth, base de données, IA, automatisation, rapports,
e-mail, validation, configuration) avec une racine par domaine permettant aux
consommateurs d'attraper soit le tronc, soit la feuille la plus précise.

Principes de conception
-----------------------

1. **Compatibilité ascendante** : ``raise KomptiaError("message")`` continue de
   fonctionner exactement comme avant. Les attributs structurés (``code``,
   ``context``) sont des kwargs optionnels.
2. **Code stable** : chaque classe expose ``default_code`` (ClassVar) — une
   chaîne ASCII en majuscules, neutre vis-à-vis de la locale. Le code est ce
   qu'on indexe dans les logs et ce qu'on mappe vers une réponse HTTP / une
   traduction i18n. ``message`` reste l'humain (français), ``code`` reste la
   machine (ASCII).
3. **Statut HTTP** : ``http_status`` (ClassVar) facilite le rendu d'une réponse
   structurée par les handlers (404 / 400 / 401 / 500 ...). Une erreur sans
   surface HTTP peut hériter le défaut générique 500 sans coût.
4. **Chaînage explicite** : utiliser ``raise NewError(...) from original`` (PEP
   3134) pour préserver la trace d'origine. Ne jamais avaler ``__cause__``.
5. **Notes de contexte** : pour des annotations ad-hoc en cours de propagation,
   utiliser ``err.add_note("...")`` (PEP 678, Python 3.11+). Les notes
   apparaissent dans le traceback formaté.
6. **Échecs en grappe** : pour signaler N erreurs corrélées (ex. validation
   d'un fichier ligne par ligne), préférer ``ExceptionGroup`` (PEP 654) plutôt
   que d'agréger dans une seule erreur — l'appelant peut alors trier avec
   ``except*``.

Exemple d'utilisation
---------------------

>>> from app.core.exceptions import ValidationError
>>> try:
...     raise ValidationError("Email invalide", field="email")
... except ValidationError as exc:
...     payload = exc.to_dict()  # logs / réponse HTTP

Sécurité
--------

* Ne jamais inclure de secret (mot de passe, token, NIR, IBAN) dans
  ``message`` ou ``context`` — ces champs sont sérialisés tels quels par
  ``to_dict()``.
* ``__cause__`` peut contenir des données sensibles (stack frame, locals).
  En frontière externe (HTTP, log centralisé), n'exposer que ``to_dict()`` et
  laisser la stack uniquement aux logs serveurs internes.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

__all__ = [
    # Racine
    "KomptiaError",
    # Authentification
    "AuthenticationError",
    "InvalidCredentialsError",
    "SessionExpiredError",
    "InsufficientPermissionsError",
    # Base de données
    "DatabaseError",
    "QueryError",
    "SageConnectionError",
    "SageDriverMissingError",
    # IA
    "AIError",
    "SQLGenerationError",
    "SQLValidationError",
    # Automatisation
    "AutomationError",
    "SchedulerError",
    "ExecutionError",
    # Rapports
    "ReportError",
    "PDFGenerationError",
    "ChartGenerationError",
    # E-mail
    "EmailError",
    "SMTPConnectionError",
    "EmailDeliveryError",
    # Validation & configuration
    "ValidationError",
    "ConfigurationError",
]


class KomptiaError(Exception):
    """Racine de toutes les erreurs métier de Komptia.

    Attributs
    ---------
    message : str
        Texte humain en français destiné à l'utilisateur final ou aux logs.
    code : str
        Identifiant ASCII stable utilisé pour l'agrégation de logs, le mapping
        i18n côté client, et le routage HTTP. Valeur par défaut : la
        ``default_code`` de la classe (héritable, surchargeable par sous-classe).
    context : dict[str, Any]
        Dictionnaire JSON-sérialisable de métadonnées (request_id, user_id,
        query_hash, ...). Ne JAMAIS y placer de secrets ni de PII.

    Class vars
    ----------
    default_code : str
        Code par défaut utilisé si l'instance n'en fournit pas.
    http_status : int
        Statut HTTP par défaut quand cette erreur est rendue par un handler.
    """

    default_code: ClassVar[str] = "KOMPTIA_ERROR"
    http_status: ClassVar[int] = 500

    def __init__(
        self,
        message: str = "",
        *,
        code: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message: str = message
        # `code or default_code` : un code vide ou None retombe sur le défaut.
        # C'est volontaire — on garantit qu'`err.code` n'est jamais falsy.
        self.code: str = code or self.default_code
        # Copie défensive : le caller peut muter sa map sans impacter l'erreur.
        self.context: dict[str, Any] = dict(context) if context else {}

    def to_dict(self) -> dict[str, Any]:
        """Représentation JSON-sérialisable pour logs et réponses HTTP.

        Volontairement n'inclut PAS la stack trace ni ``__cause__`` — ces
        informations restent serveur-side. Le caller HTTP qui souhaite exposer
        la trace au client doit le décider explicitement et la sanitiser.
        """
        return {
            "type": type(self).__name__,
            "code": self.code,
            "message": self.message,
            "context": dict(self.context),
        }

    def __repr__(self) -> str:
        cls = type(self).__name__
        return f"{cls}(code={self.code!r}, message={self.message!r})"


# ---------------------------------------------------------------------------
# Authentification & autorisation
# ---------------------------------------------------------------------------


class AuthenticationError(KomptiaError):
    """Échec d'authentification (tronc du domaine auth)."""

    default_code = "AUTH_ERROR"
    http_status = 401


class InvalidCredentialsError(AuthenticationError):
    """Identifiants (login / mot de passe / token) invalides."""

    default_code = "AUTH_INVALID_CREDENTIALS"
    http_status = 401


class SessionExpiredError(AuthenticationError):
    """Session expirée (timeout ou révocation)."""

    default_code = "AUTH_SESSION_EXPIRED"
    http_status = 401


class InsufficientPermissionsError(AuthenticationError):
    """L'utilisateur est authentifié mais n'a pas les droits requis.

    Note : 403 plutôt que 401 — l'utilisateur est connu, c'est l'autorisation
    qui manque, pas l'authentification.
    """

    default_code = "AUTH_FORBIDDEN"
    http_status = 403


# ---------------------------------------------------------------------------
# Base de données
# ---------------------------------------------------------------------------


class DatabaseError(KomptiaError):
    """Erreur générique de couche base de données (tronc du domaine DB)."""

    default_code = "DB_ERROR"
    http_status = 500


class QueryError(DatabaseError):
    """Échec d'exécution d'une requête SQL (timeout, mot-clé interdit, etc.)."""

    default_code = "DB_QUERY_ERROR"
    http_status = 500


class SageConnectionError(DatabaseError):
    """Connexion impossible vers la base source SQL Server (Sage Coala et autres).

    Cas typiques : réseau injoignable, credentials invalides, driver pyodbc
    indisponible, circuit-breaker ouvert.
    """

    default_code = "DB_SOURCE_UNREACHABLE"
    http_status = 503


class SageDriverMissingError(SageConnectionError):
    """Aucun pilote ODBC SQL Server n'est installé sur le SERVEUR APPLICATIF.

    Sous-classe distincte de :class:`SageConnectionError` : ce n'est NI un
    problème réseau NI des identifiants invalides, mais une faute de
    **déploiement** — le paquet ``msodbcsql18`` (Microsoft ODBC Driver 18 for
    SQL Server) est absent de l'image / du serveur Komptia, donc ``pyodbc`` n'a
    aucun pilote pour parler à SQL Server, même si la base source est joignable.

    La distinction permet au connecteur de :
      - NE PAS faire tripper le circuit breaker (faute permanente, pas une panne
        transitoire qui se rétablirait toute seule) ;
      - afficher un diagnostic actionnable côté administrateur système plutôt
        qu'un trompeur « erreur réseau ou d'authentification ».

    ``http_status`` hérité de :class:`SageConnectionError` (503 Service
    Unavailable) : tant que l'admin n'a pas réinstallé le pilote, le service ne
    peut pas répondre — sémantiquement un 503, pas un 500. La distinction métier
    est portée par ``default_code`` (``DB_DRIVER_MISSING``).
    """

    default_code = "DB_DRIVER_MISSING"


class SageQueryCancelledError(DatabaseError):
    """Requête SQL annulée par l'utilisateur en plein vol (cancel_event fire).

    Task #9 (2026-05-22) — émis quand l'utilisateur clique « Stop » pendant
    qu'``execute_sql`` tourne sur Sage. Le cursor pyodbc est cancellé via
    ``cursor.cancel()`` (thread-safe, envoie SQLCancel à SQL Server) puis
    cette exception remonte pour que l'agent et l'UI sachent que la requête
    a été ABANDONNÉE et qu'AUCUN résultat partiel ne doit être persisté.

    Distinct de ``QueryError`` (qui couvre les erreurs SQL légitimes) et de
    ``asyncio.CancelledError`` (annulation côté event loop, peut indiquer
    plusieurs causes).
    """

    default_code = "DB_QUERY_CANCELLED"
    http_status = 499  # Client Closed Request (Nginx convention)


# ---------------------------------------------------------------------------
# Module IA (Iris, Gladys, copilote)
# ---------------------------------------------------------------------------


class AIError(KomptiaError):
    """Erreur générique du module IA (tronc du domaine IA)."""

    default_code = "AI_ERROR"
    http_status = 500


class SQLGenerationError(AIError):
    """Le LLM n'a pas réussi à produire un SQL exécutable."""

    default_code = "AI_SQL_GENERATION_FAILED"
    http_status = 502


class SQLValidationError(AIError):
    """Le SQL généré par le LLM est syntaxiquement valide mais sémantiquement
    refusé (table inconnue, opération dangereuse, complexité excessive...).
    """

    default_code = "AI_SQL_VALIDATION_FAILED"
    http_status = 400


# ---------------------------------------------------------------------------
# Automatisations (workflows déclenchés par scheduler)
# ---------------------------------------------------------------------------


class AutomationError(KomptiaError):
    """Erreur générique d'automatisation (tronc du domaine automatisation)."""

    default_code = "AUTOMATION_ERROR"
    http_status = 500


class SchedulerError(AutomationError):
    """Échec du planificateur (APScheduler indisponible, job mal configuré...)."""

    default_code = "AUTOMATION_SCHEDULER_ERROR"
    http_status = 500


class ExecutionError(AutomationError):
    """Échec d'une étape lors de l'exécution d'un workflow d'automatisation."""

    default_code = "AUTOMATION_EXECUTION_ERROR"
    http_status = 500


class WaitForResponse(AutomationError):
    """Signal interne (PAS un échec) — un step ``email_wait_response`` a
    suspendu l'exécution en attendant la réponse externe d'un destinataire.

    Cette exception N'INDIQUE PAS un bug : elle est levée volontairement
    par l'adapter ``email_wait_response`` pour interrompre le DAG executor
    proprement après avoir :
    1. Créé la row ``WaitToken`` (token + expires_at)
    2. Envoyé le mail au destinataire avec le lien tokenisé
    3. Persisté le ``wait_checkpoint`` sur ``Execution``
    4. Marqué ``StepExecution`` + ``Execution`` = ``waiting``

    Le DAG executor catch cette exception au niveau du node et stoppe la
    cascade ; ``execute_automation`` la catche aussi pour ne PAS marquer
    l'execution ``failed`` ou ``success`` (elle reste ``waiting``). La
    reprise se fait via :func:`app.services.automation.executor.resume_automation`
    déclenchée par le POST de réponse du destinataire.

    ``wait_token_id`` permet à l'orchestrateur de savoir QUEL token a
    causé la suspension (utile pour les logs et l'UI).
    """

    default_code = "AUTOMATION_WAIT_FOR_RESPONSE"
    http_status = 200  # pas une erreur HTTP — usage interne uniquement

    def __init__(self, message: str = "", *, wait_token_id: int):
        super().__init__(message or "Step en attente d'une reponse externe")
        self.wait_token_id = wait_token_id


# ---------------------------------------------------------------------------
# Rapports (PDF, graphiques)
# ---------------------------------------------------------------------------


class ReportError(KomptiaError):
    """Erreur générique de génération de rapport (tronc du domaine reporting)."""

    default_code = "REPORT_ERROR"
    http_status = 500


class PDFGenerationError(ReportError):
    """Échec de la génération PDF (ReportLab, WeasyPrint)."""

    default_code = "REPORT_PDF_FAILED"
    http_status = 500


class ChartGenerationError(ReportError):
    """Échec de la génération d'un graphique (Plotly, Matplotlib)."""

    default_code = "REPORT_CHART_FAILED"
    http_status = 500


# ---------------------------------------------------------------------------
# E-mail (envoi via SMTP)
# ---------------------------------------------------------------------------


class EmailError(KomptiaError):
    """Erreur générique d'envoi e-mail (tronc du domaine email)."""

    default_code = "EMAIL_ERROR"
    http_status = 500


class SMTPConnectionError(EmailError):
    """Connexion au serveur SMTP impossible (réseau, auth, TLS)."""

    default_code = "EMAIL_SMTP_UNREACHABLE"
    http_status = 503


class EmailDeliveryError(EmailError):
    """Le serveur SMTP a accepté la connexion mais a refusé / échoué la livraison."""

    default_code = "EMAIL_DELIVERY_FAILED"
    http_status = 502


# ---------------------------------------------------------------------------
# Validation des données & configuration
# ---------------------------------------------------------------------------


class ValidationError(KomptiaError):
    """Validation d'un input utilisateur ou d'une donnée applicative.

    Attributs spécifiques
    ---------------------
    field : str | None
        Nom du champ fautif (utile pour formulaires côté UI).
    errors : dict[str, Any]
        Map ``champ → message`` quand plusieurs champs sont invalides en même
        temps. Vide par défaut.

    ``field`` et ``errors`` sont également propagés dans ``context`` pour la
    sérialisation, sans nécessiter d'override de ``to_dict()``.
    """

    default_code = "VALIDATION_ERROR"
    http_status = 400

    def __init__(
        self,
        message: str = "",
        *,
        field: str | None = None,
        errors: Mapping[str, Any] | None = None,
        code: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        merged_context: dict[str, Any] = dict(context) if context else {}
        # On ne réécrit pas les clés déjà présentes dans `context` — l'appelant
        # qui passe explicitement `context={"field": "..."}` reste maître.
        if field is not None:
            merged_context.setdefault("field", field)
        if errors:
            merged_context.setdefault("errors", dict(errors))
        super().__init__(message, code=code, context=merged_context)
        self.field: str | None = field
        # Copie défensive (cf. KomptiaError.__init__ pour la même raison).
        self.errors: dict[str, Any] = dict(errors) if errors else {}


class ConfigurationError(KomptiaError):
    """Configuration invalide ou incomplète (env vars, config.yaml, BDD app_settings)."""

    default_code = "CONFIG_ERROR"
    http_status = 500
