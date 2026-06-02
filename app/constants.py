"""
Constantes de code pour Komptia.

Ce module n'expose que des constantes immuables (défauts, limites techniques,
tailles binaires conventionnelles) qui ne dépendent pas du déploiement. Les
valeurs variables par client ou environnement (adresses email, modèles LLM,
quotas business pilotés par l'admin) vivent dans ``app/config.py`` ou des
variables d'environnement — pas ici.

Conventions :

* Les scalaires sont typés ``typing.Final[...]`` — mypy refuse toute
  réassignation, ce qui protège contre les mutations accidentelles à
  l'exécution.
* Les mappings partagés sont exposés via ``types.MappingProxyType`` pour
  bloquer les mutations globales. Un ``dict`` mutable au module-scope est
  une classe de bug particulièrement vicieuse : un caller qui écrirait
  ``CONTACT_FIELD_LIMITS["phone"] = 5`` contaminerait silencieusement
  tous les autres callers du process.
* Les suffixes ``_BYTES`` / ``_SECONDS`` / ``_DAYS`` / ``_HOURS`` rendent
  l'unité visible à l'usage : ``timeout=SMTP_TIMEOUT_SECONDS`` se lit sans
  revenir à cette source.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, Mapping

__all__ = [
    "AUTOMATIONS_PER_PAGE",
    "CONTACTS_MAX_PER_PAGE",
    "CONTACTS_PER_PAGE",
    "CONTACT_EMAIL_MAX_LENGTH",
    "CONTACT_SEARCH_MAX_LENGTH",
    "CONTACT_FIELD_LIMITS",
    "DASHBOARD_RECENT_LIMIT",
    "DAY_NAMES_SHORT_FR",
    "DB_TIMEOUT_SECONDS",
    "DEFAULT_PER_PAGE",
    "DEFAULT_RETENTION_DAYS",
    "DEFAULT_TOP_ROWS",
    "EXECUTIONS_PER_PAGE",
    "FILE_CHUNK_BYTES",
    "MAX_BATCH_MEMBERS",
    "MAX_CONTACT_NOTES_LENGTH",
    "MAX_CSV_IMPORT_BYTES",
    "MAX_CSV_IMPORT_ROWS",
    "MAX_DISTRIBUTION_LIST_DESCRIPTION",
    "MAX_DISTRIBUTION_LIST_NAME",
    "MAX_PREVIEW_ROWS",
    "MAX_STEP_PREVIEW_ROWS",
    "MAX_UPLOAD_BYTES",
    "RATE_LIMIT_STEP_PREVIEW",
    "SHARE_LINK_EXPIRY_HOURS",
    "SMTP_TEST_TIMEOUT_SECONDS",
    "SMTP_TIMEOUT_SECONDS",
    "STATS_RECENT_LIMIT",
    "STEP_PREVIEW_CACHE_MAX_PER_USER",
    "STEP_PREVIEW_CACHE_TTL_SECONDS",
    "STEP_PREVIEW_OUTPUT_TOKEN_TTL_SECONDS",
    "STEP_PREVIEW_TMP_TTL_SECONDS",
    "WEEK_DAYS",
]


_KIB: Final[int] = 1024
_MIB: Final[int] = 1024 * _KIB
_GIB: Final[int] = 1024 * _MIB


# ── Pagination ────────────────────────────────────────────────
DEFAULT_PER_PAGE: Final[int] = 20
DASHBOARD_RECENT_LIMIT: Final[int] = 5
STATS_RECENT_LIMIT: Final[int] = 10
AUTOMATIONS_PER_PAGE: Final[int] = 10
EXECUTIONS_PER_PAGE: Final[int] = 25
CONTACTS_PER_PAGE: Final[int] = 25
CONTACTS_MAX_PER_PAGE: Final[int] = 100
#: Cap longueur du terme de recherche contacts, appliqué côté SERVEUR (SSoT —
#: le ``maxlength`` HTML est contournable via l'API/curl). 200 chars dépasse
#: largement un nom/email/société réel et borne le coût du LIKE multi-colonnes
#: (anti-DoS léger). Cf. review loop F5.
CONTACT_SEARCH_MAX_LENGTH: Final[int] = 200

# ── Temps ─────────────────────────────────────────────────────
WEEK_DAYS: Final[int] = 7

# Locale française par défaut : Komptia sert aujourd'hui le marché
# francophone (cabinets comptables FR). Le suffixe ``_FR`` explicite la
# dépendance de locale pour qu'un lecteur ne prenne pas ce tuple pour une
# valeur I18N-neutre. Pour l'I18N réelle, dériver à partir d'un helper
# ``get_day_names(locale)``.
DAY_NAMES_SHORT_FR: Final[tuple[str, ...]] = (
    "Lun",
    "Mar",
    "Mer",
    "Jeu",
    "Ven",
    "Sam",
    "Dim",
)

# ── Tailles binaires (octets) ─────────────────────────────────
# MAX_UPLOAD_BYTES : garde-fou ~infini (1 TiB) réservé aux fichiers GÉNÉRÉS en
# interne (rapports stockés via report_storage). Ce N'EST PLUS la limite des
# uploads UTILISATEUR : depuis le 2026-05-28, celle-ci est le réglage admin
# ``AIConfig.MAX_UPLOAD_SIZE_BYTES`` (/admin/performance), lu via
# ``config_service.get_max_upload_size_bytes()`` et appliqué dans les handlers
# d'upload (Iris, datastore, rapport). Le quota cumulé par utilisateur
# (``AIConfig.STORAGE_QUOTA_PER_USER_BYTES``) borne EN PLUS la somme des fichiers
# d'un user (StorageManager.check_quota).
MAX_UPLOAD_BYTES: Final[int] = 1024 * _GIB  # 1 TiB = pratiquement infini
FILE_CHUNK_BYTES: Final[int] = 64 * _KIB
MAX_CSV_IMPORT_BYTES: Final[int] = 5 * _MIB

# ── Stockage : quota global (octets) ─────────────────────────
# SOURCE UNIQUE de vérité = AIConfig.STORAGE_QUOTA_PER_USER_BYTES,
# saisie par l'admin via /admin/performance section "Stockage local
# (SQLite)". Identique pour TOUS les users, ignore le rôle (intent
# 2026-05-14). Les constantes par rôle ``STORAGE_QUOTA_ADMIN/USER/
# READER_BYTES`` ainsi que le mapping ``ROLE_STORAGE_QUOTA_BYTES`` ont
# été supprimés — toute lecture passe désormais par
# ``StorageManager._get_global_quota()``.

# ── Timeouts (secondes) ───────────────────────────────────────
DB_TIMEOUT_SECONDS: Final[int] = 10
SMTP_TIMEOUT_SECONDS: Final[int] = 30
SMTP_TEST_TIMEOUT_SECONDS: Final[int] = 10

# ── Résultats SQL ─────────────────────────────────────────────
# Convention Komptia : AUCUN hard cap technique sur le nombre de lignes
# d'un résultat SQL. La SEULE source de vérité du plafond global est la
# valeur ``max_rows`` saisie par l'admin via /admin/database (champ
# ``DatabaseConnection.max_rows``), propagée au singleton SageConnector.
#
# Les handlers SQL DOIVENT passer ``max_rows=None`` à
# ``sage_connector.execute(...)`` → ``execute()`` utilise alors
# ``self.max_rows`` (= config admin). Imposer un cap caller plus bas
# casse cette promesse (ex. historique : MAX_DRILLDOWN_ROWS=5_000
# écrasait silencieusement un admin config à 50_000).
# Preview de résultat SQL : traité comme un classeur normal (intent user
# 2026-05-14). Sentinelle "no cap caller" — ``sage_connector.execute()``
# applique ``min(MAX_PREVIEW_ROWS, db_conn.max_rows)`` et donc admin gagne
# toujours. L'admin configure la borne effective via /admin/database.
MAX_PREVIEW_ROWS: Final[int] = 1_000_000_000
DEFAULT_TOP_ROWS: Final[int] = 100

# ── Preview d'étape sur /automations/N/edit ───────────────────
# Idem MAX_PREVIEW_ROWS : sentinelle "no cap caller", admin clamp via
# /admin/database. Avant le refacto cette valeur était volontairement bas
# (100) pour la réactivité, mais ça contredisait la convention "1 source
# de vérité = admin" du 2026-05-14.
MAX_STEP_PREVIEW_ROWS: Final[int] = 1_000_000_000

# Cache mémoire des outputs de parents pour éviter les re-runs cascadés
# (un step avec 2 parents SQL de 30 s s'exécuterait 60 s à chaque clic
# sinon). TTL court car la BDD source bouge ; LRU borné pour ne pas
# rétenir des workbooks 50k rows en mémoire serveur.
STEP_PREVIEW_CACHE_TTL_SECONDS: Final[int] = 15 * 60
STEP_PREVIEW_CACHE_MAX_PER_USER: Final[int] = 50

# TTL des fichiers tmp générés en preview (PDF/xlsx/csv). Job de cleanup
# scheduler les supprime après. Court : un preview est consommé dans
# l'heure ou jamais.
STEP_PREVIEW_TMP_TTL_SECONDS: Final[int] = 60 * 60

# TTL du token HMAC qui sert le fichier tmp via ``window.open``. Court
# car l'utilisateur clique ▶ puis "Ouvrir" dans la foulée. Borne aussi
# une éventuelle fuite d'URL.
STEP_PREVIEW_OUTPUT_TOKEN_TTL_SECONDS: Final[int] = 10 * 60

# Rate-limit utilisateur : 10 previews / 60 s. Aligné sur RATE_LIMIT_PREVIEW
# du wizard SQL — un humain qui itère ne dépasse pas 10/min.
RATE_LIMIT_STEP_PREVIEW: Final[tuple[int, int]] = (10, 60)

# ── Contacts / listes de diffusion ────────────────────────────
MAX_CSV_IMPORT_ROWS: Final[int] = 10_000
MAX_BATCH_MEMBERS: Final[int] = 1000
MAX_CONTACT_NOTES_LENGTH: Final[int] = 5000
# RFC 5321 = 254 chars max pour l'enveloppe SMTP. ``email_validator`` borne
# côté lib mais on l'ajoute ici pour valider à la frontière du body JSON
# avant la lib (anti-DoS sur des emails géants).
CONTACT_EMAIL_MAX_LENGTH: Final[int] = 254
# Phone : E.164 borne à 15 chiffres + indicatif + format = 22 chars max
# raisonnable. ``50`` donne marge confortable pour les formats étendus
# (ex : ``+33 (0)6 12 34 56 78 ext.123``). Aligné avec le ``String(50)``
# du modèle ``Contact`` (cf. ``app/models/contact.py``).
CONTACT_FIELD_LIMITS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "email": CONTACT_EMAIL_MAX_LENGTH,
        "first_name": 100,
        "last_name": 100,
        "company": 200,
        "phone": 50,
        "notes": MAX_CONTACT_NOTES_LENGTH,
    }
)
MAX_DISTRIBUTION_LIST_NAME: Final[int] = 100
MAX_DISTRIBUTION_LIST_DESCRIPTION: Final[int] = 1000

# ── Rapports ──────────────────────────────────────────────────
DEFAULT_RETENTION_DAYS: Final[int] = 90
SHARE_LINK_EXPIRY_HOURS: Final[int] = 72


# ── UI : thème ────────────────────────────────────────────────
# Modes de thème acceptés par Komptia. SSoT : importé par
# ``app/handlers/settings.py::_THEME_MODE_VALUES`` (validation backend),
# et le test ``tests/unit/test_theme_modes_ssot.py`` vérifie l'alignement
# avec les sites JS (``static/js/settings.js::VALID_THEMES`` + le
# bootstrap dans ``templates/base.html``). Toute valeur supplémentaire
# (ex: "auto", "high_contrast") doit être ajoutée ici en premier.
THEME_MODES: Final[tuple[str, ...]] = ("light", "dark", "system")
DEFAULT_THEME_MODE: Final[str] = "system"


# ── Dashboards / périodes ─────────────────────────────────────
# Fenêtres temporelles acceptées par les dashboards admin
# (``/admin/performance``, ``/admin/ai-performance``). SSoT : importée
# par les 2 handlers (``performance.py``, ``ai_admin.py``) — avant 2026-05-26
# (Bug AI-11), la liste ``(7, 30, 90)`` était dupliquée et risquait de
# diverger. Test ``tests/unit/test_dashboard_periods_ssot.py``.
# Ajouter une nouvelle valeur ici se propage automatiquement aux 2 dashboards.
DASHBOARD_PERIODS_DAYS: Final[tuple[int, ...]] = (7, 30, 90)
DEFAULT_DASHBOARD_PERIOD_DAYS: Final[int] = 7


# ── Iris : auto-feedback (carte rendue post-execute_sql) ─────
# SSoT des libellés + icônes proposés à l'utilisateur quand ``execute_sql``
# a renvoyé des lignes sans clarification suivante. Avant la centralisation
# (Komptia axe 6 « tout dynamique »), ces trois entrées étaient hardcodées
# dans ``static/js/iris.js::renderAutoFeedbackCard``. Elles sont désormais
# poussées au template ``iris.html`` puis lues par le JS via
# ``window.IRIS_CONFIG.autoFeedbackOptions`` — un seul endroit à modifier
# pour faire évoluer le wording.
#
# Chaque option est un dict ``{"value": str, "icon": str, "feedback": str}`` :
#   * ``value``    — libellé affiché ET envoyé au backend comme réponse user.
#   * ``icon``     — classe Bootstrap Icons (``bi-...``) rendue à gauche du
#                    libellé. Le frontend ajoute le préfixe ``bi `` lui-même.
#   * ``feedback`` — valeur de feedback DÉTERMINISTE déclenchée au clic
#                    (``positive`` / ``adjust`` / ``negative``). C'est la
#                    SINGLE SOURCE OF TRUTH du mapping clic→apprentissage : le
#                    frontend (``sendAutoFeedback``) POST ``/api/iris/feedback``
#                    avec cette valeur → ``learn_from_conversation_feedback``.
#                    L'apprentissage ne dépend donc PLUS de la discrétion du LLM
#                    (ancien ``learn_insight`` best-effort) — il est garanti par
#                    le code dès que l'utilisateur valide via cette carte.
#                    DOIT matcher les valeurs de ``_POSITIVE_KEYWORDS`` /
#                    ``_ADJUST_KEYWORDS`` côté ``agent_knowledge`` (test de garde).
#
# Garantie de stabilité : ne RIEN renommer dans ``value`` ni ``feedback`` sans
# coordination — ``value`` reste vu par le LLM comme un message user normal.
AUTO_FEEDBACK_OPTIONS: Final[tuple[dict[str, str], ...]] = (
    {"value": "C'est bon !", "icon": "bi-check-circle-fill", "feedback": "positive"},
    {"value": "Presque", "icon": "bi-arrow-repeat", "feedback": "adjust"},
    {"value": "Ce n'est pas ça", "icon": "bi-x-circle-fill", "feedback": "negative"},
)
