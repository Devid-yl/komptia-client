"""
Définition des outils disponibles pour l'agent IA Iris.

Chaque outil suit le format Anthropic tool-use (input_schema JSON Schema).
Les niveaux de confidentialité appliqués :

  Niveau 2 — peek_table_data : obfuscation des chaînes (suppression 1 caractère sur 2)
  Niveau 3 — analyze_numbers : chiffres bruts sans aucun contexte (noms de colonnes / tables)
  Niveau 4 — execute_sql     : résultats complets à l'utilisateur + échantillon anonymisé à l'agent
"""

import asyncio
import re
import time
import statistics
from typing import Any, Dict, Final, List, Optional, Set, Tuple

from app.core import clock
from app.services.ai.plan_tools_core import (
    PLAN_STATUSES,
    add_task as _plan_core_add_task,
    list_plan as _plan_core_list_plan,
    update_task as _plan_core_update_task,
)
from app.services.ai.schema_loader import get_schema_loader
from app.services.ai.training_store import (
    VIEW_MINING_SOURCE_PREFIX,
    get_training_store,
)
from app.services.anonymization import anonymize_for_llm
from app.services.database.query_executor import get_query_executor
from app.utils.logger import get_logger
from app.utils.sql_scan import skip_sql_string

logger = get_logger(__name__)

# Seuil de priority au-dessus duquel une règle business_context déclenche
# un alerte visible (_critical_rules_alert) en tête du résultat d'outil.
# Aligné avec view_miner.multiple_aliases (priority=5) — règles de rôles
# multiples coexistants dans les vues natives.
CRITICAL_BC_PRIORITY_THRESHOLD = 5

# ── Low-cardinality warning (cf. _handle_execute_sql) ────────────────
# Nombre minimum de lignes dans le sample pour qu'un distinct_count=1
# soit jugé "suspect". En dessous, un sample trop petit produirait
# trop de faux positifs (table de référence courte, filtre légitime).
_LOW_CARDINALITY_MIN_SAMPLE = 50
# Longueur min des valeurs string pour considérer la colonne comme une
# "vraie" valeur métier (évite les flags 'Y'/'N', codes 1-char).
_LOW_CARDINALITY_MIN_LEN = 2


# ---------------------------------------------------------------------------
# Helpers confidentialité — dé-anonymisation pour affichage utilisateur
# ---------------------------------------------------------------------------
# Quand un outil renvoie du texte qui sera affiché DIRECTEMENT à
# l'utilisateur (clarifications, suggestions, questions de suivi), il
# faut dé-anonymiser les fragments ``~XXX`` que le LLM peut y avoir
# glissés (il voit des valeurs BDD anonymisées, l'utilisateur doit voir
# le réel). Ces helpers sont fail-safe : si le service est indisponible
# ou lève, on retourne la valeur brute plutôt que de casser le flux.
# Générique : aucun motif métier filtré, juste passage par le service
# de confidentialité centralisé.


async def _restore_for_user_safe(text: Any) -> str:
    """Dé-anonymise un texte destiné à l'utilisateur. Fail-safe.

    Utilisé dans les handlers qui stockent du texte LLM-contrôlé dans
    le context (pour qu'il soit transmis à l'UI via WebSocket). Le LLM
    peut avoir cité des fragments ``~XXX`` — il faut les retraduire en
    valeurs réelles avant que l'utilisateur les voit.

    Comportement sur inputs atypiques :
    - ``None`` → retourne ``""`` (cas normal d'absence)
    - valeurs falsy non-None (``0``, ``False``, ``""``, ``[]``, ``{}``) →
      stringifiées puis passées à la restauration. ``0`` et ``False``
      sont des valeurs utilisateur légitimes qu'il ne faut pas
      silencieusement convertir en string vide.
    - str + autres types → ``str(x)`` puis restauration.
    """
    if text is None:
        return ""
    s = text if isinstance(text, str) else str(text)
    # Court-circuit : rien à restaurer sur un string vide ou un
    # contenu sans token ~XXX (évite un appel de service pour rien).
    if not s or "~" not in s:
        return s
    try:
        from app.services.anonymization.strategies import get_confidentiality_manager

        cm = get_confidentiality_manager()
        return await cm.restore_anonymized_values(s)
    except Exception as _exc:
        logger.debug("restore_for_user failed, passing through: %s", _exc)
        return s


async def _restore_options_for_user_safe(
    options: Optional[List[Any]],
) -> Optional[List[str]]:
    """Dé-anonymise chaque option d'une liste. Fail-safe par élément.

    Utilisé pour les listes d'options de clarification ou de
    suggestions. Si une option échoue à se restaurer, on garde sa
    valeur brute — on ne veut pas perdre toute la liste parce qu'un
    élément a un problème.

    Types d'éléments gérés :
    - ``str`` → restauré tel quel
    - dict/list → sérialisé en JSON puis restauré (évite la corruption
      ``str(dict)`` qui produit des quotes Python non standard)
    - autres (int, float, None...) → ``str(x)``
    """
    import json as _json

    if options is None:
        return None
    if not isinstance(options, list):
        return options  # garde le type original si pas une liste
    restored: list[str] = []
    for opt in options:
        if isinstance(opt, (dict, list)):
            try:
                opt_str = _json.dumps(opt, ensure_ascii=False)
            except (TypeError, ValueError):
                opt_str = str(opt)
            restored.append(await _restore_for_user_safe(opt_str))
        else:
            restored.append(await _restore_for_user_safe(opt))
    return restored


# ---------------------------------------------------------------------------
# Définitions Anthropic tool-use
# ---------------------------------------------------------------------------

IRIS_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "execute_sql",
        "description": (
            "Execute a read-only SELECT query on the source SQL Server database. "
            "Best suited for trivial probes (SELECT TOP N, COUNT, single-table "
            "or 1-2 JOIN introspection) and validated SQL you're confident in. "
            "For complex analytical queries (multi-CTE, STRING_AGG / WITHIN GROUP, "
            "window functions with OVER, 3+ JOINs, UNION), ``run_pipeline`` (IR mode) "
            "is **strongly recommended** — it composes the SQL programmatically "
            "via IR primitives and cannot hallucinate T-SQL syntax. ``execute_sql`` "
            "remains available for these cases but you are responsible for the "
            "syntax correctness. "
            "The full results are sent to the user in an interactive table. "
            "You receive an ANONYMIZED sample (max 5 rows, strings obfuscated) "
            "plus column names, row count and execution time. "
            "Use the sample to understand the data structure, not to quote "
            "exact values. Always provide a human-readable explanation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "Valid T-SQL SELECT statement to execute.",
                },
                "explanation": {
                    "type": "string",
                    "description": (
                        "Plain-language explanation of what this query does, "
                        "shown to the user alongside the results."
                    ),
                },
                "max_rows": {
                    "type": "integer",
                    "description": (
                        "Safety limit: maximum rows to return (default: 1000). "
                        "Do NOT use this to artificially reduce results — "
                        "only lower it if you have a specific reason."
                    ),
                    "default": 1000,
                    "minimum": 1,
                    "maximum": 1000,
                },
            },
            "required": ["sql", "explanation"],
        },
    },
    {
        "name": "get_database_schema",
        "description": (
            "Get the structure (DDL, columns, types) of a specific table you already know by name. "
            "Use search_schema first if you don't know the table name."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_name": {
                    "type": "string",
                    "description": "Exact table name to look up (optional).",
                },
                "search_term": {
                    "type": "string",
                    "description": (
                        "Keyword to search for across table names and DDL content (optional)."
                    ),
                },
            },
        },
    },
    {
        "name": "peek_table_data",
        "description": (
            "See what the data looks like in a table (sample of rows). "
            "Useful to understand the format and type of values in each column. "
            "Confidentiality is automatic: sensitive values appear as typed placeholders "
            "like [NAME_1], [DATE_1] or [EMAIL_1] (date-like and id-like strings are "
            "tokenized too). Treat any [TYPE_N] token as an anonymized value of that "
            "type, never as a readable literal; values shown literally (most numbers) are real."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_name": {
                    "type": "string",
                    "description": "Name of the table to peek at.",
                },
                "columns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": ("Specific columns to include (optional — all if omitted)."),
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of rows to sample (default: 5, max: 20).",
                    "default": 5,
                    "minimum": 1,
                    "maximum": 20,
                },
            },
            "required": ["table_name"],
        },
    },
    {
        "name": "analyze_numbers",
        "description": (
            "Analyze numeric values: detect anomalies, compute statistics, or identify distributions. "
            "Confidentiality: only the raw numbers are transmitted — no column names, "
            "no table names, no context."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "values": {
                    "type": "array",
                    "items": {"type": "number"},
                    "description": "List of numeric values to analyse (no labels).",
                    "minItems": 1,
                },
                "operation": {
                    "type": "string",
                    "enum": ["anomalies", "stats", "distribution", "trend"],
                    "description": (
                        "Analysis type: "
                        "'stats' for descriptive statistics, "
                        "'anomalies' for outlier detection, "
                        "'distribution' for frequency analysis, "
                        "'trend' for sequential trend detection."
                    ),
                },
            },
            "required": ["values", "operation"],
        },
    },
    {
        "name": "search_documentation",
        "description": (
            "Search the knowledge base for CONTENT: business documentation, "
            "view compositions, learned insights (saved by learn_insight), "
            "and validated question-SQL examples. "
            "Use this to find KNOWLEDGE about the database (meanings, relationships, "
            "patterns, previously solved queries) — not to find table/column names "
            "(use search_schema for that)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural-language search query.",
                },
                "doc_type": {
                    "type": "string",
                    "enum": ["ddl", "documentation", "question_sql"],
                    "description": (
                        "Type of document to search: "
                        "'ddl' for table schemas (semantic search), "
                        "'documentation' for business docs, view compositions, "
                        "learned insights, "
                        "'question_sql' for validated example queries."
                    ),
                },
            },
            "required": ["query", "doc_type"],
        },
    },
    {
        "name": "ask_user_clarification",
        "description": (
            "Ask the user a clarifying question when the request is ambiguous. "
            "Provide a list of suggested options the user can pick from. "
            "Use sparingly — only when truly necessary to proceed.\n\n"
            "RULES for options:\n"
            "- Each option MUST be a SEPARATE string in the array. "
            "NEVER join options with '|' or put multiple in one string.\n"
            "- Options MUST be contextual and directly answer the question. "
            "If you asked about a specific entity from SQL results, "
            "list the actual values found (e.g. the real dossier names/codes "
            "from the query results), NOT generic choices like "
            "'Je vois le bon dossier'.\n"
            "- Keep each option SHORT (under 60 chars).\n"
            "- Example GOOD: question='Quel dossier ?', "
            "options=['<nom_dossier_A> (<code_A>)', '<nom_dossier_B> (<code_B>)']\n"
            "- Example BAD: options=['Je vois le bon dossier | Je ne le vois pas']"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "The clarifying question to ask the user.",
                },
                "options": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 80},
                    "minItems": 1,
                    "maxItems": 10,
                    "description": (
                        "List of suggested answers. Each option = one separate string. "
                        "MUST be contextual (actual values from data, not generic text). "
                        "NEVER use '|' inside an option."
                    ),
                },
            },
            "required": ["question"],
        },
    },
    {
        "name": "save_to_datastore",
        "description": (
            "Save the results of a previously executed query to the user's personal datastore. "
            "References the query by its search_id so no data passes through the agent. "
            "IMPORTANT: Only use this tool when the user EXPLICITLY asks to download, export "
            "or save results as a file. NEVER use it proactively — execute_sql already displays "
            "results in an interactive table."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "search_id": {
                    "type": "integer",
                    "description": "ID of the query result to save (from execute_sql metadata).",
                },
                "filename": {
                    "type": "string",
                    "description": "Desired filename (without extension).",
                },
                "format": {
                    "type": "string",
                    "enum": ["csv", "excel"],
                    "description": "Output format: 'csv' or 'excel'.",
                },
            },
            "required": ["search_id", "filename", "format"],
        },
    },
    {
        "name": "create_report",
        "description": (
            "Generate a formatted PDF, Excel or CSV report from a SQL query. "
            "The agent specifies the SQL and report parameters; "
            "the report is stored server-side and a download link is sent to the user. "
            "IMPORTANT: Only use this tool when the user EXPLICITLY asks for a formatted "
            "report, PDF, or document. NEVER use it to simply display data — use execute_sql "
            "instead, which shows results in an interactive table automatically."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Report title displayed in the document.",
                },
                "sql": {
                    "type": "string",
                    "description": "SELECT query whose results populate the report.",
                },
                "format": {
                    "type": "string",
                    "enum": ["pdf", "excel", "csv"],
                    "description": "Output format.",
                },
                "include_charts": {
                    "type": "boolean",
                    "description": "Whether to include auto-generated charts (PDF only).",
                    "default": False,
                },
            },
            "required": ["title", "sql", "format"],
        },
    },
    {
        "name": "create_report_from_results",
        "description": (
            "Generate a formatted report (PDF, Excel or CSV) from EXISTING query results "
            "that are already displayed in the user's grid. Use this instead of create_report "
            "when data is already available from a previous execute_sql call. "
            "The 'analysis' parameter lets you include your commentary — write it using the "
            "anonymized values you saw (e.g. ~tokens); the system will automatically translate "
            "them back to real values in the final report. The user will see a professional "
            "document with real data and your analysis in clear text. "
            "IMPORTANT: Only use this when the user asks for a report from existing results."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "search_id": {
                    "type": "integer",
                    "description": (
                        "The search_id from a previous execute_sql result. "
                        "References the data already displayed in the user's grid."
                    ),
                },
                "title": {
                    "type": "string",
                    "description": "Report title displayed in the document.",
                },
                "description": {
                    "type": "string",
                    "description": "Short description displayed below the title.",
                },
                "analysis": {
                    "type": "string",
                    "description": (
                        "Your written analysis of the data. You can use the anonymized "
                        "values (~tokens) you received — they will be automatically "
                        "translated to real values in the final report. "
                        "Write professional, insightful commentary about trends, "
                        "anomalies, and key findings."
                    ),
                },
                "format": {
                    "type": "string",
                    "enum": ["pdf", "excel", "csv"],
                    "description": "Output format. PDF supports charts and analysis text.",
                },
                "chart_type": {
                    "type": "string",
                    "enum": ["bar", "line", "pie", "auto"],
                    "description": "Chart type (PDF only). 'auto' detects the best type.",
                },
                "chart_x_column": {
                    "type": "string",
                    "description": "Column name for the chart X axis.",
                },
                "chart_y_column": {
                    "type": "string",
                    "description": "Column name for the chart Y axis.",
                },
            },
            "required": ["search_id", "title", "format"],
        },
    },
    {
        "name": "check_schema_freshness",
        "description": (
            "Check if the stored database schema is up-to-date compared to the live "
            "SQL Server schema. Returns a report showing added/removed tables and "
            "whether a re-sync is needed. Use proactively at the start of a session "
            "or when a schema error is encountered."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "trigger_enriched_sync",
        "description": (
            "Admin-only: trigger a full schema sync from SQL Server PLUS semantic "
            "enrichment (table roles, column roles, relationships) via an LLM call "
            "(Haiku) on EACH table. ⚠️ DOCTRINE WARNING: this tool VIOLATES the "
            "'Sync = 0 LLM' rule (cf. .claude/rules/gladys.md règle 6) — semantic "
            "roles are normally generated only via ✅ user feedback, not at sync. "
            "Reserved for the one-shot initial enrichment post-installation. "
            "Cost: ~1 LLM call per table × N tables (can be 100+ on Sage Coala). "
            "Requires explicit user confirmation (server-enforced via "
            "ask_user_clarification). Do NOT call in normal conversation flow — "
            "use plain `trigger_schema_sync` for refreshing schema without LLM."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "tables": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Specific tables to enrich (optional — all changed tables if omitted). "
                        "Limit to relevant tables to bound the LLM cost."
                    ),
                },
            },
        },
    },
    # ------------------------------------------------------------------
    # App Controller tools
    # ------------------------------------------------------------------
    {
        "name": "manage_automations",
        "description": (
            "Manage user automations: list, create, toggle (activate/deactivate), "
            "execute manually, or delete. Automations run scheduled data pipelines "
            "(extract → transform → report → email)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "create", "toggle", "execute", "delete"],
                    "description": "Action to perform.",
                },
                "automation_id": {
                    "type": "integer",
                    "description": "ID of the automation (for toggle/execute/delete).",
                },
                "name": {
                    "type": "string",
                    "description": "Automation name (for create).",
                },
                "description": {
                    "type": "string",
                    "description": "Automation description (for create).",
                },
                "query_type": {
                    "type": "string",
                    "enum": ["nl", "sql"],
                    "description": "Query type: 'nl' (natural language) or 'sql' (raw SQL).",
                },
                "query_text": {
                    "type": "string",
                    "description": "The query to execute (for create).",
                },
                "schedule_type": {
                    "type": "string",
                    "enum": ["once", "daily", "weekly", "monthly"],
                    "description": "Schedule frequency (for create).",
                },
                "schedule_config": {
                    "type": "object",
                    "description": ("Schedule config: {hour, minute, day_of_week, day_of_month}."),
                },
                "output_format": {
                    "type": "string",
                    "enum": ["csv", "excel", "pdf"],
                    "description": "Output format (for create).",
                },
                "recipients": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Email recipients (for create).",
                },
            },
            "required": ["action"],
        },
    },
    {
        "name": "list_execution_history",
        "description": (
            "List execution history of automations. "
            "Shows status, timing, row counts and errors for past runs."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "automation_id": {
                    "type": "integer",
                    "description": "Filter by automation ID (optional).",
                },
                "status": {
                    "type": "string",
                    "enum": ["pending", "running", "success", "error"],
                    "description": "Filter by execution status (optional).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (default: 20, max: 100).",
                    "default": 20,
                    "maximum": 100,
                },
            },
        },
    },
    {
        "name": "manage_contacts",
        "description": (
            "Manage user contacts: list/search, create, update or delete. "
            "Contacts are used as email recipients for reports and automations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "create", "update", "delete"],
                    "description": "Action to perform.",
                },
                "contact_id": {
                    "type": "integer",
                    "description": "Contact ID (for update/delete).",
                },
                "search": {
                    "type": "string",
                    "description": "Search term for list (matches email, name, company).",
                },
                "email": {
                    "type": "string",
                    "description": "Contact email (for create/update).",
                },
                "first_name": {
                    "type": "string",
                    "description": "First name (for create/update).",
                },
                "last_name": {
                    "type": "string",
                    "description": "Last name (for create/update).",
                },
                "company": {
                    "type": "string",
                    "description": "Company name (for create/update).",
                },
                "phone": {
                    "type": "string",
                    "description": "Phone number (for create/update).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results for list (default: 25).",
                    "default": 25,
                },
            },
            "required": ["action"],
        },
    },
    {
        "name": "manage_distribution_lists",
        "description": (
            "Manage email distribution lists: list, create, add/remove members. "
            "Distribution lists group contacts for bulk email sends."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "create", "add_members", "remove_member"],
                    "description": "Action to perform.",
                },
                "list_id": {
                    "type": "integer",
                    "description": "Distribution list ID (for add_members/remove_member).",
                },
                "name": {
                    "type": "string",
                    "description": "List name (for create).",
                },
                "description": {
                    "type": "string",
                    "description": "List description (for create).",
                },
                "contact_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Contact IDs to add (for add_members).",
                },
                "contact_id": {
                    "type": "integer",
                    "description": "Contact ID to remove (for remove_member).",
                },
            },
            "required": ["action"],
        },
    },
    {
        "name": "send_email",
        "description": (
            "Send an email via the configured SMTP server. "
            "Provide recipients, subject and HTML body. "
            "The email is logged in the system."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "recipients": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of recipient email addresses.",
                    "minItems": 1,
                },
                "subject": {
                    "type": "string",
                    "description": "Email subject line.",
                },
                "body_html": {
                    "type": "string",
                    "description": "Email body in HTML format.",
                },
            },
            "required": ["recipients", "subject", "body_html"],
        },
    },
    {
        "name": "list_reports",
        "description": (
            "List, share or archive generated reports. "
            "Admins see all reports; regular users see only their own."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "share", "archive"],
                    "description": "Action to perform.",
                },
                "report_id": {
                    "type": "integer",
                    "description": "Report ID (for share/archive).",
                },
                "report_type": {
                    "type": "string",
                    "description": "Filter by report type (for list).",
                },
                "file_format": {
                    "type": "string",
                    "enum": ["pdf", "excel", "csv"],
                    "description": "Filter by file format (for list).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (default: 20, max: 100).",
                    "default": 20,
                },
            },
            "required": ["action"],
        },
    },
    {
        "name": "manage_users",
        "description": (
            "Admin-only: manage application users. "
            "List, create, update roles or deactivate user accounts."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "create", "update", "deactivate"],
                    "description": "Action to perform.",
                },
                "user_id": {
                    "type": "integer",
                    "description": "Target user ID (for update/deactivate).",
                },
                "username": {
                    "type": "string",
                    "description": "Username (for create, min 3 chars).",
                },
                "email": {
                    "type": "string",
                    "description": "Email address (for create/update).",
                },
                "password": {
                    "type": "string",
                    "description": "Password (for create, min 8 chars).",
                },
                "role": {
                    "type": "string",
                    "enum": ["user", "admin"],
                    "description": "User role (for create/update).",
                },
                "is_active": {
                    "type": "boolean",
                    "description": "Active status (for update).",
                },
            },
            "required": ["action"],
        },
    },
    {
        "name": "get_app_stats",
        "description": (
            "Get application statistics and metrics. "
            "Categories: 'dashboard' (user activity), 'ai' (AI performance), "
            "'performance' (system metrics), 'all' (combined)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["dashboard", "ai", "performance", "all"],
                    "description": "Statistics category to retrieve.",
                    "default": "dashboard",
                },
            },
        },
    },
    {
        "name": "manage_app_config",
        "description": (
            "Admin-only: read or update application configuration. "
            "Categories: 'ai' (LLM providers), 'smtp' (email settings), "
            "'database' (connections). API keys are masked in responses."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["get", "update"],
                    "description": "Action: 'get' to read, 'update' to modify.",
                },
                "category": {
                    "type": "string",
                    "enum": ["ai", "smtp", "database"],
                    "description": "Configuration category.",
                },
                "updates": {
                    "type": "object",
                    "description": "Key-value pairs to update (for update action).",
                },
            },
            "required": ["action", "category"],
        },
    },
    # ------------------------------------------------------------------
    # Phase 2 — Advanced agent tools
    # ------------------------------------------------------------------
    {
        "name": "analyze_query_performance",
        "description": (
            "Analyze an SQL query's execution performance. "
            "Returns the estimated execution plan, identifies missing indexes, "
            "and suggests optimizations. Use this when the user wants to "
            "understand why a query is slow or optimize it."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "The SQL query to analyze.",
                },
                "include_plan": {
                    "type": "boolean",
                    "description": "Include estimated execution plan (default: true).",
                    "default": True,
                },
            },
            "required": ["sql"],
        },
    },
    # save_user_query supprime — la table SavedQuery a ete droppee
    # (decision utilisateur 2026-05-05 « casse net »). Pour sauvegarder
    # une question/SQL, l'agent utilise `save_to_datastore` qui ecrit
    # un fichier .sql dans le datastore filesystem (la nouvelle SSoT).
    {
        "name": "schedule_task",
        "description": (
            "Schedule a recurring automated task (automation). "
            "Creates an automation that runs a query on a schedule "
            "and optionally sends results by email. "
            "Use when the user says 'run this every day/week/month'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name for the scheduled task.",
                },
                "query_text": {
                    "type": "string",
                    "description": "Natural-language or SQL query to execute.",
                },
                "query_type": {
                    "type": "string",
                    "enum": ["nl", "sql"],
                    "description": "Query type: 'nl' (natural language) or 'sql'.",
                    "default": "nl",
                },
                "schedule_type": {
                    "type": "string",
                    "enum": ["once", "daily", "weekly", "monthly"],
                    "description": "Schedule frequency.",
                },
                "schedule_config": {
                    "type": "object",
                    "description": ("Schedule details: {hour, minute, day_of_week, day_of_month}."),
                },
                "output_format": {
                    "type": "string",
                    "enum": ["csv", "excel", "pdf"],
                    "description": "Output format for results.",
                    "default": "excel",
                },
                "recipients": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Email recipients for automatic delivery.",
                },
            },
            "required": ["name", "query_text", "schedule_type"],
        },
    },
    {
        "name": "analyze_attachment",
        "description": (
            "Analyze an uploaded file (CSV or Excel). "
            "Returns column types, row count, sample data, basic statistics, "
            "and potential data quality issues. "
            "Use when the user uploads a file for analysis."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file_id": {
                    "type": "string",
                    "description": "ID of the uploaded file (from upload endpoint).",
                },
            },
            "required": ["file_id"],
        },
    },
    {
        "name": "transform_uploaded_file",
        "description": (
            "TRANSFORM an uploaded workbook (CSV or Excel) via a natural-language "
            "instruction. Delegates to the Komptia copilot_agent (the same agent "
            "the user uses via the copilot-bar on SQL results) to read the file "
            "and apply the requested modifications: add columns, pivot, group-by, "
            "filter, compute totals, etc. Use this tool ONLY when the user wants "
            "to MODIFY the file — for read-only inspection (column types, sample, "
            "stats), use `analyze_attachment` instead which is instant and free. "
            "Returns a synthetic summary: how many tabs were created/modified, "
            "what copilot did, and whether the run completed or was abandoned."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file_id": {
                    "type": "string",
                    "description": "ID of the uploaded file (from upload endpoint).",
                },
                "instruction": {
                    "type": "string",
                    "description": (
                        "Natural-language transformation instruction passed verbatim "
                        'to copilot. Must be precise and atomic (e.g. "ajoute une '
                        "colonne 'Total HT' = quantite * prix_ht et un sous-total "
                        'par client"). Avoid vague instructions like "améliore le '
                        'fichier" — copilot needs a concrete goal. Max 4000 chars.'
                    ),
                },
            },
            "required": ["file_id", "instruction"],
        },
    },
    {
        "name": "quick_overview_workbook",
        "description": (
            "Programmatic overview of an uploaded workbook — equivalent to "
            "`analyze_attachment` but reusing the shared `tabs_context` cache "
            "(no pandas re-read, 0 LLM, instant). For each materialized tab, "
            "returns: row_count, column_count, per-column stats (type_hint, "
            "non_null_count, null_count, unique_count_capped, sample_values, "
            "numeric_stats if applicable), and 5 sample rows in dense format. "
            "Best first call after upload to understand structure + content "
            "shape in ONE turn (vs list_workbook_tabs + read_workbook_rows + "
            "type inference = 2-3 turns). Use for « décris ce fichier », "
            "« quels sont les colonnes / types / valeurs typiques ? »."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file_id": {
                    "type": "string",
                    "description": "ID of the uploaded file.",
                },
            },
            "required": ["file_id"],
        },
    },
    {
        "name": "list_workbook_tabs",
        "description": (
            "List the tabs (sheets) of an uploaded workbook with their metadata "
            "— labels, columns, row counts, active flag — WITHOUT loading the "
            "cell content. Use as a first exploration step on Excel files with "
            "multiple sheets, or to discover the column names of any CSV/Excel "
            "upload before reading rows. 0 LLM call, instant. Pairs with "
            "`read_workbook_rows`, `count_workbook_rows`, `aggregate_workbook` "
            "for deeper exploration."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file_id": {
                    "type": "string",
                    "description": "ID of the uploaded file (from upload endpoint).",
                },
            },
            "required": ["file_id"],
        },
    },
    {
        "name": "read_workbook_rows",
        "description": (
            "Read a slice of cells from a specific tab of an uploaded workbook. "
            "Returns at most 60 rows per call (paginate via `row_start`/`row_end` "
            "for larger ranges). Output is sparse (cells with values only — empty "
            "cells skipped). Use after `list_workbook_tabs` to inspect actual "
            "content."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file_id": {
                    "type": "string",
                    "description": "ID of the uploaded file.",
                },
                "tab_idx": {
                    "type": "integer",
                    "description": "0-based index of the tab (from list_workbook_tabs).",
                },
                "row_start": {
                    "type": "integer",
                    "description": "0-based first row to read (default 0).",
                    "default": 0,
                },
                "row_end": {
                    "type": "integer",
                    "description": (
                        "0-based last row to read (inclusive). Default = "
                        "row_start + 59. Capped at row_start + 59 (60 rows max)."
                    ),
                },
            },
            "required": ["file_id", "tab_idx"],
        },
    },
    {
        "name": "count_workbook_rows",
        "description": (
            "Count rows in a tab that match the given `match` (= or IN) and "
            "`match_exclude` (NOT IN) filters. Cheap probe before deciding to "
            "`read_workbook_rows` — returns just an integer. Useful for "
            "questions like \"how many rows where status='paid'?\" or sanity "
            "checks before aggregation. Works on the cell-level `match` "
            "metadata attached to each row (CSV/Excel uploads have one match "
            "entry per cell with col→value)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file_id": {
                    "type": "string",
                    "description": "ID of the uploaded file.",
                },
                "tab_idx": {
                    "type": "integer",
                    "description": "0-based index of the tab.",
                },
                "match": {
                    "type": "object",
                    "description": (
                        "Filter as {col: value_or_list}. Scalar = exact match, "
                        "list = IN. Empty object = no filter (counts all rows)."
                    ),
                },
                "match_exclude": {
                    "type": "object",
                    "description": (
                        "Exclusion filter as {col: [values...]}. Always a LIST "
                        "of values (NOT IN). To exclude one value, use [value]."
                    ),
                },
            },
            "required": ["file_id", "tab_idx"],
        },
    },
    {
        "name": "aggregate_workbook",
        "description": (
            "Sum the values of `value_column` in a tab, after applying `match` "
            "(= or IN) and `match_exclude` (NOT IN) filters. Returns total + "
            "hit_count + exclude_hits (for each excluded token, how many rows "
            "were filtered by it — 0 means the token didn't match anything). "
            "Use for quick verification of totals or to compute aggregates "
            "without writing SQL. Coût quasi-nul en tokens."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file_id": {
                    "type": "string",
                    "description": "ID of the uploaded file.",
                },
                "source_tab_idx": {
                    "type": "integer",
                    "description": "0-based index of the tab to aggregate over.",
                },
                "value_column": {
                    "type": "string",
                    "description": "Name of the column to sum (case-sensitive).",
                },
                "match": {
                    "type": "object",
                    "description": ("Filter as {col: value_or_list}. Scalar = exact, list = IN."),
                },
                "match_exclude": {
                    "type": "object",
                    "description": (
                        "Exclusion as {col: [values...]} (always lists). Returns "
                        "0-hit tokens to flag potentially wrong filter values."
                    ),
                },
            },
            "required": ["file_id", "source_tab_idx", "value_column"],
        },
    },
    {
        "name": "get_user_preferences",
        "description": (
            "Retrieve the user's saved preferences, vocabulary, and context. "
            "Use this at the start of complex conversations to personalize "
            "responses. Categories: 'vocabulary' (business terms), "
            "'preference' (display/format), 'frequent_query' (common questions), "
            "'ml_context' (learned patterns)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["vocabulary", "preference", "frequent_query", "ml_context"],
                    "description": ("Filter by category (optional — all if omitted)."),
                },
            },
        },
    },
    {
        "name": "save_user_preference",
        "description": (
            "Save or update a user preference, vocabulary term, or learned "
            "context. Use when the user teaches you a term ('X means Y'), "
            "sets a preference ('always show amounts in EUR'), "
            "or you learn something useful about their workflow."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "Preference key (e.g. 'ca_means', 'default_format').",
                },
                "value": {
                    "type": "string",
                    "description": ("Preference value (e.g. 'chiffre_affaires', 'excel')."),
                },
                "category": {
                    "type": "string",
                    "enum": ["vocabulary", "preference", "frequent_query", "ml_context"],
                    "description": "Category for this preference.",
                    "default": "preference",
                },
            },
            "required": ["key", "value", "category"],
        },
    },
    {
        "name": "suggest_followup_questions",
        "description": (
            "Generate follow-up question suggestions based on the current "
            "conversation. Call this after providing a complete answer to "
            "suggest relevant next steps. The suggestions will be displayed "
            "as clickable chips to the user."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "questions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": ("2-3 follow-up questions the user might want to ask."),
                    "minItems": 1,
                    "maxItems": 5,
                },
            },
            "required": ["questions"],
        },
    },
    # --- Outils d'auto-documentation ---
    {
        "name": "introspect_table",
        "description": (
            "Get the columns and all relationships (foreign keys) of a table, "
            "including tables that reference it and tables it references. "
            "Queries SQL Server directly (INFORMATION_SCHEMA). "
            "Auto-saves the discovered structure to the knowledge base."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_name": {
                    "type": "string",
                    "description": "Nom exact de la table à inspecter.",
                },
                "info_type": {
                    "type": "string",
                    "enum": ["columns", "primary_keys", "foreign_keys", "all"],
                    "description": (
                        "Type de métadonnées à récupérer. "
                        "'all' retourne colonnes + clés primaires + clés étrangères."
                    ),
                    "default": "all",
                },
            },
            "required": ["table_name"],
        },
    },
    {
        "name": "learn_insight",
        "description": (
            "Enregistre une nouvelle connaissance dans la documentation interne. "
            "Utilise cet outil pour documenter ce que tu découvres : signification "
            "des colonnes, relations entre tables, conventions de nommage, règles métier. "
            "Ces connaissances seront réutilisées dans tes futures conversations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_name": {
                    "type": "string",
                    "description": (
                        "Table concernée par cette connaissance. "
                        "Peut être vide si la connaissance est générale."
                    ),
                },
                "insight": {
                    "type": "string",
                    "description": (
                        "La connaissance à enregistrer. Sois précis et factuel. "
                        "Sois précis et factuel, par exemple : "
                        "'La colonne X est la clé métier unique dans la table Y'."
                    ),
                },
            },
            "required": ["table_name", "insight"],
        },
    },
    {
        "name": "trigger_schema_sync",
        "description": (
            "Déclenche une synchronisation du schéma depuis SQL Server. "
            "Récupère la structure de toutes les tables et vues depuis "
            "INFORMATION_SCHEMA et met à jour la documentation interne. "
            "Opération longue (30-120s). À utiliser quand le schéma local "
            "semble obsolète ou incomplet."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "enum": ["sql_server", "yaml"],
                    "description": (
                        "'sql_server' = sync depuis la base SQL Server source (recommandé), "
                        "'yaml' = recharge depuis le fichier YAML local."
                    ),
                    "default": "sql_server",
                },
            },
        },
    },
    {
        "name": "analyze_null_data",
        "description": (
            "Analyze NULL/missing values in the last query result or in a specific table. "
            "Detects which columns have NULLs, classifies the type of missing data "
            "(never collected, not applicable, missing data, probable error), "
            "identifies columns that tend to be NULL together (co-occurrence), "
            "and suggests completion actions. "
            "If no table_name is provided, analyzes the last execute_sql result from context. "
            "Use this tool AFTER running a query to assess data quality, "
            "or proactively on a table the user is investigating."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_name": {
                    "type": "string",
                    "description": (
                        "Optional: specific table to analyze (runs SELECT TOP 200). "
                        "If omitted, analyzes the last query result from context."
                    ),
                },
                "columns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Optional: specific columns to analyze. If omitted, all columns."
                    ),
                },
                "include_suggestions": {
                    "type": "boolean",
                    "description": "Include completion action suggestions (default: true).",
                    "default": True,
                },
            },
        },
    },
    {
        "name": "save_memory",
        "description": (
            "Save a learning or insight to your persistent memory for future conversations. "
            "Use this to remember patterns, corrections, or business rules you discover.\n\n"
            "WHEN to use:\n"
            "- After correcting a SQL error: remember what went wrong and the fix\n"
            "- After discovering a business rule: 'colonne X signifie Y dans ce contexte'\n"
            "- After finding a useful SQL pattern: 'pour obtenir X, joindre A et B via C'\n\n"
            "WHEN NOT to use:\n"
            "- Do NOT save raw SQL queries or results (use learn_insight for SQL knowledge)\n"
            "- Do NOT save schema info (already in documentation)\n"
            "- Do NOT save temporary/one-time info\n"
            "- Do NOT save user-specific preferences here — those are captured "
            "automatically end-of-conversation in User.iris_memory.\n"
            "- Do NOT save more than 2 memories per conversation (be selective)\n\n"
            "Keep content SHORT: 1-2 sentences max, focused on the actionable insight."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "maxLength": 500,
                    "description": (
                        "The insight to remember. Short, actionable. "
                        "Example: 'La table F_DOCLIGNE utilise EC_Sens=0 pour débit "
                        "et EC_Sens=1 pour crédit, ne pas confondre avec les signes +/-'"
                    ),
                },
                "category": {
                    "type": "string",
                    "enum": ["error_pattern", "business_rule", "sql_pattern"],
                    "description": (
                        "Category: error_pattern (SQL errors & fixes), "
                        "business_rule (domain knowledge), "
                        "sql_pattern (useful query patterns)."
                    ),
                },
            },
            "required": ["content", "category"],
        },
    },
    # ------------------------------------------------------------------
    # Outils SQL avancés — transplantés de l'orchestrateur vers le free loop
    # pour donner à l'agent les mêmes capacités que Claude Code.
    # ------------------------------------------------------------------
    {
        "name": "search_schema",
        "description": (
            "Search a term in the database schema across 5 dimensions: table names, view names, "
            "column names, view column names, and actual values stored in the database. "
            "This is your MOST POWERFUL discovery tool — it finds which column contains "
            "a specific value (e.g., search '<entity_name>' finds it in <some_table>.<some_column>). "
            "Returns ranked matches with scores. "
            "Call this FIRST whenever you don't yet know in which table/column a value "
            "or a concept lives — both before get_database_schema (for unknown tables) "
            "and before get_resolved_values (for unknown columns containing a value). "
            "Once search_schema has identified the column, get_resolved_values can confirm "
            "the exact form and detect homonyms on that specific column."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "keywords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Keywords to search for. Use business terms, column name fragments, "
                        "or actual values that might be stored in the database. "
                        "Multiple keywords broaden the search."
                    ),
                    "minItems": 1,
                },
            },
            "required": ["keywords"],
        },
    },
    {
        "name": "test_sql",
        "description": (
            "Test a SQL query by wrapping it in SELECT COUNT(*) FROM (...). "
            "Returns ONLY the row count — nothing is displayed to the user. "
            "Use this at EVERY step of your SQL construction: "
            "after the base table, after each JOIN, after filters. "
            "Compare counts between steps: "
            "stable = correct JOIN, x5+ = cartesian product, -50% = INNER kills rows. "
            "ALWAYS test before calling execute_sql."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "SQL SELECT or WITH query to test.",
                },
            },
            "required": ["sql"],
        },
    },
    {
        "name": "get_fk_path",
        "description": (
            "Find how to JOIN two tables: returns the FK path between them, "
            "the JOIN conditions, and a ready-to-use SQL JOIN template. "
            "Includes inferred relationships (not just declared FKs). "
            "ALWAYS call this BEFORE writing a JOIN — never guess JOIN conditions."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "from_table": {
                    "type": "string",
                    "description": "Source table (already in your query).",
                },
                "to_table": {
                    "type": "string",
                    "description": "Target table (you want to JOIN to this).",
                },
            },
            "required": ["from_table", "to_table"],
        },
    },
    {
        "name": "get_resolved_values",
        "description": (
            "Confirm a value on a SPECIFIC table.column you have ALREADY identified — "
            "typically right after search_schema told you where the value lives. "
            "Returns the exact form to use via ``use_in_sql`` (correct casing, accents, spaces) "
            "and runs a COUNT(*) on the live source to surface 3 quality signals that "
            "search_schema does NOT compute: "
            "(a) ``homonym_warning: true`` — same value exists in multiple rows, "
            "your WHERE filter would target several entities at once; "
            "(b) ``mapping_inconsistency_warning: true`` — value present in the local cache "
            "but 0 rows in the live source (stale sync, soft-delete, etc.); "
            "(c) ``view_count_caveat: true`` — the table is a view that aggregates, the count "
            "may be misleading. "
            "PREREQUISITE: you must already know which table.column contains the value. "
            "If you don't, call ``search_schema([value])`` FIRST — it scans all columns "
            "at once and points you at the right one. Then get_resolved_values runs on "
            "that identified column."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "term": {
                    "type": "string",
                    "description": "Search term (partial match supported).",
                },
                "table_name": {
                    "type": "string",
                    "description": "Table to search in.",
                },
                "column_name": {
                    "type": "string",
                    "description": "Column to search in.",
                },
            },
            "required": ["term", "table_name", "column_name"],
        },
    },
    {
        "name": "check_join_compatibility",
        "description": (
            "Check if two columns from different tables can be joined even without "
            "a declared FK. Executes an INTERSECT to measure value overlap. "
            "Use this when get_fk_path returns 'no path found' but you suspect "
            "two columns contain the same type of values (e.g., both contain client codes "
            "but no FK was declared between the tables). "
            "Returns overlap percentage and distinct value counts."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_a": {"type": "string", "description": "First table name."},
                "column_a": {"type": "string", "description": "Column in first table."},
                "table_b": {"type": "string", "description": "Second table name."},
                "column_b": {"type": "string", "description": "Column in second table."},
            },
            "required": ["table_a", "column_a", "table_b", "column_b"],
        },
    },
    {
        "name": "explore_join_alternatives",
        "description": (
            "Find ALL foreign key paths between two tables, not just the shortest. "
            "Returns up to 5 alternative paths with different intermediate tables. "
            "Use this when `get_fk_path` recommends a path that doesn't work "
            "(wrong COUNT, missing data) — there may be a better route."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "from_table": {
                    "type": "string",
                    "description": "Source table (already in your query).",
                },
                "to_table": {
                    "type": "string",
                    "description": "Target table (you want to reach).",
                },
            },
            "required": ["from_table", "to_table"],
        },
    },
    {
        "name": "align_request",
        "description": (
            "Verify that what the user is asking for exists in the database. "
            "Extracts each concept from the user's message, checks if it maps to "
            "real tables/columns/values, and reports what was found, what is ambiguous, "
            "and what is missing. Call this FIRST for complex requests (2+ concepts) "
            "instead of multiple search_schema calls."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "user_message": {
                    "type": "string",
                    "description": "The user's original request in natural language.",
                },
            },
            "required": ["user_message"],
        },
    },
    {
        "name": "diagnose_zero_rows",
        "description": (
            "Analyze a SQL query that returned 0 rows and identify which filter "
            "is likely too restrictive. Breaks down the WHERE clause, classifies "
            "each predicate by risk (IS NULL, narrow IN, exact equality), and "
            "returns an action plan: which filters to test-remove first via "
            "test_sql. Use this INSTEAD of guessing when execute_sql returns 0."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "The SQL query that returned 0 rows.",
                },
            },
            "required": ["sql"],
        },
    },
    {
        "name": "match_analytical_pattern",
        "description": (
            "Detect WHICH analytical pattern (rollup, Year-over-Year, top-N, "
            "balance aging, hierarchical rollup, simple aggregate, filtered "
            "list, rolling cumulative) best matches the user's question. "
            "Returns up to 3 candidate patterns with a SQL skeleton, required "
            "input roles, and a score. Call this EARLY (right after "
            "align_request) when the question has analytical intent — the "
            "patterns tell you the CANONICAL STRUCTURE (CTE + window functions "
            "for multi-level rollup, CASE pivots for YoY, recursive CTE for "
            "hierarchy…) without dictating table/column names. You still "
            "resolve tables/columns with search_schema / introspect_table."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "user_question": {
                    "type": "string",
                    "description": "User's raw natural-language question.",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Max patterns to return (default 3, cap 5).",
                },
            },
            "required": ["user_question"],
        },
    },
    {
        "name": "compare_query_variants",
        "description": (
            "Compare 2 or 3 SQL variants side-by-side by executing a COUNT on each "
            "in parallel. Returns the row count of each variant AND computes the "
            "delta between them (absolute + percentage). Use this BEFORE execute_sql "
            "when a small SQL change could radically alter the result — e.g. to "
            "check the impact of adding/removing a filter, switching INNER↔LEFT "
            "JOIN, joining on a different column, or using an ``exercices`` table "
            "vs ``YEAR(date_col)``. Returns quickly (parallel COUNT, no data "
            "fetched). If a variant fails, the others still return."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "variants": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 3,
                    "description": (
                        "List of 2-3 variants to compare. Each variant has a "
                        "``label`` (short human description, e.g. 'avec filtre "
                        "entité') and a ``sql`` (the full query)."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "label": {"type": "string"},
                            "sql": {"type": "string"},
                        },
                        "required": ["label", "sql"],
                    },
                },
            },
            "required": ["variants"],
        },
    },
    {
        "name": "introspect_tables_batch",
        "description": (
            "Introspect multiple tables in a SINGLE call (max 10). Returns "
            "columns, foreign keys, and key constraints for each table in "
            "parallel. Use this INSTEAD of multiple sequential introspect_table "
            "calls when you need to inspect several tables at once — saves "
            "round-trips and keeps context focused."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of table names to introspect (max 10).",
                },
                "info_type": {
                    "type": "string",
                    "enum": ["columns", "foreign_keys", "all"],
                    "description": "Information to retrieve per table (default 'all').",
                },
            },
            "required": ["table_names"],
        },
    },
    # ------------------------------------------------------------------
    # Outils terminaux (P2.2) — parité avec copilot_agent.
    # Permettent au LLM de clôturer EXPLICITEMENT la conversation au lieu
    # de juste épuiser MAX_TURNS. Déclenchent la génération du
    # ``Conversation.summary`` (P2.1).
    # ------------------------------------------------------------------
    {
        "name": "done",
        "description": (
            "Call this tool when you have FINISHED answering the user's "
            "question. The conversation will be marked as completed and a "
            "concise summary will be persisted for future runs to learn from. "
            "Pass a short ``summary`` (1-3 sentences) describing what was "
            "accomplished — this helps the user recall the conversation later "
            "and helps the next agent reuse the validated decisions. "
            "Do NOT call this tool just after a tool result you produced — "
            "first explain the result to the user, then call ``done``."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": (
                        "Short summary (1-3 sentences) of what was accomplished "
                        "in this conversation. Will be visible to the user and "
                        "used to seed future conversations on the same database."
                    ),
                },
            },
            "required": ["summary"],
        },
    },
    {
        "name": "abandon",
        "description": (
            "Call this tool when you CANNOT answer the user's question and "
            "need to give up. Pass a clear ``reason`` so the user understands "
            "why (missing schema info, unanswerable question, ambiguity not "
            "resolvable by tools, permission missing, etc.). Use sparingly — "
            "prefer ``ask_user_clarification`` when an interactive resolution "
            "is plausible. Once called, the conversation is closed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "description": (
                        "Plain-language explanation of why the agent cannot "
                        "answer. Shown to the user."
                    ),
                },
            },
            "required": ["reason"],
        },
    },
    # ------------------------------------------------------------------
    # Pipeline NL→SQL — workflow principal pour les demandes SQL
    # complexes/analytiques. Délègue à ``scripts/pipeline.py`` (8 phases :
    # extract+expand → filter → curate → search → scoring FK → rerank →
    # concept fact sheets → SQL composer IR). Retourne immédiatement avec
    # un ``run_id`` ; la progression est streamée via le WebSocket
    # ``/ws/iris/pipeline``. À utiliser pour les requêtes analytiques
    # nécessitant exploration sémantique du schéma. Pour un SQL trivial
    # (count simple, lookup d'une table connue), préférer ``execute_sql``
    # directement après ``check_schema_freshness``.
    # ------------------------------------------------------------------
    {
        "name": "run_pipeline",
        "description": (
            "Launch the NL→SQL pipeline as a supervised background run. "
            "**MANDATORY for ANALYTICAL or COMPLEX SQL** : multi-CTE, "
            "STRING_AGG / WITHIN GROUP, window functions (OVER), 3+ JOINs, "
            "UNION — ``execute_sql`` refuses these at the gate (task #99). "
            "The IR composer programs the SQL via primitives (no T-SQL "
            "syntax hallucination possible) : "
            "``string_agg`` (ordered, distinct), "
            "``version_fallback`` (preference + fallback, e.g. value from "
            "2024 else 2023), "
            "``partition_by_set`` (split by closed set membership IN/NOT IN), "
            "multi-CTE chained with ``full_outer_chain`` (YoY pattern). "
            "Returns immediately with a ``run_id`` and a WebSocket URL the "
            "user can subscribe to for live progress. The pipeline emits "
            "events per phase (8 phases, typically 30s-3min total). "
            "Do NOT use this tool for trivial queries (e.g., simple "
            "count on a known table) — call ``execute_sql`` directly "
            "after ``check_schema_freshness``. Schema freshness is "
            "still required: call ``check_schema_freshness`` BEFORE "
            "this tool if not already done in the conversation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query_nl": {
                    "type": "string",
                    "description": (
                        "Natural-language question from the user. Pass it "
                        "verbatim if possible — the pipeline does its own "
                        "extraction and routing. Avoid paraphrasing."
                    ),
                },
                "mode": {
                    "type": "string",
                    "enum": ["legacy", "ir"],
                    "description": (
                        "Phase 4 composer mode. 'ir' (default) uses the "
                        "Intermediate Representation composer (mature for "
                        "analytical queries, supports profitability/multi-"
                        "CTE patterns). 'legacy' lets the LLM emit free SQL "
                        "(simpler patterns)."
                    ),
                },
                "block_all_views": {
                    "type": "boolean",
                    "description": (
                        "If false (default, task #82), SQL views are INCLUDED in "
                        "the entity shortlist (Phase 1.5) so the pipeline can use "
                        "denormalising views to generate correct SQL (e.g. YoY "
                        "reports). Anti-hallucination is still guaranteed by "
                        "blocking VIEW-MINED FKs at Phase 1.5. If true, all views "
                        "are dropped (test mode: forces reconstruction of JOINs "
                        "from base tables only)."
                    ),
                },
                "use_sage": {
                    "type": "boolean",
                    "description": (
                        "DEV-ONLY toggle. If true (default), Phase 3 probes "
                        "execute on the live source SQL Server database. "
                        "If false, probes use a local SQLite mirror file "
                        "(dev convenience when offline / no VPN, never used "
                        "in production). In a production deployment this "
                        "param is effectively a no-op — the connector "
                        "always hits the live SQL Server."
                    ),
                },
                "additional_context": {
                    "type": "string",
                    "description": (
                        "Task #93 PR3 (2026-05-21) — ADD-ONLY mécanisme "
                        "d'auto-amélioration d'Iris. Champ OPTIONNEL : "
                        "contexte complémentaire que TU AJOUTES à la query "
                        "user (sans la modifier) pour aider la pipeline à "
                        "mieux router. Cas d'usage : tu as vu via tes "
                        "tools (search_schema, introspect_table, déjà-vu "
                        "RAG) un détail pertinent que la query NL brute "
                        "n'expose pas explicitement (ex: « le user fait "
                        "souvent référence à la table X pour ce type de "
                        "question », « j'ai vérifié que la colonne Y "
                        "porte la sémantique demandée »). RÈGLE STRICTE : "
                        "tu ajoutes des INFORMATIONS, jamais des "
                        "instructions ni des reformulations de la query "
                        "user — la pipeline doit toujours voir la query "
                        "verbatim en priorité. Laisse vide si rien de "
                        "concret à ajouter (pas d'invention)."
                    ),
                },
                "stop_after_phase": {
                    "type": "string",
                    # Enum aligné sur PHASES_ORDER (scripts/pipeline.py). Literal
                    # gardé par un test anti-drift (test_pipeline_resume_tool.py)
                    # — même pattern que ``from_phase`` (pipeline_resume) pour
                    # éviter d'importer scripts.pipeline au chargement du schéma.
                    "enum": [
                        "1.1-1.2",
                        "1.2.4",
                        "1.2.5",
                        "1.2.6",
                        "1.3-1.4",
                        "1.5",
                        "2",
                        "3",
                        "4",
                    ],
                    "description": (
                        "OPTIONAL early-stop. If set, the pipeline runs from the "
                        "start UP TO AND INCLUDING this phase, then STOPS without "
                        "composing the final SQL — it returns an INTERMEDIATE "
                        "artifact, NOT an executable query. Use ONLY when the user "
                        "wants to understand or validate the schema mapping BEFORE "
                        "generating SQL. Most useful stops: '1.5' = blueprint "
                        "(candidate tables + FK join graph, schema-level) ; '3' = "
                        "concept fact sheets (resolved tables/columns with sampled "
                        "real values). ALWAYS present the result as a HYPOTHESIS to "
                        "confirm ('here are the tables I'd use — does that match?'), "
                        "NEVER as a final answer. When the user validates, call "
                        "``pipeline_resume`` (from_phase = the phase AFTER the stop) "
                        "to continue to the SQL. Omit for a normal full run "
                        "(default). '4' is a no-op (== full run)."
                    ),
                },
            },
            "required": ["query_nl"],
        },
    },
    {
        "name": "inspect_pipeline_artifact",
        "description": (
            "Read a phase-level metadata summary from a previous or "
            "running pipeline run. Returns the synthetic summary "
            "(counts, top items, no sensitive data) — NOT the full "
            "JSON artifact (that lives on disk and is served separately "
            "via the artifact API). Use to follow up on a run launched "
            "via ``run_pipeline`` (e.g., 'how many tables were filtered "
            "in Phase 1.2.5?', 'which concepts were resolved in Phase "
            "2?'). Only the user's own runs are accessible."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "run_id": {
                    "type": "integer",
                    "description": "Pipeline run ID returned by run_pipeline.",
                },
                "phase_id": {
                    "type": "string",
                    "enum": [
                        "1.1-1.2",
                        "1.2.4",
                        "1.2.5",
                        "1.2.6",
                        "1.3-1.4",
                        "1.5",
                        "2",
                        "3",
                        "4",
                    ],
                    "description": "Phase identifier.",
                },
            },
            "required": ["run_id", "phase_id"],
        },
    },
    # ------------------------------------------------------------------
    # Pipeline RESUME — reprend un run existant à une phase donnée.
    # Crée un NOUVEAU run_id (préserve l'historique du source) qui réutilise
    # les artefacts amont du run source et rejoue from_phase + downstream.
    # Mêmes garanties que ``run_pipeline`` (quota, ownership, bus events).
    # ------------------------------------------------------------------
    {
        "name": "pipeline_resume",
        "description": (
            "Resume an existing NL→SQL pipeline run from a specific phase. "
            "Use when a previous run failed at a known phase, or you "
            "diagnosed a bad upstream decision and want to retry from a "
            "specific phase with optional state patches. Creates a NEW "
            "``run_id`` that inherits the source run's "
            "query/mode/options but skips upstream phases (their results "
            "are reused from the source's snapshot as-is). The source "
            "run is preserved for audit. Returns immediately with the "
            "new ``run_id``; live progress streams via the same chat "
            "bridge as ``run_pipeline``. Refuses if: source run "
            "unknown/foreign-user/still-active, ``from_phase`` invalid, "
            "any upstream phase not completed in source, "
            "``state_overrides`` has forbidden keys or exceeds 64KB."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "run_id": {
                    "type": "integer",
                    "description": (
                        "ID of the source pipeline run to resume from. "
                        "Must belong to the current user. Must NOT be in "
                        "pending/running state (cancel it first if so)."
                    ),
                },
                "from_phase": {
                    "type": "string",
                    "enum": [
                        "1.1-1.2",
                        "1.2.4",
                        "1.2.5",
                        "1.2.6",
                        "1.3-1.4",
                        "1.5",
                        "2",
                        "3",
                        "4",
                    ],
                    "description": (
                        "Phase ID to restart from. All phases STRICTLY "
                        "BEFORE this one must have been completed in the "
                        "source run (their snapshots are reused). Phases "
                        "AT or AFTER are re-executed. Use '4' to retry "
                        "only the SQL composer with the same fact "
                        "sheets. Use '2' to redo the rerank and "
                        "everything downstream."
                    ),
                },
                "state_overrides": {
                    "type": "object",
                    "description": (
                        "OPTIONAL patches to the source state before "
                        "resume. Keys must match PipelineState fields "
                        "(extracted, filtered, curated, search, scored, "
                        "reranks, factsheets, sql_final, "
                        "concept_resolution, query, final_sql). Use "
                        "sparingly — for example to force a specific "
                        "concept_resolution choice. Telemetry fields "
                        "(started_at, phase_durations) are NOT "
                        "overridable. Total size capped at 64KB "
                        "serialized."
                    ),
                },
            },
            "required": ["run_id", "from_phase"],
        },
    },
    # ------------------------------------------------------------------
    # T20 — Mutation incrémentale de l'IR du dernier run_pipeline réussi
    # (conversation multi-tour). Évite de relancer la pipeline complète
    # quand l'utilisateur affine sa demande précédente.
    # ------------------------------------------------------------------
    {
        "name": "mutate_last_ir",
        "description": (
            "Modifie l'IR (Intermediate Representation) du DERNIER run_pipeline "
            "réussi dans cette conversation, puis recompose un nouveau SQL — "
            "SANS relancer la pipeline complète (économies tokens + latence).\n\n"
            "Utilise QUAND l'utilisateur AFFINE sa demande précédente (ajouter/"
            "retirer un filtre, changer le group-by, le tri, le limit). N'utilise "
            "PAS si l'utilisateur change la question fondamentalement (nouveau "
            "concept jamais résolu, métrique différente) — préfère `run_pipeline` "
            "dans ce cas pour bénéficier de l'exploration schéma + RAG.\n\n"
            "Opérations supportées (passe-les dans `operations`, max 10 par appel) :\n"
            "- `{op:'add_filter', concept:'<nom>', operator:'=|!=|<|>|<=|>=|IN|"
            "NOT_IN|LIKE|NOT_LIKE|IS_NULL|IS_NOT_NULL|EXISTS|NOT_EXISTS', val:<valeur>}`\n"
            "- `{op:'remove_filter', concept:'<nom>', operator:'<optional>'}` "
            "(refuse si aucun filtre matche — pas de no-op silencieux)\n"
            "- `{op:'add_group_by', concept:'<nom>'}` (idempotent si déjà présent)\n"
            "- `{op:'remove_group_by', concept:'<nom>'}`\n"
            "- `{op:'set_limit', n:<int>0 ou null pour supprimer}`\n"
            "- `{op:'set_order_by', order_by:[{concept_or_alias:'...', "
            "direction:'ASC'|'DESC'}, ...]}` (remplace toute la liste ; [] pour clear)\n\n"
            "**Refus en MVP** : IR multi-CTE ou avec FULL_OUTER derivation — "
            "relance `run_pipeline` pour ces cas (le tool renvoie un code erreur "
            "actionnable).\n\n"
            "Retourne `{success, sql, ir_summary, ops_applied, source_run_id}`. "
            "Le SQL n'est PAS exécuté automatiquement — appelle ensuite "
            "`execute_sql` pour obtenir les résultats."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "operations": {
                    "type": "array",
                    "description": (
                        "Liste d'opérations à appliquer séquentiellement (1 à 10). "
                        "Si une op échoue, l'IR stocké est INCHANGÉ (atomique)."
                    ),
                    "items": {"type": "object"},
                    "minItems": 1,
                    "maxItems": 10,
                },
            },
            "required": ["operations"],
        },
    },
    # -----------------------------------------------------------------------
    # Casquette Iris-DBA-write — admin only, écritures SQL via mail au DBA.
    # -----------------------------------------------------------------------
    {
        "name": "propose_sql_write",
        "description": (
            "ADMIN ONLY. Casquette 'Iris-DBA-write' : propose une écriture "
            "SQL (INSERT/UPDATE/DELETE) sur la base source. N'EXÉCUTE PAS "
            "directement. Le système : (1) valide via AST, (2) fait un "
            "dry-run pour estimer les lignes affectées, (3) envoie un mail "
            "à l'adresse d'approbation (« Email support » de /admin/smtp-config), "
            "(4) attend que le DBA fasse un snapshot puis clique le lien "
            "d'approbation. "
            "Sans le feu vert du DBA, AUCUNE modification n'a lieu. "
            "Utilise ce tool uniquement quand un admin demande explicitement "
            "de modifier des données. Refuse les DDL (DROP, ALTER, CREATE, "
            "TRUNCATE) — le validateur les bloquera de toute façon. Toujours "
            "fournir un 'intent' clair (ce que la modification fait en français)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": (
                        "Single-statement T-SQL : INSERT, UPDATE, ou DELETE. "
                        "Doit avoir une clause WHERE référençant une colonne "
                        "(pas WHERE 1=1) pour UPDATE/DELETE. Pas de DDL."
                    ),
                },
                "intent": {
                    "type": "string",
                    "description": (
                        "Description en français de ce que cette opération fait, "
                        "destinée au DBA externe qui ne connaît pas le contexte "
                        "Iris (ex: 'Renomme le compte 411000 en 411100 sur "
                        "toutes les écritures de janvier 2026')."
                    ),
                },
            },
            "required": ["sql", "intent"],
        },
    },
    # -----------------------------------------------------------------------
    # Casquette Iris-agent-Komptia — lecture du code source pour Q&A.
    # Tous rôles. Modèle open-by-default + denylist (SSoT : codebase_reader) —
    # PAS d'allowlist de dossiers (qui divergerait du contenu réel de l'image
    # client : tests/, docs/, *.md sont exclus du build prod). Le contrat
    # opérant est la DENYLIST (données/secrets), pas une liste de dossiers lisibles.
    # -----------------------------------------------------------------------
    {
        "name": "search_codebase",
        "description": (
            "Casquette 'Iris-agent-Komptia' : grep le code source de Komptia "
            "pour répondre aux questions sur l'app (architecture, "
            "fonctionnement, où vit telle feature). Utilise un pattern regex "
            "(re Python). Renvoie file:line + extrait. Hard caps : 200 "
            "matches total, 25 par fichier. Grep le code source du projet "
            "présent dans ce déploiement (certains dossiers de dev — tests/, "
            "docs/ — peuvent être absents de l'image de production). NE LIT "
            "JAMAIS les données utilisateur (.afz.json, BDD, classeurs) ni "
            "les secrets (.env). Préférable au read_code_file quand tu ne "
            "connais pas encore la file path exacte."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": (
                        "Regex Python (ex: 'def\\s+execute_write', "
                        "'class\\s+IrisAgent'). Min 2 chars. Précise."
                    ),
                },
                "file_glob": {
                    "type": "string",
                    "description": (
                        "Glob optionnel pour limiter les fichiers (ex: "
                        "'**/*.py', 'app/handlers/*.py')."
                    ),
                },
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "read_code_file",
        "description": (
            "Casquette 'Iris-agent-Komptia' : lit un fichier de la codebase "
            "Komptia avec pagination. Hard caps : 200 KB par fichier max, "
            "2000 lignes par appel max. Si le fichier est plus grand, "
            "appelle plusieurs fois avec offset croissant. Lisible : le code "
            "source du projet présent dans ce déploiement (certains dossiers de "
            "dev — tests/, docs/ — peuvent être absents de l'image de "
            "production). REFUSE TOUJOURS : .env, data/, outputs/, backups/, "
            "logs, BDD, classeurs (.afz.json), ET la doctrine/config interne "
            "Claude Code (CLAUDE.md, .claude/) — protection isolation "
            "utilisateurs + confidentialité."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Path relatif au projet (ex: 'app/handlers/iris.py', "
                        "'app/services/ai/agent_service.py')."
                    ),
                },
                "offset": {
                    "type": "integer",
                    "description": ("1-indexed line offset (1 = première ligne, défaut)."),
                    "default": 1,
                    "minimum": 1,
                },
                "limit": {
                    "type": "integer",
                    "description": ("Nombre de lignes à lire (max 2000). Défaut : 200."),
                    "default": 200,
                    "minimum": 1,
                    "maximum": 2000,
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "list_code_files",
        "description": (
            "Casquette 'Iris-agent-Komptia' : liste les fichiers d'un "
            "dossier de la codebase. Cap 200 fichiers retournés. Glob "
            "supporté (ex: '*.py', '**/*.html'). Mêmes restrictions de "
            "chemin que read_code_file."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "directory": {
                    "type": "string",
                    "description": (
                        "Path relatif d'un dossier du projet (ex: "
                        "'app/services/ai', 'app/handlers')."
                    ),
                },
                "glob_pattern": {
                    "type": "string",
                    "description": ("Glob (défaut '*'). Ex: '*.py', '**/*.html'."),
                    "default": "*",
                },
            },
            "required": ["directory"],
        },
    },
    # ------------------------------------------------------------------
    # T23 — Mode "exploration ouverte"
    # Détection programmatique de question vague + proposition d'axes,
    # AVANT de lancer la pipeline NL→SQL complète. Pas d'appel LLM.
    # ------------------------------------------------------------------
    {
        "name": "start_exploration_mode",
        "description": (
            "Detect whether the user query is too vague to run the NL→SQL "
            "pipeline and, if so, return 3-5 concrete exploration axes "
            "(top entities by metric, recent activity, totals by period, "
            "anomalies, distribution by dimension, comparisons). Detection "
            "is 100% programmatic — no LLM call. Use this tool BEFORE "
            "``run_pipeline`` whenever the user query is short, generic, "
            "or lacks concrete entities (e.g. 'show me data', 'donne-moi "
            "des infos', 'stats'). The returned payload includes "
            "``is_vague`` (bool), ``axes`` (list of structured "
            "exploration patterns), and ``instruction_for_assistant`` "
            "explaining what to do next. If ``is_vague`` is False, call "
            "``run_pipeline`` directly."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query_nl": {
                    "type": "string",
                    "description": ("User's natural-language question to evaluate."),
                },
                "top_n": {
                    "type": "integer",
                    "description": (
                        "Number of axes to propose (3-6, default 5). " "Clamped server-side."
                    ),
                    "default": 5,
                    "minimum": 3,
                    "maximum": 6,
                },
            },
            "required": ["query_nl"],
        },
    },
    # ── Plan structuré (todo-list dynamique partagée avec copilot) ──
    # Mêmes outils que copilot_tools.py:707-789 (plan_add / plan_update /
    # plan_list). Validation & mutation déléguées à ``plan_tools_core`` —
    # la state vit dans ``context["plan"]`` (per-turn, scope = un message
    # utilisateur). Une émission ``plan_update`` WebSocket est faite par
    # ``agent_service`` après chaque call ``plan_add`` / ``plan_update``
    # pour que le widget ``.iris-plan-group`` se rafraîchisse en temps réel.
    {
        "name": "plan_add",
        "description": (
            "Ajoute une étape à ta todo-list. Utile pour les tâches "
            "multi-étapes (exploration schéma + génération SQL + analyse, "
            "ou enchaînement plusieurs requêtes) où tu as besoin de tracer "
            "ce qui est fait, ce qui reste, ce qui a été écarté. "
            "Non-terminal. La task est créée avec status `pending` — appelle "
            "`plan_update` pour passer à `in_progress` quand tu y travailles, "
            "puis `completed` ou `cancelled` à la fin. L'utilisateur voit en "
            "temps réel la liste et le status des tasks dans un bandeau dédié "
            "au-dessus de la conversation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "subject": {
                    "type": "string",
                    "description": (
                        "Titre court de l'étape (verbe à l'impératif : "
                        "« Explorer schéma factures », « Construire la requête "
                        "agrégée », « Diagnostiquer 0 lignes »)."
                    ),
                },
                "description": {
                    "type": "string",
                    "description": (
                        "Optionnel. Pourquoi cette étape, ou la prochaine "
                        "action concrète. Utile pour te rappeler l'intention "
                        "après plusieurs turns."
                    ),
                },
            },
            "required": ["subject"],
            "additionalProperties": False,
        },
    },
    {
        "name": "plan_update",
        "description": (
            "Change le status et/ou le subject d'une task du plan. Passe à "
            "`in_progress` quand tu y travailles, `completed` quand la task "
            "est vraiment faite (pas avant), `cancelled` si tu décides en "
            "cours de route que cette étape est inutile — garde la trace "
            "au lieu de supprimer. Non-terminal."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "task_id": {
                    "type": "integer",
                    "description": "Id retourné par `plan_add`.",
                },
                "status": {
                    "type": "string",
                    # Enum dérivé de PLAN_STATUSES (plan_tools_core) — SSoT.
                    "enum": list(PLAN_STATUSES),
                    "description": (
                        "Nouveau status. Optionnel (tu peux juste renommer "
                        "via `subject` sans changer le status)."
                    ),
                },
                "subject": {
                    "type": "string",
                    "description": (
                        "Optionnel. Nouveau titre de la task si tu veux " "affiner la formulation."
                    ),
                },
            },
            "required": ["task_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "plan_list",
        "description": (
            "Retourne l'état courant de ta todo-list (toutes les tasks avec "
            "leur status et un décompte par status). Utile si tu veux te "
            "rappeler où tu en es sans remonter l'historique conversationnel. "
            "Non-terminal."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
]

# ───────────────────────────────────────────────────────────────────────────
# Task #10 P4.1 + Task #11 P4.2 — Tools DAG-aware (automation-only)
# ───────────────────────────────────────────────────────────────────────────
# Ces 6 tools sont déclarés dans ``agent_automation_tools.py`` (fichier
# séparé pour ne pas surcharger ce module 11000+ lignes). Ils sont étendus
# dans IRIS_TOOLS ici pour que le LLM les voie dans sa toolbox.
# Le filtrage par contexte (``filter_tools_for_context``) garantit qu'ils
# ne sont exposés qu'en mode ``source="automation"`` — bloqués en page/widget.
from app.services.ai.agent_automation_tools import (
    AUTOMATION_DAG_TOOL_HANDLERS,
    AUTOMATION_DAG_TOOL_NAMES,
    AUTOMATION_DAG_TOOLS,
)

IRIS_TOOLS.extend(AUTOMATION_DAG_TOOLS)


# ---------------------------------------------------------------------------
# SSOT-1 — Classification des effets de bord par outil (R131 doctrine SSOT)
# ---------------------------------------------------------------------------
#
# Single source of truth : `TOOL_SIDE_EFFECTS` est la classification autorité
# de chaque outil. Toutes les listes filtrées (allowlist mode Expliquer,
# prompt _PROMPT_HIGHLIGHTED_TOOLS, tooltip mode toggle, futurs filtres par
# rôle) DOIVENT en être dérivées plutôt qu'être maintenues séparément.
#
# Sanity check au module load : tout outil de IRIS_TOOLS sans entrée ici
# fait planter le boot (fail-fast). C'est volontaire — un outil non classifié
# qui passe en runtime serait silencieusement bloqué en mode Expliquer
# (`blocked_by=explanation_mode` car absent de la dérivée), bug invisible.
# Mieux vaut un crash au boot qu'un faux comportement masqué en production.
#
# Pour AJOUTER un nouvel outil :
#   1. Définir le tool dans IRIS_TOOLS
#   2. Ajouter une entrée dans TOOL_SIDE_EFFECTS avec sa classe (voir ci-dessous)
#   3. Les listes dérivées (allowlist, etc.) se mettent à jour automatiquement
#
# Pour MODIFIER l'autorisation d'un outil en mode Expliquer :
#   - Soit changer sa classe (ex: "sage_read_live" → "metadata_read" si on
#     cache son résultat et qu'il n'appelle plus Sage live)
#   - Soit modifier EXPLANATION_MODE_ALLOWED_CLASSES ci-dessous (impact large)

# Classes d'effet de bord autorisées (sémantique runtime, pas Anthropic schema)
SIDE_EFFECT_CLASSES: tuple[str, ...] = (
    "conversational",  # ask/done/abandon/suggest/start_exploration
    "metadata_read",  # cache schéma local, doc, codebase, artefacts disque
    "komptia_read",  # lecture BDD Komptia locale (users/reports/stats/prefs)
    "komptia_write",  # écriture BDD Komptia locale (mutations: users/prefs/memory…)
    "sage_read_live",  # query Sage live en lecture (SELECT, COUNT, INTERSECT)
    "sage_write",  # query Sage mutation (INSERT/UPDATE/DELETE — via approbation)
    "external_io",  # email SMTP, fichier disque (PDF/Excel), API externe
    "costly_async",  # pipeline complet, sync schéma enrichi (LLM massif)
    "pedagogical_analysis",  # analyse in-memory sur données déjà chargées
)

# Classes autorisées en mode "Expliquer" — l'utilisateur veut comprendre la
# démarche d'Iris SANS déclencher d'effets observables (pas de Sage live, pas
# d'écriture BDD, pas de mail, pas de fichier sur disque, pas de sync coûteuse).
#
# Note de nuance assumée : `pedagogical_analysis` inclut `analyze_query_performance`
# qui émet techniquement un SHOWPLAN_TEXT côté Sage. Acceptable car (a) lecture
# du plan, pas de données, (b) sémantique = pédago pure, (c) déjà autorisé par
# l'ancienne hardcoded list — pas de régression de comportement.
EXPLANATION_MODE_ALLOWED_CLASSES: frozenset[str] = frozenset(
    {
        "conversational",
        "metadata_read",
        "komptia_read",
        "pedagogical_analysis",
    }
)

# Classification autorité — colocaliser avec IRIS_TOOLS dans ce même fichier
# garantit que toute modif d'outil verra la classif à côté.
TOOL_SIDE_EFFECTS: Dict[str, str] = {
    # ── Conversational (OBLIGATOIRES pour terminer un tour) ──
    "ask_user_clarification": "conversational",
    "suggest_followup_questions": "conversational",
    "done": "conversational",
    "abandon": "conversational",
    "start_exploration_mode": "conversational",
    # Plan structuré (todo-list locale en mémoire — pas d'I/O Sage ni
    # Komptia). Classés ``conversational`` car mêmes garanties que
    # ``ask_user_clarification`` : pas d'effet observable persistent,
    # pas de coût $$$, autorisés en mode Expliquer.
    "plan_add": "conversational",
    "plan_update": "conversational",
    "plan_list": "conversational",
    # Task #10/#11 (2026-05-27) — Tools DAG-aware automation-only.
    # Classés ``conversational`` : mutent uniquement le ``context`` dict en
    # RAM (state du run DAG courant), aucun I/O Sage/Komptia/external. Le
    # filtrage par contexte (``AUTOMATION_TOOL_CLASSIFICATION``) garantit
    # qu'ils ne sont exposés QU'en mode ``source="automation"`` — donc jamais
    # en mode explanation (qui est forcément page/widget).
    "set_run_variable": "conversational",
    "get_run_variable": "conversational",
    "get_step_output": "conversational",
    "route_to": "conversational",
    "skip_steps": "conversational",
    "abort_run": "conversational",
    # ── Exploration métadata (cache schéma local, indexes, in-memory) ──
    "search_schema": "metadata_read",
    "introspect_table": "metadata_read",
    "introspect_tables_batch": "metadata_read",
    "get_fk_path": "metadata_read",
    "get_database_schema": "metadata_read",
    "explore_join_alternatives": "metadata_read",
    "match_analytical_pattern": "metadata_read",
    # ── Pédagogie / analyse in-memory ──
    "analyze_query_performance": "pedagogical_analysis",  # SHOWPLAN read-only (exception
    # documentée — c'est le SEUL tool de cette classe qui touche Sage ; cf.
    # _EXPLANATION_PEDAGOGICAL_SAGE_EXCEPTIONS pour le test de garde explicite)
    "analyze_numbers": "pedagogical_analysis",
    "diagnose_zero_rows": "pedagogical_analysis",
    # ── Côté serveur déclenche LLM utilitaire / mutation persistante / Sage live ──
    # 3 tools que l'ancienne hardcoded list autorisait en mode Expliquer mais
    # qui ont en réalité des effets observables. Découverts par adversarial
    # review (sub-agent code-reviewer) session 15 SSOT-1. Reclassifiés en
    # 3 classes plus précises pour respecter la promesse du mode Expliquer
    # (pas d'effet observable, pas de coût $$$, pas d'I/O Sage live).
    "align_request": "costly_async",  # déclenche call_llm(ModelKind.UTILITY,
    # max_tokens_soft=2000) côté Sage — coût $$$ + dépendance cloud, viole la
    # promesse "pas de sync coûteuse" du mode Expliquer
    "mutate_last_ir": "komptia_write",  # mute ConversationIRStore.atomic_mutate
    # (`existing["ir"] = result["new_ir"]`) → effet observable persistant entre
    # tours. Mode Expliquer ne doit pas modifier l'état runtime.
    "check_schema_freshness": "sage_read_live",  # ouvre une connexion live à
    # SQL Server via connector.connect() + queries INFORMATION_SCHEMA — pas
    # "lecture cache" mais vraie I/O Sage. Cf. schema_freshness.py:91-97.
    # ── Komptia local read (BDD locale, lectures sans I/O Sage) ──
    "get_app_stats": "komptia_read",
    "get_user_preferences": "komptia_read",
    "list_reports": "komptia_read",
    "list_execution_history": "komptia_read",
    # ── Doc / artefact local (read-only sur disque ou statique) ──
    "search_documentation": "metadata_read",
    "inspect_pipeline_artifact": "metadata_read",
    "analyze_attachment": "metadata_read",
    # Outils de lecture d'un classeur uploadé — délèguent aux cores
    # extraits de copilot_tools.py (SSoT). Pas d'I/O Sage, juste lecture
    # du fichier déjà chargé en RAM (pandas DataFrame). Cf. P2.2 task #13.
    "list_workbook_tabs": "metadata_read",
    "read_workbook_rows": "metadata_read",
    "count_workbook_rows": "metadata_read",
    "aggregate_workbook": "metadata_read",
    # quick_overview_workbook — overview programmatique sur tabs_context
    # déjà construit. Pas d'I/O disque ni Sage, juste calculs Python sur
    # la donnée en RAM. Cf. P2.3 task #14.
    "quick_overview_workbook": "metadata_read",
    # ── Codebase read ──
    "search_codebase": "metadata_read",
    "read_code_file": "metadata_read",
    "list_code_files": "metadata_read",
    # ── Sage live (lecture) — exécute du SQL en live, NON autorisé Expliquer ──
    "execute_sql": "sage_read_live",
    "peek_table_data": "sage_read_live",
    "test_sql": "sage_read_live",
    "check_join_compatibility": "sage_read_live",  # INTERSECT live
    "compare_query_variants": "sage_read_live",  # COUNT parallel live
    "analyze_null_data": "sage_read_live",
    # `get_resolved_values` lit techniquement la BDD Komptia locale (table
    # ValueMapping = cache d'anonymisation), pas Sage. Mais SÉMANTIQUEMENT
    # c'est de la préparation de filtre SQL Sage (résoudre la valeur exacte
    # avant un INSERT/SELECT). L'exclure du mode Expliquer est cohérent
    # avec la liste forbidden de ``test_agent_service.py::test_no_*``
    # (l'intent du contrat : mode Expliquer = pas de préparation SQL Sage
    # live, même si le tool lui-même n'émet pas de query Sage).
    "get_resolved_values": "sage_read_live",
    # ── Sage write (mutations via approbation utilisateur) ──
    "propose_sql_write": "sage_write",
    # ── Komptia write (BDD locale) ──
    "save_to_datastore": "komptia_write",
    "save_user_preference": "komptia_write",
    "save_memory": "komptia_write",
    "learn_insight": "komptia_write",
    "schedule_task": "komptia_write",
    "manage_automations": "komptia_write",
    "manage_contacts": "komptia_write",
    "manage_distribution_lists": "komptia_write",
    "manage_users": "komptia_write",
    "manage_app_config": "komptia_write",
    # ── External IO (email SMTP, fichier disque) ──
    "send_email": "external_io",
    "create_report": "external_io",
    "create_report_from_results": "external_io",
    # ── Costly async (LLM massif, sync long) ──
    "trigger_enriched_sync": "costly_async",
    "trigger_schema_sync": "costly_async",
    "run_pipeline": "costly_async",
    "pipeline_resume": "costly_async",
    # `transform_uploaded_file` délègue à `run_copilot_agent` (tool-use loop
    # complet, MAX_TURNS=40, plusieurs appels LLM). Coût $$$ + latence
    # ~10-60s — classification cohérente avec les autres tools qui
    # déclenchent une boucle LLM longue. Mode Expliquer interdit (un user
    # qui demande "explique-moi ce fichier" ne doit pas déclencher la
    # transformation copilot ; il a `analyze_attachment` ou des read-tools
    # pour ça).
    "transform_uploaded_file": "costly_async",
}


class ToolClassificationError(RuntimeError):
    """Erreur de configuration métier : classification d'un outil incohérente.

    Distincte d'``AssertionError`` (qui peut être skippée avec ``python -O``
    ou catché par un wrapper "internal error" en prod). Cette exception est
    explicitement métier — elle bloque le boot du module avec un message
    actionnable. Cf. adversarial review CRITICAL #4 sur SSOT-1.
    """


def _validate_tool_classifications() -> None:
    """Sanity check au module load — chaque tool a une classification valide.

    Vérifie 4 invariants :

    1. Chaque tool de IRIS_TOOLS a une entrée dans TOOL_SIDE_EFFECTS
    2. Aucune entrée orpheline (classification pour un tool retiré)
    3. Toutes les classes utilisées sont dans SIDE_EFFECT_CLASSES
    4. Chaque tool classifié a un handler enregistré dans _TOOL_HANDLERS
       (couvre la 3e collection qu'un tool doit habiter ; cf. adversarial
       review MAJOR #1 sur SSOT-1 — sans ce check, un tool peut être
       déclaré et classifié sans handler = silent runtime failure)

    Levé fail-fast au boot si un dev ajoute un tool dans IRIS_TOOLS sans
    le brancher proprement. Bug visible immédiatement vs masqué runtime.

    Raises ``ToolClassificationError`` (sous-classe de RuntimeError) plutôt
    que ``AssertionError`` car c'est une erreur de configuration métier,
    pas un bug d'assertion de programmation.
    """
    declared_tools = {t["name"] for t in IRIS_TOOLS}
    classified_tools = set(TOOL_SIDE_EFFECTS.keys())

    missing = declared_tools - classified_tools
    orphaned = classified_tools - declared_tools
    invalid = {
        name: cls for name, cls in TOOL_SIDE_EFFECTS.items() if cls not in SIDE_EFFECT_CLASSES
    }

    errors = []
    if missing:
        errors.append(
            f"{len(missing)} outils sans entrée dans TOOL_SIDE_EFFECTS : "
            f"{sorted(missing)}. Ajoute la classification dans agent_tools.py."
        )
    if orphaned:
        errors.append(
            f"{len(orphaned)} entrées orphelines dans TOOL_SIDE_EFFECTS "
            f"(tool retiré de IRIS_TOOLS sans cleanup) : {sorted(orphaned)}."
        )
    if invalid:
        errors.append(
            f"side_effect_class invalides : {invalid}. "
            f"Valeurs autorisées : {SIDE_EFFECT_CLASSES}"
        )

    if errors:
        raise ToolClassificationError(
            "TOOL_SIDE_EFFECTS — incohérence détectée :\n  - " + "\n  - ".join(errors)
        )


def validate_handlers_coverage(handlers_map: Dict[str, Any]) -> None:
    """Vérifie que chaque tool de TOOL_SIDE_EFFECTS a un handler enregistré.

    Appelée séparément après que `_TOOL_HANDLERS` soit construit (en bas
    du module, après la définition des handlers). Sans ce check, un tool
    peut être déclaré + classifié mais sans handler — `execute_tool` lèverait
    silencieusement un KeyError au premier appel runtime (bug fantôme).

    Tools sans handler (`_TOOL_HANDLERS[name]` absent) raise
    ``ToolClassificationError`` au boot avec la liste des manquants.
    """
    classified_tools = set(TOOL_SIDE_EFFECTS.keys())
    registered_handlers = set(handlers_map.keys())

    no_handler = classified_tools - registered_handlers
    if no_handler:
        raise ToolClassificationError(
            f"{len(no_handler)} outils classifiés mais sans handler dans "
            f"_TOOL_HANDLERS : {sorted(no_handler)}. Branche le handler dans "
            f"agent_tools.py ou retire l'entrée de TOOL_SIDE_EFFECTS."
        )


# Whitelist explicite des tools de classe `pedagogical_analysis` autorisés à
# faire de l'I/O Sage. Une seule exception aujourd'hui : `analyze_query_performance`
# émet un SHOWPLAN_TEXT (read-only, pas de mutation, pas de données).
# Si un dev ajoute un nouveau tool dans `pedagogical_analysis` qui touche Sage,
# il doit l'ajouter ici ET documenter pourquoi. Sans ça, la doctrine de la classe
# devient floue ("certains touchent Sage, d'autres pas") et la promesse mode
# Expliquer s'érode. Cf. adversarial review MAJOR #2 sur SSOT-1.
_EXPLANATION_PEDAGOGICAL_SAGE_EXCEPTIONS: frozenset[str] = frozenset(
    {
        "analyze_query_performance",  # SHOWPLAN_TEXT côté Sage — read-only plan
    }
)


def derive_explanation_allowed_tools() -> frozenset[str]:
    """Dérive l'allowlist du mode Expliquer depuis TOOL_SIDE_EFFECTS.

    Single source of truth : ajouter/retirer un tool de l'allowlist mode
    Expliquer = changer sa classe dans TOOL_SIDE_EFFECTS. Pas besoin de
    toucher une seconde liste hardcoded dans agent_service.py.
    """
    return frozenset(
        name for name, cls in TOOL_SIDE_EFFECTS.items() if cls in EXPLANATION_MODE_ALLOWED_CLASSES
    )


# Libellés FR humains pour les classes d'effets — utilisés pour générer les
# tooltips du toggle de mode côté UI (SSOT-4, 2026-05-21). Auparavant les
# tooltips étaient hardcodés dans ``templates/iris.html`` et mentaient si
# l'allowlist changeait. Maintenant le tooltip est dérivé de la même source
# que le runtime (``EXPLANATION_MODE_ALLOWED_CLASSES``). Si on ajoute un tool
# d'écriture, le tooltip mode Expliquer mentionne automatiquement la classe
# correspondante comme "bloquée".
_SIDE_EFFECT_CLASS_LABELS_FR: Final[dict[str, str]] = {
    "conversational": "interactions conversationnelles",
    "metadata_read": "lecture du schéma et de la documentation",
    "komptia_read": "lecture de la configuration locale",
    "komptia_write": "modification de la configuration locale",
    "sage_read_live": "exécution de requêtes SQL en lecture",
    "sage_write": "exécution de requêtes SQL en écriture",
    "external_io": "envoi d'emails et création de fichiers",
    "costly_async": "synchronisations longues et pipelines",
    "pedagogical_analysis": "analyses pédagogiques",
}


def derive_iris_mode_tooltips() -> dict[str, str]:
    """Génère les tooltips FR pour le toggle Executer/Expliquer du widget Iris.

    Single source of truth : la liste des classes autorisées en mode
    Expliquer (``EXPLANATION_MODE_ALLOWED_CLASSES``) détermine à la fois
    le runtime ET ce que le tooltip explique à l'utilisateur. Plus de
    risque que le tooltip mente si un dev change l'allowlist.

    Returns:
        Dict avec clés ``execution`` et ``explanation`` — strings prêts à
        être posés dans le ``title=`` du bouton HTML correspondant.
    """
    allowed = EXPLANATION_MODE_ALLOWED_CLASSES
    blocked = [c for c in SIDE_EFFECT_CLASSES if c not in allowed]

    # Côté Executer : on liste les classes qui SERONT effectivement exécutées
    # (= toutes). Phrasing positif "Iris peut faire X, Y, Z".
    execution_capabilities = [
        _SIDE_EFFECT_CLASS_LABELS_FR[c]
        for c in SIDE_EFFECT_CLASSES
        if c in _SIDE_EFFECT_CLASS_LABELS_FR
    ]
    execution_tooltip = (
        "Comportement normal : Iris peut effectuer toutes ses actions — "
        + ", ".join(execution_capabilities)
        + "."
    )

    # Côté Expliquer : on liste ce qui est bloqué. Phrasing négatif "pas de X, Y, Z".
    blocked_labels = [
        _SIDE_EFFECT_CLASS_LABELS_FR[c] for c in blocked if c in _SIDE_EFFECT_CLASS_LABELS_FR
    ]
    if blocked_labels:
        # Élision FR : "pas d'" devant voyelle, "pas de" sinon.
        def _negate(lbl: str) -> str:
            return ("pas d'" if lbl[:1].lower() in "aeiouéèàâêîôûïü" else "pas de ") + lbl

        explanation_tooltip = (
            "Iris explique sa démarche sans déclencher d'effets observables — "
            + ", ".join(_negate(lbl) for lbl in blocked_labels)
            + ". Utile pour comprendre comment elle répondrait."
        )
    else:
        explanation_tooltip = (
            "Iris explique sa démarche sans déclencher d'effets observables. "
            "Utile pour comprendre comment elle répondrait."
        )

    return {
        "execution": execution_tooltip,
        "explanation": explanation_tooltip,
    }


# Sanity check fail-fast au module load (cf. docstring de la fonction)
_validate_tool_classifications()


# ---------------------------------------------------------------------------
# Lazy singletons — Indexes 5D et graphe FK (construits une fois, réutilisés)
# ---------------------------------------------------------------------------

_search_indexes = None
_search_indexes_lock = asyncio.Lock()
_fk_graph = None
_fk_graph_lock = asyncio.Lock()


async def get_search_indexes():
    """Obtenir ou construire les indexes de recherche 5D (lazy singleton)."""
    global _search_indexes
    if _search_indexes is None:
        async with _search_indexes_lock:
            if _search_indexes is None:
                from app.services.ai.orchestrator_search import build_search_indexes

                store = get_training_store()
                _search_indexes = await build_search_indexes(store)
                logger.info("Search indexes 5D built (lazy singleton)")
    return _search_indexes


async def get_fk_graph():
    """Obtenir ou construire le graphe FK (lazy singleton)."""
    global _fk_graph
    if _fk_graph is None:
        async with _fk_graph_lock:
            if _fk_graph is None:
                from app.services.ai.orchestrator_tools import build_fk_graph

                store = get_training_store()
                _fk_graph = await build_fk_graph(store)
                logger.info("FK graph built (lazy singleton)")
    return _fk_graph


def invalidate_search_indexes():
    """Invalider les indexes après un schema sync (force rebuild au prochain appel)."""
    global _search_indexes, _fk_graph
    _search_indexes = None
    _fk_graph = None
    # Aussi invalider l'exploration guard (les conversations doivent re-explorer)
    try:
        from app.services.ai.agent_service import get_iris_agent

        agent = get_iris_agent()
        agent._explored_conversations.clear()
    except Exception:
        pass  # Agent pas encore initialisé
    logger.info("Search indexes, FK graph, and exploration cache invalidated")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compute_column_stats(rows_data: list[dict], columns: list[str]) -> dict[str, dict]:
    """Compute per-column statistics from the FULL result set (not obfuscated).

    Returns metadata the agent can use to reason about data shape without
    seeing actual values. This is confidentiality-safe because it only exposes
    structural information (counts, ranges for dates/numbers, lengths for strings).
    """
    from datetime import datetime, date

    stats: dict[str, dict] = {}
    if not rows_data or not columns:
        return stats

    total = len(rows_data)

    for col in columns:
        values = [row.get(col) for row in rows_data]
        non_null = [v for v in values if v is not None]
        null_count = total - len(non_null)

        col_stat: dict[str, Any] = {
            "total_rows": total,
            "null_count": null_count,
            "non_null_count": len(non_null),
        }

        if non_null:
            # Detect column type from actual values
            sample = non_null[0]

            if isinstance(sample, (int, float)):
                numeric_vals = [v for v in non_null if isinstance(v, (int, float))]
                if numeric_vals:
                    col_stat["type"] = "numeric"
                    # min/max numériques NON exposés (confidentialité — montants sensibles)
                    col_stat["distinct_count"] = len(set(numeric_vals))

            elif isinstance(sample, (datetime, date)):
                date_vals = [v for v in non_null if isinstance(v, (datetime, date))]
                if date_vals:
                    col_stat["type"] = "date"
                    col_stat["min_value"] = str(min(date_vals))
                    col_stat["max_value"] = str(max(date_vals))
                    col_stat["distinct_count"] = len(set(str(d) for d in date_vals))

            elif isinstance(sample, str):
                str_vals = [v for v in non_null if isinstance(v, str)]
                if str_vals:
                    col_stat["type"] = "string"
                    col_stat["distinct_count"] = len(set(str_vals))
                    lengths = [len(s) for s in str_vals]
                    col_stat["min_length"] = min(lengths)
                    col_stat["max_length"] = max(lengths)

            else:
                col_stat["type"] = "other"
                col_stat["distinct_count"] = len(set(str(v) for v in non_null))
        else:
            col_stat["type"] = "all_null"
            col_stat["distinct_count"] = 0

        stats[col] = col_stat

    return stats


async def _enrich_columns_with_roles(
    result: Dict[str, Any], table_name: str, *, user: Any = None
) -> None:
    """Enrich column metadata with documented semantic roles from training store.

    Adds ``documented_role`` (str or None) to each column dict and a
    ``semantic_warning`` to the result if any columns lack documentation.
    Runs a lightweight SQLite query — safe to call on every introspect (even cached).

    **Phase α.1.bis.suite (#119)** — ``user`` propagé à
    ``get_enrichment_for_tables`` pour defense-in-depth : si l'enforcer
    amont a un bug et ``table_name`` est denied pour ce user, le filtre
    dans la méthode source retire l'entry du résultat avant retour.
    """
    columns = result.get("columns")
    if not columns:
        return

    try:
        from app.services.ai.training_store import get_training_store

        ts = get_training_store()
        enrichment = await ts.get_enrichment_for_tables([table_name], user=user)
        column_roles = enrichment.get(table_name, {}).get("column_roles", {})
    except Exception as exc:
        logger.warning(
            "introspect_table: enrichment lookup failed for %s: %s",
            table_name,
            exc,
        )
        column_roles = {}

    undocumented_count = 0
    for col in columns:
        role = column_roles.get(col["name"])
        col["documented_role"] = role  # str or None
        if not role:
            undocumented_count += 1

    if undocumented_count > 0:
        result["semantic_warning"] = (
            f"{undocumented_count} colonne(s) sans sémantique documentée. "
            f"Pour ces colonnes, ne PAS deviner la signification à partir "
            f"du nom — utilise search_documentation ou demande à l'utilisateur."
        )
    else:
        result.pop("semantic_warning", None)


# Longueur minimale d'un nom d'alias reconnu comme acknowledgment de rôle.
# 3 caractères : évite les faux positifs sur des bigrammes qui apparaissent
# dans la prose (ex: "pc" dans "pc portable"). Les alias SQL naturellement
# générés par view_miner font 4-5 chars (Dos01, Alpha02, etc.).
MIN_RULE_ALIAS_LEN = 3

# Regex : extrait les alias SQL cités via `alias \`Xxx\`` dans une règle
# business_context. Template défini dans view_miner. Backtick + quantifier
# borné → pas de ReDoS.
_RULE_ALIAS_RE = re.compile(
    rf"alias\s+`([A-Za-z_][A-Za-z0-9_]{{{MIN_RULE_ALIAS_LEN - 1},}})`",
    re.IGNORECASE,
)

# Regex fallback : pour les records `view_mining:*` générés AVANT l'ajout
# du champ `primary_table` (legacy), on extrait la table ambiguë depuis
# le contenu. Le template view_miner commence systématiquement par
# « La table `<Nom>` est référencée N fois dans `<vue>` ... ».
_LEGACY_PRIMARY_RE = re.compile(
    r"La table\s+`([A-Za-z_][A-Za-z0-9_]+)`\s+est référencée",
    re.IGNORECASE,
)


def populate_coexistent_rule_tracker(context: Dict[str, Any], docs: List[Dict[str, Any]]) -> None:
    """Peuple `context["_coexistent_rule_tables"]` à partir d'une liste de
    business_context docs.

    Single source of truth : appelé depuis agent_service (à chaque tool_result)
    ET exploration_guard (à l'injection système). Garantit que les deux chemins
    d'alimentation du tracker appliquent la même logique.

    Scope resserré (design v3) — le tracker n'accepte QUE les docs qui décrivent
    une **ambiguïté de rôle réelle** (detector `multiple_aliases`), pas les docs
    informationnelles (`column_alias`, `fk_suffix`, `cooccurrence`). Critère
    d'admission, par ordre de confiance :

      1. `doc["primary_table"]` présent → multiple_aliases post-v2, ACCEPTÉ.
      2. ``content`` matche le template ``La table `X` est référencée …`` →
         multiple_aliases pre-v2 (legacy sans champ primary_table), ACCEPTÉ.
      3. Record non-`view_mining:` avec `tags_tables` + priority ≥ seuil →
         record manuel/admin, fallback ACCEPTÉ (loguer pour traçabilité).
      4. Sinon → REJETÉ (column_alias récent, fk_suffix, etc.).

    Sans ce filtrage, les docs `column_alias` (révélation d'alias dans une vue,
    pas d'ambiguïté) polluaient le tracker et le guard firing sur toute table
    touchée — cf. field test 2026-04-15 où Factures bloquait un simple COUNT.

    Les noms d'alias extraits du contenu vont dans `_coexistent_rule_aliases`
    pour que le guard accepte ces noms comme justification valide. L'extraction
    d'alias reste inconditionnelle (utile même pour les records rejetés).

    Générique : aucun nom de table/domaine hardcodé. Fail-closed via try/except.
    """
    try:
        if not docs or not isinstance(context, dict):
            return
        # Defensive init : si quelqu'un (test, sérialisation, bug amont) a
        # pré-rempli la clé avec un type incompatible (list au lieu de dict/set),
        # `setdefault` ne re-wraps pas → `tracker.setdefault(...)` ou
        # `aliases_set.add(...)` crasherait plus bas et serait avalé par
        # le try/except global → tracker silencieusement jamais peuplé.
        # On reset explicitement au bon type pour éviter cette régression
        # invisible (adversarial review A2).
        tracker = context.get("_coexistent_rule_tables")
        if not isinstance(tracker, dict):
            tracker = {}
            context["_coexistent_rule_tables"] = tracker
        aliases_set = context.get("_coexistent_rule_aliases")
        if not isinstance(aliases_set, set):
            aliases_set = set()
            context["_coexistent_rule_aliases"] = aliases_set
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            content = doc.get("content") or ""

            # Extraction d'alias — toujours tenter, indépendamment de
            # l'admission au tracker (les alias d'un column_alias restent
            # des acknowledgments valides si le guard fire sur une autre
            # rule de la même table).
            for match in _RULE_ALIAS_RE.findall(content):
                if match and len(match) >= MIN_RULE_ALIAS_LEN:
                    aliases_set.add(match)

            try:
                priority = int(doc.get("priority", 0) or 0)
            except (TypeError, ValueError):
                continue
            if priority < CRITICAL_BC_PRIORITY_THRESHOLD:
                continue
            rule_id = doc.get("id")

            # (1) primary_table explicite → multiple_aliases post-v2
            primary_raw = doc.get("primary_table")
            primary = str(primary_raw).strip() if primary_raw else ""

            # (2) Legacy multiple_aliases : template « La table `X` est
            # référencée N fois dans `view` » — déterministe, pré-v2.
            if not primary:
                m = _LEGACY_PRIMARY_RE.search(content)
                if m:
                    primary = m.group(1).strip()

            if primary:
                scope_tables = [primary.upper()]
            else:
                # (3) Fallback manuel : records admin-override non
                # `view_mining:*` — les records `view_mining:*` sans
                # primary/template sont nécessairement non-multiple_aliases
                # (column_alias, fk_suffix, cooccurrence) et NE doivent
                # PAS entrer dans le tracker, même si leur priorité a été
                # élevée par `_derive_priority_from_source`.
                source = str(doc.get("source") or "")
                if source.startswith(VIEW_MINING_SOURCE_PREFIX):
                    continue  # (4) Rejet : non-multiple_aliases récent
                tags_tables_raw = doc.get("tags_tables") or []
                if not tags_tables_raw:
                    continue  # Record manuel sans tags → inexploitable
                scope_tables = [
                    str(t).strip().upper() for t in tags_tables_raw if t and str(t).strip()
                ]
                logger.debug(
                    "populate_coexistent_rule_tracker: manual record "
                    "accepted via tags_tables fallback — rule_id=%s "
                    "source=%s",
                    rule_id,
                    source,
                )
            for table_up in scope_tables:
                if not table_up:
                    continue
                rules_set = tracker.setdefault(table_up, set())
                if rule_id is not None:
                    rules_set.add(rule_id)
    except Exception as exc:
        # Escalé de debug→warning (adversarial review A6) : un crash ici rend
        # le guard silencieux sur toute la session — pire qu'un crash visible.
        logger.warning(
            "populate_coexistent_rule_tracker: skipped (%s)",
            exc,
            exc_info=True,
        )


async def _attach_business_context(
    result: Dict[str, Any],
    tables: List[str],
    token_budget: int = 800,
) -> None:
    """Attache les business_context pertinents au résultat d'un tool.

    Déclenchement = présence d'au moins une table dans `tables` qui est taguée
    dans une doc business_context active. Pas de keyword match.

    Fail-closed : toute exception → on retire silencieusement le champ
    (jamais de propagation, jamais de plantage de l'outil).

    Args:
        result: dict retourné par le tool (muté in-place).
        tables: liste de noms de tables à matcher (case-insensitive).
        token_budget: budget tokens alloué à l'injection (défaut 800).
    """
    if not tables:
        return
    try:
        from app.services.ai.training_store import get_training_store

        ts = get_training_store()
        docs = await ts.get_business_context_for_tables(tables, token_budget=token_budget)
        if docs:
            result["business_context"] = docs
            _inject_critical_rules_alert(result, docs)
        else:
            result.pop("business_context", None)
            result.pop("_critical_rules_alert", None)
    except Exception as exc:
        logger.debug("_attach_business_context: skipped (%s)", exc)
        result.pop("business_context", None)
        result.pop("_critical_rules_alert", None)


def _inject_critical_rules_alert(result: Dict[str, Any], docs: List[Dict[str, Any]]) -> None:
    """Insère une clé `_critical_rules_alert` en tête du dict résultat si au
    moins une règle business_context a une priority >= CRITICAL_BC_PRIORITY_THRESHOLD.

    Générique : pas de nom de table/colonne dans le texte, seulement des
    comptages et un pointeur vers le champ `business_context` plus bas.

    Placement : juste après les clés d'identité (`success`, `table_name`,
    `results`) pour maximiser la visibilité avant le gros bloc de colonnes.
    Fail-closed : toute exception → clé simplement absente.
    """
    try:
        critical = [
            d
            for d in (docs or [])
            if isinstance(d, dict)
            and int(d.get("priority", 0) or 0) >= CRITICAL_BC_PRIORITY_THRESHOLD
        ]
        if not critical:
            result.pop("_critical_rules_alert", None)
            return
        n = len(critical)
        alert = (
            f"\u26a0\ufe0f RÈGLES MÉTIER CRITIQUES DÉTECTÉES "
            f"({n} règle{'s' if n > 1 else ''} de priority "
            f"\u2265 {CRITICAL_BC_PRIORITY_THRESHOLD}). "
            f"Consulte le champ `business_context` ci-dessous AVANT de "
            f"construire le moindre SQL. Chaque règle critique exige un bloc "
            f"[ANALYSIS] explicite justifiant le rôle/alias choisi."
        )
        items = list(result.items())
        identity_keys = {"success", "table_name", "results"}
        insert_idx = 0
        while insert_idx < len(items) and items[insert_idx][0] in identity_keys:
            insert_idx += 1
        filtered = [(k, v) for k, v in items if k != "_critical_rules_alert"]
        insert_idx = min(insert_idx, len(filtered))
        new_items = (
            filtered[:insert_idx] + [("_critical_rules_alert", alert)] + filtered[insert_idx:]
        )
        result.clear()
        for k, v in new_items:
            result[k] = v
    except Exception as exc:
        logger.debug("_inject_critical_rules_alert: skipped (%s)", exc)
        result.pop("_critical_rules_alert", None)


def _decontextualize_rows(
    rows: List[Dict[str, Any]], columns: Optional[List[str]]
) -> List[List[Any]]:
    """Retourne les valeurs brutes sans noms de colonnes (liste de listes).

    Confidentialité niveau 3 : les valeurs sont transmises mais sans aucun
    contexte (pas de noms de colonnes, pas de nom de table).
    """
    result = []
    for row in rows:
        if columns:
            result.append([row.get(c) for c in columns])
        else:
            result.append(list(row.values()))
    return result


def _extract_alias_to_table(sql: str) -> Dict[str, str]:
    """Extrait le mapping alias → nom de table depuis le SQL.

    Ex: 'FROM Orders o' → {'O': 'ORDERS'}
        'JOIN Customers c ON' → {'C': 'CUSTOMERS'}
    """
    # Supprimer les commentaires SQL (defense-in-depth)
    sql = re.sub(r"--[^\n]*", "", sql)
    sql = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)

    mapping: Dict[str, str] = {}
    # Pattern: FROM/JOIN TableName AliasName (alias sans mot-clé après)
    pattern = re.compile(
        r"\b(?:FROM|JOIN)\s+(?:(?:\[?\w+\]?\.){0,2})\[?(\w+)\]?\s+(?:AS\s+)?\[?(\w+)\]?",
        re.IGNORECASE,
    )
    for match in pattern.finditer(sql):
        table = match.group(1).upper()
        alias = match.group(2).upper()
        # Ignorer si l'alias est un mot-clé SQL
        if alias not in {
            "ON",
            "WHERE",
            "AND",
            "OR",
            "SET",
            "AS",
            "INNER",
            "LEFT",
            "RIGHT",
            "FULL",
            "CROSS",
            "OUTER",
            "JOIN",
            "GROUP",
            "ORDER",
            "HAVING",
            "UNION",
            "EXCEPT",
            "INTERSECT",
            "WITH",
            "INTO",
            "VALUES",
        }:
            mapping[alias] = table
    return mapping


def _extract_columns_from_sql(sql: str) -> Dict[str, Set[str]]:
    """Extrait les colonnes utilisées dans une requête SQL, groupées par alias de table.

    Retourne un dict {ALIAS_OU_TABLE: {COL1, COL2, ...}}.
    Les colonnes sans alias sont groupées sous la clé "_UNQUALIFIED".
    """
    result: Dict[str, Set[str]] = {}

    # Supprimer les commentaires SQL AVANT d'extraire les identifiants.
    # Sans ça, les mots français des commentaires (-- Filtre sur l'entité XYZ)
    # sont parsés comme des noms de colonnes → faux positifs massifs.
    sql = re.sub(r"--[^\n]*", "", sql)  # commentaires single-line
    sql = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)  # commentaires block

    # Pattern pour alias.colonne (le plus fiable)
    alias_col_pattern = re.compile(r"\b(\w+)\.(\w+)\b")
    qualified_cols: Set[str] = set()  # track pour ne pas les compter 2 fois
    for match in alias_col_pattern.finditer(sql):
        alias = match.group(1).upper()
        col = match.group(2).upper()
        # Filtrer les mots-clés SQL, schémas et noms de table évidents
        if col in {"DBO", "VALUE", "VALUES", "NULL", "TRUE", "FALSE"}:
            continue
        if alias in {"DBO"}:
            continue
        result.setdefault(alias, set()).add(col)
        qualified_cols.add(col)

    # Extraire aussi les colonnes NON qualifiées (sans alias.prefix)
    # Pour les requêtes simples (SELECT col FROM Table), la validation pré-vol
    # doit pouvoir vérifier que col existe dans Table.
    _SQL_NOISE = {
        "SELECT",
        "FROM",
        "WHERE",
        "AND",
        "OR",
        "NOT",
        "IN",
        "IS",
        "BETWEEN",
        "LIKE",
        "EXISTS",
        "CASE",
        "WHEN",
        "THEN",
        "ELSE",
        "END",
        "AS",
        "ON",
        "TOP",
        "DISTINCT",
        "ALL",
        "BY",
        "ASC",
        "DESC",
        "NULL",
        "INNER",
        "LEFT",
        "RIGHT",
        "FULL",
        "OUTER",
        "CROSS",
        "JOIN",
        "GROUP",
        "ORDER",
        "HAVING",
        "UNION",
        "EXCEPT",
        "INTERSECT",
        "WITH",
        "INTO",
        "VALUES",
        "SET",
        "TRUE",
        "FALSE",
        "SUM",
        "COUNT",
        "AVG",
        "MIN",
        "MAX",
        "ISNULL",
        "COALESCE",
        "CAST",
        "CONVERT",
        "YEAR",
        "MONTH",
        "DAY",
        "DATEPART",
        "DATEDIFF",
        "GETDATE",
        "LEN",
        "SUBSTRING",
        "REPLACE",
        "LTRIM",
        "RTRIM",
        "TRIM",
        "UPPER",
        "LOWER",
        "CONCAT",
        "ROW_NUMBER",
        "RANK",
        "DENSE_RANK",
        "OVER",
        "PARTITION",
        "FORMAT",
        "STUFF",
        "CHARINDEX",
        "PATINDEX",
        "ROUND",
        "ABS",
        "CEILING",
        "FLOOR",
        "SIGN",
        "POWER",
        "SQRT",
        "NEWID",
        "STRING_AGG",
        "IIF",
        "NULLIF",
        "DATEADD",
        "DATENAME",
        "EOMONTH",
        "DATEFROMPARTS",
        "SYSDATETIME",
        "INT",
        "FLOAT",
        "REAL",
        "DECIMAL",
        "NUMERIC",
        "VARCHAR",
        "NVARCHAR",
        "CHAR",
        "NCHAR",
        "DATETIME",
        "DATE",
        "BIT",
        "BIGINT",
        "SMALLINT",
        "TINYINT",
        "MONEY",
        "SMALLMONEY",
        "TEXT",
        "NTEXT",
        "IMAGE",
        "UNIQUEIDENTIFIER",
        "XML",
    }

    # Extraire les noms de tables et les alias-AS pour les exclure
    _table_pattern = re.compile(
        r"\b(?:FROM|JOIN)\s+(?:(?:\[?\w+\]?\.){0,2})\[?(\w+)\]?", re.IGNORECASE
    )
    table_names = {m.group(1).upper() for m in _table_pattern.finditer(sql)}

    # Capturer les aliases AS (avec ou sans crochets/guillemets)
    # AS montant_total, AS [Rang], AS [N° Facture], AS "Client"
    # Le \b final ne s'applique qu'à la branche (\w+) : pour les branches
    # quotees [..] et "..", le delimiteur de fin (] ou ") est non-word, donc
    # \b apres lui exigeait un word-char a droite (echec sur "],", "] FROM",
    # EOL). Resultat : alias entre crochets jamais captures, leurs mots
    # remontaient ensuite comme colonnes inexistantes (faux positif).
    _as_alias_pattern = re.compile(r"\bAS\s+(?:\[([^\]]+)\]|\"([^\"]+)\"|(\w+)\b)", re.IGNORECASE)
    as_aliases = set()
    for m in _as_alias_pattern.finditer(sql):
        alias = (m.group(1) or m.group(2) or m.group(3) or "").upper()
        if alias:
            as_aliases.add(alias)
            # Aussi ajouter chaque MOT de l'alias (pour [N° Facture] → FACTURE, FACTURÉ)
            for word in re.findall(r"\w+", alias):
                as_aliases.add(word.upper())

    # Match standalone identifiers (not preceded/followed by dot)
    unqualified_pattern = re.compile(r"(?<!\.)(?<!\w)\b([a-zA-Z]\w{2,})\b(?!\.)")
    for match in unqualified_pattern.finditer(sql):
        word = match.group(1).upper()
        if word in _SQL_NOISE or word in qualified_cols:
            continue
        if word in table_names or word in as_aliases:
            continue
        # Skip string literals (word inside quotes) — handle '' escaping
        pos = match.start()
        in_string = False
        i = 0
        while i < pos and i < len(sql):
            if sql[i] == "'":
                in_string = not in_string
                i = skip_sql_string(sql, i)
            else:
                i += 1
        if in_string:
            continue
        result.setdefault("_UNQUALIFIED", set()).add(word)

    return result


# Tables système qui n'ont pas besoin de validation/introspection
_SYSTEM_TABLE_PREFIXES = ("SYS.", "INFORMATION_SCHEMA", "TEMPDB.", "MSDB.", "MASTER.", "#")
# Noms courts de tables système (le parseur supprime le schéma)
_SYSTEM_SHORT_NAMES = {
    "COLUMNS",
    "TABLES",
    "VIEWS",
    "ROUTINES",
    "SCHEMATA",
    "TABLE_CONSTRAINTS",
    "KEY_COLUMN_USAGE",
    "CONSTRAINT_COLUMN_USAGE",
    "REFERENTIAL_CONSTRAINTS",
    "CHECK_CONSTRAINTS",
    "COLUMN_DOMAIN_USAGE",
}


def _fuzzy_match_table(unknown: str, known_tables: Set[str]) -> Optional[str]:
    """Trouve la table connue la plus proche d'un nom inconnu (similarité).

    Retourne le meilleur match si la similarité SequenceMatcher ≥ 80%,
    sinon None. Couvre les typos fréquents du LLM : pluriel,
    suffixe manquant, casse, etc.
    """
    from difflib import get_close_matches

    unknown_lower = unknown.lower()
    # Index lowercase → original pour retrouver le nom exact
    lower_to_original = {t.lower(): t for t in known_tables}

    matches = get_close_matches(unknown_lower, lower_to_original.keys(), n=1, cutoff=0.80)
    if matches:
        return lower_to_original[matches[0]]
    return None


def _extract_real_tables_from_sql(sql: str) -> Set[str]:
    """Extract real table names from SQL, excluding CTEs, subqueries, and system tables.

    Strips comments and uses SQLValidator to extract tables, then filters out
    CTEs, subquery aliases, and known system tables.
    """
    from app.services.ai.sql_validator import SQLValidator

    # Strip comments
    clean_sql = re.sub(r"--[^\n]*", "", sql)
    clean_sql = re.sub(r"/\*.*?\*/", "", clean_sql, flags=re.DOTALL)

    validator = SQLValidator()
    tables_in_query = validator.extract_tables_from_sql_text(clean_sql)
    cte_names = validator._extract_cte_names(clean_sql)
    subquery_aliases = validator._extract_subquery_aliases(clean_sql)
    real_tables = tables_in_query - cte_names - subquery_aliases

    # Filter system tables
    return {
        t
        for t in real_tables
        if not any(t.upper().startswith(p) for p in _SYSTEM_TABLE_PREFIXES)
        and t.upper() not in _SYSTEM_SHORT_NAMES
    }


# Regex T-SQL : strip des hints `WITH (NOLOCK)`, `WITH (ROWLOCK)`, etc.
# AVANT le parse sqlglot pour éviter les échecs silencieux (adversarial B1).
# Matche `WITH` suivi d'une parenthèse contenant des mots-clés simples.
# Ne match PAS `WITH name AS (...)` (CTE : un mot obligatoire avant `AS`).
_TSQL_HINT_RE = re.compile(
    r"\bWITH\s*\(\s*[A-Za-z_][A-Za-z0-9_,\s]*\)",
    re.IGNORECASE,
)


def _tables_in_select_scope(select, cte_names: Set[str]) -> Dict[str, List[str]]:
    """Extrait {TABLE → [alias, ...]} des tables RÉFÉRENCÉES directement par
    la clause FROM + JOINs de CE SELECT (sans descendre dans les sous-requêtes,
    UNION branches, ou autres SELECT nichés).

    Critique pour le scoping : sans cette isolation, un scalar subquery
    `SELECT (SELECT FROM T) FROM T x` compterait T deux fois et firerait
    le guard à tort (adversarial B7). Même pattern pour UNION (B6).
    """
    try:
        from sqlglot import exp
    except ImportError:
        return {}
    scope: Dict[str, List[str]] = {}

    def _record(tbl) -> None:
        if not isinstance(tbl, exp.Table):
            return
        name = (getattr(tbl, "name", None) or "").strip()
        if not name:
            return
        name_up = name.upper()
        if name_up in cte_names:
            return
        alias = (getattr(tbl, "alias_or_name", None) or name).strip()
        if not alias:
            return
        aliases_list = scope.setdefault(name_up, [])
        # Append CHAQUE occurrence (sans dédupe) pour que le count reflète
        # les self-joins réels (comma joins `FROM T a, T b` → [a, b], len=2)
        # plutôt que les aliases uniques. Adversarial B2 + B8.
        aliases_list.append(alias)

    # FROM : sqlglot nomme la clé `from_` (suffix underscore, `from` étant
    # un mot réservé Python). On utilise `find(exp.From, bfs=True)` avec
    # limite de profondeur = 1 pour rester au niveau du SELECT courant.
    # NOTE : `args.get("from_")` serait équivalent mais la convention
    # `from_` peut évoluer entre versions sqlglot. `find` est plus stable.
    from_clause = select.args.get("from_") or select.args.get("from")
    if from_clause is not None:
        _record(from_clause.this)

    # JOINs (inclut les comma joins que sqlglot normalise en CROSS JOIN).
    for join in select.args.get("joins") or []:
        target = getattr(join, "this", None)
        _record(target)

    return scope


def extract_table_aliases(sql: str) -> Dict[str, List[str]]:
    """Retourne `{TABLE_UPPER → [alias, ...]}` depuis le texte SQL.

    Usage : détecter les self-joins pour le guard coexistent_role_not_justified.
    Si `len(result[table]) >= 2`, la table est référencée ≥ 2 fois dans un
    MÊME SELECT (FROM + JOINs) → self-join avéré → ambiguïté de rôle réelle.

    Scoping par SELECT (adversarial B6/B7) : chaque `exp.Select` est traité
    comme un scope indépendant. Les références dans des sous-requêtes
    scalaires de projection et les branches UNION ne comptent PAS comme
    self-join avec le scope outer. Seule la référence multiple dans UN
    SEUL scope constitue un self-join.

    Cas couverts :
      - `FROM T a JOIN T b` → self-join (scope unique, 2 refs). Fire.
      - `FROM T a, T b` (comma join implicite) → self-join. Fire.
      - `FROM T a WHERE EXISTS (SELECT 1 FROM T b)` → outer scope 1,
        inner scope 1. MAX = 1. Pas de fire. (correct : EXISTS filtre, pas JOIN)
      - `SELECT (SELECT FROM T) FROM T x` → scalar subquery. Pas de fire.
      - `SELECT FROM T a UNION SELECT FROM T b` → 2 scopes. Pas de fire.
      - `WITH cte AS (SELECT FROM T a JOIN T b …)` → le self-join DANS la
        CTE est détecté (la CTE a son propre exp.Select). Fire.

    Hint T-SQL stripping (adversarial B1) : `WITH (NOLOCK)` et consorts
    sont retirés AVANT parse pour éviter les échecs silencieux sur SQL
    Server. sqlglot gère bien la plupart, mais fail-closed via `return {}`
    transforme tout échec en "pass silencieux" — on préfère parser plus
    de SQL que pas assez.

    Fail-closed : SQL invalide ou erreur parser → `{}`. Conséquence :
    le guard ne fire pas sur du SQL non parsable. Acceptable car SQL
    Server refusera d'exécuter → l'utilisateur voit l'erreur.

    Générique : aucun nom de table/domaine hardcodé.
    """
    if not sql or not isinstance(sql, str):
        return {}
    clean = sql
    try:
        # Strip T-SQL hints pour éviter les surprises de parsing.
        clean = _TSQL_HINT_RE.sub("", clean)
        # Strip commentaires SQL (sqlglot les ignore mais autant être explicite).
        clean = re.sub(r"--[^\n]*", "", clean)
        clean = re.sub(r"/\*.*?\*/", "", clean, flags=re.DOTALL)
    except re.error:
        return {}
    try:
        import sqlglot
        from sqlglot import exp

        parsed = sqlglot.parse_one(clean, dialect="tsql")
    except Exception:
        return {}
    if parsed is None:
        return {}

    # CTE names → référencés dans le outer SELECT comme exp.Table, à exclure
    # (pas des tables réelles). Si un CTE porte le nom d'une vraie table,
    # le comportement SQL est que FROM <name> résout vers la CTE — donc
    # l'outer query ne touche PAS la vraie table. Pas de self-join sur elle.
    cte_names: Set[str] = set()
    try:
        for cte in parsed.find_all(exp.CTE):
            cte_alias = getattr(cte, "alias_or_name", None)
            if cte_alias:
                cte_names.add(cte_alias.upper())
    except Exception:
        pass

    # Pour chaque SELECT, calcule son scope isolé (FROM + JOINs directs).
    # Retient le MAX d'occurrences par table à travers tous les scopes :
    # si N'IMPORTE QUEL SELECT a un self-join sur T, T apparaît avec len≥2.
    max_occurrences: Dict[str, List[str]] = {}
    try:
        for select in parsed.find_all(exp.Select):
            scope_aliases = _tables_in_select_scope(select, cte_names)
            for tbl, occurrences in scope_aliases.items():
                if len(occurrences) > len(max_occurrences.get(tbl, [])):
                    max_occurrences[tbl] = occurrences
    except Exception:
        return {}
    return max_occurrences


async def _validate_sql_columns(
    sql: str,
    user: Any = None,
    marker_out: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """**LEGACY WRAPPER (2026-05-26)** — délègue à ``sql_validator.validate_for_iris``.

    L'ancienne implémentation (~400 lignes) avait un parser maison avec une
    liste fermée ``sql_keywords`` qui contenait YEAR/MONTH/DAY mais oubliait
    MINUTE/HOUR/SECOND/MILLISECOND/WEEK/QUARTER. Conséquence : ``DATEDIFF(MINUTE,
    a, b)`` était rejeté à tort avec « MINUTE is not a valid column » → pattern
    « 2+2=4 » exact, motif légitime pour Iris de blâmer le système.

    Remplacement par l'oracle SQL Server lui-même (``SET PARSEONLY ON`` pour
    la syntaxe + ``SET FMTONLY ON`` pour le binding tables/colonnes, zero I/O).
    Le parser officiel SQL Server connaît à 100 % la grammaire T-SQL — pas de
    liste fermée à maintenir, pas de faux rejet sur les nouveautés.

    Signature conservée (``Optional[Dict]``) pour la compat des call sites
    (``_handle_execute_sql``, ``inspect_table_data``, ``create_report_from_sql``,
    ``copilot_iris_bridge.ask_iris``). Le dict retourné suit le format legacy
    ``{"success": False, "blocked_by": "<rule_id>", "error": "<message>", ...}``
    enrichi de la clé ``"proof"`` (structure complète inspectable par Iris).

    Comportement :
      - Si la BDD source est injoignable → en fail-open (défaut) retourne
        ``None`` MAIS pose ``marker_out["oracle_prevalidated"] = False`` si le
        caller a fourni un dict ``marker_out`` (out-param : la signature legacy
        ``Optional[Dict]`` ne peut pas porter le tri-state sans casser les
        call-sites). Les callers user-facing (``create_report``) DOIVENT
        fournir ``marker_out`` et propager le marqueur (contrat
        ``validate_for_iris`` : pas de contournement muet) ; en fail-closed
        (``ORACLE_FAIL_CLOSED=1``) le verdict revient ``passes=False``
        (``ORACLE_UNAVAILABLE``) → dict bloquant.
      - Si la validation passe → retourne ``None``.
      - Si la validation échoue → retourne le dict legacy + ``proof`` structuré.
      - **Non-autoritatif** : ce wrapper est un PRÉ-CHECK best-effort (fail-open
        sur BDD injoignable / crash du validator). La garde de sécurité
        AUTORITATIVE est ``execute_sql`` (fail-closed BLOCKING sur crash du
        validator, cf. son ``except`` plus bas) — ne JAMAIS supposer que passer
        ce pré-check suffit à rendre le SQL sûr à exécuter.
    """
    from app.services.ai.sql_validator import validate_for_iris
    from app.services.database.sage_connector import (
        SageConnectionError,
        get_sage_connector,
    )

    try:
        connector = get_sage_connector()
        verdict = await validate_for_iris(sql, user, connector)
    except SageConnectionError as exc:
        # Defense-in-depth (dead code attendu depuis 2026-06-12 : la politique
        # d'indisponibilité est centralisée DANS validate_for_iris).
        logger.warning("Sage unreachable during SQL validation (oracle skipped): %s", exc)
        if isinstance(marker_out, dict):
            marker_out["oracle_prevalidated"] = False
        return None
    except Exception as exc:  # noqa: BLE001
        # Defense-in-depth : si le validator unique lève une exception
        # imprévue (bug du validator lui-même), on log et fail-open pour ne
        # pas bloquer toute exécution d'Iris. La query partira sur SQL Server
        # qui jugera de sa validité.
        logger.error("validate_for_iris crashed unexpectedly (fail-open): %s", exc, exc_info=True)
        return None

    if verdict.passes:
        # Fail-open oracle injoignable : signaler au caller via l'out-param
        # (la valeur de retour None signifie « pas de blocage », pas
        # « pré-validé ») — cf. docstring « Comportement ».
        if (
            isinstance(marker_out, dict)
            and getattr(verdict, "oracle_validated", None) is False
        ):
            marker_out["oracle_prevalidated"] = False
        return None

    assert verdict.proof is not None
    return verdict.proof.to_tool_result()


def _compute_null_window(sql: str) -> int:
    """Fenêtre TOP pour le diagnostic NULL fill-rate (#18f verdict #30).

    Invariant CRITIQUE : ne RÉTRÉCIT JAMAIS la fenêtre originale.
    ``max(N, 1000)`` — un ``TOP 50000`` réduit à 1000 fausserait davantage
    les taux (échantillon plus petit = moins représentatif, et on
    présenterait un taux calculé sur 1000 lignes comme s'il portait sur la
    requête). Pas de ``TOP`` dans le SQL → 1000 par défaut.

    Pure (testable en isolation — garde d'EFFET, pas de présence source).
    """
    m = re.search(r"\bTOP\s+(\d+)\b", sql, flags=re.IGNORECASE)
    return max(int(m.group(1)) if m else 0, 1000)


def _build_sample_warning(sql: str, rows_data: list[dict], columns: list[str]) -> str | None:
    """
    Build a warning string when a TOP N query returns potentially misleading results.

    Detects:
    - TOP N without ORDER BY → arbitrary (non-representative) sample
    - Columns that are 100% NULL or >50% NULL in the sample

    Returns None if no warning is needed.
    """
    # Strip comments to avoid false matches
    sql_clean = re.sub(r"--[^\n]*", "", sql)
    sql_clean = re.sub(r"/\*.*?\*/", "", sql_clean, flags=re.DOTALL)

    # Find the outermost SELECT TOP: skip CTEs and subqueries.
    # Strategy: walk through the SQL tracking parenthesis depth.
    # Only match SELECT TOP at depth 0, and skip CTE WITH blocks.
    # For CTEs: the main query starts after the last `)` that closes
    # a CTE block at depth 0.
    stripped = sql_clean.strip()
    if re.match(r"\bWITH\b", stripped, re.IGNORECASE):
        # Has CTE — find the balanced closing paren at depth 0,
        # then look for SELECT after it.
        depth = 0
        main_start = 0
        for m in re.finditer(r"[()]", stripped):
            if m.group() == "(":
                depth += 1
            else:
                depth -= 1
                if depth == 0:
                    main_start = m.end()
        main_clause = stripped[main_start:]
    else:
        main_clause = stripped

    # Now find SELECT TOP at depth 0 in main_clause (skip subqueries)
    depth = 0
    top_match = None
    for m in re.finditer(r"[()]|\bSELECT\s+TOP\s+(\d+)\b", main_clause, re.IGNORECASE):
        tok = m.group()
        if tok == "(":
            depth += 1
        elif tok == ")":
            depth -= 1
        elif depth == 0 and m.group(1):
            top_match = m
            break
    if not top_match:
        return None

    top_n = int(top_match.group(1))
    if top_n == 0:
        return None

    # Check ORDER BY at top-level only (not inside parenthesized subqueries)
    depth = 0
    has_order_by = False
    for m in re.finditer(r"[()]|\bORDER\s+BY\b", main_clause, re.IGNORECASE):
        if m.group() == "(":
            depth += 1
        elif m.group() == ")":
            depth -= 1
        elif depth == 0:
            has_order_by = True

    warnings: list[str] = []

    if not has_order_by:
        warnings.append(
            f"[Note système] Échantillon arbitraire : TOP {top_n} sans ORDER BY — "
            f"les lignes retournées ne sont pas représentatives de la table. "
        )

    # Detect columns with lots of NULLs in the sample
    if rows_data:
        null_cols: list[str] = []
        for col_name in columns:
            null_count = sum(1 for row in rows_data if row.get(col_name) is None)
            if null_count == len(rows_data) and len(rows_data) >= 2:
                null_cols.append(col_name)
            elif null_count > len(rows_data) * 0.5 and len(rows_data) >= 5:
                null_cols.append(f"{col_name} ({null_count}/{len(rows_data)} NULL)")

        if null_cols:
            warnings.append(
                f"[Note système] Les colonnes {', '.join(null_cols)} sont NULL dans "
                f"cet échantillon de {len(rows_data)} lignes — ça ne signifie pas "
                f"qu'elles sont NULL dans toute la table."
            )

    # Detect duplicate rows (potential cartesian product)
    if rows_data and len(rows_data) >= 3:
        # Compare non-ID columns for duplicates
        value_cols = [c for c in columns if not c.lower().endswith(("noenreg", "id", "noEnreg"))]
        if value_cols:
            row_fingerprints = []
            for row in rows_data:
                fp = tuple(row.get(c) for c in value_cols)
                row_fingerprints.append(fp)
            unique_fps = set(row_fingerprints)
            dup_ratio = 1 - (len(unique_fps) / len(row_fingerprints))
            # Seuil à 0.7 (70%) et min 8 lignes pour éviter les faux positifs :
            # les vues avec plusieurs lignes par dossier (1-N) ont naturellement
            # ~50-60% de "doublons" sur les colonnes non-ID. Seuls les vrais
            # produits cartésiens (>70%) méritent un avertissement.
            if dup_ratio > 0.7 and len(row_fingerprints) >= 8:
                warnings.append(
                    f"[Note système] Doublons : {int(dup_ratio * 100)}% des lignes "
                    f"ont des valeurs identiques. Possible produit cartésien "
                    f"(JOIN 1-N qui multiplie les lignes). "
                    f"Vérifie que chaque JOIN est sur la bonne colonne et que la "
                    f"cardinalité est 1-1 ou N-1, pas N-M."
                )

    return " ".join(warnings) if warnings else None


# ══════════════════════════════════════════════════════════════════════
# Self-critique rotatif (P1.2)
# ══════════════════════════════════════════════════════════════════════
# Pool de questions qu'un DBA senior se pose APRÈS avoir livré une requête.
# Aucune question ne dicte de structure de réponse ni de nom de colonne —
# chacune invite à remettre en question une hypothèse implicite de la
# requête. Sélection rotative déterministe par hash (sql + question user)
# pour que :
#   - Les questions varient au fil d'une conversation (évite la désensibilisation).
#   - Le même couple (sql, question) produise toujours la même question miroir
#     (reproductibilité des tests).
_SELF_CRITIQUE_POOL: tuple[str, ...] = (
    # Complétude de la traduction
    "Relis la demande utilisateur : chaque mot ou concept distinctif est-il "
    "traduit dans ta requête, OU son absence est-elle justifiée ?",
    # Préservation / élimination silencieuse
    "Chaque JOIN de ta requête : le type choisi préserve-t-il les lignes "
    "que l'utilisateur voudrait voir, ou en écarte-t-il silencieusement ?",
    # Rôle des colonnes de sortie
    "Chaque colonne retournée a-t-elle un rôle analytique clair (dimension, "
    "mesure, total superposé) ou y en a-t-il une redondante ou manquante "
    "par rapport à l'intention ?",
    # Robustesse temporelle
    "Si la même question était reposée demain avec une période différente, "
    "ton SQL resterait-il valide, ou contient-il une hypothèse qui "
    "casserait (table de périodes hardcodée, constante d'année, etc.) ?",
    # Plausibilité quantitative
    "Le nombre de lignes retournées est-il dans l'ordre de grandeur auquel "
    "tu t'attendrais pour cette question, ou un filtre trop restrictif a-t-il "
    "coupé trop (ou trop peu) ?",
    # Sensibilité des agrégats
    "Si ta requête contient un agrégat : les NULL, les signes (crédit/débit) "
    "et l'unité (TTC/HT, devise…) sont-ils traités cohéremment ?",
    # Convention métier implicite
    "Y a-t-il une convention métier que tu as supposée sans la vérifier "
    "(exercice calendaire vs fiscal, cumul vs instantané, actif vs tout "
    "confondu) — et si oui, l'as-tu mentionnée dans ta réponse ?",
    # Colonne jumelle
    "Les colonnes que tu as choisies ont-elles des jumelles au nom proche "
    "(brut/net, HT/TTC, interne/externe, signé/absolu) dont la sémantique "
    "différerait ? As-tu retenu la bonne ?",
)


def _pick_self_critique_question(*, sql: str, user_question: str) -> str:
    """Choisit une question du pool de façon déterministe.

    Hash stable (blake2b) sur ``sql + user_question`` → index dans le pool.
    Même entrée ⇒ même question (testable, reproductible). Entrées
    différentes ⇒ questions variées (évite la désensibilisation).
    """
    import hashlib

    seed = (str(sql or "") + "|" + str(user_question or "")).encode("utf-8")
    digest = hashlib.blake2b(seed, digest_size=4).hexdigest()
    idx = int(digest, 16) % len(_SELF_CRITIQUE_POOL)
    # Préfixer d'un marqueur pour que le LLM ne confonde pas avec une
    # instruction utilisateur.
    return (
        "[auto-critique — une seule question, à intégrer à ta réflexion "
        "avant la réponse finale] " + _SELF_CRITIQUE_POOL[idx]
    )


async def _maybe_auto_correct_sql(
    sql: str,
    error_msg: str,
    executor: Any,
    params: Optional[tuple],
    user: Any = None,
) -> Optional[Dict[str, Any]]:
    """Tente une auto-correction déterministe + validation dry-run (C26).

    Utilise la classification d'erreur + ``sql_auto_corrector`` (module
    programmatique, sans LLM). Si la correction produit un SQL valide au
    dry-run, retourne ``{corrected_sql, description, category}``. Sinon,
    retourne ``None`` (fallback vers le message d'erreur classique).

    Pas de LLM call → fonctionne quel que soit le provider configuré
    (Anthropic, OpenAI, autre). La correction est silencieuse pour le
    LLM parent mais tracée pour l'utilisateur final via le flag
    ``auto_corrected`` dans le result.

    Garde-fous :
    - 1 seule tentative (pas de boucle)
    - Validation obligatoire via dry-run TOP 1 avant d'accepter
    - Si ``auto_correct`` échoue ou ne change rien → ``None``
    - Si le nouveau SQL échoue aussi → ``None`` (le flux d'erreur
      classique reprend la main)
    """
    try:
        from app.services.ai.sql_error_taxonomy import classify_error
        from app.services.ai.sql_auto_corrector import (
            auto_correct,
            can_auto_correct,
        )
    except ImportError:
        return None

    try:
        classification = classify_error(error_msg, sql)
    except Exception:
        return None

    if not can_auto_correct(classification):
        return None

    try:
        correction = await auto_correct(sql, classification)
    except Exception as exc:
        logger.debug("Auto-correct failed: %s", exc)
        return None

    if not correction.corrected or correction.sql == sql:
        return None

    # Valider la correction via un dry-run TOP 1 silencieux.
    # Aligner le mode de limitation sur la logique du dry-run original :
    # si le SQL corrigé contient déjà un TOP (la correction peut l'ajouter),
    # on remplace le TOP par TOP 1 et on désactive ``add_limit`` — sinon
    # on laisse add_limit insérer un TOP 1. Sans cette bascule, un SQL
    # déjà-préfixé de TOP serait doublement limité et rejeté à tort par
    # le parser SQL Server.
    corrected_sql = correction.sql
    _has_existing_top = bool(
        re.search(r"\bTOP\s+\d+\b", corrected_sql, re.IGNORECASE),
    )
    if _has_existing_top:
        validation_sql = re.sub(
            r"\bTOP\s+\d+\b",
            "TOP 1",
            corrected_sql,
            count=1,
            flags=re.IGNORECASE,
        )
        validation_add_limit = False
    else:
        validation_sql = corrected_sql
        validation_add_limit = True

    try:
        await executor.execute(
            validation_sql,
            max_rows=1,
            add_limit=validation_add_limit,
            params=params,
            user=user,
            rls_source="agent_tools._maybe_auto_correct_sql.validation",
        )
    except Exception as validation_exc:
        logger.info(
            "Auto-correction validated failed (category=%s): %s — "
            "fallback vers message d'erreur LLM",
            correction.category,
            str(validation_exc)[:200],
        )
        return None

    logger.info(
        "Auto-correction applied and validated (category=%s): %s",
        correction.category,
        correction.description[:200],
    )
    return {
        "corrected_sql": corrected_sql,
        "description": correction.description,
        "category": correction.category,
        "original_sql": sql,
    }


def _classify_sql_error(error_msg: str) -> str:
    """Classify a SQL error into a safe hint for the LLM without leaking schema details."""
    msg = error_msg.lower()
    if ("arithmetic" in msg or "arithmétique" in msg or "dépassement" in msg) and (
        "overflow" in msg or "dépassement" in msg or "22003" in msg
    ):
        return (
            "DÉPASSEMENT ARITHMÉTIQUE — SUM/AVG sur une colonne numeric dépasse "
            "la capacité du type. SOLUTION : enveloppe chaque agrégation avec "
            "CAST(colonne AS DECIMAL(38,2)) AVANT le SUM, ex: "
            "SUM(CAST(maColonne AS DECIMAL(38,2))). "
            "NE PAS faire CAST(SUM(...)) car le SUM overflow avant le CAST."
        )
    if ("datetime" in msg or "22007" in msg or "hors limites" in msg) and (
        "conversion" in msg or "type" in msg
    ):
        return (
            "CONVERSION DATE ÉCHOUÉE — une colonne datetime est comparée à une "
            "chaîne de caractères dans un format ambigu. SOLUTIONS :\n"
            "1. Utilise introspect_table pour vérifier le type réel de la colonne "
            "(varchar stockant des dates ? datetime ? date ?)\n"
            "2. Si la colonne est datetime/date : utilise le format ISO sans tirets "
            "'YYYYMMDD' (ex: '20231001' au lieu de '2023-10-01') — c'est le SEUL "
            "format garanti sans ambiguïté dans SQL Server\n"
            "3. Si la colonne est varchar : utilise TRY_CONVERT(date, colonne, 120) "
            "pour la convertir explicitement\n"
            "4. Alternative : utilise CONVERT(date, 'YYYY-MM-DD', 120) pour les "
            "littéraux de date"
        )
    if "conversion" in msg or "cast" in msg or "type" in msg or "arithmetic" in msg:
        return "Erreur de type/conversion — une colonne a un type incompatible avec l'opération demandée. Vérifie les types avec introspect_table"
    if "invalid column" in msg or "colonne non valide" in msg:
        return "Colonne introuvable — utilise introspect_table pour vérifier les noms de colonnes exacts"
    if "invalid object" in msg or ("objet" in msg and "non valide" in msg):
        return "Table/vue introuvable — utilise get_database_schema pour voir les tables existantes. NE JAMAIS deviner un nom de table"
    if "syntax" in msg or "incorrect syntax" in msg or "syntaxe" in msg:
        return "Erreur de syntaxe SQL — vérifie la structure de ta requête (parenthèses, virgules, mots-clés)"
    if "seules les" in msg and "select" in msg and "autoris" in msg:
        return "Requête rejetée par le système — seules les requêtes SELECT sont autorisées (lecture seule)"
    if "null" in msg or "cannot insert" in msg:
        return "Erreur liée aux valeurs NULL — utilise ISNULL() ou COALESCE() dans le SELECT (pas le GROUP BY)"
    if "group by" in msg or "aggregate" in msg:
        return (
            "Erreur d'agrégation — toutes les colonnes non agrégées doivent être dans le GROUP BY"
        )
    if "timeout" in msg or "timed out" in msg:
        return "Requête trop lente (timeout) — simplifie ou ajoute des filtres WHERE"
    if "permission" in msg or "denied" in msg:
        return "Permission refusée — cette table/vue n'est pas accessible en lecture"
    if "ambiguous" in msg:
        return "Nom de colonne ambigu — ajoute un alias de table (ex: t.colonne au lieu de colonne)"
    return "Erreur SQL non classifiée — simplifie ta requête à SELECT TOP 5 pour isoler le problème"


# ---------------------------------------------------------------------------
# SQL Guards — enforcement programmatique (anciennement règles du prompt)
# ---------------------------------------------------------------------------
# Ces vérifications remplacent des instructions dans le system prompt par
# des verrous déterministes. Le code garantit le respect, le prompt non.
# ---------------------------------------------------------------------------

# R78: opérations d'écriture interdites (base en lecture seule)
_WRITE_PATTERN = re.compile(
    r"^\s*(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|EXEC|EXECUTE|MERGE)\b",
    re.IGNORECASE,
)

# R57: CAST(... AS FLOAT) interdit sur colonnes numeric/decimal
_CAST_FLOAT_PATTERN = re.compile(
    r"CAST\s*\([^)]+\s+AS\s+FLOAT\s*\)",
    re.IGNORECASE,
)

# R11 PII patterns : SUPPRIMÉS 2026-05-26 (T16-M4/M9, doctrine single source of truth).
# Les anciens `_PLACEHOLDER_PATTERN` + `_UNQUOTED_PLACEHOLDER_PATTERN` (orphans
# depuis le refactor T7.4 qui a converti `_enforce_sql_guards` en wrapper) sont
# remplacés par `_VALIDATOR_UNQUOTED_PLACEHOLDER_PATTERN` dans
# `app/services/ai/sql_validator.py` — single source de vérité pour les guards
# d'anti-injection PII. Toute nouvelle catégorie PII (NUMERO_SECU_N, etc.)
# se déclare DANS sql_validator.py.


def _normalize_sql_syntax(sql: str) -> Tuple[str, List[Dict[str, Any]]]:
    """Pré-traitement déterministe du SQL avant validation.

    Corrige les erreurs de syntaxe récurrentes des LLM :
    - LIMIT N (MySQL/PostgreSQL) → TOP N (SQL Server)

    **Provenance trail (2026-05-26, doctrine « 100 % justifié »)** : retourne
    aussi la liste des transformations appliquées (pour que la transparence
    soit visible côté tool_result et que Iris ne puisse jamais dire « le
    système a réécrit ma query silencieusement »).

    Returns:
        Tuple ``(sql_normalized, transformations)`` où ``transformations`` est
        une liste vide si aucune réécriture n'a été appliquée, ou une liste de
        dicts ``{"rule": "limit_to_top", "before": "LIMIT 20", "after": "TOP 20"}``.
    """
    transformations: List[Dict[str, Any]] = []

    # LIMIT N en fin de requête ou après WHERE/ORDER BY → SELECT TOP N
    # Pattern: "... LIMIT 20" en fin ou avant un ;
    limit_match = re.search(r"\bLIMIT\s+(\d+)\s*;?\s*$", sql, re.IGNORECASE)
    if limit_match:
        n = limit_match.group(1)
        before_fragment = limit_match.group(0).rstrip(";").strip()
        # Retirer le LIMIT
        sql = sql[: limit_match.start()].rstrip()
        # Ajouter TOP N après le premier SELECT (au niveau 0, pas dans les sous-requêtes)
        depth = 0
        for m in re.finditer(r"[()]|\bSELECT\b", sql, re.IGNORECASE):
            if m.group() == "(":
                depth += 1
            elif m.group() == ")":
                depth -= 1
            elif depth == 0:
                # Premier SELECT au niveau 0
                insert_pos = m.end()
                # Vérifier s'il y a déjà un TOP
                after = sql[insert_pos : insert_pos + 20].strip()
                if not re.match(r"TOP\s+\d+", after, re.IGNORECASE):
                    sql = sql[:insert_pos] + f" TOP {n}" + sql[insert_pos:]
                break
        logger.info("SQL syntax fix: LIMIT %s → TOP %s", n, n)
        transformations.append(
            {
                "rule": "limit_to_top",
                "rule_doc": (
                    "T-SQL n'accepte pas LIMIT — le système a remplacé par "
                    "SELECT [DISTINCT] TOP N à la position du SELECT principal."
                ),
                "before": before_fragment,
                "after": f"TOP {n}",
            }
        )

    return sql, transformations


def _enforce_sql_guards(sql: str) -> Optional[Dict[str, Any]]:
    """**LEGACY WRAPPER (2026-05-26)** — délègue à
    ``sql_validator._check_deterministic_guards``.

    Single source of truth pour les 3 gardes déterministes (read_only,
    system_table, unquoted_placeholder) = `_check_deterministic_guards`
    dans ``app/services/ai/sql_validator.py``. La logique inline qui était
    dupliquée ici est supprimée (doctrine 2026-05-26 « blocages 100 %
    justifiés » + élimination single source of truth).

    Returns:
        ``None`` si toutes les gardes passent.
        Un dict format legacy ``{"success": False, "blocked_by": "<rule_id>",
        "error": "<message>", "columns": [], "row_count": 0,
        "execution_time_ms": 0}`` sinon — avec en plus la clé ``"proof"``
        (structure complète inspectable par Iris).

    Conservé pour compat des tests directs (``tests/unit/test_agent_tools.py``
    `_enforce_sql_guards`*) et de tout caller externe éventuel. Les call
    sites internes de l'app (`_handle_execute_sql`, `_handle_test_sql`,
    `_handle_run_pipeline`) passent désormais par `validate_for_iris`
    directement et n'utilisent plus cette fonction.
    """
    from app.services.ai.sql_validator import (
        _check_deterministic_guards,
        _compute_sql_hash,
    )

    provenance: List[Dict[str, Any]] = []
    verdict = _check_deterministic_guards(sql, _compute_sql_hash(sql), provenance)
    if verdict.passes:
        return None
    assert verdict.proof is not None
    return verdict.proof.to_tool_result()


# ---------------------------------------------------------------------------
# Individual tool handlers
# ---------------------------------------------------------------------------


async def _handle_execute_sql(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """
    Execute a SELECT on the source SQL Server database.

    Results are stored in context["pending_results"] for the WebSocket layer to
    forward directly to the user. The agent only receives metadata.
    """
    # ── R24 Hard Gate : RETIRÉ 2026-05-25 ──
    # Voir git log. Le rappel "schéma à jour" est désormais un nudge soft
    # injecté en post-tool (cf. agent_service._enforce_post_tool_rules).

    # ── Task #99 REFONTE-L1 Hard Gate : RETIRÉ 2026-05-25 ──
    # Voir git log. execute_sql accepte désormais tout SELECT read-only,
    # y compris les SQL analytiques complexes (multi-CTE, STRING_AGG,
    # window, 3+ JOINs). `run_pipeline` reste recommandé pour ces cas
    # (cf. description IRIS_TOOLS.execute_sql + prompt) mais n'est plus
    # imposé par le runtime. Si le LLM hallucine la syntaxe T-SQL, le
    # SQL Server renvoie une erreur claire qui déclenche les nudges /
    # `deterministic_tool_failure` existants.

    # C26 — Isolation : reset ``_auto_corrections`` à chaque appel pour
    # que le flag du résultat ne fuite PAS d'une requête à l'autre. Sans
    # ce reset, une requête réussie qui suit une correction afficherait
    # à tort "une correction automatique a été appliquée" au user.
    if isinstance(context, dict):
        context.pop("_auto_corrections", None)

    sql: str = tool_input["sql"]
    explanation: str = tool_input.get("explanation", "")
    # Dé-anonymisation : l'explanation est transmise à l'UI dans l'event
    # sql_results et affichée à l'utilisateur. Le LLM peut avoir inclus
    # des fragments ~XXX. On restaure avant stockage dans pending_results.
    explanation = await _restore_for_user_safe(explanation)
    # 2026-05-20 : suppression du clamp hardcodé ``min(input, 1000)`` qui
    # ignorait le cap admin ``DatabaseConnection.max_rows`` (paramétrable
    # via /admin/database). Désormais : si le LLM fournit un max_rows
    # explicite, on le passe tel quel ; sinon ``None`` → le connector
    # applique automatiquement le cap admin (single source of truth).
    # Le connector fait ``min(caller, admin)`` donc impossible pour le
    # LLM de dépasser la config admin.
    raw_max_rows = tool_input.get("max_rows")
    try:
        max_rows: Optional[int] = int(raw_max_rows) if raw_max_rows is not None else None
    except (ValueError, TypeError):
        max_rows = None
    if isinstance(max_rows, int) and max_rows < 1:
        # Valeur aberrante d'un LLM (0, négatif) → fallback admin cap.
        max_rows = None

    # ── Pré-traitement syntax (LIMIT→TOP, etc.) ──────────────────────
    # **T16-C1 (2026-05-26)** : `_normalize_sql_syntax` est désormais
    # appliqué à l'intérieur de `validate_for_iris` (sql_validator.py)
    # pour éliminer l'asymétrie execute_sql vs test_sql. Le tracking
    # des transformations passe par `verdict.provenance` (extrait
    # ci-dessous APRÈS validate_for_iris pour exposer à l'extérieur
    # via context). L'appel inline ici est SUPPRIMÉ.

    # ── R57 cast_float (softening 2026-05-25) ──
    # Side effect : flag positionné AVANT le validator pour que le nudge
    # post-tool soit injecté même si la requête finit par échouer côté SQL.
    if _CAST_FLOAT_PATTERN.search(sql) and isinstance(context, dict):
        context["_cast_float_warning_pending"] = True

    # P4.3 — Mémoriser le SQL en cours pour que learn_insight puisse le
    # réutiliser en cas de validation ✅ utilisateur (capture exemplar).
    if isinstance(context, dict):
        context["_last_executed_sql"] = sql

    # ── Validator unique (doctrine 2026-05-26 « blocages 100 % justifiés ») ──
    # `validate_for_iris` combine en UN seul point d'entrée :
    #   1. Gardes déterministes : read_only / system_table / unquoted_placeholder
    #      (équivalent de l'ancien `_enforce_sql_guards`)
    #   2. RLS : `data_access_enforcer.enforce_sql` (transforme le SQL via
    #      row_filter si une règle s'applique, ou retourne `is_denied=True`)
    #   3. Oracle SQL Server : `SET PARSEONLY ON` + `SET FMTONLY ON` (syntaxe
    #      + binding tables/colonnes, zero I/O) — c'est l'oracle qui remplace
    #      le parser maison buggé `_validate_sql_columns` (cf. T6).
    #
    # Chaque rejet retourne un `Proof` structuré (rule_id, evidence, sql_server_says,
    # suggested_fix) qu'Iris peut inspecter — plus de message opaque type
    # « server_guard ». Cf. `app/services/ai/sql_validator.py:validate_for_iris`.
    from app.services.ai.sql_validator import validate_for_iris
    from app.services.database.sage_connector import (
        SageConnectionError,
        get_sage_connector,
    )

    try:
        _connector_for_validation = get_sage_connector()
        _verdict = await validate_for_iris(sql, user, _connector_for_validation)
    except SageConnectionError as _sage_exc:
        # Sage injoignable AU MOMENT de la validation — fail-open transitoire :
        # le path d'exécution ci-dessous tentera la vraie connexion qui retourne
        # l'erreur réseau au user via son canal d'erreur normal (pas via Proof).
        logger.warning("Sage unreachable during validation (deferring to exec): %s", _sage_exc)
        _verdict = None
    except Exception as _val_exc:  # noqa: BLE001 — fail-closed sur bug validator
        logger.error(
            "validate_for_iris crashed (fail-closed BLOCKING): %s",
            _val_exc,
            exc_info=True,
        )
        return {
            "success": False,
            "error": (
                "Validation indisponible — requête bloquée par sécurité. "
                "Réessaie ou contacte l'administrateur."
            ),
            "blocked_by": "validation_error",
            "columns": [],
            "row_count": 0,
            "execution_time_ms": 0,
        }

    if _verdict is not None:
        if not _verdict.passes:
            assert _verdict.proof is not None
            return _verdict.proof.to_tool_result()
        # Utiliser le SQL post-RLS + post-normalisation (peut être transformé)
        if _verdict.sql_used:
            sql = _verdict.sql_used
        # T9 + T16-C1 : extraire le tracking des transformations système
        # depuis verdict.provenance pour exposer via context (observabilité).
        if _verdict.provenance and isinstance(context, dict):
            _norm_entries = [
                p for p in _verdict.provenance if p.get("step") == "normalize_sql_syntax"
            ]
            if _norm_entries:
                _flat_transforms: list[dict] = []
                for entry in _norm_entries:
                    _flat_transforms.extend(entry.get("transformations") or [])
                if _flat_transforms:
                    existing = list(context.get("_sql_system_transformations") or [])
                    existing.extend(_flat_transforms)
                    context["_sql_system_transformations"] = existing

    # ── Marqueur « non pré-validé par le SGBD » (politique oracle fail-open) ──
    # ``validate_for_iris`` ne raise plus SageConnectionError : en fail-open
    # (défaut) il retourne passes=True + oracle_validated=False. Ce flag est
    # propagé (a) au tool result pour Iris, (b) au ``pending_results`` →
    # event ``sql_results`` → bannière grille — pas de contournement muet.
    # NB : ``_verdict is None`` ne peut venir QUE du except SageConnectionError
    # legacy ci-dessus (defense-in-depth) → même traitement non-pré-validé.
    # ``getattr`` : tolère les verdicts duck-typés (tests, wrappers legacy).
    _oracle_unvalidated = _verdict is None or (
        _verdict.passes and getattr(_verdict, "oracle_validated", None) is False
    )
    # ──────────────────────────────────────────────────────────────────

    # ── Substitution des placeholders pseudonymizer → requête paramétrisée ──
    # Le LLM peut écrire dans le SQL des tokens produits par le Pseudonymizer
    # runtime (format ``§...§``) ou les tokens legacy ``~xxx`` issus du
    # sanitize_user_input. La table de correspondance vit dans ``pii_mapping``
    # (contexte courant). Depuis 2026-05-22 : /data-privacy + Pseudonymizer
    # = seule source des pseudos (plus de lookup ValueMapping.anonymized_value).
    #
    # Filet anti-régression : si le SQL contient des tokens ``~xxx`` résiduels
    # (issus du RAG, d'une conversation antérieure, d'un widget restored) qui
    # ne sont PAS dans ``pii_mapping``, on enrichit le mapping en lookup-ant
    # ``anonymization_terms`` pour le ``user_id`` courant. Sans ce filet, les
    # ``~xxx`` survivants seraient envoyés en clair au SQL Server → DataError
    # ou 0 rows silencieux.
    pii_mapping = dict(context.get("pii_mapping") or {})
    params = None

    user_id = context.get("user_id")
    if user_id is None:
        _user_obj = context.get("user")
        if _user_obj is not None:
            user_id = getattr(_user_obj, "id", None)

    _tilde_tokens = set(re.findall(r"'(~[^']+)'", sql))
    _missing_tokens = _tilde_tokens - set(pii_mapping.keys())
    if _missing_tokens and user_id is not None:
        try:
            from app.core.database import get_session
            from app.models.anonymization_term import AnonymizationTerm
            from sqlalchemy import select as _sa_select

            _pseudo_lookups = {tok: tok[1:].replace("_", " ") for tok in _missing_tokens}
            async with get_session() as _sess:
                _stmt = _sa_select(
                    AnonymizationTerm.pseudo_middle,
                    AnonymizationTerm.term,
                ).where(
                    AnonymizationTerm.user_id == user_id,
                    AnonymizationTerm.pseudo_middle.in_(list(_pseudo_lookups.values())),
                    AnonymizationTerm.enabled.is_(True),
                )
                _result = await _sess.execute(_stmt)
                _resolved = {row.pseudo_middle: row.term for row in _result}
            for tok, pseudo in _pseudo_lookups.items():
                if pseudo in _resolved:
                    pii_mapping[tok] = _resolved[pseudo]
        except Exception as _resolve_err:
            logger.warning("anonymization_terms lookup for SQL tokens failed: %s", _resolve_err)

    # ── Fail-closed sur tokens ~xxx non résolus (doctrine "100% justifié") ──
    # AVANT 2026-05-26 : si un token ~xxx était présent dans le SQL mais absent
    #   de pii_mapping ET de /data-privacy, on loggait un warning et on exécutait
    #   quand même → 0 lignes silencieux OU DataError SQL Server opaque pour Iris.
    # APRÈS : on bloque déterministiquement avec un Proof structuré qui explique
    #   l'origine probable (RAG obsolète OU terme non configuré dans /data-privacy)
    #   et l'action concrète à faire. Iris ne peut plus inférer "0 rows = pas de
    #   données" alors que c'est en réalité "tokens cassés".
    _still_missing = _tilde_tokens - set(pii_mapping.keys())
    if _still_missing:
        from app.services.ai.sql_validator import Proof, _compute_sql_hash

        _proof = Proof(
            rule_id="UNRESOLVED_PSEUDO_TOKEN",
            rule_doc=(
                "Le SQL référence des tokens anonymisés (~xxx) qui ne sont ni "
                "dans le pii_mapping de la session courante, ni dans la table "
                "anonymization_terms (/data-privacy) de l'utilisateur. Exécuter "
                "tels quels enverrait des chaînes inconnues au SQL Server → "
                "résultats vides ou type error silencieux."
            ),
            evidence={"unresolved_tokens": sorted(_still_missing)},
            sql_hash=_compute_sql_hash(sql),
            suggested_fix=(
                "Deux causes possibles :\n"
                "  1. RAG obsolète : les tokens viennent d'une conversation/widget "
                "antérieur, mais le mapping a expiré. Régénère via schema_sync ou "
                "redemande à l'utilisateur la valeur réelle qu'il visait.\n"
                "  2. Terme non configuré : l'utilisateur doit ajouter le terme "
                "dans /data-privacy → 'Ajouter un terme pseudonymisé'."
            ),
        )
        logger.warning(
            "execute_sql BLOCKED: unresolved tokens %s (fail-closed)",
            sorted(_still_missing),
        )
        return _proof.to_tool_result()

    if pii_mapping:
        from app.services.anonymization.strategies import get_confidentiality_manager

        cm = get_confidentiality_manager()
        sql, param_list = cm.substitute_sql_placeholders(sql, pii_mapping)
        if param_list:
            params = tuple(param_list)
            logger.info(
                "SQL placeholders substituted: %d params (from pii_mapping)",
                len(param_list),
            )
    # ────────────────────────────────────────────────────────────────────

    # ── Normalisation syntaxe SQL Server : TOP N DISTINCT → DISTINCT TOP N ──
    # Le LLM génère souvent SELECT TOP N DISTINCT ... qui est invalide.
    # SQL Server exige SELECT DISTINCT TOP N ...
    sql = re.sub(
        r"\b(SELECT\s+)TOP\s+(\d+)\s+DISTINCT\b",
        r"\1DISTINCT TOP \2",
        sql,
        flags=re.IGNORECASE,
    )

    executor = get_query_executor()

    # ── Dry run TOP 1 : vérifier la structure avant exécution complète ──
    # Si la requête n'est pas déjà minuscule (TOP 1-5), on exécute d'abord
    # une version TOP 1 pour détecter les erreurs de structure sans attendre
    # le scan complet. Économise du temps sur les erreurs de colonne/type.
    # Skip dans 2 cas :
    #  - SQL vide/whitespace (laissera l'exécution principale lever une erreur claire)
    #  - Plusieurs TOP (CTE + SELECT principal) : `re.sub(..., count=1)` toucherait
    #    le premier TOP rencontré (souvent celui du CTE interne), produisant une
    #    requête de test sémantiquement différente de la vraie.
    _small_top = re.search(r"\bTOP\s+([1-5])\b", sql, re.IGNORECASE)
    _top_count = len(re.findall(r"\bTOP\s+\d+\b", sql, flags=re.IGNORECASE))
    _sql_blank = not sql or not sql.strip()
    if not _small_top and not _sql_blank and _top_count <= 1:
        # Initialiser dry_sql AVANT le try : si executor.execute() raise avant
        # toute ré-affectation, la variable doit exister pour le message d'erreur.
        dry_sql = sql
        try:
            # Construire la version dry run (remplacer TOP N par TOP 1, ou ajouter TOP 1)
            _existing_top = re.search(r"\bTOP\s+\d+\b", sql, re.IGNORECASE)
            if _existing_top:
                dry_sql = re.sub(r"\bTOP\s+\d+\b", "TOP 1", sql, count=1, flags=re.IGNORECASE)
                dry_result = await executor.execute(
                    dry_sql,
                    max_rows=1,
                    add_limit=False,
                    params=params,
                    user=user,
                    rls_source="agent_tools._handle_execute_sql.dry_run",
                )
            else:
                # Pas de TOP existant → déléguer l'insertion à add_row_limit
                # qui gère correctement DISTINCT, CTEs, et commentaires SQL.
                dry_result = await executor.execute(
                    sql,
                    max_rows=1,
                    add_limit=True,
                    params=params,
                    user=user,
                    rls_source="agent_tools._handle_execute_sql.dry_run",
                )
            logger.debug("Dry run TOP 1 OK (%d cols)", len(dry_result.columns or []))
        except Exception as dry_exc:
            # Le dry run a échoué → la requête complète échouerait aussi
            # Retourner l'erreur immédiatement (économise le temps du scan complet)
            from app.core.exceptions import SageConnectionError

            if isinstance(dry_exc, SageConnectionError):
                return {
                    "success": False,
                    "error": str(dry_exc),
                    "is_connection_error": True,
                    "columns": [],
                    "row_count": 0,
                    "execution_time_ms": 0,
                }
            error_msg = str(dry_exc)
            error_code = getattr(dry_exc, "sqlstate", None)

            # ── C26 : tentative d'auto-correction déterministe ──
            # Pas de LLM call : la correction utilise des règles
            # programmatiques (fuzzy match colonnes, ajout GROUP BY,
            # HAVING/WHERE swap, type mismatch). Si elle produit un SQL
            # valide au dry-run, on utilise celui-ci et on trace la
            # correction pour affichage utilisateur.
            _auto_correction = await _maybe_auto_correct_sql(
                dry_sql,
                error_msg,
                executor,
                params,
                user=user,
            )
            if _auto_correction is not None:
                # Le SQL corrigé passe le dry-run — on l'adopte pour
                # l'exécution complète. Le LLM verra le flag
                # ``auto_corrected`` dans le result final.
                sql = _auto_correction["corrected_sql"]
                dry_sql = sql
                context.setdefault("_auto_corrections", []).append(
                    {
                        "category": _auto_correction["category"],
                        "description": _auto_correction["description"],
                    }
                )
                # Sortir du bloc dry-run : le nouveau SQL continuera
                # vers l'exécution complète ci-dessous
            else:
                sanitized_hint = _classify_sql_error(error_msg)
                # Phase 3.2 : sanitize l'``error_msg`` brut avant remontée
                # — SQL Server révèle le vrai nom dans "Invalid object
                # name 'X'", ce qui fuit vers le LLM puis l'user.
                from app.services.data_access.error_messages import (
                    sanitize_sql_server_error_message,
                )

                safe_error_msg = await sanitize_sql_server_error_message(error_msg, user)
                logger.info(
                    "Dry run TOP 1 failed (skipping full query): %s",
                    error_msg[:200],  # log brut côté serveur pour debug
                )
                return {
                    "success": False,
                    "error": (
                        f"═══ ERREUR SQL SERVER ═══\n"
                        f"Message: {safe_error_msg}\n"
                        f"═══ REQUÊTE ÉCHOUÉE ═══\n"
                        f"{dry_sql}\n"
                        f"═══ DIAGNOSTIC ═══\n"
                        f"{sanitized_hint}\n"
                        f"OBLIGATOIRE : identifie la cause et corrige AVANT de retenter."
                    ),
                    "sql": dry_sql,
                    "error_code": error_code,
                    "columns": [],
                    "row_count": 0,
                    "execution_time_ms": 0,
                }
    # ────────────────────────────────────────────────────────────────────

    # ── T27 — Plan d'exécution préventif (SHOWPLAN_XML) ────────────────
    # Avant d'exécuter une query potentiellement coûteuse, demander à
    # SQL Server le plan estimé. Si le plan révèle un Table Scan massif,
    # un Hash/Nested Loops sans clé/prédicat (cartésien), ou un cost
    # agrégé > seuil → flag ``query_plan_warning`` injecté plus bas dans
    # la response. Le LLM Iris peut alerter l'utilisateur ("requête
    # potentiellement longue").
    # Trigger : SQL > 200 chars OU JOIN multi-table. SkipP silencieux si :
    # - mode SQLite (pas de SHOWPLAN_XML équivalent)
    # - permission SHOWPLAN refusée par SQL Server
    # - timeout / erreur réseau
    # Fail-safe absolu : aucune exception ne remonte ; ce hook ne bloque
    # PAS l'exécution principale.
    _query_plan_warning: Optional[Dict[str, Any]] = None
    try:
        from app.services.ai.query_plan_preview import analyze_query_plan

        _query_plan_preview = await analyze_query_plan(
            sql,
            executor.connector,
            params=params,
        )
        if _query_plan_preview.get("has_warning"):
            _query_plan_warning = _query_plan_preview
            logger.warning(
                "T27 query_plan_warning: severity=%s signals=%d cost=%s rows=%s",
                _query_plan_preview.get("severity"),
                len(_query_plan_preview.get("signals", [])),
                _query_plan_preview.get("estimated_total_cost"),
                _query_plan_preview.get("estimated_total_rows"),
            )
    except Exception:  # noqa: BLE001 — fail-safe
        logger.exception("T27 query_plan_preview hook failed (skipped)")
    # ────────────────────────────────────────────────────────────────────

    start = time.monotonic()

    # Task #9 (2026-05-22) — récupère cancel_event depuis le context partagé
    # de l'agent (posé par agent_service.run() pour propager le Stop user).
    # Si présent et set en cours d'exec, le connector pyodbc cancel le cursor
    # via SQLCancel et raise SageQueryCancelledError — pas de résultat partiel.
    _cancel_event_for_sql = context.get("_cancel_event") if isinstance(context, dict) else None

    try:
        result = await executor.execute(
            sql,
            max_rows=max_rows,
            add_limit=False,
            params=params,
            user=user,
            rls_source="agent_tools._handle_execute_sql",
            cancel_event=_cancel_event_for_sql,
        )
        elapsed_ms = (time.monotonic() - start) * 1000

        rows_data = result.to_dicts()

        # 2026-05-19 — Retrait du hook scan_sql_result_terms (task #8 POINT 2
        # initial). Le scan backend tirait pour TOUTES les exécutions SQL
        # d'Iris, y compris celles en background non affichées à l'user.
        # Résultat : des GUIDs/bytes techniques arrivaient en BDD comme
        # termes "à anonymiser" alors que l'user ne les voyait JAMAIS.
        #
        # Nouvelle règle : le scan d'anonymisation tire UNIQUEMENT depuis
        # les cellules VISIBLES dans un classeur (iris-grid). Ce trigger
        # frontend est déclenché par ``GridTabManager.addTab`` quand les
        # rows sont posées (= au moment où l'user voit) — cf.
        # ``static/js/iris-grid.js``. Si l'user ne voit pas une cellule,
        # elle n'est pas scannée. Source de vérité unique : ``/data/privacy``.

        # SQL affiché à l'utilisateur : paramétré + params séparés (pas de substitution)
        display_sql = sql
        if params:
            param_strs = [f"'{p}'" if isinstance(p, str) else str(p) for p in params]
            display_sql = f"{sql}\n-- Paramètres : [{', '.join(param_strs)}]"

        # Store full data in context — the WebSocket handler sends this to the user
        if "pending_results" not in context:
            context["pending_results"] = []
        search_id = len(context["pending_results"])
        context["pending_results"].append(
            {
                "search_id": search_id,
                "sql": display_sql,
                "explanation": explanation,
                "columns": result.columns,
                "data": rows_data,
                "row_count": result.row_count,
                "execution_time_ms": elapsed_ms,
                "truncated": result.truncated,
                # Clé ADDITIVE, posée uniquement quand False : l'event
                # ``sql_results`` la forwarde et la grille affiche la bannière
                # « non pré-validé par le SGBD ». Absente = chemin normal.
                **({"oracle_prevalidated": False} if _oracle_unvalidated else {}),
            }
        )

        logger.info(
            "execute_sql: query dispatched to user",
            extra={
                "user_id": getattr(user, "id", None),
                "rows": result.row_count,
                "elapsed_ms": round(elapsed_ms, 1),
            },
        )

        # Anonymise le sample 5 lignes via le proxy unifié.
        # Couches : (1) PII regex (EMAIL/SIRET/IBAN/...), (2) Pseudonymizer
        # user-scoped (BDD `anonymization_terms`). Les valeurs réelles ne
        # quittent JAMAIS la couche tool — seuls des tokens `§…§` et
        # `[TYPE_N]` partent au LLM. Les dates ne sont plus tronquées.
        sample_rows = rows_data[:5]
        anonymized_sample, _ = await anonymize_for_llm(
            getattr(user, "id", None), sample_rows, "IRIS_CHAT"
        )

        # Compute column-level statistics from the FULL result (not obfuscated).
        # This gives the agent accurate data understanding without revealing values.
        col_stats = _compute_column_stats(rows_data, list(result.columns))

        # ── Inject enriched stats for columns with many NULLs in the sample ────
        # When the sample has mostly NULLs, the LLM may wrongly conclude that
        # ALL values are NULL, even if the enriched doc says otherwise.
        # Add hints from training_store for affected columns.
        null_context_hints: Dict[str, str] = {}
        try:
            null_heavy_cols = [
                col_name
                for col_name, stats in col_stats.items()
                if stats.get("null_count", 0) > stats.get("total_rows", 1) * 0.5
            ]

            if null_heavy_cols:
                from app.services.ai.training_store import get_training_store

                ts = get_training_store()
                tables = _extract_real_tables_from_sql(sql)
                if tables:
                    # **#119** — user propagé pour filtre defense-in-depth.
                    enrichment = await ts.get_enrichment_for_tables(list(tables), user=user)
                    for col in null_heavy_cols:
                        for tbl, enr in enrichment.items():
                            col_info = enr.get("column_stats", {}).get(col)
                            if col_info:
                                null_pct = col_info.get("null_pct", "?")
                                distinct = col_info.get("distinct", "?")
                                hint = (
                                    f"[Note système] La colonne '{col}' est NULL dans "
                                    f"l'échantillon, mais la table complète a "
                                    f"{distinct} valeurs distinctes ({null_pct}% NULL)."
                                )
                                vals = enr.get("column_values", {}).get(col, [])
                                if vals:
                                    hint += f" Valeurs connues (anonymisées) : {', '.join(str(v)[:50] for v in vals[:10])}"
                                null_context_hints[col] = hint
        except Exception as exc:
            logger.debug("Failed to inject NULL context hints: %s", str(exc)[:200])
        # ────────────────────────────────────────────────────────────────────────

        # Return metadata + anonymized sample to help the LLM reason
        response: Dict[str, Any] = {
            "success": True,
            "search_id": search_id,
            "columns": result.columns,
            "row_count": result.row_count,
            "execution_time_ms": round(elapsed_ms, 1),
            "column_stats": col_stats,
            "anonymized_sample": anonymized_sample,
            "_anonymization_warning": (
                "⚠️ Les valeurs texte ci-dessous sont anonymisées par tokens. "
                "Deux formats : `§…§` (termes utilisateur, ex: `§nn_4b3§`) et "
                "`[TYPE_N]` (PII auto, ex: `[EMAIL_1]`, `[SIRET_2]`). "
                "L'utilisateur voit les valeurs réelles dans son interface — "
                "tu reçois uniquement les tokens. UTILISE les tokens tels quels "
                "dans tes réponses, le système les retraduit avant affichage."
            ),
            "note": (
                "⚠️ ANONYMISATION : Les données COMPLÈTES sont affichées à "
                "l'utilisateur dans un tableau interactif — TU ne les vois PAS. "
                "L'échantillon ci-dessus contient des tokens `§…§` (termes user) "
                "et `[TYPE_N]` (PII auto) qui REMPLACENT les valeurs réelles. "
                + _PII_PLACEHOLDER_TRUTH
                + " "
                "UTILISE column_stats (distinct_count, min/max, etc.) pour "
                "comprendre la forme des données. INTERDIT d'inventer de nouveaux "
                "tokens (pas de `§CLIENT_X§` jamais vu, pas de `[EMAIL_99]` non "
                "fourni) — n'utilise que ceux présents dans l'échantillon."
            ),
        }

        # ── Add NULL context hints if any columns were flagged ────────────────
        if null_context_hints:
            response["_null_context_hints"] = null_context_hints

        # ── Marqueur oracle fail-open → tool result (Iris doit le relayer) ──
        if _oracle_unvalidated:
            from app.services.ai.sql_validator import ORACLE_NOT_PREVALIDATED_WARNING

            response["oracle_prevalidated"] = False
            response["oracle_warning"] = (
                "⚠️ " + ORACLE_NOT_PREVALIDATED_WARNING + " Mentionne-le à "
                "l'utilisateur en présentant ce résultat (l'interface affiche "
                "aussi un bandeau sur la grille)."
            )

        # ── T22 — Détection cartésien masqué (JOIN sans ON/USING) ─────────
        # Catégorie "données fausses silencieuses" : un JOIN sans condition
        # produit un produit cartésien (rows × N) sans erreur visible. On
        # parse l'AST sqlglot pour détecter le cas le plus net. Le LLM
        # voit ``cartesian_warning`` dans la response et peut adapter sa
        # présentation à l'utilisateur (warning doublons potentiels).
        # Fail-safe : si parse échoue, le warning est omis (ne bloque pas).
        try:
            from app.services.ai.cartesian_detector import detect_cartesian_joins

            cartesian = detect_cartesian_joins(sql)
            if cartesian.get("has_suspect_joins"):
                response["cartesian_warning"] = cartesian
                logger.warning(
                    "T22: cartesian join detected (suspect=%d, total=%d) in SQL",
                    len(cartesian.get("suspect_joins", [])),
                    cartesian.get("total_joins", 0),
                )
        except Exception:  # noqa: BLE001 — fail-safe
            logger.exception("T22 cartesian_detector hook failed (skipped)")

        # ── T16 — Diagnostic 0-rows : bug silencieux vs légitime ────────────
        # Quand le SQL retourne 0 rows, distinguer :
        #   (a) probable bug : filtres/joints masquent les données existantes
        #   (b) légitime    : la donnée n'existe pas dans les tables participantes
        # Stratégie : COUNT(*) par table physique participante (cap 5, timeout
        # par probe + global). Le LLM Iris utilise ``zero_rows_diagnostic``
        # dans le response pour adapter la réponse à l'utilisateur.
        # Fail-safe : si le diagnostic crash, on ne bloque pas le retour (le
        # LLM verra juste row_count=0 sans hint additionnel).
        if result.row_count == 0:
            try:
                from app.services.ai.zero_rows_diagnostic import diagnose_zero_rows

                diagnostic = await diagnose_zero_rows(
                    sql,
                    executor,
                    user,
                )
                response["zero_rows_diagnostic"] = diagnostic
                logger.info(
                    "zero_rows_diagnostic: cause=%s confidence=%s tables_probed=%d",
                    diagnostic.get("probable_cause"),
                    diagnostic.get("confidence"),
                    len(diagnostic.get("tables_probed", [])),
                )
            except Exception:  # noqa: BLE001 — fail-safe, ne bloque pas le retour
                logger.exception("zero_rows_diagnostic hook failed (skipped, row_count=0)")

        # ── T25 — Cross-check post-exécution via variante SQL ────────────
        # Quand le SQL contient un agrégat (SUM/AVG/COUNT/MIN/MAX) ET
        # qu'au moins une table participante > 1M rows ET qu'on n'est
        # pas en mode exploration, exécuter une variante équivalente
        # (wrapping sub-query) et comparer row_count + somme des
        # colonnes numériques. Si écart > 1% → flag ``cross_check_warning``.
        # Complète la triangulation avec T22 (anti-cartésien) et T16
        # (0-rows) pour la catégorie « données fausses silencieuses ».
        # Fail-safe : si le cross-check crash, on ne bloque pas le retour.
        # Note : skipped silencieusement si pas d'agrégat, pas de large
        # table, schema indisponible, ou résultat tronqué — ce qui couvre
        # la majorité des appels (cap coût strict).
        if result.row_count is not None and result.row_count > 0:
            try:
                from app.services.ai.cross_check_post_execution import (
                    cross_check_sql_result,
                )
                from app.services.ai.schema_loader import get_schema_loader

                exploration_mode = False
                if isinstance(context, dict):
                    exploration_mode = bool(
                        context.get("_exploration_mode") or context.get("exploration_mode")
                    )

                cross_check = await cross_check_sql_result(
                    sql,
                    int(result.row_count),
                    executor,
                    user,
                    original_columns=list(result.columns or []),
                    original_rows=rows_data,
                    schema_loader=get_schema_loader(),
                    exploration_mode=exploration_mode,
                    truncated=bool(getattr(result, "truncated", False)),
                    params=params,
                )
                if cross_check.get("has_warning"):
                    response["cross_check_warning"] = cross_check
                    logger.warning(
                        "T25 cross-check warning: reason=%s confidence=%s",
                        cross_check.get("reason"),
                        cross_check.get("confidence"),
                    )
            except Exception:  # noqa: BLE001 — fail-safe
                logger.exception("T25 cross_check_post_execution hook failed (skipped)")

        # ── T27 — Attache le warning plan d'exécution (capturé pre-exec) ──
        # Le warning a été calculé AVANT executor.execute() pour bénéficier
        # du plan estimé (sans subir le coût de la query). On l'attache
        # ici (post-exec) pour rester cohérent avec le pattern T16/T22/T25
        # : tous les warnings post-exec sont mergés dans la response du
        # tool. Le LLM Iris voit ``query_plan_warning`` aux côtés des
        # autres signaux et peut adapter sa réponse à l'utilisateur.
        if _query_plan_warning is not None:
            response["query_plan_warning"] = _query_plan_warning

        # ── Missing-filter nudge (souple, remplace l'ancien blocage) ──
        # Le pré-check (agent_service) signale que l'utilisateur a mentionné
        # des valeurs qui n'apparaissent pas dans le SQL. On ne bloque plus
        # l'exécution (frustrant en boucle) — on remonte juste un rappel que
        # le LLM lira avec le résultat et peut choisir d'ignorer si l'étape
        # est volontairement exploratoire.
        if isinstance(context, dict):
            _missing_nudge = context.pop("_missing_filters_nudge", None)
            if _missing_nudge:
                response["_missing_filters_nudge"] = (
                    "Note : l'utilisateur a mentionné "
                    f"{', '.join(_missing_nudge)} mais ces valeurs "
                    "n'apparaissent pas dans ton SQL. Si c'est volontaire "
                    "(étape de diagnostic, filtrage en plusieurs temps, "
                    "etc.) explique-le à l'utilisateur. Sinon, ajoute-les "
                    "à la clause WHERE avant de présenter le résultat."
                )

        # ── P4.2 — Détection de changepoint vs historique (best-effort) ──
        # Compare ``row_count`` actuel à la médiane des dernières
        # exécutions de la même question. Best-effort : ne bloque jamais
        # le retour d'execute_sql, ne pollue le response qu'en cas d'écart
        # statistiquement significatif. Anti-2+2=4 : seuils relatifs,
        # aucun nom de table hardcodé.
        try:
            user_q_cp = context.get("user_message") or context.get("user_question") or ""
            if isinstance(user_q_cp, str) and user_q_cp.strip() and result.row_count is not None:
                from app.services.ai.changepoint_detector import (
                    get_changepoint_detector,
                )

                alert = await get_changepoint_detector().detect(
                    question=user_q_cp,
                    current_row_count=int(result.row_count),
                )
                if alert is not None:
                    response["_changepoint_alert"] = {
                        "severity": alert.severity,
                        "current_row_count": alert.current_row_count,
                        "historical_median": alert.historical_median,
                        "historical_count": alert.historical_count,
                        "delta_pct": alert.delta_pct,
                        "z_score": alert.z_score,
                        "message": alert.message,
                    }
        except Exception as cp_exc:  # noqa: BLE001
            logger.debug("changepoint detection skipped: %s", cp_exc, exc_info=True)

        # ── Avertissement échantillon non représentatif (TOP N sans ORDER BY) ──
        _sample_warn = _build_sample_warning(sql, rows_data, list(result.columns))
        if _sample_warn:
            response["sample_warning"] = _sample_warn

        # ── Auto-fill rate pour colonnes 100% NULL dans TOP queries ──────────
        # CODE > PROMPT : au lieu de dire "va vérifier", on VÉRIFIE et on injecte
        # le résultat. Le LLM ne peut plus ignorer.
        # FIX (hunt it.49, BF3) : match INSENSIBLE À LA CASSE. Le générateur
        # ``_build_sample_warning`` (l.~3748) produit « ... sont NULL dans cet
        # échantillon... » (minuscule « dans »), or ce gate testait « NULL DANS »
        # (majuscule) → JAMAIS de match → tout ce bloc d'analyse fill-rate était
        # MORT silencieusement (l'user ne recevait jamais le diagnostic). Le marqueur
        # « null dans » implique ``null_cols`` non vide (donc ``rows_data`` non vide).
        # ⚠️ Couplage de chaîne fragile générateur↔consommateur : si la formulation
        # du warning change, garder le substring « null dans » (ou découpler).
        if _sample_warn and "null dans" in _sample_warn.lower():
            try:
                # Identifier les colonnes 100% NULL dans l'échantillon
                all_null_cols = []
                for col_name in result.columns:
                    if all(row.get(col_name) is None for row in rows_data):
                        all_null_cols.append(col_name)

                if all_null_cols:
                    # Utiliser la requête originale SANS le TOP comme sous-requête.
                    # Ça préserve tous les JOINs/WHERE → les colonnes de TOUTES
                    # les tables sont accessibles (pas juste la table principale).
                    # On élargit TOP N à au moins 1000 pour un échantillon
                    # plus large sans scanner toute la BDD. #18f (verdict #30) :
                    # max(N, 1000) — ne JAMAIS rétrécir la fenêtre (un TOP
                    # 50000 original réduit à 1000 faussait les taux davantage).
                    _null_window = _compute_null_window(sql)
                    expanded_sql = re.sub(
                        r"\bTOP\s+\d+\b",
                        f"TOP {_null_window}",
                        sql,
                        count=1,
                        flags=re.IGNORECASE,
                    )
                    count_parts = ["COUNT(*) AS total_rows"]
                    for col in all_null_cols[:5]:  # Max 5 colonnes
                        safe_col = col.replace("]", "]]")
                        count_parts.append(f"COUNT([{safe_col}]) AS [{safe_col}_non_null]")
                    count_sql = (
                        f"SELECT {', '.join(count_parts)} " f"FROM ({expanded_sql}) AS _null_check"
                    )
                    from app.services.database.sage_connector import get_sage_connector

                    connector = get_sage_connector()
                    fill_result = await connector.execute(count_sql, max_rows=1)
                    fill_rows = fill_result.to_dicts()
                    if fill_rows:
                        fill_data = fill_rows[0]
                        total = fill_data.get("total_rows", 0)
                        fill_info = {}
                        for col in all_null_cols[:5]:
                            non_null = fill_data.get(f"{col}_non_null", 0)
                            pct = round(non_null / total * 100, 1) if total else 0
                            fill_info[col] = {
                                "total_rows": total,
                                "non_null": non_null,
                                "fill_rate_pct": pct,
                            }
                        # Aussi récupérer le taux TABLE-LEVEL (sans les filtres WHERE)
                        # pour éviter le faux "0% → colonne vide" quand c'est juste
                        # le filtre qui exclut les lignes remplies.
                        try:
                            tables_in_sql = list(_extract_real_tables_from_sql(sql))[:3]
                            if tables_in_sql:
                                for col in list(fill_info.keys()):
                                    # Chercher dans quelle table source cette colonne existe
                                    # (break dès le premier match — pas de N² queries)
                                    for tbl in tables_in_sql:
                                        if not _validate_identifier(tbl):
                                            continue
                                        try:
                                            tbl_count_sql = (
                                                f"SELECT COUNT(*) AS t, COUNT([{col.replace(']', ']]')}]) AS n "
                                                f"FROM [{tbl}]"
                                            )
                                            tbl_result = await connector.execute(
                                                tbl_count_sql, max_rows=1
                                            )
                                            tbl_rows = tbl_result.to_dicts()
                                            if tbl_rows:
                                                t = tbl_rows[0].get("t", 0)
                                                n = tbl_rows[0].get("n", 0)
                                                if t > 0:
                                                    global_pct = round(n / t * 100, 1)
                                                    fill_info[col]["table_level"] = {
                                                        "table": tbl,
                                                        "total_rows": t,
                                                        "non_null": n,
                                                        "fill_rate_pct": global_pct,
                                                    }
                                                    # Message clair si le taux diffère
                                                    if (
                                                        global_pct > 10
                                                        and fill_info[col]["fill_rate_pct"] < 5
                                                    ):
                                                        # FIX (hunt it.49, BF4) : interpoler le VRAI
                                                        # taux filtré (condition `< 5` → 0-4%, pas
                                                        # forcément 0). Avant : « 0% » hardcodé →
                                                        # message FAUX (« 0% » pour un vrai 2%) qui
                                                        # trompait LLM + user sur la dispo réelle.
                                                        _filtered_pct = fill_info[col]["fill_rate_pct"]
                                                        fill_info[col]["_warning"] = (
                                                            f"⚠️ La colonne '{col}' est {global_pct}% remplie "
                                                            f"dans la table {tbl} mais {_filtered_pct}% dans "
                                                            f"ta requête filtrée. "
                                                            f"Tes filtres WHERE excluent les lignes remplies. "
                                                            f"Vérifie tes filtres ou élargis la recherche."
                                                        )
                                                    break  # Trouvé dans cette table
                                        except Exception:
                                            continue  # Colonne pas dans cette table
                        except Exception as tbl_err:
                            logger.debug("Table-level fill rate failed: %s", tbl_err)

                        # #18f (verdict #30) — fenêtre saturée = les taux
                        # portent sur un ÉCHANTILLON (TOP sans ORDER BY),
                        # pas sur la requête entière : le dire au LLM qui
                        # relaie ces chiffres à l'utilisateur.
                        _totals = [
                            v.get("total_rows")
                            for v in fill_info.values()
                            if isinstance(v, dict) and isinstance(v.get("total_rows"), int)
                        ]
                        if _totals and max(_totals) >= _null_window:
                            fill_info["_sample_note"] = (
                                f"Taux calculés sur une fenêtre TOP {_null_window} "
                                "sans ORDER BY (échantillon de préfixe) — "
                                "total_rows N'EST PAS le total de la requête ; "
                                "ne présente pas ces taux comme exhaustifs."
                            )
                        # #18f (verdict #30, partie 3) — au-delà de 5 colonnes
                        # 100% NULL, seules les 5 premières sont diagnostiquées.
                        # Sans ce marqueur, le LLM croit avoir le taux de TOUTES
                        # les colonnes vides → il relaie un diagnostic partiel
                        # comme complet (colonne vide non signalée = donnée
                        # fausse silencieuse).
                        if len(all_null_cols) > 5:
                            fill_info["_omitted_columns"] = len(all_null_cols) - 5
                            fill_info["_omitted_columns_note"] = (
                                f"{len(all_null_cols) - 5} autre(s) colonne(s) "
                                "100% NULL dans l'échantillon ne sont PAS "
                                "diagnostiquées ici (cap à 5) — ne conclus pas "
                                "qu'elles sont remplies."
                            )
                        response["_auto_null_fill_rates"] = fill_info
                        # Logger défensif : fill_info contient aussi des entrées
                        # méta (_sample_note str, _omitted_columns int) — n'agréger
                        # le % que sur les vraies entrées colonne (dict + clé).
                        logger.info(
                            "Auto NULL fill rate injected for %d columns: %s",
                            sum(
                                1
                                for v in fill_info.values()
                                if isinstance(v, dict) and "fill_rate_pct" in v
                            ),
                            {
                                k: f"{v['fill_rate_pct']}%"
                                for k, v in fill_info.items()
                                if isinstance(v, dict) and "fill_rate_pct" in v
                            },
                        )
            except Exception as fill_err:
                logger.debug("Auto NULL fill rate failed: %s", fill_err)

        # ── Low-cardinality warning : colonne string "verrouillée" à 1 valeur ──
        # CODE > PROMPT : quand une colonne texte a distinct_count=1 sur un
        # gros échantillon, c'est souvent le signe que la requête ne voit
        # qu'une facette d'une entité potentiellement multi-facettes (contexte
        # implicite absent des filtres). Générique : aucun nom de table /
        # colonne hardcodé.
        #
        # Faux positif à éviter : si la colonne est explicitement filtrée
        # dans la clause WHERE (ex: ``WHERE statut = 'ACTIF'``), obtenir
        # distinct_count=1 est ATTENDU et non suspect. On détecte ce cas
        # en regardant si le nom de la colonne apparaît dans la clause
        # WHERE du SQL exécuté, et on exclut alors cette colonne.
        try:
            suspect_cols: list[str] = []
            # Extraire la portion WHERE (approx, générique) pour identifier
            # les colonnes filtrées. On évite sqlparse ici pour rester léger
            # — une simple capture du texte post-WHERE suffit à couvrir le
            # faux positif le plus courant.
            _where_match = re.search(
                r"\bWHERE\b(.*?)(?:\bGROUP\s+BY\b|\bORDER\s+BY\b|\bHAVING\b|\bLIMIT\b|$)",
                sql,
                re.IGNORECASE | re.DOTALL,
            )
            _where_text = (_where_match.group(1) if _where_match else "").lower()
            for _col, _stats in col_stats.items():
                if not isinstance(_stats, dict):
                    continue
                if _stats.get("type") != "string":
                    continue
                # Coercion défensive : les stats peuvent arriver sérialisées
                # en string via certains chemins (JSON round-trip). int()
                # explicite évite un TypeError silencieusement catché plus bas.
                try:
                    _total = int(_stats.get("total_rows", 0) or 0)
                    _distinct = int(_stats.get("distinct_count", 0) or 0)
                    _non_null = int(_stats.get("non_null_count", 0) or 0)
                    _min_len = int(_stats.get("min_length", 0) or 0)
                except (TypeError, ValueError):
                    continue
                # Seuils conservateurs : besoin d'un échantillon significatif
                # ET d'une colonne qui a vraiment une valeur (pas juste 0/1 flag).
                if not (
                    _total >= _LOW_CARDINALITY_MIN_SAMPLE
                    and _distinct == 1
                    and _non_null >= _LOW_CARDINALITY_MIN_SAMPLE
                    and _min_len >= _LOW_CARDINALITY_MIN_LEN
                ):
                    continue
                # Skip si la colonne est filtrée explicitement dans le WHERE
                # (distinct=1 est alors attendu, pas suspect). Match sur le
                # nom de colonne quel qu'il soit — générique.
                if _col and _col.lower() in _where_text:
                    continue
                suspect_cols.append(_col)
            if suspect_cols:
                response["_low_cardinality_warning"] = (
                    "[NOTE INTERNE — message du système] Colonne(s) avec UNE SEULE "
                    f"valeur distincte sur un échantillon ≥ {_LOW_CARDINALITY_MIN_SAMPLE} lignes : "
                    f"{', '.join(suspect_cols[:5])}. Ce n'est pas forcément un "
                    "bug, mais si cette/ces colonnes sont censées identifier "
                    "une entité (groupe, entité, contexte, tenant...), vérifie "
                    "avec `SELECT DISTINCT` sur la table source qu'il n'existe "
                    "pas d'autres valeurs hors de ton périmètre actuel. Un "
                    "filtre implicite peut masquer des données."
                )
        except Exception as _lc_exc:
            logger.debug("Low-cardinality check failed: %s", _lc_exc)

        # C26 : si une auto-correction a été appliquée lors du dry-run,
        # l'exposer dans le result pour que le LLM puisse l'expliquer à
        # l'utilisateur ("j'ai corrigé X qui était faux"). Générique :
        # indépendant du provider LLM.
        _corrections = context.get("_auto_corrections") if isinstance(context, dict) else None
        if _corrections:
            response["auto_corrected"] = _corrections
            response["_auto_correction_note"] = (
                "Une correction automatique du SQL a été appliquée avant "
                "exécution (erreur déterministe détectée + fix programmatique). "
                "Mentionne-la brièvement à l'utilisateur dans ta réponse."
            )

        # P1.1 — Référence RAG comme contrat faible sur le nombre de
        # colonnes. Anti-2+2=4 : on compare uniquement le NOMBRE de
        # colonnes produites vs la référence (pas les noms — le LLM
        # reste libre de nommer et structurer). Un ratio faible signale
        # souvent une dimension oubliée ; on renvoie un nudge non
        # bloquant que le LLM devra expliquer à l'utilisateur.
        _ref_cols = context.get("_rag_reference_columns") if isinstance(context, dict) else None
        if _ref_cols and isinstance(_ref_cols, list):
            produced = list(result.columns or [])
            ratio = (len(produced) / len(_ref_cols)) if _ref_cols else 1.0
            if ratio < 0.5:
                response["_reference_columns_coverage"] = {
                    "produced_count": len(produced),
                    "reference_count": len(_ref_cols),
                    "ratio": round(ratio, 2),
                    "hint": (
                        "Ta sortie contient notablement moins de colonnes "
                        "que la référence historique de cette question. "
                        "Cela peut être volontaire (simplification) ou "
                        "signaler une dimension oubliée (une granularité "
                        "d'analyse attendue par l'utilisateur). Si tu "
                        "juges ta simplification justifiée, explique-la "
                        "brièvement dans ta réponse à l'utilisateur. "
                        "Sinon, reprends l'analyse pour ajouter la "
                        "dimension manquante."
                    ),
                }

        # P1.2 — Self-critique rotatif. Anti-2+2=4 : ce n'est PAS une
        # check-list que le LLM peut remplir mécaniquement. C'est UNE
        # question choisie par rotation déterministe parmi un pool de
        # questions abstraites qu'un DBA senior se pose après avoir
        # livré une requête. L'objectif : semer une seconde de doute,
        # pas dicter une structure de réponse.
        user_question = context.get("_original_message", "") if isinstance(context, dict) else ""
        response["_self_critique"] = _pick_self_critique_question(
            sql=sql,
            user_question=str(user_question or ""),
        )

        return response

    except Exception as exc:
        from app.core.exceptions import SageConnectionError

        is_connection_error = isinstance(exc, SageConnectionError)
        if is_connection_error:
            # P2.6 (audit 2026-05-26) — Avant : message fixe « Connexion à la
            # base de données source impossible. Vérifie la configuration
            # réseau. » qui jetait ``str(exc)`` (lequel depuis P1.1 contient
            # ``[SQLSTATE] message ODBC`` actionnable : login failed, cert
            # untrusted, network unreachable, etc.). Iris ne pouvait pas
            # auto-diagnostiquer faute de contexte.
            # Maintenant : helper SSoT P2.1 avec ``audience="llm"`` → message
            # structuré ``[SQLSTATE] <sanitized_msg>`` qui inclut le détail
            # ODBC (sanitisé par sanitize_sql_server_error_message pour le
            # mode invisible des noms denied).
            logger.warning("execute_sql: connexion Sage impossible: %s", str(exc)[:200])
            from app.services.data_access.error_messages import (
                sanitize_sql_for_client as _ssfc,
            )

            _conn_payload = await _ssfc(exc, user, audience="llm")
            return {
                "success": False,
                "error": _conn_payload["message"],
                "sqlstate": _conn_payload.get("sqlstate"),
                "category": _conn_payload.get("category"),
                "is_connection_error": True,
                "columns": [],
                "row_count": 0,
                "execution_time_ms": 0,
            }
        error_msg = str(exc)
        error_code = getattr(exc, "sqlstate", None)
        logger.warning("execute_sql failed: %s | SQL: %.200s", exc, sql, exc_info=True)

        # Classify error for the LLM without leaking raw schema details
        sanitized_hint = _classify_sql_error(error_msg)

        # Phase 3.2 : sanitize ``error_msg`` brut — SQL Server peut révéler
        # un nom de table/colonne interdit dans "Invalid object/column name 'X'".
        from app.services.data_access.error_messages import (
            sanitize_sql_server_error_message,
        )

        safe_error_msg = await sanitize_sql_server_error_message(error_msg, user)

        # C26 — si une auto-correction a déjà été tentée et validée au
        # dry-run mais que l'exécution complète échoue quand même,
        # marquer le result pour empêcher le post-process de retenter
        # une deuxième auto-correction sur le SQL déjà corrigé (cascade).
        _already_autocorrected = bool(
            context.get("_auto_corrections") if isinstance(context, dict) else None
        )

        error_response: Dict[str, Any] = {
            "success": False,
            "error": (
                f"═══ ERREUR SQL SERVER ═══\n"
                f"Message: {safe_error_msg}\n"
                f"═══ REQUÊTE ÉCHOUÉE ═══\n"
                f"{sql}\n"
                f"═══ DIAGNOSTIC ═══\n"
                f"{sanitized_hint}\n"
                f"OBLIGATOIRE : identifie la cause et corrige AVANT de retenter."
            ),
            "sql": sql,
            "error_code": error_code,
            "columns": [],
            "row_count": 0,
            "execution_time_ms": 0,
        }
        if _already_autocorrected:
            error_response["_auto_correction_exhausted"] = True
        # ── T27 — Propage le warning plan d'exécution dans la branche error ──
        # Si le pré-check SHOWPLAN avait déjà détecté un plan suspect
        # (cost > seuil, table scan massif), le warning aide le LLM à
        # diagnostiquer une éventuelle correlation entre le plan et
        # l'erreur (ex: timeout sur Table Scan). Ne PAS perdre cette
        # info dans la branche error.
        if _query_plan_warning is not None:
            error_response["query_plan_warning"] = _query_plan_warning
        return error_response


async def _handle_get_database_schema(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """
    Return DDL / column info from the training store and schema loader.
    Not sensitive — metadata only.

    RLS : filtre la liste des tables (mode list_all) et refuse les modes
    exact/search sur tables denied. L'agent ne doit pas pouvoir voir le
    DDL d'une table interdite à l'user (leak du schéma sensible).
    """
    table_name: Optional[str] = tool_input.get("table_name")
    search_term: Optional[str] = tool_input.get("search_term")

    from app.services.data_access.enforcer import (
        DataAccessDeniedError,
        assert_table_access,
    )
    from app.services.data_access.llm_context import filter_to_visible
    from app.services.data_access.visible_schema import build_user_schema_view

    # Phase α.4.A — Matérialiser la view UNE FOIS pour tout le handler
    # (évite les double matérialisations entre les branches list_all et search).
    try:
        view = await build_user_schema_view(user)
    except Exception:
        logger.warning(
            "get_database_schema: visible_schema build failed (no filter, "
            "runtime block remains)",
            exc_info=True,
        )
        view = None

    if not table_name and not search_term:
        # Return list of all known table names — filtré via UserSchemaView
        # (mode invisible : Phase 4.2). Plus strict que le legacy
        # ``filter_table_catalogue`` ; cf. agent_knowledge pour la doctrine.
        training_store = get_training_store()
        # Phase α.4.A : propager user pour filtrage à la source.
        table_names = await training_store.get_all_table_names(user=user)
        if view is not None and view.has_restrictions:
            table_names = filter_to_visible(view, table_names)
        return {
            "success": True,
            "mode": "list_all",
            "table_count": len(table_names),
            "tables": table_names,
        }

    training_store = get_training_store()

    if table_name:
        # RLS check — refuse si table denied
        try:
            await assert_table_access(table_name, user)
        except DataAccessDeniedError as exc:
            return {
                "success": False,
                "error": exc.user_message,
                "blocked_by": "data_access_rule",
            }
        # Exact lookup via training store
        ddl_entries = await training_store.get_ddl_by_table_names([table_name], user=user)
        if ddl_entries:
            entry = ddl_entries[0]
            # Also try schema loader for structured column info
            loader = get_schema_loader()
            # Phase α.4.A : passer user_view aux méthodes SchemaLoader
            columns = loader.get_table_columns(table_name, user_view=view)
            description = loader.get_table_description(table_name, user_view=view)
            return {
                "success": True,
                "mode": "exact",
                "table_name": table_name,
                "ddl": entry["content"],
                "description": description,
                "columns": columns,
            }
        return {
            "success": False,
            "error": f"Table '{table_name}' not found in training store.",
        }

    # Search mode — filtre les résultats par UserSchemaView (mode invisible).
    # Phase α.4.A : propager user à get_related_ddl ; view réutilisée du
    # haut du handler (pas de double matérialisation).
    ddl_results = await training_store.get_related_ddl(search_term, n_results=5, user=user)
    if view is not None and view.has_restrictions:
        result_tables = [r["table_name"] for r in ddl_results]
        allowed_tables = filter_to_visible(view, result_tables)
        allowed_set = {t.upper() for t in allowed_tables}
        ddl_results = [r for r in ddl_results if r.get("table_name", "").upper() in allowed_set]
    return {
        "success": True,
        "mode": "search",
        "query": search_term,
        "results": [
            {
                "table_name": r["table_name"],
                "ddl": r["content"],
                "relevance_score": round(r["score"], 3),
            }
            for r in ddl_results
        ],
    }


def _validate_identifier(name: str) -> bool:
    """Validate a SQL identifier (table/column name) against injection patterns."""
    import re

    # Only allow alphanumeric, underscore, and common SQL Server identifiers
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_@#$]{0,127}$", name))


# #132 — SSoT de la vérité sur ce que l'anonymisation fait aux nombres/dates,
# partagée par TOUTES les notes LLM-facing des outils qui renvoient un échantillon
# anonymisé (``peek_table_data`` ET ``execute_sql``). ``anonymize_for_llm`` (couche
# PII ``apply_builtin_pii``) tokenise NON SEULEMENT les noms (``§…§`` user) mais AUSSI
# toute chaîne ressemblant à une date / un email / un identifiant en ``[TYPE_N]``
# (dont ``[DATE_N]``). Les anciennes notes affirmaient « dates inchangées / non
# anonymisées » → mensonge : le LLM croyait lire ``2024-03-12`` alors qu'il reçoit
# ``[DATE_1]`` (données fausses dans le prompt-outil). Une seule source = pas de drift.
_PII_PLACEHOLDER_TRUTH = (
    "Les nombres simples restent littéraux ; en revanche toute valeur qui ressemble "
    "à une date, un email ou un identifiant est tokenisée (une date devient `[DATE_N]`). "
    "Un token `[TYPE_N]` représente une vraie valeur masquée de ce type — raisonne "
    "dessus comme tel, jamais comme un littéral lisible."
)

_PEEK_ANONYMIZATION_NOTICE = (
    "⚠️ Les valeurs texte ci-dessous sont anonymisées par tokens. "
    "Deux formats : `§…§` (termes utilisateur) et `[TYPE_N]` (PII auto). "
    "L'utilisateur voit les valeurs réelles dans son interface — "
    "tu reçois uniquement les tokens. INTERDIT d'inventer de nouveaux "
    "tokens — utilise uniquement ceux présents dans la réponse. " + _PII_PLACEHOLDER_TRUTH
)


async def _handle_peek_table_data(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Execute SELECT TOP N on a table and anonymise all string values via the proxy.

    Le sample est anonymisé par :func:`anonymize_for_llm` (PII regex +
    Pseudonymizer user-scoped) — les valeurs réelles restent côté tool, le
    LLM ne reçoit que des tokens `§…§` (termes user) et `[TYPE_N]` (PII auto).
    """
    table_name: str = tool_input["table_name"]
    columns: Optional[List[str]] = tool_input.get("columns")
    try:
        limit: int = min(int(tool_input.get("limit", 5)), 20)
    except (ValueError, TypeError):
        limit = 5

    # F1: Validate table and column names against SQL injection
    if not _validate_identifier(table_name):
        return {"success": False, "error": "Nom de table invalide."}

    if columns:
        for col in columns:
            if not _validate_identifier(col):
                return {"success": False, "error": f"Nom de colonne invalide : {col}"}

    # Validation d'existence des colonnes (même protection que execute_sql)
    if columns:
        validation_error = await _validate_sql_columns(
            f"SELECT TOP 1 {', '.join(f'[{c}]' for c in columns)} FROM [{table_name}]",
            user=user,
        )
        if validation_error is not None:
            return validation_error

    col_clause = ", ".join(f"[{c}]" for c in columns) if columns else "*"
    sql = f"SELECT TOP {limit} {col_clause} FROM [{table_name}]"

    executor = get_query_executor()

    # Confidentialité AUTOMATIQUE — pas de choix utilisateur.
    # Anonymisation via le proxy unifié (PII regex + Pseudonymizer user-scoped).
    # Strings → tokens `§…§` (termes user) et `[TYPE_N]` (PII auto).
    # #132 — Les chaînes ressemblant à une date / un email / un identifiant SONT
    # tokenisées par la couche PII (``_PII_PATTERNS["DATE"]`` → `[DATE_N]`). Seuls
    # les nombres simples restent littéraux. (Les notes LLM-facing le disent via
    # ``_PII_PLACEHOLDER_TRUTH`` — ne jamais réintroduire « dates inchangées ».)

    try:
        from app.services.data_access.enforcer import DataAccessDeniedError

        result = await executor.execute(
            sql, max_rows=limit, add_limit=False, user=user, rls_source="peek_table_data"
        )
        raw_rows = result.to_dicts()

        logger.info(
            "peek_table_data: sample returned (anonymized via proxy)",
            extra={
                "table": table_name,
                "rows": len(raw_rows),
                "user_id": getattr(user, "id", None),
            },
        )

        processed_rows, _ = await anonymize_for_llm(
            getattr(user, "id", None), raw_rows, "IRIS_CHAT"
        )
        return {
            "success": True,
            "table_name": table_name,
            "columns": result.columns,
            "row_count": len(processed_rows),
            "rows": processed_rows,
            "_anonymization_warning": _PEEK_ANONYMIZATION_NOTICE,
        }

    except DataAccessDeniedError as exc:
        return {
            "success": False,
            "error": exc.user_message,
            "blocked_by": "data_access_rule",
        }
    except Exception as exc:
        logger.warning("peek_table_data failed for table: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de la lecture d'aperçu de la table."}


async def _handle_analyze_numbers(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """
    Perform statistical analysis on a list of numbers.
    No column names, no table names — context-free (level-3 confidentiality).
    """
    values: List[float] = [float(v) for v in tool_input["values"]]
    operation: str = tool_input["operation"]

    if not values:
        return {"success": False, "error": "Empty values list."}

    try:
        if operation == "stats":
            result_data = _compute_stats(values)

        elif operation == "anomalies":
            result_data = _detect_anomalies(values)

        elif operation == "distribution":
            result_data = _compute_distribution(values)

        elif operation == "trend":
            result_data = _compute_trend(values)

        else:
            return {"success": False, "error": f"Unknown operation: {operation}"}

        logger.info(
            "analyze_numbers: analysis completed",
            extra={"operation": operation, "n_values": len(values)},
        )

        return {"success": True, "operation": operation, "n_values": len(values), **result_data}

    except Exception as exc:
        logger.warning("analyze_numbers failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de l'analyse statistique."}


def _compute_stats(values: List[float]) -> Dict[str, Any]:
    n = len(values)
    sorted_vals = sorted(values)
    mean = statistics.mean(values)
    return {
        "count": n,
        "min": min(values),
        "max": max(values),
        "mean": round(mean, 4),
        "median": round(statistics.median(values), 4),
        "stdev": round(statistics.stdev(values), 4) if n > 1 else 0.0,
        "q1": round(sorted_vals[n // 4], 4),
        "q3": round(sorted_vals[(3 * n) // 4], 4),
        "sum": round(sum(values), 4),
    }


def _detect_anomalies(values: List[float]) -> Dict[str, Any]:
    """IQR-based outlier detection."""
    n = len(values)
    sorted_vals = sorted(values)
    q1 = sorted_vals[n // 4]
    q3 = sorted_vals[(3 * n) // 4]
    iqr = q3 - q1
    lower = q1 - 1.5 * iqr
    upper = q3 + 1.5 * iqr
    outliers = [v for v in values if v < lower or v > upper]
    outlier_indices = [i for i, v in enumerate(values) if v < lower or v > upper]
    return {
        "outlier_count": len(outliers),
        "outlier_indices": outlier_indices,
        "outlier_values": outliers,
        "lower_fence": round(lower, 4),
        "upper_fence": round(upper, 4),
        "iqr": round(iqr, 4),
    }


def _compute_distribution(values: List[float]) -> Dict[str, Any]:
    """Frequency distribution using 10 equal-width buckets."""
    min_v = min(values)
    max_v = max(values)
    n_buckets = min(10, len(values))

    if max_v == min_v:
        return {"buckets": [{"range": f"{min_v}", "count": len(values)}]}

    bucket_width = (max_v - min_v) / n_buckets
    buckets: List[Dict[str, Any]] = []

    for i in range(n_buckets):
        lo = min_v + i * bucket_width
        hi = lo + bucket_width
        count = sum(1 for v in values if lo <= v < hi)
        buckets.append(
            {
                "range": f"{round(lo, 2)}–{round(hi, 2)}",
                "count": count,
            }
        )

    # Last bucket includes the max value
    if buckets:
        last_lo = min_v + (n_buckets - 1) * bucket_width
        buckets[-1]["count"] = sum(1 for v in values if v >= last_lo)

    return {"min": min_v, "max": max_v, "bucket_width": round(bucket_width, 4), "buckets": buckets}


def _compute_trend(values: List[float]) -> Dict[str, Any]:
    """Simple linear trend via least-squares slope."""
    n = len(values)
    if n < 2:
        return {"trend": "insufficient_data", "slope": 0.0}

    x_mean = (n - 1) / 2.0
    y_mean = statistics.mean(values)

    numerator = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))
    denominator = sum((i - x_mean) ** 2 for i in range(n))

    slope = numerator / denominator if denominator != 0 else 0.0

    # Percentage change from first to last
    first = values[0]
    last = values[-1]
    pct_change = ((last - first) / abs(first) * 100) if first != 0 else None

    trend_direction = "stable"
    if slope > 0.01:
        trend_direction = "increasing"
    elif slope < -0.01:
        trend_direction = "decreasing"

    return {
        "trend": trend_direction,
        "slope": round(slope, 6),
        "first_value": first,
        "last_value": last,
        "pct_change": round(pct_change, 2) if pct_change is not None else None,
    }


_MAX_SEARCH_DOC_CALLS = 8


async def _handle_search_documentation(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict:
    """Search the RAG training store."""
    query: str = tool_input["query"]
    doc_type: str = tool_input["doc_type"]

    training_store = get_training_store()

    try:
        if doc_type == "ddl":
            # Phase α.4.A : propager user.
            results = await training_store.get_related_ddl(query, n_results=5, user=user)
            items = [
                {
                    "id": r["id"],
                    "table_name": r["table_name"],
                    "content": r["content"],
                    "score": round(r["score"], 3),
                }
                for r in results
            ]

        elif doc_type == "documentation":
            # Note α.1.bis (task #86) : get_related_documentation n'est pas
            # encore patchée mode invisible. À compléter quand #86 sera
            # done — pour l'instant pas de user= ici.
            results = await training_store.get_related_documentation(query, n_results=5)
            items = [
                {
                    "id": r["id"],
                    "category": r.get("category"),
                    "content": r["content"],
                    "score": round(r["score"], 3),
                }
                for r in results
            ]

        elif doc_type == "question_sql":
            # Phase α.4.A : propager user (Phase 5.1 a déjà ajouté le param).
            results = await training_store.get_similar_question_sql(query, n_results=5, user=user)
            items = [
                {
                    "id": r["id"],
                    "question": r["question"],
                    "sql": r["sql"],
                    "score": round(r["score"], 3),
                }
                for r in results
            ]

        else:
            return {"success": False, "error": f"Unknown doc_type: {doc_type}"}

        logger.info(
            "search_documentation: results returned",
            extra={"doc_type": doc_type, "query": query[:60], "count": len(items)},
        )

        return {
            "success": True,
            "doc_type": doc_type,
            "query": query,
            "result_count": len(items),
            "results": items,
        }

    except Exception as exc:
        logger.warning("search_documentation failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de la recherche documentaire."}


async def _handle_ask_user_clarification(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict:
    """
    Store a clarification request in context for the WebSocket layer to relay to the user.
    The agent's turn ends here — the answer will arrive as the next user message.
    """
    question: str = tool_input["question"]
    options: Optional[List[str]] = tool_input.get("options")

    # Dé-anonymisation : le LLM voit les valeurs BDD anonymisées (ex: ~XXX,
    # fragments tronqués) et peut les glisser dans la question ou les
    # options. L'utilisateur, lui, doit voir les valeurs réelles. On
    # restaure AVANT de pousser dans le context (qui est consommé par la
    # couche WebSocket et l'UI). Fail-safe : si la restauration échoue
    # (service indisponible), on garde les valeurs brutes — mieux vaut
    # afficher ~XXX que crasher la boucle de clarification.
    question = await _restore_for_user_safe(question)
    options = await _restore_options_for_user_safe(options)

    clarification_request = {
        "type": "clarification_request",
        "question": question,
        "options": options or [],
    }

    if "clarification_requests" not in context:
        context["clarification_requests"] = []
    context["clarification_requests"].append(clarification_request)

    logger.info(
        "ask_user_clarification: request queued",
        extra={"question_preview": question[:80], "user_id": getattr(user, "id", None)},
    )

    response: Dict[str, Any] = {
        "success": True,
        "status": "pending",
        "note": "Clarification request sent to user. Wait for their reply before continuing.",
    }

    # Soft-nudge : si un SQL validé est associé à cette conversation
    # (déjà-vu re-scoré ≥ 0.50) ET la question porte sur une valeur
    # déjà filtrée par ce SQL, signaler la redondance au LLM. Pas un
    # hard-block — l'utilisateur peut légitimement vouloir changer de
    # scope (autre périmètre). Le nudge donne au LLM l'info pour qu'il
    # puisse décider AU PROCHAIN TOUR : utiliser la valeur du SQL
    # validé directement, ou attendre la réponse.
    #
    # Anti-2+2=4 : aucune liste de mots-clés métier hardcodée. On
    # tokenise la question et on exige UNE DOUBLE CORRESPONDANCE pour
    # éviter les faux-positifs (un nom de colonne court comme « code »
    # ou « type » apparaît dans des questions sans rapport avec le
    # scope) :
    #
    # 1) au moins UN token significatif de la colonne dans la question,
    # 2) ET au moins UN token de la valeur (ou la valeur en substring
    #    pour les valeurs courtes) dans la question.
    #
    # Sans la condition (2), une question « De quel type de rapport
    # parles-tu ? » matcherait toute colonne contenant le mot
    # « type », même si la valeur du SQL n'a aucun rapport avec le
    # propos de l'utilisateur.
    sql_scope = context.get("_validated_sql_scope") or {}
    if sql_scope and isinstance(sql_scope, dict):
        try:
            from app.services.ai.training_store import SimpleTextSearch

            q_lower = (question or "").lower()
            q_tokens = set(SimpleTextSearch.tokenize(question or ""))
            redundant_hits: list[str] = []
            for col, vals in sql_scope.items():
                col_tokens = set(SimpleTextSearch.tokenize(str(col)))
                # ex : la question évoque le concept couvert par
                # ``<colName>`` alors que le SQL filtre déjà sur
                # ``<colName>=<value>``. La double-condition (col +
                # value) plus bas évite les faux-positifs sur tokens
                # courts génériques (« code », « type », « date »).
                col_matches_question = bool(col_tokens & q_tokens) or (str(col).lower() in q_lower)
                if not col_matches_question:
                    continue
                # Condition (2) : au moins UNE valeur du scope doit
                # être référencée (token ou substring) dans la
                # question, sinon on ne peut pas affirmer qu'elle est
                # redondante avec le SQL validé.
                value_match = False
                for v in vals or []:
                    if v is None:
                        continue
                    v_str = str(v)
                    if not v_str:
                        continue
                    v_tokens = set(SimpleTextSearch.tokenize(v_str))
                    if v_tokens & q_tokens or v_str.lower() in q_lower:
                        value_match = True
                        break
                if not value_match:
                    continue
                vals_str = ", ".join(f"'{v}'" for v in (vals or [])[:5] if v is not None)
                if vals_str:
                    redundant_hits.append(f"{col} = {vals_str}")
            if redundant_hits:
                response["_sql_scope_hint"] = (
                    "Le SQL validé associé à cette conversation contient "
                    "déjà ces filtres : "
                    + " ; ".join(redundant_hits)
                    + ". Si l'utilisateur ne demande pas explicitement de "
                    "changer ces valeurs, tu peux les réutiliser sans "
                    "attendre la réponse. Si la question portait sur ces "
                    "valeurs, considère ne PAS la reposer au tour suivant."
                )
        except Exception as _scope_err:
            logger.debug("ask_user_clarification scope hint skipped: %s", _scope_err)

    return response


async def _handle_save_to_datastore(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """
    Save a previously executed query result (by search_id) to the user's datastore.
    The actual data is retrieved from context — never from the agent.
    """
    try:
        search_id: int = int(tool_input["search_id"])
    except (ValueError, TypeError, KeyError):
        return {"success": False, "error": "search_id invalide ou manquant."}
    filename: str = tool_input["filename"]
    fmt: str = tool_input["format"]
    # Dé-anonymisation : le LLM peut avoir inclus des fragments ~XXX
    # dans le filename (il voit les valeurs BDD obfusquées). Le nom
    # affiché à l'utilisateur doit être lisible.
    filename = await _restore_for_user_safe(filename)

    pending = context.get("pending_results", [])
    if search_id < 0 or search_id >= len(pending):
        return {
            "success": False,
            "error": f"No query result found for search_id={search_id}.",
        }

    query_result = pending[search_id]
    data = query_result.get("data", [])

    try:
        if fmt == "csv":
            file_content, mime = _serialize_csv(data, query_result["columns"])
            ext = "csv"
        elif fmt == "excel":
            file_content, mime = _serialize_excel(data, query_result["columns"])
            ext = "xlsx"
        else:
            return {"success": False, "error": f"Unsupported format: {fmt}"}

        safe_name = f"{filename}.{ext}"

        # Store save task in context for the handler to persist to disk / DB
        if "datastore_saves" not in context:
            context["datastore_saves"] = []
        context["datastore_saves"].append(
            {
                "filename": safe_name,
                "content": file_content,
                "mime": mime,
                "row_count": len(data),
                "user_id": getattr(user, "id", None),
            }
        )

        logger.info(
            "save_to_datastore: file queued for save",
            extra={
                "saved_filename": safe_name,
                "rows": len(data),
                "user_id": getattr(user, "id", None),
            },
        )

        return {
            "success": True,
            "filename": safe_name,
            "row_count": len(data),
            "format": fmt,
            "note": "File queued for storage in your datastore.",
        }

    except Exception as exc:
        logger.warning("save_to_datastore failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de la sauvegarde dans le datastore."}


def _serialize_csv(data: List[Dict[str, Any]], columns: List[str]) -> tuple:
    """Sérialise ``data`` en CSV via le service unifié — bytes UTF-8 BOM
    avec sanitisation OWASP-CSV-Injection sur headers ET valeurs."""
    from app.services.export.csv_export import to_csv_bytes

    return to_csv_bytes(data, columns=columns), "text/csv"


def _serialize_excel(data: List[Dict[str, Any]], columns: List[str]) -> tuple:
    import io

    try:
        import openpyxl

        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(columns)
        for row in data:
            ws.append([row.get(col) for col in columns])
        buf = io.BytesIO()
        wb.save(buf)
        return (
            buf.getvalue(),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    except ImportError:
        # Fallback to CSV if openpyxl not available
        logger.warning("openpyxl not available, falling back to CSV for Excel export")
        return _serialize_csv(data, columns)


async def _handle_create_report(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """
    Generate a PDF/Excel/CSV report from a SQL query.
    The report file is stored server-side and a download link is queued for the user.
    """
    title: str = tool_input["title"]
    sql: str = tool_input["sql"]
    fmt: str = tool_input["format"]
    include_charts: bool = bool(tool_input.get("include_charts", False))
    # Dé-anonymisation du titre — affiché à l'utilisateur dans la notif
    # "📄 Rapport « TITRE » en cours de sauvegarde…". Si le LLM a
    # inclus des fragments ~XXX, l'utilisateur doit voir le réel.
    title = await _restore_for_user_safe(title)

    # ── Validate SQL columns before execution ──
    # ``_oracle_marker`` : out-param posé par le wrapper quand l'oracle SGBD
    # était injoignable (fail-open) — le rapport est un artefact user-facing,
    # le marqueur « non pré-validé » DOIT le suivre (contrat validate_for_iris).
    _oracle_marker: Dict[str, Any] = {}
    try:
        validation_error = await _validate_sql_columns(sql, user=user, marker_out=_oracle_marker)
    except Exception as ve:
        logger.warning("Column validation error in create_report (query allowed): %s", ve)
        validation_error = None

    if validation_error:
        # ``validation_error`` est le dict Proof.to_tool_result() — extraire
        # la STRING pour _classify_sql_error (qui fait .lower() ; lui passer
        # le dict crashait en AttributeError → « Erreur interne » opaque au
        # lieu du refus actionnable, p.ex. ORACLE_UNAVAILABLE en fail-closed).
        err_msg = (
            validation_error.get("error")
            if isinstance(validation_error, dict)
            else str(validation_error)
        ) or "SQL rejeté par la validation."
        response: Dict[str, Any] = {
            "success": False,
            "error": err_msg,
            "hint": _classify_sql_error(err_msg),
        }
        if isinstance(validation_error, dict):
            if validation_error.get("blocked_by"):
                response["blocked_by"] = validation_error["blocked_by"]
            if validation_error.get("proof"):
                response["proof"] = validation_error["proof"]
        return response

    executor = get_query_executor()

    try:
        # max_rows=None → utilise le cap admin (cf. doctrine
        # /admin/database). Avant on hardcodait 1000 ce qui tronquait
        # silencieusement les rapports PDF/Excel à 1000 lignes même
        # si l'admin avait configuré 50000 (incident 2026-05-20).
        # ``add_limit=True`` (default) : un TOP N est injecté côté SQL
        # Server, évitant un scan + transfert réseau complet pour ensuite
        # drainer 99% des rows côté pyodbc (perf review 2026-05-20
        # CRITICAL #4). Le hard cap applicatif s'applique aussi.
        result = await executor.execute(sql, max_rows=None, user=user, rls_source="create_report")
        data = result.to_dicts()

        if fmt == "pdf":
            file_content, mime, ext = await _generate_pdf_report(title, data, user, include_charts)
        elif fmt == "excel":
            file_content, mime = _serialize_excel(data, result.columns)
            ext = "xlsx"
        elif fmt == "csv":
            file_content, mime = _serialize_csv(data, result.columns)
            ext = "csv"
        else:
            return {"success": False, "error": f"Unsupported format: {fmt}"}

        safe_name = _safe_filename(title, ext)

        if "report_saves" not in context:
            context["report_saves"] = []
        context["report_saves"].append(
            {
                "title": title,
                "filename": safe_name,
                "content": file_content,
                "mime": mime,
                "format": fmt,
                "row_count": len(data),
                "user_id": getattr(user, "id", None),
                # Clé ADDITIVE (posée uniquement quand False) : forwardée par
                # l'event ``report_ready`` → avertissement sur la carte rapport.
                **(
                    {"oracle_prevalidated": False}
                    if _oracle_marker.get("oracle_prevalidated") is False
                    else {}
                ),
            }
        )

        logger.info(
            "create_report: report queued",
            extra={
                "title": title,
                "format": fmt,
                "rows": len(data),
                "user_id": getattr(user, "id", None),
            },
        )

        response = {
            "success": True,
            "title": title,
            "filename": safe_name,
            "format": fmt,
            "row_count": len(data),
            "note": "Report generated and queued for download.",
        }
        if _oracle_marker.get("oracle_prevalidated") is False:
            from app.services.ai.sql_validator import ORACLE_NOT_PREVALIDATED_WARNING

            response["oracle_prevalidated"] = False
            response["oracle_warning"] = (
                "⚠️ " + ORACLE_NOT_PREVALIDATED_WARNING + " Mentionne-le à "
                "l'utilisateur en présentant ce rapport."
            )
        return response

    except Exception as exc:
        logger.warning("create_report failed: %s", exc, exc_info=True)
        hint = _classify_sql_error(str(exc))
        return {
            "success": False,
            "error": f"Échec de la génération du rapport : {hint}",
            "hint": hint,
        }


async def _generate_pdf_report(
    title: str,
    data: List[Dict[str, Any]],
    user: Any,
    include_charts: bool,
    description: Optional[str] = None,
    analysis_text: Optional[str] = None,
    chart_config: Optional[Dict[str, Any]] = None,
) -> tuple:
    """Generate PDF bytes using PDFGenerator."""
    import tempfile
    from pathlib import Path
    from app.services.reporting.pdf_generator import PDFGenerator

    # Si l'user a une company.name distincte (multi-tenant éventuel), on
    # l'utilise. Sinon ``PDFGenerator`` lit ``branding.get_company_name``
    # (config admin globale) — pas de hardcode "Cabinet Comptable" ici.
    generator = PDFGenerator(company_name=getattr(getattr(user, "company", None), "name", None))

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    generator.generate_from_query_result(
        output_path=tmp_path,
        title=title,
        description=description,
        results=data,
        include_chart=include_charts,
        chart_config=chart_config,
        include_analysis=bool(analysis_text),
        analysis_text=analysis_text,
    )

    content = tmp_path.read_bytes()
    tmp_path.unlink(missing_ok=True)
    return content, "application/pdf", "pdf"


async def _handle_create_report_from_results(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict:
    """
    Generate a report from existing query results (pending_results).

    Uses the same search_id pattern as save_to_datastore.
    For PDF: runs ReportAnalyzer (detect_trends/anomalies programmatically)
    on the real data, then de-anonymizes the LLM's analysis text and includes
    both in the final PDF alongside real data.
    """
    # ── Parse input (same pattern as save_to_datastore) ──
    try:
        search_id = int(tool_input["search_id"])
    except (ValueError, TypeError, KeyError):
        return {"success": False, "error": "search_id invalide ou manquant."}

    title: str = tool_input["title"]
    description: str = tool_input.get("description", "")
    analysis: str = tool_input.get("analysis", "")
    fmt: str = tool_input["format"]
    chart_type: str = tool_input.get("chart_type", "")
    chart_x: str = tool_input.get("chart_x_column", "")
    chart_y: str = tool_input.get("chart_y_column", "")
    # Dé-anonymisation des champs visibles par l'utilisateur (titre,
    # description, analyse). Ils sont inclus dans le PDF final et
    # parfois notifiés dans le chat — le LLM peut avoir inséré des
    # fragments ~XXX qu'il faut restaurer avant affichage.
    title = await _restore_for_user_safe(title)
    description = await _restore_for_user_safe(description)
    analysis = await _restore_for_user_safe(analysis)

    # ── Get real data from pending_results (same as save_to_datastore) ──
    pending = context.get("pending_results", [])
    if search_id < 0 or search_id >= len(pending):
        return {
            "success": False,
            "error": f"No query result found for search_id={search_id}.",
        }

    result_entry = pending[search_id]
    data = result_entry.get("data", [])
    columns = result_entry.get("columns", [])

    if not data:
        return {
            "success": False,
            "error": "Les resultats de la requete sont vides.",
        }

    # ── Build analysis text ──
    # 1. Programmatic: ReportAnalyzer detects trends/anomalies on REAL data
    #    (no LLM call — pure statistical analysis, no confidentiality issue)
    # 2. LLM analysis: de-anonymize the text the LLM wrote using ~tokens
    # 3. Combine both into a single analysis section
    final_analysis = ""

    try:
        if fmt == "pdf":
            from app.services.reporting.report_analyzer import ReportAnalyzer

            analyzer = ReportAnalyzer()

            # Programmatic trend/anomaly detection on real data (no LLM, safe)
            trends = analyzer.detect_trends(data)
            anomalies = analyzer.detect_anomalies(data)
            stats_analysis = analyzer._generate_fallback_analysis(trends, anomalies)

            # De-anonymize the LLM's analysis text if provided
            llm_analysis = ""
            if analysis:
                from app.services.anonymization.strategies import get_confidentiality_manager

                cm = get_confidentiality_manager()

                # Restore PII placeholders from session mapping
                pii_mapping = context.get("pii_mapping", {})
                if pii_mapping:
                    analysis = cm.restore_response(analysis, pii_mapping)

                # Restore ~tokens from ValueMapping database
                llm_analysis = await cm.restore_anonymized_values(analysis)

            # Combine: LLM analysis first (richer), stats as complement
            if llm_analysis and stats_analysis:
                final_analysis = llm_analysis + "\n\n" + stats_analysis
            elif llm_analysis:
                final_analysis = llm_analysis
            else:
                final_analysis = stats_analysis

    except Exception as e:
        logger.warning("Report analysis generation failed (non-fatal): %s", e)
        # Non-fatal: report still generated without analysis

    # ── Generate the report ──
    try:
        if fmt == "pdf":
            chart_config = None
            include_chart = bool(chart_type and chart_x and chart_y)

            # Validate chart columns exist in the data
            if include_chart:
                if chart_x not in columns or chart_y not in columns:
                    missing = chart_x if chart_x not in columns else chart_y
                    return {
                        "success": False,
                        "error": (
                            f"Colonne '{missing}' introuvable. "
                            f"Colonnes disponibles : {', '.join(columns)}"
                        ),
                    }
                chart_config = {
                    "chart_type": chart_type if chart_type != "auto" else None,
                    "x_column": chart_x,
                    "y_column": chart_y,
                }

            # Reuse the same _generate_pdf_report function (extended with new params)
            file_content, mime, ext = await _generate_pdf_report(
                title=title,
                data=data,
                user=user,
                include_charts=include_chart,
                description=description or None,
                analysis_text=final_analysis or None,
                chart_config=chart_config,
            )
        elif fmt == "excel":
            file_content, mime = _serialize_excel(data, columns)
            ext = "xlsx"
        elif fmt == "csv":
            file_content, mime = _serialize_csv(data, columns)
            ext = "csv"
        else:
            return {"success": False, "error": f"Format non supporte : {fmt}"}

        safe_name = _safe_filename(title, ext)

        # Queue for persistence (same pattern as create_report and save_to_datastore)
        if "report_saves" not in context:
            context["report_saves"] = []
        context["report_saves"].append(
            {
                "title": title,
                "filename": safe_name,
                "content": file_content,
                "mime": mime,
                "format": fmt,
                "row_count": len(data),
                "user_id": getattr(user, "id", None),
            }
        )

        logger.info(
            "create_report_from_results: report queued",
            extra={
                "title": title,
                "format": fmt,
                "rows": len(data),
                "search_id": search_id,
                "has_analysis": bool(final_analysis),
            },
        )

        return {
            "success": True,
            "title": title,
            "filename": safe_name,
            "format": fmt,
            "row_count": len(data),
            "has_analysis": bool(final_analysis),
            "note": "Rapport genere a partir du classeur.",
        }

    except Exception as exc:
        logger.warning("create_report_from_results failed: %s", exc, exc_info=True)
        return {
            "success": False,
            "error": "Echec de la generation du rapport. Verifiez le format et les donnees.",
        }


def _safe_filename(title: str, ext: str) -> str:
    """Convert a report title to a safe filesystem filename."""
    import re

    safe = re.sub(r"[^\w\s\-]", "", title, flags=re.UNICODE)
    safe = re.sub(r"\s+", "_", safe.strip())
    return f"{safe[:80]}.{ext}"


# ------------------------------------------------------------------
# Phase 2 — New agent tool handlers
# ------------------------------------------------------------------


async def _handle_analyze_query_performance(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict:
    """Analyze SQL query performance using SET SHOWPLAN_TEXT."""
    sql: str = tool_input["sql"]
    include_plan: bool = bool(tool_input.get("include_plan", True))

    try:
        suggestions = []
        plan_text = None

        if include_plan:
            # Get estimated execution plan — use separate SET statements
            # to avoid SQL injection (sql is NOT interpolated into the plan
            # query; we run SET SHOWPLAN_TEXT ON, then the original query
            # separately, so the executor handles parameterization).
            try:
                # SQL Server: SET SHOWPLAN_TEXT only works as a session
                # setting. We run the query in explain-only mode.
                from app.services.database.query_executor import get_query_executor

                plan_executor = get_query_executor()
                plan_result = await plan_executor.execute_plan(sql)
                plan_text = plan_result if isinstance(plan_result, str) else str(plan_result)
            except AttributeError:
                # execute_plan not available — fall back to static analysis
                plan_text = (
                    "Plan d'exécution non disponible " "(méthode execute_plan non implémentée)."
                )
            except Exception:
                plan_text = "Impossible de récupérer le plan d'exécution."

        # Analyze SQL for common performance issues
        sql_upper = sql.upper()
        if "SELECT *" in sql_upper:
            suggestions.append("Évitez SELECT * — listez les colonnes nécessaires.")
        if "WHERE" not in sql_upper:
            suggestions.append("Aucune clause WHERE — la requête scanne toute la table.")
        if sql_upper.count("JOIN") > 3:
            suggestions.append(
                f"{sql_upper.count('JOIN')} JOIN détectés — "
                "vérifiez que chaque jointure est nécessaire."
            )
        if "LIKE '%'" in sql_upper or "LIKE '%" in sql_upper:
            suggestions.append("LIKE avec wildcard en début empêche l'utilisation d'index.")
        if "ORDER BY" in sql_upper and "TOP" not in sql_upper:
            suggestions.append(
                "ORDER BY sans TOP/LIMIT peut être coûteux sur de " "grands résultats."
            )
        if "DISTINCT" in sql_upper:
            suggestions.append("DISTINCT peut masquer un problème de jointure (doublons).")

        return {
            "success": True,
            "execution_plan": plan_text,
            "suggestions": suggestions,
            "suggestion_count": len(suggestions),
        }

    except Exception as exc:
        logger.warning("analyze_query_performance failed: %s", exc, exc_info=True)
        return {
            "success": False,
            "error": "Échec de l'analyse de performance.",
        }


# _handle_save_user_query supprime — cf. decision « casse net SavedQuery »
# (2026-05-05). L'agent passe maintenant par `save_to_datastore` pour
# persister une requete sous forme de fichier .sql.


async def _handle_schedule_task(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Create a scheduled automation task."""
    from app.core.database import get_session
    from app.models.automation import Automation

    name: str = tool_input["name"]
    query_text: str = tool_input["query_text"]
    query_type: str = tool_input.get("query_type", "nl")
    schedule_type: str = tool_input["schedule_type"]
    schedule_config: dict = tool_input.get("schedule_config", {})
    output_format: str = tool_input.get("output_format", "excel")
    recipients: list = tool_input.get("recipients", [])

    try:
        import json as _json

        async with get_session() as session:
            automation = Automation(
                user_id=user.id,
                name=name,
                description=f"Créé par Iris: {query_text[:100]}",
                query_type=query_type,
                query_text=query_text,
                schedule_type=schedule_type,
                schedule_config=_json.dumps(schedule_config),
                output_format=output_format,
                recipients=_json.dumps(recipients),
                is_active=True,
            )
            session.add(automation)
            await session.commit()
            auto_id = automation.id

        logger.info(
            "schedule_task: automation created",
            extra={"automation_id": auto_id, "user_id": user.id},
        )
        return {
            "success": True,
            "automation_id": auto_id,
            "name": name,
            "schedule_type": schedule_type,
            "note": f"Tâche planifiée '{name}' créée ({schedule_type}).",
        }

    except Exception as exc:
        logger.warning("schedule_task failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de la création de la tâche planifiée."}


# ---------------------------------------------------------------------------
# Anonymisation des tool_result des outils workbook upload Iris
# (CRIT-3 adversarial review 2026-05-26).
#
# Avant ce fix, ``_handle_analyze_attachment`` / ``_handle_read_workbook_rows``
# / ``_handle_quick_overview_workbook`` / ``_handle_aggregate_workbook`` /
# ``_handle_list_workbook_tabs`` retournaient ``sample_rows``,
# ``columns_summary``, ``cells``, ``numeric_stats`` SANS passer par
# ``anonymize_for_llm``. Les commentaires affirmaient à tort que
# « l'anonymisation est appliquée ensuite » — il n'existe pas de couche
# d'anonymisation systématique sur les ``tool_result`` dans le runtime
# agent (`agent_service.py`). Conséquence : pour un Excel > 200 Ko (qui
# bypass le ``_file_hint`` inline déjà anonymisé Task #36), les valeurs
# brutes (noms clients, IBAN, montants individuels) partaient au LLM
# cloud et dans ``llm_log.md`` en clair.
#
# Fix : helper unique appelé en fin de chaque tool workbook concerné.
# ``anonymize_for_llm`` est récursif et idempotent — il n'altère pas
# les keys de dict (= colonnes structurelles), seulement les valeurs
# strings. Précédence : PII regex (EMAIL/SIRET/IBAN/...) > pseudonymizer
# user. Cf. ``app/services/anonymization/proxy.py`` lignes 294+.
# ---------------------------------------------------------------------------


async def _anonymize_workbook_tool_result(result: Dict[str, Any], user: Any) -> Dict[str, Any]:
    """Anonymise les valeurs d'un ``tool_result`` workbook upload avant
    retour au LLM.

    Idempotent et défensif : si l'anonymisation lève (panne du moteur PII /
    BDD pseudonymizer), on **fail-closed** en remplaçant les zones
    sensibles par un placeholder. Doctrine Komptia : jamais cleartext
    silencieux quand l'anonymisation devrait être active.

    Args:
        result: dict retourné par un ``_handle_*_workbook_*`` ou
            ``_handle_analyze_attachment``. Modifié non-mutatif (copy
            via la récursion de ``anonymize_for_llm``).
        user: objet user (a ``.id``). Si None → on skip pseudonymizer
            (PII regex toujours appliquée).

    Returns:
        Le dict anonymisé. ``result["success"]``, ``result["error"]``,
        ``result["file_id"]`` et les autres champs structurels restent
        intacts (les keys ne sont pas touchées par ``anonymize_for_llm``).

    Note :
        Le ``restore_fn`` retourné par ``anonymize_for_llm`` n'est PAS
        gardé — la convention Komptia pour les ``tool_result`` au LLM
        d'analyse est unidirectionnelle (le LLM ne renvoie pas les
        tokens dans un contexte attendu par le runtime).
    """
    if not isinstance(result, dict):
        return result
    # Ne rien faire si erreur — pas de données utilisateur sensibles
    # dans un payload d'erreur (juste un message Komptia générique).
    if result.get("error") or result.get("success") is False:
        return result

    user_id = getattr(user, "id", None)
    # Étape 1 — anonymisation complète (PII regex + pseudonymizer user).
    # Si la BDD est down ou non-init (tests), on tombe en étape 2.
    try:
        from app.services.anonymization import anonymize_for_llm

        anonymized, _restore = await anonymize_for_llm(user_id, result, "IRIS_CHAT")
        if isinstance(anonymized, dict):
            return anonymized
        return result
    except Exception as full_exc:
        logger.warning(
            "Anonymisation complète tool_result KO — fallback PII-only: %s",
            full_exc,
        )

    # Étape 2 — PII-only fallback (regex seule, pas de BDD requise).
    # Couvre EMAIL/PHONE/SIRET/SIREN/IBAN/AMOUNT — suffit pour la majorité
    # des fuites usuelles. Le pseudonymizer user manque (pas de tokens
    # `§…§` pour les termes /data-privacy), mais aucune donnée brute en
    # clair non plus.
    try:
        from app.services.anonymization.proxy import _pii_anonymize_recursive

        pii_mapping: Dict[str, str] = {}
        pii_counters: Dict[str, int] = {}
        return _pii_anonymize_recursive(result, pii_mapping, pii_counters)
    except Exception as pii_exc:
        logger.error(
            "PII-only fallback aussi KO (fail-closed): %s",
            pii_exc,
            exc_info=True,
        )

    # Étape 3 — Fail-closed final : remplace les payloads à risque par un
    # placeholder. Le LLM verra une erreur claire plutôt que des données
    # en clair. N'arrive QUE si même la PII regex (pure Python) crash.
    safe_result = dict(result)
    for risky_key in (
        "sample_rows",
        "rows",
        "cells",
        "values",
        "columns_summary",
        "numeric_stats",
        "tabs",
    ):
        if risky_key in safe_result:
            safe_result[risky_key] = f"[ANONYMIZATION_FAILED — contenu masqué fail-closed]"
    return safe_result


async def _handle_analyze_attachment(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Analyze an uploaded CSV/Excel file.

    REFACTOR 2026-05-26 (P2.4 task #15) — Alias de ``quick_overview_workbook``
    qui adapte la sortie au format historique ``analyze_attachment`` pour
    rétrocompatibilité ascendante (tests + prompts existants).

    Avant le refactor : double path de lecture (pandas direct ici vs
    ``_build_tabs_context_from_upload`` côté workbook tools). Maintenant :
    une seule lecture pandas via le cache ``file_info['_built_tabs']``,
    réutilisée par TOUS les outils de lecture/analyse upload (P2.1 + P2.2 +
    P2.3 + P2.4). Doctrine SSoT respectée.

    Format de retour préservé : ``filename``, ``row_count``, ``column_count``,
    ``columns: [{name, dtype, null_count, unique_count}]``, ``sample_rows``,
    ``numeric_stats``. Note : ``memory_mb`` retiré (pas dispo via tabs_context
    format ; non utilisé en pratique). ``dtype`` change de notation pandas
    (``int64``, ``float64``, ``object``) à notation type_hint Komptia
    (``int``, ``float``, ``str``, ``numeric``, ``mixed:...``). ``unique_count``
    devient ``unique_count_capped`` (limité à 20 — protection anti-OOM sur
    colonnes high-cardinality).
    """
    file_id = tool_input.get("file_id")
    built, err = await _resolve_workbook_for_read(file_id, user, context)
    if err:
        # Compat ascendante : message historique « introuvable »
        return {"success": False, "error": err}

    uploads = context.get("uploads", {}) or {}
    file_info = uploads.get(file_id) or {}
    filename = file_info.get("filename", "unknown")

    overview = _quick_overview_from_tabs(
        built["tabs_context"],
        filename=filename,
        active_sheet_content=built.get("sheet_content"),
    )

    if not overview["tabs"]:
        return {"success": False, "error": "Aucun onglet analysable dans le fichier."}

    # Sélectionne le premier onglet (matérialisé en priorité — historiquement
    # ``pd.read_excel`` sans ``sheet_name`` retournait sheet[0] uniquement).
    first_tab = overview["tabs"][0]
    if not first_tab.get("stats_available"):
        # Avec active_sheet_content passé ci-dessus, on n'arrive ici que si
        # le premier onglet est réellement sans cellules (classeur vide).
        return {
            "success": False,
            "error": (
                "Le premier onglet ne contient aucune cellule exploitable "
                "(classeur vide ?). Utilise list_workbook_tabs pour vérifier "
                "la structure des onglets."
            ),
        }

    # Map vers format historique
    result: Dict[str, Any] = {
        "success": True,
        "filename": filename,
        "row_count": first_tab["row_count"],
        "column_count": first_tab["column_count"],
        "columns": [
            {
                "name": c["name"],
                "dtype": c["type_hint"],
                "null_count": c["null_count"],
                # Compat : champ historique ``unique_count`` mais flag explicite
                # ``unique_capped_at`` si overflow pour que le LLM ne tire pas
                # de conclusions fausses sur la cardinalité réelle.
                "unique_count": c["unique_count_capped"],
            }
            for c in first_tab.get("columns_summary", [])
        ],
        "sample_rows": first_tab.get("sample_rows", []),
    }

    # Flag overflow agrégé pour transparence
    if any(c.get("unique_overflow") for c in first_tab.get("columns_summary", [])):
        result["unique_count_capped_at"] = _QUICK_OVERVIEW_UNIQUE_CAP

    # numeric_stats au format historique (dict {col_name: {min, max, sum, mean, count}})
    numeric_stats = {
        c["name"]: c["numeric_stats"]
        for c in first_tab.get("columns_summary", [])
        if "numeric_stats" in c
    }
    if numeric_stats:
        result["numeric_stats"] = numeric_stats

    trunc_note = _upload_truncation_note(built)
    if trunc_note:
        result["truncated_note"] = trunc_note

    # Multi-sheet hint
    if overview["tab_count"] > 1:
        non_active = [t["label"] for t in overview["tabs"][1:]]
        result["multi_sheet_note"] = (
            f"Excel multi-onglets ({overview['tab_count']} total). Analyse "
            f"détaillée du premier onglet « {first_tab['label']} » uniquement. "
            f"Autres onglets : {', '.join(non_active[:5])}"
            f"{'…' if len(non_active) > 5 else ''}. Utilise "
            "`list_workbook_tabs` + `quick_overview_workbook(file_id)` pour "
            "explorer les autres."
        )

    # CRIT-3 — anonymise les valeurs sensibles AVANT retour LLM
    return await _anonymize_workbook_tool_result(result, user)


# ---------------------------------------------------------------------------
# Plafond de cellules envoyées à copilot pour un upload. Au-delà, on tronque
# avec un message explicite — la tabs_context envoyée au LLM doit rester
# bornée (chaque cellule = ~30-80 tokens en JSON sparse, donc 20k cellules
# ≈ 600k-1.6M tokens, hors-limite).
#
# 20 000 cellules ≈ 200 lignes × 100 colonnes ou 2000 lignes × 10 colonnes,
# largement suffisant pour les classeurs typiques d'un cabinet. Pour les
# fichiers plus gros, le user doit segmenter manuellement ou utiliser SQL.
# Pas de constante dans `constants_ai.py` car spécifique à ce handler.
_UPLOAD_MAX_CELLS_FOR_COPILOT: int = 20_000


# ---------------------------------------------------------------------------
# Patterns de prompt-injection à détecter dans une instruction user-passée-au-LLM
# (transform_uploaded_file). DETECTION ONLY — on ne bloque PAS le run et on ne
# modifie PAS l'instruction (préserve l'intent légitime, évite les faux positifs).
# Le but est d'alimenter les logs d'audit pour qu'un admin puisse identifier
# a posteriori les abus / tentatives d'injection.
#
# Liste minimale, centrée sur les signatures jailbreak / role hijack les plus
# courantes (ChatGPT/Claude/Llama 2024-2026). Case-insensitive matching.
# Cf. adversarial review M1 du 2026-05-26 + task #18 de la todo Komptia.
#
# Si tu ajoutes un pattern : (a) doit être un signal FORT (pas un mot anodin),
# (b) documente le pourquoi, (c) test associé dans
# ``tests/unit/test_iris_transform_uploaded_file.py`` (task #10).
_PROMPT_INJECTION_PATTERNS: tuple[tuple[str, str], ...] = (
    ("ignore previous", "directive hijack — tentative de bypass du system prompt"),
    ("ignore your system", "directive hijack — tentative de bypass du system prompt"),
    ("ignore all instructions", "directive hijack — tentative de bypass complet"),
    ("disregard previous", "directive hijack — variante 'disregard'"),
    ("you are now", "role rewrite — tentative de redéfinir l'agent"),
    ("forget everything", "directive hijack — reset prompt"),
    ("system:", "role tag — injection d'un faux tour 'system'"),
    ("assistant:", "role tag — injection d'un faux tour 'assistant'"),
    ("</system>", "balise XML système — délimiteur de prompt"),
    ("<system>", "balise XML système — délimiteur de prompt"),
    ("[/inst]", "marker Llama-style fin instruction"),
    ("[inst]", "marker Llama-style début instruction"),
    ("<|im_end|>", "marker OpenAI ChatML fin message"),
    ("<|im_start|>", "marker OpenAI ChatML début message"),
    ("```system", "block markdown fake system"),
    # NB: pas d'entries pour "{{" / "${" car trop de faux positifs sur du
    # vrai contenu métier (formules Excel, syntaxe template légitime).
)

# Seuil au-delà duquel on logue WARN même sans pattern matché — instruction
# anormalement longue ≈ tentative de dilution. 1000 chars couvre toute
# instruction métier raisonnable (les vraies font 50-300 chars).
_INSTRUCTION_LONG_THRESHOLD: int = 1000


def _scan_instruction_for_injection_signals(instruction: str) -> List[str]:
    """Scanne une instruction et retourne la liste des patterns suspects matchés.

    Non-bloquant : caller logue les résultats mais continue le run. Préserve
    l'intent user (un coiffeur qui écrit *"Ignore previous totals"* pour
    décrire une transformation légitime ne doit pas être bloqué).

    Args:
        instruction: chaîne à scanner. Pas de normalisation NFKC ici (les
            attaques par homoglyphes sont rares dans ce contexte ; si besoin,
            réutiliser ``copilot_memory.sanitize_memory_for_prompt`` qui fait
            déjà NFKC + délimiteurs).

    Returns:
        Liste des descriptions de patterns matchés (vide si rien).
    """
    if not isinstance(instruction, str) or not instruction:
        return []
    lower = instruction.lower()
    return [desc for pattern, desc in _PROMPT_INJECTION_PATTERNS if pattern in lower]


def _build_tabs_context_from_upload(file_info: Dict[str, Any]) -> Dict[str, Any]:
    """Construit le couple ``tabs_context`` + ``sheet_content`` attendu par
    ``run_copilot_agent`` à partir d'un upload Iris (CSV ou Excel).

    Helper séparé du handler pour :

    * Permettre la réutilisation (Phase 2 du chantier upload-as-result —
      la session 2cbd7223 livrera potentiellement sa propre version, on
      pourra alors swap par un import sans casser le handler).
    * Tester unitairement sans monter un faux agent complet.

    Args:
        file_info: dict tel que stocké dans ``context["uploads"][file_id]``
            par ``_load_uploaded_file`` (agent_service.py). Contient au
            minimum ``type`` (csv/xlsx) et soit ``path`` (disque) soit
            ``content`` (bytes en mémoire).

    Returns:
        dict ``{tabs_context, sheet_content, truncated, total_cells}`` :
        - ``tabs_context`` : liste de 1 onglet par sheet, sans champ ``sql``
          (l'upload n'EST pas un résultat SQL), avec ``label``, ``row_count``,
          ``columns``, ``is_active``.
        - ``sheet_content`` : cellules sparse de l'onglet actif, format
          ``[{row, col, value}]`` (row 0 = headers, row 1+ = données).
        - ``truncated`` : True si on a tronqué pour rester sous
          ``_UPLOAD_MAX_CELLS_FOR_COPILOT``.
        - ``total_cells`` : nombre total de cellules avant troncation.

    Raises:
        ValueError: si ``file_info`` ne contient ni ``path`` ni ``content``,
            ou si le format n'est pas supporté.
    """
    import io

    try:
        import pandas as pd  # type: ignore[import-not-found]
    except ImportError as exc:
        # Pandas est requis pour parser CSV/Excel — même contrainte que
        # ``analyze_attachment``. Si la lib n'est pas installée dans
        # l'environnement (cas dev sans pandas, ou container minimal),
        # on retourne une erreur claire au lieu d'un crash opaque.
        raise ValueError(
            "pandas n'est pas installé — impossible de parser le fichier. "
            "Contacte l'admin pour ajouter pandas aux dépendances."
        ) from exc

    file_type = (file_info.get("type") or "csv").lower()
    file_path = file_info.get("path")
    file_bytes = file_info.get("content")

    if not file_path and not file_bytes:
        raise ValueError("upload sans path ni content (fichier introuvable)")

    # Lecture du fichier — multi-sheet pour Excel, single pour CSV.
    # On utilise un dict {sheet_name → DataFrame} dans les deux cas pour
    # garder un flow unifié downstream.
    if file_type in ("csv", "text/csv"):
        # Multi-encoding fallback : un CSV exporté par Sage / Excel Windows
        # arrive souvent en cp1252 / latin-1, pas UTF-8. Sans fallback,
        # ``pd.read_csv`` lève ``UnicodeDecodeError`` opaque côté user
        # (cf. adversarial review C2, 2026-05-26). On essaie dans l'ordre
        # de probabilité décroissante.
        df_main = None
        last_decode_err: Optional[Exception] = None
        for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
            try:
                src = file_path if file_path else io.BytesIO(file_bytes)
                df_main = pd.read_csv(src, encoding=encoding)
                break
            except UnicodeDecodeError as enc_exc:
                last_decode_err = enc_exc
                continue
            except pd.errors.ParserError as parse_exc:
                # CSV mal-quoté / colonnes inégales — pas un problème
                # d'encoding, message clair direct.
                raise ValueError(
                    f"CSV mal formé (parser pandas) : {parse_exc}. "
                    "Vérifie les délimiteurs et les guillemets."
                ) from parse_exc
        if df_main is None:
            raise ValueError(
                f"CSV illisible (encoding non détecté). Détail : {last_decode_err}. "
                "Sauvegarde le fichier en UTF-8 et re-uploade."
            )
        # CSV = "1 sheet" qu'on nomme du filename si dispo
        sheet_name = file_info.get("filename") or "data"
        sheets = {sheet_name: df_main}
    elif file_type in (
        "xlsx",
        "excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ):
        # ``sheet_name=None`` retourne un dict de tous les sheets — copilot
        # gère le multi-onglets nativement, on lui passe tout.
        if file_path:
            sheets_raw = pd.read_excel(file_path, sheet_name=None)
        else:
            sheets_raw = pd.read_excel(io.BytesIO(file_bytes), sheet_name=None)
        sheets = {str(name): df for name, df in sheets_raw.items()}
    else:
        raise ValueError(f"format non supporté: {file_type}")

    # Construction tabs_context. Pas de champ ``sql`` (upload != résultat SQL).
    # `row_count` inclut la ligne d'en-tête (= +1 par rapport au DataFrame).
    tabs_context: List[Dict[str, Any]] = []
    sheet_content: List[Dict[str, Any]] = []  # cellules de l'onglet actif uniquement
    active_cells = 0  # cellules matérialisées dans sheet_content (active uniquement)
    metadata_cells = 0  # cellules cumulées sur TOUS les onglets (info uniquement)
    truncated = False

    for tab_idx, (sheet_label, df) in enumerate(sheets.items()):
        is_active = tab_idx == 0
        columns = [str(c) for c in df.columns]
        tab_cells = (len(df) + 1) * len(df.columns)  # +1 pour la ligne header
        metadata_cells += tab_cells

        tab_entry: Dict[str, Any] = {
            "label": sheet_label,
            "row_count": len(df) + 1,
            "columns": columns,
            "is_active": is_active,
        }
        tabs_context.append(tab_entry)

        # On ne matérialise sheet_content QUE pour l'onglet actif (premier).
        # Les onglets non-actifs restent en metadata seul ; copilot peut
        # les lire à la demande via ses outils (list_tabs / read_tab_rows
        # côté copilot — mais ici on lui pré-charge l'actif pour zero-cost
        # immediate access).
        if not is_active:
            continue

        # Truncation calculée sur les cellules de l'ACTIF uniquement
        # (cf. adversarial review M4, 2026-05-26 — l'ancienne version
        # cumulait tous les onglets et tronquait à tort un actif petit
        # quand les onglets non-actifs gros faisaient déborder le budget).
        if tab_cells > _UPLOAD_MAX_CELLS_FOR_COPILOT:
            truncated = True
            # On garde uniquement les N premières lignes qui rentrent dans
            # le budget. -1 ligne pour le header déjà compté.
            n_cols = max(1, len(df.columns))
            budget_rows = max(1, (_UPLOAD_MAX_CELLS_FOR_COPILOT // n_cols) - 1)
            # Total ORIGINAL conservé AVANT troncation — sans lui, impossible
            # de signaler que stats/agrégats portent sur un sous-ensemble
            # (doctrine Q5 : un total partiel présenté comme complet = pire
            # mode de failure). Consommé par _upload_truncation_note +
            # _quick_overview_from_tabs + le front (légende « sur N »).
            tab_entry["row_count_original"] = len(df) + 1
            tab_entry["truncated"] = True
            df = df.head(budget_rows)
            # On corrige row_count dans l'entry pour refléter la troncation
            tab_entry["row_count"] = len(df) + 1

        active_cells = (len(df) + 1) * len(df.columns)

        # Headers (row 0). On utilise le NOM de colonne comme ``col`` (et non
        # l'index numérique) pour cohérence avec les cellules data ci-dessous
        # — ``_aggregate_core`` compare ``cell["col"] == value_column`` (un
        # string nom de colonne), donc index numérique = no-match silencieux.
        for col_name in columns:
            sheet_content.append({"row": 0, "col": col_name, "value": col_name})

        # Data (row 1+). Sparse : on skip les NaN/None (copilot infère
        # cellule vide). Astype object pour éviter les conversions pandas
        # qui changent les types (datetime → Timestamp non-sérialisable).
        #
        # IMPORTANT (P2.2 task #13, 2026-05-26) : on attache à CHAQUE cellule
        # un ``match`` synthétique = dict des autres valeurs de la même
        # ligne. Sans ça, ``_count_rows_core`` / ``_aggregate_core`` (qui
        # filtrent via ``sc_cell.get("match")``) skip TOUTE cellule sans
        # match → count/aggregate sur upload retourne 0 → outils
        # ``count_workbook_rows`` / ``aggregate_workbook`` cassés.
        # Pattern calqué sur ce que copilot fait en interne quand il crée un
        # onglet via emit_tab depuis un résultat SQL : chaque cellule de
        # mesure porte les valeurs de toutes les dimensions de sa row.
        # Pour un upload CSV/Excel, on ne distingue pas dimensions vs
        # mesures → chaque cellule porte toutes les autres colonnes en match.
        # Le ``row_match`` est partagé par référence entre les cellules d'une
        # même row — économise de la mémoire (1 dict par row, pas 1 par cell).
        # Sécurisé car aucun consumer downstream ne mute ce dict.
        for row_idx_zero_based, row_tuple in enumerate(df.itertuples(index=False, name=None)):
            row_idx = row_idx_zero_based + 1  # +1 pour skip le header en row 0
            serialized: List[Any] = []
            row_match: Dict[str, Any] = {}
            for col_idx, val in enumerate(row_tuple):
                if val is None or (isinstance(val, float) and pd.isna(val)):
                    serialized.append(None)
                    continue
                if isinstance(val, (bytes, bytearray)):
                    try:
                        val = bytes(val).decode("utf-8", errors="replace")
                    except Exception:
                        val = repr(val)[:200]
                elif not isinstance(val, (str, int, float, bool)):
                    val = str(val)
                serialized.append(val)
                row_match[columns[col_idx]] = val
            for col_idx, val in enumerate(serialized):
                if val is None:
                    continue
                sheet_content.append(
                    {
                        "row": row_idx,
                        "col": columns[col_idx],
                        "value": val,
                        "match": row_match,
                    }
                )

    # M3 : si multi-sheet, on remonte la liste des labels non-actifs pour
    # que le handler puisse en informer copilot/Iris (sinon copilot ne
    # "voit" pas les autres onglets et hallucinera ou abandonnera si
    # l'instruction porte sur un autre onglet).
    non_active_labels = [t["label"] for t in tabs_context if not t.get("is_active")]
    return {
        "tabs_context": tabs_context,
        "sheet_content": sheet_content,
        "truncated": truncated,
        "active_cells": active_cells,
        "metadata_cells": metadata_cells,
        "non_active_sheet_labels": non_active_labels,
    }


def _summarize_copilot_result_for_iris(copilot_result: Dict[str, Any]) -> Dict[str, Any]:
    """Convertit le résultat brut de ``run_copilot_agent`` en dict synthétique
    digérable par le LLM Iris.

    Le résultat copilot a une structure riche (``emits``, ``modifications``,
    ``metrics``, ``terminal_kind``, etc.) — un LLM Iris qui reçoit tout ça
    en clair serait noyé. On extrait l'essentiel : type terminal, compte
    onglets touchés, résumé FR si dispo.
    """
    if not isinstance(copilot_result, dict):
        return {
            "success": False,
            "type": "error",
            "summary": "Réponse copilot invalide (format inattendu).",
        }

    # C1 — Early-returns de ``run_copilot_agent`` (BDD anonymisation KO,
    # LLM manager indispo, instruction vide post-sanitize) retournent un
    # dict ``{"error": "..."}`` SANS champ ``type``. Avant ce check, le
    # handler les classait à tort comme ``type="unknown"`` → summary
    # générique qui masque la vraie cause (cf. adversarial review C1,
    # 2026-05-26). On détecte le shape ``{error}`` en premier et on
    # renvoie un ``type`` dédié non-retentable côté Iris.
    if "error" in copilot_result and "type" not in copilot_result:
        return {
            "success": False,
            "type": "copilot_init_error",
            "summary": (
                "Le copilot n'a pas pu démarrer le run : "
                f"{copilot_result.get('error')}. "
                "Ce n'est pas un échec de l'IA — vérifie la configuration "
                "(anonymisation /data-privacy, clé LLM via /admin/ai-config) "
                "ou contacte l'admin. Pas de retry automatique pertinent."
            ),
        }

    terminal_type = copilot_result.get("type", "unknown")
    emits = copilot_result.get("emits") or []
    modifications = copilot_result.get("modifications") or []
    emits_count = len(emits) if isinstance(emits, list) else 0
    mods_count = len(modifications) if isinstance(modifications, list) else 0
    # ``done`` peut contenir un ``summary`` rédigé par copilot lui-même
    # (cf. handle_done dans copilot_tools.py). Sinon on en construit un
    # générique depuis les counts.
    summary = copilot_result.get("summary")

    if terminal_type == "done":
        if not summary:
            if emits_count > 0 and mods_count > 0:
                summary = (
                    f"Transformation terminée. {emits_count} nouveau(x) onglet(s) "
                    f"créé(s), {mods_count} onglet(s) modifié(s)."
                )
            elif emits_count > 0:
                summary = f"Transformation terminée. {emits_count} nouveau(x) onglet(s) créé(s)."
            elif mods_count > 0:
                summary = f"Transformation terminée. {mods_count} onglet(s) modifié(s)."
            else:
                summary = (
                    "Copilot a terminé mais sans modification effective — "
                    "vérifie que l'instruction était bien explicite et exécutable."
                )
        return {
            "success": True,
            "type": "done",
            "summary": summary,
            "emits_count": emits_count,
            "modifications_count": mods_count,
        }

    if terminal_type == "abandon":
        return {
            "success": False,
            "type": "abandon",
            "summary": (
                "Copilot a jugé la demande infaisable : "
                f"{copilot_result.get('reason') or summary or 'raison non précisée'}."
            ),
            "emits_count": emits_count,
            "modifications_count": mods_count,
        }

    if terminal_type == "max_turns_reached":
        return {
            "success": False,
            "type": "max_turns_reached",
            "summary": (
                f"Copilot a atteint son budget de tours ({mods_count + emits_count} actions "
                "effectuées avant épuisement). Reformule plus précisément ou découpe la "
                "demande, puis relance."
            ),
            "emits_count": emits_count,
            "modifications_count": mods_count,
        }

    if terminal_type == "cancelled":
        return {
            "success": False,
            "type": "cancelled",
            "summary": "Run copilot annulé (timeout réseau ou stop user).",
        }

    # Cas dégradé : erreur générique ou format inconnu. On préserve le
    # message côté copilot s'il est présent, sinon message neutre FR.
    error_msg = copilot_result.get("error") or summary or "erreur inconnue"
    return {
        "success": False,
        "type": "error",
        "summary": f"Échec copilot : {error_msg}",
    }


async def _handle_transform_uploaded_file(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict:
    """Délègue la transformation d'un classeur uploadé à ``copilot_agent``.

    Doctrine SSoT :
    * On appelle ``run_copilot_agent`` directement — zéro duplication de
      sa logique (tool-use loop, anonymisation, RLS, pseudonymizer, etc.).
    * Le format ``tabs_context`` / ``sheet_content`` est construit par
      ``_build_tabs_context_from_upload`` à partir du même file_info que
      ``_handle_analyze_attachment`` utilise — donc même source de vérité
      pour la lecture pandas (CSV / Excel multi-sheet).
    * Pour la Phase 2 unification, ce helper sera potentiellement remplacé
      par un import depuis la session 2cbd7223 (upload-as-result).

    Politique d'erreur (taxonomie 4 cas Komptia, axe 5 du contrat) :
    * (a) métier : file_id introuvable, instruction vide/trop longue,
      format non supporté → message FR neutre.
    * (b) 4xx : pas applicable ici (filtré par le handler HTTP en amont).
    * (c) 5xx : crash pandas / copilot inattendu → message générique,
      stack trace dans logs serveur.
    * (d) réseau : copilot retourne ``cancelled`` ou ``max_turns_reached``
      → relayé tel quel au LLM Iris.
    """
    import uuid

    # 1. Validation des inputs.
    file_id = tool_input.get("file_id")
    instruction = tool_input.get("instruction")

    if not isinstance(file_id, str) or not file_id.strip():
        return {"success": False, "type": "error", "error": "Le paramètre `file_id` est requis."}

    if not isinstance(instruction, str) or not instruction.strip():
        return {
            "success": False,
            "type": "error",
            "error": (
                "Le paramètre `instruction` est requis et doit être une consigne "
                'non-vide (ex: "ajoute un sous-total par client").'
            ),
        }

    # Cap d'entrée défensif (cf. adversarial review M2, 2026-05-26) : ce
    # n'est PAS un mirror du cap copilot (qui plafonne via ``max_tokens``
    # LLM, pas un char count), mais une sanity-bound côté Iris pour éviter
    # qu'un LLM ne forge une instruction kilométrique (prompt injection
    # par dilution, fuite tokens). 4000 chars couvre largement toute
    # instruction métier légitime.
    if len(instruction) > 4000:
        return {
            "success": False,
            "type": "error",
            "error": (
                "L'instruction est trop longue (>4000 caractères). "
                "Reformule plus concise — découpe en plusieurs transformations "
                "atomiques si besoin."
            ),
        }

    # M1 (task #18) — Détection passive de prompt injection. On ne bloque
    # PAS et on ne modifie PAS l'instruction (préserve l'intent légitime,
    # zéro faux positif côté UX). On logue uniquement, pour qu'un admin
    # puisse identifier a posteriori les abus via les logs.
    injection_signals = _scan_instruction_for_injection_signals(instruction)
    long_instruction = len(instruction) > _INSTRUCTION_LONG_THRESHOLD
    if injection_signals or long_instruction:
        logger.warning(
            "transform_uploaded_file: instruction suspecte (audit, non-bloquant)",
            extra={
                "tool": "transform_uploaded_file",
                "file_id": file_id,
                "user_id": getattr(user, "id", None),
                "instruction_len": len(instruction),
                "long_instruction": long_instruction,
                "injection_patterns_matched": injection_signals,
                "instruction_preview": instruction[:200],
            },
        )

    # F1 — Fail-closed sur user_id manquant. Sans user_id, copilot bascule
    # en mode test (cf. copilot_agent.py:505) qui bypass complètement le
    # pseudonymizer user-scopé + l'enforcer RLS data_access → fuite
    # silencieuse de PII vers le LLM cloud. Inacceptable, fail explicite
    # (cf. adversarial review F1, 2026-05-26).
    user_id = getattr(user, "id", None)
    if user_id is None:
        logger.warning("transform_uploaded_file: appelé sans user_id valide — refus fail-closed")
        return {
            "success": False,
            "type": "error",
            "error": ("Session utilisateur non identifiée — re-connecte-toi avant " "de retenter."),
        }

    # 2. Résolution du file_info depuis le context de l'agent. Première
    #    voie : context["uploads"] (chargé par agent.run() si file_id
    #    fourni au start). Fallback C3 : si le LLM appelle ce tool avec
    #    un file_id différent ou après que le context a été overwrité,
    #    on recharge depuis disque via ``_load_uploaded_file`` (validation
    #    UUID + scope user appliqués). Cf. adversarial review C3.
    uploads = context.get("uploads", {}) or {}
    file_info = uploads.get(file_id)
    if not file_info:
        try:
            from app.services.ai.agent_service import IrisAgent

            file_info = await IrisAgent._load_uploaded_file(file_id, user)
        except Exception:
            logger.exception(
                "transform_uploaded_file: fallback _load_uploaded_file a levé " "(file_id=%s)",
                file_id,
            )
            file_info = None
        if file_info:
            # On met aussi en cache pour les prochains tours du même run.
            uploads_cache = context.setdefault("uploads", {})
            uploads_cache[file_id] = file_info

    if not file_info:
        return {
            "success": False,
            "type": "error",
            "error": (
                f"Fichier `{file_id}` introuvable. Vérifie l'ID ou re-uploade "
                "le fichier puis relance la demande."
            ),
        }

    # 3. Construction tabs_context + sheet_content depuis l'upload.
    # Cache hit via ``file_info["_built_tabs"]`` — partagé avec les workbook
    # read-handlers (P2.2 task #13). Si le LLM a fait analyze_attachment +
    # quick_overview avant transform, la lecture pandas est faite UNE seule
    # fois et réutilisée ici. Sinon construit fresh.
    try:
        if "_built_tabs" not in file_info:
            # Off-loop obligatoire — cf. commentaire dans
            # _resolve_workbook_for_read (parse pandas ~16s sur gros xlsx).
            file_info["_built_tabs"] = await asyncio.to_thread(
                _build_tabs_context_from_upload, file_info
            )
        built = file_info["_built_tabs"]
    except ValueError as exc:
        # Erreur métier (format non supporté, fichier vide, encoding KO) —
        # message clair, on relaye le détail du helper.
        return {
            "success": False,
            "type": "error",
            "error": f"Lecture du fichier impossible : {exc}",
        }
    except Exception:
        logger.exception(
            "transform_uploaded_file: échec construction tabs_context (file_id=%s)",
            file_id,
        )
        return {
            "success": False,
            "type": "error",
            "error": "Erreur interne lors de la lecture du fichier (voir logs serveur).",
        }

    tabs_context = built["tabs_context"]
    sheet_content = built["sheet_content"]
    truncated = built["truncated"]
    active_cells = built["active_cells"]
    metadata_cells = built["metadata_cells"]
    non_active_labels = built["non_active_sheet_labels"]

    if not tabs_context or not sheet_content:
        return {
            "success": False,
            "type": "error",
            "error": (
                "Le fichier semble vide ou illisible (0 cellule extractible). "
                "Vérifie le contenu et re-uploade."
            ),
        }

    # 4. Préparation des params pour copilot. user_id + user (objet ORM)
    #    propagés pour pseudonymizer user-scoped + enforcer RLS data_access
    #    (CLAUDE.md axe 4 + axe 18 — isolation users).
    run_id = str(uuid.uuid4())

    log_extra = {
        "tool": "transform_uploaded_file",
        "run_id": run_id,
        "user_id": user_id,
        "file_id": file_id,
        "tabs_count": len(tabs_context),
        "non_active_tabs": len(non_active_labels),
        "cells_sent": len(sheet_content),
        "active_cells_total": active_cells,
        "all_cells_in_file": metadata_cells,
        "truncated": truncated,
        "instruction_len": len(instruction),
        # F3 — preview tronqué pour traçabilité 4-cas sans payload énorme
        # dans les logs.
        "instruction_preview": instruction[:200],
    }
    logger.info("transform_uploaded_file: dispatching to copilot", extra=log_extra)

    # 5. Appel direct à run_copilot_agent — zéro duplication, mêmes
    #    paramètres que ``result_assistant.py:917`` (le handler HTTP
    #    appelé quand le user tape dans la copilot-bar).
    try:
        from app.services.ai.copilot_agent import run_copilot_agent

        copilot_result = await run_copilot_agent(
            sql="",
            instruction=instruction,
            columns=None,
            display_state=None,
            tabs_context=tabs_context,
            sheet_content=sheet_content,
            sheet_context=None,
            is_auto_fill=False,
            run_id=run_id,
            user_id=user_id,
            anonymization_state=None,
            copilot_memory="",
            workbook_ref=None,
            selected_cells=None,
            user=user,
        )
    except Exception:
        logger.exception(
            "transform_uploaded_file: run_copilot_agent a crashé",
            extra=log_extra,
        )
        return {
            "success": False,
            "type": "error",
            "error": "Échec interne du copilot (voir logs serveur).",
        }

    # 6. Conversion result → dict synthétique pour le LLM Iris.
    summary_dict = _summarize_copilot_result_for_iris(copilot_result)

    # M3 — Si le fichier avait des onglets non-actifs (Excel multi-sheet),
    # signaler à Iris/user pour éviter l'hallucination "le 3e onglet n'a
    # rien vu être appliqué". Côté contrat : copilot peut lire les autres
    # onglets via ses tools (``list_tabs`` / ``read_tab_rows``) — donc le
    # message est informationnel, pas un échec.
    if non_active_labels:
        summary_dict["multi_sheet_note"] = (
            f"Le fichier contenait {len(non_active_labels) + 1} onglets. "
            f"Copilot a un accès direct à l'onglet actif (premier) + les "
            f"métadonnées des autres ({', '.join(non_active_labels[:5])}"
            f"{'…' if len(non_active_labels) > 5 else ''}). Si la transformation "
            "devait porter sur un autre onglet, dis-le explicitement dans une "
            "nouvelle instruction."
        )

    # 7. Honnêteté UX (M5) : le tool retourne un dict synthétique au LLM
    # Iris, mais la matérialisation du résultat dans le result area /iris
    # est wirée par la session 2cbd7223 (upload-as-result). Tant qu'elle
    # n'est pas livrée, on dit la vérité : le résumé est dispo, la pièce
    # téléchargeable arrive en Phase 2 du chantier.
    if summary_dict.get("success"):
        summary_dict["next_action_hint"] = (
            "Résumé textuel de la transformation disponible ci-dessous. "
            "L'export téléchargeable du classeur transformé sera branché "
            "en Phase 2 du chantier upload-as-result (session séparée). "
            "Pour l'instant, communique le résumé à l'utilisateur."
        )
    if truncated:
        existing_summary = summary_dict.get("summary") or ""
        summary_dict["summary"] = (
            f"{existing_summary} Note : le fichier dépassait "
            f"{_UPLOAD_MAX_CELLS_FOR_COPILOT} cellules — copilot a travaillé sur "
            f"un échantillon. Pour traiter l'intégralité, segmente le fichier."
        ).strip()
        summary_dict["truncated"] = True

    logger.info(
        "transform_uploaded_file: copilot returned type=%s",
        summary_dict.get("type"),
        extra={**log_extra, "result_type": summary_dict.get("type")},
    )
    return summary_dict


# ---------------------------------------------------------------------------
# Outils Iris pour LIRE un classeur uploadé sans déclencher copilot_agent.
# Phase 2.2 (task #13) — délèguent aux cores extraits dans copilot_tools.py
# (P2.1, task #12). Doctrine SSoT : une seule implémentation, deux callers
# (copilot via handle_X(args, ctx), Iris via handle_iris_workbook_X qui
# construit les inputs depuis l'upload).
# ---------------------------------------------------------------------------


async def _resolve_workbook_for_read(
    file_id: str, user: Any, context: Dict[str, Any]
) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Résout un ``file_id`` vers son tabs_context+sheet_content (cachés),
    pour les outils de lecture Iris.

    Stratégie :
    1. Lookup ``context["uploads"][file_id]`` (chargé par agent.run() ou
       par le fallback dans transform_uploaded_file).
    2. Fallback : ``IrisAgent._load_uploaded_file(file_id, user)`` qui valide
       UUID + scope user, puis cache.
    3. Cache le ``built`` (résultat de ``_build_tabs_context_from_upload``)
       sur l'entry ``file_info["_built_tabs"]`` pour éviter de re-parser
       le fichier à CHAQUE appel d'outil de lecture (4 outils dans le même
       run → 4 reads pandas sans cache, coûteux).

    Returns:
        ``(built, None)`` en succès, où ``built`` est le dict retourné par
        ``_build_tabs_context_from_upload``.
        ``(None, error_message)`` en cas d'erreur (file introuvable, format
        non supporté, etc.) — message FR neutre, prêt à retourner au LLM.
    """
    if not isinstance(file_id, str) or not file_id.strip():
        return None, "Le paramètre `file_id` est requis."

    # Fail-closed sur user_id manquant (defense-in-depth C2 P2 adversarial,
    # 2026-05-26). Même garde que `_handle_transform_uploaded_file` (F1) —
    # sans user_id, le scope de l'upload ne peut être validé côté
    # ``_load_uploaded_file``, et un cache hit `_built_tabs` orphelin ne
    # vérifierait rien. Refus explicite avec message clair plutôt qu'une
    # erreur générique « introuvable ».
    user_id = getattr(user, "id", None)
    if user_id is None:
        logger.warning(
            "workbook_read: appelé sans user_id valide — refus fail-closed " "(file_id=%s)",
            file_id,
        )
        return None, "Session utilisateur non identifiée — re-connecte-toi."

    uploads = context.get("uploads", {}) or {}
    file_info = uploads.get(file_id)
    if not file_info:
        try:
            from app.services.ai.agent_service import IrisAgent

            file_info = await IrisAgent._load_uploaded_file(file_id, user)
        except Exception:
            logger.exception(
                "workbook_read: fallback _load_uploaded_file a levé (file_id=%s)",
                file_id,
            )
            file_info = None
        if file_info:
            uploads_cache = context.setdefault("uploads", {})
            uploads_cache[file_id] = file_info

    if not file_info:
        return None, (
            f"Fichier `{file_id}` introuvable. Vérifie l'ID ou re-uploade "
            "le fichier puis relance la demande."
        )

    # Cache le built sur file_info — invalidation naturelle quand le user
    # re-uploade (nouveau file_id = nouveau file_info, ancien jamais
    # invalidé en place).
    if "_built_tabs" not in file_info:
        try:
            # Parse pandas/openpyxl = CPU/IO pur (~16s observés sur un xlsx
            # de 2.8 Mo en prod) — JAMAIS sur l'event loop (gel total de
            # l'app, cf. loop_lag_monitor). to_thread est race-benign ici :
            # les workbook tools ne sont pas dans _PARALLEL_SAFE_TOOLS
            # (exécution séquentielle par run) et file_info est per-run.
            # Si un jour ils deviennent parallèles, ajouter un asyncio.Lock
            # par file_info pour éviter N parses concurrents du même fichier.
            file_info["_built_tabs"] = await asyncio.to_thread(
                _build_tabs_context_from_upload, file_info
            )
        except ValueError as exc:
            return None, f"Lecture du fichier impossible : {exc}"
        except Exception:
            logger.exception("workbook_read: échec construction tabs_context (file_id=%s)", file_id)
            return None, "Erreur interne lors de la lecture du fichier (voir logs serveur)."

    return file_info["_built_tabs"], None


def _upload_truncation_note(built: Dict[str, Any]) -> Optional[str]:
    """Note explicite quand l'onglet actif a été tronqué au parse.

    Le builder cape l'onglet actif à ``_UPLOAD_MAX_CELLS_FOR_COPILOT``
    cellules : tout count/aggregate/stat calculé dessus est PARTIEL. Sans
    cette note, un « total montant » sommé sur les N premières lignes est
    présenté comme un total fichier-entier — chiffre plausible et faux,
    pire mode de failure pour un cabinet comptable (doctrine Q5). À injecter
    dans le retour de TOUS les read-handlers quand ``built["truncated"]``.
    """
    if not built.get("truncated"):
        return None
    active = next(
        (t for t in built.get("tabs_context") or [] if isinstance(t, dict) and t.get("is_active")),
        None,
    )
    kept = max(0, (active.get("row_count") or 1) - 1) if active else 0
    original = max(0, (active.get("row_count_original") or 1) - 1) if active else 0
    if original > kept > 0:
        detail = f"les {kept} premières lignes sur {original}"
    else:
        detail = f"les {kept} premières lignes" if kept else "un sous-ensemble du fichier"
    return (
        f"⚠️ Fichier tronqué au parse (cap {_UPLOAD_MAX_CELLS_FOR_COPILOT} "
        f"cellules) : lectures, comptages, agrégats et statistiques portent "
        f"sur {detail} UNIQUEMENT — totaux PARTIELS, ne les présente pas "
        "comme des totaux fichier-entier. Pour des chiffres exacts, propose "
        "à l'utilisateur de requêter la source SQL ou de réduire le fichier."
    )


def _workbook_tab_materialized_guard(built: Dict[str, Any], tab_idx: Any) -> Optional[str]:
    """Erreur explicite si l'onglet ciblé n'a pas ses cellules en mémoire.

    ``_build_tabs_context_from_upload`` ne matérialise QUE l'onglet actif
    (premier) — les onglets suivants d'un Excel multi-feuilles n'ont que des
    métadonnées. Sans ce garde, les cores copilot lisent ``[]`` et
    retournent « 0 cellule / 0 ligne » avec ``success=True`` : le LLM
    conclut à un onglet vide alors qu'il est plein — données fausses
    silencieuses, le pire mode de failure (doctrine Q5 + bug prod
    2026-06-11). Retourne ``None`` si la lecture peut procéder ; laisse le
    core produire ses propres erreurs pour un ``tab_idx`` invalide.
    """
    tabs = built.get("tabs_context") or []
    # bool est un int en Python — True ≡ tabs[1] silencieux : on laisse le
    # core produire son erreur de type plutôt que de guard le mauvais onglet.
    if isinstance(tab_idx, bool):
        return None
    if not isinstance(tab_idx, int) or tab_idx < 0 or tab_idx >= len(tabs):
        return None
    tab = tabs[tab_idx]
    if not isinstance(tab, dict):
        return None
    if tab.get("sheet_content"):
        return None
    if tab.get("is_active") and built.get("sheet_content"):
        return None
    if tab.get("is_active"):
        # Onglet ACTIF sans cellules top-level ni embedded alors que les
        # métadonnées annoncent des données : parse incomplet/anormal — la
        # recette « place l'onglet en premier » serait absurde (il l'est déjà).
        row_count_active = tab.get("row_count") or 0
        if row_count_active <= 1:
            return None
        return (
            f"Onglet {tab_idx} (actif) annoncé non-vide "
            f"(~{max(0, row_count_active - 1)} ligne(s) de données) mais aucune "
            "cellule n'a été matérialisée au parse — lecture incomplète. "
            "Demande à l'utilisateur de re-uploader le fichier ; si ça "
            "persiste, signale le bug."
        )
    if "row_count" not in tab:
        # Fail-closed : métadonnées incomplètes → impossible de garantir que
        # « 0 cellule » serait honnête (doctrine Q5).
        return (
            f"Onglet {tab_idx} : métadonnées incomplètes (row_count absent), "
            "contenu non vérifiable — lecture refusée pour ne pas retourner "
            "un faux « onglet vide »."
        )
    row_count = tab.get("row_count") or 0
    if row_count <= 1:
        # Onglet réellement vide (ou header seul) — un résultat vide est honnête.
        return None
    # NB : PAS de label d'onglet dans ce message — les labels peuvent contenir
    # des noms clients (CRIT-3, cf. list_workbook_tabs qui les anonymise) et
    # ce retour d'erreur ne passe pas par le pseudonymizer. L'index suffit,
    # le LLM a les labels anonymisés via list_workbook_tabs.
    return (
        f"Onglet {tab_idx} non matérialisé en mémoire : seul le premier "
        f"onglet d'un classeur multi-feuilles est chargé au parse. Ses "
        f"métadonnées annoncent ~{row_count - 1} ligne(s) de données — ce "
        "n'est PAS un onglet vide, son contenu est juste illisible par les "
        "outils de lecture. Demande à l'utilisateur d'exporter cet onglet "
        "dans un fichier séparé (ou de le placer en premier) puis de "
        "re-uploader."
    )


async def _handle_list_workbook_tabs(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Liste les onglets d'un classeur uploadé. Délègue à
    ``copilot_tools._list_tabs_core`` (SSoT)."""
    file_id = tool_input.get("file_id")
    built, err = await _resolve_workbook_for_read(file_id, user, context)
    if err:
        return {"success": False, "error": err}
    from app.services.ai.copilot_tools import _list_tabs_core

    result = _list_tabs_core(built["tabs_context"])
    result["success"] = True
    result["file_id"] = file_id
    # CRIT-3 — anonymise les noms d'onglets (peuvent contenir clients/PII)
    return await _anonymize_workbook_tool_result(result, user)


async def _handle_read_workbook_rows(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Lit un slice de cellules d'un onglet. Délègue à
    ``copilot_tools._read_tab_rows_core`` (SSoT)."""
    file_id = tool_input.get("file_id")
    built, err = await _resolve_workbook_for_read(file_id, user, context)
    if err:
        return {"success": False, "error": err}
    from app.services.ai.copilot_tools import _read_tab_rows_core

    guard_err = _workbook_tab_materialized_guard(built, tool_input.get("tab_idx"))
    if guard_err:
        return {"success": False, "error": guard_err}

    # On NE passe PAS de tabs_touched — l'instrumentation copilot
    # (progress UI) n'a pas d'équivalent côté Iris (le LLM Iris voit
    # le résultat dans son tour, pas besoin de tracker l'avancement).
    # top_level_sheet_content=built["sheet_content"] : comme chez copilot,
    # ``_build_tabs_context_from_upload`` matérialise les cellules de
    # l'onglet ACTIF au top-level uniquement — les entrées de tabs_context
    # ne portent QUE des métadonnées (label/row_count/columns/is_active).
    # Passer None ici fait lire ``tab.get("sheet_content") or []`` → le
    # core retourne « 0 cellule » silencieux sur un onglet plein (bug prod
    # 2026-06-11, fichier TempsDuSite 714 lignes lu comme vide).
    # include_match=False : économie massive de tokens LLM. Les uploads
    # ont un ``match`` synthétique sur chaque cellule (cf. P2 task #13
    # + adversarial C3) qui contient TOUTES les colonnes de la row —
    # incluse dans le retour, ça explose à 20-30 entries par cellule.
    # Le LLM Iris peut reconstituer la row via les valeurs des autres
    # cellules de la même row si besoin.
    result = _read_tab_rows_core(
        tool_input,
        tabs_context=built["tabs_context"],
        top_level_sheet_content=built.get("sheet_content"),
        tabs_touched=None,
        include_match=False,
    )
    if "error" not in result:
        result["success"] = True
        result["file_id"] = file_id
        trunc_note = _upload_truncation_note(built)
        if trunc_note:
            result["truncated_note"] = trunc_note
    else:
        result["success"] = False
    # CRIT-3 — anonymise les rows/cells brutes avant retour LLM
    return await _anonymize_workbook_tool_result(result, user)


async def _handle_count_workbook_rows(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Compte les lignes matching d'un onglet. Délègue à
    ``copilot_tools._count_rows_from_inputs`` (SSoT)."""
    file_id = tool_input.get("file_id")
    built, err = await _resolve_workbook_for_read(file_id, user, context)
    if err:
        return {"success": False, "error": err}
    from app.services.ai.copilot_tools import _count_rows_from_inputs

    guard_err = _workbook_tab_materialized_guard(built, tool_input.get("tab_idx"))
    if guard_err:
        return {"success": False, "error": guard_err}

    # top_level_sheet_content : cellules de l'onglet actif (cf. commentaire
    # détaillé dans _handle_read_workbook_rows — None = count 0 silencieux).
    result = _count_rows_from_inputs(
        tool_input,
        tabs_context=built["tabs_context"],
        top_level_sheet_content=built.get("sheet_content"),
        tabs_touched=None,
    )
    if "error" not in result:
        result["success"] = True
        result["file_id"] = file_id
        trunc_note = _upload_truncation_note(built)
        if trunc_note:
            result["truncated_note"] = trunc_note
    else:
        result["success"] = False
    # CRIT-3 — anonymise les filter values référencées dans le retour
    return await _anonymize_workbook_tool_result(result, user)


async def _handle_aggregate_workbook(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Agrège une colonne d'un onglet. Délègue à
    ``copilot_tools._aggregate_from_inputs`` (SSoT).

    Le résultat (group_by buckets + valeurs agrégées) passe ensuite par
    :func:`_anonymize_workbook_tool_result` avant retour au LLM (CRIT-3
    adversarial fix 2026-05-26). Le ``pseudonymizer=None`` ici est
    intentionnel — l'agrégation s'effectue sur les VRAIES valeurs
    (sinon un GROUP BY sur une colonne pseudonymisée bucket toutes les
    lignes ensemble). L'anonymisation est appliquée APRÈS, sur le retour.
    """
    file_id = tool_input.get("file_id")
    built, err = await _resolve_workbook_for_read(file_id, user, context)
    if err:
        return {"success": False, "error": err}
    from app.services.ai.copilot_tools import _aggregate_from_inputs

    guard_err = _workbook_tab_materialized_guard(built, tool_input.get("source_tab_idx"))
    if guard_err:
        return {"success": False, "error": guard_err}

    # top_level_sheet_content : cellules de l'onglet actif (cf. commentaire
    # détaillé dans _handle_read_workbook_rows — None = agrégat 0 silencieux).
    result = _aggregate_from_inputs(
        tool_input,
        tabs_context=built["tabs_context"],
        top_level_sheet_content=built.get("sheet_content"),
        tabs_touched=None,
        pseudonymizer=None,
    )
    if "error" not in result:
        result["success"] = True
        result["file_id"] = file_id
        trunc_note = _upload_truncation_note(built)
        if trunc_note:
            result["truncated_note"] = trunc_note
    else:
        result["success"] = False
    # CRIT-3 — anonymise les bucket keys (valeurs string en GROUP BY)
    return await _anonymize_workbook_tool_result(result, user)


# ---------------------------------------------------------------------------
# quick_overview_workbook — aperçu programmatique d'un upload sans pandas
# (P2.3 task #14). Calcule depuis le ``tabs_context`` déjà construit par
# ``_build_tabs_context_from_upload`` (cache hit via ``_resolve_workbook_for_read``)
# pour mitiger la latence : sans cet outil, le LLM Iris ferait list_tabs +
# read_tab_rows (au moins 1 ligne) puis devrait inférer types/stats → 2-3
# turns + tokens. quick_overview = 1 turn, 0 LLM, output structuré complet.
#
# C'est le pendant unifié de ``analyze_attachment`` (qui re-parse via pandas
# à chaque appel). À terme (task #15), analyze_attachment pourra être un
# alias de quick_overview_workbook.
# ---------------------------------------------------------------------------

# Cap d'unique values trackés par colonne — au-delà, on bascule en
# "+N autres" pour éviter d'allouer un set énorme sur des colonnes
# high-cardinality (ex: facture_id avec 100k valeurs uniques).
_QUICK_OVERVIEW_UNIQUE_CAP: int = 20


def _quick_overview_from_tabs(
    tabs_context: List[Dict[str, Any]],
    filename: Optional[str] = None,
    active_sheet_content: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Calcule un overview structurel d'un workbook depuis le tabs_context
    déjà construit (zéro pandas, zéro re-parse).

    ``active_sheet_content`` : cellules de l'onglet actif quand elles vivent
    au top-level du ``built`` (pattern ``_build_tabs_context_from_upload`` —
    identique au pattern copilot ``ctx.sheet_content``). Sans ce paramètre,
    l'onglet actif d'un upload était traité « non matérialisé » et l'overview
    retombait en métadonnées-seules (bug prod 2026-06-11).

    Pour chaque onglet matérialisé (avec sheet_content non vide), calcule :
    - row_count, column_count
    - par colonne : null_count, unique_count (capé à ``_QUICK_OVERVIEW_UNIQUE_CAP``),
      type_hint inféré (int/float/str/bool/mixed), sample_values (≤ 5 valeurs distinctes)
    - sample_rows (5 premières rows complètes en mode dense)
    - numeric_stats par colonne numérique : min, max, sum, mean (count non-null)

    Pour les onglets non matérialisés (Excel multi-sheet, sheet_content vide),
    retourne seulement les métadonnées (label, columns, row_count).
    """
    overview_tabs: List[Dict[str, Any]] = []

    for tab_idx, tab in enumerate(tabs_context):
        if not isinstance(tab, dict):
            continue
        tab_label = tab.get("label", f"Onglet {tab_idx}")
        tab_columns = list(tab.get("columns", []))
        tab_row_count = tab.get("row_count", 0)
        cells = tab.get("sheet_content") or []
        if not cells and tab.get("is_active") and active_sheet_content:
            cells = active_sheet_content

        if not cells:
            # Onglet non matérialisé — overview minimal sans stats.
            # NB : ne PAS recommander read_workbook_rows ici — il échouerait
            # aussi (mêmes cellules absentes) : guidance circulaire qui a
            # fait tourner Iris en rond en prod (2026-06-11).
            overview_tabs.append(
                {
                    "label": tab_label,
                    "index": tab_idx,
                    "row_count": tab_row_count,
                    "column_count": len(tab_columns),
                    "columns": tab_columns,
                    "is_active": bool(tab.get("is_active")),
                    "stats_available": False,
                    "stats_note": (
                        "Onglet non matérialisé en mémoire (seul le premier "
                        "onglet d'un classeur multi-feuilles est chargé au "
                        "parse) — contenu illisible par les outils de "
                        "lecture, mais PAS vide d'après les métadonnées. "
                        "Demande à l'utilisateur d'exporter cet onglet "
                        "séparément ou de le placer en premier."
                    ),
                }
            )
            continue

        # Per-column accumulators. On utilise tab_columns comme source de
        # vérité pour les noms (préserve l'ordre + couvre les colonnes qui
        # n'apparaîtraient pas dans cells si toutes valeurs sont None).
        col_stats: Dict[str, Dict[str, Any]] = {
            name: {
                "name": name,
                "non_null_count": 0,
                "null_count": 0,  # rempli en fin via (row_count - non_null_count)
                "unique_values": set(),
                "unique_overflow": False,
                "type_counts": {},  # type_name → count
                "numeric_values": [],  # collecte pour stats numériques
            }
            for name in tab_columns
        }

        # Itère les cellules data (skip headers row 0). row_count_data = total
        # rows de data (sans header) — utile pour calculer null_count par colonne.
        for cell in cells:
            if not isinstance(cell, dict):
                continue
            row = cell.get("row")
            if not isinstance(row, int) or row < 1:
                # row 0 = header, on skip ; row < 0 ou non-int = bizarre, skip
                continue
            col = cell.get("col")
            if col not in col_stats:
                continue
            val = cell.get("value")
            if val is None:
                continue  # cellule sparse vide explicitement
            stats = col_stats[col]
            stats["non_null_count"] += 1
            # Type tracking
            type_name = type(val).__name__
            stats["type_counts"][type_name] = stats["type_counts"].get(type_name, 0) + 1
            # Unique tracking (capé)
            if not stats["unique_overflow"]:
                if len(stats["unique_values"]) >= _QUICK_OVERVIEW_UNIQUE_CAP:
                    stats["unique_overflow"] = True
                else:
                    try:
                        stats["unique_values"].add(val)
                    except TypeError:
                        # val unhashable (rare : dict/list dans une cellule)
                        pass
            # Numeric collection pour stats
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                stats["numeric_values"].append(float(val))

        # Compute le row_count effectif de données (le tab.row_count inclut le
        # header, sauf si déjà ajusté en amont). On dérive du max(row) observé
        # car le row_count metadata peut être imprécis sur les uploads tronqués.
        data_rows_observed = max(
            (cell.get("row", 0) for cell in cells if isinstance(cell, dict)),
            default=0,
        )

        # Build columns_summary
        columns_summary: List[Dict[str, Any]] = []
        for name in tab_columns:
            s = col_stats[name]
            null_count = max(0, data_rows_observed - s["non_null_count"])
            # Type hint = type dominant ; si > 1 type observé, "mixed"
            type_counts = s["type_counts"]
            if not type_counts:
                type_hint = "empty"
            elif len(type_counts) == 1:
                type_hint = next(iter(type_counts))
            else:
                # Mixed numeric (int + float) reste numérique
                non_bool_types = {t for t in type_counts if t != "bool"}
                if non_bool_types <= {"int", "float"}:
                    type_hint = "numeric"
                else:
                    type_hint = "mixed:" + ",".join(sorted(type_counts.keys()))

            entry: Dict[str, Any] = {
                "name": name,
                "type_hint": type_hint,
                "non_null_count": s["non_null_count"],
                "null_count": null_count,
                "unique_count_capped": len(s["unique_values"]),
                "unique_overflow": s["unique_overflow"],
            }
            # Sample values (jusqu'à 5)
            if s["unique_values"]:
                entry["sample_values"] = list(s["unique_values"])[:5]
            # Stats numériques
            if s["numeric_values"]:
                nums = s["numeric_values"]
                entry["numeric_stats"] = {
                    "count": len(nums),
                    "min": round(min(nums), 6),
                    "max": round(max(nums), 6),
                    "sum": round(sum(nums), 6),
                    "mean": round(sum(nums) / len(nums), 6),
                }
            columns_summary.append(entry)

        # Sample rows (5 premières rows en dense). On utilise _build_dense_rows
        # de copilot_tools comme SSoT (gère bien le format sparse + nom de col).
        from app.services.ai.copilot_tools import _build_dense_rows

        dense = _build_dense_rows(cells, tab_columns, data_rows_observed)
        sample_rows = []
        for row_idx, dense_row in enumerate(dense[:5], start=1):
            sample_rows.append(
                {tab_columns[i]: dense_row[i] for i in range(min(len(tab_columns), len(dense_row)))}
            )

        overview_entry: Dict[str, Any] = {
            "label": tab_label,
            "index": tab_idx,
            "row_count": data_rows_observed,
            "column_count": len(tab_columns),
            "columns_summary": columns_summary,
            "sample_rows": sample_rows,
            "is_active": bool(tab.get("is_active")),
            "stats_available": True,
        }
        # Onglet tronqué au parse (cap cellules du builder) : exposer le
        # total ORIGINAL pour que LLM et frontend ne présentent jamais le
        # sous-ensemble comme le fichier entier (doctrine Q5).
        if tab.get("truncated"):
            overview_entry["truncated"] = True
            orig = tab.get("row_count_original")
            if isinstance(orig, int) and orig > 1:
                overview_entry["row_count_original"] = orig - 1  # data rows
        overview_tabs.append(overview_entry)

    return {"tabs": overview_tabs, "filename": filename, "tab_count": len(tabs_context)}


async def _handle_quick_overview_workbook(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict:
    """Overview programmatique (0 LLM) d'un upload via le tabs_context partagé.

    Délègue à ``_quick_overview_from_tabs`` (pure). Cache hit via
    ``_resolve_workbook_for_read`` (file_info['_built_tabs']) — le helper est
    construit une seule fois par run même si list_workbook_tabs / read_workbook_rows
    / count_workbook_rows / aggregate_workbook ont été appelés avant.
    """
    file_id = tool_input.get("file_id")
    built, err = await _resolve_workbook_for_read(file_id, user, context)
    if err:
        return {"success": False, "error": err}
    # Le filename est dans context["uploads"][file_id]["filename"]
    uploads = context.get("uploads", {}) or {}
    file_info = uploads.get(file_id) or {}
    filename = file_info.get("filename")
    result = _quick_overview_from_tabs(
        built["tabs_context"],
        filename=filename,
        active_sheet_content=built.get("sheet_content"),
    )
    result["success"] = True
    result["file_id"] = file_id
    trunc_note = _upload_truncation_note(built)
    if trunc_note:
        result["truncated_note"] = trunc_note
    # CRIT-3 — anonymise sample_rows + columns_summary + numeric_stats
    return await _anonymize_workbook_tool_result(result, user)


async def _handle_get_user_preferences(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict:
    """Retrieve user preferences from the database."""
    from sqlalchemy import select
    from app.core.database import get_session
    from app.models.user_preference import UserPreference

    category: Optional[str] = tool_input.get("category")

    try:
        async with get_session() as session:
            stmt = select(UserPreference).where(UserPreference.user_id == user.id)
            if category:
                stmt = stmt.where(UserPreference.category == category)
            result = await session.execute(stmt)
            prefs = result.scalars().all()

        prefs_list = [{"key": p.key, "value": p.value, "category": p.category} for p in prefs]

        return {
            "success": True,
            "count": len(prefs_list),
            "preferences": prefs_list,
        }

    except Exception as exc:
        logger.warning("get_user_preferences failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de la lecture des préférences."}


async def _handle_save_user_preference(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict:
    """Save or update a user preference (upsert)."""
    from sqlalchemy import select
    from app.core.database import get_session
    from app.models.user_preference import UserPreference

    key: str = tool_input["key"]
    value: str = tool_input["value"]
    category: str = tool_input.get("category", "preference")

    try:
        async with get_session() as session:
            # Check if preference already exists
            stmt = select(UserPreference).where(
                UserPreference.user_id == user.id,
                UserPreference.key == key,
            )
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                existing.value = value
                existing.category = category
                action = "updated"
            else:
                pref = UserPreference(
                    user_id=user.id,
                    key=key,
                    value=value,
                    category=category,
                )
                session.add(pref)
                action = "created"

            await session.commit()

        return {
            "success": True,
            "action": action,
            "key": key,
            "category": category,
            "note": f"Préférence '{key}' {action}.",
        }

    except Exception as exc:
        logger.warning("save_user_preference failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Échec de la sauvegarde de la préférence."}


async def _handle_suggest_followup_questions(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict:
    """Store follow-up suggestions in context for the WebSocket layer."""
    questions: List[str] = tool_input["questions"]

    # Dé-anonymisation : même raison que ask_user_clarification —
    # le LLM peut glisser des fragments anonymisés (~XXX) dans une
    # suggestion, ils doivent être restaurés avant d'atteindre l'UI.
    questions = await _restore_options_for_user_safe(questions)

    if "suggestions" not in context:
        context["suggestions"] = []
    context["suggestions"].extend(questions)

    return {
        "success": True,
        "count": len(questions),
        "note": "Suggestions envoyées à l'utilisateur.",
    }


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Auto-documentation tool handlers
# ---------------------------------------------------------------------------


async def _handle_introspect_table(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Introspect a table's metadata from SQL Server via INFORMATION_SCHEMA."""
    from app.services.database.sage_connector import get_sage_connector

    table_name = tool_input["table_name"].strip()
    info_type = tool_input.get("info_type", "all")

    if not _validate_identifier(table_name):
        return {"success": False, "error": f"Nom de table invalide : {table_name}"}

    # ── RLS table-level check (defense-in-depth) ──
    # Empêche l'agent de récupérer la structure d'une table denied —
    # leak des noms de colonnes / FK / contraintes serait possible
    # sinon. Voir adversarial review issue HIGH "Leak de structure".
    try:
        from app.services.data_access.enforcer import (
            DataAccessDeniedError,
            assert_table_access,
        )

        await assert_table_access(table_name, user)
    except DataAccessDeniedError as exc:
        return {
            "success": False,
            "error": exc.user_message,
            "blocked_by": "data_access_rule",
        }

    # ── Cache intra-session : évite de re-requêter Sage pour la même table ──
    cache = context.setdefault("_introspect_cache", {})
    cache_key = f"{table_name}|{info_type}"
    if cache_key in cache:
        cached = cache[cache_key]
        logger.debug("introspect_table: cache hit for %s (%s)", table_name, info_type)
        result_copy = {**cached, "_from_cache": True}
        # Enrichir avec les rôles sémantiques même depuis le cache (peut changer mid-session)
        # **#119** — user propagé pour filtre defense-in-depth.
        await _enrich_columns_with_roles(result_copy, table_name, user=user)
        # Attacher le business_context frais (peut être modifié mid-session par admin)
        await _attach_business_context(result_copy, [table_name])
        return result_copy

    connector = get_sage_connector()
    result: Dict[str, Any] = {"success": True, "table_name": table_name}

    columns: list = []  # Toujours initialisé (évite NameError si info_type inattendus)
    try:
        # Charger les colonnes si demandé OU si FK demandé (pour enrichir
        # les FK avec l'info nullable → le LLM sait LEFT vs INNER JOIN)
        if info_type in ("columns", "all", "foreign_keys"):
            # Phase α.4.A : propager user pour filtrage à la source.
            columns = await connector.get_columns(table_name, user=user)

            if info_type in ("columns", "all"):
                result["columns"] = columns
                result["column_count"] = len(columns)

            # ── Enrichissement DBA : index, identity, defaults ────────────
            # Un expert SQL vérifie ces infos AVANT d'écrire une requête.
            # Délégué au connector (interface agnostique SQL Server / SQLite).
            try:
                # 1. Index : agrège par colonne (indexed=true, unique=true si
                #    au moins un index UNIQUE couvre la colonne)
                indexes = await connector.get_indexes(table_name)
                indexed_cols: Dict[str, Dict[str, Any]] = {}
                for idx in indexes:
                    col_name = idx["column_name"]
                    is_unique = bool(idx["is_unique"])
                    if col_name not in indexed_cols:
                        indexed_cols[col_name] = {"indexed": True, "unique_index": is_unique}
                    elif is_unique:
                        indexed_cols[col_name]["unique_index"] = True

                # 2. Identity (auto-increment)
                identity_cols = set(await connector.get_identity_columns(table_name))

                # Enrichir les colonnes avec ces infos
                for col in columns:
                    col_name = col["name"]
                    idx_info = indexed_cols.get(col_name, {})
                    col["indexed"] = idx_info.get("indexed", False)
                    if idx_info.get("unique_index"):
                        col["unique_index"] = True
                    if col_name in identity_cols:
                        col["identity"] = True
                    # Exposer la valeur par défaut (déjà dans get_columns mais ignorée)
                    if col.get("default"):
                        col["default_value"] = col["default"]

            except Exception as dba_err:
                logger.warning("DBA enrichment failed for %s: %s", table_name, dba_err)

        if info_type in ("primary_keys", "all"):
            try:
                result["primary_keys"] = await connector.get_primary_keys(table_name)
            except Exception as pk_err:
                logger.warning("primary_keys lookup failed for %s: %s", table_name, pk_err)
                result["primary_keys"] = []

        if info_type in ("foreign_keys", "all"):
            try:
                # Phase α.4.A : propager user — filtre FK vers tables invisibles.
                fks_raw = await connector.get_foreign_keys(table_name, user=user)
            except Exception as fk_err:
                logger.warning("foreign_keys lookup failed for %s: %s", table_name, fk_err)
                fks_raw = []

            # Index de nullabilité et cardinalité depuis les colonnes enrichies.
            # `columns` est toujours défini ici car info_type="foreign_keys" et
            # "all" déclenchent tous deux le chargement des colonnes.
            col_info_map = {c["name"]: c for c in columns}

            fk_list = []
            for fk in fks_raw:
                fk_col_name = fk["column"]
                col_info = col_info_map.get(fk_col_name, {})
                is_nullable = col_info.get("nullable", True)
                has_unique_idx = col_info.get("unique_index", False)

                # Cardinalité déduite :
                # - unique_index sur FK → 1-1 (chaque ligne a une FK unique)
                # - pas d'unique_index → N-1 (plusieurs lignes pointent vers 1 ref)
                cardinality = "1-1" if has_unique_idx else "N-1"

                # Join hint combinant nullable + cardinalité
                if is_nullable:
                    hint = (
                        "LEFT JOIN recommandé (colonne nullable — pas de correspondance garantie)"
                    )
                elif cardinality == "N-1":
                    hint = "INNER JOIN safe (NOT NULL, N-1 — chaque ligne a une correspondance)"
                else:
                    hint = "INNER JOIN safe (NOT NULL, 1-1 — relation unique)"

                fk_list.append(
                    {
                        "column": fk_col_name,
                        "references_table": fk["references_table"],
                        "references_column": fk["references_column"],
                        "constraint_name": fk["constraint_name"],
                        "nullable": "YES" if is_nullable else "NO",
                        "cardinality": cardinality,
                        "join_hint": hint,
                    }
                )

            result["foreign_keys"] = fk_list

        # --- FK entrantes : quelles tables pointent vers celle-ci ---
        if info_type in ("foreign_keys", "all"):
            try:
                # Phase α.4.A : propager user — filtre FK depuis tables invisibles.
                rev_fks_raw = await connector.get_referencing_foreign_keys(table_name, user=user)
            except Exception as rfk_err:
                logger.warning(
                    "referencing_foreign_keys lookup failed for %s: %s", table_name, rfk_err
                )
                rev_fks_raw = []
            _REV_FK_MAX = 20  # Limiter les FK entrantes (tables hub)
            result["reverse_foreign_keys"] = rev_fks_raw[:_REV_FK_MAX]
            if len(rev_fks_raw) > _REV_FK_MAX:
                result["reverse_fk_truncated"] = True
                result["reverse_fk_total"] = len(rev_fks_raw)

        # --- CHECK constraints : valeurs valides pour certaines colonnes ---
        if info_type == "all":
            try:
                check_constraints = await connector.get_check_constraints(table_name)
                if check_constraints:
                    result["check_constraints"] = [
                        {
                            "constraint_name": cc["constraint_name"],
                            "clause": (cc["clause"] or "")[:200],  # Limiter la taille
                        }
                        for cc in check_constraints[:10]  # Max 10 contraintes
                    ]
            except Exception as chk_err:
                logger.warning("CHECK constraints failed for %s: %s", table_name, chk_err)

        logger.info("introspect_table: %s info_type=%s", table_name, info_type)

        # --- FK 1-hop: auto-introspect referenced tables (capped) ---
        _FK_HOP_MAX_TABLES = 10
        related_tables_info: Dict[str, Any] = {}
        fk_truncated = False

        # Combiner tables référencées (FK sortantes) ET référençantes (FK entrantes)
        all_related_tables: set = set()
        if result.get("foreign_keys"):
            all_related_tables.update(fk["references_table"] for fk in result["foreign_keys"])
        if result.get("reverse_foreign_keys"):
            all_related_tables.update(
                fk["referencing_table"] for fk in result["reverse_foreign_keys"]
            )

        if all_related_tables:
            if len(all_related_tables) > _FK_HOP_MAX_TABLES:
                logger.warning(
                    "introspect_table: %s has %d related tables, capping to %d",
                    table_name,
                    len(all_related_tables),
                    _FK_HOP_MAX_TABLES,
                )
                all_related_tables = set(list(all_related_tables)[:_FK_HOP_MAX_TABLES])
                fk_truncated = True

            for ref_table in all_related_tables:
                try:
                    # Phase α.4.A : propager user pour le FK-hop.
                    ref_columns = await connector.get_columns(ref_table, user=user)
                    ref_fks_raw = await connector.get_foreign_keys(ref_table, user=user)
                    # Index de nullabilité pour cette table liée
                    ref_col_nullable = {c["name"]: c.get("nullable", True) for c in ref_columns}
                    ref_fks = [
                        {
                            "column": fk["column"],
                            "references_table": fk["references_table"],
                            "references_column": fk["references_column"],
                            "nullable": "YES" if ref_col_nullable.get(fk["column"], True) else "NO",
                        }
                        for fk in ref_fks_raw
                    ]
                    related_tables_info[ref_table] = {
                        "columns": [
                            {"name": c["name"], "type": c.get("type", "?")}
                            for c in ref_columns[:15]
                        ],
                        "column_count": len(ref_columns),
                        "foreign_keys": ref_fks,
                    }
                except Exception as ref_exc:
                    logger.warning(
                        "introspect_table: failed to introspect related table %s: %s",
                        ref_table,
                        ref_exc,
                    )

            if related_tables_info:
                result["related_tables"] = related_tables_info

                # Séparer les tables qui pointent vers nous vs celles qu'on référence
                outgoing = set()
                incoming = set()
                if result.get("foreign_keys"):
                    outgoing = {fk["references_table"] for fk in result["foreign_keys"]}
                if result.get("reverse_foreign_keys"):
                    incoming = {fk["referencing_table"] for fk in result["reverse_foreign_keys"]}

                parts_hint = [f"{table_name} fait partie d'une grappe."]
                if outgoing & set(related_tables_info.keys()):
                    parts_hint.append(
                        f"Référence : {', '.join(sorted(outgoing & set(related_tables_info.keys())))}."
                    )
                if incoming & set(related_tables_info.keys()):
                    parts_hint.append(
                        f"Référencée par : {', '.join(sorted(incoming & set(related_tables_info.keys())))}."
                    )
                result["cluster_hint"] = " ".join(parts_hint)

                if fk_truncated:
                    result["_partial"] = True
                    result["cluster_hint"] += (
                        f" (Attention : la table a plus de {_FK_HOP_MAX_TABLES} tables liées, "
                        "seules les premières ont été introspectées.)"
                    )

        # ── Suggestion de vues : chercher les vues qui contiennent cette table ──
        try:
            from sqlalchemy import select as sa_select
            from app.models.training_data import TrainingData, TrainingDataType
            from app.core.database import get_session

            escaped_name = table_name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            async with get_session() as session:
                view_rows = await session.execute(
                    sa_select(TrainingData.category, TrainingData.content).where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.is_active == True,  # noqa: E712
                        TrainingData.category.like("view_composition:%"),
                        TrainingData.content.ilike(f"%{escaped_name}%", escape="\\"),
                    )
                )
                found_views = view_rows.all()
                if found_views:
                    suggested = []
                    for row in found_views[:5]:
                        vname = row[0].split(":", 1)[1] if ":" in row[0] else row[0]
                        suggested.append({"view_name": vname, "description": row[1]})
                    result["suggested_views"] = suggested
                    result["view_hint"] = (
                        f"💡 VUES DISPONIBLES : {len(suggested)} vue(s) consolident "
                        f"la table {table_name} avec d'autres tables. "
                        f"Quand tu dois joindre plusieurs tables de cette grappe, "
                        f"PRÉFÈRE utiliser une vue existante plutôt que de refaire "
                        f"les JOINs manuellement — les vues contiennent souvent des "
                        f"colonnes calculées absentes des tables de base."
                    )

        except Exception as view_exc:
            logger.debug("introspect_table: view suggestion search failed: %s", view_exc)

        # ── Cet objet EST-il LUI-MÊME une vue ? ──────────────────────────────
        # #20 (SSoT) : détection via le helper canonique
        # ``TrainingStore.is_cached_view`` (MÊME logique que #9a recommend_join →
        # plus de divergence cache/live). Si oui : signaler au LLM que l'absence
        # de FK est NORMALE pour une vue → la requêter directement comme FROM,
        # NE PAS l'abandonner pour les tables brutes (cause racine du bug
        # « entité » : viewGroupes01 ignorée car FK=[]). Hors de la session
        # ci-dessus (le helper ouvre la sienne) pour éviter tout nesting.
        try:
            if await get_training_store().is_cached_view(table_name):
                result["is_view"] = True
                result["object_type"] = "VIEW"
                result["view_self_hint"] = (
                    f"ℹ️ {table_name} est une VUE SQL (pas une table de base). "
                    "L'absence de clés étrangères est NORMALE pour une vue : "
                    f"requête-la directement comme source (FROM {table_name}). "
                    "Elle pré-joint déjà ses tables sous-jacentes — ne conclus "
                    "PAS « pas de chemin de jointure » et ne te rabats pas sur "
                    "les tables brutes."
                )
        except Exception as _isv_exc:
            logger.debug("introspect_table: is_view check failed: %s", _isv_exc)

        # Auto-learn: persist key discoveries so future conversations benefit
        try:
            pass

            parts = []
            if result.get("columns"):
                col_summaries = []
                for c in result["columns"][:20]:
                    col_type = c.get("type", "?")
                    precision = c.get("precision")
                    if precision:
                        col_type = f"{col_type}({precision})"
                    col_summaries.append(f"{c['name']} ({col_type})")
                parts.append(f"Colonnes: {', '.join(col_summaries)}")
            if result.get("primary_keys"):
                parts.append(f"PK: {', '.join(result['primary_keys'])}")
            if result.get("foreign_keys"):
                fk_strs = [
                    f"{fk['column']} -> {fk['references_table']}.{fk['references_column']}"
                    for fk in result["foreign_keys"]
                ]
                parts.append(f"FK sortantes: {'; '.join(fk_strs)}")
            if result.get("reverse_foreign_keys"):
                rev_strs = [
                    f"{fk['referencing_table']}.{fk['referencing_column']} -> {table_name}"
                    for fk in result["reverse_foreign_keys"][:10]
                ]
                parts.append(f"FK entrantes: {'; '.join(rev_strs)}")
            if related_tables_info:
                cluster_tables = list(related_tables_info.keys())
                parts.append(f"Grappe: {table_name} fonctionne avec {', '.join(cluster_tables)}")

            # Auto-learn supprimé — la doc ne s'enrichit que par :
            # 1. Schema sync (programmatique)
            # 2. Feedback ✅ (learn_from_conversation_feedback)
            # 3. learn_insight (outil LLM explicite pendant conversation)
            # introspect_table retourne les infos au LLM directement,
            # pas besoin de les dupliquer dans le training store.
            result["auto_learned"] = False
        except Exception as learn_exc:
            logger.debug("introspect_table insight build failed: %s", learn_exc)
            result["auto_learned"] = False

        # Enrichir avec les rôles sémantiques (toujours frais, pas caché)
        # **#119** — user propagé pour filtre defense-in-depth.
        await _enrich_columns_with_roles(result, table_name, user=user)

        # ── Stocker en cache pour la session (SANS les rôles — ajoutés dynamiquement) ──
        cache[cache_key] = result

        # Attacher le business_context APRÈS le cache (doit rester frais à chaque appel)
        await _attach_business_context(result, [table_name])
        # Si info_type="all", stocker aussi les sous-clés pour éviter les appels partiels
        if info_type == "all":
            for sub_type in ("columns", "primary_keys", "foreign_keys"):
                sub_key = f"{table_name}|{sub_type}"
                if sub_key not in cache:
                    sub_result = {"success": True, "table_name": table_name}
                    if sub_type == "columns" and "columns" in result:
                        sub_result["columns"] = result["columns"]
                        sub_result["column_count"] = result.get("column_count", 0)
                    elif sub_type == "primary_keys" and "primary_keys" in result:
                        sub_result["primary_keys"] = result["primary_keys"]
                    elif sub_type == "foreign_keys" and "foreign_keys" in result:
                        sub_result["foreign_keys"] = result["foreign_keys"]
                    cache[sub_key] = sub_result

        return result

    except Exception as exc:
        from app.core.exceptions import SageConnectionError

        if isinstance(exc, SageConnectionError):
            # P2.6 — idem _handle_execute_sql : helper SSoT P2.1 audience="llm"
            # pour ne plus jeter le str(exc) qui contient SQLSTATE + détail ODBC.
            logger.warning("introspect_table: connexion Sage impossible: %s", str(exc)[:200])
            from app.services.data_access.error_messages import (
                sanitize_sql_for_client as _ssfc,
            )

            _conn_payload = await _ssfc(exc, user, audience="llm")
            return {
                "success": False,
                "error": _conn_payload["message"],
                "sqlstate": _conn_payload.get("sqlstate"),
                "category": _conn_payload.get("category"),
                "is_connection_error": True,
            }
        logger.error("introspect_table failed: %s", exc, exc_info=True)
        return {"success": False, "error": f"Erreur d'introspection : {str(exc)[:200]}"}


async def _handle_learn_insight(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Save a knowledge insight to the training store.

    P4.3 — Si le contexte contient la dernière question utilisateur + le
    dernier SQL validé, on en extrait aussi le motif analytique dominant
    (via ``match_patterns``) et on stocke la paire comme *exemple* attaché
    au slug du motif. C'est une capture **sans 2+2=4** : on ne modifie
    jamais les patterns hardcodés, on empile simplement des exemples réels
    validés par l'utilisateur — que le matcher pourra exploiter plus tard.
    """
    from app.services.ai.agent_knowledge import get_agent_knowledge

    table_name = tool_input.get("table_name", "").strip()
    insight = tool_input.get("insight", "").strip()

    if not insight:
        return {"success": False, "error": "L'insight ne peut pas être vide."}

    # Validate table_name if provided (prevent RAG poisoning)
    effective_name = table_name or "general"
    if table_name and not _validate_identifier(table_name):
        return {"success": False, "error": f"Nom de table invalide : {table_name}"}

    knowledge = get_agent_knowledge()
    captured_pattern: Optional[str] = None
    try:
        await knowledge.learn(
            table_name=effective_name,
            insight=insight,
            source="agent",
            user_id=getattr(user, "id", None),
        )
        logger.info("learn_insight: saved for table=%s", effective_name)

        # ── P4.3 : capture du motif analytique ─────────────────────────
        # Conditions : on a la question user + un SQL validé dans le
        # contexte. La question + le SQL sont envoyés à match_patterns ;
        # si un match >= seuil émerge, on l'attache comme exemplar.
        try:
            user_q = context.get("user_message") or context.get("user_question") or ""
            last_sql = context.get("_last_validated_sql") or context.get("_last_executed_sql") or ""
            if isinstance(user_q, str) and user_q.strip():
                from app.services.ai.analytical_patterns import match_patterns

                matches = match_patterns(user_q, max_results=1)
                if matches:
                    top = matches[0]
                    # Seuil prudent : on ne capture que les matches clairs
                    # (au-dessus du min_score du pattern lui-même + marge).
                    if top.score >= max(
                        float(getattr(top.pattern, "min_score", 1.0)) + 1.0,
                        3.0,
                    ):
                        exemplar_doc = (
                            f"## Exemple validé par utilisateur — "
                            f"pattern `{top.pattern.slug}`\n\n"
                            f"**Question** : {user_q.strip()}\n\n"
                            f"**Motif matché** : {top.pattern.name} "
                            f"(score {top.score:.1f})\n\n"
                        )
                        if last_sql:
                            exemplar_doc += (
                                f"**SQL validé** :\n\n```sql\n"
                                f"{str(last_sql).strip()[:4000]}\n```\n"
                            )
                        await knowledge.store.add_documentation(
                            doc=exemplar_doc,
                            category=f"pattern_exemplar:{top.pattern.slug}",
                            tags=[
                                "pattern_exemplar",
                                top.pattern.slug,
                                "validated_by_user",
                            ],
                            source="agent",
                            user_id=getattr(user, "id", None),
                        )
                        captured_pattern = top.pattern.slug
                        logger.info(
                            "learn_insight: pattern_exemplar stored for " "slug=%s (score=%.2f)",
                            top.pattern.slug,
                            top.score,
                        )
        except Exception as pattern_exc:  # noqa: BLE001
            # Capture best-effort : un échec ici ne doit PAS invalider
            # l'insight principal déjà enregistré.
            logger.debug(
                "learn_insight: pattern capture skipped (%s)",
                pattern_exc,
                exc_info=True,
            )

        response: Dict[str, Any] = {
            "success": True,
            "message": f"Connaissance enregistrée pour {effective_name}.",
        }
        if captured_pattern:
            response["pattern_exemplar"] = captured_pattern
        return response
    except Exception as exc:
        logger.error("learn_insight failed: %s", exc)
        return {"success": False, "error": f"Erreur : {exc}"}


async def _handle_trigger_schema_sync(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Trigger a schema synchronization via the frontend modal (SSE)."""
    # Au lieu de lancer le sync ici (bloquant la boucle agent),
    # on demande au frontend d'ouvrir le modal SSE qui lancera le sync.
    context["sync_requested"] = True

    return {
        "success": True,
        "message": (
            "Synchronisation lancée. Le modal de progression s'affiche "
            "dans l'interface — tu peux continuer à me parler pendant ce temps."
        ),
    }


async def _handle_check_schema_freshness(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict:
    """Check if the stored schema is fresh compared to live SQL Server."""
    try:
        from app.services.ai.schema_freshness import get_freshness_checker

        checker = get_freshness_checker()
        report = await checker.check()

        result = {
            "success": True,
            "is_fresh": report.is_fresh,
            "last_sync": report.last_sync.isoformat() if report.last_sync else None,
            "tables_added": report.tables_added,
            "tables_removed": report.tables_removed,
            "columns_changed": report.columns_changed,
            "changes_count": len(report.changes),
        }

        if not report.is_fresh:
            # Détecter si c'est un vrai changement ou une connexion impossible
            # (si TOUTES les tables sont "supprimées" et 0 ajoutées, c'est
            # probablement que le serveur SQL est inaccessible, pas que le
            # schéma a changé)
            # En mode SQLite, INFORMATION_SCHEMA n'existe pas → le check live
            # voit 0 tables et croit que tout a été supprimé. On utilise le cache.
            from app.services.database.sage_connector import get_current_sage_mode

            if get_current_sage_mode() == "sqlite":
                try:
                    store = get_training_store()
                    # Phase α.4.A : propager user.
                    table_names = await store.get_all_table_names(user=user)
                    if table_names:
                        context["_schema_freshness_checked"] = True
                        return {
                            "success": True,
                            "is_fresh": True,
                            "tables_count": len(table_names),
                            "message": (
                                f"Schéma disponible : {len(table_names)} tables. "
                                f"Tu peux exécuter des requêtes normalement."
                            ),
                        }
                except Exception:
                    pass

            result["message"] = (
                f"Le schéma n'est pas à jour. "
                f"{len(report.tables_added)} tables ajoutées, "
                f"{len(report.tables_removed)} tables supprimées, "
                f"{len(report.columns_changed)} colonnes modifiées. "
                f"Utilisez trigger_enriched_sync pour mettre à jour."
            )
        else:
            result["message"] = "Le schéma est à jour."

        return result
    except Exception as exc:
        # Fallback : si la vérification live échoue (SQLite mode, connexion
        # SQL Server indisponible), vérifier si le training store a des données.
        # Si oui, le schéma est considéré "frais depuis le cache".
        logger.warning("check_schema_freshness live check failed: %s", exc)
        try:
            store = get_training_store()
            # Phase α.4.A : propager user.
            table_names = await store.get_all_table_names(user=user)
            if table_names and len(table_names) > 0:
                logger.info(
                    "Freshness fallback: %d tables in training store, marking as fresh",
                    len(table_names),
                )
                context["_schema_freshness_checked"] = True
                return {
                    "success": True,
                    "is_fresh": True,
                    "tables_count": len(table_names),
                    "message": (
                        f"Schéma disponible : {len(table_names)} tables. "
                        f"Tu peux exécuter des requêtes normalement."
                    ),
                }
        except Exception:
            pass
        return {"success": False, "error": f"Erreur de vérification : {exc}"}


async def _handle_trigger_enriched_sync(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict:
    """Trigger schema sync + semantic enrichment. Admin only (defense-in-depth).

    M9 — ⚠️ Cet outil viole la doctrine 'Sync = 0 LLM' de
    ``.claude/rules/gladys.md`` (règle 6). Il est conservé pour le cas
    d'usage initial (one-shot post-install) mais doit être déclenché
    explicitement par l'admin via :
    - confirmation utilisateur préalable (server-enforced via
      ``ask_user_clarification`` — cf. ``_CONFIRMATION_REQUIRED_TOOLS``
      dans ``agent_service.py``)
    - le check ``role == 'admin'`` ci-dessous (defense-in-depth)

    Chaque déclenchement log un WARN d'audit explicite avec le nombre
    de tables et l'estimation de coût LLM, pour qu'un déclenchement
    anormal soit visible dans le journal admin.
    """
    # Defense-in-depth: vérifier le rôle même si execute_tool le fait déjà
    if getattr(user, "role", None) != "admin":
        logger.warning("trigger_enriched_sync: accès refusé pour user %s", getattr(user, "id", "?"))
        return {"success": False, "error": "Permission refusée. Outil réservé aux administrateurs."}

    # M9 — Audit trail systématique : tout déclenchement laisse une trace
    # explicite dans les logs (au-dessus du seuil INFO/DEBUG des autres
    # appels d'outils). Permet à l'admin de tracer un déclenchement
    # accidentel ou un coût $ surprise.
    _tables_requested = tool_input.get("tables") or "<toutes les tables changées>"
    logger.warning(
        "trigger_enriched_sync DÉCLENCHÉ par user_id=%s (admin) — tables=%s — "
        "viole doctrine 'Sync = 0 LLM' (cf. .claude/rules/gladys.md règle 6), "
        "coût LLM Haiku ≈ 1 appel/table",
        getattr(user, "id", "?"),
        _tables_requested,
    )

    try:
        from app.services.ai.schema_sync import get_sync_service
        from app.services.ai.schema_enricher import get_schema_enricher

        # Step 1: Sync schema from Sage
        sync_service = get_sync_service()
        sync_result = await sync_service.sync_from_sage(user_id=getattr(user, "id", None))

        if not sync_result.get("success"):
            return {
                "success": False,
                "error": f"Sync échouée : {sync_result.get('error', 'unknown')}",
            }

        # Step 2: Enrich semantically
        enricher = get_schema_enricher()
        tables_to_enrich = tool_input.get("tables")

        if tables_to_enrich:
            # Enrich specific tables
            from app.services.ai.training_store import get_training_store

            store = get_training_store()
            # Phase α.4.A : propager user (admin-only mais cohérence du flow).
            ddl_items = await store.get_ddl_by_table_names(tables_to_enrich, user=user)
            ddl_map = {item["table_name"]: item["content"] for item in ddl_items}
            enrich_result = await enricher.enrich_all_tables(list(ddl_map.keys()), ddl_map)
        else:
            # Enrich all tables from the sync
            from app.services.ai.training_store import get_training_store

            store = get_training_store()
            # Phase α.4.A : propager user.
            all_tables = await store.get_all_table_names(user=user)
            ddl_items = await store.get_ddl_by_table_names(all_tables, user=user)
            ddl_map = {item["table_name"]: item["content"] for item in ddl_items}
            enrich_result = await enricher.enrich_all_tables(list(ddl_map.keys()), ddl_map)

        return {
            "success": True,
            "sync_tables": sync_result.get("tables_count", 0),
            "sync_duration": round(sync_result.get("duration", 0), 1),
            "enrichment": enrich_result,
            "message": (
                f"Synchronisation + enrichissement terminés : "
                f"{sync_result.get('tables_count', 0)} tables synchronisées, "
                f"{enrich_result.get('tables_enriched', 0)} tables enrichies."
            ),
        }
    except RuntimeError as exc:
        logger.warning("trigger_enriched_sync RuntimeError: %s", exc)
        return {"success": False, "error": "Erreur de synchronisation enrichie."}
    except Exception as exc:
        logger.error("trigger_enriched_sync failed: %s", exc, exc_info=True)
        return {"success": False, "error": "Erreur de synchronisation enrichie."}


async def _handle_analyze_null_data(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict:
    """Analyse les valeurs NULL dans les résultats de requête ou une table spécifique."""
    from app.services.ai.null_analyzer import (
        get_null_analyzer,
        generate_null_report,
        suggest_completion_actions,
    )

    table_name: Optional[str] = tool_input.get("table_name")
    requested_columns: Optional[List[str]] = tool_input.get("columns")
    include_suggestions: bool = tool_input.get("include_suggestions", True)

    analyzer = get_null_analyzer()
    rows: List[Dict[str, Any]] = []
    columns: Optional[List[str]] = None
    source_label: str = "query"
    # #18e — divulgation d'échantillonnage (posés par la branche table_name).
    _sampled_from_table: bool = False
    _table_total_rows: Optional[int] = None

    if table_name:
        # Validate identifiers against SQL injection
        table_name = table_name.strip()
        if not _validate_identifier(table_name):
            return {"success": False, "error": "Nom de table invalide."}
        if requested_columns:
            for col in requested_columns:
                if not _validate_identifier(col):
                    return {"success": False, "error": f"Nom de colonne invalide : {col}"}

        # Analyse d'une table spécifique via SQL Server
        source_label = table_name
        executor = get_query_executor()

        # Construire la requête SELECT
        col_clause = ", ".join(f"[{c}]" for c in requested_columns) if requested_columns else "*"
        sql = f"SELECT TOP 200 {col_clause} FROM [{table_name}]"

        try:
            from app.services.data_access.enforcer import DataAccessDeniedError

            result = await executor.execute(
                sql, max_rows=200, add_limit=False, user=user, rls_source="analyze_null_data"
            )
            rows = result.to_dicts()
            columns = result.columns
            # #18e (triage caps 2026-06-10) — l'analyse porte sur un
            # ÉCHANTILLON TOP-sans-ORDER-BY (préfixe physique) : faux dès que
            # la distribution des NULL corrèle avec l'ordre d'insertion (ex.
            # colonne ajoutée en 2020 → 100% NULL sur les vieilles lignes).
            # Avant : présenté comme exhaustif. On récupère le vrai total
            # (fail-soft) et on DIVULGUE l'échantillonnage dans la réponse.
            _sampled_from_table = True
            _table_total_rows = None
            try:
                _count_res = await executor.execute(
                    f"SELECT COUNT_BIG(*) AS n FROM [{table_name}]",
                    max_rows=1,
                    add_limit=False,
                    user=user,
                    rls_source="analyze_null_data",
                )
                _count_rows = _count_res.to_dicts()
                if _count_rows:
                    _table_total_rows = next(iter(_count_rows[0].values()), None)
            except Exception:  # noqa: BLE001 — divulgation best-effort
                logger.debug("analyze_null_data: COUNT total échoué", exc_info=True)
        except DataAccessDeniedError as exc:
            return {
                "success": False,
                "error": exc.user_message,
                "blocked_by": "data_access_rule",
            }
        except Exception:
            logger.warning(
                "analyze_null_data: query failed for table %s", table_name, exc_info=True
            )
            return {
                "success": False,
                "error": (
                    f"Impossible de lire la table {table_name}. "
                    "Vérifiez que la table existe et que la connexion est active."
                ),
            }
    else:
        # Utiliser le dernier résultat de requête du contexte
        pending = context.get("pending_results", [])
        if not pending:
            return {
                "success": False,
                "error": (
                    "Aucun résultat de requête disponible. "
                    "Exécute d'abord une requête avec execute_sql, "
                    "ou spécifie un table_name."
                ),
            }
        last_result = pending[-1]
        rows = last_result.get("data", [])
        columns = last_result.get("columns")
        source_label = last_result.get("sql", "last_query")[:80]

    if not rows:
        return {
            "success": True,
            "message": "Aucune donnée à analyser (résultat vide).",
            "analysis": {
                "total_rows": 0,
                "columns_with_nulls": 0,
                "null_density_percent": 0,
            },
        }

    # Lancer l'analyse
    analysis = analyzer.analyze(rows, columns, source_label=source_label)
    report = generate_null_report(analysis)

    # #18e — divulgation d'échantillonnage (branche table_name uniquement ;
    # la branche pending_results analyse le résultat COMPLET déjà chargé).
    if _sampled_from_table:
        _total_note = (
            f" sur {_table_total_rows} dans la table"
            if isinstance(_table_total_rows, int)
            else ""
        )
        report = (
            f"⚠ ANALYSE SUR ÉCHANTILLON : {len(rows)} ligne(s){_total_note}, "
            "prélevées en TOP sans ORDER BY (préfixe physique, NON "
            "représentatif de la distribution). Les ratios ci-dessous valent "
            "pour cet échantillon uniquement.\n\n" + report
        )

    response: Dict[str, Any] = {
        "success": True,
        "report": report,
        "analysis": analysis.to_dict(),
    }
    if _sampled_from_table:
        response["sampling"] = {
            "is_sample": True,
            "sample_size": len(rows),
            "table_total_rows": _table_total_rows,
            "note": "TOP sans ORDER BY — échantillon non représentatif",
        }

    if include_suggestions:
        actions = suggest_completion_actions(analysis)
        response["completion_actions"] = actions
        if actions:
            response["priority_action"] = actions[0]

    logger.info(
        "analyze_null_data: %d rows, %d cols with NULLs",
        analysis.total_rows,
        analysis.columns_with_nulls,
        extra={"user_id": getattr(user, "id", None), "source": source_label[:50]},
    )

    return response


async def _handle_save_memory(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Sauvegarde une mémoire persistante pour Iris."""
    from app.services.ai.agent_memory import get_agent_memory

    content = tool_input.get("content", "").strip()
    category = tool_input.get("category", "")

    memory = get_agent_memory()
    result = await memory.save(content, category, user_id=getattr(user, "id", None))

    return {
        "success": result["status"] != "rejected",
        "status": result["status"],
        "message": result["message"],
    }


# ---------------------------------------------------------------------------
# Handlers pour les 4 outils SQL avancés (transplantés de l'orchestrateur)
# ---------------------------------------------------------------------------


async def _handle_search_schema(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Recherche 5D dans le schéma : tables, vues, colonnes, valeurs."""
    raw_keywords = tool_input.get("keywords", [])
    if not raw_keywords:
        return {"success": False, "error": "Au moins un mot-clé requis."}

    # Filtrer les keywords problématiques :
    # - Trop courts (< 2 chars) → bruit
    # - Nombres purs de 4 chiffres (années) → matchent des millions de valeurs
    # - Max 15 keywords par appel pour limiter le temps de recherche
    keywords = []
    skipped = []
    for kw in raw_keywords[:15]:
        kw = kw.strip()
        if len(kw) < 2:
            skipped.append(kw)
            continue
        keywords.append(kw)

    if not keywords:
        return {"success": False, "error": "Aucun mot-clé valide après filtrage."}

    try:
        from app.services.ai.orchestrator_search import (
            search_all_terms,
            format_results_for_llm,
        )

        indexes = await get_search_indexes()
        results = await search_all_terms(keywords, indexes)
        # 12_000 chars ≈ 3000 tokens — assez pour donner au LLM une short-list
        # de candidats pertinents, sans polluer le contexte. Avant (30_000) le
        # log montrait des recherches qui ramenaient 20k+ lignes anonymisées
        # dont le LLM ne tirait aucune info exploitable.
        formatted = format_results_for_llm(results, max_chars=12_000)

        response: Dict[str, Any] = {
            "success": True,
            "results": formatted,
            "keywords_searched": keywords,
        }
        if not results:
            response["note"] = (
                "Aucun résultat trouvé pour ces termes. "
                "Essayez des termes plus génériques ou vérifiez l'orthographe."
            )
        if skipped:
            response["keywords_skipped"] = skipped

        # ── Business context : déclencheur = tables trouvées par la recherche ──
        # On prend les top tables (tous termes confondus, par score) pour éviter
        # de polluer avec des tables peu pertinentes.
        try:
            tables_hit: List[str] = []
            seen_tables: set = set()
            for term_results in results.values():
                for match in getattr(term_results, "matches", [])[:10]:
                    tname = getattr(match, "table_name", "") or ""
                    if tname and tname.upper() not in seen_tables:
                        seen_tables.add(tname.upper())
                        tables_hit.append(tname)
                        if len(tables_hit) >= 20:
                            break
                if len(tables_hit) >= 20:
                    break
            if tables_hit:
                await _attach_business_context(response, tables_hit, token_budget=800)
        except Exception as bc_exc:
            logger.debug("search_schema: business_context attach skipped: %s", bc_exc)

        return response
    except Exception as e:
        logger.error("search_schema error: %s", e, exc_info=True)
        return {"success": False, "error": f"Erreur recherche schéma: {e}"}


async def _handle_test_sql(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict[str, Any]:
    """Exécute un COUNT(*) silencieux pour vérifier une requête en construction."""
    sql = tool_input.get("sql", "").strip()
    if not sql:
        return {"success": False, "error": "SQL requis."}

    try:
        from app.services.ai.orchestrator_tools import execute_count
        from app.services.ai.sql_validator import validate_for_iris
        from app.services.database.sage_connector import (
            SageConnectionError,
            get_current_sage_mode,
            get_sage_connector,
        )

        is_sqlite = get_current_sage_mode() == "sqlite"
        connector = get_sage_connector()

        # ── Validator unique (parité avec execute_sql, doctrine 2026-05-26) ──
        # AVANT 2026-05-26 : `test_sql` ne passait PAS par `_enforce_sql_guards`
        #   → asymétrie observable (test_sql accepte ce qu'execute_sql bloque,
        #   ou inversement). Motif légitime pour Iris de blâmer le système.
        # APRÈS : les 2 tools appellent strictement la même fonction
        #   `validate_for_iris` → asymétrie impossible par construction.
        try:
            _verdict = await validate_for_iris(sql, user, connector)
        except SageConnectionError as _sage_exc:
            logger.warning(
                "Sage unreachable during test_sql validation (deferring): %s",
                _sage_exc,
            )
            _verdict = None
        except Exception as _val_exc:  # noqa: BLE001
            logger.error(
                "validate_for_iris crashed in test_sql (fail-closed): %s",
                _val_exc,
                exc_info=True,
            )
            return {
                "success": False,
                "error": (
                    "Validation indisponible — test bloqué par sécurité. "
                    "Réessaie ou contacte l'administrateur."
                ),
                "blocked_by": "validation_error",
            }

        if _verdict is not None:
            if not _verdict.passes:
                assert _verdict.proof is not None
                return _verdict.proof.to_tool_result()
            # SQL post-RLS pour le COUNT (row_filter éventuellement appliqué)
            if _verdict.sql_used:
                sql = _verdict.sql_used

        # Marqueur oracle fail-open (cf. _handle_execute_sql, même politique).
        _oracle_unvalidated = _verdict is None or (
            _verdict.passes and getattr(_verdict, "oracle_validated", None) is False
        )

        result = await execute_count(sql, connector, user=user)

        # RLS-blocked → propager le message d'erreur explicitement
        if isinstance(result, dict) and result.get("blocked_by") == "data_access_rule":
            return {
                "success": False,
                "error": result.get("error") or "Accès refusé",
                "blocked_by": "data_access_rule",
            }

        if isinstance(result, int):
            if result < 0:
                return {
                    "success": False,
                    "count": result,
                    "sql_tested": sql[:200],
                    "error": (
                        "Le COUNT a retourné une valeur négative inattendue. "
                        "Vérifie la requête SQL."
                    ),
                }
            response: Dict[str, Any] = {
                "success": True,
                "count": result,
                "sql_tested": sql[:200],
            }
            if _oracle_unvalidated:
                from app.services.ai.sql_validator import (
                    ORACLE_NOT_PREVALIDATED_WARNING,
                )

                response["oracle_prevalidated"] = False
                response["oracle_warning"] = "⚠️ " + ORACLE_NOT_PREVALIDATED_WARNING
            if is_sqlite:
                response["_sqlite_warning"] = (
                    "⚠️ COUNT exécuté sur la copie SQLite locale (pas SQL Server). "
                    "Le résultat peut être inexact. Utilise execute_sql pour le vrai résultat."
                )
            # ── Sanity checks pré-execute : retirés (2026-05-01).
            # Les 6 checks reposaient sur des LISTES FERMÉES de cues
            # (`_AGGREGATION_CUES`, `_PER_CUES`, `_TEMPORAL_CUES`,
            # `_TOP_N_CUES`, etc.). C'est le pattern « 2+2=4 » : on tente
            # de couvrir un pan d'interprétations possibles avec une liste
            # close, alors qu'une question utilisateur peut formuler le
            # même besoin de N+1 manières dont aucune n'est dans la liste.
            # Le LLM, avec le prompt IRIS renforcé, fait ce travail mieux
            # (auto-critique sur l'adéquation question ↔ SQL avant chaque
            # execute). Le `_self_critique` rotatif (questions ouvertes
            # générateurs sur un pool de 8 angles) fournit le déclencheur
            # systématique sans liste restrictive.

            # ── Delta COUNT automatique : RETIRÉ 2026-05-26 (doctrine
            # "100% justifié") — heuristique probabiliste (ratio ×5 = cartésien
            # supposé) qui peut être fausse sur CROSS JOIN intentionnel, jointure
            # explosive légitime, ou pivot. Iris recevait un warning non
            # vérifiable → motif légitime de défausse "le système se trompe".
            # Suppression propre : Iris voit le COUNT brut et raisonne. Si le
            # cabinet veut un signal cartésien, c'est à Iris de le détecter
            # par DISTINCT/EXISTS, pas au système d'imposer une heuristique.
            return response
        elif isinstance(result, str):
            # Trivial query rejected or info message
            return {"success": True, "message": result}
        elif isinstance(result, dict):
            # Error dict with SQL Server error details
            return {"success": False, **result}
        else:
            return {"success": False, "error": f"Résultat inattendu: {result}"}
    except Exception as e:
        logger.error("test_sql error: %s", e, exc_info=True)
        return {"success": False, "error": f"Erreur test SQL: {e}"}


async def _handle_match_analytical_pattern(
    tool_input: Dict[str, Any],
    user: Any,
    context: Dict,
) -> Dict[str, Any]:
    """Match la question utilisateur contre le pattern store (P2.3).

    Retourne les 1-3 motifs analytiques les plus pertinents avec leur
    squelette SQL canonique et les rôles à résoudre. Anti-2+2=4 : les
    squelettes contiennent uniquement des placeholders génériques
    (``<fact_table>``, ``<measure_column>``) — le LLM doit instancier
    avec ses propres outils (search_schema, introspect_table).
    """
    question = tool_input.get("user_question", "") if isinstance(tool_input, dict) else ""
    if not isinstance(question, str) or not question.strip():
        return {
            "success": False,
            "error": "Paramètre 'user_question' requis (texte non vide).",
        }

    max_results = tool_input.get("max_results", 3) if isinstance(tool_input, dict) else 3
    try:
        max_results = max(1, min(5, int(max_results)))
    except (TypeError, ValueError):
        max_results = 3

    try:
        from app.services.ai.analytical_patterns import (
            fetch_exemplar_boosts,
            match_patterns,
        )
    except ImportError:
        return {"success": False, "error": "Pattern store indisponible."}

    # P2.5 : bonus basé sur les exemplars validés historiquement
    try:
        boosts = await fetch_exemplar_boosts()
    except Exception:  # best-effort
        boosts = {}
    matches = match_patterns(
        question,
        max_results=max_results,
        exemplar_boosts=boosts,
    )
    if not matches:
        return {
            "success": True,
            "matches": [],
            "hint": (
                "Aucun motif analytique standard ne matche clairement cette "
                "question. Construis ta requête normalement avec tes outils — "
                "le pattern store couvre les cas les plus courants, pas tous."
            ),
        }

    # Rendu : métadata compacte + prompt_block complet pour que le LLM voie
    # le squelette sans le perdre.
    rendered = []
    for m in matches:
        entry = m.to_dict()
        entry["prompt_block"] = m.pattern.to_prompt_block()
        rendered.append(entry)

    return {
        "success": True,
        "matches": rendered,
        "hint": (
            "Utilise le 1er match comme GUIDE STRUCTUREL (pas comme squelette "
            "à copier). Instancie les placeholders <fact_table>, "
            "<measure_column>, etc. en cherchant les vraies tables/colonnes "
            "avec search_schema + introspect_table. Si aucun motif ne "
            "convient vraiment, construis from scratch — les motifs couvrent "
            "les cas fréquents, pas tous."
        ),
    }


async def _handle_compare_query_variants(
    tool_input: Dict[str, Any],
    user: Any,
    context: Dict,
) -> Dict[str, Any]:
    """Compare 2-3 variantes SQL par COUNT parallèle (profil DBA).

    Crucial pour les cas où une petite modif change radicalement les
    résultats : filtre sur entité, INNER/LEFT JOIN, table exercices vs
    ``YEAR(facDate)``, colonne de JOIN alternative, etc.

    Contre-mesure générique : en un appel, voir le delta entre variantes
    AVANT d'exécuter la mauvaise version. Provider-agnostic, pas de LLM.

    Garde-fous :
    - min 2 / max 3 variantes par appel
    - chaque COUNT timeout ~30s (hérité du connecteur)
    - une variante en échec n'empêche pas les autres
    - retour structuré : rows par variant + delta absolu + delta %
    """
    variants_raw = tool_input.get("variants") if isinstance(tool_input, dict) else None
    if not isinstance(variants_raw, list) or len(variants_raw) < 2:
        return {
            "success": False,
            "error": "Paramètre 'variants' requis : liste de 2 à 3 variantes.",
        }
    if len(variants_raw) > 3:
        return {
            "success": False,
            "error": (
                f"Max 3 variantes par appel (reçu {len(variants_raw)}). "
                "Compare 2 à 2 si tu as plus d'alternatives."
            ),
        }

    cleaned_variants: list[dict] = []
    for i, v in enumerate(variants_raw):
        if not isinstance(v, dict):
            return {
                "success": False,
                "error": f"Variante {i + 1} invalide : attend un objet {{label, sql}}.",
            }
        label = v.get("label", "").strip() if isinstance(v.get("label"), str) else ""
        sql = v.get("sql", "").strip() if isinstance(v.get("sql"), str) else ""
        if not sql:
            return {
                "success": False,
                "error": f"Variante {i + 1} : 'sql' requis.",
            }
        if not label:
            label = f"variante {i + 1}"
        cleaned_variants.append({"label": label, "sql": sql})

    try:
        from app.services.ai.orchestrator_tools import execute_count
        from app.services.ai.sql_validator import validate_for_iris
        from app.services.database.sage_connector import (
            SageConnectionError,
            get_sage_connector,
        )

        connector = get_sage_connector()
    except Exception as exc:
        return {"success": False, "error": f"Connecteur indisponible : {exc}"}

    async def _count_one(variant: dict) -> dict:
        # ── Oracle unique AVANT exécution (parité execute_sql/test_sql, doctrine
        # 2026-05-26) ──────────────────────────────────────────────────────────
        # Sans ça, `compare_query_variants` était le SEUL chemin d'exécution SQL
        # d'Iris qui ne passait PAS par `validate_for_iris` (PARSEONLY/FMTONLY +
        # RLS) : asymétrie observable (compare comptait du SQL que execute_sql /
        # test_sql auraient bloqué) = motif légitime pour Iris de blâmer le système.
        # On valide chaque variante indépendamment ; une variante rejetée n'empêche
        # PAS les autres (garde-fou existant). RLS reste appliquée en plus par
        # execute_count (defense-in-depth ; row_filter idempotent au count).
        v_sql = variant["sql"]
        try:
            _verdict = await validate_for_iris(v_sql, user, connector)
        except SageConnectionError as _sage_exc:
            logger.warning(
                "Sage unreachable during compare_query_variants validation (deferring): %s",
                _sage_exc,
            )
            _verdict = None
        except Exception as _val_exc:  # noqa: BLE001
            logger.error(
                "validate_for_iris crashed in compare_query_variants (fail-closed): %s",
                _val_exc,
                exc_info=True,
            )
            return {
                "label": variant["label"],
                "sql": v_sql[:500],
                "count": -1,
                "error": "Validation indisponible — variante bloquée par sécurité.",
                "blocked_by": "validation_error",
            }
        if _verdict is not None:
            if not _verdict.passes:
                assert _verdict.proof is not None
                _proof = _verdict.proof.to_tool_result()
                _msg = _proof.get("error") if isinstance(_proof, dict) else None
                return {
                    "label": variant["label"],
                    "sql": v_sql[:500],
                    "count": -1,
                    "error": _msg or "SQL rejeté par la validation.",
                    "blocked_by": "validation_failed",
                }
            # SQL post-RLS pour le COUNT (row_filter éventuellement appliqué),
            # à l'identique de test_sql.
            if _verdict.sql_used:
                v_sql = _verdict.sql_used
        try:
            result = await execute_count(v_sql, connector, user=user)
            if isinstance(result, dict) and result.get("blocked_by") == "data_access_rule":
                return {
                    "label": variant["label"],
                    "sql": v_sql[:500],
                    "count": -1,
                    "error": result.get("error") or "Accès refusé",
                    "blocked_by": "data_access_rule",
                }
            if isinstance(result, int):
                # Marqueur oracle fail-open (même politique qu'execute_sql).
                _oracle_unvalidated = _verdict is None or (
                    _verdict.passes
                    and getattr(_verdict, "oracle_validated", None) is False
                )
                _out: dict = {
                    "label": variant["label"],
                    "sql": v_sql[:500],
                    "count": result,
                    "error": None,
                }
                if _oracle_unvalidated:
                    from app.services.ai.sql_validator import (
                        ORACLE_NOT_PREVALIDATED_WARNING,
                    )

                    _out["oracle_prevalidated"] = False
                    _out["oracle_warning"] = "⚠️ " + ORACLE_NOT_PREVALIDATED_WARNING
                return _out
            if isinstance(result, str):
                # Trivial query / info message
                return {
                    "label": variant["label"],
                    "sql": v_sql[:500],
                    "count": None,
                    "info": result,
                    "error": None,
                }
            if isinstance(result, dict):
                return {
                    "label": variant["label"],
                    "sql": v_sql[:500],
                    "count": None,
                    "error": result.get("error") or str(result),
                }
            return {
                "label": variant["label"],
                "sql": v_sql[:500],
                "count": None,
                "error": f"Résultat inattendu : {type(result).__name__}",
            }
        except Exception as e:
            return {
                "label": variant["label"],
                "sql": v_sql[:500],
                "count": None,
                "error": str(e)[:300],
            }

    results = await asyncio.gather(
        *[_count_one(v) for v in cleaned_variants],
        return_exceptions=False,  # chaque _count_one capture déjà ses erreurs
    )

    # Calculer les deltas entre variantes (seuls les counts numériques RÉELS).
    # Un variant bloqué (RLS / validation) renvoie count=-1 + blocked_by : il NE
    # DOIT PAS entrer dans le calcul de delta, sinon le DBA verrait des deltas
    # fantaisistes (« 100 → -1 (-101 lignes) ») = donnée fausse silencieuse
    # (consequences.md Q5). On exige un count entier >= 0 ET l'absence de blocked_by.
    deltas: list[str] = []
    counts = [
        (r["label"], r.get("count"))
        for r in results
        if isinstance(r.get("count"), int)
        and r.get("count") >= 0
        and not r.get("blocked_by")
    ]
    if len(counts) >= 2:
        for i in range(len(counts)):
            for j in range(i + 1, len(counts)):
                label_i, c_i = counts[i]
                label_j, c_j = counts[j]
                diff = c_j - c_i
                if c_i > 0:
                    pct = (diff / c_i) * 100
                    if abs(pct) < 0.5:
                        trend = "équivalent"
                    elif pct > 0:
                        trend = f"+{pct:.1f}%"
                    else:
                        trend = f"{pct:.1f}%"
                else:
                    trend = "référence vide"
                deltas.append(
                    f"'{label_j}' vs '{label_i}' : {c_i:,} → {c_j:,} "
                    f"({'+' if diff >= 0 else ''}{diff:,} lignes, {trend})"
                )

    # Interpréter les gros deltas (aide au raisonnement DBA)
    hints: list[str] = []
    if len(counts) >= 2:
        count_values = [c for _, c in counts if c is not None]
        if count_values and max(count_values) > 0:
            ratio = max(count_values) / max(1, min(count_values) if min(count_values) > 0 else 1)
            if ratio >= 5:
                hints.append(
                    "Delta majeur (×5+) entre variantes — le changement SQL a un "
                    "impact STRUCTUREL (filtre qui coupe, JOIN qui multiplie, "
                    "table/colonne qui change la sémantique). Vérifie quelle "
                    "variante correspond à l'intention utilisateur."
                )
            elif ratio >= 1.5:
                hints.append(
                    "Delta notable entre variantes — le changement SQL affecte "
                    "visiblement le scope. Confirme avec l'utilisateur si tu "
                    "n'es pas certain du choix."
                )

    return {
        "success": True,
        "variants_compared": len(cleaned_variants),
        "results": results,
        "deltas": deltas,
        "interpretation_hints": hints,
    }


async def _handle_introspect_tables_batch(
    tool_input: Dict[str, Any],
    user: Any,
    context: Dict,
) -> Dict[str, Any]:
    """Introspecte plusieurs tables en parallèle (C21 — sub-agent programmatique).

    Agit comme un "sub-agent Schema Explorer" sans LLM : le main agent
    fournit une liste de tables, on déclenche les introspections en
    parallèle via ``asyncio.gather``, et on retourne un résumé consolidé.

    Avantages vs appels séquentiels :
    - Réduit les round-trips LLM (1 tool_use au lieu de N)
    - Parallélise les requêtes SQL Server (gain de latence)
    - Provider-agnostic : aucun appel LLM nécessaire
    """
    raw_tables = tool_input.get("table_names") if isinstance(tool_input, dict) else None
    if not isinstance(raw_tables, list) or not raw_tables:
        return {
            "success": False,
            "error": "Paramètre 'table_names' requis : liste non vide.",
        }

    if len(raw_tables) > 10:
        return {
            "success": False,
            "error": (
                f"Max 10 tables par appel (reçu {len(raw_tables)}). "
                "Découpe en plusieurs batches."
            ),
        }

    # Validation + normalisation des identifiants
    cleaned: list[str] = []
    invalid: list[str] = []
    for t in raw_tables:
        if not isinstance(t, str):
            invalid.append(str(t)[:50])
            continue
        t_clean = t.strip()
        if not t_clean or not _validate_identifier(t_clean):
            invalid.append(t_clean[:50])
            continue
        cleaned.append(t_clean)

    if invalid:
        return {
            "success": False,
            "error": (
                f"Noms de tables invalides : {invalid[:3]}. "
                "Les noms doivent être des identifiants SQL valides."
            ),
        }

    info_type = tool_input.get("info_type", "all")
    if info_type not in ("columns", "foreign_keys", "all"):
        info_type = "all"

    # Déduplication préservant l'ordre
    seen: set[str] = set()
    unique_tables = []
    for t in cleaned:
        key = t.lower()
        if key not in seen:
            seen.add(key)
            unique_tables.append(t)

    # Introspection — on sérialise via un semaphore même si asyncio.gather
    # est utilisé. Raison : ``_handle_introspect_table`` écrit dans
    # ``context["_introspect_cache"]`` et mute des résultats partagés
    # (``_enrich_columns_with_roles``). Deux coroutines qui traitent des
    # tables ayant des voisins FK en commun peuvent race sur les mêmes
    # clés de cache et produire des colonnes enrichies incohérentes.
    # Compromis : on perd le parallélisme mais on garde la correctness.
    # L'appel I/O-bound sur une seule connexion Sage ne bénéficie de
    # toute façon pas beaucoup du parallélisme.
    _batch_lock = asyncio.Semaphore(1)

    async def _introspect_one(table_name: str) -> Dict[str, Any]:
        async with _batch_lock:
            return await _handle_introspect_table(
                {"table_name": table_name, "info_type": info_type},
                user,
                context,
            )

    sub_results = await asyncio.gather(
        *[_introspect_one(t) for t in unique_tables],
        return_exceptions=True,
    )

    consolidated: Dict[str, Any] = {
        "success": True,
        "info_type": info_type,
        "tables_requested": len(raw_tables),
        "tables_introspected": len(unique_tables),
        "tables": {},
    }
    per_table_errors: list[str] = []

    for tname, res in zip(unique_tables, sub_results):
        if isinstance(res, Exception):
            per_table_errors.append(f"{tname}: {str(res)[:150]}")
            consolidated["tables"][tname] = {
                "success": False,
                "error": str(res)[:300],
            }
        elif isinstance(res, dict):
            consolidated["tables"][tname] = res
            if not res.get("success", True):
                per_table_errors.append(f"{tname}: {str(res.get('error', 'unknown'))[:150]}")

    if per_table_errors:
        consolidated["partial_errors"] = per_table_errors

    return consolidated


async def _handle_diagnose_zero_rows(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Diagnostique pourquoi un SQL retourne 0 lignes (B12).

    Extrait les filtres WHERE via sqlglot, classe chaque prédicat par
    risque de 0 lignes, et retourne un plan d'action : quels filtres
    tester en premier avec ``test_sql``.

    Ne lance AUCUN COUNT lui-même : l'exécution est à la charge du LLM
    via ``test_sql`` pour rester compatible avec les modes SQLite/SQL
    Server et éviter de dupliquer la logique de connexion. Purement
    analytique — testable sans BDD.
    """
    sql = tool_input.get("sql", "").strip() if isinstance(tool_input, dict) else ""
    if not sql:
        return {"success": False, "error": "Paramètre 'sql' requis."}

    try:
        from app.services.ai.filter_extractor import (
            extract_filters_from_sql,
            summarize_filters_fr,
        )
    except ImportError:
        return {"success": False, "error": "Module filter_extractor indisponible."}

    filters = extract_filters_from_sql(sql)

    result: Dict[str, Any] = {
        "success": True,
        "sql_analyzed": sql[:200] + ("…" if len(sql) > 200 else ""),
    }

    if not filters:
        result["has_filters"] = False
        result["diagnosis"] = "no_where_clause"
        result["action_plan"] = (
            "Le SQL n'a pas de clause WHERE. Un retour de 0 lignes indique "
            "soit que la table de base est vide (teste SELECT COUNT(*) FROM "
            "<table_base>), soit qu'une condition JOIN élimine toutes les "
            "lignes. Retire les JOIN un par un via test_sql pour identifier "
            "celui qui coupe — ou passe en LEFT JOIN pour voir les orphelins."
        )
        return result

    # Classer les filtres par risque observé
    high_risk: list[dict] = []
    medium_risk: list[dict] = []
    low_risk: list[dict] = []

    for f in filters:
        col = f.column.strip("[]")
        # IS NULL : très restrictif sur la plupart des colonnes
        if f.operator == "IS NULL":
            high_risk.append(
                {
                    "filter": f.raw,
                    "column": col,
                    "reason": (
                        "IS NULL — très restrictif si la colonne a rarement des "
                        "NULL. Vérifie si les lignes attendues ont vraiment NULL "
                        "ou si c'est IS NOT NULL qu'il faut."
                    ),
                }
            )
        # IN avec 1 ou 2 valeurs : fragile si une valeur est mal orthographiée
        elif f.operator == "IN" and isinstance(f.value, list) and 0 < len(f.value) <= 2:
            high_risk.append(
                {
                    "filter": f.raw,
                    "column": col,
                    "reason": (
                        f"IN avec {len(f.value)} valeur(s) — teste que ces "
                        "valeurs existent EXACTEMENT via get_resolved_values "
                        "(casse, accents, espaces)."
                    ),
                }
            )
        # Égalité string : même problème
        elif f.operator == "=" and isinstance(f.value, str):
            high_risk.append(
                {
                    "filter": f.raw,
                    "column": col,
                    "reason": (
                        "Égalité sur string — vérifie via get_resolved_values "
                        "que la valeur existe exactement (casse, espaces)."
                    ),
                }
            )
        # LIKE : sensible au pattern
        elif f.operator == "LIKE":
            medium_risk.append(
                {
                    "filter": f.raw,
                    "column": col,
                    "reason": (
                        "LIKE — vérifie le pattern (wildcards %/_, casse "
                        "sensible selon collation)."
                    ),
                }
            )
        # Dates / plages numériques
        elif f.operator in (">=", ">", "<=", "<", "BETWEEN"):
            medium_risk.append(
                {
                    "filter": f.raw,
                    "column": col,
                    "reason": (
                        "Filtre de plage/date — vérifie les bornes "
                        "(mois/année/timezone) et que les données existent "
                        "dans cette plage."
                    ),
                }
            )
        else:
            low_risk.append(
                {
                    "filter": f.raw,
                    "column": col,
                    "reason": "Opérateur standard — moins probable comme coupable.",
                }
            )

    # Réordonner : high_risk d'abord, puis medium, puis low
    ranked = high_risk + medium_risk + low_risk
    # Plan d'action : suggérer test_sql sur chaque filtre retiré
    steps = []
    for i, r in enumerate(ranked[:5], 1):
        steps.append(
            f"{i}. Retire le filtre `{r['filter']}` et relance test_sql. "
            f"Si le COUNT passe à >0, ce filtre est le coupable "
            f"({r['reason']})."
        )

    result["has_filters"] = True
    result["diagnosis"] = "has_filters_to_test"
    result["filter_count"] = len(filters)
    result["filters_summary_fr"] = summarize_filters_fr(filters)
    result["high_risk_filters"] = high_risk
    result["medium_risk_filters"] = medium_risk
    result["low_risk_filters"] = low_risk
    result["action_plan"] = (
        "\n".join(steps)
        if steps
        else (
            "Aucun filtre suspect à risque élevé. Le 0 lignes vient "
            "probablement d'une JOIN — teste en retirant les JOIN un par un."
        )
    )

    return result


async def _handle_get_fk_path(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Trouve le chemin FK entre deux tables via BFS + recommandation JOIN."""
    from_table = tool_input.get("from_table", "").strip()
    to_table = tool_input.get("to_table", "").strip()
    if not from_table or not to_table:
        return {"success": False, "error": "from_table et to_table requis."}

    try:
        from app.services.ai.orchestrator_tools import recommend_join

        store = get_training_store()
        fk_graph = await get_fk_graph()
        result = await recommend_join(from_table, to_table, fk_graph, store)

        return {"success": True, **result}
    except Exception as e:
        logger.error("get_fk_path error: %s", e, exc_info=True)
        return {"success": False, "error": f"Erreur recherche FK: {e}"}


async def _handle_get_resolved_values(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Trouve les valeurs réelles matchant un terme, retourne les tokens anonymisés."""
    term = tool_input.get("term", "").strip()
    table_name = tool_input.get("table_name", "").strip()
    column_name = tool_input.get("column_name", "").strip()
    if not term or not table_name or not column_name:
        return {"success": False, "error": "term, table_name et column_name requis."}

    try:
        from app.services.ai.orchestrator_tools import get_resolved_values

        result = await get_resolved_values(term, table_name, column_name)
        return {"success": True, **result}
    except Exception as e:
        logger.error("get_resolved_values error: %s", e, exc_info=True)
        return {"success": False, "error": f"Erreur résolution valeurs: {e}"}


# #A5 (revue adversariale) : UNKNOWN RETIRÉ. Le fallback word-split (JSON KO,
# ligne ~9545) ET le défaut role-less (``concept.get("role", "UNKNOWN")``)
# produisent UNKNOWN → flagger l'ambiguïté dessus sur-sollicitait l'utilisateur
# (ce que David déteste) sur le chemin dégradé. Seuls les rôles de filtre/axe
# EXPLICITEMENT extraits par le LLM déclenchent désormais la désambiguïsation.
_AMBIGUITY_SENSITIVE_ROLES = frozenset({"WHERE_IN", "WHERE_NOT", "GROUP_BY"})


def _is_cross_table_ambiguous(candidate_cols: set, role: str) -> bool:
    """True si un concept de filtre/axe matche N≥2 colonnes sur ≥2 tables.

    Heuristique anti-faux-silencieux (bug « entité » SOFIGEC) : un concept
    de FILTRE/AXE (WHERE/GROUP BY) qui correspond à plusieurs colonnes
    DISTINCTES réparties sur des tables différentes est une ambiguïté
    d'INTENTION métier — le choix change le résultat et doit être tranché
    par l'utilisateur, pas deviné. On NE lève PAS l'ambiguïté pour un simple
    SELECT (mauvais choix visible/corrigeable) ni pour une seule colonne.
    100% générique : ``candidate_cols`` est un set de ``(table, column)``
    issu du schéma réel, aucun nom hardcodé.
    """
    if role not in _AMBIGUITY_SENSITIVE_ROLES:
        return False
    if len(candidate_cols) < 2:
        return False
    distinct_tables = {t for (t, _c) in candidate_cols}
    return len(distinct_tables) >= 2


async def _handle_align_request(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Rassemble TOUS les candidats pour chaque concept de la requête utilisateur.

    Fait programmatiquement le travail de Phase 1 de l'orchestrateur :
    1. Extrait les concepts via un appel LLM léger
    2. Cherche TOUT pour chaque concept dans les index 5D
    3. Classe chaque concept : found/ambiguous/not_found/calculated
    4. Retourne un plan structuré
    """
    user_message = tool_input.get("user_message", "").strip()
    if not user_message:
        return {"success": False, "error": "Message utilisateur requis."}

    try:
        from app.services.ai.orchestrator_search import (
            search_all_terms,
            format_results_for_llm,
        )

        indexes = await get_search_indexes()

        # ── Étape 1 : Extraire les concepts (LLM léger) ──
        # Réutiliser le prompt d'extraction de l'orchestrateur
        from app.services.ai.llm_providers import LLMRequest
        from app.services.ai.llm_runtime import CallProfile, ModelKind, call_llm
        from app.services.anonymization import anonymize_for_llm
        from app.services.anonymization.proxy import (
            get_confidentiality_prompt,
        )

        extract_prompt = (
            "Extrais de cette requête utilisateur tous les concepts qui correspondent "
            "à des données dans une base de données SQL.\n\n"
            f"Requête : {user_message}\n\n"
            "Pour chaque concept, identifie :\n"
            "- Le terme principal et 2-3 synonymes/variantes\n"
            "- Le rôle SQL probable : SELECT (donnée demandée), WHERE_IN (filtre inclusion), "
            "WHERE_NOT (filtre exclusion), GROUP_BY (axe d'analyse), FROM (source)\n"
            "- Les valeurs littérales mentionnées (codes, noms, nombres)\n\n"
            "Réponds UNIQUEMENT en JSON :\n"
            '{"concepts": [\n'
            '  {"term": "concept principal", "synonyms": ["syn1", "syn2"], '
            '"role": "SELECT|WHERE_IN|WHERE_NOT|GROUP_BY|FROM", '
            '"values": ["val1", "val2"]}\n'
            "]}"
        )

        # Proxy d'anonymisation single source of truth. **user_id thread**
        # depuis le ``user`` authentifié : l'extraction de concepts ne
        # raisonne PAS sur le schéma (Cycle 8 RESOLVE ne s'applique pas
        # ici — c'est une étape locale d'extraction de tokens), donc le
        # pseudonymizer user-scoped est légitime. Sans ça, des noms de
        # clients / fournisseurs / codes métier (ex: ``DUPONT MARTIN
        # SARL``) seraient envoyés en cleartext au LLM cloud — couvert
        # par aucune regex PII built-in (review adversariale tâche #7,
        # finding HIGH).
        #
        # Flow :
        # 1. ``DUPONT MARTIN SARL`` dans ``user_message`` → tokenisé
        #    ``§abc§`` par le pseudonymizer + ``[EMAIL_N]``/etc. par PII regex
        # 2. LLM extrait ``values: ["§abc§"]`` du JSON
        # 3. ``restore_fn(response.content)`` dé-tokenise → ``values:
        #    ["DUPONT MARTIN SARL"]``
        # 4. ``search_all_terms`` (local, en-mémoire) match l'index 5D
        #    avec le cleartext — strictement local, pas d'envoi LLM.
        user_id_for_anon = getattr(user, "id", None) if user is not None else None
        extract_prompt_anon, restore_fn = await anonymize_for_llm(
            user_id_for_anon, extract_prompt, "IRIS_CHAT"
        )
        extract_response = await call_llm(
            CallProfile(
                caller="agent_tool_concepts",
                model_kind=ModelKind.UTILITY,
                max_tokens_soft=2000,
            ),
            LLMRequest(
                prompt=extract_prompt_anon,
                system=(
                    get_confidentiality_prompt("IRIS_CHAT")
                    + "\n\n"
                    + "Tu es un expert en extraction de termes SQL. Réponds UNIQUEMENT en JSON."
                ),
                temperature=0.0,
            ),
        )
        # Parser le JSON ENCORE anonymisé puis restaurer la structure
        # (review adversariale tâche #7 — EPIC E4 + E5). Ordre :
        #   1. ``json.loads`` sur la réponse anonymisée — les tokens
        #      ``[EMAIL_N]`` / ``§…§`` ne contiennent jamais de caractères
        #      JSON-spéciaux (``"``, ``\\``, ``\\n``), donc le parsing est
        #      sûr. Le cleartext susceptible de casser le JSON (``Jean
        #      "JJ" Dupont``) reste hors de la chaîne brute.
        #   2. ``restore_fn`` sur la structure parsée — le walker récursif
        #      du proxy gère dict/list/str et restaure chaque valeur
        #      string-by-string, où les caractères spéciaux ne sont plus
        #      structurels (déjà désérialisés par ``json.loads``).
        # Pas de mutation de ``extract_response.content`` (cf. EPIC E5 —
        # divergence ``raw_response`` / ``completion_tokens``, risque
        # cache poisoning futur). On travaille sur une variable locale.
        import json as _json

        concepts: list = []
        raw_anon = (extract_response.content or "").strip()
        try:
            json_start = raw_anon.find("{")
            json_end = raw_anon.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                parsed_anon = _json.loads(raw_anon[json_start:json_end])
                parsed = restore_fn(parsed_anon)
                concepts = parsed.get("concepts", []) if isinstance(parsed, dict) else []
        except Exception as parse_err:
            logger.warning("align_request: JSON parse failed: %s", parse_err)
            # Fallback : utiliser les mots du message comme termes
            words = [w for w in user_message.split() if len(w) >= 3]
            concepts = [
                {"term": w, "synonyms": [], "role": "UNKNOWN", "values": []} for w in words[:10]
            ]

        if not concepts:
            return {"success": False, "error": "Aucun concept extrait de la requête."}

        # ── Étape 2 : Chercher TOUS les candidats pour chaque concept ──
        # ── Recherches PARALLÈLES pour tous les concepts ──
        # Au lieu de chercher séquentiellement (lent), on lance toutes
        # les recherches en parallèle avec asyncio.gather.

        # Collecter TOUS les termes à chercher (concepts + valeurs)
        all_search_terms: list[str] = []
        for concept in concepts:
            all_search_terms.append(concept.get("term", ""))
            all_search_terms.extend(concept.get("synonyms", []))
            all_search_terms.extend(concept.get("values", []))

        # Dédupliquer et filtrer
        unique_terms = list(dict.fromkeys(t for t in all_search_terms if t and len(t) >= 2))

        # UNE seule recherche massive (le moteur gère le batching)
        all_results = await search_all_terms(unique_terms, indexes)

        # ── Lecteur ConceptGlossary (#13) : rejoue les désambiguïsations DÉJÀ
        # validées par feedback ✅ pour ne PAS redemander (boucle « apprendre →
        # rejouer »). Fail-open : si la lecture échoue, on continue sans (le pire
        # cas = on redemande, jamais un faux). ──
        try:
            from app.services.ai.agent_knowledge import get_concept_glossary_mappings

            # #A1 (revue adversariale) : la clé glossaire ÉCRITE vient de
            # l'extraction concept du PIPELINE ; la clé LUE ici vient de
            # l'extraction d'align_request (prompts différents → libellés
            # divergents, « CA » vs « chiffre d'affaires »). On élargit la
            # recherche aux SYNONYMES (qu'align_request extrait déjà) pour que la
            # clé pipeline matche au moins un synonyme → le rejeu #13 se déclenche.
            _glossary_terms: list[str] = []
            for _c in concepts:
                _glossary_terms.append(_c.get("term", ""))
                _glossary_terms.extend(_c.get("synonyms", []) or [])
            glossary = await get_concept_glossary_mappings(_glossary_terms)
        except Exception as _gloss_exc:
            logger.debug("align_request: lecture glossaire ignorée: %s", _gloss_exc)
            glossary = {}

        # Construire le plan par concept
        alignment_plan: list[dict] = []

        for concept in concepts:
            term = concept.get("term", "")
            synonyms = concept.get("synonyms", [])
            role = concept.get("role", "UNKNOWN")
            values = concept.get("values", [])

            # Extraire les résultats pour CE concept
            concept_terms = [term] + synonyms
            concept_results = {t: all_results[t] for t in concept_terms if t in all_results}
            formatted = format_results_for_llm(concept_results, max_chars=5_000)

            # Extraire les localisations de valeurs
            value_locations: list[dict] = []
            for val in values:
                if val in all_results:
                    for m in all_results[val].matches:
                        if m.dimension == "value" and m.match_type in ("exact", "contains"):
                            value_locations.append(
                                {
                                    "value": val,
                                    "table": m.table_name,
                                    "column": m.column_name,
                                    "match_type": m.match_type,
                                    "real_value": m.real_value or "",
                                }
                            )

            # Déduplication
            seen_vl: set[tuple] = set()
            unique_vl = []
            for vl in value_locations:
                key = (vl["value"], vl["table"], vl["column"])
                if key not in seen_vl:
                    seen_vl.add(key)
                    unique_vl.append(vl)

            # Statut
            has_columns = any(
                m.dimension in ("column", "view_column") and m.match_type in ("exact", "contains")
                for r in concept_results.values()
                for m in r.matches
            )
            has_values = len(unique_vl) > 0

            # ── Ambiguïté STRUCTURELLE (anti-faux-silencieux, bug « entité ») ──
            # Si un concept de FILTRE/AXE matche N≥2 colonnes DISTINCTES sur ≥2
            # TABLES différentes, le choix de colonne change le résultat et n'est
            # PAS tranchable par les outils seuls = question d'INTENTION métier.
            # Détection 100% programmatique et générique (aucun nom hardcodé),
            # depuis les candidats 5D DÉJÀ montrés au LLM (cohérence plan↔question).
            # Restreinte aux rôles où un mauvais choix = chiffre faux SILENCIEUX
            # (filtre/group) — on ne sur-sollicite pas sur un simple SELECT.
            # Candidats = colonnes de TABLES DE BASE uniquement (dimension
            # "column", PAS "view_column") : une vue dérive de ses tables, donc
            # « Factures.facMontant vs viewX.montant » n'est pas une vraie
            # ambiguïté de sens (même donnée) — l'inclure sur-solliciterait
            # l'utilisateur. Le bug ciblé (« entité ») est inter-tables-de-base.
            candidate_cols = {
                (m.table_name, m.column_name)
                for r in concept_results.values()
                for m in r.matches
                if m.dimension == "column"
                and m.match_type in ("exact", "contains")
                and m.table_name
                and m.column_name
            }
            is_cross_table_ambiguous = _is_cross_table_ambiguous(candidate_cols, role)
            # #A1 : on cherche le mapping appris par le terme PUIS ses synonymes
            # (priorité au terme) — la clé pipeline peut correspondre à l'un d'eux.
            learned: list = []
            for _lk in [term] + (synonyms or []):
                _lk_norm = (_lk or "").strip().lower()
                if _lk_norm and _lk_norm in glossary:
                    learned = glossary[_lk_norm]
                    break

            if len(learned) == 1:
                # Concept DÉJÀ désambiguïsé par un feedback ✅ antérieur (UN SEUL
                # mapping appris) → on applique sans redemander. Boucle « demander
                # une fois, apprendre, rejouer » : surclasse la détection #11.
                # #A4 (revue adversariale) : si ≥2 mappings concurrents (concept
                # multi-contexte), on NE surclasse PAS — imposer le mapping d'un
                # autre contexte en silence rouvrirait le faux-silencieux. Le
                # glossaire reste affiché comme HINT (learned_mapping/alternatives)
                # mais l'ambiguïté est maintenue → l'utilisateur tranche pour CE
                # contexte.
                status = "found"
                is_cross_table_ambiguous = False
            elif is_cross_table_ambiguous:
                # Prime sur "found" : colonnes concurrentes inter-tables → lever
                # l'ambiguïté AVANT le SQL (sinon faux silencieux type SOFIGEC).
                status = "ambiguous"
            elif has_columns and (not values or has_values):
                status = "found"
            elif has_columns and values and not has_values:
                status = "calculated"
            elif not has_columns and has_values:
                status = "value_only"
            elif has_columns:
                status = "ambiguous"
            else:
                status = "not_found"

            alignment_plan.append(
                {
                    "concept": term,
                    "role": role,
                    "status": status,
                    "search_results": formatted,
                    "values_found": unique_vl[:10],
                    "values_requested": values,
                    "candidate_columns": sorted(f"{t}.{c}" for (t, c) in candidate_cols),
                    "learned_mapping": learned[0] if learned else None,
                    "learned_alternatives": learned[1:5] if len(learned) > 1 else [],
                }
            )

        # ── Étape 3 : Formater le plan ──
        plan_lines = ["# PLAN D'ALIGNEMENT\n"]
        found_count = sum(1 for c in alignment_plan if c["status"] == "found")
        total = len(alignment_plan)
        plan_lines.append(
            f"**{found_count}/{total} concepts alignés.** "
            f"Vérifie chaque concept avant de construire le SQL.\n"
        )

        _ambiguous_plan = [c for c in alignment_plan if c["status"] == "ambiguous"]
        if _ambiguous_plan:
            plan_lines.append(
                f"\n> 🛑 **STOP — {len(_ambiguous_plan)} concept(s) AMBIGU(S).** "
                "Avant d'écrire le moindre SQL, lève l'ambiguïté avec "
                "`ask_user_clarification` : présente les options en langage MÉTIER "
                "(pas en schéma) avec un échantillon de ce que chacune donnerait. "
                "Choisir au hasard = risque de chiffre FAUX silencieux.\n"
            )

        for c in alignment_plan:
            icon = {
                "found": "✅",
                "ambiguous": "⚠️",
                "not_found": "❌",
                "calculated": "🔧",
                "value_only": "📍",
            }.get(c["status"], "❓")

            plan_lines.append(f"\n## {icon} {c['concept']} ({c['role']})")

            if c.get("learned_mapping"):
                _lm = c["learned_mapping"]
                plan_lines.append(
                    f"  → ✅ APPRIS (feedback validé {_lm.get('usage_count', 1)}×) : "
                    f"pour ce concept, utilise `{_lm['table']}.{_lm['column']}`. "
                    "Ne redemande pas — désambiguïsation déjà confirmée."
                )
                _alts = c.get("learned_alternatives") or []
                if _alts:
                    plan_lines.append(
                        "    Alternatives apprises (moins fréquentes) : "
                        + ", ".join(f"{a['table']}.{a['column']}" for a in _alts)
                    )

            if c["status"] == "calculated":
                plan_lines.append(
                    "  → Colonnes trouvées mais valeurs non stockées. "
                    "Probablement une VALEUR CALCULÉE (CASE WHEN, DATEDIFF, etc.)."
                )
            elif c["status"] == "not_found":
                plan_lines.append(
                    "  → Rien trouvé. Utilise introspect_table sur les tables proches "
                    "ou demande à l'utilisateur."
                )
            elif c["status"] == "value_only":
                plan_lines.append(
                    "  → Valeur trouvée mais pas de colonne directe. "
                    "La valeur est peut-être dans une colonne au nom différent."
                )
            elif c["status"] == "ambiguous":
                plan_lines.append(
                    "  → ⚠️ AMBIGU : ce concept correspond à PLUSIEURS colonnes sur "
                    "des tables différentes — le choix change le résultat. DEMANDE à "
                    "l'utilisateur laquelle via `ask_user_clarification` (langage "
                    "métier, AVANT tout SQL). Ne devine pas."
                )
                _cand = c.get("candidate_columns") or []
                if _cand:
                    plan_lines.append(f"    Candidats : {', '.join(_cand[:8])}")

            # Valeurs trouvées
            if c["values_found"]:
                plan_lines.append("  **Valeurs localisées :**")
                for vl in c["values_found"][:5]:
                    plan_lines.append(
                        f"    - \"{vl['value']}\" → {vl['table']}.{vl['column']} "
                        f"[{vl['match_type']}] (valeur: \"{vl['real_value']}\")"
                    )
            elif c["values_requested"]:
                plan_lines.append(
                    f"  **Valeurs demandées mais NON trouvées : {c['values_requested']}**"
                )

            # Résultats de recherche
            plan_lines.append(f"  **Candidats :**\n{c['search_results']}")

        # P2.4 — Injecter un éventuel motif analytique probable en
        # tête du plan. Anti-2+2=4 : on ne prescrit rien, on donne
        # le squelette canonique avec placeholders génériques, le
        # LLM reste maître de l'instancier (et de choisir un autre
        # pattern ou construire from scratch).
        pattern_section = ""
        try:
            from app.services.ai.analytical_patterns import (
                fetch_exemplar_boosts,
                match_patterns,
            )

            try:
                boosts_align = await fetch_exemplar_boosts()
            except Exception:
                boosts_align = {}
            top_matches = match_patterns(
                user_message,
                max_results=2,
                exemplar_boosts=boosts_align,
            )
            if top_matches:
                sec_lines = [
                    "\n\n## 🧩 Motif analytique probable",
                    "",
                    "Un ou plusieurs motifs réutilisables matchent cette "
                    "question. Voir aussi `match_analytical_pattern` si tu "
                    "veux le détail complet.",
                    "",
                ]
                for m in top_matches:
                    sec_lines.append(
                        f"- **{m.pattern.name}** (score {m.score:.1f}, "
                        f"slug `{m.pattern.slug}`) — {m.pattern.description.splitlines()[0]}"
                    )
                sec_lines.append("")
                sec_lines.append(
                    "Utilise ces motifs comme GUIDE STRUCTUREL (CTE, window "
                    "functions, recursive CTE…) en instanciant les rôles "
                    "avec les tables/colonnes que tu vas trouver dans les "
                    "étapes suivantes."
                )
                pattern_section = "\n".join(sec_lines)
        except Exception as _pattern_exc:
            logger.debug("Pattern matching in align_request skipped: %s", _pattern_exc)

        # Note : le flag ``context["_pending_ambiguity"]`` (qui armait le guard
        # DUR #15 bloquant ``execute_sql``) a été RETIRÉ 2026-06-11 sur demande
        # utilisateur. Le signal d'ambiguïté reste SOFT : ``requires_user_clarification``
        # + ``ambiguous_concepts`` dans le résultat ci-dessous + bannière 🛑 dans
        # le plan + prompt #12 → l'agent est DIRIGÉ vers ``ask_user_clarification``,
        # il n'est plus FORCÉ.

        return {
            "success": True,
            "alignment_plan": "\n".join(plan_lines) + pattern_section,
            "concepts_count": total,
            "found": found_count,
            "ambiguous": sum(1 for c in alignment_plan if c["status"] == "ambiguous"),
            "not_found": sum(1 for c in alignment_plan if c["status"] == "not_found"),
            "calculated": sum(1 for c in alignment_plan if c["status"] == "calculated"),
            "pattern_hint_count": pattern_section.count("**") // 2 if pattern_section else 0,
            # Anti-faux-silencieux : signal machine-lisible (consommable par un
            # guard amont agent_service [tâche #11b] ET par le LLM) — il DOIT
            # clarifier les concepts ambigus avant de générer du SQL.
            "requires_user_clarification": any(
                c["status"] == "ambiguous" for c in alignment_plan
            ),
            "ambiguous_concepts": [
                {
                    "concept": c["concept"],
                    "role": c["role"],
                    "candidates": c.get("candidate_columns", []),
                }
                for c in alignment_plan
                if c["status"] == "ambiguous"
            ],
        }
    except Exception as e:
        logger.error("align_request error: %s", e, exc_info=True)
        return {"success": False, "error": f"Erreur alignement: {e}"}


async def _handle_check_join_compatibility(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Vérifie la compatibilité de jointure entre deux colonnes sans FK déclarée."""
    table_a = tool_input.get("table_a", "").strip()
    column_a = tool_input.get("column_a", "").strip()
    table_b = tool_input.get("table_b", "").strip()
    column_b = tool_input.get("column_b", "").strip()

    if not all([table_a, column_a, table_b, column_b]):
        return {"success": False, "error": "Tous les paramètres sont requis."}

    # ── Validation d'identifiants (anti-injection) ──
    # table_*/column_* sont interpolés en f-string `[{...}]` dans la requête
    # INTERSECT ci-dessous. Sans validation, un nom contenant `]` casse le
    # bracket-quoting (injection SQL). Même garde que peek_table_data /
    # execute_sql (SSoT _validate_identifier).
    for _ident in (table_a, column_a, table_b, column_b):
        if not _validate_identifier(_ident):
            return {"success": False, "error": "Nom de table ou de colonne invalide."}

    # ── RLS check (defense-in-depth) ──
    # check_join_compatibility est un canal latéral majeur (count des
    # valeurs distinctes / overlap entre 2 colonnes). On bloque si
    # l'une des deux tables/colonnes est interdite à l'user.
    try:
        from app.services.data_access.enforcer import (
            DataAccessDeniedError,
            assert_table_access,
        )

        await assert_table_access(table_a, user, columns=[column_a])
        await assert_table_access(table_b, user, columns=[column_b])
    except DataAccessDeniedError as exc:
        return {
            "success": False,
            "error": exc.user_message,
            "blocked_by": "data_access_rule",
        }

    try:
        from app.services.database.sage_connector import get_sage_connector

        connector = get_sage_connector()

        # Même requête INTERSECT que le sync utilise pour détecter les FK inférées
        sql = (
            f"SELECT "
            f"(SELECT COUNT(DISTINCT [{column_a}]) FROM [{table_a}]) AS distinct_a, "
            f"(SELECT COUNT(DISTINCT [{column_b}]) FROM [{table_b}]) AS distinct_b, "
            f"(SELECT COUNT(*) FROM ("
            f"SELECT DISTINCT [{column_a}] FROM [{table_a}] "
            f"INTERSECT "
            f"SELECT DISTINCT [{column_b}] FROM [{table_b}]"
            f") x) AS overlap"
        )

        # ── RLS row-level (en plus du check table/colonne ci-dessus) ──
        # Injecte les filtres de LIGNES de l'user dans la requête de comptage —
        # sinon distinct/overlap portent sur TOUTES les lignes (canal latéral de
        # cardinalité sur des lignes non visibles). SSoT = enforce_for_executor
        # (idem execute_count / query_executor). Fail-closed : enforce_sql renvoie
        # denied si un row_filter ne peut pas être appliqué proprement — JAMAIS
        # de SQL non filtrée (donc pas de count faux silencieux).
        from app.services.data_access.enforcer import (
            DataAccessDeniedError,
            enforce_for_executor,
        )

        try:
            sql = await enforce_for_executor(sql, user, source="check_join_compatibility")
        except DataAccessDeniedError as exc:
            return {
                "success": False,
                "error": exc.user_message,
                "blocked_by": "data_access_rule",
            }

        result = await connector.execute(sql, max_rows=1)
        if not result.rows:
            return {"success": False, "error": "Pas de résultat."}

        row = result.rows[0]
        distinct_a = int(row[0] or 0)
        distinct_b = int(row[1] or 0)
        overlap = int(row[2] or 0)

        if distinct_a == 0 and distinct_b == 0:
            return {"success": True, "compatible": False, "reason": "Les deux colonnes sont vides."}

        # Calculer la compatibilité dans les deux sens
        containment_a_in_b = overlap / distinct_a if distinct_a > 0 else 0
        containment_b_in_a = overlap / distinct_b if distinct_b > 0 else 0
        best_containment = max(containment_a_in_b, containment_b_in_a)

        compatible = best_containment >= 0.5
        if best_containment >= 0.9:
            confidence = "haute"
        elif best_containment >= 0.7:
            confidence = "moyenne"
        elif best_containment >= 0.5:
            confidence = "faible"
        else:
            confidence = "incompatible"

        join_type = "INNER JOIN" if containment_a_in_b >= 0.95 else "LEFT JOIN"

        return {
            "success": True,
            "compatible": compatible,
            "confidence": confidence,
            "overlap_count": overlap,
            "distinct_a": distinct_a,
            "distinct_b": distinct_b,
            "containment_a_to_b": f"{containment_a_in_b:.0%}",
            "containment_b_to_a": f"{containment_b_in_a:.0%}",
            "recommended_join": (
                (
                    f"{join_type} [{table_b}] ON [{table_a}].[{column_a}] = "
                    f"[{table_b}].[{column_b}]"
                )
                if compatible
                else None
            ),
            "warning": (
                (
                    f"Pas de FK déclarée. Jointure basée sur correspondance de valeurs "
                    f"({confidence}, {overlap} valeurs communes sur {distinct_a}/{distinct_b}). "
                    f"Vérifie avec test_sql après le JOIN."
                )
                if compatible
                else (
                    f"Correspondance trop faible ({best_containment:.0%}). "
                    f"Ces colonnes ne semblent pas partager le même domaine de valeurs."
                )
            ),
        }
    except Exception as e:
        logger.error("check_join_compatibility error: %s", e, exc_info=True)
        return {"success": False, "error": f"Erreur vérification compatibilité: {e}"}


async def _handle_explore_join_alternatives(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Trouve TOUS les chemins FK entre deux tables (pas juste le plus court)."""
    from_table = tool_input.get("from_table", "").strip()
    to_table = tool_input.get("to_table", "").strip()
    if not from_table or not to_table:
        return {"success": False, "error": "from_table et to_table requis."}

    try:
        from app.services.ai.orchestrator_tools import find_all_fk_paths

        fk_graph = await get_fk_graph()
        all_paths = find_all_fk_paths(from_table, to_table, fk_graph, max_hops=4)

        if not all_paths:
            return {
                "success": True,
                "found": False,
                "message": f"Aucun chemin FK trouvé entre {from_table} et {to_table}.",
                "paths": [],
            }

        # Formater les top 5 chemins
        formatted_paths = []
        for i, path in enumerate(all_paths[:5]):
            hops = []
            for edge in path:
                hops.append(
                    f"{edge.get('source', '?')}.{edge.get('src_col', '?')} → "
                    f"{edge.get('target', '?')}.{edge.get('tgt_col', '?')}"
                )
            formatted_paths.append(
                {
                    "path_id": i + 1,
                    "hops": len(path),
                    "joins": hops,
                    "tables": [edge.get("source", "?") for edge in path]
                    + [path[-1].get("target", "?")],
                }
            )

        return {
            "success": True,
            "found": True,
            "total_paths": len(all_paths),
            "paths_shown": len(formatted_paths),
            "paths": formatted_paths,
        }
    except Exception as e:
        logger.error("explore_join_alternatives error: %s", e, exc_info=True)
        return {"success": False, "error": f"Erreur exploration FK: {e}"}


from app.services.ai.agent_tools_app import APP_TOOL_HANDLERS

# ---------------------------------------------------------------------------
# Outils terminaux (P2.2)
# ---------------------------------------------------------------------------


async def _handle_done(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict[str, Any]:
    """Clôture explicite de la conversation Iris.

    Stocke ``terminal_kind="done"`` + ``terminal_summary`` dans le context.
    Le runtime (``agent_service.py``) lit ces clés après chaque tool dispatch
    et sort de la free-loop ; déclenche aussi la génération du
    ``Conversation.summary`` (P2.1) à la sortie.

    Pas de side-effect ici (pas d'écriture BDD, pas de génération de mémoire).
    Le runtime orchestre — l'outil ne fait QUE signaler.
    """
    summary = (tool_input.get("summary") or "").strip()
    if not summary:
        return {
            "success": False,
            "error": (
                "Le paramètre `summary` est requis. Décris en 1-3 phrases ce "
                "qui a été accompli dans cette conversation."
            ),
        }
    if len(summary) > 1000:
        summary = summary[:1000].rstrip() + "…"

    context["_terminal_kind"] = "done"
    context["_terminal_summary"] = summary
    return {
        "success": True,
        "terminal_kind": "done",
        "summary": summary,
        "message": "Conversation marquée comme terminée.",
    }


async def _handle_abandon(tool_input: Dict[str, Any], user: Any, context: Dict) -> Dict[str, Any]:
    """Abandon explicite avec raison.

    Pour les cas où l'agent ne peut pas répondre (manque de schéma, ambiguïté
    irrésoluble, etc.). Stocke ``terminal_kind="abandon"`` + raison dans le
    context. Le runtime sort de la free-loop.
    """
    reason = (tool_input.get("reason") or "").strip()
    if not reason:
        return {
            "success": False,
            "error": (
                "Le paramètre `reason` est requis. Explique clairement à "
                "l'utilisateur pourquoi tu abandonnes."
            ),
        }
    if len(reason) > 1000:
        reason = reason[:1000].rstrip() + "…"

    context["_terminal_kind"] = "abandon"
    context["_terminal_summary"] = reason
    return {
        "success": True,
        "terminal_kind": "abandon",
        "reason": reason,
        "message": "Conversation marquée comme abandonnée.",
    }


# ─────────────────────────────────────────────────────────────────────
# Pipeline NL→SQL — handlers
# ─────────────────────────────────────────────────────────────────────


async def _handle_run_pipeline(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Crée un ``PipelineRun`` BDD et lance le runner en background.

    Le tool retourne immédiatement avec ``run_id``. La progression est
    exposée via le WebSocket ``/ws/iris/pipeline`` (frontend lazy-load
    le panneau dédié à la réception du 1er event ``pipeline_started``).

    Validations server-side :
    - ``query_nl`` non vide, longueur <= 5000 chars (defense-in-depth ;
      le LLM ne devrait pas générer plus, mais on coupe).
    - User authentifié (le caller ``execute_tool`` pose ``user`` non-None).
    - Quota par user : pas géré ici (cf. `_RATE_LIMIT_RUN_PIPELINE` à
      ajouter côté handler HTTP/WS — le tool LLM n'a pas la priorité du
      quota).

    En cas d'échec création (collision output_dir, BDD KO), retourne
    ``success=False`` avec message actionnable — le LLM peut décider de
    reformuler ou d'abandonner.
    """

    query_nl = (tool_input.get("query_nl") or "").strip()
    if not query_nl:
        return {
            "success": False,
            "error": (
                "Le paramètre `query_nl` est requis (la question utilisateur "
                "en langage naturel)."
            ),
        }
    # #18f (triage caps 2026-06-10) — aligné sur le pattern honnête du site
    # exploration_mode (l.~10830, ``was_truncated``) : couper la question NL
    # en silence avant run_pipeline = pipeline qui répond à une question
    # AMPUTÉE → SQL faux sans signal. L'agent doit le dire à l'utilisateur.
    query_nl_truncated = False
    if len(query_nl) > 5000:
        query_nl = query_nl[:5000].rstrip()
        query_nl_truncated = True

    user_id = getattr(user, "id", None)
    if user_id is None:
        return {
            "success": False,
            "error": ("Utilisateur non identifié — impossible de lancer la pipeline."),
        }

    # Imports lazy : évite charger pipeline_runner (et donc scripts/pipeline.py
    # ~12k lignes) au boot du serveur si ce tool n'est jamais appelé.
    try:
        from app.models.pipeline_run import PipelineMode, TriggeredVia
        from app.services.ai.pipeline_runner import (
            QuotaExceededError,
            start_pipeline_run,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("run_pipeline: import pipeline_runner failed")
        return {
            "success": False,
            "error": ("Module pipeline_runner indisponible. Détail: " + str(exc)),
        }

    mode_raw = (tool_input.get("mode") or "ir").strip().lower()
    try:
        mode = PipelineMode(mode_raw)
    except ValueError:
        return {
            "success": False,
            "error": f"Mode invalide '{mode_raw}'. Valides : 'legacy', 'ir'.",
        }

    # task #82 — défaut False : vues incluses dans le shortlist Phase 1.5.
    block_all_views = bool(tool_input.get("block_all_views", False))
    use_sage = bool(tool_input.get("use_sage", True))

    # Feature « preview » (docs/design/iris_stop_at_phase.md) : Iris peut
    # demander d'arrêter la pipeline à une phase intermédiaire (blueprint 1.5
    # / factsheets 3) au lieu d'aller jusqu'au SQL. Normalisation empty→None ;
    # la VALIDATION de la phase (fail-closed sur valeur inconnue) est faite en
    # aval par ``_build_phases_to_run`` (SSoT). None = run complet.
    stop_after_phase = (tool_input.get("stop_after_phase") or "").strip() or None

    # Task #93 PR3 (2026-05-21) — ADD-only : Iris peut enrichir la query NL
    # avec un contexte complémentaire (informations vues via ses tools), sans
    # modifier la query user qui reste source de vérité. Cap à 2000 chars
    # (defense-in-depth ; le LLM ne devrait pas générer plus, mais on coupe
    # plutôt que d'exploser le prompt cache de Phase 1.1).
    additional_context = (tool_input.get("additional_context") or "").strip()
    if len(additional_context) > 2000:
        additional_context = additional_context[:2000].rstrip()
        logger.warning(
            "run_pipeline: additional_context tronqué à 2000 chars " "(reçu %d chars)",
            len(tool_input.get("additional_context") or ""),
        )

    conversation_id = context.get("_conversation_id") if isinstance(context, dict) else None

    # Fix L8++ #63 garde-fou anti-boucle (2026-05-20) : si l'utilisateur
    # vient juste de lancer la MÊME query_nl et qu'elle a échoué dans la
    # dernière minute, on refuse de relancer. Sinon le LLM Iris peut
    # entrer en boucle infinie (run_pipeline crash sur 'montant TTC' →
    # Iris reçoit message d'erreur → Iris relance run_pipeline avec la
    # même query → re-crash → ...). Garde valable pour TOUTE cause
    # d'échec (pas juste concept_unresolved) — une query qui vient de
    # foirer ne va pas mystérieusement réussir 5 secondes plus tard.
    # L'utilisateur doit clarifier OU reformuler entre les 2 essais.
    try:
        from datetime import timedelta

        from sqlalchemy import select

        from app.core.database import get_session_factory
        from app.models.pipeline_run import PipelineRun, PipelineRunStatus

        _retry_window = timedelta(seconds=60)
        _now = clock.naive_utc()
        _threshold = _now - _retry_window

        async with get_session_factory()() as _session:
            _recent = await _session.execute(
                select(PipelineRun)
                .where(
                    PipelineRun.user_id == user_id,
                    PipelineRun.query_nl == query_nl,
                    PipelineRun.status == PipelineRunStatus.FAILED,
                    PipelineRun.created_at >= _threshold,
                )
                .order_by(PipelineRun.created_at.desc())
                .limit(1)
            )
            _last_failed = _recent.scalar_one_or_none()
        if _last_failed is not None:
            _err_excerpt = (_last_failed.error_message or "")[:200]
            logger.info(
                "run_pipeline: relance bloquée — query identique à un run "
                "FAILED il y a < 60s (run_id=%s, user=%s)",
                _last_failed.id,
                user_id,
            )
            return {
                "success": False,
                "error": (
                    "Tu viens de relancer la même question alors qu'elle a "
                    f"échoué il y a moins de 60s (run #{_last_failed.id}). "
                    "Relancer la pipeline avec une query identique va "
                    "probablement reproduire le même échec et brûler du "
                    "budget LLM inutilement.\n\n"
                    f"Cause de l'échec précédent : {_err_excerpt}\n\n"
                    "Actions recommandées : (a) appeler `ask_user_clarification` "
                    "pour faire préciser ce qui posait problème, (b) reformuler "
                    "la query avec des termes différents, (c) attendre au moins "
                    "60s si tu penses que c'est un problème transitoire."
                ),
                "retry_blocked": True,
                "previous_run_id": _last_failed.id,
            }
    except Exception:  # noqa: BLE001
        # Fail-open : si la BDD est down ou la query échoue, on laisse
        # passer (le risque d'avoir le run normal qui échoue aussi sur
        # BDD down est largement moindre que celui de bloquer un
        # utilisateur légitime). Logué pour debug.
        logger.exception(
            "run_pipeline: retry-window check failed — fail-open (user=%s)",
            user_id,
        )

    try:
        run = await start_pipeline_run(
            user_id=user_id,
            query_nl=query_nl,
            mode=mode,
            block_all_views=block_all_views,
            use_sage=use_sage,
            conversation_id=conversation_id,
            triggered_via=TriggeredVia.IRIS_CHAT,
            request_id=context.get("_request_id") if isinstance(context, dict) else None,
            additional_context=additional_context or None,
            stop_after_phase=stop_after_phase,
        )
    except QuotaExceededError as exc:
        return {
            "success": False,
            "error": (
                f"Quota journalier atteint ({exc.limit} runs/24h). "
                "L'utilisateur doit attendre ou demander à un admin "
                "de relever PIPELINE_MAX_RUNS_PER_DAY."
            ),
        }
    except FileExistsError as exc:
        logger.error("run_pipeline: output_dir collision: %s", exc)
        return {
            "success": False,
            "error": (
                "Conflit interne : un run précédent occupe le dossier de "
                "sortie. Réessayer dans quelques secondes."
            ),
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception("run_pipeline: start_pipeline_run failed")
        return {
            "success": False,
            "error": f"Échec du démarrage de la pipeline : {exc}",
        }

    # Mémoire context : permet à l'agent de référencer ce run dans la
    # même conversation (ex: `inspect_pipeline_artifact` peut lire ces ids
    # si le LLM passe via le bus).
    if isinstance(context, dict):
        active_runs = context.setdefault("_active_pipeline_runs", [])
        active_runs.append(run.id)

    # Note (refonte UX 2026-05-08) : ce dict initial est INTERCEPTÉ par
    # ``agent_service`` (cf. ``_stream_pipeline_run_to_chat``) qui :
    # 1. Subscribe au bus pipeline pour ``run_id``.
    # 2. Stream les events des 8 phases dans le chat Iris (tool_use /
    #    tool_result par phase, rendus par les renderers Iris standards).
    # 3. À la fin, REMPLACE ce dict par un résumé synthétique compact
    #    contenant phases_summary, final_sql, total_cost_usd, status, etc.
    # Donc le LLM Iris ne voit JAMAIS les clés ci-dessous — il voit le
    # résumé final. Les ``instructions_for_assistant`` sont posées par
    # le synthétique final (cf. _stream_pipeline_run_to_chat).
    result_payload: Dict[str, Any] = {
        "success": True,
        "run_id": run.id,
        "status": (run.status.value if hasattr(run.status, "value") else str(run.status)),
    }
    if query_nl_truncated:
        # #18f — le pipeline a travaillé sur une question AMPUTÉE à 5000
        # chars : l'agent doit le signaler (le SQL peut ignorer la fin de
        # la demande).
        result_payload["query_nl_truncated"] = True
        result_payload["warning"] = (
            "La question a été tronquée à 5000 caractères avant le pipeline "
            "— le SQL peut ignorer la fin de la demande. Signale-le à "
            "l'utilisateur et propose de reformuler plus court."
        )
    return result_payload


async def _handle_inspect_pipeline_artifact(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Retourne le ``metadata_summary`` d'une phase d'un run.

    Vérifie l'ownership (run.user_id == user.id) — le LLM ne peut pas
    inspecter les runs d'autres utilisateurs même s'il invente un run_id.
    """

    run_id = tool_input.get("run_id")
    phase_id = (tool_input.get("phase_id") or "").strip()
    if not isinstance(run_id, int) or not phase_id:
        return {
            "success": False,
            "error": "Paramètres requis : `run_id` (int) et `phase_id` (string).",
        }

    user_id = getattr(user, "id", None)
    if user_id is None:
        return {"success": False, "error": "Utilisateur non identifié."}

    try:
        from sqlalchemy import select

        from app.core.database import get_session_factory
        from app.models.pipeline_run import PipelinePhaseExecution, PipelineRun
    except Exception as exc:  # noqa: BLE001
        logger.exception("inspect_pipeline_artifact: import failed")
        return {"success": False, "error": str(exc)}

    async with get_session_factory()() as session:
        run = await session.get(PipelineRun, run_id)
        if run is None or run.user_id != user_id:
            # 404-like : ne pas distinguer "absent" vs "pas à toi" (anti-leak)
            return {"success": False, "error": f"Run #{run_id} introuvable."}

        stmt = (
            select(PipelinePhaseExecution)
            .where(
                PipelinePhaseExecution.pipeline_run_id == run_id,
                PipelinePhaseExecution.phase_id == phase_id,
                PipelinePhaseExecution.is_superseded.is_(False),
            )
            .order_by(PipelinePhaseExecution.attempt_number.desc())
            .limit(1)
        )
        result = await session.execute(stmt)
        phase_exec = result.scalar_one_or_none()
        if phase_exec is None:
            return {
                "success": False,
                "error": (f"Phase {phase_id} non encore exécutée pour le run #{run_id}."),
            }

        return {
            "success": True,
            "run_id": run_id,
            "phase_id": phase_id,
            "phase_label": phase_exec.phase_label,
            "status": (
                phase_exec.status.value
                if hasattr(phase_exec.status, "value")
                else str(phase_exec.status)
            ),
            "duration_seconds": phase_exec.duration_seconds,
            "tokens_input": phase_exec.tokens_input,
            "tokens_output": phase_exec.tokens_output,
            "cost_usd": phase_exec.cost_usd_snapshot,
            "metadata_summary": phase_exec.metadata_summary,
            "error_message": phase_exec.error_message,
        }


# ---------------------------------------------------------------------------
# Pipeline RESUME : reprend un run existant à une phase donnée
# ---------------------------------------------------------------------------


async def _handle_pipeline_resume(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Crée un nouveau ``PipelineRun`` à partir d'un run source + une phase.

    Délègue à ``pipeline_runner.resume_pipeline_run()`` qui :

    - Vérifie ownership (anti cross-user, message 404-like).
    - Refuse si source en PENDING/RUNNING (anti race avec runner actif).
    - Charge ``run.json`` source + tronque aux phases < ``from_phase``.
    - Apply ``state_overrides`` (whitelist anti-injection LLM, cap 64 KiB).
    - Pré-écrit ``run.json`` dans le nouveau ``output_dir``.
    - Lance la pipeline avec ``resume=True``.

    Le nouveau ``run_id`` est intercepté par ``agent_service`` (cf.
    ``_stream_pipeline_run_to_chat``) qui bridge le bus pipeline vers
    le chat Iris — même UX que ``run_pipeline``.

    Validations server-side :
    - ``run_id`` int positif ; ``from_phase`` string non vide ;
      ``state_overrides`` dict ou None.
    - ``user_id`` présent (caller ``execute_tool`` pose ``user`` non-None).

    En cas d'échec, retourne ``success=False`` avec message actionnable —
    le LLM peut décider de reformuler la phase ou d'abandonner.
    """

    source_run_id = tool_input.get("run_id")
    if not isinstance(source_run_id, int) or source_run_id <= 0:
        return {
            "success": False,
            "error": (
                "Le paramètre `run_id` est requis (entier positif, ID du "
                "run source à reprendre)."
            ),
        }

    from_phase = (tool_input.get("from_phase") or "").strip()
    if not from_phase:
        return {
            "success": False,
            "error": (
                "Le paramètre `from_phase` est requis (string, ex: '2', "
                "'4'). Voir l'enum dans la spec du tool."
            ),
        }

    state_overrides = tool_input.get("state_overrides")
    if state_overrides is not None and not isinstance(state_overrides, dict):
        return {
            "success": False,
            "error": "`state_overrides` doit être un objet (dict) si fourni.",
        }

    user_id = getattr(user, "id", None)
    if user_id is None:
        return {
            "success": False,
            "error": ("Utilisateur non identifié — impossible de reprendre la " "pipeline."),
        }

    # Imports lazy : cohérent avec ``_handle_run_pipeline``.
    try:
        from app.models.pipeline_run import TriggeredVia
        from app.services.ai.pipeline_runner import (
            QuotaExceededError,
            ResumeValidationError,
            resume_pipeline_run,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("pipeline_resume: import pipeline_runner failed")
        return {
            "success": False,
            "error": "Module pipeline_runner indisponible. Détail: " + str(exc),
        }

    try:
        run = await resume_pipeline_run(
            user_id=user_id,
            source_run_id=source_run_id,
            from_phase=from_phase,
            state_overrides=state_overrides,
            triggered_via=TriggeredVia.IRIS_CHAT,
            request_id=(context.get("_request_id") if isinstance(context, dict) else None),
        )
    except ResumeValidationError as exc:
        # Erreur de validation (4xx-like) — message actionnable pour le LLM.
        return {"success": False, "error": str(exc)}
    except QuotaExceededError as exc:
        return {
            "success": False,
            "error": (
                f"Quota journalier atteint ({exc.limit} runs/24h). "
                "L'utilisateur doit attendre ou demander à un admin "
                "de relever PIPELINE_MAX_RUNS_PER_DAY."
            ),
        }
    except FileExistsError as exc:
        logger.error("pipeline_resume: output_dir collision: %s", exc)
        return {
            "success": False,
            "error": (
                "Conflit interne : un run précédent occupe le dossier de "
                "sortie. Réessayer dans quelques secondes."
            ),
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception("pipeline_resume: resume_pipeline_run failed")
        return {
            "success": False,
            "error": f"Échec du redémarrage de la pipeline : {exc}",
        }

    # Mémoire context : permet à l'agent de référencer ce nouveau run dans
    # la même conversation (cohérent avec ``_handle_run_pipeline``).
    if isinstance(context, dict):
        active_runs = context.setdefault("_active_pipeline_runs", [])
        active_runs.append(run.id)

    # Note : ce dict initial est INTERCEPTÉ par ``agent_service`` (cf.
    # ``_stream_pipeline_run_to_chat``) qui bridge le bus pipeline vers
    # le chat Iris (mêmes events tool_use/tool_result que pour
    # ``run_pipeline``). Le LLM Iris ne voit donc JAMAIS ce dict — il
    # voit le résumé synthétique final écrit par le bridge.
    return {
        "success": True,
        "run_id": run.id,
        "source_run_id": source_run_id,
        "from_phase": from_phase,
        "status": (run.status.value if hasattr(run.status, "value") else str(run.status)),
    }


# ---------------------------------------------------------------------------
# T20 — Mutation incrémentale IR (conversation multi-tour)
# ---------------------------------------------------------------------------


def _summarize_ir_for_llm(ir: dict) -> dict:
    """Compact human-readable summary de l'IR pour le retour tool — pas le
    dump complet (l'IR brut peut être verbeux et inutile pour le LLM
    qui voit déjà le SQL final).
    """
    if not isinstance(ir, dict):
        return {}
    select_aliases: list[str] = []
    for it in ir.get("select", []) or []:
        if isinstance(it, dict):
            a = it.get("alias")
            if isinstance(a, str) and a:
                select_aliases.append(a)
    filters_global: list[str] = []
    for f in ir.get("filters_global", []) or []:
        if isinstance(f, dict):
            concept = f.get("concept", "?")
            op_filter = f.get("op", "?")
            val = f.get("val", "")
            if op_filter in ("IS_NULL", "IS_NOT_NULL"):
                filters_global.append(f"{concept} {op_filter}")
            else:
                filters_global.append(f"{concept} {op_filter} {val!r}")
    group_by = [c for c in (ir.get("group_by_concepts") or []) if isinstance(c, str)]
    order_by_str: list[str] = []
    for o in ir.get("order_by", []) or []:
        if isinstance(o, dict):
            coa = o.get("concept_or_alias", "?")
            direction = o.get("direction", "?")
            order_by_str.append(f"{coa} {direction}")
    return {
        "from_concept": ir.get("from_concept"),
        "select_aliases": select_aliases,
        "filters_global": filters_global,
        "group_by_concepts": group_by,
        "order_by": order_by_str,
        "limit": ir.get("limit"),
    }


async def _handle_mutate_last_ir(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """T20 — Mutation incrémentale de l'IR du dernier ``run_pipeline`` réussi.

    Flow :

    1. Récupère ``conversation_id`` du contexte + ``user_id`` de ``user``
       (defense-in-depth — la clé store inclut user_id, anti-leak cross-user).
    2. Charge le bundle ``IRBundle`` depuis ``ConversationIRStore``.
       Si absent → erreur ``NO_PREVIOUS_IR`` actionnable.
    3. ``apply_operations(prev_ir, operations)`` — atomique :
       toute IRMutationError laisse le store INCHANGÉ.
    4. ``ir_to_sql(new_ir, prev_concept_resolution, fk_lookup=prev_fk_lookup)``
       — recompose le SQL depuis l'IR muté + la résolution conceptuelle
       du run source (pas de re-résolution Phase 2.5 — économies LLM).
    5. ``store.update_ir(user_id, conv_id, new_ir)`` — persiste la mutation
       pour la prochaine itération.

    Retourne :
        - ``{success: True, sql, ir_summary, ops_applied, source_run_id}``
        - ``{success: False, error, code}`` sur tout échec (jamais d'exception
          bubble up — le LLM voit toujours un dict structuré).

    Codes d'erreur :
        - ``INVALID_INPUT`` : operations manquantes/mal formées
        - ``NO_CONVERSATION`` : conversation_id absent du contexte
        - ``NO_USER`` : user.id absent
        - ``NO_PREVIOUS_IR`` : aucun bundle en store (run pipeline jamais fait,
          ou évincé LRU, ou restart serveur)
        - ``CORRUPT_IR`` : bundle stocké corrompu (très rare)
        - ``MUTATION_ERROR`` : IRMutationError levée pendant apply_operations
        - ``COMPOSE_ERROR`` : ir_to_sql lève (concept manquant dans
          concept_resolution, IR invalide post-mutation, etc.)
        - ``IMPORT_ERROR`` : modules indisponibles (très rare)
        - ``INTERNAL_ERROR`` : exception inattendue
    """
    operations = tool_input.get("operations")
    if not isinstance(operations, list) or len(operations) == 0:
        return {
            "success": False,
            "error": (
                "`operations` doit être une liste non vide (max 10 entrées). "
                "Exemple : [{op:'add_filter', concept:'année', operator:'=', "
                "val:'2024'}]."
            ),
            "code": "INVALID_INPUT",
        }

    conversation_id = context.get("_conversation_id") if isinstance(context, dict) else None
    # Le caller (agent_service) peut passer conversation_id sous forme str
    # ou int — normalise en int.
    if isinstance(conversation_id, str) and conversation_id.isdigit():
        conversation_id = int(conversation_id)
    if not isinstance(conversation_id, int) or conversation_id <= 0:
        return {
            "success": False,
            "error": (
                "Conversation non identifiée — impossible de récupérer l'IR "
                "précédente. Utilise `run_pipeline` pour démarrer une nouvelle "
                "requête."
            ),
            "code": "NO_CONVERSATION",
        }

    user_id = getattr(user, "id", None)
    if not isinstance(user_id, int) or user_id <= 0:
        return {
            "success": False,
            "error": "Utilisateur non identifié.",
            "code": "NO_USER",
        }

    try:
        from app.services.ai.conversation_ir_store import get_ir_store
        from app.services.ai.ir_mutator import (
            IRMutationError,
            apply_operations,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("mutate_last_ir: import ir_mutator/store failed")
        return {
            "success": False,
            "error": f"Modules indisponibles : {exc}",
            "code": "IMPORT_ERROR",
        }

    store = get_ir_store()

    # Atomic read-modify-write : tout le pipeline get → mutate → compose →
    # update_ir tourne sous le lock de la clé. Anti TOCTOU concurrent
    # (cf. adversarial review T20).
    async def _mutator(bundle):
        if bundle is None:
            return {
                "_outcome": {
                    "success": False,
                    "error": (
                        "Aucune IR précédente pour cette conversation. Causes "
                        "possibles : (1) la pipeline n'a pas encore tourné dans "
                        "cette conversation, (2) le cache LRU l'a évincée (>200 "
                        "conversations actives), (3) le serveur a redémarré. "
                        "Utilise `run_pipeline` pour construire une nouvelle "
                        "requête depuis zéro."
                    ),
                    "code": "NO_PREVIOUS_IR",
                }
            }

        prev_ir = bundle.get("ir")
        concept_resolution = bundle.get("concept_resolution") or {}
        fk_lookup_local = bundle.get("fk_lookup") or {}
        source_run_id = bundle.get("source_run_id")

        if not isinstance(prev_ir, dict) or not prev_ir:
            return {
                "_outcome": {
                    "success": False,
                    "error": (
                        "IR précédente corrompue (vide ou non-dict). Relance "
                        "`run_pipeline` pour reconstruire une IR propre."
                    ),
                    "code": "CORRUPT_IR",
                }
            }

        # Mutation atomique (deep-copy interne).
        try:
            new_ir = apply_operations(prev_ir, operations)
        except IRMutationError as exc:
            return {
                "_outcome": {
                    "success": False,
                    "error": f"Mutation refusée : {exc}",
                    "code": "MUTATION_ERROR",
                }
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception("mutate_last_ir: apply_operations crashed")
            return {
                "_outcome": {
                    "success": False,
                    "error": f"Erreur inattendue mutation : {exc}",
                    "code": "INTERNAL_ERROR",
                }
            }

        # Composition SQL — concept_resolution réutilisé, fk_lookup
        # recalculé si absent du bundle (run.json ne le sérialise PAS).
        from scripts.pipeline import ir_to_sql

        if not fk_lookup_local:
            try:
                from scripts.pipeline import (
                    SAGE_DB,
                    get_fk_lookup_from_db_with_views,
                )

                fk_lookup_local = get_fk_lookup_from_db_with_views(SAGE_DB) or {}
            except Exception:  # noqa: BLE001
                logger.warning(
                    "mutate_last_ir: fk_lookup recompute failed — "
                    "ir_to_sql will reject multi-table IR"
                )
                fk_lookup_local = {}

        try:
            new_sql = ir_to_sql(new_ir, concept_resolution, fk_lookup=fk_lookup_local or None)
        except Exception as exc:  # noqa: BLE001
            logger.exception("mutate_last_ir: ir_to_sql failed")
            return {
                "_outcome": {
                    "success": False,
                    "error": (
                        f"Composition SQL échoue ({type(exc).__name__}: {exc}). "
                        "Cause probable : un concept demandé n'est pas dans la "
                        "résolution du run précédent, ou un JOIN entre 2 tables "
                        "n'a pas de FK connue. Relance `run_pipeline` avec la "
                        "requête complète."
                    ),
                    "code": "COMPOSE_ERROR",
                }
            }

        # Succès — le store sera mis à jour automatiquement par atomic_mutate
        # via la clé "new_ir" du retour, AVANT release lock.
        return {
            "new_ir": new_ir,
            "_outcome": {
                "success": True,
                "sql": new_sql,
                "ir_summary": _summarize_ir_for_llm(new_ir),
                "ops_applied": len(operations),
                "source_run_id": source_run_id,
            },
        }

    try:
        wrapped = await store.atomic_mutate(user_id, conversation_id, _mutator)
    except Exception as exc:  # noqa: BLE001
        logger.exception("mutate_last_ir: atomic_mutate crashed")
        return {
            "success": False,
            "error": f"Erreur interne store : {exc}",
            "code": "INTERNAL_ERROR",
        }

    return wrapped.get(
        "_outcome",
        {
            "success": False,
            "error": "Mutator a retourné un payload inattendu.",
            "code": "INTERNAL_ERROR",
        },
    )


# ---------------------------------------------------------------------------
# Casquette Iris-DBA-write : propose_sql_write
# ---------------------------------------------------------------------------


async def _handle_propose_sql_write(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Handler ``propose_sql_write`` — délègue à iris_write_session.

    Le tool n'exécute rien. Il valide, dry-run, audit, et envoie un mail
    au DBA externe. La SQL n'est exécutée qu'après le clic du DBA dans le
    mail (handler HTTP /iris/sql-write/dba/<token>).
    """
    sql = (tool_input.get("sql") or "").strip()
    intent = (tool_input.get("intent") or "").strip()
    if not sql:
        return {"success": False, "error": "Paramètre 'sql' manquant."}
    if not intent:
        return {
            "success": False,
            "error": (
                "Paramètre 'intent' manquant : décris en français ce que "
                "l'opération fait (le DBA externe doit comprendre sans contexte)."
            ),
        }

    from app.services.ai.iris_write_session import propose_sql_write

    # Récupération depuis le context posé par agent_service.py (clés
    # actuelles : _original_message pour le user_message ; request_id
    # n'est pas posé en runtime donc on le génère ici pour pouvoir
    # tracer le flow audit ↔ logs).
    import uuid as _uuid

    conversation_id = context.get("conversation_id") if context else None
    request_id = (context.get("request_id") if context else None) or _uuid.uuid4().hex
    original_nl = context.get("_original_message") if context else None

    result = await propose_sql_write(
        user=user,
        sql=sql,
        intent=intent,
        conversation_id=conversation_id,
        request_id=request_id,
        original_nl=original_nl,
    )

    return {
        "success": result.success,
        "audit_id": result.audit_id,
        "status": result.status,
        "operation": result.operation,
        "tables": result.tables,
        "estimated_rows": result.estimated_rows,
        "dba_email": result.dba_email,
        "expires_at": result.expires_at.isoformat() if result.expires_at else None,
        "user_message": result.user_message,
        "error": result.error,
    }


# ---------------------------------------------------------------------------
# Casquette Iris-agent-Komptia : search/read/list codebase
# ---------------------------------------------------------------------------

# Budget global par session conversationnelle (cap soft via context dict).
_CODEBASE_SESSION_LINES_KEY = "_codebase_session_lines"


def _check_codebase_session_budget(context: Dict, lines_to_add: int) -> Optional[str]:
    """Met à jour le compteur global de lignes lues. Retourne un message
    d'erreur si le budget de session est dépassé, sinon None."""
    from app.services.ai.codebase_reader import SESSION_LINES_BUDGET

    used = int(context.get(_CODEBASE_SESSION_LINES_KEY, 0))
    if used + lines_to_add > SESSION_LINES_BUDGET:
        return (
            f"Budget session de lecture du code atteint "
            f"({used} lignes lues sur {SESSION_LINES_BUDGET}). "
            "Synthétise ce que tu as déjà vu plutôt que de lire plus."
        )
    context[_CODEBASE_SESSION_LINES_KEY] = used + lines_to_add
    return None


async def _handle_search_codebase(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Handler ``search_codebase`` — grep + scrub secrets.

    L'I/O (subprocess ripgrep ou walk filesystem) est bloquant ; on le
    bascule dans un thread via ``run_in_executor`` pour ne pas figer
    l'event loop Tornado pendant 1-20s.

    ``user`` propagé à ``grep_codebase`` pour autoriser les paths
    user-scoped sous ``data/datastore/<id>/`` et ``data/uploads/<id>/``
    (cf. ``codebase_reader.is_path_safe``). Sans ``user``, ces paths
    sont refusés (fail-closed).
    """
    pattern = (tool_input.get("pattern") or "").strip()
    file_glob = tool_input.get("file_glob")
    if not pattern:
        return {"success": False, "error": "Paramètre 'pattern' manquant."}

    from app.services.ai.code_secret_scrubber import scrub_dict
    from app.services.ai.codebase_reader import grep_codebase

    loop = asyncio.get_running_loop()
    raw_result = await loop.run_in_executor(
        None, lambda: grep_codebase(pattern=pattern, file_glob=file_glob, user=user)
    )
    scrubbed = scrub_dict(raw_result)

    # Compteur de lignes : on compte les snippets retournés (proxy raisonnable
    # pour le coût token).
    matches_count = len(scrubbed.get("matches", []) or [])
    budget_error = _check_codebase_session_budget(context, matches_count)
    if budget_error:
        return {
            "success": False,
            "error": budget_error,
        }

    if scrubbed.get("error"):
        return {"success": False, "error": scrubbed["error"]}

    return {
        "success": True,
        "pattern": scrubbed["pattern"],
        "file_glob": scrubbed.get("file_glob"),
        "matches": scrubbed["matches"],
        "total": scrubbed["total"],
        "truncated": scrubbed["truncated"],
        "notice": scrubbed.get("notice"),
    }


async def _handle_read_code_file(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Handler ``read_code_file`` — lit un fichier scrub-protégé.

    L'I/O fichier (open + read 200 KB) est wrappé dans run_in_executor
    pour ne pas bloquer l'event loop sur les gros fichiers (pipeline.py
    fait 8400 lignes / ~600 KB).

    ``user`` propagé à ``read_file_paginated`` pour autoriser les fichiers
    sous ``data/datastore/<id>/`` et ``data/uploads/<id>/`` (cf.
    ``codebase_reader.is_path_safe``).
    """
    path = (tool_input.get("path") or "").strip()
    if not path:
        return {"success": False, "error": "Paramètre 'path' manquant."}
    offset = int(tool_input.get("offset", 1) or 1)
    limit = int(tool_input.get("limit", 200) or 200)

    from app.services.ai.code_secret_scrubber import scrub
    from app.services.ai.codebase_reader import read_file_paginated

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: read_file_paginated(rel_path=path, offset=offset, limit=limit, user=user),
    )
    if result.get("error"):
        return {"success": False, "error": result["error"], "path": result.get("path")}

    # Budget : compte les lignes effectivement retournées
    line_count = int(result.get("line_count", 0))
    budget_error = _check_codebase_session_budget(context, line_count)
    if budget_error:
        return {"success": False, "error": budget_error}

    # Scrub le contenu avant retour LLM (clés API en commentaires, etc.)
    scrubbed_content = scrub(result.get("content", ""))

    return {
        "success": True,
        "path": result["path"],
        "content": scrubbed_content,
        "offset": result["offset"],
        "line_count": result["line_count"],
        "total_lines": result["total_lines"],
        "size_bytes": result["size_bytes"],
        "truncated": result["truncated"],
        "notice": result.get("notice"),
    }


async def _handle_list_code_files(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Handler ``list_code_files`` — glob un dossier autorisé.

    Le ``Path.glob()`` peut walker beaucoup d'entrées sur un grand
    dossier — wrappé dans run_in_executor.

    ``user`` propagé à ``list_files`` pour autoriser les paths user-scoped
    sous ``data/datastore/<id>/`` et ``data/uploads/<id>/``.
    """
    del context  # pas de budget pour list
    directory = (tool_input.get("directory") or "").strip()
    glob_pattern = (tool_input.get("glob_pattern") or "*").strip() or "*"
    if not directory:
        return {"success": False, "error": "Paramètre 'directory' manquant."}

    from app.services.ai.codebase_reader import list_files

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: list_files(directory=directory, glob_pattern=glob_pattern, user=user),
    )
    if result.get("error"):
        return {"success": False, "error": result["error"]}

    return {
        "success": True,
        "directory": result["directory"],
        "files": result["files"],
        "total": result["total"],
        "truncated": result["truncated"],
        "notice": result.get("notice"),
    }


# ---------------------------------------------------------------------------
# T23 — Mode "exploration ouverte"
# ---------------------------------------------------------------------------


async def _handle_start_exploration_mode(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Handler ``start_exploration_mode`` — détection vague + axes proposés.

    Programmatique uniquement (0 appel LLM, no I/O réseau). Lit le schéma
    via ``get_schema_loader`` (cache local). Si le loader échoue, retombe
    sur des axes purement génériques (sans ``suggested_tables``).

    Le payload retourné contient ``is_vague``, ``axes`` (3-MAX_AXES items
    neutres), un flag ``action`` structuré et une
    ``instruction_for_assistant`` que l'agent IA doit suivre.

    Trace ``user.id`` et ``conversation_id`` pour audit (defense-in-depth) :
    permet plus tard de rate-limiter par user ou d'auditer les patterns
    d'usage du mode exploration.
    """
    user_id = getattr(user, "id", None)
    conversation_id = None
    if isinstance(context, dict):
        conversation_id = context.get("_conversation_id") or context.get("conversation_id")

    query_nl = (tool_input.get("query_nl") or "").strip()
    if not query_nl:
        return {
            "success": False,
            "error": ("Le paramètre `query_nl` est requis (la question utilisateur " "à évaluer)."),
        }

    # Cap dur côté serveur (défense en profondeur) — cohérent avec run_pipeline.
    # Le payload retourné inclut ``was_truncated`` pour que l'agent IA puisse
    # signaler à l'user que sa question a été tronquée (pas de fail silencieux).
    was_truncated = False
    if len(query_nl) > 5000:
        query_nl = query_nl[:5000].rstrip()
        was_truncated = True

    # Imports lazy pour éviter de charger le module si le tool n'est jamais
    # appelé (et pour faciliter le mock côté tests).
    from app.services.ai.exploration_mode import (
        MAX_AXES,
        MIN_AXES,
        format_exploration_response,
        is_query_vague,
        propose_exploration_axes,
    )

    try:
        top_n = int(tool_input.get("top_n", 5))
    except (TypeError, ValueError):
        top_n = 5
    top_n = max(MIN_AXES, min(top_n, MAX_AXES))

    schema_tables: List[str] = []
    try:
        loader = get_schema_loader()
        # Phase α.4.A : matérialiser user_view et passer au SchemaLoader.
        try:
            from app.services.data_access.visible_schema import build_user_schema_view

            user_view = await build_user_schema_view(user)
        except Exception:
            user_view = None
        tables_dict = loader.get_tables(user_view=user_view) or {}
        # ``get_tables`` peut théoriquement renvoyer autre chose qu'un dict
        # (loader buggé / mock incohérent). On normalise en list[str] safe.
        if isinstance(tables_dict, dict):
            schema_tables = [str(k) for k in tables_dict.keys() if k]
        elif isinstance(tables_dict, (list, tuple, set, frozenset)):
            schema_tables = [str(k) for k in tables_dict if k]
        else:
            schema_tables = []
    except Exception:  # noqa: BLE001
        # Schema loader peut échouer si BDD locale non initialisée — on
        # continue avec axes génériques (pas de fail-stop).
        logger.warning(
            "start_exploration_mode: schema_loader failed, axes sans " "suggested_tables",
            exc_info=True,
        )
        schema_tables = []

    detection = is_query_vague(query_nl, schema_tables=schema_tables)

    axes: List[Any]
    if detection.is_vague:
        axes = propose_exploration_axes(query_nl, schema_tables=schema_tables, top_n=top_n)
    else:
        axes = []

    payload = format_exploration_response(query_nl, detection, axes)

    logger.info(
        "start_exploration_mode: user=%s conv=%s query_len=%d " "is_vague=%s axes=%d truncated=%s",
        user_id,
        conversation_id,
        len(query_nl),
        detection.is_vague,
        len(axes),
        was_truncated,
    )

    return {
        "success": True,
        "was_truncated": was_truncated,
        **payload,
    }


# ---------------------------------------------------------------------------
# Plan structuré (plan_add / plan_update / plan_list)
# ---------------------------------------------------------------------------
#
# Mêmes outils que copilot_tools.py — validation déléguée à
# ``plan_tools_core``. La state vit dans ``context["plan"]`` (initialisé
# côté ``agent_service.run()``). L'émission WebSocket ``plan_update`` qui
# rafraîchit le widget UI est gérée par ``agent_service`` après chaque
# call (pas ici) — un handler reste un mutateur de state, pas un I/O.


async def _handle_plan_add(
    tool_input: Dict[str, Any],
    user: Any,
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """Ajoute une task au plan structuré de la conversation courante."""
    plan = context.setdefault("plan", [])
    next_id = context.get("_plan_next_id", 1)

    ok, task, new_next_id, err = _plan_core_add_task(
        plan,
        next_id,
        tool_input.get("subject"),
        tool_input.get("description"),
    )
    if not ok:
        return {"success": False, "error": f"plan_add: {err}"}

    context["_plan_next_id"] = new_next_id
    return {
        "success": True,
        "task_id": task["id"],
        "status": task["status"],
        "plan_size": len(plan),
    }


async def _handle_plan_update(
    tool_input: Dict[str, Any],
    user: Any,
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """Met à jour le status et/ou le subject d'une task existante."""
    plan = context.setdefault("plan", [])
    ok, task, err = _plan_core_update_task(
        plan,
        tool_input.get("task_id"),
        tool_input.get("status"),
        tool_input.get("subject"),
    )
    if not ok:
        return {"success": False, "error": f"plan_update: {err}"}

    return {
        "success": True,
        "task_id": task["id"],
        "status": task["status"],
    }


async def _handle_plan_list(
    tool_input: Dict[str, Any],
    user: Any,
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """Retourne l'état courant du plan + décompte par status."""
    plan = context.setdefault("plan", [])
    payload = _plan_core_list_plan(plan)
    return {"success": True, **payload}


_TOOL_HANDLERS = {
    "execute_sql": _handle_execute_sql,
    "get_database_schema": _handle_get_database_schema,
    "peek_table_data": _handle_peek_table_data,
    "analyze_numbers": _handle_analyze_numbers,
    "search_documentation": _handle_search_documentation,
    "ask_user_clarification": _handle_ask_user_clarification,
    "save_to_datastore": _handle_save_to_datastore,
    "create_report": _handle_create_report,
    "create_report_from_results": _handle_create_report_from_results,
    "analyze_query_performance": _handle_analyze_query_performance,
    "schedule_task": _handle_schedule_task,
    "analyze_attachment": _handle_analyze_attachment,
    "transform_uploaded_file": _handle_transform_uploaded_file,
    "list_workbook_tabs": _handle_list_workbook_tabs,
    "read_workbook_rows": _handle_read_workbook_rows,
    "count_workbook_rows": _handle_count_workbook_rows,
    "aggregate_workbook": _handle_aggregate_workbook,
    "quick_overview_workbook": _handle_quick_overview_workbook,
    "get_user_preferences": _handle_get_user_preferences,
    "save_user_preference": _handle_save_user_preference,
    "suggest_followup_questions": _handle_suggest_followup_questions,
    "introspect_table": _handle_introspect_table,
    "learn_insight": _handle_learn_insight,
    "trigger_schema_sync": _handle_trigger_schema_sync,
    "check_schema_freshness": _handle_check_schema_freshness,
    "trigger_enriched_sync": _handle_trigger_enriched_sync,
    "analyze_null_data": _handle_analyze_null_data,
    "save_memory": _handle_save_memory,
    # Outils SQL avancés (ex-orchestrateur)
    "search_schema": _handle_search_schema,
    "test_sql": _handle_test_sql,
    "get_fk_path": _handle_get_fk_path,
    "get_resolved_values": _handle_get_resolved_values,
    "explore_join_alternatives": _handle_explore_join_alternatives,
    "check_join_compatibility": _handle_check_join_compatibility,
    "align_request": _handle_align_request,
    "diagnose_zero_rows": _handle_diagnose_zero_rows,
    "introspect_tables_batch": _handle_introspect_tables_batch,
    "compare_query_variants": _handle_compare_query_variants,
    "match_analytical_pattern": _handle_match_analytical_pattern,
    "done": _handle_done,
    "abandon": _handle_abandon,
    # Pipeline NL→SQL — workflow principal pour SQL analytique
    "run_pipeline": _handle_run_pipeline,
    "inspect_pipeline_artifact": _handle_inspect_pipeline_artifact,
    "pipeline_resume": _handle_pipeline_resume,
    # T20 — Mutation IR pour conversation multi-tour
    "mutate_last_ir": _handle_mutate_last_ir,
    # Casquette Iris-DBA-write (admin only — voir _ADMIN_ONLY_TOOLS)
    "propose_sql_write": _handle_propose_sql_write,
    # Casquette Iris-agent-Komptia (tous rôles)
    "search_codebase": _handle_search_codebase,
    "read_code_file": _handle_read_code_file,
    "list_code_files": _handle_list_code_files,
    # T23 — Mode exploration ouverte
    "start_exploration_mode": _handle_start_exploration_mode,
    # Plan structuré (todo-list partagée avec copilot — core dans plan_tools_core)
    "plan_add": _handle_plan_add,
    "plan_update": _handle_plan_update,
    "plan_list": _handle_plan_list,
    # Task #10/#11 — Tools DAG-aware automation (handlers dans agent_automation_tools.py)
    **AUTOMATION_DAG_TOOL_HANDLERS,
    **APP_TOOL_HANDLERS,
}


# SSOT-1 (suite) — sanity check de couverture handlers, après que
# _TOOL_HANDLERS soit construit (cf. adversarial review MAJOR #1).
# Sans ça, un tool peut être classifié sans handler enregistré = silent
# KeyError au premier appel runtime, bug masqué jusqu'à utilisation.
validate_handlers_coverage(_TOOL_HANDLERS)


async def execute_tool(
    tool_name: str,
    tool_input: Dict[str, Any],
    user: Any,
    context: Dict,
    role_value: str = "iris",
) -> Dict[str, Any]:
    """
    Dispatch a tool call to the appropriate handler.

    Args:
        tool_name:  Name of the tool as declared in IRIS_TOOLS.
        tool_input: Validated input dict from Anthropic's tool_use block.
        user:       Current authenticated user object (ORM model).
        context:    Mutable dict shared across the agent's turn.
                    Handlers may store pending results, clarification requests, etc.
        role_value: Current agent role (for permission enforcement).

    Returns:
        A dict with at minimum a "success" boolean key and tool-specific fields.
        Errors are returned as {"success": False, "error": "..."} — never raised.
    """
    handler = _TOOL_HANDLERS.get(tool_name)
    if handler is None:
        logger.warning("execute_tool: unknown tool '%s'", tool_name)
        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    # Defense-in-depth: enforce role-based permission even if LLM bypasses tool filtering
    allowed_names = _ROLE_TOOLS.get(role_value, set())
    if tool_name not in allowed_names:
        logger.warning(
            "execute_tool: role '%s' not allowed to call '%s'",
            role_value,
            tool_name,
        )
        return {"success": False, "error": "Permission refusée pour cet outil."}

    # Enforce admin-only tools server-side
    if tool_name in _ADMIN_ONLY_TOOLS:
        user_role = getattr(user, "role", None)
        user_role_str = getattr(user_role, "value", user_role)
        if user_role_str != "admin":
            logger.warning(
                "execute_tool: non-admin user tried to call admin tool '%s'",
                tool_name,
            )
            return {"success": False, "error": "Permission refusée. Réservé aux administrateurs."}

    # S5 (L3O4) — Defense-in-depth: en mode automation, ré-appliquer la whitelist
    # ``AUTOMATION_TOOL_CLASSIFICATION`` à l'EXÉCUTION (pas seulement à l'exposition
    # via ``filter_tools_for_context``). Sans ça, blocage par MASQUAGE SEUL : un
    # tool_use forgé / halluciné / rejoué (ex. send_email, manage_users,
    # propose_sql_write) contournerait le filtre et s'exécuterait en background.
    # Fail-closed strict (doctrine 2026-05-27) : tout tool != "allowed" (donc
    # "blocked" OU absent de la classification) est refusé. ``isinstance(context, dict)``
    # garde contre un context non-dict inattendu (refus = sûr).
    if isinstance(context, dict) and context.get("_exec_source") == "automation":
        if AUTOMATION_TOOL_CLASSIFICATION.get(tool_name) != "allowed":
            logger.warning(
                "execute_tool: tool '%s' bloqué en mode automation "
                "(classification=%r, défense-en-profondeur)",
                tool_name,
                AUTOMATION_TOOL_CLASSIFICATION.get(tool_name),
            )
            return {
                "success": False,
                "error": "Outil non autorisé en mode automation (exécution en arrière-plan).",
            }

    logger.info(
        "execute_tool: dispatching '%s'",
        tool_name,
        extra={"user_id": getattr(user, "id", None), "input_keys": list(tool_input.keys())},
    )

    try:
        return await handler(tool_input, user, context)
    except Exception:
        logger.error(
            "execute_tool: unhandled exception in '%s'",
            tool_name,
            exc_info=True,
        )
        error_msg = f"Erreur interne dans l'outil {tool_name}."
        return {"success": False, "error": error_msg}


# ---------------------------------------------------------------------------
# Tool-role filtering
# ---------------------------------------------------------------------------

# Tools accessible per role. IRIS sees everything (it's the generalist).
# Admin-only tools require user.role == "admin" regardless of agent role.
_ROLE_TOOLS: Dict[str, set] = {
    "iris": {
        "execute_sql",
        "get_database_schema",
        "peek_table_data",
        "analyze_numbers",
        "search_documentation",
        "ask_user_clarification",
        "analyze_query_performance",
        "analyze_attachment",
        "transform_uploaded_file",
        "list_workbook_tabs",
        "read_workbook_rows",
        "count_workbook_rows",
        "aggregate_workbook",
        "quick_overview_workbook",
        "get_user_preferences",
        "save_user_preference",
        "suggest_followup_questions",
        "introspect_table",
        "learn_insight",
        "trigger_schema_sync",
        "check_schema_freshness",
        "trigger_enriched_sync",
        "analyze_null_data",
        "save_memory",
        # Outils SQL avancés (ex-orchestrateur)
        "search_schema",
        "test_sql",
        "get_fk_path",
        "get_resolved_values",
        "explore_join_alternatives",
        "check_join_compatibility",
        "align_request",
        "diagnose_zero_rows",
        "introspect_tables_batch",
        "compare_query_variants",
        "match_analytical_pattern",
        "create_report_from_results",
        # Pipeline NL→SQL (workflow principal pour SQL analytique)
        "run_pipeline",
        "inspect_pipeline_artifact",
        "pipeline_resume",
        # T20 — Mutation IR multi-tour (refine de la dernière run_pipeline)
        "mutate_last_ir",
        # T23 — Mode exploration ouverte (préfilter avant run_pipeline)
        "start_exploration_mode",
        # Casquette Iris-DBA-write (admin only, filtré côté get_tools_for_role)
        "propose_sql_write",
        # Casquette Iris-agent-Komptia (lecture du code source)
        "search_codebase",
        "read_code_file",
        "list_code_files",
        # Outils terminaux (P2.2)
        "done",
        "abandon",
        # Plan structuré (todo-list dynamique — affichée live à l'utilisateur)
        "plan_add",
        "plan_update",
        "plan_list",
        # --- Désactivés temporairement ---
        # "create_report",
        # "send_email",
        # "save_to_datastore",
        # "schedule_task",
        # "manage_automations",
        # "list_execution_history",
        # "manage_contacts",
        # "manage_distribution_lists",
        # "list_reports",
        # "manage_users",
        # "get_app_stats",
        # "manage_app_config",
    },
    "sql_expert": {
        # Outils SQL essentiels
        "execute_sql",
        "test_sql",
        "peek_table_data",
        "introspect_table",
        "introspect_tables_batch",
        "search_schema",
        "get_fk_path",
        "get_resolved_values",
        "explore_join_alternatives",
        "check_join_compatibility",  # Confirme un JOIN sans FK déclarée (INTERSECT)
        "align_request",  # Extrait les concepts de la demande user
        "match_analytical_pattern",  # P2.3 — motif canonique (rollup, YoY…)
        "get_database_schema",
        "diagnose_zero_rows",
        "compare_query_variants",  # Compare 2-3 SQL côte à côte (COUNT delta)
        # Diagnostic avancé (profil DBA)
        "analyze_query_performance",  # Plan d'exécution / stats
        "analyze_null_data",  # Colonnes mostly NULL
        "analyze_numbers",  # Stats numériques + outliers
        # Transformation classeur uploadé (délègue à copilot_agent — Phase 1
        # du chantier upload-as-result). IrisAgent.run() force role=SQL_EXPERT
        # runtime, donc ce tool doit être ici pour être visible du LLM via
        # `get_tools_for_role`.
        "transform_uploaded_file",
        # Task #7 — ``analyze_attachment`` pour les fichiers binaires/gros
        # (>200 Ko) qui ne sont pas inlinés dans le user message par
        # ``agent_service.py`` (cf. _file_hint, fallback file_id+notice).
        # Sans ce tool, le LLM voit la notice « Utilise analyze_attachment »
        # mais n'a pas l'outil dans sa toolbox → tool_use échoue → l'agent
        # est obligé d'inventer une excuse à l'user. Ajouté après bump du
        # tour onboarding (Task #22) pour que les users qui voient le step
        # trombone puissent ENFIN attacher Excel/binaires fonctionnellement.
        "analyze_attachment",
        # Lecture granulaire d'un classeur uploadé via les cores copilot
        # (P2.2 task #13). Permet à Iris de naviguer dans un upload sans
        # déclencher copilot_agent (cas typique : « combien de lignes où
        # statut=payé ? »). Complémentaire à analyze_attachment (lecture
        # statistique d'ensemble) et transform_uploaded_file (modification).
        "list_workbook_tabs",
        "read_workbook_rows",
        "count_workbook_rows",
        "aggregate_workbook",
        # Overview programmatique 0-LLM (P2.3 task #14) — recommandé en
        # premier appel après upload pour aperçu structurel + sample en 1 turn.
        "quick_overview_workbook",
        # Interaction utilisateur
        "ask_user_clarification",
        # Schéma & documentation
        "check_schema_freshness",
        "trigger_schema_sync",
        "learn_insight",
        "save_memory",  # Persistance apprentissage cross-conversation
        # Pipeline NL→SQL (workflow principal pour SQL analytique)
        "run_pipeline",
        "inspect_pipeline_artifact",
        "pipeline_resume",
        # T20 — Mutation IR multi-tour (refine de la dernière run_pipeline)
        "mutate_last_ir",
        # T23 — Mode exploration ouverte (préfilter avant run_pipeline)
        "start_exploration_mode",
        # Casquette Iris-DBA-write (admin only, filtré côté get_tools_for_role)
        "propose_sql_write",
        # Casquette Iris-agent-Komptia (lecture du code source)
        "search_codebase",
        "read_code_file",
        "list_code_files",
        # Outils terminaux (P2.2)
        "done",
        "abandon",
        # Plan structuré (todo-list dynamique — affichée live à l'utilisateur)
        "plan_add",
        "plan_update",
        "plan_list",
        # Task #10/#11 — Tools DAG-aware exclusivement disponibles en mode
        # automation. Listés ici pour passer le check ``_ROLE_TOOLS`` ; le
        # filtrage par contexte (``filter_tools_for_context``) garantit
        # qu'ils ne sont exposés qu'en ``source="automation"`` — invisibles
        # en page/widget par AUTOMATION_TOOL_CLASSIFICATION (allowed only auto).
        "set_run_variable",
        "get_run_variable",
        "get_step_output",
        "route_to",
        "skip_steps",
        "abort_run",
        # --- Désactivés temporairement ---
        # "save_to_datastore",
        # "create_report",
    },
    "data_analyst": {
        "execute_sql",
        "get_database_schema",
        "peek_table_data",
        "analyze_numbers",
        "search_documentation",
        "ask_user_clarification",
        "analyze_query_performance",
        "analyze_attachment",
        "introspect_table",
        "learn_insight",
        "get_user_preferences",
        "save_user_preference",
        "suggest_followup_questions",
        "check_schema_freshness",
        "trigger_schema_sync",
        "trigger_enriched_sync",
        "analyze_null_data",
        "save_memory",
        # Outils SQL avancés (ex-orchestrateur)
        "search_schema",
        "test_sql",
        "get_fk_path",
        "get_resolved_values",
        "explore_join_alternatives",
        "create_report_from_results",
        # T23 — Mode exploration ouverte (préfilter avant run_pipeline)
        "start_exploration_mode",
        # Casquette Iris-agent-Komptia (lecture du code source)
        "search_codebase",
        "read_code_file",
        "list_code_files",
        # Outils terminaux (P2.2)
        "done",
        "abandon",
        # Plan structuré (todo-list dynamique — affichée live à l'utilisateur)
        "plan_add",
        "plan_update",
        "plan_list",
        # --- Désactivés temporairement ---
        # "save_to_datastore",
        # "create_report",
    },
    "app_controller": {
        "ask_user_clarification",
        "get_user_preferences",
        "save_user_preference",
        "suggest_followup_questions",
        # Casquette Iris-agent-Komptia (lecture du code source)
        "search_codebase",
        "read_code_file",
        "list_code_files",
        # Outils terminaux (P2.2) — utiles aussi pour app_controller pour
        # marquer une demande satisfaite (action effectuée) ou impossible.
        "done",
        "abandon",
        # Plan structuré (todo-list dynamique — affichée live à l'utilisateur)
        "plan_add",
        "plan_update",
        "plan_list",
        # --- Désactivés temporairement ---
        # "create_report",
        # "send_email",
        # "save_to_datastore",
        # "schedule_task",
        # "manage_automations",
        # "list_execution_history",
        # "manage_contacts",
        # "manage_distribution_lists",
        # "list_reports",
        # "manage_users",
        # "get_app_stats",
        # "manage_app_config",
    },
}

_ADMIN_ONLY_TOOLS = {
    "manage_users",
    "manage_app_config",
    "get_app_stats",
    "trigger_schema_sync",
    "trigger_enriched_sync",
    # Casquette Iris-DBA-write : seul un admin peut PROPOSER une écriture.
    # Le DBA externe approuvera ensuite via mail. Defense-in-depth :
    # iris_write_session vérifie aussi user.role == admin avant tout.
    "propose_sql_write",
}


def get_tools_for_role(role_value: str, user: Any) -> List[Dict[str, Any]]:
    """
    Return the subset of IRIS_TOOLS available for the given role and user.

    - Filters tools by role (SQL_EXPERT only sees SQL tools, etc.)
    - Removes admin-only tools for non-admin users
    - Falls back to IRIS (all tools) if role unknown
    """
    allowed_names = _ROLE_TOOLS.get(role_value)
    if allowed_names is None:
        logger.error("get_tools_for_role: unknown role '%s', returning empty tools", role_value)
        return []

    # P2.3 SSoT : delegate to ``app.handlers.base.is_admin`` (line 901) which
    # robustly handles UserRole enum + string + None (fail-closed). Ancien
    # check inline manuel : drift garanti des qu'un nouveau role apparait.
    from app.handlers.base import is_admin as _is_admin

    is_admin = _is_admin(user)

    filtered: List[Dict[str, Any]] = []
    for tool in IRIS_TOOLS:
        name = tool["name"]
        if name not in allowed_names:
            continue
        if name in _ADMIN_ONLY_TOOLS and not is_admin:
            continue
        filtered.append(tool)

    return filtered


# ---------------------------------------------------------------------------
# Task #8 P3.1 + Task #30 P3.4 — Filtrage tools par contexte d'exécution
# (whitelist fail-closed pour mode automation).
# ---------------------------------------------------------------------------
# Doctrine 2026-05-27 (décision P0 Q1 "fail-closed strict v1") : tool ABSENT
# de cette classification = BLOQUÉ par défaut en mode automation (linter de
# garde garantit la complétion en CI cf. test_iris_automation_tool_classification.py).
#
# Catégories :
# - "allowed"  : lecture / analyse / raisonnement / control-flow (safe en background)
# - "blocked"  : actions sortantes (passent par steps DAG dédiés),
#                admin (cycle infini), mutation/state interactif, mémoire user
#                (pollution cross-runs cf. Task #31), ask user (fail-closed v1).
AUTOMATION_TOOL_CLASSIFICATION: Dict[str, str] = {
    # ── ALLOWED — SQL read-only (enforcement RLS via query_executor cf. Task #28)
    "execute_sql": "allowed",
    "test_sql": "allowed",
    "peek_table_data": "allowed",
    "analyze_query_performance": "allowed",
    # ── ALLOWED — Schema discovery (read-only)
    "get_database_schema": "allowed",
    "search_schema": "allowed",
    "introspect_table": "allowed",
    "introspect_tables_batch": "allowed",
    "check_schema_freshness": "allowed",
    "get_fk_path": "allowed",
    "get_resolved_values": "allowed",
    # ── ALLOWED — Analyse données / diagnostic
    "analyze_attachment": "allowed",
    "analyze_null_data": "allowed",
    "analyze_numbers": "allowed",
    "diagnose_zero_rows": "allowed",
    "check_join_compatibility": "allowed",
    "compare_query_variants": "allowed",
    "explore_join_alternatives": "allowed",
    "match_analytical_pattern": "allowed",
    "align_request": "allowed",
    # ── ALLOWED — Workbook read-only (consume step outputs amont)
    "aggregate_workbook": "allowed",
    "count_workbook_rows": "allowed",
    "list_workbook_tabs": "allowed",
    "quick_overview_workbook": "allowed",
    "read_workbook_rows": "allowed",
    "transform_uploaded_file": "allowed",
    # ── ALLOWED — Pipeline (IR generation read-only via run_pipeline)
    "run_pipeline": "allowed",
    "inspect_pipeline_artifact": "allowed",
    # ── ALLOWED — Code exploration read-only
    "search_codebase": "allowed",
    "read_code_file": "allowed",
    "list_code_files": "allowed",
    # ── ALLOWED — Listings / stats read-only
    "get_app_stats": "allowed",
    "list_reports": "allowed",
    "list_execution_history": "allowed",
    "search_documentation": "allowed",
    "suggest_followup_questions": "allowed",
    "get_user_preferences": "allowed",  # READ seulement (save_* est bloqué)
    "start_exploration_mode": "allowed",
    # ── ALLOWED — Control-flow / planning
    "abandon": "allowed",
    "done": "allowed",
    "plan_add": "allowed",
    "plan_update": "allowed",
    "plan_list": "allowed",
    # ──────────────────────────────────────────────────────────────────────
    # ── BLOCKED — Ask user (fail-closed strict v1, décision P0 Q1)
    "ask_user_clarification": "blocked",
    # ── BLOCKED — Actions sortantes (steps DAG dédiés existent)
    "send_email": "blocked",  # → step email
    "save_to_datastore": "blocked",  # → step save_to_datastore
    "create_report": "blocked",  # → step report
    "create_report_from_results": "blocked",  # → step report
    # ── BLOCKED — Admin (cycle infini / hors-scope)
    "manage_users": "blocked",
    "manage_app_config": "blocked",
    "manage_automations": "blocked",  # anti-récursion infinie
    "manage_contacts": "blocked",
    "manage_distribution_lists": "blocked",
    "schedule_task": "blocked",
    # ── BLOCKED — Sync lourd (pas dans un step run)
    "trigger_schema_sync": "blocked",
    "trigger_enriched_sync": "blocked",
    # ── BLOCKED — Mutation / state interactif (non-déterministe en automation)
    "propose_sql_write": "blocked",
    "mutate_last_ir": "blocked",
    "pipeline_resume": "blocked",
    # ── BLOCKED — Mémoire user (pollution cross-runs cf. Task #31)
    "save_memory": "blocked",
    "save_user_preference": "blocked",
    "learn_insight": "blocked",
    # ── ALLOWED (automation-only) — DAG-aware tools (Tasks #10/#11)
    # Ces tools n'ont AUCUN sens hors automation : ils mutent le state du
    # run DAG. Exposés seulement en mode "automation" via la classification
    # ci-dessous. Bloqués automatiquement en page/widget car non listés en
    # "allowed" universellement (et le filtre fail-closed ne les expose qu'ici).
    "set_run_variable": "allowed",
    "get_run_variable": "allowed",
    "get_step_output": "allowed",
    "route_to": "allowed",
    "skip_steps": "allowed",
    "abort_run": "allowed",
}


def filter_tools_for_context(tools: List[Dict[str, Any]], context: str) -> List[Dict[str, Any]]:
    """Filtre les tools selon le contexte d'exécution (page/widget/automation).

    Args:
        tools: Liste de tools déjà filtrés par role (cf. ``get_tools_for_role``).
        context: ``"page"`` | ``"widget"`` | ``"automation"``.
            - ``"page"`` / ``"widget"`` : pas de restriction supplémentaire
              (l'user interagit en direct, tools admin/mutation autorisés
              selon role).
            - ``"automation"`` : whitelist fail-closed via
              ``AUTOMATION_TOOL_CLASSIFICATION``. Tool absent ou marqué
              ``"blocked"`` = exclu (jamais visible par l'agent).

    Returns:
        Liste filtrée. Pour ``"automation"`` : uniquement les tools marqués
        ``"allowed"`` dans la classification.

    Note:
        Le linter CI ``test_iris_automation_tool_classification.py`` garantit
        que TOUT tool de ``IRIS_TOOLS`` est explicitement classifié — un nouvel
        outil ajouté sans classification fait fail le test (= bloqué en
        automation par défaut, design fail-closed).
    """
    if context != "automation":
        return tools
    return [t for t in tools if AUTOMATION_TOOL_CLASSIFICATION.get(t["name"]) == "allowed"]


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

__all__ = [
    "IRIS_TOOLS",
    "execute_tool",
    "get_tools_for_role",
    "invalidate_search_indexes",
]
