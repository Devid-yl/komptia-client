"""
Taxonomie d'erreurs SQL pour auto-correction guidée.

Classifie les erreurs SQL Server en 10 catégories avec prompts de correction
spécialisés. Inspiré de SQL-of-Thought (arXiv:2509.00581) et MAGIC (AAAI 2025).

Chaque catégorie d'erreur a :
- Des regex de détection (messages d'erreur SQL Server)
- Un prompt de correction ciblé (pas un générique "fixe ça")
- Des suggestions d'outils à utiliser pour résoudre le problème
"""

import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ErrorClassification:
    """Résultat de la classification d'une erreur SQL."""

    category: str  # Une des ERROR_TAXONOMY_CATEGORIES
    confidence: float  # 0.0-1.0, confiance dans la classification
    details: str  # Description humaine du problème
    sql_fragment: str = ""  # Partie du SQL en cause (si identifiable)
    # Suggestions "did you mean" — surtout pour column_not_found : si le
    # caller fournit les noms des colonnes candidates, une distance
    # éditionnelle identifie les plus proches. Fourni par le caller
    # (ex: ``agent_tools._handle_execute_sql``) qui a accès aux
    # schémas — la taxonomy ne peut pas les deviner.
    suggestions: list[str] = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.suggestions is None:
            self.suggestions = []



# Patterns de détection par catégorie (messages d'erreur SQL Server + pyodbc)
_DETECTION_PATTERNS: dict[str, list[re.Pattern]] = {
    "table_not_found": [
        re.compile(r"Invalid object name '([^']+)'", re.IGNORECASE),
        re.compile(r"Could not find (?:server|table|object) '([^']+)'", re.IGNORECASE),
        re.compile(r"table[s]?\s+(?:inexistante|non disponible|introuvable)", re.IGNORECASE),
        re.compile(r"does not exist.*table", re.IGNORECASE),
        re.compile(r"Nom d'objet '([^']+)' non valide", re.IGNORECASE),
    ],
    "excel_reference": [
        # "Invalid column name 'B3'" where B3 looks like an Excel cell reference
        re.compile(r"Invalid column name '([A-Z]{1,2}\d{1,4})'", re.IGNORECASE),
        re.compile(r"Nom de colonne '([A-Z]{1,2}\d{1,4})' non valide", re.IGNORECASE),
        # Pre-flight detection message from validator
        re.compile(r"[Rr].f.rences? tableur d.tect.es?", re.IGNORECASE),
    ],
    "column_not_found": [
        re.compile(r"Invalid column name '([^']+)'", re.IGNORECASE),
        re.compile(r"Colonne[s]?\s+'([^']+)'\s+(?:inexistante|introuvable)", re.IGNORECASE),
        # Spécifique : capturer l'identifiant multi-partie (ex: 'Col01.colCode')
        re.compile(r"multi-part identifier\s+['\"]([^'\"]+)['\"]", re.IGNORECASE),
        # Fallback générique (sans capture)
        re.compile(
            r"(?:multi-part identifier|ambiguous column).*could not be bound", re.IGNORECASE
        ),
        re.compile(r"No column name was specified for column (\d+)", re.IGNORECASE),
        re.compile(r"Nom de colonne '([^']+)' non valide", re.IGNORECASE),
    ],
    "type_mismatch": [
        re.compile(
            r"Conversion failed.*converting.*(?:varchar|nvarchar|int|datetime)", re.IGNORECASE
        ),
        re.compile(r"Arithmetic overflow", re.IGNORECASE),
        re.compile(r"Error converting data type", re.IGNORECASE),
        re.compile(r"Operand type clash", re.IGNORECASE),
        re.compile(r"cannot be (?:cast|converted) to", re.IGNORECASE),
        # French SQL Server messages
        re.compile(r"La conversion.*type de donn.es", re.IGNORECASE),
        re.compile(r"valeur hors limites", re.IGNORECASE),
        re.compile(r"d.passement arithm.tique", re.IGNORECASE),
        re.compile(r"Erreur SQL \(2200[0-9]\)", re.IGNORECASE),  # SQLSTATE 2200x = data errors
    ],
    "join_error": [
        re.compile(r"The multi-part identifier.*could not be bound", re.IGNORECASE),
        re.compile(r"Ambiguous column name '([^']+)'", re.IGNORECASE),
        re.compile(r"correlation name.*already.*in use", re.IGNORECASE),
    ],
    "agg_no_groupby": [
        re.compile(
            r"Column '([^']+)' is invalid.*(?:aggregate function|GROUP BY)",
            re.IGNORECASE,
        ),
        re.compile(r"not contained in.*(?:aggregate|GROUP BY)", re.IGNORECASE),
    ],
    "having_vs_where": [
        re.compile(r"An aggregate.*in the WHERE clause", re.IGNORECASE),
        re.compile(r"Cannot use an aggregate.*in.*WHERE", re.IGNORECASE),
    ],
    "null_arithmetic": [
        re.compile(r"Divide by zero", re.IGNORECASE),
        re.compile(r"Warning:.*Null value.*eliminated.*aggregate", re.IGNORECASE),
    ],
    "timeout_or_resource": [
        re.compile(r"Timeout expired", re.IGNORECASE),
        re.compile(r"Lock request time out", re.IGNORECASE),
        re.compile(r"Insufficient (?:memory|resources)", re.IGNORECASE),
        re.compile(r"Connection.*(?:timed out|refused|reset)", re.IGNORECASE),
        re.compile(r"deadlock", re.IGNORECASE),
    ],
    "zero_rows": [
        # Pas une erreur SQL Server — détecté côté applicatif
        re.compile(r"0 (?:lignes?|rows?|résultats?)", re.IGNORECASE),
    ],
    "duplicate_cte_columns": [
        re.compile(
            r"The column '([^']+)' was specified multiple times for '([^']+)'", re.IGNORECASE
        ),
        re.compile(r"colonne '([^']+)' a .t. sp.cifi.e plusieurs fois", re.IGNORECASE),
        re.compile(r"Colonne dupliqu.e '([^']+)' dans le SELECT du CTE", re.IGNORECASE),
    ],
    "syntax_error": [
        re.compile(r"Incorrect syntax near '([^']+)'", re.IGNORECASE),
        re.compile(r"Syntaxe incorrecte\b", re.IGNORECASE),
        re.compile(r"Unexpected token", re.IGNORECASE),
        re.compile(r"parse error", re.IGNORECASE),
        re.compile(r"syntax error", re.IGNORECASE),
        re.compile(r"Expecting.*found", re.IGNORECASE),
    ],
    # server_guard : blocage applicatif AVANT exécution SQL Server.
    # N'est PAS une erreur de syntaxe — la requête est peut-être parfaitement
    # valide, mais un garde-fou serveur l'a refusée (doublon, flux imposé, etc.).
    # Le guide de correction pour `syntax_error` est trompeur pour ces cas :
    # il oriente vers "vérifie tes parenthèses" alors que le SQL est bon.
    "server_guard": [
        re.compile(r"test_sql_required", re.IGNORECASE),
        re.compile(r"analysis_required", re.IGNORECASE),
        re.compile(r"Seules les requ.tes SELECT sont autoris.es", re.IGNORECASE),
        re.compile(r"blocked_by", re.IGNORECASE),
    ],
    "internal_error": [
        # Erreurs Python (bugs applicatifs) — NON-retryables : retenter le SQL
        # ne corrigera pas un bug du code. Patterns structurellement ancrés pour
        # éviter les faux positifs (ex: RAISERROR('... TypeError in trigger ...')
        # ne matcherait pas `^\s*TypeError:`).
        # 1. Traceback Python (signal définitif)
        re.compile(r"^Traceback \(most recent call last\):", re.MULTILINE),
        # 2. Frame Python ("File \"...\", line N")
        re.compile(r'^\s*File "[^"]+", line \d+', re.MULTILINE),
        # 3. Exception Python formatée en début de ligne : "NomException: message"
        re.compile(
            r"^\s*(?:"
            + "|".join(
                [
                    "UnboundLocalError",
                    "AttributeError",
                    "NameError",
                    "TypeError",
                    "KeyError",
                    "ImportError",
                    "ModuleNotFoundError",
                    "RecursionError",
                    "IndexError",
                    "ValueError",
                    "RuntimeError",
                ]
            )
            + r"):",
            re.MULTILINE,
        ),
        # 4. Message générique émis par execute_tool quand un handler lève une
        # exception non gérée (app/services/ai/agent_tools.py:5956).
        re.compile(r"Erreur interne dans l'outil\b"),
    ],
}

# Seuils de confiance centralisés (évite les magic numbers éparpillés).
_INTERNAL_ERROR_CONFIDENCE = 0.95  # Traceback/handler error = signal quasi-certain
_TIMEOUT_CONFIDENCE_THRESHOLD = 0.7  # Au-dessus : timeout confirmé, non-retryable

# Prompts de correction spécialisés par catégorie
_CORRECTION_PROMPTS: dict[str, str] = {
    "table_not_found": (
        "La table référencée n'existe pas dans la base. "
        "Utilise l'outil introspect_table ou search_documentation pour "
        "trouver le nom exact de la table. "
        "Vérifie aussi les vues disponibles."
    ),
    "excel_reference": (
        "Le SQL contient des références de cellules tableur (B3, C5, etc.) au lieu de "
        "vrais noms de colonnes SQL. Les coordonnées [row, col] dans le contenu de la feuille "
        "sont des POSITIONS de cellules, PAS des colonnes SQL Server.\n"
        "- Pour calculer une somme de cellules existantes, utilise le type 'cell'.\n"
        "- Pour des données SQL, utilise les vrais noms de colonnes de la base de données.\n"
        "- NE JAMAIS utiliser B3, C5, D10 etc. comme noms de colonnes dans le SQL."
    ),
    "column_not_found": (
        "La colonne référencée n'existe pas dans cette table. Actions :\n"
        "1. Utilise `introspect_table` sur la table concernée pour voir les colonnes exactes\n"
        "2. **Vérifie si la colonne existe dans une VUE consolidée** — les vues combinent "
        "plusieurs tables et contiennent des colonnes absentes des tables de base\n"
        "3. Utilise `search_documentation` avec le nom de la colonne pour trouver "
        "dans quelle table/vue elle se trouve"
    ),
    "type_mismatch": (
        "Erreur de conversion de type. Dans SQL Server :\n"
        "- **Dates (SQLSTATE 22007)** : TOUJOURS vérifier le type de la colonne avec "
        "introspect_table. Si la colonne est datetime/date, utilise le format ISO sans "
        "tirets : '20231001' au lieu de '2023-10-01' (seul format non ambigu). "
        "Si la colonne est varchar stockant des dates, utilise TRY_CONVERT(date, colonne, 120)\n"
        "- Ne JAMAIS utiliser CAST(... AS FLOAT) pour les montants → utiliser DECIMAL(18,2)\n"
        "- Vérifier les types réels avec introspect_table avant de CAST\n"
        "- Les identifiants/codes sont souvent des VARCHAR, pas des INT\n"
        "- Pour Arithmetic overflow → utiliser DECIMAL(38,2) au lieu de DECIMAL(18,2)"
    ),
    "join_error": (
        "Erreur de jointure. Vérifie :\n"
        "1. Que toutes les tables ont un alias unique\n"
        "2. Que les colonnes ambiguës sont préfixées par l'alias\n"
        "3. Utilise introspect_table pour vérifier les clés étrangères réelles\n"
        "4. Ne PAS inventer de relations — utiliser search_documentation "
        "pour trouver les FK documentées"
    ),
    "agg_no_groupby": (
        "Colonne dans le SELECT qui n'est ni agrégée ni dans le GROUP BY. "
        "Deux solutions :\n"
        "1. Ajouter la colonne au GROUP BY\n"
        "2. L'envelopper dans une fonction d'agrégation (MAX, MIN, etc.)\n"
        "Vérifie que TOUTES les colonnes non-agrégées sont dans le GROUP BY."
    ),
    "having_vs_where": (
        "Un agrégat (SUM, COUNT, etc.) est utilisé dans WHERE au lieu de HAVING. "
        "Règle : WHERE filtre AVANT l'agrégation, HAVING filtre APRÈS. "
        "Déplace la condition avec l'agrégat dans une clause HAVING."
    ),
    "null_arithmetic": (
        "Division par zéro ou NULL dans un calcul. Utilise ISNULL() ou NULLIF() :\n"
        "- Division : col1 / NULLIF(col2, 0) — évite divide by zero\n"
        "- Somme : ISNULL(col, 0) — remplace NULL par 0\n"
        "- Vérifier quelles colonnes sont nullable avec introspect_table"
    ),
    "timeout_or_resource": (
        "La requête est trop lourde ou le serveur ne répond pas. Simplifie :\n"
        "1. Ajoute TOP 100 si absent — ⚠ c'est un échantillon de DIAGNOSTIC : si "
        "tu ajoutes (ou gardes) un TOP pour contourner le timeout, tu DOIS dire "
        "EXPLICITEMENT à l'utilisateur que le résultat affiché est limité aux N "
        "premières lignes (PARTIEL, pas exhaustif) et lui proposer de relancer "
        "sans limite une fois la cause du timeout corrigée. Ne présente JAMAIS "
        "un résultat tronqué par TOP comme s'il était complet.\n"
        "2. Réduis le nombre de JOINs\n"
        "3. Utilise des filtres WHERE restrictifs (date, dossier)\n"
        "4. Évite les sous-requêtes corrélées — utilise des CTEs\n"
        "5. Si timeout persistant → c'est un problème réseau, pas SQL"
    ),
    "zero_rows": (
        "La requête a retourné 0 résultats. Ça peut signifier :\n"
        "1. Les données n'existent pas (réponse légitime)\n"
        "2. Un filtre WHERE est trop restrictif ou mal formaté\n"
        "3. Le format des valeurs est incorrect (ex: 'client' vs 'CLIENT' vs '0')\n\n"
        "Pour vérifier : utilise peek_table_data sur la table principale pour "
        "voir les valeurs réelles des colonnes de filtre."
    ),
    "duplicate_cte_columns": (
        "La CTE contient des colonnes dupliquées dans le SELECT. "
        "SQL Server erreur 8156 : une colonne ne peut apparaître qu'une seule fois.\n"
        "Actions :\n"
        "1. Identifier les colonnes dupliquées dans le SELECT du CTE\n"
        "2. Supprimer les occurrences en double (garder une seule)\n"
        "3. Vérifier que chaque colonne est listée UNE SEULE FOIS"
    ),
    "syntax_error": (
        "Erreur de syntaxe SQL — la structure de la requête est invalide.\n"
        "Vérifie :\n"
        "1. Les parenthèses sont équilibrées\n"
        "2. Les mots-clés SQL sont dans le bon ordre "
        "(SELECT [DISTINCT] [TOP N] colonnes FROM table)\n"
        "3. Pas de virgule en trop ou manquante\n"
        "4. Les alias de table sont corrects\n"
        "5. Si la requête est un CTE (WITH), vérifie que le SELECT final est présent"
    ),
    "internal_error": (
        "Erreur interne de l'application (bug du code Python, pas du SQL).\n"
        "Retenter la même requête ne corrigera RIEN — c'est un bug serveur.\n"
        "Action : signale le problème à l'utilisateur et demande-lui "
        "une approche différente (autre formulation, autre table). "
        "N'entre PAS dans une boucle de retry."
    ),
    "server_guard": (
        "La requête a été BLOQUÉE par un garde-fou serveur — ce n'est PAS une\n"
        "erreur de syntaxe. Le SQL est peut-être parfaitement correct.\n"
        "Lis le message `error` pour l'instruction exacte (souvent : appeler\n"
        "`test_sql` d'abord, éviter un appel dupliqué, ou justifier un choix\n"
        "de jointure multi-rôle). NE modifie PAS la requête tant que tu n'as\n"
        "pas suivi l'instruction du guard — ta requête peut être bonne."
    ),
}

# Suggestions d'outils par catégorie
_TOOL_HINTS: dict[str, list[str]] = {
    "table_not_found": ["introspect_table", "search_documentation", "get_database_schema"],
    "excel_reference": ["introspect_table", "get_database_schema"],
    "column_not_found": ["introspect_table", "search_documentation", "get_database_schema"],
    "type_mismatch": ["introspect_table", "peek_table_data"],
    "join_error": ["introspect_table", "search_documentation"],
    "agg_no_groupby": [],
    "having_vs_where": [],
    "null_arithmetic": ["introspect_table"],
    "timeout_or_resource": [],
    "zero_rows": ["peek_table_data", "introspect_table"],
    "duplicate_cte_columns": ["introspect_table"],
    "syntax_error": [],
    "internal_error": [],
    "server_guard": ["test_sql"],
}


def classify_error(error_message: str, sql: str = "") -> ErrorClassification:
    """
    Classifie une erreur SQL dans une des 9 catégories de la taxonomie.

    Args:
        error_message: Message d'erreur SQL Server ou applicatif
        sql: Requête SQL qui a causé l'erreur (pour extraction de contexte)

    Returns:
        ErrorClassification avec catégorie, confiance et détails
    """
    if not error_message:
        return ErrorClassification(
            category="timeout_or_resource",
            confidence=0.3,
            details="Erreur sans message — possible timeout ou déconnexion",
        )

    # Priorité absolue : si on détecte un marqueur définitif de bug Python
    # (traceback ou message générique du handler), court-circuiter le scoring.
    # Sans ça, `classify_error` compare les confidences (0.8 vs 0.9) et un
    # bug Python avec "Invalid column name 'X'" dans le message serait
    # misclassifié en column_not_found, donc retryable → boucle infinie.
    if re.search(
        r"^Traceback \(most recent call last\):", error_message, re.MULTILINE
    ) or re.search(r"Erreur interne dans l'outil\b", error_message):
        return ErrorClassification(
            category="internal_error",
            confidence=_INTERNAL_ERROR_CONFIDENCE,
            details=error_message[:500],
        )

    best_category = ""
    best_confidence = 0.0
    best_fragment = ""

    for category, patterns in _DETECTION_PATTERNS.items():
        for pattern in patterns:
            match = pattern.search(error_message)
            if match:
                # Confiance plus haute si le pattern est spécifique (avec groupe de capture)
                confidence = 0.9 if match.groups() else 0.8
                if confidence > best_confidence:
                    best_category = category
                    best_confidence = confidence
                    best_fragment = match.group(1) if match.groups() else ""
                break  # Un match par catégorie suffit

    if not best_category:
        # Fallback : essayer de deviner par mots-clés génériques
        error_upper = error_message.upper()
        if "TIMEOUT" in error_upper or "CONNECTION" in error_upper:
            best_category = "timeout_or_resource"
            best_confidence = 0.5
        elif "SYNTAX" in error_upper or "SYNTAXE" in error_upper:
            best_category = "syntax_error"
            best_confidence = 0.5
        elif "CONVERSION" in error_upper or "CONVERT" in error_upper or "CAST" in error_upper:
            best_category = "type_mismatch"
            best_confidence = 0.5
        elif "2200" in error_message:  # SQLSTATE 2200x = data exception errors
            best_category = "type_mismatch"
            best_confidence = 0.4
        elif "SELECT" in error_upper and "AUTORIS" in error_upper:
            # "Seules les requêtes SELECT sont autorisées" → blocage serveur,
            # pas une vraie erreur de syntaxe. Oriente le LLM vers le bon reflex.
            best_category = "server_guard"
            best_confidence = 0.6
        elif "BLOQU" in error_upper or "BLOCKED" in error_upper:
            best_category = "server_guard"
            best_confidence = 0.6
        else:
            best_category = "syntax_error"
            best_confidence = 0.2

    logger.debug(
        "Erreur classifiée: %s (confiance=%.2f) fragment='%s'",
        best_category,
        best_confidence,
        best_fragment,
    )

    return ErrorClassification(
        category=best_category,
        confidence=best_confidence,
        details=error_message[:500],
        sql_fragment=best_fragment,
    )


def get_correction_prompt(classification: ErrorClassification) -> str:
    """
    Retourne un prompt de correction spécialisé pour le type d'erreur.

    Ce prompt sera injecté dans le contexte de l'agent pour guider
    la correction, au lieu d'un générique "la requête a échoué".
    """
    base_prompt = _CORRECTION_PROMPTS.get(classification.category, "")

    parts = [f"**Erreur classifiée : {classification.category}**"]

    if classification.sql_fragment:
        parts.append(f"Élément en cause : `{classification.sql_fragment}`")

    parts.append(f"Détail : {classification.details[:300]}")

    if base_prompt:
        parts.append(f"\n**Guide de correction :**\n{base_prompt}")

    return "\n".join(parts)


def get_tool_hints(classification: ErrorClassification) -> list[str]:
    """Retourne les outils suggérés pour résoudre ce type d'erreur."""
    return _TOOL_HINTS.get(classification.category, [])


def is_retryable(classification: ErrorClassification) -> bool:
    """Indique si l'erreur peut être corrigée par une nouvelle tentative SQL."""
    # Les erreurs internes (bugs Python) ne sont JAMAIS corrigibles en retentant :
    # c'est un bug serveur, pas du SQL mal formé.
    if classification.category == "internal_error":
        return False
    # Les timeouts réseau ne sont pas corrigibles par du SQL différent
    if classification.category == "timeout_or_resource":
        return classification.confidence < _TIMEOUT_CONFIDENCE_THRESHOLD
    return True
