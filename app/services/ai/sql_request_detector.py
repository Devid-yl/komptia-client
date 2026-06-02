"""Détection heuristique d'une demande SQL utilisateur.

Extrait de l'ancien ``orchestrator.py`` (archivé 2026-05-21 dans
``_trash/iris_dormant_2026_05_21/``) car ``detect_sql_request`` est utilisé
ACTIVEMENT par ``agent_service.py`` (Exploration Guard ligne 4448) alors que
le reste de l'orchestrateur est désactivé runtime (``_USE_ORCHESTRATOR = False``).

Cette fonction n'a aucune dépendance sur la classe ``IrisOrchestrator`` —
c'est juste une heuristique mot-clé pour décider si un message utilisateur
ressemble à une extraction de données SQL (auquel cas l'agent doit forcer
une exploration schéma avant la génération SQL).

API publique : ``detect_sql_request(message, role_value, mode) -> bool``.
"""

from __future__ import annotations

import re


# Keywords that indicate the user wants SQL data extraction
_SQL_KEYWORDS_FR = frozenset(
    {
        "donne",
        "donner",
        "donne-moi",
        "montre",
        "montrer",
        "montre-moi",
        "affiche",
        "afficher",
        "liste",
        "lister",
        "combien",
        "quel",
        "quelle",
        "quels",
        "quelles",
        "total",
        "somme",
        "moyenne",
        "calcule",
        "calculer",
        "extraire",
        "extraction",
        "cherche",
        "chercher",
        "trouve",
        "trouver",
        "chiffre",
        "montant",
        "nombre",
        "statistique",
        "rapport",
        "ventilation",
        "répartition",
        "évolution",
        "comparaison",
        "comparer",
        "analyser",
        "analyse",
    }
)

# Keywords that indicate NON-SQL requests
_NON_SQL_KEYWORDS = frozenset(
    {
        "bonjour",
        "salut",
        "merci",
        "aide",
        "help",
        "comment",
        "configure",
        "paramètre",
        "envoie",
        "email",
        "automatisation",
        "automation",
        "rapport",  # can be SQL or report generation
    }
)


def detect_sql_request(message: str, role_value: str = "", mode: str = "execution") -> bool:
    """Detect if a message requires SQL orchestration.

    Returns True for data extraction requests, False for:
    - Simple questions about schema
    - APP_CONTROLLER requests
    - Explanation mode
    - Greetings / general chat
    """
    if mode != "execution":
        return False

    if role_value == "app_controller":
        return False

    msg_lower = message.lower().strip()

    # Very short messages are usually not SQL
    if len(msg_lower) < 10:
        return False

    # Check for SQL keywords (sets non utilisés mais conservés pour traçabilité
    # historique du calcul — un futur refactor pourra utiliser ``non_sql_matches``
    # pour pondérer la décision si nécessaire).
    words = set(re.findall(r"\b\w+\b", msg_lower))
    sql_matches = words & _SQL_KEYWORDS_FR
    _non_sql_matches = words & _NON_SQL_KEYWORDS  # noqa: F841 — réservé pour ponderation future

    # If at least 2 SQL keywords, it's likely SQL
    if len(sql_matches) >= 2:
        return True

    # Questions with "combien", "quel", etc. are SQL
    if msg_lower.startswith(("combien", "quel", "quelle", "quels", "quelles")):
        return True

    # "Donne-moi" type requests
    if msg_lower.startswith(("donne", "montre", "affiche", "liste", "extrais")):
        return True

    return False
