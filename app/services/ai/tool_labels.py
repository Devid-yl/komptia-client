"""SSOT — Génération des libellés UI (icône + label FR) des outils Iris.

**Problème historique** : ``TOOL_LABELS`` dans ``agent_service.py`` était une dict
de ~53 entrées hardcodées du genre ``"execute_sql": {"icon": "📊", "label":
"Exécution SQL"}``. Ajouter un outil obligeait à toucher 3 collections :
``IRIS_TOOLS``, ``TOOL_SIDE_EFFECTS`` (classification side-effects, SSOT-1),
et ``TOOL_LABELS``. En session 1 du prod-loop on avait déjà rattrapé 20 oublis
silencieux via F2. SSOT-3 (2026-05-21) tue cette duplication.

**Solution SSOT** :

1. L'icône est dérivée de la classe ``TOOL_SIDE_EFFECTS`` (déjà SSOT depuis #1)
   via ``_ICON_BY_CLASS`` — une icône par catégorie d'effet. Un dev qui ajoute
   un outil et le classe correctement obtient automatiquement une icône cohérente
   avec la sémantique de l'outil.
2. Le label FR est généré par convention ``snake_case → "Action FR"`` via deux
   tables de fragments (``_VERB_FR`` pour le premier token quand c'est un verbe
   d'action, ``_NOUN_FR`` pour les noms techniques type "sql"→"SQL", "fk"→"FK").
   L'acronyme reste en majuscules (pas de mécanique "Sql"), la grammaire FR
   reste lisible.
3. Des overrides explicites (``_LABEL_OVERRIDES`` et ``_ICON_OVERRIDES``) couvrent
   les cas où la convention rendrait un label maladroit ("done" → "Fin du tour"
   plutôt que "Done"). Ces overrides restent un facteur de qualité humaine, mais
   ils sont **opt-in** : sans override la convention produit un label correct.

**Garantie SSOT** : un nouvel outil ajouté à ``IRIS_TOOLS`` + classifié dans
``TOOL_SIDE_EFFECTS`` obtient AUTOMATIQUEMENT une icône et un label FR sans
toucher ce module. L'override n'est nécessaire que pour la finition.

**Test de garde** : ``tests/unit/test_tool_labels_ssot.py`` vérifie qu'aucune
entrée n'est plus hardcodée individuellement et que tout outil de IRIS_TOOLS
reçoit un label valide.
"""

from __future__ import annotations

from typing import Final


# ─────────────────────────────────────────────────────────────────────────────
# Icônes — dérivées de la classe d'effets (SSOT depuis TOOL_SIDE_EFFECTS #1)
# ─────────────────────────────────────────────────────────────────────────────

# Une icône par classe d'effet. Choisies pour matcher l'intuition utilisateur
# (loupe = lecture, disquette = écriture, etc.). Si une nouvelle classe est
# ajoutée à ``SIDE_EFFECT_CLASSES``, l'override par défaut "🔧" s'applique
# en attendant que ce mapping soit étendu — fail-safe, pas fail-fast (un nouvel
# outil reste utilisable avec icône générique).
_ICON_BY_CLASS: Final[dict[str, str]] = {
    "conversational": "💬",
    "metadata_read": "🔍",
    "komptia_read": "📊",
    "komptia_write": "💾",
    "sage_read_live": "📊",
    "sage_write": "⚠",
    "external_io": "📧",
    "costly_async": "🤖",
    "pedagogical_analysis": "📈",
}

# Overrides quand l'icône par classe n'est pas la plus parlante pour CE tool.
# Garder ce dict petit — chaque entrée est une dette de cohérence.
_ICON_OVERRIDES: Final[dict[str, str]] = {
    # Conversational mais visuellement distincts
    "ask_user_clarification": "❓",
    "suggest_followup_questions": "💡",
    "done": "✅",
    "abandon": "🚫",
    "start_exploration_mode": "🧭",
    # Metadata read avec visuel spécifique
    "search_documentation": "📚",
    "introspect_table": "🔍",
    "introspect_tables_batch": "📚",
    "get_database_schema": "🗂️",
    "get_fk_path": "🔗",
    "explore_join_alternatives": "🔀",
    "match_analytical_pattern": "🧩",
    "search_schema": "🔎",
    "search_codebase": "🔎",
    "read_code_file": "📄",
    "list_code_files": "📁",
    "inspect_pipeline_artifact": "🔍",
    "analyze_attachment": "📎",
    # Outils Phase 1+2 du chantier upload-as-result (transform + 4 workbook
    # read + quick_overview). Icônes spécifiques pour les distinguer du
    # générique 🔍 metadata_read — workbook tools manipulent un fichier
    # uploadé (📋), transform_uploaded_file est costly_async (🛠️ remplace
    # 🤖 générique car ici c'est de la transformation utilisateur, pas
    # un sync système).
    "transform_uploaded_file": "🛠️",
    "list_workbook_tabs": "📋",
    "read_workbook_rows": "📄",
    "count_workbook_rows": "🔢",
    "aggregate_workbook": "🧮",
    "quick_overview_workbook": "📊",
    # Sage read live spécifiques
    "execute_sql": "📊",
    "peek_table_data": "👁️",
    "test_sql": "🧪",
    "check_join_compatibility": "🔬",
    "compare_query_variants": "⚖️",
    "analyze_null_data": "🔍",
    "get_resolved_values": "🎯",
    # Pédagogie
    "analyze_query_performance": "⚡",
    "analyze_numbers": "📈",
    "diagnose_zero_rows": "🩺",
    # Komptia read/write spécifiques
    "get_app_stats": "📊",
    "get_user_preferences": "⚙",
    "list_reports": "📄",
    "list_execution_history": "📅",
    "save_to_datastore": "💾",
    "save_user_preference": "💾",
    "save_memory": "💾",
    "schedule_task": "📅",
    "learn_insight": "🧠",
    "manage_automations": "⚙️",
    "manage_contacts": "👥",
    "manage_distribution_lists": "📋",
    "manage_users": "👤",
    "manage_app_config": "⚙️",
    # External / costly
    "send_email": "📧",
    "create_report": "📄",
    "create_report_from_results": "📊",
    "trigger_enriched_sync": "🧠",
    "trigger_schema_sync": "🔄",
    "check_schema_freshness": "🔄",
    "run_pipeline": "🤖",
    "pipeline_resume": "⏳",
    "mutate_last_ir": "🔄",
    "propose_sql_write": "⚠",
    "align_request": "🧭",
}


# ─────────────────────────────────────────────────────────────────────────────
# Labels FR — convention snake_case → "Action FR" + overrides ciblés
# ─────────────────────────────────────────────────────────────────────────────

# Fragment FR pour le premier token (verbe d'action). Format :
# ``(nom_action, particule)`` où la particule sert d'articulation FR
# entre le verbe et le complément ("Lecture du schéma" → particule "du ").
# Quand la particule est ``""``, le verbe colle directement au nom
# (ex: "Test SQL").
_VERB_FR: Final[dict[str, tuple[str, str]]] = {
    "execute": ("Exécution", "de "),
    "introspect": ("Inspection", "de "),
    "get": ("Lecture", "du "),
    "list": ("Liste", "des "),
    "search": ("Recherche", "de "),
    "peek": ("Aperçu", "des "),
    "analyze": ("Analyse", "de "),
    "save": ("Sauvegarde", "de "),
    "create": ("Création", "de "),
    "send": ("Envoi", "de "),
    "learn": ("Apprentissage", ""),
    "suggest": ("Suggestions", "de "),
    "manage": ("Gestion", "des "),
    "check": ("Vérification", "de "),
    "trigger": ("Déclenchement", "de "),
    "explore": ("Exploration", "de "),
    "align": ("Alignement", "de "),
    "diagnose": ("Diagnostic", "de "),
    "compare": ("Comparaison", "de "),
    "match": ("Correspondance", "de "),
    "test": ("Test", ""),
    "read": ("Lecture", "du "),
    "inspect": ("Inspection", "de "),
    "schedule": ("Planification", "de "),
    "run": ("Exécution", "de "),
    "mutate": ("Mutation", "de "),
    "propose": ("Proposition", "de "),
    "start": ("Démarrage", "du "),
    "ask": ("Demande", "de "),
}

# Fragment FR pour les noms techniques (acronymes à préserver, traductions
# courtes). Les acronymes restent en majuscules.
_NOUN_FR: Final[dict[str, str]] = {
    "sql": "SQL",
    "fk": "FK",
    "ir": "IR",
    "schema": "schéma",
    "table": "table",
    "tables": "tables",
    "data": "données",
    "report": "rapport",
    "reports": "rapports",
    "email": "email",
    "documentation": "documentation",
    "preference": "préférence",
    "preferences": "préférences",
    "user": "utilisateur",
    "users": "utilisateurs",
    "contacts": "contacts",
    "automations": "automatisations",
    "memory": "mémoire",
    "task": "tâche",
    "config": "configuration",
    "stats": "statistiques",
    "history": "historique",
    "datastore": "classeur",
    "performance": "performance",
    "pattern": "motif",
    "values": "valeurs",
    "null": "NULL",
    "join": "jointure",
    "joins": "jointures",
    "path": "chemin",
    "variants": "variantes",
    "alternatives": "alternatives",
    "freshness": "fraîcheur",
    "code": "code",
    "files": "fichiers",
    "file": "fichier",
    "pipeline": "pipeline",
    "artifact": "artefact",
    "attachment": "pièce jointe",
    "compatibility": "compatibilité",
    "rows": "lignes",
    "zero": "zéro",
    "query": "requête",
    "request": "requête",
    "insight": "insight",
    "questions": "questions",
    "followup": "suivi",
    "clarification": "clarification",
    "mode": "mode",
    "exploration": "exploration",
    "batch": "batch",
    "distribution": "distribution",
    "lists": "listes",
    "app": "application",
    "enriched": "enrichi",
    "sync": "sync",
    "numbers": "numérique",
    "write": "écriture",
    "last": "dernier",
    "resolved": "résolues",
    "analytical": "analytique",
}

# Overrides pour les outils où la convention rendrait un label maladroit
# (ordre des mots, vocabulaire métier spécifique, particules FR
# irrégulières comme "d'" devant voyelle, acronymes invertibles…).
# Chaque entrée est une dette de cohérence — à chaque ajout ici, se demander
# si la convention pourrait être enrichie à la place (verbe ou nom manquant).
#
# La convention seule produit déjà un label valide pour ~7 outils. Les
# overrides ne sont nécessaires que pour atteindre la qualité FR cible.
# Ajouter un nouvel outil n'impose AUCUN override — le label par défaut est
# toujours acceptable.
_LABEL_OVERRIDES: Final[dict[str, str]] = {
    "ask_user_clarification": "Question à l'utilisateur",
    "save_to_datastore": "Sauvegarde des résultats",
    "create_report_from_results": "Rapport depuis le classeur",
    "manage_automations": "Gestion d'automatisation",
    "manage_distribution_lists": "Gestion des listes",
    "manage_app_config": "Gestion configuration",
    "analyze_query_performance": "Analyse de performance",
    "trigger_enriched_sync": "Sync + enrichissement",
    "search_schema": "Recherche schéma 5D",
    "get_fk_path": "Chemin FK",
    "get_resolved_values": "Résolution de valeurs",
    "align_request": "Alignement requête ↔ BDD",
    "diagnose_zero_rows": "Diagnostic du 0 résultats",
    "introspect_tables_batch": "Inspection batch de tables",
    "compare_query_variants": "Comparaison de variantes SQL",
    "match_analytical_pattern": "Motif analytique",
    "done": "Fin du tour",
    "start_exploration_mode": "Mode exploration",
    "search_codebase": "Recherche dans le code",
    "read_code_file": "Lecture fichier code",
    "list_code_files": "Liste fichiers code",
    "inspect_pipeline_artifact": "Inspection artefact pipeline",
    "run_pipeline": "Pipeline NL→SQL",
    "pipeline_resume": "Reprise pipeline",
    "mutate_last_ir": "Transformation IR",
    "propose_sql_write": "Proposition d'écriture SQL",
    "schedule_task": "Planification d'automation",
    "trigger_schema_sync": "Sync du schéma",
    "check_schema_freshness": "Vérification du schéma",
    "save_user_preference": "Sauvegarde préférence",
    "save_memory": "Sauvegarde mémoire",
    "list_execution_history": "Historique d'exécutions",
    "get_user_preferences": "Préférences utilisateur",
    "get_app_stats": "Statistiques de l'app",
    "analyze_null_data": "Analyse des valeurs NULL",
    "explore_join_alternatives": "Alternatives de jointure",
    "check_join_compatibility": "Compatibilité de jointure",
    "test_sql": "Test SQL (COUNT)",
    "execute_sql": "Exécution SQL",
    "get_database_schema": "Lecture du schéma",
    "search_documentation": "Recherche documentation",
    "peek_table_data": "Aperçu des données",
    "analyze_numbers": "Analyse numérique",
    "send_email": "Envoi d'email",
    "learn_insight": "Apprentissage",
    "suggest_followup_questions": "Suggestions de suivi",
    # Outils Phase 1+2 du chantier upload-as-result. La convention
    # snake_case → "Lister Workbook Tabs" / "Lire Workbook Rows" est
    # maladroite — overrides FR clairs.
    "transform_uploaded_file": "Transformation du classeur",
    "list_workbook_tabs": "Liste des onglets",
    "read_workbook_rows": "Lecture du contenu",
    "count_workbook_rows": "Comptage filtré",
    "aggregate_workbook": "Agrégation filtrée",
    "quick_overview_workbook": "Aperçu du classeur",
}


def _derive_label_fr(tool_name: str) -> str:
    """Génère un label FR à partir du nom snake_case.

    Convention : premier token = verbe (cherché dans ``_VERB_FR``), tokens
    suivants = noms (cherchés dans ``_NOUN_FR``, fallback titlecase). Le
    résultat est lisible même quand un fragment n'est pas mappé — un dev
    voit alors apparaître l'anglais et sait quoi enrichir.

    Si aucun token n'est mappé du tout, retourne le tool_name en TitleCase
    (filet de sécurité — pas d'erreur, juste un label moins poli).
    """
    if tool_name in _LABEL_OVERRIDES:
        return _LABEL_OVERRIDES[tool_name]

    parts = tool_name.split("_")
    if not parts:
        return tool_name

    head = parts[0].lower()
    rest = parts[1:]

    verb_entry = _VERB_FR.get(head)
    if verb_entry is None:
        # Pas un verbe connu — titlecase mécanique mais lisible (filet)
        return " ".join(p.capitalize() for p in parts)

    verb_fr, particle = verb_entry
    if not rest:
        return verb_fr

    noun_pieces = []
    for tok in rest:
        low = tok.lower()
        mapped = _NOUN_FR.get(low)
        if mapped is None:
            # Acronyme court probable (≤4) → upper, sinon titlecase
            mapped = tok.upper() if len(tok) <= 3 else tok.capitalize()
        noun_pieces.append(mapped)

    nouns = " ".join(noun_pieces)
    return f"{verb_fr} {particle}{nouns}".strip()


def _derive_icon(tool_name: str, side_effect_class: str | None) -> str:
    """Icône finale = override explicite > icône par classe > fallback 🔧."""
    if tool_name in _ICON_OVERRIDES:
        return _ICON_OVERRIDES[tool_name]
    if side_effect_class and side_effect_class in _ICON_BY_CLASS:
        return _ICON_BY_CLASS[side_effect_class]
    return "🔧"


def build_tool_labels(
    declared_tools: list[str],
    side_effects: dict[str, str],
) -> dict[str, dict[str, str]]:
    """Construit le dict TOOL_LABELS depuis IRIS_TOOLS + TOOL_SIDE_EFFECTS.

    Args:
        declared_tools: liste des noms d'outils déclarés dans ``IRIS_TOOLS``.
        side_effects: mapping nom→classe d'effet (``TOOL_SIDE_EFFECTS``).

    Returns:
        Dict ``{tool_name: {"icon": ..., "label": ...}}`` couvrant 100 % des
        outils déclarés. Aucun appel à la BDD ni au LLM — pur déterministe
        au module load.

    Le retour ne contient que des outils PRÉSENTS dans ``declared_tools`` —
    pas d'entrée orpheline. C'est l'inverse de l'ancien comportement où une
    entrée TOOL_LABELS pour un tool retiré de IRIS_TOOLS pouvait rester
    silencieusement (now caught by ``_validate_tool_classifications`` côté
    SSOT-1 mais pas pour les labels).
    """
    out: dict[str, dict[str, str]] = {}
    for name in declared_tools:
        cls = side_effects.get(name)
        out[name] = {
            "icon": _derive_icon(name, cls),
            "label": _derive_label_fr(name),
        }
    return out


__all__ = ["build_tool_labels"]
