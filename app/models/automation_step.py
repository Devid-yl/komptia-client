"""
Modele AutomationStep pour Komptia.

Represente une etape dans un workflow d'automatisation multi-etapes (style n8n).
Chaque Automation peut avoir 0..N etapes ordonnees qui forment un pipeline configurable:
extraction -> verification -> transformation -> analyse -> rapport -> email
"""

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import String, Boolean, DateTime, ForeignKey, JSON, Integer
from sqlalchemy.orm import relationship, Mapped, mapped_column

from app.core import clock
from app.core.database import Base

if TYPE_CHECKING:
    from app.models.automation import Automation  # noqa: F401
    from app.models.automation_edge import AutomationEdge  # noqa: F401


class StepType(str, Enum):
    """Types d'etapes disponibles dans un workflow.

    Les 4 categories miroirent la vision utilisateur (cf. CLAUDE.md
    « Source → Format → Rapport/Conversion → Envoi ») :
    1. SOURCE     — produire un classeur (extract_sql, load_workbook,
                    load_saved_query)
    2. FORMAT     — transformer un classeur (format_copilot, qui sera
                    etendu pour couvrir un maximum d'actions automatisables ;
                    cf. docs/design_format_via_copilot.md)
    3. CONVERSION — convertir le classeur en livrable typé (report PDF
                    par IA, export_workbook csv/excel)
    4. SORTIE     — diffuser le livrable (email, save_to_datastore)
    """

    # Source — produire un classeur
    EXTRACT_SQL = "extract_sql"  # Requete SQL ecrite directement dans le step
    LOAD_WORKBOOK = "load_workbook"  # Charger un classeur stocke dans /datastore
    LOAD_SAVED_QUERY = "load_saved_query"  # Rejouer une requete sauvegardee

    # Format — transformer un classeur
    FORMAT_COPILOT = "format_copilot"  # Reformatage NL via copilot_agent
    # Agent IA décideur (Tasks #6/#10/#11/#12 — 2026-05-27).
    # Iris (agent /iris page) invoqué en backend pour PRENDRE DES DÉCISIONS
    # (pas produire des données) : router conditionnellement, skip steps,
    # écrire variables interpolables aval, abort. Cf. iris_automation_bridge.
    IRIS = "iris"

    # Conversion — convertir le classeur en livrable typé
    REPORT = "report"  # Rapport PDF analyse par l'IA
    EXPORT_WORKBOOK = "export_workbook"  # Export plat csv/excel

    # Sortie — diffuser le livrable
    EMAIL = "email"  # Envoi mail vers contacts/listes
    EMAIL_WAIT_RESPONSE = "email_wait_response"  # Email + attente reponse via lien tokenise
    SAVE_TO_DATASTORE = (
        "save_to_datastore"  # Sauvegarder le classeur en .afz.json dans le datastore user
    )
    # -------------------------------------------------------------------------
    # Types retires :
    # - HTTP_REQUEST, CONDITION, SWITCH : costumes sans corps en mode DAG
    #   (handler manquant ou routing then/else ignore). Le branchement
    #   multi-pipelines est supporte nativement par la topologie DAG.
    # - DELAY, LOOP, FOR_EACH, PARALLEL, SUB_WORKFLOW, TRY_CATCH : concepts
    #   lineaires incompatibles avec un DAG pur (cycles interdits).
    # - FILTER_ROWS, FILTER_COLUMNS, SORT, DEDUPLICATE, RENAME_COLUMNS,
    #   COMPUTE_COLUMN, AGGREGATE, MAP_VALUES : fusionnees dans `format` —
    #   format_copilot couvre via instruction NL au copilot_agent (qui
    #   sera etendu pour couvrir un maximum d'actions automatisables ;
    #   cf. docs/design_format_via_copilot.md). Les implementations
    #   primitives `_step_*` restent dans WorkflowEngine en interne, le
    #   temps que copilot puisse les remplacer toutes.
    # - FORMAT_MANUAL : approche "recording iris-grid + recette atomique"
    #   abandonnee 2026-04-30. Cf. docs/design_format_via_copilot.md.
    # - VALIDATE_NOT_NULL, VALIDATE_TYPES, VALIDATE_RANGE, VALIDATE_UNIQUE,
    #   ANALYZE_STATS, ANALYZE_ANOMALIES, SET_VARIABLE : non demandes par
    #   la vision utilisateur. L'analyse est dans `report` (IA).
    # -------------------------------------------------------------------------


# Metadata par type d'etape pour le frontend
STEP_TYPE_META = {
    StepType.EXTRACT_SQL: {
        "label": "Requete SQL",
        "icon": "database",
        "category": "source",
        "description": "Executer une requete SQL ecrite directement dans le step",
        "config_schema": {
            "sql": {"type": "text", "label": "Requete SQL", "required": True},
        },
    },
    StepType.LOAD_WORKBOOK: {
        "label": "Charger un classeur",
        "icon": "folder-symlink",
        "category": "source",
        "description": "Charger un classeur (.afz.json, .xlsx ou .csv) deja stocke dans /datastore",
        "config_schema": {
            "path": {
                "type": "string",
                # Le frontend utilise ``widget`` pour afficher un picker (cf.
                # ``automation-pickers.js``). ``type`` reste la source de
                # verite cote validator backend — on ne change que l'UX.
                "widget": "datastore_file_picker",
                "label": "Fichier",
                "required": True,
                "help": (
                    "Choisissez un fichier dans votre datastore (.afz.json, "
                    ".xlsx, .csv). Ouvre le navigateur de fichiers."
                ),
            },
        },
    },
    StepType.LOAD_SAVED_QUERY: {
        "label": "Rejouer une requete sauvegardee",
        "icon": "bookmark-star",
        "category": "source",
        "description": "Rejouer une requete sauvegardee dans /datastore (lit le fichier .sql et l'execute tel quel, sans regeneration)",
        "config_schema": {
            "sql_path": {
                "type": "string",
                "widget": "datastore_sql_picker",
                "label": "Fichier .sql sauvegarde",
                "required": True,
                "help": (
                    "Choisissez un fichier .sql dans votre datastore "
                    "(genere depuis Iris via le bouton « Enregistrer »)."
                ),
            },
        },
    },
    StepType.FORMAT_COPILOT: {
        "label": "Iris format",
        "icon": "magic",
        "category": "format",
        "description": (
            "Decrire en langage naturel la transformation a appliquer ; "
            "le copilot IA l'applique sur le classeur. "
            "Les termes detectes doivent etre confirmes dans /iris."
        ),
        "config_schema": {
            "instruction": {
                "type": "text",
                "label": "Instruction (en francais)",
                "required": True,
                "help": (
                    "Soyez precis : 'regroupe par client puis somme la colonne "
                    "montant' donne mieux que 'fais le total'."
                ),
            },
        },
    },
    StepType.IRIS: {
        "label": "Iris (décide)",
        "icon": "robot",
        "category": "format",  # Section UI "Agent IA" (cf. STEP_CATEGORIES["format"])
        "description": (
            "L'agent Iris (le même que sur /iris) invoqué en backend pour "
            "PRENDRE DES DÉCISIONS : router conditionnellement, skip étapes "
            "aval, écrire des variables interpolables, abort l'automatisation. "
            "Iris ne PRODUIT PAS de données (utilisez « Iris format » pour ça)."
        ),
        # Task #24 (2026-05-27) — Info-tooltips cliquables (i icons) pour
        # expliquer les concepts du décideur aux users non-tech. Le frontend
        # (canvas) lit `info_tooltips` et affiche des `info-tooltip.js`
        # cliquables (PAS hover — cf. axe 4 Komptia + feedback
        # `feedback_no_decorative_i_buttons`). Convention : titre court +
        # corps explicite avec exemple concret.
        "info_tooltips": [
            {
                "key": "decideur_vs_format",
                "title": "Décideur ≠ Format",
                "body": (
                    "Le step « Iris (décide) » NE TRANSFORME PAS le classeur. "
                    "Il analyse, raisonne, prend des décisions (variables, "
                    "skip steps, abort). Pour transformer un classeur (ajout "
                    "de colonnes, agrégations, filtres), utilise « Iris format »."
                ),
            },
            {
                "key": "variables_interpolation",
                "title": "Variables interpolables",
                "body": (
                    "Quand Iris appelle set_run_variable('verdict', 'OUI'), "
                    "les steps aval peuvent référencer cette valeur via "
                    "{{nom_de_ton_step.verdict}} dans leur configuration "
                    "(corps de mail, requête SQL, titre de rapport, etc.)."
                ),
            },
            {
                "key": "skip_steps_doctrine",
                "title": "Skip steps",
                "body": (
                    "Iris peut désactiver des étapes aval (ex: skip l'envoi "
                    "mail si rien à signaler). Le DAG marque ces steps comme "
                    "« Ignorés » dans l'historique. Seuls les descendants "
                    "topologiques du step Iris peuvent être skippés (pas "
                    "d'ancêtre ou de step parallèle indépendant)."
                ),
            },
            {
                "key": "abort_vs_skip",
                "title": "Abort vs Skip",
                "body": (
                    "« skip_steps » désactive certains steps aval ciblés. "
                    "« abort_run » arrête TOUTE l'automation avec une raison "
                    "tracée. Préfère skip quand seuls quelques steps n'ont "
                    "plus de sens ; abort quand la donnée est corrompue ou "
                    "incohérente (le run entier est invalide)."
                ),
            },
            {
                "key": "cost_llm",
                "title": "Coût LLM",
                "body": (
                    "Chaque step Iris consomme du budget LLM (cf. "
                    "/admin/ai-config et automation.max_llm_cost_eur). "
                    "Le coût cumulé est tracé dans l'historique de chaque run. "
                    "Si le cap est atteint, l'automation est interrompue. "
                    "Préfère des instructions courtes et précises pour "
                    "minimiser le coût."
                ),
            },
            {
                "key": "no_ask_user",
                "title": "Pas de demande utilisateur",
                "body": (
                    "En mode automation, Iris ne PEUT PAS poser de questions "
                    "à l'utilisateur (pas d'écran ouvert). S'il manque "
                    "d'information, il termine l'étape en abandon avec "
                    "une explication claire — l'utilisateur ajuste alors "
                    "l'instruction et relance."
                ),
            },
        ],
        "config_schema": {
            "instruction": {
                "type": "text",
                "label": "Instruction (en français)",
                "required": True,
                "help": (
                    "Décrivez la décision attendue. Ex: « Si le workbook "
                    "amont contient plus de 100 anomalies, abort_run avec "
                    "le décompte. Sinon, set_run_variable('verdict', 'OK') »."
                ),
                # Task #37 (2026-05-27) — Palette d'exemples cliquables.
                # Le frontend (canvas) lit cette liste et affiche les 6
                # templates à côté de la textarea, cliquables → remplit le
                # champ instruction. Aide les users à démarrer.
                # Convention : exemples génériques (pas de noms réels client/
                # fournisseur), focus sur des décisions métier comptables
                # typiques. Mis à jour à chaque retour terrain pertinent.
                "examples": [
                    {
                        "label": "Skip mail si rien à signaler",
                        "value": (
                            "Si le workbook amont est vide ou contient moins "
                            "de 5 lignes, appelle skip_steps([ID_DU_STEP_EMAIL]) "
                            "avec la raison « Aucune anomalie à signaler ». "
                            "Sinon, appelle done(« Anomalies détectées, "
                            "notification envoyée »)."
                        ),
                    },
                    {
                        "label": "Abort si incohérence calcul",
                        "value": (
                            "Vérifie que la somme des sous-totaux du workbook "
                            "amont est égale au total affiché. Si écart > 1€, "
                            "appelle abort_run avec le détail de l'écart "
                            "(severity='error'). Sinon, done."
                        ),
                    },
                    {
                        "label": "Verdict OUI/NON pour interpolation aval",
                        "value": (
                            "Analyse le workbook amont. Si plus de 10 clients "
                            "dépassent le délai de paiement de 60 jours, "
                            "set_run_variable('alerte_retards', 'OUI') sinon "
                            "set_run_variable('alerte_retards', 'NON'). "
                            "Termine par done avec un résumé court."
                        ),
                    },
                    {
                        "label": "Compteur d'anomalies",
                        "value": (
                            "Compte les lignes du workbook amont où la "
                            "colonne 'statut' vaut 'anomalie'. "
                            "set_run_variable('nb_anomalies', <compte>) puis "
                            "done avec le décompte."
                        ),
                    },
                    {
                        "label": "Top N pour mail dynamique",
                        "value": (
                            "Trouve les 5 clients avec le plus gros encours "
                            "dans le workbook amont. "
                            "set_run_variable('top_clients_csv', '<noms "
                            "séparés par virgule>'). Ces noms seront "
                            "interpolés dans le corps du mail aval via "
                            "{{step.top_clients_csv}}."
                        ),
                    },
                    {
                        "label": "Période fiscale dynamique",
                        "value": (
                            "Détermine le premier et dernier jour du mois "
                            "fiscal en cours via execute_sql sur la table "
                            "des périodes Sage. "
                            "set_run_variable('date_debut', '<YYYY-MM-DD>') "
                            "et set_run_variable('date_fin', '<YYYY-MM-DD>'). "
                            "Ces dates seront interpolées dans les requêtes "
                            "SQL des steps aval."
                        ),
                    },
                ],
            },
        },
    },
    StepType.REPORT: {
        "label": "Rapport (analyse IA)",
        "icon": "file-earmark-text",
        "category": "conversion",
        "description": (
            "Generer un rapport PDF analyse par l'IA : selection des feuilles "
            "et des classeurs, l'IA construit le plan, redige les sections "
            "et compose les graphiques."
        ),
        "config_schema": {
            "title": {"type": "string", "label": "Titre du rapport"},
            "prompt": {
                "type": "text",
                "label": "Instruction pour l'IA",
                "help": (
                    "Ex : 'analyse les variations mensuelles du chiffre "
                    "d'affaires par client et identifie les anomalies'"
                ),
            },
        },
    },
    StepType.EXPORT_WORKBOOK: {
        "label": "Convertir en Excel/CSV",
        "icon": "file-earmark-spreadsheet",
        "category": "conversion",
        "description": (
            "Convertir le classeur (ou des feuilles selectionnees) en fichier "
            "Excel ou CSV. Aucune analyse IA — export plat."
        ),
        "config_schema": {
            "format": {
                "type": "select",
                "label": "Format de sortie",
                "options": ["excel", "csv"],
                "default": "excel",
                "required": True,
            },
            "tabs": {
                "type": "string",
                "widget": "workbook_tabs_multi_picker",
                "label": "Feuilles a inclure",
                "default": "all",
                "help": (
                    "Selectionnez les onglets a inclure, ou laissez 'Tous' "
                    "par defaut. En CSV avec plusieurs onglets, un fichier "
                    "par onglet."
                ),
            },
            "filename": {
                "type": "string",
                "label": "Nom du fichier (sans extension, optionnel)",
            },
            "export_anonymized": {
                "type": "boolean",
                "label": "Anonymiser les valeurs",
                "default": False,
                "help": (
                    "Si coche : remplace les valeurs sensibles par les "
                    "pseudonymes definis sur /data/privacy avant d'ecrire le "
                    "fichier. Les valeurs non configurees restent en clair. "
                    "Utile quand l'export part vers un destinataire externe."
                ),
            },
        },
    },
    StepType.EMAIL: {
        "label": "Envoyer par email",
        "icon": "envelope",
        "category": "sortie",
        "description": (
            "Envoyer le resultat (rapport, export, classeur) a des contacts "
            "ou a une liste de diffusion (cf. /contacts)."
        ),
        "config_schema": {
            "to": {
                "type": "list",
                "widget": "contacts_chips",
                "label": "Destinataires (emails directs)",
                "help": "Tapez ou choisissez parmi vos contacts.",
            },
            "from_distribution_list_id": {
                "type": "number",
                "widget": "distribution_list_picker",
                "label": "Liste de diffusion",
                "help": "Choisissez parmi vos listes de diffusion (cf. /contacts).",
            },
            "cc": {
                "type": "list",
                "widget": "contacts_chips",
                "label": "Copies (cc)",
            },
            "bcc": {
                "type": "list",
                "widget": "contacts_chips",
                "label": "Copies cachees (bcc)",
            },
            "subject": {"type": "string", "label": "Objet de l'email"},
            "export_anonymized": {
                "type": "boolean",
                "label": "Anonymiser les classeurs joints automatiquement",
                "default": False,
                "help": (
                    "Si coche : les classeurs convertis AUTOMATIQUEMENT en piece "
                    "jointe (cas Format -> Email direct, sans step Export) sont "
                    "anonymises via /data/privacy. Les fichiers produits par un step "
                    "Export gardent le reglage de CE step. Utile : l'email part vers "
                    "des destinataires externes."
                ),
            },
        },
    },
    StepType.EMAIL_WAIT_RESPONSE: {
        # Envoi mail a UN destinataire avec un lien tokenise.
        # L'automation se met en pause (status='waiting') jusqu'a ce que
        # le destinataire ouvre le lien et soumette sa reponse (texte
        # libre + fichier optionnel CSV/Excel). Au submit : reprise
        # automatique du DAG via APScheduler one-shot.
        # Cancel-on-next-run : si une nouvelle execution scheduled
        # arrive pendant l'attente, l'execution waiting est annulee
        # et le destinataire recoit un mail "tache annulee".
        "label": "Envoyer + attendre reponse",
        "icon": "envelope-paper",
        "category": "sortie",
        "description": (
            "Envoyer un mail a UN destinataire avec un lien securise. "
            "L'automatisation se met en pause jusqu'a ce que le destinataire "
            "soumette une reponse (texte et/ou fichier). Reprise automatique "
            "au submit. Annulee si la prochaine execution arrive avant la "
            "reponse."
        ),
        "config_schema": {
            "to": {
                "type": "string",
                # Pas de widget custom : champ texte natif pour saisir UN seul
                # email. ``contacts_chips`` est réservé aux listes multiples
                # (EMAIL.to/cc/bcc) ; un picker mono-destinataire dédié n'est
                # pas implémenté côté frontend, donc on évite le "costume sans
                # corps" en restant sur le widget natif.
                "label": "Destinataire (email unique)",
                "required": True,
                "help": "Un seul destinataire (vs envoi standard).",
            },
            "subject": {
                "type": "string",
                "label": "Objet de l'email",
                "required": True,
            },
            "body": {
                "type": "text",
                "widget": "textarea",
                "label": "Corps du message",
                "help": (
                    "Le lien sera ajoute automatiquement en bas du mail. "
                    "Decrivez ici ce que vous attendez du destinataire."
                ),
            },
            "response_kind": {
                "type": "select",
                "label": "Type de reponse attendue",
                "options": ["text", "file", "both"],
                "default": "text",
                "help": ("text = champ libre ; file = upload CSV/Excel ; " "both = les deux."),
            },
            "file_format": {
                "type": "select",
                "label": "Format de fichier accepte",
                "options": ["csv", "xlsx", "both"],
                "default": "both",
                "help": "Applicable seulement si response_kind = file ou both.",
            },
            "wait_timeout_hours": {
                "type": "number",
                "label": "Delai max d'attente (heures)",
                "default": 0,
                "help": (
                    "0 = auto (calcule selon le schedule de l'automatisation). "
                    "Sinon : nombre d'heures fixe avant annulation. Max 720 (30j)."
                ),
            },
            "reminder_hours_before": {
                "type": "number",
                "label": "Rappel au proprio (heures avant expiration)",
                "default": 0,
                "help": (
                    "0 = pas de rappel. Sinon : envoie un mail au proprio de "
                    "l'automatisation X heures avant expiration du lien."
                ),
            },
            "include_inputs_as_attachments": {
                "type": "boolean",
                "label": "Joindre les entrees du step en piece jointe",
                "default": False,
                "help": (
                    "Si coche : joint les fichiers/classeurs des etapes "
                    "precedentes au mail (utile pour donner du contexte au "
                    "destinataire). Si decoche : juste le lien."
                ),
            },
        },
    },
    StepType.SAVE_TO_DATASTORE: {
        # NB collision de nommage : Iris (chat agent) expose deja un tool
        # `save_to_datastore` (`app/services/ai/agent_tools.py:330`) qui
        # sert a persister un resultat SQL en .csv/.sql (~le user dit
        # « enregistre cette requete »). Le step type ci-dessous est
        # different : il sauvegarde le workbook complet en .afz.json a
        # la fin d'un workflow d'automation. Routings differents
        # (`_TOOL_HANDLERS` chat vs adapter executor DAG), pas de bug
        # technique direct, mais a garder en tete au moment d'une
        # discussion produit ou d'un audit logging.
        "label": "Sauvegarder dans le datastore",
        "icon": "hdd",
        "category": "sortie",
        "description": (
            "Sauvegarder le classeur dans le datastore utilisateur "
            "(.afz.json) pour reutilisation par d'autres automations "
            "(via load_workbook) ou consultation manuelle."
        ),
        "config_schema": {
            "folder_path": {
                "type": "string",
                "label": "Dossier de destination",
                "default": "automations",
                "help": (
                    "Chemin relatif dans votre datastore (ex : 'rapports/2026'). "
                    "Sera cree s'il n'existe pas. Vide = racine du datastore."
                ),
            },
            "filename": {
                "type": "string",
                "label": "Nom du fichier (sans extension)",
                "required": True,
                "help": (
                    "Le suffixe '.afz.json' est ajoute automatiquement. "
                    "Pour rendre le nom unique : utilisez {date} ou {datetime}, "
                    "remplaces a l'execution (ex : 'rapport_{date}')."
                ),
            },
            "overwrite": {
                "type": "boolean",
                "label": "Ecraser si le fichier existe deja",
                "default": False,
                "help": (
                    "Decoche : ajoute un suffixe numerique (rapport_2.afz.json). "
                    "Coche : remplace le fichier existant."
                ),
            },
        },
    },
}

# Categories pour regroupement UI
# Order suit la vision DAG 4 maillons (CLAUDE.md) :
# Source → Format → Rapport/Conversion → Envoi (renomme « Sortie »).
STEP_CATEGORIES = {
    "source": {"label": "Source", "icon": "database", "order": 1},
    "format": {"label": "Agent IA", "icon": "arrow-repeat", "order": 2},
    "conversion": {"label": "Conversion", "icon": "file-earmark-arrow-down", "order": 3},
    "sortie": {"label": "Sortie", "icon": "box-arrow-right", "order": 4},
}


class AutomationStep(Base):
    """
    Etape d'un workflow d'automatisation multi-etapes.

    Un workflow est une suite ordonnee d'etapes qui forment un pipeline:
    chaque etape recoit les donnees de l'etape precedente et passe
    son resultat a l'etape suivante.
    """

    __tablename__ = "F_AUTOMATION_STEP"

    # Identification
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    automation_id: Mapped[int] = mapped_column(
        ForeignKey("F_AUTOMATION.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Automatisation parente",
    )

    # Configuration de l'etape
    name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        comment="Nom descriptif de l'etape (ex: 'Extraire les clients actifs')",
    )
    step_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Type d'etape (extract_sql, filter_rows, report, email, etc.)",
    )
    step_order: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Ordre d'execution dans le workflow (0-based)",
    )
    config: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Configuration specifique au type d'etape (SQL, colonnes, seuils, etc.)",
    )

    # Etat
    is_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Etape active (les etapes desactivees sont sautees)",
    )

    # Layout canvas (Phase 1 DAG) — position visuelle du node sur le canvas
    # Drawflow/LiteGraph. `None` = layout auto (grille depuis step_order).
    layout_x: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Position X du node sur le canvas (px). NULL = layout auto.",
    )
    layout_y: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Position Y du node sur le canvas (px). NULL = layout auto.",
    )

    # Policies d'entree (Phase 1 DAG) — comportement quand les inputs du node
    # ont certaines caracteristiques (ex: classeur vide, parent null).
    # Ex: {"on_empty": "abort"|"warn"|"continue"}. NULL = policy par defaut.
    input_policy: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Policy d'entree du node (on_empty, etc.). NULL = defaut.",
    )

    # Retry config
    max_retries: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Nombre max de tentatives supplementaires (0 = pas de retry, max 5)",
    )
    retry_delay_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=5,
        server_default="5",
        comment="Delai en secondes entre chaque retry (1-60)",
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        onupdate=clock.now,
    )

    # Relations
    automation: Mapped["Automation"] = relationship("Automation", back_populates="steps")
    outgoing_edges: Mapped[list["AutomationEdge"]] = relationship(
        "AutomationEdge",
        foreign_keys="AutomationEdge.from_step_id",
        back_populates="from_step",
        cascade="all, delete-orphan",
    )
    incoming_edges: Mapped[list["AutomationEdge"]] = relationship(
        "AutomationEdge",
        foreign_keys="AutomationEdge.to_step_id",
        back_populates="to_step",
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return (
            f"<AutomationStep(id={self.id}, type='{self.step_type}', "
            f"order={self.step_order}, name='{self.name}')>"
        )

    def to_dict(self):
        """Convertit en dictionnaire pour JSON API."""
        meta = STEP_TYPE_META.get(self.step_type, {})
        return {
            "id": self.id,
            "automation_id": self.automation_id,
            "name": self.name,
            "step_type": self.step_type,
            "step_order": self.step_order,
            "config": self.config or {},
            "is_enabled": self.is_enabled,
            "label": meta.get("label", self.step_type),
            "icon": meta.get("icon", "gear"),
            "category": meta.get("category", "autre"),
            "max_retries": self.max_retries,
            "retry_delay_seconds": self.retry_delay_seconds,
            "layout_x": self.layout_x,
            "layout_y": self.layout_y,
            "input_policy": self.input_policy or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def validate(self, *, partial: bool = False) -> list[str]:
        """Valide la configuration de l'etape. Retourne une liste d'erreurs.

        Args:
            partial: Si ``True``, on n'exige PAS les champs ``required``.
                Mode utilise pour la creation/edition cote canvas : un step
                fraichement drag-and-drop arrive avec ``config={}`` et c'est
                normal — l'utilisateur va le configurer via le panel ensuite.
                Le check ``required`` est applique a l'activation seulement
                (cf. ``validate_completeness`` qui rappelle cette methode
                avec ``partial=False`` sur chaque node).

                Si ``False`` (defaut, retrocompat), on rejette les champs
                ``required`` manquants — comportement historique.

        Test ``partial=True`` : valide toujours le **type** et le **schema**
        (cles inconnues sont rejetees ailleurs via ``_validate_step_config``).
        Donc on n'autorise pas n'importe quoi : on autorise juste un
        brouillon.
        """
        errors = []

        # Verifier le type
        valid_types = [t.value for t in StepType]
        if self.step_type not in valid_types:
            errors.append(f"Type d'etape inconnu: {self.step_type}")
            return errors

        if partial:
            # Mode brouillon : on ne check pas les required. Le type est
            # valide, le schema-keys aussi (verifie en amont par
            # `_validate_step_config`). Suffisant pour persister un step
            # tout juste drag-droppe.
            return errors

        # Verifier la config requise
        meta = STEP_TYPE_META.get(StepType(self.step_type), {})
        schema = meta.get("config_schema", {})
        cfg = self.config or {}

        for field_name, field_spec in schema.items():
            if field_spec.get("required") and not cfg.get(field_name):
                errors.append(f"Champ requis manquant: {field_spec.get('label', field_name)}")

        return errors
