"""Schemas + dispatch + context pour l'agent widget_planner.

Ce module définit :
- :data:`WIDGET_PLANNER_TOOLS` — la liste des 8 tools exposés au LLM
  (format Anthropic ``{name, description, input_schema}``).
- :class:`WidgetPlannerContext` — état partagé entre handlers de tools
  (rows SQL pré-exécutées, proposals accumulées, terminal_kind).
- :func:`dispatch_widget_planner_tool` — router tool_name → handler.

Status : SCAFFOLDING (PR 2.1). Les handlers sont stubbés (raise
``NotImplementedError``) — implémentation réelle en PR 2.3 (Task #10).

⚠️ Anti-pattern à éviter : ne PAS exposer ``ask_clarification`` tant
qu'un canal aller-retour frontend n'est pas implémenté (costume sans
corps — decision brainstorm 2026-05-17).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from app.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Schemas des 8 tools exposés au LLM
# ---------------------------------------------------------------------------

WIDGET_PLANNER_TOOLS: list[dict[str, Any]] = [
    {
        "name": "peek_sql_result",
        "description": (
            "Retourne un échantillon de N lignes du résultat SQL exécuté en "
            "début de run. Les valeurs sont anonymisées (§…§ pseudo + "
            "[TYPE_N] PII) — tu vois la STRUCTURE et la cardinalité, pas le "
            "contenu réel. Utilise ce tool pour comprendre la forme avant "
            "de proposer des widgets."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Nombre max de lignes (cap 50).",
                    "default": 20,
                    "minimum": 1,
                    "maximum": 50,
                },
            },
            "required": [],
            "additionalProperties": False,
        },
    },
    {
        "name": "column_stats",
        "description": (
            "Stats déterministes (0 LLM) sur UNE colonne du résultat : "
            "type Python (str/int/float/date), pourcentage de NULL, "
            "cardinalité distincte, min/max si numérique ou date. Pas de "
            "valeurs réelles exposées."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "column": {
                    "type": "string",
                    "description": "Nom de colonne (DOIT exister dans le résultat).",
                },
            },
            "required": ["column"],
            "additionalProperties": False,
        },
    },
    {
        "name": "distinct_values",
        "description": (
            "Top N valeurs distinctes d'une colonne (anonymisées). Utile "
            "pour identifier les catégories d'une dimension avant un "
            "groupby."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "column": {
                    "type": "string",
                    "description": "Nom de colonne.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Nombre max de valeurs (cap 30).",
                    "default": 15,
                    "minimum": 1,
                    "maximum": 30,
                },
            },
            "required": ["column"],
            "additionalProperties": False,
        },
    },
    {
        "name": "aggregate_column",
        "description": (
            "Calcule une agrégation Python sur une colonne, optionnellement "
            "groupée par une autre colonne. Permet de tester une hypothèse "
            "(« la somme de montant par mois ») avant de proposer le widget. "
            "**Note sémantique sur `count`** : `count` + `column='*'` = "
            "nombre total de lignes. `count` + `column='nom_colonne'` = "
            "nombre de valeurs NON-NULL dans cette colonne (subtilité SQL). "
            "Si tu veux juste compter les lignes, utilise `column='*'`."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "column": {
                    "type": "string",
                    "description": "Colonne numérique à agréger.",
                },
                "agg": {
                    "type": "string",
                    "enum": ["sum", "avg", "min", "max", "count"],
                    "description": "Type d'agrégation.",
                },
                "group_by": {
                    "type": "string",
                    "description": (
                        "Colonne de regroupement (optionnel). Si absent, "
                        "retourne une valeur scalaire."
                    ),
                },
            },
            "required": ["column", "agg"],
            "additionalProperties": False,
        },
    },
    {
        "name": "read_existing_widgets",
        "description": (
            "Liste les widgets DÉJÀ présents dans ce dashboard (title, "
            "widget_type, intent). Permet d'éviter de proposer un widget "
            "qui existerait déjà sous une autre forme (anti-doublon)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
    },
    {
        "name": "propose_widget",
        "description": (
            "Ajoute UN widget à la liste des propositions du run en cours. "
            "Tu DOIS appeler ce tool au moins une fois avant `commit_widgets`.\n\n"
            "PARAMS par `transformation.kind` (utilise EXACTEMENT ces clés — "
            "tout autre nom de clé est rejeté) :\n"
            "- `passthrough` → `params: {}` (table brute — INTERDIT pour "
            "widget_type='chart', utiliser une recette structurée).\n"
            "- `scalar_aggregate` → `params: {column: str, agg: 'sum'|'avg'|'count'|'min'|'max'}`. "
            "Cas `count` toutes lignes : `column='*'`.\n"
            "- `scalar_from_column` → `params: {column: str, filter_col?: str, filter_value?: str|num}`. "
            "Pour extraire un rollup déjà présent dans la data (ex: ligne TOTAL).\n"
            "- `groupby` → `params: {category_col: str, value_col: str, agg: 'sum'|'avg'|'count'|'min'|'max', "
            "sort?: 'asc'|'desc'|'none', limit?: int<=100}`. Pour bar/pie/donut.\n"
            "- `groupby_2d` → `params: {category_col: str, series_col: str, value_col: str, "
            "agg: ..., sort?: ..., limit?: int<=100}`. Pour bar multi-série.\n"
            "- `time_series` → `params: {date_col: str, value_col: str, agg: ..., "
            "bucket: 'day'|'week'|'month'|'quarter'|'year'}`. Pour line/area.\n"
            "- `time_series_multi` → `params: {date_col: str, series_col: str, value_col: str, "
            "agg: ..., bucket: ..., max_series?: int 1..10}`. Pour line multi-ligne.\n"
            "- `top_n_2d` → mêmes params que `groupby_2d`. Top-N catégorie × série.\n\n"
            "Toute valeur de `column`/`category_col`/`value_col`/`date_col`/`series_col` "
            "DOIT être un nom exact présent dans `columns` du contexte (ou `*` pour `count`)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "intent": {
                    "type": "string",
                    "enum": [
                        "headline_kpi",
                        "comparison",
                        "comparison_2d",
                        "trend",
                        "trend_multi",
                        "distribution",
                        "top_ranking",
                        "detail_table",
                    ],
                },
                "widget_type": {
                    "type": "string",
                    "enum": ["chart", "kpi", "table"],
                },
                "chart_type": {
                    "type": "string",
                    "enum": ["line", "bar", "pie", "donut", "area", "scatter"],
                    "description": "Requis si widget_type=chart, sinon null.",
                },
                "transformation": {
                    "type": "object",
                    "properties": {
                        "kind": {
                            "type": "string",
                            "enum": [
                                "passthrough",
                                "scalar_aggregate",
                                "scalar_from_column",
                                "groupby",
                                "groupby_2d",
                                "time_series",
                                "time_series_multi",
                                "top_n_2d",
                            ],
                            "description": (
                                "Type de recette. Voir le cookbook params par kind "
                                "dans la description du tool."
                            ),
                        },
                        "params": {
                            "type": "object",
                            "description": (
                                "Params spécifiques au kind. Cookbook complet "
                                "des clés attendues dans la description du tool."
                            ),
                        },
                    },
                    "required": ["kind"],
                    "additionalProperties": False,
                },
                "title": {
                    "type": "string",
                    "description": "Titre court (max 80 chars).",
                    "maxLength": 80,
                },
                "col_span": {
                    "type": "integer",
                    "enum": [3, 4, 6, 8, 12],
                    "description": "Largeur sur grille 12 colonnes.",
                },
                "render_spec": {
                    "type": "object",
                    "description": (
                        "Choix de présentation (number_format, unit, "
                        "x_label, y_label, insight). Voir RenderSpec."
                    ),
                },
                "drill_column": {
                    "type": "string",
                    "description": "Colonne de drill-down (optionnel).",
                },
            },
            "required": ["intent", "widget_type", "transformation", "title", "col_span"],
            "additionalProperties": False,
        },
    },
    {
        "name": "commit_widgets",
        "description": (
            "Finalise le run avec les widgets proposés. Requiert au moins "
            "1 appel préalable à `propose_widget`. Termine la boucle "
            "tool-use."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
    },
    {
        "name": "abort",
        "description": (
            "Termine le run SANS produire de widget — utilise quand le SQL "
            "ne retourne rien d'exploitable (0 ligne, schéma absurde, "
            "ambiguïté irréductible). Doit fournir une raison courte qui "
            "sera loguée."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "description": "Raison courte (max 200 chars).",
                    "maxLength": 200,
                },
            },
            "required": ["reason"],
            "additionalProperties": False,
        },
    },
]


# Validation rapide au boot — détecte les erreurs de saisie schemas dès l'import
# (mieux qu'au 1er run en prod où ça crasherait l'API LLM avec un message obscur).
def _self_check_tools() -> None:
    names = set()
    for tool in WIDGET_PLANNER_TOOLS:
        if not isinstance(tool.get("name"), str) or not tool["name"]:
            raise RuntimeError(f"Tool sans nom valide : {tool!r}")
        if tool["name"] in names:
            raise RuntimeError(f"Tool dupliqué : {tool['name']}")
        names.add(tool["name"])
        if not isinstance(tool.get("input_schema"), dict):
            raise RuntimeError(f"Tool {tool['name']} sans input_schema")
        schema = tool["input_schema"]
        if schema.get("type") != "object":
            raise RuntimeError(f"Tool {tool['name']} input_schema.type != 'object'")
        # Garde-fou contre les typos dans `required` (review adversariale
        # 2026-05-17 LOW #2) : si on déclare `required: ["colum"]` au lieu
        # de `"column"`, l'API LLM crashera à runtime ET le LLM ne saura
        # jamais appeler le tool correctement. On fail à l'import au lieu
        # qu'au 1er run prod.
        properties = schema.get("properties") or {}
        for required_key in schema.get("required") or []:
            if required_key not in properties:
                raise RuntimeError(
                    f"Tool {tool['name']}: clé '{required_key}' dans "
                    f"required absente des properties — typo probable."
                )


_self_check_tools()


# ---------------------------------------------------------------------------
# Contexte partagé entre handlers
# ---------------------------------------------------------------------------


@dataclass
class WidgetPlannerContext:
    """État partagé entre les handlers de tools et la boucle agent.

    Pattern calqué sur :class:`app.services.ai.copilot_tools.CopilotContext`.
    """

    # Inputs initiaux du run
    sql: str
    user_hint: Optional[str] = None
    dashboard_id: Optional[int] = None
    user_id: Optional[int] = None
    run_id: str = ""

    # Données SQL pré-exécutées (UNE FOIS au début du run, partagées entre tools)
    columns: list[str] = field(default_factory=list)
    rows: list[list[Any]] = field(default_factory=list)
    profile: dict[str, Any] = field(default_factory=dict)
    real_row_count: int = 0

    # Widgets existants dans le dashboard (memory recompute — pas de migration BDD)
    existing_widgets: list[dict[str, Any]] = field(default_factory=list)

    # Proposals accumulées via propose_widget (committées par commit_widgets)
    proposals: list[dict[str, Any]] = field(default_factory=list)

    # Anonymisation — attachés au context pour que les handlers puissent
    # dé-anonymiser avant exécution puis ré-anonymiser au retour.
    pseudonymizer: Optional[Any] = None
    pii_mapping: dict[str, str] = field(default_factory=dict)
    pii_counters: dict[str, int] = field(default_factory=dict)

    # Terminal flag — set par commit_widgets / abort → boucle s'arrête.
    terminal_kind: Optional[str] = None  # "commit" | "abort" | None
    abort_reason: Optional[str] = None

    # Compteur de turns pour DoS guard (MAX_TOOL_CALLS).
    turn_count: int = 0


# ---------------------------------------------------------------------------
# Dispatch — handlers stubbés en PR 2.1, implémentés en PR 2.3
# ---------------------------------------------------------------------------

ToolHandler = Callable[[dict, WidgetPlannerContext], Awaitable[dict]]


# ─────────────────────────────────────────────────────────────────────
# Handlers réels (PR 2.3)
# ─────────────────────────────────────────────────────────────────────
#
# Tous les handlers reçoivent en entrée un ``ctx`` pré-rempli par la
# boucle agent (PR 2.4) : ``ctx.rows + ctx.columns + ctx.profile`` sont
# le résultat SQL exécuté UNE FOIS en début de run. Les handlers
# opèrent en mémoire, JAMAIS de ré-exécution SQL.
#
# Les valeurs renvoyées au LLM sont systématiquement passées par
# ``ctx.pseudonymizer.anonymize`` — règle anti-leak invariant. Si
# ``ctx.pseudonymizer`` est None (mode test sans user_id), les valeurs
# partent en clair (caller responsabilité).

# Caps DoS centralisés dans ``limits.py`` (fix C3 review globale 2026-05-18).
# Avant : éparpillés sur 3 fichiers. Maintenant : single source of truth +
# assertion alignement schema JSON au boot.
from app.services.dashboard.widget_planner_agent.limits import (
    MAX_ABORT_REASON_LEN as _MAX_ABORT_REASON_LEN,
    MAX_DISTINCT_VALUES as _MAX_DISTINCT_VALUES,
    MAX_PEEK_ROWS as _MAX_PEEK_ROWS,
    MAX_TITLE_LEN as _MAX_TITLE_LEN,
)

# Whitelist + caps render_spec (fix MEDIUM #4 review adversariale 2026-05-17).
# Reject toute clé inconnue + cap longueur sur les strings affichées au user.
_RENDER_SPEC_STRING_CAPS: dict[str, int] = {
    "number_format": 20,
    "unit": 10,
    "x_label": 40,
    "y_label": 40,
    "insight": 280,
    "color_hint": 20,
}
# Liste fermée des number_format autorisés (cf. designer.py:_VALID_NUMBER_FORMATS).
_ALLOWED_NUMBER_FORMATS = frozenset(
    {"number", "integer", "decimal", "currency_eur", "percent", "none"}
)

# Cohérence widget_type ↔ transformation.kind (fix HIGH #L2 review
# adversariale finale 2026-05-18 + fix dashboard graph creation 2026-05-22) :
# sans ce check, un LLM peut proposer widget_type='kpi' + transformation=
# 'time_series' (incohérent visuel). Pour widget_type='chart' ET 'kpi',
# `passthrough` est NOW explicitement interdit (avant : autorisé silencieusement
# → renderer reçoit `{type:'table'}` au lieu de la forme attendue → widget vide).
# Le check `_handle_propose_widget` retourne une erreur prescriptive AVANT
# d'arriver ici, mais on garde la cohérence défense-en-profondeur si la
# table est étendue dans le futur.
_COMPATIBLE_RECIPES: dict[str, frozenset[str]] = {
    "kpi": frozenset({"scalar_aggregate", "scalar_from_column"}),
    "chart": frozenset({"groupby", "groupby_2d", "time_series", "time_series_multi", "top_n_2d"}),
    "table": frozenset({"passthrough", "groupby"}),
}

# Schéma des params attendus par kind — source de vérité pour les messages
# d'erreur prescriptifs (fix dashboard graph creation 2026-05-22 + adversarial
# review fix F1/F2/F3 : aliases + value_col conditionnel + agg optional).
# Avant : le LLM voyait juste `{"params": {"type": "object"}}` dans le tool
# schema et devait deviner les noms de clés → boucle de rejets → passthrough.
#
# Chaque entrée :
# - ``required`` : clés OBLIGATOIRES dans params (sans condition)
# - ``required_unless_count`` : clés requises SAUF si agg='count' (validate_recipe
#   défaut value_col facultatif quand agg=count, cf. transformations.py:687-691)
# - ``optional`` : clés autorisées en plus (incluant agg si default 'sum' OK)
# - ``aliases`` : nom_alternatif → nom_canonique. validate_recipe reconnaît :
#   category↔category_col, value↔value_col, x_col↔date_col, y_col↔value_col,
#   value_col↔column pour scalar_aggregate / scalar_from_column.
# - ``column_refs`` : clés (canoniques) dont la valeur DOIT être une colonne
#   de ctx.columns (sauf wildcard `*` pour scalar_aggregate.count)
# - ``wildcard_keys`` : clés où `value='*'` est valide (count toutes lignes)
# - ``example`` : exemple textuel pour le message d'erreur.
#
# Aligné sur ``validate_recipe`` (transformations.py:635+) — invariant
# vérifié au boot par ``_self_check_expected_params``.
_EXPECTED_PARAMS: dict[str, dict[str, Any]] = {
    "passthrough": {
        "required": (),
        "required_unless_count": (),
        "optional": (),
        "aliases": {},
        "column_refs": (),
        "wildcard_keys": (),
        "example": "{kind: 'passthrough', params: {}}",
    },
    "scalar_aggregate": {
        # validate_recipe: column est requis sauf si agg=count (where col defaults '*')
        "required": (),
        "required_unless_count": ("column",),
        # agg défaut 'sum' (transformations.py:669) → optional
        "optional": ("label", "agg"),
        "aliases": {"value_col": "column"},
        "column_refs": ("column",),
        "wildcard_keys": ("column",),  # column='*' valide pour count
        "example": (
            "{kind: 'scalar_aggregate', params: {column: '<nom_colonne>', "
            "agg: 'sum'}}  (utilise column='*' pour count toutes lignes)"
        ),
    },
    "scalar_from_column": {
        "required": ("column",),
        "required_unless_count": (),
        "optional": ("label", "filter_col", "filter_value"),
        "aliases": {"value_col": "column"},
        "column_refs": ("column", "filter_col"),
        "wildcard_keys": (),
        "example": "{kind: 'scalar_from_column', params: {column: '<nom_colonne>'}}",
    },
    "groupby": {
        "required": ("category_col",),
        "required_unless_count": ("value_col",),
        "optional": ("agg", "sort", "limit", "label"),
        "aliases": {"category": "category_col", "value": "value_col"},
        "column_refs": ("category_col", "value_col"),
        "wildcard_keys": (),
        "example": (
            "{kind: 'groupby', params: {category_col: '<dim>', "
            "value_col: '<mesure>', agg: 'sum'}}"
        ),
    },
    "groupby_2d": {
        "required": ("category_col", "series_col"),
        "required_unless_count": ("value_col",),
        "optional": ("agg", "sort", "limit"),
        "aliases": {},
        "column_refs": ("category_col", "series_col", "value_col"),
        "wildcard_keys": (),
        "example": (
            "{kind: 'groupby_2d', params: {category_col: '<dim1>', "
            "series_col: '<dim2>', value_col: '<mesure>', agg: 'sum'}}"
        ),
    },
    "top_n_2d": {
        "required": ("category_col", "series_col"),
        "required_unless_count": ("value_col",),
        "optional": ("agg", "sort", "limit"),
        "aliases": {},
        "column_refs": ("category_col", "series_col", "value_col"),
        "wildcard_keys": (),
        "example": (
            "{kind: 'top_n_2d', params: {category_col: '<dim1>', "
            "series_col: '<dim2>', value_col: '<mesure>', agg: 'sum', limit: 10}}"
        ),
    },
    "time_series": {
        "required": ("date_col",),
        "required_unless_count": ("value_col",),
        "optional": ("agg", "bucket", "label"),
        "aliases": {"x_col": "date_col", "y_col": "value_col"},
        "column_refs": ("date_col", "value_col"),
        "wildcard_keys": (),
        "example": (
            "{kind: 'time_series', params: {date_col: '<colonne_date>', "
            "value_col: '<mesure>', agg: 'sum', bucket: 'month'}}"
        ),
    },
    "time_series_multi": {
        "required": ("date_col", "series_col"),
        "required_unless_count": ("value_col",),
        "optional": ("agg", "bucket", "max_series"),
        "aliases": {},
        "column_refs": ("date_col", "series_col", "value_col"),
        "wildcard_keys": (),
        "example": (
            "{kind: 'time_series_multi', params: {date_col: '<colonne_date>', "
            "series_col: '<dim>', value_col: '<mesure>', agg: 'sum', "
            "bucket: 'month'}}"
        ),
    },
}


def _self_check_expected_params() -> None:
    """Garde-fou boot : ``_EXPECTED_PARAMS`` couvre exactement les kinds que
    ``validate_recipe`` accepte. Si quelqu'un ajoute un kind à
    ``VALID_TRANSFORM_KINDS`` sans documenter ses params ici → fail à
    l'import au lieu qu'au 1er rejet en prod (LLM bouclerait à nouveau).
    """
    from app.services.dashboard.widget_planner.transformations import (
        VALID_TRANSFORM_KINDS,
    )

    documented = set(_EXPECTED_PARAMS.keys())
    if documented != VALID_TRANSFORM_KINDS:
        missing = VALID_TRANSFORM_KINDS - documented
        extra = documented - VALID_TRANSFORM_KINDS
        raise RuntimeError(
            f"_EXPECTED_PARAMS désaligné avec VALID_TRANSFORM_KINDS. "
            f"Kinds manquants : {missing}. Kinds en trop : {extra}."
        )
    # Cross-check : l'enum du tool schema doit aussi être aligné.
    for tool in WIDGET_PLANNER_TOOLS:
        if tool["name"] != "propose_widget":
            continue
        kind_enum = tool["input_schema"]["properties"]["transformation"]["properties"]["kind"][
            "enum"
        ]
        if set(kind_enum) != VALID_TRANSFORM_KINDS:
            raise RuntimeError(
                f"Tool schema propose_widget.transformation.kind.enum "
                f"désaligné avec VALID_TRANSFORM_KINDS. "
                f"Tool: {set(kind_enum)}. Runtime: {VALID_TRANSFORM_KINDS}."
            )


_self_check_expected_params()

# Pattern partagé pour strip control chars (fix CC1+CC2 review globale
# 2026-05-18). Avant : pattern dupliqué 3× dans ce module + None mort code.
from app.services.dashboard.widget_planner_agent._sanitize import (
    strip_control as _strip_control,
)


def _sanitize_render_spec(raw: Any) -> dict[str, Any]:
    """Whitelist + caps + strip control chars sur le ``render_spec`` LLM.

    Defense-in-depth contre prompt-injection / DoS via insight géant —
    fix MEDIUM #4 review adversariale 2026-05-17. Tout champ inconnu est
    silencieusement droppé (le LLM apprend par convention que seuls les
    champs documentés passent).
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for key, cap in _RENDER_SPEC_STRING_CAPS.items():
        val = raw.get(key)
        if not isinstance(val, str):
            continue
        # Strip control chars partagé (fix CC1) + strip whitespace + cap.
        clean = _strip_control(val).strip()[:cap]
        if not clean:
            continue
        # number_format restrict to closed enum
        if key == "number_format" and clean not in _ALLOWED_NUMBER_FORMATS:
            continue
        out[key] = clean
    return out


def _anonymize_value(value: Any, ctx: WidgetPlannerContext) -> Any:
    """Anonymise une valeur arbitraire via le pseudonymizer du ctx.

    **Couche 1 uniquement** (pseudonymizer user-scoped §…§). Pour la
    défense complète qui inclut aussi la couche PII regex (emails, SIRET,
    IBAN, téléphones), utiliser :func:`_anonymize_full`.

    No-op si pseudonymizer absent (mode test). Renvoie ``value`` tel quel
    pour les types non-string (int, float, bool, None) — le pseudonymizer
    fait ce check en interne mais on raccourcit ici pour perf.
    """
    if ctx.pseudonymizer is None:
        return value
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return ctx.pseudonymizer.anonymize(value)


def _anonymize_full(value: Any, ctx: WidgetPlannerContext) -> Any:
    """Anonymisation DEFENSE-IN-DEPTH : pseudonymizer + PII regex layer.

    Fix SEC1 review globale 2026-05-18 : avant cette PR, seul
    ``_handle_aggregate_column`` appliquait la couche PII regex. Les
    handlers de read (`peek_sql_result`, `column_stats`, `distinct_values`)
    n'appliquaient QUE le pseudonymizer scoped → un email/SIRET/IBAN
    présent dans une row mais pas dans le state user anonymization_terms
    leak cleartext au LLM.

    Ordre des couches :
    1. Pseudonymizer user-scoped (§DUPONT§) — couvre les noms propres
       listés par l'utilisateur via /data/privacy.
    2. PII regex (`[EMAIL_N]`, `[SIRET_N]`…) — couvre les patterns
       identifiables sans nécessiter de listing user.

    Le mapping PII (``ctx.pii_mapping`` + ``ctx.pii_counters``) est
    PARTAGÉ cross-payload : les mêmes valeurs réelles retrouvent le même
    token entre les différents handlers (cohérent avec
    :mod:`copilot_agent`). Cela permet aussi au restore final
    (côté handler système) de remonter les vraies valeurs.
    """
    # Couche 1 : pseudonymizer scoped.
    pseudo_anonymized = _anonymize_value(value, ctx)
    # Couche 2 : PII regex (emails/SIRET/IBAN/téléphones/etc.).
    # No-op silencieux si pseudo_anonymized n'est ni dict/list/str.
    if pseudo_anonymized is None:
        return None
    try:
        from app.services.anonymization.proxy import (
            _pii_anonymize_recursive as _pii_anon_walk,
        )

        return _pii_anon_walk(pseudo_anonymized, ctx.pii_mapping, ctx.pii_counters)
    except Exception:  # noqa: BLE001
        # Non-bloquant : si la couche PII fail, on garde au moins le
        # pseudonymizer. Log + continue (cohérent avec
        # _handle_aggregate_column fix PR 2.6).
        logger.warning(
            "_anonymize_full: PII regex layer a levé, retour anonymisé "
            "uniquement par pseudonymizer",
            exc_info=True,
        )
        return pseudo_anonymized


def _col_index_or_none(ctx: WidgetPlannerContext, column: str) -> Optional[int]:
    """Retourne l'index 0-based de ``column`` dans ``ctx.columns`` ou None."""
    try:
        return ctx.columns.index(column)
    except ValueError:
        return None


async def _handle_peek_sql_result(input_: dict, ctx: WidgetPlannerContext) -> dict:
    """Retourne un échantillon de rows anonymisés (cap 50).

    Inputs :
        ``limit`` (int 1..50, défaut 20)

    Defense-in-depth : cap forcé même si le LLM envoie ``limit > 50``
    (schema strict d'Anthropic normalement bloque, mais OpenAI-compat
    permissif peut laisser passer).
    """
    limit_raw = input_.get("limit", 20)
    try:
        limit = max(1, min(int(limit_raw), _MAX_PEEK_ROWS))
    except (TypeError, ValueError):
        limit = 20

    sample = ctx.rows[:limit]
    return {
        "columns": list(ctx.columns),
        # Fix SEC1 review globale 2026-05-18 : utilise _anonymize_full
        # (pseudo + PII regex) au lieu de _anonymize_value (pseudo seul).
        # Sans ça, un email/SIRET/IBAN dans une row leak cleartext au LLM.
        "rows": _anonymize_full(sample, ctx),
        "total_rows": ctx.real_row_count,
        "shown_rows": len(sample),
    }


async def _handle_column_stats(input_: dict, ctx: WidgetPlannerContext) -> dict:
    """Stats déterministes d'UNE colonne (zero LLM).

    Inputs :
        ``column`` (str, obligatoire) — doit exister dans ctx.columns

    Lit ``ctx.profile`` pré-calculé par :func:`profile_columns` (PR 2.4).
    Retourne ``{type, null_pct, cardinality, min, max}`` — pas de
    valeurs réelles, juste la structure.
    """
    column = input_.get("column")
    if not isinstance(column, str) or not column:
        return {"error": "Le paramètre 'column' est obligatoire."}

    cols_profile = (ctx.profile or {}).get("columns") or []
    found = next((c for c in cols_profile if c.get("name") == column), None)
    if found is None:
        return {
            "error": (
                f"Colonne '{column}' absente du résultat. "
                f"Colonnes disponibles : {list(ctx.columns)}."
            ),
        }
    # Champs structurels (kind/null_pct/cardinality) — non-anonymisables.
    # ``type`` a un fallback "unknown" pour ne pas envoyer None ambigu au LLM
    # (review adversariale 2026-05-17 MEDIUM #5).
    out: dict[str, Any] = {
        "name": found.get("name"),
        "type": found.get("kind") or found.get("type") or "unknown",
        "null_pct": found.get("null_pct"),
        "cardinality": found.get("cardinality"),
    }
    # min/max numerics : passés par _anonymize_full (pseudo + PII regex).
    # Fix SEC1 review globale 2026-05-18 : le pseudonymizer scoped seul
    # ratait les patterns identifiables (matricule numérique encodé en
    # string, email dans un champ "label"). Le contrat anti-leak du
    # module (commentaire en haut de fichier) DOIT tenir uniformément.
    numeric_stats = found.get("numeric_stats")
    if isinstance(numeric_stats, dict):
        out["min"] = _anonymize_full(numeric_stats.get("min"), ctx)
        out["max"] = _anonymize_full(numeric_stats.get("max"), ctx)
        out["mean"] = _anonymize_full(numeric_stats.get("mean"), ctx)
    # date_range : valeurs ISO ("2026-01-15") — DOIT passer par les 2
    # couches (une date métier peut être confidentielle ; PII regex
    # catch les patterns de dates anormales).
    date_range = found.get("date_range")
    if isinstance(date_range, dict):
        out["date_min"] = _anonymize_full(date_range.get("min"), ctx)
        out["date_max"] = _anonymize_full(date_range.get("max"), ctx)
    return out


async def _handle_distinct_values(input_: dict, ctx: WidgetPlannerContext) -> dict:
    """Top N valeurs distinctes anonymisées (cap 30).

    Inputs :
        ``column`` (str, obligatoire)
        ``limit`` (int 1..30, défaut 15)
    """
    column = input_.get("column")
    if not isinstance(column, str) or not column:
        return {"error": "Le paramètre 'column' est obligatoire."}
    idx = _col_index_or_none(ctx, column)
    if idx is None:
        return {
            "error": (f"Colonne '{column}' absente. Disponibles : {list(ctx.columns)}."),
        }
    try:
        limit = max(1, min(int(input_.get("limit", 15)), _MAX_DISTINCT_VALUES))
    except (TypeError, ValueError):
        limit = 15

    # Collecte les valeurs uniques (préserve l'ordre d'apparition).
    seen: set = set()
    distinct: list[Any] = []
    for row in ctx.rows:
        if idx >= len(row):
            continue
        v = row[idx]
        if v is None:
            continue
        # set() ne supporte pas les types non-hashables (list/dict). On
        # convertit en str pour la dedup, mais on retourne la valeur
        # originelle (apres anonymisation).
        key = v if isinstance(v, (str, int, float, bool, tuple)) else str(v)
        if key in seen:
            continue
        seen.add(key)
        distinct.append(v)
        if len(distinct) >= limit:
            break

    return {
        "column": column,
        # Fix SEC1 review globale 2026-05-18 : _anonymize_full (pseudo +
        # PII regex). Sans ça, distinct_values sur une colonne "email"
        # leak les adresses cleartext au LLM.
        "values": _anonymize_full(distinct, ctx),
        "count": len(distinct),
        "capped": len(distinct) >= limit,
    }


async def _handle_aggregate_column(input_: dict, ctx: WidgetPlannerContext) -> dict:
    """Agrège une colonne, optionnellement groupée. Utilise apply_transformation
    pour réutiliser exactement la même logique que le pipeline 3-shot.

    Inputs :
        ``column`` (str, obligatoire)
        ``agg`` (sum/avg/min/max/count, obligatoire)
        ``group_by`` (str, optionnel) — si fourni → résultat groupé

    Output : ``{value, label}`` pour scalar OU ``{labels, datasets}`` pour
    groupé. Valeurs anonymisées.
    """
    from app.services.dashboard.widget_planner.transformations import (
        TransformationError,
        apply_transformation,
    )

    column = input_.get("column")
    agg = input_.get("agg")
    group_by = input_.get("group_by")

    if not isinstance(column, str) or not column:
        return {"error": "Le paramètre 'column' est obligatoire."}
    if agg not in ("sum", "avg", "min", "max", "count"):
        return {"error": f"agg invalide : {agg!r}. Attendu sum/avg/min/max/count."}
    # Fix S4 review globale 2026-05-18 : rejeter explicitement
    # column="*" + group_by (combinaison sans sémantique claire,
    # apply_transformation lèverait sur l'index "*" → loop LLM sur error).
    if column == "*" and isinstance(group_by, str) and group_by:
        return {
            "error": (
                "column='*' n'est valide qu'avec agg='count' SANS group_by. "
                "Pour grouper, choisir une vraie colonne (count(non-null) sur "
                f"cette colonne). Disponibles : {list(ctx.columns)}."
            ),
        }
    if _col_index_or_none(ctx, column) is None and column != "*":
        return {
            "error": (f"Colonne '{column}' absente. Disponibles : {list(ctx.columns)}."),
        }
    if isinstance(group_by, str) and group_by:
        if _col_index_or_none(ctx, group_by) is None:
            return {
                "error": (
                    f"Colonne group_by '{group_by}' absente. " f"Disponibles : {list(ctx.columns)}."
                ),
            }
        recipe = {
            "kind": "groupby",
            "params": {
                "category_col": group_by,
                "value_col": column,
                "agg": agg,
                "limit": 20,  # garde-fou : 20 buckets max au LLM
            },
        }
    else:
        recipe = {
            "kind": "scalar_aggregate",
            "params": {"column": column, "agg": agg},
        }

    try:
        result = apply_transformation(ctx.columns, ctx.rows, recipe)
    except TransformationError as exc:
        return {"error": f"Échec d'agrégation : {exc}"}
    # Anti-leak : utilise _anonymize_full qui chaîne pseudo + PII regex.
    # Couvre les labels DÉRIVÉS (ex: groupby concat « nom + date », bucket
    # time_series « 2026-01 ») hors scope_tokens via la couche PII regex.
    # Fix SEC1 review globale 2026-05-18 : helper unifié au lieu de
    # duplication inline (cohérent avec peek/distinct/column_stats).
    return _anonymize_full(result, ctx)


async def _handle_read_existing_widgets(_input: dict, ctx: WidgetPlannerContext) -> dict:
    """Liste FRESH des widgets du dashboard (re-fetch BDD à chaque appel).

    Fix LOG7 review globale 2026-05-18 : avant cette PR, retournait
    ``ctx.existing_widgets`` snapshot du début du run. Si l'agent tourne
    60s et qu'un autre onglet user supprime un widget pendant ce temps,
    le LLM continuait à voir le widget supprimé → propose un widget
    "non redondant" qui est en fait nouveau. Le nom du tool suggère
    "live read" — la réalité doit suivre.

    Defense-in-depth :
    - Re-fetch via :func:`read_existing_widgets_summary` (ownership check)
    - Anonymisation systématique des titres avant retour LLM (cohérent
      avec ``agent.py`` ligne 209-213 qui anonymise le snapshot initial)
    - Le coût supplémentaire (1 query BDD par appel tool) est négligeable
      vs le coût d'un widget agent dupliqué.

    Fallback : si la BDD est indisponible OU si dashboard_id/user_id
    sont None (tests), on retourne ``ctx.existing_widgets`` (snapshot
    initial) plutôt que erreur — le LLM continue à pouvoir raisonner.
    """
    from app.services.dashboard.widget_planner_agent.memory import (
        read_existing_widgets_summary,
    )

    if ctx.dashboard_id is None or ctx.user_id is None:
        # Mode test/script sans contexte BDD : retourne le snapshot.
        return {
            "widgets": list(ctx.existing_widgets),
            "count": len(ctx.existing_widgets),
            "fresh": False,
        }

    try:
        fresh = await read_existing_widgets_summary(ctx.dashboard_id, ctx.user_id)
    except Exception:  # noqa: BLE001
        # Fallback non-bloquant : retourne le snapshot initial.
        logger.warning(
            "read_existing_widgets: re-fetch BDD a levé, retour snapshot initial",
            exc_info=True,
        )
        return {
            "widgets": list(ctx.existing_widgets),
            "count": len(ctx.existing_widgets),
            "fresh": False,
        }

    # Anonymisation cohérente avec agent.py:209-213 (fix HIGH #1 PR 2.4).
    # Sans ça, un titre cleartext leak via tool_result au LLM.
    if ctx.pseudonymizer is not None and len(ctx.pseudonymizer) > 0:
        for w in fresh:
            if isinstance(w.get("title"), str):
                w["title"] = ctx.pseudonymizer.anonymize_text(w["title"])
    return {
        "widgets": fresh,
        "count": len(fresh),
        "fresh": True,
    }


# Cap appliqué aux user-controlled echoes dans le diagnostic (fix adversarial
# review F5/F18 2026-05-22). Bornes contre prompt-injection / DoS denial-of-wallet
# si un LLM hostile envoie des clés ou valeurs de 100KB.
_DIAGNOSTIC_VALUE_CAP = 80


def _safe_repr_for_llm(value: Any) -> str:
    """``repr(value)`` neutralisé pour echo LLM : strip control chars + cap."""
    return _strip_control(repr(value), cap=_DIAGNOSTIC_VALUE_CAP)


def _safe_key_for_llm(key: Any) -> str:
    """Clé de dict neutralisée : strip control chars + cap. Conserve `str`."""
    return _strip_control(str(key), cap=_DIAGNOSTIC_VALUE_CAP)


def _safe_columns_for_llm(ctx: WidgetPlannerContext) -> list[str]:
    """Anonymise ``ctx.columns`` avant emission au LLM via le diagnostic
    (fix adversarial review F7 2026-05-22).

    Le diagnostic embed ``ctx.columns`` dans son message. Normalement ce sont
    des noms schéma (Niveau 1, non sensibles), mais sous threat model les
    aliases SQL (``SELECT col AS '<PII>'``) peuvent injecter de la PII dans
    les noms. On applique le pseudonymizer scoped (mêmes invariants que
    ``_anonymize_value``).
    """
    if ctx.pseudonymizer is None:
        return list(ctx.columns)
    return [_anonymize_value(c, ctx) if isinstance(c, str) else c for c in ctx.columns]


def _resolve_aliases(params: dict, expected: dict) -> dict:
    """Renomme les clés alias vers leurs équivalents canoniques.

    ``validate_recipe`` accepte des aliases (cf. transformations.py:666,679,
    687,706,714) — sans cette résolution, le diagnostic considérerait
    ``category='client'`` comme une clé inconnue alors que ``validate_recipe``
    l'accepte comme synonyme de ``category_col``. Fix adversarial review F1.

    Si une clé canonique ET son alias sont fournis, la canonique gagne (même
    comportement que ``validate_recipe`` via le ``or`` chain).
    """
    aliases = expected.get("aliases") or {}
    if not aliases:
        return dict(params)
    out: dict[str, Any] = dict(params)
    for alias, canonical in aliases.items():
        if alias in params and canonical not in out:
            out[canonical] = params[alias]
    return out


def _diag_shape(transformation: Any) -> Optional[str]:
    """Vérifie que ``transformation`` est un dict {kind, params}. Retourne
    un message d'erreur si la shape est cassée, sinon ``None``."""
    if not isinstance(transformation, dict):
        return (
            f"transformation doit être un objet `{{kind, params}}`. Reçu : "
            f"{type(transformation).__name__}. Exemple : {{kind: 'groupby', "
            f"params: {{category_col: '<dim>', value_col: '<mesure>', "
            f"agg: 'sum'}}}}."
        )
    return None


def _diag_keys(canonical: dict, raw: dict, expected: dict) -> list[str]:
    """Détecte clés requises manquantes (avec exception ``count``) et clés
    inconnues. Retourne une liste de fragments d'erreur.

    Fix adversarial review F1/F2/F3 : (1) tient compte des aliases résolus
    pour le check missing (2) ``agg`` est dans ``optional`` (default 'sum')
    (3) ``value_col`` est conditionnellement requis selon ``agg=count``.
    """
    required = set(expected["required"])
    optional = set(expected["optional"])
    cond_required = set(expected.get("required_unless_count") or ())
    aliases = expected.get("aliases") or {}
    allowed_input = required | optional | cond_required | set(aliases.keys())

    # Resolved (canonical) keys → check missing
    canon_keys = set(canonical.keys())
    missing = required - canon_keys

    # Conditionnellement requis : ajouter au missing si agg != 'count'
    agg_value = str(canonical.get("agg") or "").lower()
    if agg_value != "count":
        missing |= cond_required - canon_keys

    # Unknown : clés brutes (post-LLM, avant alias resolution) qui ne sont
    # ni canoniques autorisées ni aliases connues.
    unknown = set(raw.keys()) - allowed_input

    issues: list[str] = []
    if missing:
        issues.append(
            f"Clé(s) requise(s) manquante(s) : " f"{sorted(_safe_key_for_llm(k) for k in missing)}."
        )
    if unknown:
        issues.append(
            f"Clé(s) inconnue(s) : "
            f"{sorted(_safe_key_for_llm(k) for k in unknown)} "
            f"(autorisées pour ce kind : "
            f"{sorted(_safe_key_for_llm(k) for k in allowed_input) or '∅'})."
        )
    return issues


def _diag_columns(canonical: dict, expected: dict, columns_visible: list[str]) -> list[str]:
    """Détecte les références de colonnes invalides (non-str, vides, ou
    absentes de ``columns_visible``).

    Fix adversarial review F4/F8 : (1) ``wildcard_keys`` autorise `*` seulement
    pour les kinds qui en font sens (scalar_aggregate.column) (2) un non-string
    n'est plus silencieusement skip — il est signalé avec son type.
    """
    wildcard_keys = set(expected.get("wildcard_keys") or ())
    bad: list[str] = []
    for key in expected["column_refs"]:
        if key not in canonical:
            continue
        val = canonical[key]
        if val is None:
            continue
        if not isinstance(val, str):
            type_info = type(val).__name__
            bad.append(f"{key}={_safe_repr_for_llm(val)} " f"(attendu chaîne, reçu {type_info})")
            continue
        v = val.strip()
        if not v:
            continue
        if v == "*" and key in wildcard_keys:
            continue
        if v not in columns_visible:
            bad.append(f"{key}={_safe_repr_for_llm(val)}")
    if bad:
        return [f"Référence(s) de colonne inexistante(s) ou invalide(s) : {bad}."]
    return []


def _diag_enums(canonical: dict, expected: dict) -> list[str]:
    """Détecte les valeurs hors enum pour agg/bucket/sort.

    Defense-in-depth : si LLM envoie ``agg={'op':'sum'}`` (non-string), on le
    signale ; si valeur hors enum, idem. Cap appliqué.
    """
    from app.services.dashboard.widget_planner.transformations import (
        VALID_AGGS,
        VALID_BUCKETS,
        VALID_SORTS,
    )

    allowed_keys = (
        set(expected["required"])
        | set(expected["optional"])
        | set(expected.get("required_unless_count") or ())
    )
    enum_errors: list[str] = []

    def _check(key: str, valid_set: set) -> None:
        if key not in allowed_keys or key not in canonical:
            return
        raw_val = canonical[key]
        if raw_val is None:
            return
        if not isinstance(raw_val, str):
            enum_errors.append(
                f"{key}={_safe_repr_for_llm(raw_val)} "
                f"(attendu chaîne, reçu {type(raw_val).__name__})"
            )
            return
        lower = raw_val.strip().lower()
        if lower and lower not in valid_set:
            enum_errors.append(f"{key}={_safe_repr_for_llm(raw_val)} (attendu {sorted(valid_set)})")

    _check("agg", VALID_AGGS)
    _check("bucket", VALID_BUCKETS)
    _check("sort", VALID_SORTS)
    if enum_errors:
        return [f"Valeur(s) hors enum : {enum_errors}."]
    return []


def _diagnose_recipe_failure(transformation: Any, ctx: WidgetPlannerContext) -> str:
    """Diagnostique POURQUOI ``validate_recipe`` a retourné ``None`` pour
    produire un message d'erreur prescriptif au LLM (fix dashboard graph
    creation 2026-05-22, raffiné par review adversariale).

    Avant ce helper, le message générique « transformation invalide ou
    colonne référencée inexistante » laissait le LLM penser que c'était
    un problème de colonne — il cherchait d'autres colonnes au lieu de
    corriger les CLÉS de ``params``. Vu en boucle dans llm_log.md
    (~99566-100735) : le LLM invente ``group_column/measure_column``,
    ``dimensions/measures``, etc.

    Le diagnostic identifie le cas concret en 4 couches (split en helpers
    testables isolément) :
    1. ``_diag_shape`` : transformation est-elle bien un dict {kind, params} ?
    2. ``_diag_keys`` : quelles clés sont requises/inconnues (aliases résolus,
       value_col conditionnel à agg=count) ?
    3. ``_diag_columns`` : les références de colonne pointent-elles vers
       ctx.columns (wildcards autorisés seulement pour scalar_aggregate.column) ?
    4. ``_diag_enums`` : agg/bucket/sort dans leurs enums ?

    Retourne TOUJOURS un message prescriptif non-vide avec :
    1. Cause(s) précise(s) (un fragment par couche en échec)
    2. Exemple textuel correct pour le kind concerné
    3. Liste des colonnes disponibles ANONYMISÉES si pseudonymizer dispo

    Defense-in-depth :
    - Ne suppose rien sur la structure (None / list / str / dict mal formé).
    - User-controlled echoes (clés, valeurs) sont strip_control + cap-bornés.
    - ctx.columns passe par _safe_columns_for_llm avant emission.
    """
    from app.services.dashboard.widget_planner.transformations import (
        VALID_TRANSFORM_KINDS,
    )

    shape_err = _diag_shape(transformation)
    if shape_err is not None:
        return f"{shape_err} " f"Colonnes disponibles : {_safe_columns_for_llm(ctx)}."

    kind = transformation.get("kind")
    if not isinstance(kind, str) or kind not in VALID_TRANSFORM_KINDS:
        return (
            f"transformation.kind={_safe_repr_for_llm(kind)} invalide. "
            f"Attendu un de : {sorted(VALID_TRANSFORM_KINDS)}. Voir le "
            f"cookbook des params dans la description du tool `propose_widget`."
        )

    expected = _EXPECTED_PARAMS.get(kind)
    if expected is None:  # Garde-fou : _self_check_expected_params l'empêche.
        return (
            f"transformation.kind={kind!r} accepté mais ses params ne sont "
            f"pas documentés (anomalie interne). Signaler via le bouton "
            f"Signaler un bug."
        )

    params_raw = transformation.get("params")
    cond_required = expected.get("required_unless_count") or ()
    if params_raw is None:
        return (
            f"transformation.params manquant pour kind={kind!r}. "
            f"Clés requises : {list(expected['required']) + list(cond_required)}. "
            f"Exemple : {expected['example']}. "
            f"Colonnes disponibles : {_safe_columns_for_llm(ctx)}."
        )
    if not isinstance(params_raw, dict):
        return (
            f"transformation.params doit être un objet, reçu "
            f"{type(params_raw).__name__}. Exemple : {expected['example']}. "
            f"Colonnes disponibles : {_safe_columns_for_llm(ctx)}."
        )

    # Résolution des aliases : `category` → `category_col`, etc.
    canonical = _resolve_aliases(params_raw, expected)

    columns_visible = _safe_columns_for_llm(ctx)

    # Couche de diagnostic — chaque helper renvoie une liste de fragments.
    issues: list[str] = []
    issues.extend(_diag_keys(canonical, params_raw, expected))
    issues.extend(_diag_columns(canonical, expected, columns_visible))
    issues.extend(_diag_enums(canonical, expected))

    parts: list[str] = [f"transformation.params invalide pour kind={kind!r}."]
    parts.extend(issues)
    if not issues:
        # Cas résiduel : validate_recipe a refusé pour une raison non
        # détectée (combinaison edge). Diagnostic générique mais avec
        # exemple toujours utile.
        parts.append(
            "Combinaison de params refusée par le validateur (vérifier "
            "la cohérence agg vs colonnes numériques, sort, limit 1..100)."
        )
    parts.append(f"Exemple correct : {expected['example']}.")
    parts.append(f"Colonnes disponibles : {columns_visible}.")
    return " ".join(parts)


def _validate_widget_proposal(
    input_: dict, ctx: WidgetPlannerContext
) -> tuple[Optional[dict], list[str]]:
    """Valide une proposition de widget — fonction PURE (no I/O, no mutate ctx).

    Refactor CC4 review globale 2026-05-18 : extraction du bloc validation
    de ``_handle_propose_widget`` pour testabilité unitaire (validation
    isolée du dispatch/ctx mutation).

    Args:
        input_: dict tool_input du LLM (widget_type, chart_type, col_span,
            title, transformation, intent, drill_column, render_spec).
        ctx: ``WidgetPlannerContext`` lu en READ-ONLY pour valider que les
            colonnes référencées (transformation.params.column, drill_column)
            existent dans ``ctx.columns``.

    Returns:
        Tuple ``(proposal_dict | None, errors)`` :
        - Si ``errors`` non-vide, ``proposal_dict`` est ``None``.
        - Sinon ``proposal_dict`` est prêt à append à ``ctx.proposals``.

    Validation stricte (defense-in-depth — Anthropic strict mode normalement
    filtre, mais on revalide ici) :
    - widget_type ∈ {chart, kpi, table} (text non exposé à l'agent)
    - chart_type ∈ VALID_CHART_TYPES si widget_type='chart'
    - col_span ∈ {3, 4, 6, 8, 12}
    - transformation valide via ``validate_recipe`` du pipeline existant
    - title 1..80 chars, neutralisé chars de contrôle
    - cohérence widget_type ↔ transformation.kind via ``_COMPATIBLE_RECIPES``
    - drill_column ignoré silencieusement si absent de ctx.columns
    """
    from app.models.dashboard import DashboardWidget
    from app.services.dashboard.widget_planner.transformations import (
        validate_recipe,
    )

    errors: list[str] = []

    # widget_type
    widget_type = input_.get("widget_type")
    if widget_type not in ("chart", "kpi", "table"):
        errors.append(
            f"widget_type invalide : {widget_type!r}. "
            "Attendu chart/kpi/table. Pour du texte statique, passer par "
            "le mode manuel UI (pas par cet agent)."
        )

    # chart_type (si chart)
    chart_type = input_.get("chart_type")
    if widget_type == "chart":
        if chart_type not in DashboardWidget.VALID_CHART_TYPES:
            errors.append(
                f"chart_type invalide : {chart_type!r}. "
                f"Attendu {list(DashboardWidget.VALID_CHART_TYPES)}."
            )
    elif chart_type is not None:
        # widget_type != chart mais chart_type fourni → ignore
        chart_type = None

    # col_span
    col_span = input_.get("col_span")
    if col_span not in DashboardWidget.VALID_COL_SPANS:
        errors.append(
            f"col_span invalide : {col_span!r}. "
            f"Attendu {list(DashboardWidget.VALID_COL_SPANS)}."
        )

    # title — strip control chars partagé (cf. fix CC1).
    title_raw = input_.get("title")
    if not isinstance(title_raw, str) or not title_raw.strip():
        errors.append("Le titre est obligatoire (1 à 80 chars).")
        title = ""
    else:
        title = _strip_control(title_raw, cap=_MAX_TITLE_LEN)
        if not title.strip():
            errors.append("Le titre ne contient que des caractères de contrôle.")

    # transformation recipe — diagnostic prescriptif si rejet (fix dashboard
    # graph creation 2026-05-22 + adversarial fixes F9/F10). Avant : message
    # générique « transformation invalide ou colonne référencée inexistante »
    # → le LLM (vu en boucle dans llm_log.md 99566-100735) cherchait d'autres
    # COLONNES alors que le vrai problème était les NOMS DES CLÉS de params
    # (`group_column` inventé au lieu de `category_col`).
    transformation = input_.get("transformation")
    raw_kind = transformation.get("kind") if isinstance(transformation, dict) else None

    # Gardes explicites widget_type + passthrough (fix F14 : kpi aussi). Sans
    # ces messages dédiés, passthrough sur chart/kpi est rejeté avec un
    # message générique non-prescriptif. Le flag `passthrough_blocked` permet
    # ensuite de skip le check générique de cohérence pour éviter la double
    # erreur (fix F9 : LLM voyait 2 erreurs pour 1 root cause).
    passthrough_blocked = False
    if widget_type == "chart" and raw_kind == "passthrough":
        errors.append(
            "transformation.kind='passthrough' interdit pour "
            "widget_type='chart' (passthrough donne une table brute, pas un "
            "graphique). Utiliser une recette structurée : groupby (bar/pie), "
            "groupby_2d (bar multi-série), time_series (line/area), "
            "time_series_multi (line multi), top_n_2d. Exemple : "
            "{kind: 'groupby', params: {category_col: '<dim>', "
            "value_col: '<mesure>', agg: 'sum'}}. "
            f"Colonnes disponibles : {_safe_columns_for_llm(ctx)}."
        )
        passthrough_blocked = True
    elif widget_type == "kpi" and raw_kind == "passthrough":
        errors.append(
            "transformation.kind='passthrough' interdit pour widget_type="
            "'kpi' (passthrough donne une table, pas une valeur scalaire). "
            "Utiliser scalar_aggregate (calculer la valeur) ou "
            "scalar_from_column (extraire une valeur déjà présente). "
            "Exemple : {kind: 'scalar_aggregate', params: {column: "
            "'<mesure>', agg: 'sum'}}. "
            f"Colonnes disponibles : {_safe_columns_for_llm(ctx)}."
        )
        passthrough_blocked = True

    clean_recipe = validate_recipe(transformation, ctx.columns)
    if clean_recipe is None:
        # Fix F10 : émettre le diagnostic prescriptif AUSSI pour table — le
        # silent fallback masquait les erreurs LLM sur les tables avant. Le
        # fallback passthrough reste appliqué juste en-dessous pour garder
        # le widget récupérable.
        errors.append(_diagnose_recipe_failure(transformation, ctx))
        clean_recipe = {"kind": "passthrough", "params": {}}

    # Cohérence widget_type ↔ transformation.kind (fix L2) — defense in
    # depth après les checks ciblés. Fix F9 : skip si on a déjà émis un
    # message dédié passthrough+chart/kpi (sinon le LLM voit 2 erreurs pour
    # 1 root cause).
    if widget_type in _COMPATIBLE_RECIPES and not passthrough_blocked:
        recipe_kind = clean_recipe.get("kind")
        if recipe_kind not in _COMPATIBLE_RECIPES[widget_type]:
            errors.append(
                f"transformation.kind={recipe_kind!r} incompatible avec "
                f"widget_type={widget_type!r}. Combinaisons valides : "
                f"{sorted(_COMPATIBLE_RECIPES[widget_type])}."
            )

    # drill_column — silencieusement droppé si absent (cohérent analyst)
    intent = input_.get("intent")
    drill_column = input_.get("drill_column")
    if isinstance(drill_column, str) and drill_column.strip():
        if _col_index_or_none(ctx, drill_column.strip()) is None:
            drill_column = None
        else:
            drill_column = drill_column.strip()
    else:
        drill_column = None

    if errors:
        return None, errors

    # Sanitize render_spec : whitelist + caps + strip control chars.
    safe_render_spec = _sanitize_render_spec(input_.get("render_spec"))

    return (
        {
            "intent": intent or "detail_table",
            "widget_type": widget_type,
            "chart_type": chart_type,
            "col_span": col_span,
            "title": title,
            "transformation": clean_recipe,
            "drill_column": drill_column,
            "render_spec": safe_render_spec,
        },
        [],
    )


async def _handle_propose_widget(input_: dict, ctx: WidgetPlannerContext) -> dict:
    """Valide une proposition de widget et l'ajoute à ctx.proposals.

    Orchestrateur léger : délègue la validation à
    :func:`_validate_widget_proposal` (fonction pure testable) puis
    mute ``ctx.proposals`` si OK.

    Retourne ``{accepted: True, widget_index: N, total_proposals: M}``
    ou ``{accepted: False, errors: [...]}``.

    Observability (fix dashboard graph creation 2026-05-22 + adversarial F6) :
    chaque rejet est logué en WARNING côté serveur. Pour respecter la doctrine
    Komptia Niveau 2 (« pas de raw values ni keys user-controlled dans les
    logs »), on NE logue PAS les noms de clés bruts envoyés par le LLM — on
    catégorise plutôt en :
    - ``known_keys`` : intersection avec ``_EXPECTED_PARAMS[kind]`` (clés
      schéma, fermées par enum, donc safe à logger)
    - ``unknown_count`` : nombre de clés que le LLM a inventées (pas leur
      contenu — un attaquant /data-privacy ne peut pas faire leak de PII via
      ce canal)

    Permet de diagnostiquer une boucle d'erreurs sans devoir regrep dans
    ``llm_log.md`` (43k+ lignes) et sans risque de leak PII.
    """
    proposal, errors = _validate_widget_proposal(input_, ctx)
    if errors or proposal is None:
        transformation = input_.get("transformation")
        kind = transformation.get("kind") if isinstance(transformation, dict) else None
        params = transformation.get("params") if isinstance(transformation, dict) else None

        # Fix F6 : ne pas logger les clés brutes (PII potentiel sous threat
        # model). Catégoriser en known (depuis _EXPECTED_PARAMS, enum fermé)
        # et compter le reste.
        known_keys: list[str] = []
        unknown_count = 0
        if isinstance(params, dict):
            expected = _EXPECTED_PARAMS.get(kind) if isinstance(kind, str) else None
            if expected is not None:
                allowed = (
                    set(expected["required"])
                    | set(expected["optional"])
                    | set(expected.get("required_unless_count") or ())
                    | set((expected.get("aliases") or {}).keys())
                )
                for k in params.keys():
                    if isinstance(k, str) and k in allowed:
                        known_keys.append(k)
                    else:
                        unknown_count += 1
            else:
                # kind invalide → on ne peut pas catégoriser, on compte tout
                # comme unknown (sans logger les noms).
                unknown_count = len(params)
        logger.warning(
            "widget_planner_agent: propose_widget rejeté "
            "(dashboard_id=%s widget_type=%s kind=%s known_keys=%s "
            "unknown_count=%d errors=%d)",
            ctx.dashboard_id,
            input_.get("widget_type"),
            kind if isinstance(kind, str) and kind in _EXPECTED_PARAMS else None,
            sorted(known_keys),
            unknown_count,
            len(errors),
        )
        return {"accepted": False, "errors": errors}
    ctx.proposals.append(proposal)
    return {
        "accepted": True,
        "widget_index": len(ctx.proposals) - 1,
        "total_proposals": len(ctx.proposals),
    }


async def _handle_commit_widgets(_input: dict, ctx: WidgetPlannerContext) -> dict:
    """Finalise le run. Requiert >=1 propose_widget préalable.

    Set ``ctx.terminal_kind = "commit"`` → la boucle agent (PR 2.4) sort
    et matérialise les ctx.proposals en list[WidgetPlanV2].
    """
    if len(ctx.proposals) < 1:
        return {
            "error": (
                "Aucune proposition à committer. Appelle au moins une fois "
                "`propose_widget` avant `commit_widgets`."
            ),
        }
    ctx.terminal_kind = "commit"
    return {
        "committed": True,
        "count": len(ctx.proposals),
    }


async def _handle_abort(input_: dict, ctx: WidgetPlannerContext) -> dict:
    """Termine le run SANS widget — pour SQL impossible à exploiter.

    Set ``ctx.terminal_kind = "abort"`` + stocke la raison (cap 200 chars).
    """
    raw_reason = input_.get("reason")
    if not isinstance(raw_reason, str) or not raw_reason.strip():
        reason = "Aucune raison fournie."
    else:
        reason = raw_reason.strip()[:_MAX_ABORT_REASON_LEN]
    ctx.terminal_kind = "abort"
    ctx.abort_reason = reason
    return {"aborted": True, "reason": reason}


_HANDLERS: dict[str, ToolHandler] = {
    "peek_sql_result": _handle_peek_sql_result,
    "column_stats": _handle_column_stats,
    "distinct_values": _handle_distinct_values,
    "aggregate_column": _handle_aggregate_column,
    "read_existing_widgets": _handle_read_existing_widgets,
    "propose_widget": _handle_propose_widget,
    "commit_widgets": _handle_commit_widgets,
    "abort": _handle_abort,
}


async def dispatch_widget_planner_tool(
    tool_name: str,
    tool_input: dict[str, Any],
    ctx: WidgetPlannerContext,
) -> dict[str, Any]:
    """Route un tool_call vers son handler. Retourne le dict envoyé au LLM
    comme ``tool_result.content``.

    Behavior :
    - tool inconnu → ``{"error": "..."}`` (l'agent transmet au LLM qui
      ré-essaie ou abort).
    - handler raise NotImplementedError → ``{"error": "..."}`` (utile en
      PR 2.1 scaffolding pour ne pas faire crasher la boucle).
    - handler raise autre exception → log + ``{"error": "..."}`` (fail-open
      partiel : un tool buggé ne plante pas le run entier).
    """
    handler = _HANDLERS.get(tool_name)
    if handler is None:
        return {"error": f"Outil inconnu : {tool_name}."}
    try:
        return await handler(tool_input or {}, ctx)
    except NotImplementedError as exc:
        # Cas PR 2.1 scaffolding — on remonte l'info pour debug sans crash.
        return {"error": str(exc), "stub": True}
    except Exception as exc:  # noqa: BLE001
        logger.exception("widget_planner_agent: tool %s a levé", tool_name)
        return {"error": f"Exception dans l'outil {tool_name} : {exc}"}
