"""Outils du mini-agent copilot (grid-copilot tool-loop).

Philosophie : donner au LLM les primitives qu'un agent utilise pour
explorer un classeur inconnu :
- LISTER les onglets (`list_tabs`)
- LIRE des portions d'onglets pour comprendre la structure (`read_tab_rows`)
- AGRÉGER des valeurs via filtres (`aggregate`)
- PRÉVISUALISER un emit sans committer (`preview_emit_tab`)
- ÉMETTRE l'onglet final (`emit_tab`)
- ABANDONNER proprement si infaisable (`abandon`)

Le dispatch réutilise les helpers existants de `result_assistant.py`
(_expand_emit_tab, _validate_emit_tab, _recompute_emit_tab)
pour garantir la cohérence avec l'ancien chemin one-shot.
"""

from __future__ import annotations

import asyncio
import copy as _copy
import logging
import time
from decimal import Decimal
from typing import Any, Dict, List, Optional

from app.services.ai.filter_extractor import extract_sql_scope
from app.services.ai.plan_tools_core import (
    PLAN_STATUSES as _PLAN_STATUSES,
    add_task as _core_add_task,
    list_plan as _core_list_plan,
    update_task as _core_update_task,
)
from app.services.result_assistant import (
    _emit_tab_in_excluded,
    _emit_tab_match_value,
    _emit_tab_scalar_eq,
    _expand_emit_tab,
    _recompute_emit_tab,
    _validate_emit_tab,
    deanon_source_match,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# JSON schemas (format Anthropic tools)
# ---------------------------------------------------------------------------

COPILOT_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "list_tabs",
        "description": (
            "Liste tous les onglets ouverts du classeur avec leurs métadonnées "
            "(label, row_count, columns, is_active, sql si c'est un onglet SQL). "
            "Appelle ceci EN PREMIER pour voir ce qui existe avant de lire ou "
            "agréger quoi que ce soit. "
            "Pour les onglets SQL, le champ `scope` résume les filtres positifs "
            "du WHERE (col IN (vals) / col = v) sous forme `{col: [vals]}` — "
            "ce qui te permet de comparer les portées de deux onglets avant de "
            "les croiser. `scope: {}` = SQL sans filtre utile ; `scope: null` "
            "= SQL non parsable. Deux onglets sans le même `scope` sur une "
            "dimension métier ne sont PAS interchangeables."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "read_tab_rows",
        "description": (
            "Lit une portion d'un onglet : les lignes + cellDetails entre "
            "row_start et row_end (inclus). Les rows retournées sont 0-based "
            "(row=0 = première ligne). Utile pour inspecter la structure d'un "
            "template à reproduire (identifier les sections, les labels de "
            "ligne/colonne, les positions des sous-totaux) OU pour comprendre "
            "les colonnes-dimensions d'un onglet SQL. Cap : max 60 lignes par "
            "appel, si tu as besoin de plus fais plusieurs appels."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "tab_idx": {
                    "type": "integer",
                    "description": "Index 0-based de l'onglet (voir list_tabs).",
                },
                "row_start": {
                    "type": "integer",
                    "description": "Première ligne à lire (0-based, inclusif). Défaut: 0.",
                    "default": 0,
                },
                "row_end": {
                    "type": "integer",
                    "description": (
                        "Dernière ligne à lire (0-based, inclusif). " "Défaut: row_start + 59."
                    ),
                },
            },
            "required": ["tab_idx"],
            "additionalProperties": False,
        },
    },
    {
        "name": "rename_tab",
        "description": (
            "Change le label d'un onglet existant. Pas de recompute, pas "
            "de modification de contenu — seulement le titre affiché. "
            "Terminal — après cet appel, ton turn se termine."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target_tab_index": {
                    "type": "integer",
                    "description": "Index 0-based de l'onglet à renommer.",
                },
                "new_label": {
                    "type": "string",
                    "description": "Nouveau label. Non-vide, max 200 chars.",
                },
            },
            "required": ["target_tab_index", "new_label"],
            "additionalProperties": False,
        },
    },
    {
        "name": "delete_tab",
        "description": (
            "Supprime un onglet du classeur. Refuse si l'onglet est actif "
            "(tu dois d'abord utiliser un autre onglet comme actif, ou "
            "choisir un tool différent). Irréversible côté session. "
            "Terminal — après cet appel, ton turn se termine."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target_tab_index": {
                    "type": "integer",
                    "description": "Index 0-based de l'onglet à supprimer.",
                },
            },
            "required": ["target_tab_index"],
            "additionalProperties": False,
        },
    },
    {
        "name": "patch_tab",
        "description": (
            "Modifie 1 à N cellules précises d'un onglet EXISTANT, sans "
            "reconstruire l'onglet entier. À utiliser pour corriger une "
            "valeur, ajouter un label manquant, ou mettre à jour un "
            "cellDetails (match/value_column/derived_formula) sans refaire "
            "l'émission complète. Tous les patches s'appliquent en un batch "
            "atomique ; les cellules non listées restent inchangées. "
            "Terminal — après cet appel, ton turn se termine."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target_tab_index": {
                    "type": "integer",
                    "description": (
                        "Index 0-based de l'onglet à modifier dans le " "classeur (voir list_tabs)."
                    ),
                },
                "patches": {
                    "type": "object",
                    "description": (
                        "Clés `R,C` 0-based, valeurs = soit une valeur "
                        "littérale (string/number/null) qui devient la "
                        "nouvelle valeur de la cellule, soit un objet "
                        "`{value?: ..., cellDetail?: {match?, "
                        "match_exclude?, value_column?, source_tab_index?, "
                        "derived_formula?, label?}}` pour changer la spec "
                        "de recompute. Au moins un patch requis."
                    ),
                },
            },
            "required": ["target_tab_index", "patches"],
            "additionalProperties": False,
        },
    },
    {
        "name": "ask_iris",
        "description": (
            "Valide un SQL proposé et, si l'exécution réussit, matérialise "
            "les résultats dans un nouvel onglet du classeur. Iris valide "
            "contre le schéma BDD réel puis exécute ; les rows ne sont PAS "
            "renvoyées dans ton contexte — un onglet est ajouté à la place, "
            "que tu consultes ensuite via `list_tabs` / `read_tab_rows` / "
            "`aggregate` / `count_rows`. Retour : `{status, sql, "
            "tab_index?, label?, columns?, row_count?, errors?, "
            "schema_suggestions?}`. `status` ∈ {`tab_created`, `validated`, "
            "`invalid`, `error`}. Sur `error` : utilise `errors` + "
            "`schema_suggestions` pour reformuler et ré-appeler. Si "
            "`execute=false` : validation seule sans exécution (moins "
            "coûteux), aucun onglet créé."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": (
                        "Description de l'intention. Informatif uniquement "
                        "(logs/erreurs) — la génération est faite à partir "
                        "de `draft_sql`."
                    ),
                },
                "draft_sql": {
                    "type": "string",
                    "description": (
                        "SQL brouillon que tu proposes. Iris le valide "
                        "(schéma réel) puis l'exécute. Peut contenir les "
                        "tokens `§…§` (seront résolus avant exécution)."
                    ),
                },
                "execute": {
                    "type": "boolean",
                    "description": (
                        "True (défaut) = valide + exécute. False = valide "
                        "seulement, retourne les erreurs éventuelles sans "
                        "taper la BDD."
                    ),
                    "default": True,
                },
            },
            "required": ["task", "draft_sql"],
            "additionalProperties": False,
        },
    },
    {
        "name": "modify_tab_sql",
        "description": (
            "MUTE le SQL d'un onglet SQL existant — variation à partir du "
            "SQL actuel (ou d'un ``draft_sql`` fourni), exécution via Iris, "
            "puis ÉCRASEMENT en place du contenu de l'onglet cible. **Label "
            "et index préservés** ; ``sql``, ``columns``, ``rows`` remplacés ; "
            "``cellDetails`` éventuels DROP par sécurité (incohérence "
            "valeur↔SQL après mutation). **Différent d'``ask_iris``** qui crée "
            "TOUJOURS un nouvel onglet. Utilise ça quand l'utilisateur dit "
            "« modifie ce SQL pour ... » et qu'il veut UN onglet final, pas "
            "deux quasi-identiques. Non-terminal — chainable avec d'autres "
            "actions.\n\n"
            "Retour : ``{status, target_tab_index, label, sql, columns, "
            "row_count, errors?}``. ``status`` ∈ {``tab_updated``, ``error``}. "
            "Sur ``error`` : ``errors`` + ``schema_suggestions`` exploitables "
            "pour reformuler ``task`` ou ``draft_sql``. **Refus** si l'onglet "
            "cible n'a pas de ``sql`` (dashboard pur — non-mutable)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target_tab_index": {
                    "type": "integer",
                    "description": "Index 0-based de l'onglet SQL à modifier.",
                },
                "task": {
                    "type": "string",
                    "description": (
                        "Description en langage naturel de la variation voulue "
                        "(ex : « ajoute un filtre sur année = 2024 », « groupe "
                        "par mois au lieu de jour »). Iris adapte le SQL "
                        "actuel (ou ``draft_sql``) selon cette intention."
                    ),
                },
                "draft_sql": {
                    "type": "string",
                    "description": (
                        "Optionnel — SQL brouillon à partir duquel Iris part. "
                        "Si absent, le SQL actuel de l'onglet cible sert de "
                        "base. Peut contenir les tokens ``§…§`` "
                        "(résolus avant exécution)."
                    ),
                },
            },
            "required": ["target_tab_index", "task"],
            "additionalProperties": False,
        },
    },
    {
        "name": "count_rows",
        "description": (
            "Compte les lignes d'un onglet qui matchent `match` / `match_exclude`. "
            "Retour : `{count: N, exclude_hits?: {col: {token: nb_rows_filtrées}}}`. "
            "Coût en tokens quasi-nul. Utilise ça AVANT `read_tab_rows` pour savoir "
            "si un onglet contient des lignes pertinentes pour ton filtre. "
            "`exclude_hits` te révèle combien de lignes CHAQUE token de "
            "`match_exclude` a effectivement filtrées — un token à 0 signifie qu'il "
            "ne filtre rien (la valeur n'existe peut-être pas sous cette forme)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "tab_idx": {"type": "integer", "description": "Index 0-based de l'onglet."},
                "match": {
                    "type": "object",
                    "description": (
                        "Filtres d'égalité (scalaire), IN (liste), ou opérateurs "
                        "étendus (dict $op : $gt/$gte/$lt/$lte/$ne/$between/$like/"
                        "$is_null). Clés = colonnes-dimensions. Exemples : "
                        "{Montant: {$gte: 1000}}, {Client: {$like: 'A%'}}, "
                        "{Contact: {$is_null: true}}."
                    ),
                },
                "match_exclude": {
                    "type": "object",
                    "description": (
                        "Exclusions : NOT IN (liste) ou opérateurs $op (ex "
                        "{col: {$gt: 1000}} exclut tout ce qui dépasse 1000). "
                        "Clés = colonnes."
                    ),
                },
            },
            "required": ["tab_idx"],
            "additionalProperties": False,
        },
    },
    {
        "name": "search_workbook",
        "description": (
            "Recherche substring (case-insensitive) dans **tous les onglets** "
            "du classeur — utile quand tu cherches une valeur précise (libellé, "
            "code, nombre) dont tu ne sais pas dans quel onglet elle se trouve. "
            "Match sur :\n"
            "  - **noms de colonnes** (substring case-insensitive)\n"
            "  - **valeurs de cellules** (string ou cast str(value))\n"
            "Retourne `{groups: [{tab_index, label, matches: [{type, row, col, "
            "col_name, value?}]}], truncated}` — groupé par onglet, max ~50 "
            "résultats au total. ``truncated=true`` si la limite a été atteinte. "
            "Pour reprendre, affine ta query (plus spécifique) ou cible un "
            "onglet précis avec count_rows / aggregate / read_tab_rows. "
            "Cet outil reproduit le bouton 🔍 du frontend — ce que l'utilisateur "
            "voit quand il clique dessus, tu peux l'utiliser de la même façon."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": ("Substring à chercher (≥ 2 caractères, case-insensitive)."),
                },
                "max_results": {
                    "type": "integer",
                    "description": "Cap du total de matches (défaut : 50).",
                    "default": 50,
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "aggregate",
        "description": (
            "Somme les valeurs numériques d'un onglet source qui matchent les "
            "filtres `match` (égalité exacte sur les clés), en excluant celles "
            "qui matchent `match_exclude`. Retourne "
            "`{total, hit_count, exclude_hits?: {col: {token: nb_cellules_filtrées}}}`. "
            "`exclude_hits` compte combien de cellules chaque token de "
            "`match_exclude` a effectivement filtrées. Un token à 0 n'a filtré "
            "aucune cellule — soit la valeur n'existe pas sous cette forme dans "
            "la source, soit elle a un nom légèrement différent (ex: code court "
            "vs libellé long)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "source_tab_idx": {
                    "type": "integer",
                    "description": "Index de l'onglet source (SQL ou dashboard).",
                },
                "match": {
                    "type": "object",
                    "description": (
                        "Filtres : égalité (scalar), IN (liste), ou opérateurs "
                        "étendus (dict $op : $gt/$gte/$lt/$lte/$ne/$between/$like/"
                        "$is_null). Clés = colonnes-dimensions de l'onglet source. "
                        "Ex : {Montant: {$gte: 1000}}, {Client: {$like: 'A%'}}."
                    ),
                },
                "match_exclude": {
                    "type": "object",
                    "description": (
                        "Exclusions : NOT IN (liste) ou opérateurs $op (ex "
                        "{col: {$gt: 1000}} exclut > 1000). Clés = colonnes."
                    ),
                },
                "value_column": {
                    "type": "string",
                    "description": "Nom de la colonne-mesure à sommer.",
                },
            },
            "required": ["source_tab_idx", "value_column"],
            "additionalProperties": False,
        },
    },
    {
        "name": "preview_emit_tab",
        "description": (
            "Simule un emit_tab sans commit. Retourne des metrics de couverture "
            "(cellDetails posés, matched vs no_source, zéros, cellules à None), la "
            "liste `uncovered_template_positions` des positions numériques du "
            "template encore non remplies, et pour chacune un champ "
            "`candidate_source_tabs` — indices de tabs dont les noms de colonnes "
            "correspondent à au moins une dimension déjà utilisée dans les "
            "cellDetails de la même row/col. Les candidats sont des PISTES "
            "structurelles, pas des verdicts : le tab peut ne pas contenir les "
            "valeurs voulues pour la combinaison précise (à confirmer via "
            "`count_rows`/`aggregate`), et un tab hors liste peut convenir si "
            "l'angle d'attaque diffère. Si ≥4 cellDetails partagent exactement "
            "la même combinaison (source_tab_index, value_column, match_exclude), "
            "`factorization_hints` te les pointe — signal pour factoriser via "
            "`cell_groups` et avoir un seul point de correction. Même payload "
            "que emit_tab ; appel idempotent, itère autant que nécessaire."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "label": {"type": "string"},
                "new_tab": {"type": "boolean", "default": True},
                "clone_structure_from": {"type": "integer"},
                "rows_overrides": {"type": "object"},
                "columns": {"type": "array", "items": {"type": "string"}},
                "rows": {"type": "array"},
                "merges": {"type": "array"},
                "cellDetails": {"type": "object"},
                "cell_groups": {"type": "array"},
            },
            "required": ["label"],
            "additionalProperties": True,
        },
    },
    {
        "name": "emit_tab",
        "description": (
            "ÉMET l'onglet final (COMMIT). C'est ton dernier appel pour cette "
            "demande — après ça, le classeur sera mis à jour. **APPELLE "
            "preview_emit_tab D'ABORD** pour vérifier la couverture. Utilise "
            "`clone_structure_from: <idx>` pour hériter de la structure d'un "
            "onglet existant sans re-émettre rows/columns/merges. Pour les "
            "cellules numériques, fournis `cellDetails` avec un `match` — le "
            "backend sommera depuis les onglets sources. Coordonnées R,C "
            "0-based. Regroupe par `cell_groups` pour factoriser les champs "
            "partagés (match_exclude, value_column, source_tab_index)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "label": {
                    "type": "string",
                    "description": "Titre du nouvel onglet. Unique.",
                },
                "new_tab": {
                    "type": "boolean",
                    "description": "True = nouvel onglet (défaut). False = écrase l'actif.",
                    "default": True,
                },
                "clone_structure_from": {
                    "type": "integer",
                    "description": (
                        "Index 0-based de l'onglet dont on copie la structure "
                        "(columns, rows, merges). Cas typique : index de l'onglet actif."
                    ),
                },
                "rows_overrides": {
                    "type": "object",
                    "description": (
                        "Substitutions textuelles après clone. Clés 'R,C' 0-based, "
                        "valeurs = texte de remplacement (titre, nom entité, etc.)."
                    ),
                },
                "columns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Noms de colonnes. NON REQUIS si clone_structure_from est fourni."
                    ),
                },
                "rows": {
                    "type": "array",
                    "description": (
                        "Grille 2D (liste de listes). NON REQUIS si clone_structure_from "
                        "est fourni. Utilise null pour cellules vides."
                    ),
                },
                "merges": {
                    "type": "array",
                    "description": "Merges {r1,c1,r2,c2}. Optionnel.",
                },
                "cellDetails": {
                    "type": "object",
                    "description": (
                        "Per-cell match pour recompute. Clés 'R,C' 0-based. "
                        "Chaque valeur : {match, match_exclude?, value_column?, "
                        "source_tab_index?, label?}."
                    ),
                },
                "cell_groups": {
                    "type": "array",
                    "description": (
                        "Groupes partageant match_exclude/value_column/source_tab_index. "
                        "Format : [{source_tab_index, value_column, match_exclude?, "
                        "cells: {'R,C': {match, label}}}]."
                    ),
                },
                "sort_by": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "column": {"type": "string"},
                            "direction": {
                                "type": "string",
                                "enum": ["asc", "desc"],
                                "default": "asc",
                            },
                        },
                        "required": ["column"],
                    },
                    "description": (
                        "Optionnel — tri des rows par une ou plusieurs colonnes "
                        "APRÈS le recompute des cellDetails. Format : "
                        "[{column: 'Montant', direction: 'desc'}, {column: 'Date'}]. "
                        "Multi-colonnes : tri stable cumulé (col2 d'abord puis "
                        "col1, comme SQL ORDER BY col1, col2). NULLS LAST dans "
                        "les 2 directions. Incompatible avec `merges` (les "
                        "rectangles de fusion seraient brisés par la permutation). "
                        "Les clés de `cellDetails` sont automatiquement remappées."
                    ),
                },
                "sql": {
                    "type": "string",
                    "description": (
                        "Optionnel — SQL associé à l'onglet. Si fourni, "
                        "l'onglet résultant est de **type SQL** côté frontend "
                        "(sort, filter, drill-down natifs activés). "
                        "Cas typique : tu as utilisé ask_iris pour matérialiser "
                        "un onglet `iris_result_N` (qui a déjà un sql), et "
                        "tu veux livrer cet onglet comme résultat final — "
                        "fournis ici le sql de iris_result_N pour préserver "
                        "le type SQL. Sans sql : onglet de type 'dashboard' "
                        "(si cellDetails) ou 'imported' (si rows brutes)."
                    ),
                },
            },
            "required": ["label"],
            "additionalProperties": True,
        },
    },
    {
        "name": "run_python",
        "description": (
            "Exécute du Python d'exploration sans commit. Retourne `stdout` + "
            "un aperçu de `session` (dict partagé entre appels de ce run).\n\n"
            "Contrat du sandbox :\n"
            "  `tabs`      — list[dict], une entrée par onglet, index = même "
            "ordre que `list_tabs()`.\n"
            "  `tabs[i]`   — dict avec :\n"
            "    - `index`         : int\n"
            "    - `label`         : str\n"
            "    - `columns`       : list[str]\n"
            "    - `row_count`     : int\n"
            "    - `is_active`     : bool\n"
            "    - `sql`?          : str (présent si onglet SQL)\n"
            "    - `sheet_content`?: list[dict] (présent si l'onglet a des "
            "cellules) — MÊME SHAPE que ce que `read_tab_rows(i).cells` retourne. "
            "Chaque entrée = dict `{row:int (1-based), col:str, value:any, "
            "match?:dict, label?:str}`. Itère avec `for cell in tabs[i]['sheet_content']:`.\n"
            "    - `rows`?         : list[list] dense 2D 0-based, présent UNIQUEMENT "
            "pour onglets non-SQL. Absent pour SQL tabs car les dimensions vivent "
            "dans `cell.match`.\n"
            "  `session`   — dict partagé entre tous les `run_python` d'un même run. "
            "Survit aux appels, utile pour stocker des agrégats intermédiaires.\n\n"
            "Sandbox : `for/if/while`, imports whitelist "
            "(`math, json, itertools, collections, re, datetime, statistics, copy`), "
            "méthodes usuelles (`.get/.items/.keys/.values`), `def` local. "
            "Pas de `os/sys/subprocess/open`, pas de dunders, timeout 10 s.\n\n"
            "Utilise `print()` pour produire du stdout (retourné dans `stdout`)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": (
                        "Code Python à exécuter. Accès à `tabs` et `session` "
                        "(voir contrat dans la description du tool)."
                    ),
                },
            },
            "required": ["code"],
            "additionalProperties": False,
        },
    },
    {
        "name": "emit_via_code",
        "description": (
            "COMMIT terminal via sandbox Python. Utile quand le template contient "
            "beaucoup de cellDetails qui partagent des dimensions (p.ex. N sections × "
            "M périodes) et qu'énumérer chacune manuellement serait fastidieux.\n\n"
            "Helpers exposés dans le sandbox :\n"
            "  `add_cell(r, c, match=, match_exclude=, value_column=, "
            "source_tab_index=, derived_formula=, label=)` — ajoute un cellDetails à "
            "(r, c) 0-based du NOUVEL onglet. Mêmes champs que `emit_tab.cellDetails`.\n"
            "  `add_override(r, c, value)` — ajoute un rows_overrides à (r, c).\n\n"
            "Accès aux sources (même contrat que `run_python`) :\n"
            "  `tabs`     — list[dict], 1 entrée par onglet du classeur.\n"
            "  `tabs[i]`  — `{index, label, columns: list[str], row_count, is_active, "
            "sql?, sheet_content?: list[dict{row, col, value, match?, label?}], "
            "rows?: list[list]}`. `sheet_content` est MÊME SHAPE que "
            "`read_tab_rows(i).cells` — sparse, row 1-based, match porte les dims. "
            "`rows` dense 2D 0-based uniquement pour onglets non-SQL.\n"
            "  `session`  — dict partagé avec les `run_python` du même run.\n\n"
            "Sandbox identique à `run_python` (for/if/while, imports whitelist, "
            "`def` local, timeout 10 s, pas de `os/sys/subprocess/open` ni dunders). "
            "Cap 5000 cellules émises par appel. "
            "`preview=true` renvoie metrics + uncovered sans committer — itère avant "
            "le commit final."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "label": {
                    "type": "string",
                    "description": "Titre du nouvel onglet.",
                },
                "new_tab": {"type": "boolean", "default": True},
                "clone_structure_from": {
                    "type": "integer",
                    "description": (
                        "Index de l'onglet dont on copie la structure " "(columns, rows, merges)."
                    ),
                },
                "rows_overrides": {
                    "type": "object",
                    "description": (
                        "Substitutions textuelles statiques (R,C → valeur). "
                        "Complémentaire aux `add_override` du code Python."
                    ),
                },
                "code": {
                    "type": "string",
                    "description": (
                        "Code Python qui appelle `add_cell(...)` et/ou "
                        "`add_override(...)` dans des boucles pour "
                        "générer les cellules. Voir la description du tool."
                    ),
                },
                "preview": {
                    "type": "boolean",
                    "description": (
                        "Si true, renvoie les metrics + uncovered sans "
                        "commit. Permets d'itérer sur le code avant emit final."
                    ),
                    "default": False,
                },
            },
            "required": ["label", "code"],
            "additionalProperties": True,
        },
    },
    {
        "name": "abandon",
        "description": (
            "Utilise ceci UNIQUEMENT si tu constates que la demande est "
            "infaisable (données manquantes, ambiguïté non résoluble, etc.) "
            "après avoir vraiment essayé. L'utilisateur verra le `reason`. "
            "**TERMINAL** — clôture le run."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "description": "Explication courte de ce qui bloque.",
                },
            },
            "required": ["reason"],
            "additionalProperties": False,
        },
    },
    {
        "name": "done",
        "description": (
            "Clôture le run et livre l'ensemble des onglets émis et "
            "modifications effectuées. **C'est le SEUL outil qui termine "
            "un run normal** (avec `abandon` pour les cas infaisables). "
            "Les outils `emit_tab`, `emit_via_code`, `patch_tab`, "
            "`rename_tab`, `delete_tab` sont **non-terminaux** : tu peux "
            "les enchaîner pour produire/modifier plusieurs onglets dans le "
            "même run, puis appelles `done` une fois quand toute la demande "
            "est satisfaite. Refuse si AUCUNE action n'a été enregistrée "
            "(emit + modifications vides) — dans ce cas la demande est soit "
            "infaisable (`abandon`) soit pas encore commencée."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": (
                        "Optionnel. Récapitulatif court (1-3 phrases) de ce qui "
                        "a été fait dans ce run, à destination de l'utilisateur. "
                        "Si tu en fournis un, il sera affiché à côté du résultat."
                    ),
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "plan_add",
        "description": (
            "Ajoute une étape à ta todo-list. Utile pour les tâches "
            "multi-étapes (croisement de plusieurs sources, reproduction de "
            "template, enchaînement validation/correction) où tu as besoin "
            "de tracer ce qui est fait, ce qui reste, ce qui a été écarté. "
            "Non-terminal. La task est créée avec status `pending` — appelle "
            "`plan_update` pour passer à `in_progress` quand tu y travailles, "
            "puis `completed` ou `cancelled` à la fin. L'utilisateur voit "
            "en temps réel la task `in_progress` dans le bandeau de la grille."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "subject": {
                    "type": "string",
                    "description": (
                        "Titre court de l'étape (verbe à l'impératif : "
                        "« Lire template », « Vérifier code stat juridique », "
                        "« Poser cellules section SOCIAL »)."
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
                    "enum": list(_PLAN_STATUSES),
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
            "leur status). Utile si tu veux te rappeler où tu en es sans "
            "remonter l'historique conversationnel. Non-terminal."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "explain_substitution",
        "description": (
            "DOIT être appelé AVANT d'utiliser une valeur sémantiquement "
            "traduite depuis la demande utilisateur — quand le terme que "
            "l'utilisateur emploie ne correspond pas au caractère près à "
            "une valeur présente dans la source, et que tu choisis une "
            "valeur proche pour appliquer un filtre, un match ou une "
            "exclusion. Non-terminal : tu continues ta tâche après l'appel. "
            "La substitution est rétro-injectée dans la réponse finale pour "
            "que l'utilisateur voie ce que tu as traduit et puisse corriger "
            "si tu as mal compris. Usage obligatoire pour toute traduction "
            "terme-utilisateur → valeur-source non triviale — évite les "
            "substitutions silencieuses qui falsifient le résultat sans "
            "laisser de trace."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "original": {
                    "type": "string",
                    "description": (
                        "Terme tel que fourni par l'utilisateur (verbatim de " "sa demande)."
                    ),
                },
                "replacement": {
                    "type": "string",
                    "description": (
                        "Valeur réelle qui sera utilisée dans la requête ou "
                        "le filtre (telle que présente dans la source)."
                    ),
                },
                "reason": {
                    "type": "string",
                    "description": (
                        "Pourquoi cette traduction est légitime : quelle "
                        "preuve concrète la justifie (valeur observée dans "
                        "une colonne, distinct de col_distinct, row vue via "
                        "read_tab_rows, etc.). Phrase courte, factuelle, "
                        "vérifiable."
                    ),
                },
            },
            "required": ["original", "replacement", "reason"],
            "additionalProperties": False,
        },
    },
]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


class CopilotContext:
    """Contexte partagé entre handlers d'outils. Contient les données du
    classeur reçues du frontend + variables de résultat set par emit_tab/abandon
    + session persistente entre appels ``run_python`` du même run.
    """

    def __init__(
        self,
        tabs_context: Optional[List[Dict[str, Any]]],
        sheet_content: Optional[List[Dict[str, Any]]],
        columns: Optional[List[str]],
        sql: str,
        instruction: str,
    ) -> None:
        self.tabs_context = tabs_context or []
        self.sheet_content = sheet_content or []
        self.columns = columns or []
        self.sql = sql or ""
        self.instruction = instruction
        self.terminal_result: Optional[Dict[str, Any]] = None
        # ``"done" | "abandon" | "emit_tab_error"``. Seuls ``done`` et
        # ``abandon`` clôturent le run ; ``emit_tab_error`` est un sentinel
        # interne (le turn a planté sur expand/validate, la boucle reset les
        # flags et laisse le LLM retenter au turn suivant). Les autres outils
        # de modification (``emit_tab``, ``emit_via_code``, ``patch_tab``,
        # ``rename_tab``, ``delete_tab``) sont **non-terminaux** : le LLM
        # peut les enchaîner pour produire ou modifier plusieurs onglets dans
        # le même run, puis appeler ``done`` quand il a fini.
        self.terminal_kind: Optional[str] = None
        # Relance de protocole (incident 2026-06-12) : True dès que la boucle
        # a renvoyé UNE fois le rappel « appelle done/abandon » après un
        # end_turn texte sans terminal. Borne anti-boucle : une seule relance
        # par run — au 2e end_turn texte, la boucle rescue (travail accumulé)
        # ou retourne l'erreur no_terminal (rien accompli).
        self.end_turn_nudge_sent: bool = False
        # Liste des onglets émis par ``emit_tab`` / ``emit_via_code`` dans ce
        # run (FIFO). Chaque entrée garde le ``final_result`` complet (tab,
        # description, metrics, recompute_ms…). Packé dans ``terminal_result``
        # par ``handle_done``.
        self.emits: List[Dict[str, Any]] = []
        # Liste des modifications de tabs par ``patch_tab`` / ``rename_tab``
        # / ``delete_tab`` dans ce run (FIFO). Même rôle.
        self.modifications: List[Dict[str, Any]] = []
        # Session partagée entre les appels `run_python` du même turn-loop.
        # Équivalent du scratch Python que j'utilise (pickle entre scripts) :
        # le LLM peut stocker des agrégats, un plan, des références de
        # positions — les réutiliser dans un appel ultérieur sans
        # recalculer. Mutated in-place par le sandbox.
        self.session: Dict[str, Any] = {}
        # Miroir d'exploration : onglets effectivement sondés par le LLM
        # (read_tab_rows, aggregate, count_rows). Exposé dans le résultat de
        # `preview_emit_tab` pour qu'il voie "tu commit avec N/M onglets
        # jamais ouverts" — signal factuel, pas de directive.
        self.tabs_touched: set = set()
        # Cache des appels `ask_iris` de ce run. Clé = hash(sql_cleartext,
        # max_rows), valeur = résultat ré-anonymisé. Scope = 1 run copilot,
        # jamais persistant inter-sessions (chaque run reconstruit son cache).
        self._iris_cache: Dict[str, Dict[str, Any]] = {}
        # Compteur d'onglets créés par ask_iris dans ce run. Sert à nommer
        # les nouveaux onglets ("iris_result_1", "iris_result_2", …) de
        # manière déterministe et non-collisionnante. Le SQL exécuté par
        # Iris n'est PAS renvoyé dans le contexte du LLM ; il est
        # matérialisé dans un nouvel onglet ajouté à ``tabs_context`` que le
        # LLM consulte ensuite via ``list_tabs`` / ``read_tab_rows`` /
        # ``aggregate`` — évite de gonfler le contexte LLM avec les rows.
        self._iris_tab_counter: int = 0
        # [DEBUG TEMPORAIRE] Compteur de tentatives d'appel à ask_iris
        # (incrémenté dans ``handle_ask_iris`` dès l'entrée — indépendant
        # du succès / erreur). Sert à l'interview de debug post-run pour
        # savoir si le LLM a tenté iris ou pas. À RETIRER quand le debug
        # est terminé.
        self._iris_call_attempts: int = 0
        # [DEBUG TEMPORAIRE] Flag levé pendant le run par
        # ``handle_preview_emit_tab`` / ``handle_emit_via_code`` (preview)
        # quand des positions uncovered exposent des ``reference_sqls``.
        # Lu à la toute fin de ``run_copilot_agent`` pour décider si une
        # interview post-run est posée. Le flag n'est JAMAIS exposé au
        # LLM pendant le run — il ne modifie pas son comportement.
        # À RETIRER avec l'interview quand le debug est terminé.
        self._iris_debug_needs_interview: bool = False
        # Traductions sémantiques demande-utilisateur → valeur-source que le
        # LLM a effectuées (via ``explain_substitution``). Rétro-injectées
        # dans les metrics du résultat final pour que l'utilisateur voie les
        # traductions et puisse les corriger si le LLM s'est trompé.
        # Liste de dicts ``{"original", "replacement", "reason"}`` dans
        # l'ordre d'apparition.
        self.substitutions: List[Dict[str, str]] = []
        # Todo-list dynamique du LLM (comme celle de Claude Code). Le LLM la
        # construit via plan_add/plan_update/plan_list pour tracer les étapes
        # d'une tâche complexe. Visible au frontend en temps réel (polling),
        # miroir dans les tool_results suivants pour qu'il se rappelle. Vide
        # = le LLM n'a pas pris la peine ; c'est son choix, non bloquant.
        # Chaque task : ``{"id": int, "subject": str, "description": str?,
        # "status": "pending" | "in_progress" | "completed" | "cancelled"}``.
        self.plan: List[Dict[str, Any]] = []
        # Prochain id attribué par plan_add (séquentiel, commence à 1).
        self._plan_next_id: int = 1
        # Identifiant unique du run copilot, passé par le frontend et utilisé
        # pour indexer le store de progress (``copilot_progress_store``). Le
        # frontend le génère avec crypto.randomUUID() ou fallback. Vide si le
        # run est lancé en test/debug sans frontend — dans ce cas le store
        # n'est pas synchronisé (pas d'erreur, juste pas de polling possible).
        self.run_id: str = ""
        # Id de l'utilisateur qui a déclenché le run. Indexe le store avec
        # (user_id, run_id) pour empêcher qu'un user accède au plan d'un
        # autre même s'il devinait son run_id. Vide en test/debug — dans ce
        # cas le store n'est pas synchronisé (pas d'erreur).
        self.user_id: Any = None
        # Objet ORM ``User`` complet (distinct de ``user_id``). Utilisé pour
        # le Row-Level-Security du module ``data_access`` : ``executor.execute``
        # a besoin de ``user.role`` / ``user.scopes`` pour appliquer le
        # filtrage cellules/tables/colonnes. Sans cet objet, l'enforcer
        # logue ``RLS skip`` et la requête passe non-filtrée (fail-OPEN
        # historique pour callers legacy). Préfixé ``_`` pour rappeler qu'il
        # ne doit pas être exposé au LLM via ``state_snapshot`` — c'est de
        # l'état interne pour le pipeline RLS.
        self._user: Any = None
        # Numéro de turn courant, posé par la boucle run_copilot_agent à
        # chaque tour. Exposé sur le ctx pour les besoins de la boucle agent.
        self.turn_count: int = 0


def _list_tabs_core(tabs_context: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Logique pure de ``handle_list_tabs`` — pas de CopilotContext requis.

    Extrait de ``handle_list_tabs`` pour réutilisation depuis le dispatcher
    Iris (task #13 / Phase 2.2 — `transform_uploaded_file` ne porte pas de
    ``CopilotContext`` mais peut construire son propre ``tabs_context`` via
    ``_build_tabs_context_from_upload`` côté agent_tools.py). Doctrine
    SSoT : une seule implémentation, deux callers (copilot via
    ``handle_list_tabs``, Iris via appel direct).

    Aucun side-effect, aucune dépendance à ``ctx.tabs_touched`` (list_tabs
    ne marque pas les onglets comme touchés — seul read_tab_rows / aggregate
    le font).
    """
    summary = []
    for i, tab in enumerate(tabs_context):
        if not isinstance(tab, dict):
            continue
        sql = tab.get("sql") or ""
        entry: Dict[str, Any] = {
            "index": i,
            "label": tab.get("label", f"Onglet {i}"),
            "columns": tab.get("columns", []),
            "row_count": tab.get("row_count", 0),
            "is_active": bool(tab.get("is_active")),
        }
        if sql:
            entry["sql"] = sql
            # scope : dict des filtres IN/= positifs, {} si WHERE sans filtre
            # utile, None si SQL non parsable. On expose TOUJOURS la clé pour
            # que le LLM distingue explicitement "pas de filtre" vs "système
            # incapable d'inférer" — pas de silence ambigu.
            entry["scope"] = extract_sql_scope(sql)
        col_distinct = tab.get("col_distinct")
        if isinstance(col_distinct, dict) and col_distinct:
            dist_summary = {}
            for col, info in col_distinct.items():
                if not isinstance(info, dict):
                    continue
                if info.get("type") == "numeric":
                    dist_summary[col] = (
                        f"numeric [{info.get('min')}..{info.get('max')}], "
                        f"{info.get('distinct')} distinct"
                    )
                else:
                    vals = info.get("values", [])
                    # #18d (triage caps 2026-06-10) — consommer TOUTES les
                    # valeurs fournies par le producteur (workbook_loader,
                    # budget _COL_DISTINCT_MAX_VALUES=30 déjà calibré) : le
                    # re-slice [:20] local créait une zone aveugle 21..30 où
                    # le LLM voyait 20 valeurs SANS marqueur (le flag
                    # ``truncated`` producteur ne s'allume qu'au-delà de 30,
                    # et le « +N autres » était calculé sur len(vals), pas sur
                    # ce qui était montré) → le LLM croyait la liste complète
                    # et générait mappings/filtres incomplets en silence.
                    # Marqueur dès que distinct > montré, calcul sur le montré.
                    distinct_total = info.get("distinct", 0) or 0
                    hidden = distinct_total - len(vals)
                    dist_summary[col] = list(vals) + (
                        [f"(+{hidden} autres)"] if hidden > 0 else []
                    )
            entry["col_distinct"] = dist_summary
            # #18f — le front (iris-grid) scanne au plus MAX_SCAN_ROWS lignes
            # pour bâtir col_distinct : au-delà, min/max/distinct sont des
            # stats de PRÉFIXE. Le dire au LLM explicitement.
            _scan = tab.get("col_distinct_scan")
            if (
                isinstance(_scan, dict)
                and isinstance(_scan.get("total"), (int, float))
                and isinstance(_scan.get("scanned"), (int, float))
                and _scan["total"] > _scan["scanned"]
            ):
                entry["col_distinct_note"] = (
                    f"⚠ stats calculées sur les {int(_scan['scanned'])} premières "
                    f"lignes sur {int(_scan['total'])} — min/max/comptes distincts "
                    "PARTIELS, ne pas les traiter comme exhaustifs"
                )
        summary.append(entry)
    return {"tabs": summary}


async def handle_list_tabs(
    _args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Retourne la liste des onglets avec métadonnées (sans le contenu).

    Thin wrapper sur ``_list_tabs_core`` — extrait le champ ``tabs_context``
    du ``CopilotContext`` et délègue à la logique pure. Cf. P2.1 refactor
    SSoT (task #12 todo Komptia, 2026-05-26).
    """
    return _list_tabs_core(ctx.tabs_context)


def _read_tab_rows_core(
    args: Dict[str, Any],
    tabs_context: List[Dict[str, Any]],
    top_level_sheet_content: Optional[List[Dict[str, Any]]] = None,
    tabs_touched: Optional[set] = None,
    include_match: bool = True,
) -> Dict[str, Any]:
    """Logique pure de ``handle_read_tab_rows`` — pas de CopilotContext requis.

    Args:
        args: payload tool_use ({tab_idx, row_start, row_end?}).
        tabs_context: la liste d'onglets (chacun dict avec sheet_content
            possiblement embedded).
        top_level_sheet_content: sheet_content du tab actif (qui n'est PAS
            stocké dans tabs_context[i].sheet_content côté copilot mais à
            l'extérieur). Pour Iris qui construit tabs_context depuis un
            upload, on peut passer ``None`` — le sheet_content vit déjà dans
            chaque tab.
        tabs_touched: set optionnel à muter pour tracking (copilot s'en
            sert pour son progress UI). Si ``None``, pas de tracking.
        include_match: si True (défaut, copilot legacy), inclut
            ``cell["match"]`` dans le retour pour exposer les dimensions
            de la row. Pour les uploads (où chaque cellule porte un
            ``match`` synthétique avec TOUTES les colonnes de la row,
            cf. C3 P2 adversarial 2026-05-26), passer ``False`` économise
            massivement de tokens LLM — un slice de 60 rows × 20 cols
            sans ``match`` ≈ 1.2K entries, AVEC ≈ 24K+ entries.

    Cf. P2.1 refactor SSoT (task #12 todo Komptia, 2026-05-26) — extraction
    pour réutilisation par le dispatcher Iris (task #13).
    """
    tab_idx = args.get("tab_idx")
    if not isinstance(tab_idx, int) or tab_idx < 0 or tab_idx >= len(tabs_context):
        return {"error": f"tab_idx {tab_idx} invalide (max {len(tabs_context) - 1})."}
    row_start = int(args.get("row_start", 0))
    row_end = args.get("row_end")
    if row_end is None:
        row_end = row_start + 59
    row_end = int(row_end)
    if row_end < row_start:
        return {"error": f"row_end ({row_end}) < row_start ({row_start})."}
    if row_end - row_start > 59:
        row_end = row_start + 59  # cap 60 rows

    tab = tabs_context[tab_idx]
    if tabs_touched is not None:
        tabs_touched.add(tab_idx)
    # L'actif (chez copilot) n'a pas son contenu dans tabs_context — il est
    # en top-level sheet_content. Pour Iris (qui build tabs_context depuis
    # un upload), le sheet_content vit dans chaque tab → on tombe sur le
    # else et tout fonctionne pareil.
    if tab.get("is_active") and top_level_sheet_content:
        source_content = top_level_sheet_content
    else:
        source_content = tab.get("sheet_content") or []

    # sheet_content est 1-based côté frontend (row = r + 1). On translate ici en
    # 0-based pour l'agent — c'est la convention de TOUS les outils copilot.
    rows_out: List[Dict[str, Any]] = []
    for cell in source_content:
        if not isinstance(cell, dict):
            continue
        r = cell.get("row")
        if not isinstance(r, int):
            continue
        r0 = r - 1  # 1-based → 0-based
        if r0 < row_start or r0 > row_end:
            continue
        entry = {
            "row": r0,
            "col": cell.get("col"),
            "value": cell.get("value"),
        }
        if include_match and cell.get("match"):
            entry["match"] = cell["match"]
        if cell.get("label"):
            entry["label"] = cell["label"]
        rows_out.append(entry)

    return {
        "tab_idx": tab_idx,
        "label": tab.get("label"),
        "row_start_0based": row_start,
        "row_end_0based": row_end,
        "cells": rows_out,
        "row_count_total": tab.get("row_count", 0),
    }


async def handle_read_tab_rows(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Retourne un slice du sheet_content de l'onglet (ou sheet_content top-level
    si l'onglet demandé est l'actif).

    Thin wrapper sur ``_read_tab_rows_core`` — passe les champs du
    ``CopilotContext`` (tabs_context, sheet_content top-level, tabs_touched).
    Cf. P2.1 refactor SSoT (task #12 todo Komptia, 2026-05-26).
    """
    return _read_tab_rows_core(
        args,
        tabs_context=ctx.tabs_context,
        top_level_sheet_content=ctx.sheet_content,
        tabs_touched=ctx.tabs_touched,
    )


def _aggregate_core(
    sheet_content: List[Any],
    match: Dict[str, Any],
    match_exclude: Dict[str, Any],
    value_column: str,
    pseudonymizer: Optional[Any] = None,
) -> Dict[str, Any]:
    """Logique pure d'aggregation, partagée entre ``handle_aggregate`` et
    (potentiellement) d'autres chemins. Pure : pas de ctx, pas d'I/O.

    Retourne aussi ``exclude_hits`` : pour chaque token de chaque clé de
    ``match_exclude``, combien de cellules ont été effectivement filtrées
    par ce token. Un token à 0 signifie qu'il ne filtre rien — la valeur
    n'existe peut-être pas sous cette forme dans les données source.
    """
    # Initialise exclude_hits avec TOUS les tokens déclarés, y compris ceux
    # qui ne matcheront rien — c'est précisément leur 0 qui est informatif.
    exclude_hits: Dict[str, Dict[Any, int]] = {}
    for col, tokens in match_exclude.items():
        if isinstance(tokens, list):
            exclude_hits[col] = {t: 0 for t in tokens}

    # Dedup exclude_hits PAR ROW (cf. P2 adversarial review C1, 2026-05-26).
    # Sur uploads (P2.2 task #13) chaque row a N cellules portant le même
    # ``match`` synthétique → sans dedup, exclude_hits était inflaté N×.
    # Pour copilot legacy (emit_tab : 1 cellule mesure/row), pas d'impact.
    excluded_rows_counted: set = set()

    total = 0.0
    hit_count = 0
    # #120 — même réconciliation que ``_recompute_emit_tab`` (SSoT
    # ``deanon_source_match``) : le ``match`` LLM est cleartext (post-_full_restore)
    # mais ``sheet_content`` est anonymisé → sans ça, ``aggregate`` (outil de pré-vol
    # du LLM) renvoie 0 SILENCIEUX sur tout classeur anonymisé. Clés utiles seulement.
    _needed_keys = set(match.keys()) | set(match_exclude.keys())
    for sc_cell in sheet_content:
        if not isinstance(sc_cell, dict):
            continue
        sc_match = sc_cell.get("match")
        if not isinstance(sc_match, dict):
            continue
        # Vue cleartext pour les comparaisons UNIQUEMENT (jamais renvoyée au LLM).
        sc_match_cmp = deanon_source_match(sc_match, pseudonymizer, _needed_keys)
        # match filter — scalaire (=) ou liste (IN)
        ok = True
        for mk, mv in match.items():
            if not _emit_tab_match_value(sc_match_cmp.get(mk), mv):
                ok = False
                break
        if not ok:
            continue
        # match_exclude filter
        excluded = False
        excluded_on_key: Optional[str] = None
        for ek, evs in match_exclude.items():
            if not isinstance(evs, list):
                continue
            if _emit_tab_in_excluded(sc_match_cmp.get(ek), evs):
                excluded = True
                excluded_on_key = ek
                break
        if excluded:
            # Incrémente le compteur sur le TOKEN DE LA LISTE exclude qui a
            # matché la valeur de la cellule — via la même sémantique d'égalité
            # tolérante (_emit_tab_scalar_eq : "FN "=="FN", 2023==2023.0, etc.)
            # que _emit_tab_in_excluded utilise pour décider de l'exclusion.
            # Sinon le compteur mentirait : exclusion effective mais tombée à
            # zéro sur la clé dict literal. Cf. BLOCKER 1 review adversariale.
            # DEDUP PAR ROW (C1 P2 adversarial, 2026-05-26) : on n'incrémente
            # qu'une seule fois par row exclue, même si la row a N cellules
            # avec le même match (cas upload). Pour copilot legacy (1 cellule
            # mesure/row), pas de changement de comportement.
            row_idx = sc_cell.get("row")
            if row_idx not in excluded_rows_counted:
                if isinstance(row_idx, int):
                    excluded_rows_counted.add(row_idx)
                if excluded_on_key is not None and excluded_on_key in exclude_hits:
                    actual = sc_match_cmp.get(excluded_on_key)
                    for token in match_exclude.get(excluded_on_key, []):
                        if _emit_tab_scalar_eq(actual, token):
                            if token in exclude_hits[excluded_on_key]:
                                exclude_hits[excluded_on_key][token] += 1
                            break
            continue
        # value_column filter
        if sc_cell.get("col") != value_column:
            continue
        val = sc_cell.get("value")
        # Passe par le chokepoint anonymisation : si la valeur est un token
        # `§...§` (cas où l'utilisateur a anonymisé une valeur numérique),
        # désanonymise avant float(). Sinon WARNING explicite — plus de
        # silent drop à la `except: continue`.
        from app.services.anonymization.pseudonymizer import coerce_to_numeric as _coerce

        numeric_val = _coerce(
            val,
            pseudonymizer=pseudonymizer,
            context_hint=f"_aggregate_core col={value_column!r}",
        )
        if numeric_val is None:
            continue
        total += numeric_val
        hit_count += 1

    out: Dict[str, Any] = {
        "total": round(total, 6),
        "hit_count": hit_count,
    }
    if exclude_hits:
        out["exclude_hits"] = exclude_hits
    return out


async def handle_search_workbook(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Recherche substring (case-insensitive) dans tous les onglets du
    classeur. Réplique le comportement du bouton 🔍 frontend
    (``_performSearch`` dans ``static/js/iris-grid.js``).

    Match sur :
    - noms de colonnes (substring)
    - valeurs des cellules dans ``sheet_content`` (cast en str)

    Cap les matches au total (``max_results``, défaut 50). Pour les onglets
    de l'actif, ``ctx.sheet_content`` est utilisé. Pour les onglets non
    actifs, ``tab["sheet_content"]`` est utilisé.
    """
    query = args.get("query")
    if not isinstance(query, str) or len(query.strip()) < 2:
        return {"error": "search_workbook: query requise (≥ 2 caractères)."}
    max_results = args.get("max_results")
    if not isinstance(max_results, int) or max_results < 1:
        max_results = 50

    q = query.strip().lower()
    groups: List[Dict[str, Any]] = []
    total_matches = 0
    truncated = False

    for tab_idx, tab in enumerate(ctx.tabs_context):
        if total_matches >= max_results:
            truncated = True
            break
        label = tab.get("label", f"tab {tab_idx}")
        columns = tab.get("columns") or []
        # Source de cellules : sheet_content du tab (ou top-level pour l'actif)
        if tab.get("is_active") and ctx.sheet_content:
            source_content = ctx.sheet_content
        else:
            source_content = tab.get("sheet_content") or []

        tab_matches: List[Dict[str, Any]] = []

        # Match sur noms de colonnes
        for c_idx, col_name in enumerate(columns):
            if total_matches + len(tab_matches) >= max_results:
                truncated = True
                break
            if isinstance(col_name, str) and q in col_name.lower():
                tab_matches.append(
                    {
                        "type": "column",
                        "col": c_idx,
                        "col_name": col_name,
                    }
                )

        # Match sur valeurs de cellules (un seul hit par row pour ne pas
        # exploser les résultats — comme le frontend qui break dans la
        # boucle col à la première match).
        rows_seen_match: set = set()
        for cell in source_content:
            if total_matches + len(tab_matches) >= max_results:
                truncated = True
                break
            if not isinstance(cell, dict):
                continue
            r = cell.get("row")
            if r in rows_seen_match:
                continue
            value = cell.get("value")
            if value is None:
                continue
            try:
                value_str = str(value).lower()
            except Exception:
                continue
            if q in value_str:
                rows_seen_match.add(r)
                tab_matches.append(
                    {
                        "type": "cell",
                        "row": r - 1 if isinstance(r, int) and r >= 1 else r,
                        "col": cell.get("col"),
                        "col_name": cell.get("col"),
                        "value": str(value)[:200],
                    }
                )

        if tab_matches:
            groups.append(
                {
                    "tab_index": tab_idx,
                    "label": label,
                    "matches": tab_matches,
                }
            )
            total_matches += len(tab_matches)

    return {
        "groups": groups,
        "truncated": truncated,
        "total_matches": total_matches,
    }


def _aggregate_from_inputs(
    args: Dict[str, Any],
    tabs_context: List[Dict[str, Any]],
    top_level_sheet_content: Optional[List[Dict[str, Any]]] = None,
    tabs_touched: Optional[set] = None,
    pseudonymizer: Optional[Any] = None,
) -> Dict[str, Any]:
    """Logique de ``handle_aggregate`` sans dépendance à ``CopilotContext``.

    Extrait pour réutilisation côté Iris (task #13). Le ``pseudonymizer`` est
    passé en paramètre explicite — copilot le récupère via ``ctx._pseudonymizer``,
    Iris via le ``Pseudonymizer`` user-scopé construit côté handler. Cf. P2.1
    refactor SSoT (task #12).
    """
    src_idx = args.get("source_tab_idx")
    if not isinstance(src_idx, int) or src_idx < 0 or src_idx >= len(tabs_context):
        return {"error": f"source_tab_idx {src_idx} invalide."}
    value_column = args.get("value_column")
    if not isinstance(value_column, str) or not value_column:
        return {"error": "value_column requis (string)."}
    match = args.get("match") or {}
    match_exclude = args.get("match_exclude") or {}
    if not isinstance(match, dict):
        return {"error": "match doit être un objet."}
    if not isinstance(match_exclude, dict):
        return {"error": "match_exclude doit être un objet."}
    # Fail-loud sur match_exclude[col] non-liste : BLOCKER 3 review. Le LLM
    # s'attend à NOT IN ; un scalaire silencieusement ignoré ment sur le total.
    for ek, evs in match_exclude.items():
        if not isinstance(evs, list):
            return {
                "error": (
                    f"match_exclude[{ek!r}] doit être une LISTE de valeurs "
                    f"(NOT IN), reçu {type(evs).__name__}. Si tu veux exclure "
                    f"une seule valeur, passe [valeur]."
                )
            }

    tab = tabs_context[src_idx]
    if tabs_touched is not None:
        tabs_touched.add(src_idx)
    sheet_content = tab.get("sheet_content") or []
    if not sheet_content and tab.get("is_active"):
        sheet_content = top_level_sheet_content or []

    result = _aggregate_core(
        sheet_content,
        match,
        match_exclude,
        value_column,
        pseudonymizer=pseudonymizer,
    )
    if "error" in result:
        return result
    result["source_tab_idx"] = src_idx
    result["value_column"] = value_column
    return result


async def handle_aggregate(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Somme les valeurs matching match/match_exclude dans un onglet source.
    Réutilise la même logique que _recompute_emit_tab pour garantir la cohérence
    des résultats entre cet outil de vérification et le recompute final.

    Thin wrapper sur ``_aggregate_from_inputs`` — cf. P2.1 refactor SSoT.
    """
    return _aggregate_from_inputs(
        args,
        tabs_context=ctx.tabs_context,
        top_level_sheet_content=ctx.sheet_content,
        tabs_touched=ctx.tabs_touched,
        pseudonymizer=getattr(ctx, "_pseudonymizer", None),
    )


def _count_rows_core(
    sheet_content: List[Any],
    match: Dict[str, Any],
    match_exclude: Dict[str, Any],
    pseudonymizer: Optional[Any] = None,
) -> Dict[str, Any]:
    """Compte les lignes distinctes matchant filters. Pas de value_column.

    Logique : chaque cellule porte sa dimension via `cell.match`. On accumule
    toutes les dimensions rencontrées par `row` pour reconstruire "la ligne
    logique", puis on filtre. Pour onglets SQL (sheet_content = cellules-mesure),
    une ligne logique = une combinaison unique de dimensions.

    Retourne aussi ``exclude_hits`` (même sémantique que _aggregate_core) :
    un token à 0 dans la réponse signifie qu'il ne filtre aucune ligne —
    utile pour détecter un token déclaré mais inutile.
    """
    # Collecte les dimensions par row pour reconstituer les lignes logiques.
    row_dims: Dict[int, Dict[str, Any]] = {}
    for sc_cell in sheet_content:
        if not isinstance(sc_cell, dict):
            continue
        r = sc_cell.get("row")
        if not isinstance(r, int):
            continue
        sc_match = sc_cell.get("match")
        if not isinstance(sc_match, dict):
            continue
        if r not in row_dims:
            row_dims[r] = {}
        # Fusionne dims (même row peut avoir plusieurs cellules avec dims partagées).
        for k, v in sc_match.items():
            row_dims[r][k] = v

    exclude_hits: Dict[str, Dict[Any, int]] = {}
    for col, tokens in match_exclude.items():
        if isinstance(tokens, list):
            exclude_hits[col] = {t: 0 for t in tokens}

    # #120 — réconciliation cleartext (SSoT ``deanon_source_match``) : sans ça,
    # ``count_rows`` (outil de pré-vol du LLM) renvoie 0 SILENCIEUX sur tout classeur
    # anonymisé (dims source tokenisés vs match LLM cleartext post-_full_restore).
    _needed_keys = set(match.keys()) | set(match_exclude.keys())
    count = 0
    for dims in row_dims.values():
        # Vue cleartext pour comparaison UNIQUEMENT (jamais renvoyée au LLM).
        dims_cmp = deanon_source_match(dims, pseudonymizer, _needed_keys)
        ok = True
        for mk, mv in match.items():
            if not _emit_tab_match_value(dims_cmp.get(mk), mv):
                ok = False
                break
        if not ok:
            continue
        excluded = False
        excluded_on_key: Optional[str] = None
        for ek, evs in match_exclude.items():
            if not isinstance(evs, list):
                continue
            if _emit_tab_in_excluded(dims_cmp.get(ek), evs):
                excluded = True
                excluded_on_key = ek
                break
        if excluded:
            # Même logique qu'_aggregate_core (BLOCKER 1 review) : match tolérant.
            if excluded_on_key is not None and excluded_on_key in exclude_hits:
                actual = dims_cmp.get(excluded_on_key)
                for token in match_exclude.get(excluded_on_key, []):
                    if _emit_tab_scalar_eq(actual, token):
                        if token in exclude_hits[excluded_on_key]:
                            exclude_hits[excluded_on_key][token] += 1
                        break
            continue
        count += 1
    out: Dict[str, Any] = {"count": count}
    if exclude_hits:
        out["exclude_hits"] = exclude_hits
    return out


def _iris_rows_to_sheet_content(
    rows: List[List[Any]],
    columns: List[str],
) -> List[Dict[str, Any]]:
    """Transforme la grille dense (columns, rows) issue d'Iris en
    ``sheet_content`` sparse au format attendu par tous les tools copilot
    (``read_tab_rows``, ``aggregate``, ``count_rows``, ``_aggregate_core``,
    ``_count_rows_core``).

    Convention : pour chaque row, on émet UNE cellule par colonne dont la valeur
    est numérique (int/float, hors bool). Le ``match`` de chaque cellule contient
    TOUTES les autres colonnes de la row (string + numériques) — ainsi le LLM
    peut filtrer indifféremment via aggregate(value_column='X', match={…}).

    Pourquoi pas "1 mesure unique" comme la fixture historique : les SQL générés
    par le LLM peuvent avoir plusieurs colonnes-mesure (totalMontant + totalBudget
    + totalSalaire). Émettre 1 cellule par colonne numérique permet au LLM
    d'agréger sur n'importe laquelle sans connaître a priori la convention.

    Cas écartés (sparse / fail-quiet) :
    * row malformée (pas list/tuple) : skip de la row entière
    * len(row) ≠ len(columns) : skip — on évite les dict(zip) tronqués qui
      perdent silencieusement des colonnes (CWE "données fausses sans erreur")
    * val None ou bool ou non-numérique : pas émis comme cellule mesure
      (mais reste exposé dans le ``match`` des autres cellules de la row)
    """
    sheet: List[Dict[str, Any]] = []
    if not columns:
        return sheet
    n_cols = len(columns)
    for r_idx, row in enumerate(rows):
        if not isinstance(row, (list, tuple)) or len(row) != n_cols:
            continue
        cells_by_col = dict(zip(columns, row))
        # 1-based pour cohérence avec convention copilot (sheet_content row=1..N).
        row_1based = r_idx + 1
        for col_name, val in cells_by_col.items():
            if isinstance(val, bool):
                continue
            # Coercion strings numériques (Decimal SQL Server sérialisé en
            # string : '70673.00', '-100.00'). Sans ce parse, le SC ne
            # contiendrait AUCUNE cellule pour les colonnes-mesure
            # — le recompute backend trouverait alors match mais
            # `value_column` jamais matché → cellules à None silencieuses.
            # Bug diagnostiqué 2026-04-27 : 0 valeurs visibles dans tous
            # les onglets RATIO2 PAP <expert> car iris_result_X.totalMontant
            # arrive en string et était skippé.
            # Symétrie avec ``_build_sheet_content_sql`` (workbook_loader)
            # qui coerce déjà.
            if not isinstance(val, (int, float)):
                if isinstance(val, Decimal):
                    # CHEMIN LIVE (#149) : ask_iris / emit_tab_via_iris exécutent
                    # un SQL frais sur Sage ; ``query_result.rows`` arrive NON
                    # sérialisé (cf. copilot_iris_bridge : rows natives) → les
                    # colonnes MONEY/NUMERIC/DECIMAL SQL Server sont des
                    # ``decimal.Decimal`` natifs, PAS des strings. Le commentaire
                    # ci-dessus (« sérialisé en string ») ne vaut QUE pour le
                    # chemin .afz.json. Sans cette branche, la cellule MESURE
                    # tombait dans le ``else: continue`` → droppée du
                    # sheet_content → aggregate/count_rows copilot FAUX
                    # silencieusement (même classe que #139/#147/#148).
                    try:
                        f = float(val)
                    except (ValueError, OverflowError):
                        continue
                    if f != f or f in (float("inf"), float("-inf")):
                        continue
                    val = f
                elif isinstance(val, str):
                    s = val.strip()
                    if not s:
                        continue
                    try:
                        # Tolère les formats Decimal SQL Server : '12345.67',
                        # '12 345.67' (espace), '12,345.67' (virgule en sep).
                        # Doit être SANS lettre — sinon c'est probablement
                        # une dimension (ex: 'BILAN', '2023/2024').
                        normalized = s.replace(" ", "").replace("\u00a0", "")
                        # On accepte virgule comme décimal, mais SI une seule
                        # virgule et pas de point. Pour éviter "1,234,567"
                        # (séparateur milliers) → on bascule en float natif
                        # si possible, sinon skip.
                        if "," in normalized and "." not in normalized:
                            normalized = normalized.replace(",", ".")
                        elif "," in normalized and "." in normalized:
                            # format anglais : "12,345.67" → drop comma
                            normalized = normalized.replace(",", "")
                        coerced = float(normalized)
                    except (ValueError, TypeError):
                        continue
                    val = coerced
                else:
                    continue
            match = {k: v for k, v in cells_by_col.items() if k != col_name}
            sheet.append(
                {
                    "row": row_1based,
                    "col": col_name,
                    "value": val,
                    "match": match,
                }
            )
    return sheet


async def handle_ask_iris(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Délègue à Iris la validation d'un SQL ; si l'exécution réussit,
    matérialise les résultats dans un **nouvel onglet** du classeur plutôt
    que de les injecter dans le contexte du LLM.

    Le bridge ``copilot_iris_bridge.ask_iris`` gère :
    - désanonymisation du draft_sql (tokens ``§…§`` → cleartext) si le
      copilot a été lancé avec pseudonymizer actif
    - validation contre INFORMATION_SCHEMA
    - exécution (timeout 30s, max_rows 1000 par défaut)
    - ré-anonymisation des rows retournées

    **Contrat de retour vers le LLM** (pas celui du bridge) :

    - ``execute=False`` (dry-run) : ``{status: "validated" | "invalid",
      sql, errors, schema_suggestions?}``. Aucun onglet créé. Utile pour
      sonder le schéma sans toucher la BDD.
    - Erreur de validation ou d'exécution : ``{status: "error", sql?,
      errors, schema_suggestions?}``. Aucun onglet créé. Le LLM
      reformule ``task`` / ``draft_sql`` et réessaie.
    - Succès : ``{status: "tab_created", tab_index, label, sql,
      columns, row_count}``. Les rows sont matérialisées dans un nouvel
      onglet ajouté à ``ctx.tabs_context`` ; le LLM le consulte ensuite
      via ``list_tabs`` / ``read_tab_rows`` / ``aggregate`` /
      ``count_rows``. Objectif : ne pas gonfler le contexte LLM avec N
      rows quand une consultation à la demande suffit.

    Le pseudonymizer actif est récupéré depuis ``ctx._pseudonymizer`` si
    l'appelant (``run_copilot_agent``) l'a attaché. Sinon passage en clair.
    """
    # [DEBUG TEMPORAIRE] Compteur de tentatives ask_iris, incrémenté dès
    # l'entrée du handler (avant validation args). Sert au guardrail
    # informationnel qui détecte 0 tentative + uncovered significatif.
    # Incrémenté qu'on ait un draft_sql valide ou pas — on veut savoir si
    # le LLM a "engagé" l'outil, même pour une tentative malformée.
    try:
        ctx._iris_call_attempts += 1
    except AttributeError:
        # Ctx issu d'un chemin qui ne serait pas passé par __init__ complet ;
        # ne bloque pas le handler sur un attribut manquant.
        pass
    task = args.get("task") or ""
    draft_sql = args.get("draft_sql") or ""
    execute = args.get("execute", True)
    # max_rows n'est plus exposé au LLM dans le schéma JSON (cf
    # copilot_tools.py : retiré du schéma 2026-04-23). 2026-05-20 :
    # default ``None`` au lieu de 1000 → utilise le cap admin
    # (``DatabaseConnection.max_rows``) au lieu de l'ignorer.
    max_rows = args.get("max_rows")

    if not isinstance(task, str):
        return {"status": "error", "errors": ["task doit être une string"]}
    if not isinstance(draft_sql, str) or not draft_sql.strip():
        return {
            "status": "error",
            "errors": ["draft_sql requis (SQL brouillon proposé par le LLM)"],
        }
    if max_rows is not None and (not isinstance(max_rows, int) or max_rows < 1):
        max_rows = None

    from app.services.ai.copilot_iris_bridge import ask_iris as _bridge_ask_iris

    pseudo = getattr(ctx, "_pseudonymizer", None)
    cache = getattr(ctx, "_iris_cache", None)
    # ``ctx.user_id`` propage au proxy du transform LLM : pseudonymizer
    # user-scoped chargé dans ``transform_sql_via_llm`` quand fourni.
    # ``None`` = caller sans user (cas système rare ici, le copilot tourne
    # toujours avec un user_id).
    # ``ctx._user`` propage l'objet ORM complet jusqu'à ``executor.execute``
    # pour activer le RLS data_access. Distinct de ``user_id`` (qui suffit
    # pour le pseudonymizer user-scoped mais pas pour le RLS).
    bridge_result = await _bridge_ask_iris(
        task=task,
        draft_sql=draft_sql,
        execute=bool(execute),
        max_rows=max_rows,
        pseudonymizer=pseudo,
        cache=cache,
        user_id=getattr(ctx, "user_id", None),
        user=getattr(ctx, "_user", None),
    )

    errors = list(bridge_result.get("errors") or [])
    schema_suggestions = bridge_result.get("schema_suggestions")
    sql_final = bridge_result.get("sql") or draft_sql
    validated = bool(bridge_result.get("validated"))
    executed = bool(bridge_result.get("executed"))
    # **Phase 2.5.ter fix BLOCKING #1 review** — Propager le marker RLS
    # remonté par le bridge. Sans cette propagation, le bloc
    # ``DATA_ACCESS_GUIDANCE`` du prompt copilot (qui matche
    # ``{success: false, blocked_by: data_access_rule}``) ne se déclenche
    # JAMAIS. Le LLM copilot voit juste ``status: error`` opaque, peut
    # re-tenter avec un nom voisin ou générer un ``emit_tab(sql=...)``
    # contenant le nom denied → leak dans le ``.afz.json``.
    blocked_by = bridge_result.get("blocked_by")
    is_data_access_denied = blocked_by == "data_access_rule"

    # Dry-run : on ne matérialise rien, on renvoie juste le verdict
    # validation (+ erreurs runtime éventuelles du dry-run).
    if not execute:
        out: Dict[str, Any] = {
            "status": "validated" if validated and not errors else "invalid",
            "sql": sql_final,
            "errors": errors,
        }
        if schema_suggestions:
            out["schema_suggestions"] = schema_suggestions
        if is_data_access_denied:
            # Marker structuré aligné sur le contrat documenté dans
            # ``agent_roles.DATA_ACCESS_GUIDANCE``.
            out["success"] = False
            out["blocked_by"] = "data_access_rule"
            out["status"] = "data_access_denied"
        return out

    # Erreur de validation ou d'exécution : pas de matérialisation.
    if not executed or not validated:
        out = {
            "status": "error",
            "sql": sql_final,
            "errors": errors or ["Exécution Iris échouée (voir logs)"],
        }
        if schema_suggestions:
            out["schema_suggestions"] = schema_suggestions
        if is_data_access_denied:
            out["success"] = False
            out["blocked_by"] = "data_access_rule"
            out["status"] = "data_access_denied"
        return out

    # Succès : on crée un nouvel onglet dans ``ctx.tabs_context`` avec les
    # rows de la requête. Le LLM verra cet onglet au prochain
    # ``list_tabs`` et pourra le consulter via ``read_tab_rows``,
    # ``aggregate``, ``count_rows``. Aucune row n'est renvoyée dans le
    # tool_result (évite de gonfler le contexte LLM — c'est précisément ce
    # que permet la matérialisation en onglet).
    columns = list(bridge_result.get("columns") or [])
    rows_raw = bridge_result.get("rows") or []
    # Coercion défensive : ``rows`` doit être une grille dense 2D (list[list])
    # pour être compatible avec les handlers qui lisent ``tab.rows``.
    rows = [list(r) for r in rows_raw if isinstance(r, (list, tuple))]
    row_count = bridge_result.get("row_count")
    if not isinstance(row_count, int):
        row_count = len(rows)

    # Matérialise les rows en ``sheet_content`` sparse — MÊME contrat que les
    # onglets SQL Komptia classiques (cf. fixture _stress_noisy_hidden_mois_ca_ec.json).
    # Les tools downstream (read_tab_rows, aggregate, count_rows, _aggregate_core,
    # _count_rows_core) lisent EXCLUSIVEMENT sheet_content avec ``cell.match``.
    # Sans cette transformation, l'onglet créé par ask_iris est invisible aux
    # outils de filtrage/aggregation, alors que le LLM y a accès via run_python
    # uniquement (asymétrie qui force des contournements). Convention : 1 cellule
    # par colonne numérique de la row ; ``match`` = toutes les AUTRES colonnes.
    sheet_content = _iris_rows_to_sheet_content(rows, columns)

    # **Cap d'accumulation par run (fix 2026-06-11, sweep Moyen confirmé)** :
    # chaque ask_iris exécuté matérialise un onglet COMPLET (jusqu'à
    # max_rows lignes) dans ctx.tabs_context + ctx.emits — sans borne, un
    # run qui enchaîne les ask_iris accumule une mémoire non bornée, des
    # list_tabs O(N) croissants et des tool_results toujours plus gros.
    # Cap dérivé de MAX_TURNS (SSoT interne — chaque matérialisation
    # consomme un tour ; en demander plus de la moitié n'a pas de sens).
    # Import LOCAL : copilot_agent importe ce module au chargement (cycle).
    from app.services.ai.copilot_agent import MAX_TURNS as _MAX_TURNS

    _max_iris_tabs = max(1, _MAX_TURNS // 2)
    if ctx._iris_tab_counter >= _max_iris_tabs:
        logger.warning(
            "ask_iris: cap d'onglets matérialisés atteint (%d) pour ce run — "
            "résultat SQL non matérialisé.",
            _max_iris_tabs,
        )
        return {
            "status": "error",
            "errors": [
                f"Limite d'onglets ask_iris atteinte ({_max_iris_tabs} par run). "
                "Réutilise les onglets déjà créés (list_tabs, read_tab_rows, "
                "aggregate) ou termine avec `done`."
            ],
        }

    ctx._iris_tab_counter += 1
    label = f"iris_result_{ctx._iris_tab_counter}"
    tab_index = len(ctx.tabs_context)
    new_tab: Dict[str, Any] = {
        "index": tab_index,
        "label": label,
        "columns": columns,
        "row_count": row_count,
        "is_active": False,
        "sql": sql_final,
        "rows": rows,
        "sheet_content": sheet_content,
    }
    ctx.tabs_context.append(new_tab)

    # Pousse l'onglet iris_result dans ``ctx.emits`` au format ``emit_tab`` afin
    # que le frontend le rende au commit final (``done``). Sans ce push, l'onglet
    # n'existait que dans la vue de l'agent (``tabs_context``) et l'utilisateur
    # ne le voyait jamais s'ajouter à la barre d'onglets — alors qu'il s'agit
    # d'une matérialisation SQL à 1000 lignes que l'utilisateur a tout intérêt
    # à pouvoir consulter / drill-downer / sauvegarder.
    # Format : même shape que ``handle_emit_tab.final_result`` pour que le
    # ``_handleMultiActionResult`` côté frontend itère uniformément.
    # Marqueur explicite : ce payload représente un résultat SQL pur (matérialisation
    # via ask_iris), pas un dashboard. Le frontend doit conserver le sql et NE PAS
    # forcer isDashboardSheet=true. Sans ce flag, _handleEmitTab traite l'onglet
    # comme un dashboard (legacy emit_tab pour transformations à cellDetails+merges)
    # et l'onglet perd ses capabilities SQL (tri, filtre, etc.).
    iris_emit_payload: Dict[str, Any] = {
        "type": "emit_tab",
        "is_sql_result": True,
        "description": f"Onglet généré par ask_iris : {label}",
        "tab": {
            "label": label,
            "columns": list(columns),
            "rows": [list(r) for r in rows],
            "sql": sql_final,
            "row_count": row_count,
        },
        "new_tab": True,
        "metrics": {
            "recompute_ms": 0,
            "recomputed": 0,
            "trusted": row_count,
            "no_source": 0,
        },
    }
    ctx.emits.append(iris_emit_payload)

    out = {
        "status": "tab_created",
        "tab_index": tab_index,
        "label": label,
        "sql": sql_final,
        "columns": columns,
        "row_count": row_count,
    }
    # ``errors`` peuvent contenir des warnings non-fatals (cf bridge) — on
    # les propage au LLM pour info, même en cas de succès.
    if errors:
        out["errors"] = errors
    return out


async def handle_modify_tab_sql(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Mute le SQL d'un onglet existant : variation via Iris puis écrasement
    en place du contenu. **Label et index préservés**. ``cellDetails``
    éventuels DROP (incohérence valeur↔SQL après mutation — principe Komptia
    "résultat faux silencieusement interdit").

    Différent d'``ask_iris`` qui crée TOUJOURS un nouvel onglet. Utilise
    ce tool quand l'utilisateur veut UN onglet final muté, pas deux
    quasi-identiques.
    """
    target_idx = args.get("target_tab_index")
    task = args.get("task") or ""
    draft_sql = args.get("draft_sql") or ""

    # Validation amont
    if not isinstance(target_idx, int) or isinstance(target_idx, bool):
        return {
            "status": "error",
            "errors": ["target_tab_index doit être un entier."],
        }
    if target_idx < 0 or target_idx >= len(ctx.tabs_context):
        return {
            "status": "error",
            "errors": [
                f"target_tab_index {target_idx} hors bornes " f"(0..{len(ctx.tabs_context) - 1})."
            ],
        }
    if not isinstance(task, str) or not task.strip():
        return {
            "status": "error",
            "errors": ["task requis (description NL de la modification)."],
        }
    target_tab = ctx.tabs_context[target_idx]
    if not isinstance(target_tab, dict):
        return {
            "status": "error",
            "errors": [f"onglet {target_idx} corrompu."],
        }
    current_sql = target_tab.get("sql") or ""
    if not current_sql and not draft_sql:
        return {
            "status": "error",
            "errors": [
                f"Onglet {target_idx} n'a pas de SQL et `draft_sql` non "
                "fourni — modify_tab_sql ne peut pas muter un dashboard "
                "pur. Utilise `ask_iris` (créera un nouvel onglet) ou "
                "fournis un `draft_sql` explicite."
            ],
        }
    if not isinstance(draft_sql, str):
        return {
            "status": "error",
            "errors": ["draft_sql doit être une string si fourni."],
        }
    # Fallback : si pas de draft fourni, on utilise le SQL actuel comme base
    if not draft_sql:
        draft_sql = current_sql

    # Délégation à Iris pour génération + validation + exécution
    from app.services.ai.copilot_iris_bridge import ask_iris as _bridge_ask_iris

    pseudo = getattr(ctx, "_pseudonymizer", None)
    cache = getattr(ctx, "_iris_cache", None)
    try:
        # max_rows=None → admin cap (cf. doctrine /admin/database).
        # Avant on hardcodait 1000 ce qui ignorait la config admin.
        bridge_result = await _bridge_ask_iris(
            task=task,
            draft_sql=draft_sql,
            execute=True,
            max_rows=None,
            pseudonymizer=pseudo,
            cache=cache,
            user_id=getattr(ctx, "user_id", None),
            user=getattr(ctx, "_user", None),
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("modify_tab_sql: bridge ask_iris a crashé")
        # ``_safe_error_message`` (CWE-209, fix 2026-06-11) : l'exception
        # vient du pipeline Iris (SQL Server pyodbc + provider LLM) — un
        # timeout/refus de connexion embarque DSN, host, voire credentials.
        # Ce message repart au LLM CLOUD en tool_result. Import LOCAL
        # (cycle bridge→copilot_agent→ce module au chargement).
        from app.services.ai.copilot_automation_bridge import _safe_error_message

        return {
            "status": "error",
            "target_tab_index": target_idx,
            "errors": [f"Erreur interne lors de l'appel Iris : {_safe_error_message(exc)}"],
        }

    errors = list(bridge_result.get("errors") or [])
    schema_suggestions = bridge_result.get("schema_suggestions")
    sql_final = bridge_result.get("sql") or draft_sql
    validated = bool(bridge_result.get("validated"))
    executed = bool(bridge_result.get("executed"))
    # Phase 2.5.ter fix BLOCKING #1 — propager le marker RLS (cf.
    # commentaire dans handle_ask_iris).
    is_data_access_denied = bridge_result.get("blocked_by") == "data_access_rule"

    # Échec validation/exécution : pas de mutation, l'onglet cible reste
    # tel quel. Le LLM voit l'erreur + suggestions pour reformuler.
    if not executed or not validated:
        out: Dict[str, Any] = {
            "status": "error",
            "target_tab_index": target_idx,
            "sql": sql_final,
            "errors": errors or ["Exécution Iris échouée (voir logs)"],
        }
        if schema_suggestions:
            out["schema_suggestions"] = schema_suggestions
        if is_data_access_denied:
            out["success"] = False
            out["blocked_by"] = "data_access_rule"
            out["status"] = "data_access_denied"
        return out

    # Succès : on ÉCRASE le contenu de l'onglet cible en préservant son
    # label + index. cellDetails volontairement DROP car incohérent avec
    # le nouveau SQL (les `match` pourraient pointer des colonnes qui
    # n'existent plus, les valeurs sommées correspondaient à l'ancien
    # filtrage, etc.). Principe Komptia : mieux vaut perdre des cellDetails
    # qu'avoir des chiffres silencieusement faux.
    columns = list(bridge_result.get("columns") or [])
    rows_raw = bridge_result.get("rows") or []
    rows = [list(r) for r in rows_raw if isinstance(r, (list, tuple))]
    row_count = bridge_result.get("row_count")
    if not isinstance(row_count, int):
        row_count = len(rows)
    label_preserved = target_tab.get("label", f"Tab {target_idx + 1}")
    sheet_content = _iris_rows_to_sheet_content(rows, columns)

    # Mute ctx.tabs_context en place — pour que les outils suivants du
    # même run (read_tab_rows, count_rows, aggregate) voient le nouveau
    # contenu IMMÉDIATEMENT (parité avec `_mirror_emit_to_tabs_context`
    # pour les emit_tab classiques).
    ctx.tabs_context[target_idx] = {
        "index": target_idx,
        "label": label_preserved,
        "columns": columns,
        "row_count": row_count,
        "is_active": target_tab.get("is_active", False),
        "sql": sql_final,
        "rows": rows,
        "sheet_content": sheet_content,
    }

    # Pousse un payload dans ctx.modifications pour que le frontend applique
    # la mutation au commit final (`done`). Type dédié `modify_tab_sql` →
    # le frontend appelle `onReplaceTabContent(target_idx, payload)` qui
    # mute l'onglet à cet index sans le supprimer/recréer (préserve
    # scroll, sélection, filtres frontend).
    #
    # **Pourquoi ctx.modifications et pas ctx.emits ?** ``ctx.emits`` est
    # réservé aux **créations d'onglets complets** (shape
    # ``{type, tab: {label, columns, rows, ...}}``) que le frontend traite
    # via ``_handleEmitTab``. Les **mutations sur onglet existant**
    # (``patch_tab``, ``rename_tab``, ``delete_tab``, ``modify_tab_sql``)
    # ont chacune un shape spécifique et sont dispatchées par ``.type``
    # dans la boucle ``modifications`` de ``_handleMultiActionResult``.
    # Régression évitée 2026-05-22 : ce payload était poussé dans
    # ``ctx.emits`` → le frontend tentait de l'interpréter comme un
    # ``emit_tab``, échouait sur ``result.tab`` absent et affichait
    # silencieusement « emit_tab: structure invalide » sans appliquer la
    # mutation à l'onglet. L'utilisateur voyait l'opération réussir
    # côté logs mais aucun changement à l'écran.
    modify_payload: Dict[str, Any] = {
        "type": "modify_tab_sql",
        "target_tab_index": target_idx,
        "label": label_preserved,
        "description": f"Modification du SQL : {label_preserved}",
        "columns": columns,
        "rows": rows,
        "sql": sql_final,
        "row_count": row_count,
    }
    ctx.modifications.append(modify_payload)

    out = {
        "status": "tab_updated",
        "target_tab_index": target_idx,
        "label": label_preserved,
        "sql": sql_final,
        "columns": columns,
        "row_count": row_count,
        "message": (
            # Rappel de protocole OBLIGATOIRE (incident 2026-06-12) : sans la
            # phrase « appelle done », ce message au passé accompli se lit
            # comme une confirmation FINALE — Haiku le relayait en texte au
            # lieu d'appeler l'outil terminal, et le run perdait tout. Les 5
            # autres outils d'action (emit_tab, patch_tab, rename_tab,
            # delete_tab, emit_via_code) portent déjà ce rappel —
            # modify_tab_sql était le SEUL sans, et l'incident est tombé
            # précisément dessus.
            f"SQL de l'onglet « {label_preserved} » mis à jour "
            f"({row_count} lignes). cellDetails éventuels ont été retirés "
            "(incohérence valeur↔SQL après mutation). Action accumulée — "
            "rien n'est livré tant que tu n'as pas clôturé : continue avec "
            "d'autres actions ou appelle `done` pour clôturer."
        ),
    }
    if errors:
        out["errors"] = errors
    return out


def _count_rows_from_inputs(
    args: Dict[str, Any],
    tabs_context: List[Dict[str, Any]],
    top_level_sheet_content: Optional[List[Dict[str, Any]]] = None,
    tabs_touched: Optional[set] = None,
    pseudonymizer: Optional[Any] = None,
) -> Dict[str, Any]:
    """Logique de ``handle_count_rows`` sans dépendance à ``CopilotContext``.

    Extrait pour réutilisation côté Iris (task #13 — `transform_uploaded_file`
    construit son propre tabs_context depuis un upload, sans CopilotContext).
    La validation des inputs + dispatch vers ``_count_rows_core`` (déjà pur)
    est partagée entre copilot et Iris. Cf. P2.1 refactor SSoT (task #12).

    ``tabs_touched`` reste optionnel : copilot s'en sert pour son progress UI,
    Iris n'en a pas besoin.
    """
    src_idx = args.get("tab_idx")
    if not isinstance(src_idx, int) or src_idx < 0 or src_idx >= len(tabs_context):
        return {"error": f"tab_idx {src_idx} invalide."}
    match = args.get("match") or {}
    match_exclude = args.get("match_exclude") or {}
    if not isinstance(match, dict):
        return {"error": "match doit être un objet."}
    if not isinstance(match_exclude, dict):
        return {"error": "match_exclude doit être un objet."}
    # Fail-loud sur match_exclude[col] non-liste : cf. BLOCKER 3 review adv.
    for ek, evs in match_exclude.items():
        if not isinstance(evs, list):
            return {
                "error": (
                    f"match_exclude[{ek!r}] doit être une LISTE de valeurs "
                    f"(NOT IN), reçu {type(evs).__name__}. Si tu veux exclure "
                    f"une seule valeur, passe [valeur]."
                )
            }

    tab = tabs_context[src_idx]
    if tabs_touched is not None:
        tabs_touched.add(src_idx)
    sheet_content = tab.get("sheet_content") or []
    if not sheet_content and tab.get("is_active"):
        sheet_content = top_level_sheet_content or []

    result = _count_rows_core(sheet_content, match, match_exclude, pseudonymizer=pseudonymizer)
    result["tab_idx"] = src_idx
    return result


async def handle_count_rows(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Compte les lignes d'un onglet qui matchent `match` / `match_exclude`.

    Alternative low-cost à `read_tab_rows` quand le LLM veut juste savoir
    "est-ce que cet onglet contient des lignes pour mon filtre ?" avant de
    décider s'il vaut la peine de consommer des tokens à lire le contenu.
    Retourne un unique entier — coût quasi-nul en tokens.

    Thin wrapper sur ``_count_rows_from_inputs`` — cf. P2.1 refactor SSoT.
    """
    return _count_rows_from_inputs(
        args,
        tabs_context=ctx.tabs_context,
        top_level_sheet_content=ctx.sheet_content,
        tabs_touched=ctx.tabs_touched,
        pseudonymizer=getattr(ctx, "_pseudonymizer", None),
    )


def _build_dense_rows(
    sheet_content: Optional[List[Dict[str, Any]]],
    columns: Optional[List[str]],
    row_count: int,
) -> List[List[Any]]:
    """Reconstruit une vue dense 2D (0-based) depuis le sheet_content sparse
    (1-based côté frontend).

    Retourne une liste de listes : `rows[r][c] = valeur` ou `None`. Complément
    du format sparse pour les onglets de type *template* (Excel, dashboard).

    Pour les onglets SQL, `sheet_content` n'émet QUE les cellules-mesure —
    les dimensions vivent dans `cell["match"]`. Construire un dense pour un
    SQL tab renverrait None sur toutes les colonnes-dim, ce qui serait
    silencieusement faux. Le caller doit donc skip cet helper sur les SQL
    tabs (cf. `_build_sandbox_tabs`).
    """
    if not isinstance(sheet_content, list) or not sheet_content:
        return []
    if not isinstance(columns, list) or not columns:
        return []
    col_idx: Dict[str, int] = {c: i for i, c in enumerate(columns) if isinstance(c, str)}
    if not col_idx:
        return []
    # max_row protège contre un row_count désaligné avec le contenu réel :
    # si une cell existe à row=100 et row_count=50, on étend plutôt que de
    # jeter silencieusement la donnée.
    max_row = 0
    for cell in sheet_content:
        if not isinstance(cell, dict):
            continue
        r = cell.get("row")
        if isinstance(r, int) and r > max_row:
            max_row = r
    try:
        nrows = max(int(row_count or 0), max_row)
    except Exception:
        nrows = max_row
    if nrows <= 0:
        return []
    rows: List[List[Any]] = [[None] * len(columns) for _ in range(nrows)]
    for cell in sheet_content:
        if not isinstance(cell, dict):
            continue
        r = cell.get("row")
        if not isinstance(r, int) or r < 1 or r > nrows:
            continue
        i = col_idx.get(cell.get("col"))
        if i is None:
            continue
        rows[r - 1][i] = cell.get("value")
    return rows


def _build_sandbox_tabs(ctx: "CopilotContext") -> List[Dict[str, Any]]:
    """Construit le snapshot ``tabs`` exposé au sandbox Python.

    Factorise la construction entre ``handle_run_python`` et
    ``handle_emit_via_code`` pour garantir la symétrie des vues : les deux
    outils voient EXACTEMENT la même donnée. Sans ce helper, un drift sur une
    seule copie produirait des vues divergentes pour le même classeur — cas
    classique de « données fausses silencieusement ».

    Deep-copy le sheet_content pour isoler les mutations sandbox de
    ``ctx.tabs_context`` (partagé avec le reste du turn). La vue dense
    ``rows`` n'est construite que pour les onglets non-SQL : pour les SQL,
    les cellules émises ne contiennent QUE les colonnes-mesure (les
    dimensions sont dans ``cell["match"]``) — une vue dense y remplirait
    les colonnes-dim de None, ce qui serait silencieusement faux.
    """
    sandbox_tabs: List[Dict[str, Any]] = []
    for i, tab in enumerate(ctx.tabs_context):
        if not isinstance(tab, dict):
            continue
        entry: Dict[str, Any] = {
            "index": i,
            "label": tab.get("label"),
            "columns": list(tab.get("columns") or []),
            "row_count": int(tab.get("row_count") or 0),
            "is_active": bool(tab.get("is_active")),
        }
        if tab.get("sql"):
            entry["sql"] = tab["sql"]
        sc = tab.get("sheet_content")
        if tab.get("is_active") and not sc:
            sc = ctx.sheet_content
        if sc:
            entry["sheet_content"] = _copy.deepcopy(sc)
            if not tab.get("sql"):
                entry["rows"] = _build_dense_rows(
                    entry["sheet_content"],
                    entry["columns"],
                    entry["row_count"],
                )
        sandbox_tabs.append(entry)
    return sandbox_tabs


def _build_emit_parsed(args: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": "emit_tab",
        "description": args.get("description")
        or f"Reconstruction via copilot : {args.get('label')}",
        "new_tab": bool(args.get("new_tab", True)),
        "tab": {k: v for k, v in args.items() if k != "new_tab"},
    }


#: Cap d'octets par VALEUR de cellule (tâche #20, review) : le cap en
#: nombre de cellules ne borne pas la mémoire — 1 cellule string de 50 Mo
#: passait (deepcopy + JSON frontend non bornés). 100k chars par valeur =
#: très au-delà de toute valeur métier légitime, et borne le payload total
#: à MAX_EMIT_CELLS × _MAX_CELL_VALUE_LEN.
_MAX_CELL_VALUE_LEN = 100_000


def _oversized_str(val: Any) -> bool:
    return isinstance(val, str) and len(val) > _MAX_CELL_VALUE_LEN


def _validate_emit_payload_size(parsed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Caps de taille sur le payload d'un emit (tâche #20).

    La génération par code (``add_cell``/``add_override``) est déjà capée
    par le sandbox (``_MAX_CELLS``/``_MAX_OVERRIDES``) — mais les args
    DIRECTS d'``emit_tab``/``preview_emit_tab`` (et le ``rows_overrides``
    statique d'``emit_via_code``) ne l'étaient pas : un payload pathologique
    (LLM bavard, prompt-injection via résultat SQL) partait en deepcopy +
    expand + recompute + miroir tabs_context + JSON frontend sans borne.
    Mêmes bornes que le sandbox (SSoT ``MAX_EMIT_CELLS``/``MAX_EMIT_OVERRIDES``).

    Sémantique (alignée sur le sandbox) : caps PAR CATÉGORIE — cellules
    (rows + sheet_content + cell_groups), cellDetails, rows_overrides ont
    chacun leur borne, comme ``_MAX_CELLS``/``_MAX_OVERRIDES`` sont
    distincts côté sandbox. Worst-case cumulé = somme des catégories.

    Double appel OBLIGATOIRE (review #20) : AVANT expand (fail-fast, pas de
    deepcopy d'un payload géant) **ET APRÈS expand** — ``cell_groups`` est
    déroulé en ``cellDetails`` PAR expand : un check uniquement pré-expand
    se faisait contourner (les cellules venaient du payload LLM, pas du
    classeur). Le re-check post-expand couvre aussi tout futur champ
    expandable. (``clone_structure_from``, lui, vient bien du classeur
    existant, borné par construction.)

    Hors périmètre documenté : la matérialisation ``ask_iris`` écrit dans
    ``ctx.emits`` sans passer ici — elle est bornée par un AUTRE mécanisme
    (cap d'onglets iris MAX_TURNS//2 + max_rows admin).

    Retourne un dict d'erreur actionnable ou ``None`` si OK.
    """
    from app.services.ai.copilot_python_sandbox import (
        MAX_EMIT_CELLS,
        MAX_EMIT_OVERRIDES,
    )

    tab = parsed.get("tab") or {}
    if not isinstance(tab, dict):
        return None  # la validation de forme en aval gérera

    rows = tab.get("rows")
    dense_cells = 0
    if isinstance(rows, list):
        for r in rows:
            if isinstance(r, list):
                dense_cells += len(r)
                if any(_oversized_str(v) for v in r):
                    return {
                        "error": (
                            f"emit refusé : une valeur de cellule dépasse "
                            f"{_MAX_CELL_VALUE_LEN} caractères. Tronque ou "
                            "agrège la donnée avant émission."
                        )
                    }
            elif _oversized_str(r):
                # Row malformée (string géante) : la validation de forme la
                # rejetterait en aval, mais APRÈS deepcopy — borne ici.
                return {
                    "error": (
                        f"emit refusé : row string de plus de "
                        f"{_MAX_CELL_VALUE_LEN} caractères (rows doit être "
                        "une liste de listes)."
                    )
                }
    sc = tab.get("sheet_content")
    sparse_cells = 0
    if isinstance(sc, list):
        sparse_cells = len(sc)
        for entry in sc:
            if isinstance(entry, dict) and _oversized_str(entry.get("value")):
                return {
                    "error": (
                        f"emit refusé : une valeur de sheet_content dépasse "
                        f"{_MAX_CELL_VALUE_LEN} caractères."
                    )
                }
    # cell_groups : déroulé en cellDetails par expand — compte les cellules
    # DÈS le pré-expand pour fail-fast (le post-expand re-vérifie de toute
    # façon via cellDetails).
    group_cells = 0
    cg = tab.get("cell_groups")
    if isinstance(cg, list):
        for g in cg:
            if isinstance(g, dict) and isinstance(g.get("cells"), dict):
                group_cells += len(g["cells"])
    total_cells = dense_cells + sparse_cells + group_cells
    if total_cells > MAX_EMIT_CELLS:
        return {
            "error": (
                f"emit refusé : {total_cells} cellules (rows + sheet_content "
                f"+ cell_groups), cap {MAX_EMIT_CELLS}. Découpe en plusieurs "
                "onglets/emits, ou agrège les données avant émission."
            )
        }
    cd = tab.get("cellDetails")
    if isinstance(cd, dict) and len(cd) > MAX_EMIT_CELLS:
        return {
            "error": (
                f"emit refusé : {len(cd)} cellDetails, cap {MAX_EMIT_CELLS}. "
                "Ne détaille que les cellules qui en ont besoin."
            )
        }
    ov = tab.get("rows_overrides")
    if isinstance(ov, dict):
        if len(ov) > MAX_EMIT_OVERRIDES:
            return {
                "error": (
                    f"emit refusé : {len(ov)} rows_overrides, cap "
                    f"{MAX_EMIT_OVERRIDES}. Découpe en plusieurs emits."
                )
            }
        if any(_oversized_str(v) for v in ov.values()):
            return {
                "error": (
                    f"emit refusé : une valeur de rows_overrides dépasse "
                    f"{_MAX_CELL_VALUE_LEN} caractères."
                )
            }
    return None


#: Caps défensifs sur sort_by — empêche un payload pathologique (LLM
#: bavard, prompt injection via résultat SQL) de causer un O(N×M) coûteux.
#: 8 colonnes de tri = équivalent SQL pratique (ORDER BY > 8 cols est rare).
#: 256 chars/column = largement suffisant pour des noms de colonnes Sage.
_SORT_BY_MAX_COLUMNS = 8
_SORT_BY_MAX_COLUMN_NAME_LEN = 256


def _validate_sort_by_spec(
    sort_by: Any,
    columns: List[str],
    has_derived_formula: bool,
    has_merges: bool,
) -> Optional[Dict[str, Any]]:
    """Valide la spec ``sort_by`` SANS exécuter le tri. Appelé en pre-recompute
    pour fail-fast sur input malformé (évite de gaspiller du CPU à recomputer
    un tab qui sera rejeté).

    Retourne un dict d'erreur ou ``None`` si OK.
    """
    if not sort_by:
        return None
    if not isinstance(sort_by, list):
        return {"error": "sort_by doit être une liste de {column, direction}."}
    if len(sort_by) > _SORT_BY_MAX_COLUMNS:
        return {
            "error": (
                f"sort_by accepte au plus {_SORT_BY_MAX_COLUMNS} colonnes "
                f"(reçu {len(sort_by)}). Réduis le nombre de colonnes triées."
            )
        }
    if has_merges:
        return {
            "error": (
                "sort_by incompatible avec merges : la permutation des rows "
                "briserait les rectangles de fusion. Supprime les merges "
                "OU retire sort_by."
            )
        }
    if has_derived_formula:
        # Les ``derived_formula.refs`` ("R,C") pointent par index — un tri
        # change les index sans remapper les refs, ce qui produirait des
        # valeurs et drill-down SQL silencieusement faux. Refus explicite
        # tant qu'un remap des refs n'est pas implémenté + testé.
        return {
            "error": (
                "sort_by incompatible avec derived_formula : les refs "
                'internes ("R,C") pointent par index et ne sont pas '
                "remappées par le tri, ce qui produirait des calculs et "
                "drill-down SQL silencieusement faux. Retire derived_formula "
                "OU sort_by."
            )
        }
    for spec in sort_by:
        if not isinstance(spec, dict):
            return {
                "error": (
                    f"sort_by item invalide : {spec!r} (attendu dict " f"{{column, direction?}})."
                )
            }
        col = spec.get("column")
        direction_raw = spec.get("direction", "asc")
        if not isinstance(direction_raw, str):
            return {
                "error": (
                    f"sort_by.direction doit être 'asc' ou 'desc' " f"(reçu {direction_raw!r})."
                )
            }
        direction = direction_raw.lower().strip()
        if direction not in ("asc", "desc"):
            return {
                "error": (
                    f"sort_by.direction invalide : {direction_raw!r} " f"(attendu 'asc' ou 'desc')."
                )
            }
        if not isinstance(col, str):
            return {"error": f"sort_by.column doit être string (reçu {type(col).__name__})."}
        if len(col) > _SORT_BY_MAX_COLUMN_NAME_LEN:
            return {
                "error": (
                    f"sort_by.column trop long : {len(col)} chars "
                    f"(max {_SORT_BY_MAX_COLUMN_NAME_LEN})."
                )
            }
        if col not in columns:
            return {
                "error": (
                    f"sort_by.column inconnue : {col!r} (colonnes " f"disponibles : {columns})."
                )
            }
    return None


def _apply_sort_by_to_tab(tab: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Applique le tri ``sort_by`` aux rows d'un tab APRÈS recompute des
    cellDetails. Permute aussi les clés ``cellDetails`` pour préserver le
    mapping cell → metadata. Retourne un dict d'erreur ou ``None`` si OK.

    Le helper est appelé par ``handle_emit_tab`` et ``handle_emit_via_code``
    après ``_recompute_emit_tab`` pour garantir que les valeurs triées sont
    les valeurs finales (sommées, pas les placeholders LLM).

    Pré-validation côté caller via ``_validate_sort_by_spec`` (gates :
    merges, derived_formula, format, cap len). Le helper re-valide
    minimalement (col existe, direction) en cas d'appel direct.

    Sémantique :
    - ``sort_by`` absent ou vide → no-op
    - Multi-colonnes : tri stable cumulé en ordre inverse (col2 d'abord puis
      col1 — comme SQL ``ORDER BY col1, col2``). Python sort est stable.
    - NULLS LAST dans les 2 directions : partitionnement non-null/null
      explicite, le null part toujours à la fin
    - Types mixtes (string + int) → fallback en string (pas d'exception)
    - ``cellDetails`` est remappé : ancienne clé "old_r,c" → "new_r,c"
    """
    sort_by = tab.get("sort_by")
    if not sort_by:
        return None
    if not isinstance(sort_by, list):
        return {"error": "sort_by doit être une liste de {column, direction}."}
    columns = tab.get("columns") or []
    rows = tab.get("rows") or []
    if not rows:
        return None
    if tab.get("merges"):
        return {
            "error": (
                "sort_by incompatible avec merges : la permutation des rows "
                "briserait les rectangles de fusion. Supprime les merges "
                "OU retire sort_by."
            )
        }

    # Validation + traduction en (col_index, reverse) — fail-fast sur input.
    # En cas d'appel via handle_emit_tab/handle_emit_via_code, la validation
    # est déjà passée via _validate_sort_by_spec mais on garde la double
    # check ici pour les appels directs (tests, scripts).
    sort_specs: List[tuple] = []
    for spec in sort_by:
        if not isinstance(spec, dict):
            return {
                "error": (
                    f"sort_by item invalide : {spec!r} (attendu dict " f"{{column, direction?}})."
                )
            }
        col = spec.get("column")
        direction_raw = spec.get("direction", "asc")
        if not isinstance(direction_raw, str):
            return {
                "error": (
                    f"sort_by.direction doit être 'asc' ou 'desc' " f"(reçu {direction_raw!r})."
                )
            }
        direction = direction_raw.lower().strip()
        if direction not in ("asc", "desc"):
            return {
                "error": (
                    f"sort_by.direction invalide : {direction_raw!r} " f"(attendu 'asc' ou 'desc')."
                )
            }
        if not isinstance(col, str) or col not in columns:
            return {
                "error": (
                    f"sort_by.column inconnue : {col!r} (colonnes " f"disponibles : {columns})."
                )
            }
        sort_specs.append((columns.index(col), direction == "desc"))

    # Tri stable multi-colonnes : itérer en ordre inverse (Python sort
    # stable préserve l'ordre précédent pour les égalités).
    indexed = list(enumerate(rows))  # [(old_idx, row), ...]
    for col_idx, reverse in reversed(sort_specs):

        def _val(item: tuple, _idx: int = col_idx) -> Any:
            r = item[1]
            return r[_idx] if _idx < len(r) else None

        non_null = [it for it in indexed if _val(it) is not None]
        null_part = [it for it in indexed if _val(it) is None]
        try:
            non_null.sort(key=lambda it: _val(it), reverse=reverse)
        except TypeError:
            # Types mixtes incomparables (str vs int) — fallback string.
            # Pas idéal mais préserve une sortie déterministe vs raise.
            non_null.sort(key=lambda it: str(_val(it)), reverse=reverse)
        # NULLS LAST : les null vont toujours en fin, peu importe direction
        indexed = non_null + null_part

    permutation = [old_idx for old_idx, _ in indexed]
    tab["rows"] = [rows[i] for i in permutation]

    # Remap cellDetails clés "R,C" → "newR,C" (la colonne ne change pas).
    cd = tab.get("cellDetails") or {}
    if cd:
        old_to_new = {old_r: new_r for new_r, old_r in enumerate(permutation)}
        new_cd: Dict[str, Any] = {}
        for key, val in cd.items():
            if not isinstance(key, str):
                new_cd[key] = val
                continue
            parts = key.split(",", 1)
            if len(parts) != 2:
                new_cd[key] = val
                continue
            try:
                old_r = int(parts[0].strip())
            except ValueError:
                new_cd[key] = val
                continue
            new_r = old_to_new.get(old_r)
            if new_r is None:
                # cellDetails pointant une row hors du tab — préserve telle
                # quelle (sera ignoré au render, mais on ne perd pas de data).
                new_cd[key] = val
            else:
                new_cd[f"{new_r},{parts[1].strip()}"] = val
        tab["cellDetails"] = new_cd

    return None


# Nombre max de tabs candidats retournés par position uncovered. Cap
# défensif contre l'empoisonnement sur gros classeurs : si 20 tabs
# partagent tous `exercice`, on ne renvoie que les N meilleurs (plus
# grand overlap d'abord) — évite que le LLM ne pick le tab[0] par biais
# de position quand la liste est longue.
_CANDIDATE_SOURCE_TABS_CAP = 5


def _extract_columns_as_list(tab: Dict[str, Any]) -> List[str]:
    """Extrait les noms de colonnes d'un tab, tolérant aux formes hétérogènes.

    Accepte :
    - `tab["columns"]` = list[str] (forme canonique)
    - `tab["columns"]` = dict {col_name: type} (certains producteurs SQL)
    - `tab["columns"]` = tuple (converti en list)

    Retourne `[]` pour toute forme non reconnue. Pas de log : le helper
    est appelé sur des tabs anonymisés, on n'a pas de signal utilisable
    en DEBUG sans surface exposée.
    """
    cols = tab.get("columns")
    if cols is None:
        return []
    if isinstance(cols, list):
        return [c for c in cols if isinstance(c, str)]
    if isinstance(cols, tuple):
        return [c for c in cols if isinstance(c, str)]
    if isinstance(cols, dict):
        return [c for c in cols.keys() if isinstance(c, str)]
    return []


def _compute_uncovered_with_candidates(
    rows: List[List[Any]],
    nrows: int,
    ncols: int,
    cell_details: Dict[str, Any],
    template_positions: List[str],
    tabs_context: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Construit la liste `uncovered_template_positions` retournée au LLM.

    Pour chaque position numérique du template qui reste à None après
    recompute, retourne un dict avec :
    - `pos` (ex: "7,3")
    - `row_label` (optionnel) : valeur textuelle de col 0 de la row, non
      interprétée. Cap 200 chars.
    - `candidate_source_tabs` (optionnel) : indices de tabs, triés par
      score (nombre de keys-dimensions en overlap avec les cellDetails
      voisines), cap `_CANDIDATE_SOURCE_TABS_CAP`. Match mécanique sur
      les NOMS DE COLONNES ; ne lit ni ne matche les valeurs.
      **Piste structurelle**, pas verdict : le tab peut ne pas contenir
      les valeurs pour la combinaison précise — le LLM confirme via
      `count_rows`/`aggregate`. Le tri par score réduit le biais
      position-1er (un tab matchant 2 dims passe devant un qui n'en
      matche qu'une).
    - `candidate_source_dimensions` (optionnel) : noms de colonnes qui
      ont servi à sélectionner les candidats — auditable.
    - `reference_sqls` (optionnel) : parmi les candidats, ceux qui
      exposent un attribut `sql` (= onglets SQL issus d'un
      ``emit_tab(sql=…)`` ou ``ask_iris``). Chaque entrée :
      ``{tab_idx, tab_label, sql, shared_dims, missing_dims}``.
      Donne au LLM un ``draft_sql`` prêt-à-l'emploi pour ``ask_iris``
      quand une variation (GROUP BY différent, filtre en plus, colonne
      dérivée) transformerait ce SQL en la donnée manquante. Générique :
      aucun nom de tab ou de colonne hardcodé, ne s'active que si un
      candidat expose effectivement un `sql`. Absent si aucun candidat
      n'a de SQL exposé.

    Edge cases :
    - cellules sans cellDetails voisin posé → union_keys vide → aucun
      candidat (aide arrive quand le LLM a commencé à poser ; au premier
      preview d'un template vide, la liste est naturellement absente).
    - `tabs_context` None/malformé → candidats ignorés, uncovered remonté.
    - `tab.columns` = dict/tuple/autre → `_extract_columns_as_list` gère.
    - `detail.match` non-dict ou `detail_key` non-parseable → ignoré.
    - Aucun candidat n'expose de `sql` (cas classeur sans onglet SQL) →
      `reference_sqls` absent, pas de régression.
    """
    uncovered: List[Dict[str, Any]] = []
    if not template_positions:
        return uncovered

    # Pré-calcul des KEYS de match utilisées par row/col dans les cellDetails
    # déjà posés. Purement structurel (noms de dimensions).
    row_neighbor_keys: Dict[int, set] = {}
    col_neighbor_keys: Dict[int, set] = {}
    for detail_key, detail in (cell_details or {}).items():
        if not isinstance(detail, dict):
            continue
        try:
            dr_str, dc_str = str(detail_key).split(",", 1)
            dr, dc = int(dr_str.strip()), int(dc_str.strip())
        except (ValueError, AttributeError):
            continue
        match_dict = detail.get("match") if isinstance(detail.get("match"), dict) else {}
        if not match_dict:
            continue
        keys = set(match_dict.keys())
        row_neighbor_keys.setdefault(dr, set()).update(keys)
        col_neighbor_keys.setdefault(dc, set()).update(keys)

    for pos in template_positions:
        try:
            r_str, c_str = pos.split(",", 1)
            r, c = int(r_str.strip()), int(c_str.strip())
        except (ValueError, AttributeError):
            continue
        if r < 0 or r >= nrows or c < 0 or c >= ncols:
            continue
        if rows[r][c] is not None:
            continue

        entry: Dict[str, Any] = {"pos": pos}
        row_label_val = rows[r][0] if len(rows[r]) > 0 else None
        if isinstance(row_label_val, str):
            stripped = row_label_val.strip()
            if stripped:
                if len(stripped) > 200:
                    stripped = stripped[:200] + "…"
                entry["row_label"] = stripped

        union_keys = row_neighbor_keys.get(r, set()) | col_neighbor_keys.get(c, set())
        if union_keys and isinstance(tabs_context, list):
            # Score chaque tab par nombre de keys-dims en overlap. Trie
            # descendant → meilleure piste en tête. Tie-break : index asc
            # (déterministe, évite qu'un même preview produise deux sorties
            # différentes selon implémentation de sort).
            scored: List[tuple] = []
            for tab_idx, tab in enumerate(tabs_context):
                if not isinstance(tab, dict):
                    continue
                tab_cols = _extract_columns_as_list(tab)
                if not tab_cols:
                    continue
                overlap = sum(1 for k in union_keys if k in tab_cols)
                if overlap > 0:
                    scored.append((overlap, tab_idx))
            if scored:
                scored.sort(key=lambda t: (-t[0], t[1]))
                top = scored[:_CANDIDATE_SOURCE_TABS_CAP]
                entry["candidate_source_tabs"] = [idx for _, idx in top]
                entry["candidate_source_dimensions"] = sorted(union_keys)
                if len(scored) > _CANDIDATE_SOURCE_TABS_CAP:
                    entry["candidate_source_tabs_truncated_from"] = len(scored)

                # Pour chaque candidat qui expose un `sql` (onglet SQL
                # issu d'un ``emit_tab(sql=…)`` ou ``ask_iris``), joint
                # le SQL en clair + les dims en commun / manquantes.
                # Objectif : donner au LLM un ``draft_sql`` prêt-à-
                # l'emploi pour ``ask_iris`` quand une variation
                # (GROUP BY, filtre, colonne dérivée) transformerait ce
                # SQL en la donnée voulue — supprime l'étape "trouver une
                # piste SQL" que le LLM a du mal à franchir subjectivement.
                # Générique : aucun nom de tab/colonne hardcodé, activation
                # conditionnelle au fait qu'un candidat expose `sql`.
                reference_sqls: List[Dict[str, Any]] = []
                for _, cand_idx in top:
                    cand_tab = tabs_context[cand_idx]
                    if not isinstance(cand_tab, dict):
                        continue
                    cand_sql = cand_tab.get("sql")
                    if not isinstance(cand_sql, str) or not cand_sql.strip():
                        continue
                    cand_cols_set = set(_extract_columns_as_list(cand_tab))
                    reference_sqls.append(
                        {
                            "tab_idx": cand_idx,
                            "tab_label": cand_tab.get("label"),
                            "sql": cand_sql,
                            "shared_dims": sorted(union_keys & cand_cols_set),
                            "missing_dims": sorted(union_keys - cand_cols_set),
                        }
                    )
                if reference_sqls:
                    entry["reference_sqls"] = reference_sqls
        uncovered.append(entry)

    return uncovered


_UNCOVERED_WARNING_BODY = (
    "Voir `uncovered_template_positions` (chaque entrée : `pos`, "
    "`row_label`? issu de col 0, et `candidate_source_tabs`? = tabs "
    "dont `columns` contient au moins une dimension déjà utilisée par "
    "les cellDetails **voisines déjà posées** — purement structurel, "
    "trié par nombre de dimensions en commun décroissant, cappé à 5). "
    "**Les candidats sont des pistes, pas des verdicts** : un tab "
    "listé peut ne pas avoir les valeurs voulues pour cette combinaison "
    "précise — confirme avec `count_rows(idx, match=…)` ou `aggregate(…)`, "
    "et regarde aussi les tabs hors liste s'ils te semblent pertinents. "
    "Si tu n'as posé aucun cellDetails voisin encore, la liste peut être "
    "absente (rien à déduire par analogie) ; commence par quelques "
    "positions sûres puis re-preview. **`reference_sqls`** (si présent) "
    "expose le `sql` brut des candidats qui en ont un, avec `shared_dims` "
    "/ `missing_dims` : si `missing_dims` est non-vide, `ask_iris(task, "
    "draft_sql=<sql>)` avec une `task` qui décrit la variation voulue "
    "(GROUP BY élargi, filtre supplémentaire, colonne dérivée) reconstruit "
    "souvent la source en un appel. Plusieurs leviers coexistent pour "
    "chaque position non couverte, sans ordre de préférence : cellDetails "
    "pointant vers un tab (candidat ou non), `cell_groups` combinant "
    "plusieurs sources, `derived_formula` calculant depuis des cellules "
    "déjà remplies, `ask_iris(draft_sql)` pour reconstruire une source "
    "absente, `run_python` + `add_override` pour un calcul programmatique, "
    "ou laisser vide si la donnée n'existe vraiment pas. À toi de juger "
    "selon la sémantique de la cellule ; le bon levier n'est pas toujours "
    "le premier de la liste."
)


def _uncovered_has_reference_sqls(uncovered: List[Dict[str, Any]]) -> bool:
    """[DEBUG TEMPORAIRE] True si au moins une position uncovered expose un
    ``reference_sqls`` non-vide. Détecteur pur, pas de side-effect."""
    return any(u.get("reference_sqls") for u in (uncovered or []))


def _build_iris_refusal_interview_prompt(ctx: "CopilotContext") -> str:
    """[DEBUG TEMPORAIRE — à retirer quand debug terminé]

    Construit le message utilisateur posé en **interview post-run** :
    le LLM a terminé son run, le terminal_result est figé, l'interview
    est un appel LLM séparé dont la réponse est capturée dans
    ``llm_log.md``. Le LLM n'a pas vu cette question pendant le run —
    son comportement n'est pas influencé par l'instrumentation.

    Format imposé (template ``JE N'UTILISE PAS ASK_IRIS POUR CES
    POSITIONS CAR…``) pour faciliter la capture : un grep sur le log
    remonte les explications d'un run.

    À RETIRER (helper + compteur ``_iris_call_attempts`` + flag
    ``_iris_debug_needs_interview`` + logique d'interview dans
    ``run_copilot_agent``) une fois le comportement diagnostiqué.
    """
    attempts = getattr(ctx, "_iris_call_attempts", 0)
    if attempts == 0:
        context_phrase = (
            "Tu n'as **jamais** appelé `ask_iris` dans ce run, alors que "
            "certaines positions non couvertes exposaient des SQL de "
            "référence qu'une variation aurait pu transformer en la donnée "
            "manquante."
        )
    else:
        context_phrase = (
            f"Tu as appelé `ask_iris` {attempts} fois dans ce run, mais "
            "certaines positions restent non couvertes malgré des SQL de "
            "référence disponibles pour elles."
        )
    return (
        "🔍 INTERVIEW DE DEBUG — LE RUN EST TERMINÉ, CECI EST UNE QUESTION "
        "SURPRISE POSTÉRIEURE\n"
        "\n"
        f"{context_phrase}\n"
        "\n"
        "Explique ta décision en suivant EXACTEMENT ce format (remplace les "
        "«…» par ta réponse concrète) :\n"
        "\n"
        "```\n"
        "JE N'UTILISE PAS ASK_IRIS POUR CES POSITIONS CAR :\n"
        "  (1) SQL de référence inadaptés : [oui / non]. Si oui, en quoi concrètement ? …\n"
        "  (2) Variation SQL infaisable : [oui / non]. Si oui, quelle variation et pourquoi infaisable ? …\n"
        "  (3) Autre levier préféré : [oui / non]. Si oui, lequel et en quoi est-il supérieur à ask_iris ici ? …\n"
        "  (4) Manque de confiance dans l'outil ask_iris : [oui / non]. Si oui, qu'est-ce qui te fait hésiter ? …\n"
        "  (5) Autre raison : …\n"
        "```\n"
        "\n"
        "Cette interview ne modifie PAS ton résultat — le tab est déjà émis. "
        "Elle sert à l'équipe à comprendre pourquoi `ask_iris` est évité "
        "dans ce type de situation, pour améliorer le produit."
    )


# Seuil minimum de cellules partageant exactement les mêmes attributs pour
# déclencher un factorization_hint. 2 = toute duplication détectée — le LLM
# lit le count et juge si la factorisation vaut la peine. Garde la décision
# à sa main plutôt que d'imposer un chiffre magique (review : "pourquoi 4 ?").
_FACTORIZATION_HINT_MIN_COUNT = 2
# Cap de positions montrées dans chaque hint (les exemples suffisent).
_FACTORIZATION_HINT_EXAMPLES_CAP = 5
# Cap total de hints retournés pour ne pas gonfler le payload sur un
# classeur à patterns multiples.
_FACTORIZATION_HINTS_CAP = 8


def _factorization_signature(detail: Dict[str, Any]) -> Optional[tuple]:
    """Construit une clé hashable capturant le triplet factorisable d'un
    cellDetail. Retourne None si le cellDetail n'a aucun des attributs
    pertinents (ex: cellule purement dérivée via derived_formula), ou si
    la structure contient des éléments non-hashables (list/dict imbriqués
    dans match_exclude, improbable mais possible si le LLM hallucine)."""
    src = detail.get("source_tab_index")
    vcol = detail.get("value_column")
    mexc = detail.get("match_exclude")
    # Si aucun des 3 n'est posé, rien à factoriser.
    if src is None and not vcol and not mexc:
        return None
    mexc_sig: tuple = ()
    if isinstance(mexc, dict) and mexc:
        items = []
        try:
            for k in sorted(mexc.keys()):
                v = mexc[k]
                if isinstance(v, list):
                    # Si l'un des éléments de la liste n'est pas hashable
                    # (ex: dict imbriqué), le tuple crashera à l'insertion dans
                    # groups (clé dict). On preempt avec un hash explicite.
                    items.append((k, tuple(v)))
                else:
                    items.append((k, (v,)))
            mexc_sig = tuple(items)
            # Vérifier que la signature est hashable (ex: tuple contenant un
            # dict lèverait TypeError au setdefault).
            hash((src, vcol, mexc_sig))
        except TypeError:
            return None
    return (src, vcol, mexc_sig)


def _compute_factorization_hints(cd: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Détecte les groupes de ≥N cellDetails partageant exactement la même
    combinaison (source_tab_index, value_column, match_exclude).

    Retourne une liste de hints `{count, shared: {...}, example_positions: [...]}`.
    Purement indicatif — le LLM décide s'il veut factoriser via cell_groups.
    """
    if not isinstance(cd, dict) or not cd:
        return []
    groups: Dict[tuple, List[str]] = {}
    shared_by_sig: Dict[tuple, Dict[str, Any]] = {}
    for pos, detail in cd.items():
        if not isinstance(detail, dict):
            continue
        sig = _factorization_signature(detail)
        if sig is None:
            continue
        groups.setdefault(sig, []).append(pos)
        if sig not in shared_by_sig:
            shared: Dict[str, Any] = {}
            if detail.get("source_tab_index") is not None:
                shared["source_tab_index"] = detail["source_tab_index"]
            if detail.get("value_column"):
                shared["value_column"] = detail["value_column"]
            mexc = detail.get("match_exclude")
            if isinstance(mexc, dict) and mexc:
                # deepcopy pour éviter qu'une mutation du cellDetail source
                # (par un autre chemin, ou par une re-preview après
                # modification) ne fuie dans le hint déjà retourné. Cf.
                # review HIGH 6 — pas de référence partagée implicite.
                shared["match_exclude"] = _copy.deepcopy(mexc)
            shared_by_sig[sig] = shared
    hints: List[Dict[str, Any]] = []
    for sig, positions in groups.items():
        if len(positions) < _FACTORIZATION_HINT_MIN_COUNT:
            continue
        hints.append(
            {
                "count": len(positions),
                "shared": shared_by_sig[sig],
                "example_positions": sorted(positions)[:_FACTORIZATION_HINT_EXAMPLES_CAP],
            }
        )
    # Plus gros groupe d'abord, cap global pour ne pas gonfler.
    hints.sort(key=lambda h: h["count"], reverse=True)
    return hints[:_FACTORIZATION_HINTS_CAP]


async def handle_preview_emit_tab(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Simule un emit_tab sans commit. Le LLM peut voir les warnings puis itérer."""
    parsed = _build_emit_parsed(args)
    # Cap de taille AVANT la deepcopy (tâche #20) : pas de copie d'un
    # payload pathologique. Preview = pas de terminal_kind.
    size_err = _validate_emit_payload_size(parsed)
    if size_err:
        return {"ok": False, **size_err, "stage": "size"}
    # Travailler sur une COPY pour ne pas muter l'agent context pendant preview
    parsed_copy = _copy.deepcopy(parsed)
    expand_err = _expand_emit_tab(parsed_copy, ctx.tabs_context, ctx.sheet_content)
    if expand_err:
        return {"ok": False, **expand_err, "stage": "expand"}
    # Re-check POST-expand (review #20) : cell_groups → cellDetails.
    size_err = _validate_emit_payload_size(parsed_copy)
    if size_err:
        return {"ok": False, **size_err, "stage": "size"}
    val_err = _validate_emit_tab(parsed_copy, ctx.tabs_context)
    if val_err:
        return {"ok": False, **val_err, "stage": "validate"}
    parsed_copy = _recompute_emit_tab(
        parsed_copy,
        ctx.tabs_context,
        pseudonymizer=getattr(ctx, "_pseudonymizer", None),
    )
    m = parsed_copy.get("_recompute_metrics") or {}
    tab = parsed_copy["tab"]
    rows = tab.get("rows") or []
    nrows = len(rows)
    ncols = len(tab.get("columns") or [])
    cd = tab.get("cellDetails") or {}
    # Quelques métriques utiles pour guider le LLM
    zero_cells = 0
    none_cells = 0
    for key in cd:
        try:
            r, c = key.split(",", 1)
            r, c = int(r.strip()), int(c.strip())
        except (ValueError, AttributeError):
            continue
        if r < 0 or r >= nrows or c < 0 or c >= ncols:
            continue
        v = rows[r][c]
        if v is None:
            none_cells += 1
        elif isinstance(v, (int, float)) and not isinstance(v, bool) and v == 0:
            zero_cells += 1
    warnings: List[str] = []
    total_cd = len(cd)
    if m.get("no_source", 0) > 0:
        warnings.append(
            f"⚠️ {m['no_source']} cellule(s) avec cellDetails n'ont trouvé AUCUNE "
            "ligne source matchant leur `match` — valeur LLM conservée telle quelle. "
            "Vérifie que `source_tab_index` pointe vers le bon onglet et que les "
            "clés de `match` existent bien comme colonnes-dimensions."
        )
    if zero_cells > 0:
        warnings.append(
            f"ℹ️ {zero_cells} cellule(s) ont calculé 0.0 — soit pas de data, soit "
            "un match trop restrictif (combinaison de filtres trop étroite)."
        )
    # Bug fix (2026-04-17) : comparaison `none_cells > cd` (int > dict)
    # levait TypeError à chaque preview, ce qui faisait dégrader la stratégie
    # du LLM. Remplacé par un ratio None/total explicite.
    if total_cd > 0 and none_cells > 0:
        ratio = none_cells / total_cd
        if ratio > 0.3:
            warnings.append(
                f"⚠️ {none_cells}/{total_cd} cellules cellDetails ({ratio:.0%}) "
                "restent à None — match invalide ou source_tab_index incorrect ?"
            )

    # Coverage checker structurel : positions du template qui avaient une valeur
    # numérique (AVANT wipe) et qui ne sont actuellement pas remplies. Purement
    # structurel — aucun scan de labels, aucun jugement métier. Marche sur
    # n'importe quel template cloné.
    #
    # Chaque position non couverte est enrichie avec le label de col 0 (si
    # string non-vide) — aide le LLM à réaliser "j'ai raté tous les 'Avancement'"
    # sans qu'on lui dicte aucune règle métier. Purement structurel : on lit
    # juste rows[r][0] de la ligne en question. Marche sur un classeur compta
    # ou un classeur e-commerce — le label est ce qu'il est.
    coverage_meta = parsed_copy.get("_coverage_meta") or {}
    template_positions: List[str] = coverage_meta.get("template_numeric_positions", [])
    uncovered = _compute_uncovered_with_candidates(
        rows,
        nrows,
        ncols,
        cd,
        template_positions,
        ctx.tabs_context,
    )
    if uncovered:
        count = len(uncovered)
        total = len(template_positions)
        warnings.append(
            f"⚠️ Couverture incomplète : {count}/{total} positions numériques "
            f"du template clone ne sont pas remplies. " + _UNCOVERED_WARNING_BODY
        )
    # [DEBUG TEMPORAIRE] Mémorise si la condition d'interview debug est
    # remplie — l'interview est posée en fin de run par ``run_copilot_agent``
    # pour ne PAS influencer le comportement du LLM pendant le run. Signal
    # stocké sur ctx, pas exposé au LLM ici.
    if _uncovered_has_reference_sqls(uncovered):
        ctx._iris_debug_needs_interview = True

    # no_source_hints : diagnostic enrichi des cellules qui n'ont matché aucune
    # ligne source. Expose POURQUOI (valeur absente de col_distinct, clé
    # inconnue, numérique hors range) pour que le LLM corrige au lieu de
    # committer des cellules qui utilisent une surface form absente de la
    # data (typo, label humain ≠ code data, etc.).
    # Pur signal — ne bloque pas. Groupé par signature de match (dédup).
    no_source_hints = m.get("no_source_hints") or []
    if no_source_hints:
        # Remonte un warning qui pointe spécifiquement vers les hints
        example_pairs: List[str] = []
        for h in no_source_hints[:2]:
            for err in h.get("errors", []):
                if err.get("reason") == "value_not_in_source":
                    mk = err.get("match_key")
                    mv = err.get("match_value")
                    closest = err.get("closest_values") or []
                    if mk and closest:
                        example_pairs.append(f"match.{mk}={mv!r} → proche de {closest[0]!r}")
                        break
                elif err.get("reason") == "key_not_in_any_tab":
                    missing = err.get("missing_keys") or []
                    if missing:
                        example_pairs.append(
                            f"match.{missing[0]!r} n'est une colonne d'aucun onglet"
                        )
                        break
                elif err.get("reason") == "numeric_out_of_range":
                    mk = err.get("match_key")
                    mv = err.get("match_value")
                    example_pairs.append(
                        f"match.{mk}={mv!r} hors [{err.get('source_min')}, "
                        f"{err.get('source_max')}]"
                    )
                    break
        example_str = " ; ".join(example_pairs) if example_pairs else ""
        warnings.append(
            f"⚠️ Diagnostic no_source : {len(no_source_hints)} groupe(s) de "
            "match invalides (valeurs inexistantes dans la source). "
            + (f"Ex : {example_str}. " if example_str else "")
            + "Voir `no_source_hints` pour chaque groupe : match, "
            "affected_cells_count, closest_values."
        )

    # match_samples : pour les cellules dont le match a ≥2 clés-listes
    # (candidat cross-product), on expose les rows concrètes qui ont matché.
    # Le LLM voit si ses listes produisent un produit cartésien non voulu.
    match_samples = m.get("match_samples") or []
    if match_samples:
        warnings.append(
            f"ℹ️ {len(match_samples)} cellule(s) utilisent un `match` avec "
            "plusieurs clés-listes. Le backend fait un PRODUIT CARTÉSIEN de "
            "toutes les combinaisons, pas des paires ordonnées. Voir "
            "`match_samples` pour vérifier ligne par ligne ce qui est "
            "effectivement sommé — si tu voulais N paires précises mais en "
            "vois N×M, sépare-les en add_cell distincts et additionne via "
            "derived_formula."
        )

    # source_tab_ties : 2+ onglets ont les mêmes colonnes pour couvrir ce
    # match — le backend a pické le 1er par ordre d'index. Si la somme est
    # bonne, ignore. Si elle est fausse, précise via `source_tab_index`.
    source_tab_ties = m.get("source_tab_ties") or []
    if source_tab_ties:
        first = source_tab_ties[0]
        cands = first.get("candidate_tab_indices") or []
        picked = first.get("picked_tab_index")
        warnings.append(
            f"ℹ️ {len(source_tab_ties)} groupe(s) de match ont plusieurs "
            f"onglets candidats à la même spécificité "
            f"(ex : indices {cands} — backend a pické tab {picked}). Si la "
            "valeur produite est incorrecte, ajoute `source_tab_index` dans "
            "ton cellDetails pour lever l'ambiguïté. Croise avec `list_tabs` "
            "pour identifier le bon onglet."
        )

    # Miroir d'exploration : quels onglets as-tu sondés (read_tab_rows /
    # aggregate / count_rows) avant d'en arriver à ce preview ? Si le LLM
    # s'apprête à commit avec la moitié du classeur jamais ouvert, il le voit.
    # Purement factuel — pas de suggestion, pas de jugement.
    tabs_total = len(ctx.tabs_context)
    tabs_touched_sorted = sorted(ctx.tabs_touched)
    tabs_not_touched = [i for i in range(tabs_total) if i not in ctx.tabs_touched]
    if tabs_not_touched and total_cd > 0:
        # Enrichir chaque indice avec label/row_count/extrait de colonnes pour
        # que le LLM identifie d'un coup d'œil ce qu'il a ignoré. Cols cappées
        # à 3 pour ne pas gonfler le warning si beaucoup d'onglets.
        lines = []
        for i in tabs_not_touched:
            tab = ctx.tabs_context[i] if i < len(ctx.tabs_context) else {}
            label = tab.get("label", f"Onglet {i}") if isinstance(tab, dict) else f"Onglet {i}"
            row_count = tab.get("row_count", 0) if isinstance(tab, dict) else 0
            cols = tab.get("columns", []) if isinstance(tab, dict) else []
            cols_preview = ", ".join(cols[:3]) if cols else ""
            if len(cols) > 3:
                cols_preview += f", … (+{len(cols) - 3})"
            suffix = f" — {cols_preview}" if cols_preview else ""
            lines.append(f"  [{i}] {label} ({row_count}l{suffix})")
        warnings.append(
            f"ℹ️ {len(tabs_not_touched)}/{tabs_total} onglet(s) jamais sondés "
            f"(read_tab_rows/aggregate/count_rows) :\n"
            + "\n".join(lines)
            + "\nSi l'un d'eux pouvait couvrir une position uncovered, vérifie avec "
            "`count_rows(idx, match={...})` avant de commit."
        )

    # Factorization hints : groupes de ≥4 cellDetails partageant exactement
    # le même triplet (source_tab_index, value_column, match_exclude sérialisé).
    # Purement indicatif — la justesse du résultat ne dépend pas de la
    # factorisation, mais un match_exclude dupliqué 30× devient difficile à
    # corriger à un seul endroit. Signale, ne corrige pas.
    factorization_hints = _compute_factorization_hints(cd)

    result = {
        "ok": True,
        "stage": "preview",
        "grid_size": f"{nrows}×{ncols}",
        "cellDetails_count": len(cd),
        "recomputed": m.get("recomputed", 0),
        "trusted": m.get("trusted", 0),
        "no_source": m.get("no_source", 0),
        "derived_evaluated": m.get("derived_evaluated", 0),
        "derived_none": m.get("derived_none", 0),
        "zero_value_cells": zero_cells,
        "none_value_cells": none_cells,
        "tabs_touched": tabs_touched_sorted,
        "tabs_not_touched": tabs_not_touched,
        "warnings": warnings,
        "next_action": (
            "Si la couverture est bonne et les warnings acceptables, appelle emit_tab "
            "avec le MÊME payload pour commit. Sinon ajuste ton payload (ajoute des "
            "cell_groups manquants, corrige les match) et re-preview."
        ),
    }
    if factorization_hints:
        result["factorization_hints"] = factorization_hints
    if no_source_hints:
        result["no_source_hints"] = no_source_hints
    if match_samples:
        result["match_samples"] = match_samples
    if source_tab_ties:
        result["source_tab_ties"] = source_tab_ties
    if template_positions:
        result["template_numeric_positions_count"] = len(template_positions)
        result["covered_positions_count"] = len(template_positions) - len(uncovered)
        # Cap à 50 positions pour limiter la taille du tool_result renvoyé
        # au LLM. S'il reste plus, on le lui dit explicitement.
        if uncovered:
            if len(uncovered) > 50:
                result["uncovered_template_positions"] = uncovered[:50]
                result["uncovered_truncated"] = (
                    f"... (+{len(uncovered) - 50} autres). Ajoute les couvertures "
                    "manquantes et re-preview pour voir le reste."
                )
            else:
                result["uncovered_template_positions"] = uncovered
    else:
        # Pas de clone_structure_from → pas de wipe → pas de positions
        # mémorisées. Le LLM peut croire "zéro uncovered = parfait" alors qu'en
        # fait aucun check n'a tourné. On le lui signale explicitement.
        result["coverage_check"] = (
            "skipped — pas de `clone_structure_from` fourni. Si tu clones un "
            "template existant, passe son index pour activer le check de couverture."
        )
    return result


def _coerce_row_count(
    explicit: Any,
    rows: list,
    sheet_content: list,
) -> int:
    """Détermine le ``row_count`` effectif d'un onglet émis.

    Ordre de priorité :

    1. ``explicit`` non-bool, numérique, non-négatif → utilisé tel quel
       (cas d'un onglet matérialisé par SQL où le bridge a déjà compté).
       ``bool`` est explicitement exclu car ``isinstance(True, int) is
       True`` en Python — un ``row_count=True`` sortirait à 1 silencieusement.
    2. Sinon ``len(rows)`` si non-vide.
    3. Sinon ``len(sheet_content)`` (cas des emits cellDetails dont
       ``rows`` est vide mais où ``sheet_content`` porte les cellules).
    4. Sinon 0.
    """
    if isinstance(explicit, bool):
        explicit = None
    if isinstance(explicit, (int, float)) and explicit >= 0:
        return int(explicit)
    if rows:
        return len(rows)
    return len(sheet_content)


def _mirror_emit_to_tabs_context(
    parsed: Dict[str, Any],
    ctx: CopilotContext,
) -> None:
    """Synchronise ``ctx.tabs_context`` avec un emit qui vient d'être ajouté
    à ``ctx.emits``.

    Sans ce mirroring, le contrat documenté de ``emit_tab`` (« ajoute un
    nouvel onglet (ou écrase l'actif) ») n'est honoré que côté frontend
    au moment de ``done``. Pendant le run, ``list_tabs`` /
    ``read_tab_rows`` / ``count_rows`` / ``aggregate`` voient l'ancien
    état → l'agent croit que son emit a échoué et bricole un workaround
    (cas réel : run #60 du 2026-04-28 où l'agent a renoncé et juste
    renommé l'onglet ``iris_result_1`` au lieu d'écraser l'actif).

    Comportement :

    * ``new_tab=True`` (défaut) → append d'une nouvelle entrée à la fin,
      ``is_active=False`` (un nouvel onglet n'est pas actif tant que
      l'utilisateur ne le sélectionne pas côté UI).
    * ``new_tab=False`` → remplace l'entrée à l'index ``is_active=True``,
      en préservant ce flag. Fail-safe : si aucun onglet actif, fallback
      sur append plutôt que perdre l'emit.

    Suit le même pattern que ``ask_iris`` (qui mute déjà
    ``ctx.tabs_context`` à la matérialisation d'un résultat SQL). Tous
    les emits passent par cette fonction unique → cohérence garantie
    entre ``handle_emit_tab`` et ``handle_emit_via_code``.

    Anti-aliasing : on deepcopy le payload pour éviter que des mutations
    ultérieures de ``ctx.tabs_context[i]`` (par un futur ``patch_tab``
    in-mémoire ou similaire) propagent silencieusement vers
    ``ctx.emits[-1]["tab"]`` qui partagerait alors les mêmes inner dicts.
    """
    try:
        is_new = bool(parsed.get("new_tab", True))
        tab_payload: Dict[str, Any] = _copy.deepcopy(parsed.get("tab") or {})

        rows = tab_payload.get("rows") or []
        sheet_content = tab_payload.get("sheet_content") or []
        row_count = _coerce_row_count(
            tab_payload.get("row_count"),
            rows,
            sheet_content,
        )

        new_entry: Dict[str, Any] = {
            "label": tab_payload.get("label", ""),
            "columns": list(tab_payload.get("columns") or []),
            "rows": rows,
            "sheet_content": sheet_content,
            "sql": tab_payload.get("sql"),
            "row_count": row_count,
        }
        # Préserver les champs structurels supplémentaires (merges,
        # cellDetails, cell_groups) sans laisser passer les fields
        # contrôlés par cette fonction (label/columns/rows/...). Une
        # whitelist explicite éviterait que le LLM puisse forcer
        # ``index`` ou ``is_active`` via des champs additionnels.
        for _passthrough_key in ("merges", "cellDetails", "cell_groups"):
            if _passthrough_key in tab_payload:
                new_entry[_passthrough_key] = tab_payload[_passthrough_key]

        if is_new:
            new_entry["index"] = len(ctx.tabs_context)
            new_entry["is_active"] = False
            ctx.tabs_context.append(new_entry)
            return

        actives = [i for i, _t in enumerate(ctx.tabs_context) if _t.get("is_active")]
        if len(actives) > 1:
            logger.warning(
                "emit_tab mirror: %d onglets is_active=True (%s) — "
                "remplacement du premier seulement.",
                len(actives),
                actives,
            )
        active_idx = actives[0] if actives else None
        if active_idx is None:
            new_entry["index"] = len(ctx.tabs_context)
            new_entry["is_active"] = False
            ctx.tabs_context.append(new_entry)
        else:
            new_entry["index"] = active_idx
            new_entry["is_active"] = True
            ctx.tabs_context[active_idx] = new_entry
    except Exception as exc:
        # Ne jamais bloquer un emit valide à cause du mirroring : l'emit
        # reste dans ``ctx.emits``, le frontend appliquera au commit.
        # WARNING et pas debug (fix 2026-06-11, tâche #14) : un mirror
        # raté = l'agent voit un état PÉRIMÉ via list_tabs/read_tab_rows
        # pour le reste du run (pathologie documentée run #60 : il croit
        # l'emit échoué et bricole). Invisible en debug, ops doit le voir.
        logger.warning(
            "emit_tab tabs_context mirror skipped (non-bloquant — l'agent "
            "verra un état périmé jusqu'à la fin du run): %s",
            exc,
            exc_info=True,
        )


async def handle_emit_tab(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Émet un nouvel onglet (ou écrase l'actif). **NON-TERMINAL** : le LLM
    peut appeler ``emit_tab`` plusieurs fois dans le même run pour produire
    plusieurs onglets, puis appelle ``done`` pour clôturer. Si la commande
    est rejetée par expand/validate, on positionne ``emit_tab_error`` (le
    LLM voit l'erreur et peut retenter au turn suivant).
    """
    parsed = _build_emit_parsed(args)
    # Cap de taille AVANT expand/recompute (tâche #20) : fail-fast sur un
    # payload pathologique, même sémantique d'erreur qu'expand/validate
    # (emit_tab_error → le LLM corrige au turn suivant).
    size_err = _validate_emit_payload_size(parsed)
    if size_err:
        ctx.terminal_kind = "emit_tab_error"
        ctx.terminal_result = size_err
        return size_err
    # Expand forme compacte + recompute
    expand_err = _expand_emit_tab(parsed, ctx.tabs_context, ctx.sheet_content)
    if expand_err:
        ctx.terminal_kind = "emit_tab_error"
        ctx.terminal_result = expand_err
        return expand_err
    # Re-check POST-expand (review #20) : cell_groups vient d'être déroulé
    # en cellDetails — sans ce 2e check, il contournait le cap pré-expand.
    size_err = _validate_emit_payload_size(parsed)
    if size_err:
        ctx.terminal_kind = "emit_tab_error"
        ctx.terminal_result = size_err
        return size_err
    val_err = _validate_emit_tab(parsed, ctx.tabs_context)
    if val_err:
        ctx.terminal_kind = "emit_tab_error"
        ctx.terminal_result = val_err
        return val_err

    # Pré-validation sort_by AVANT recompute pour fail-fast sur input
    # malformé (évite gaspillage CPU si tab volumineux et sort invalide).
    tab_pre = parsed.get("tab") or {}
    cd_pre = tab_pre.get("cellDetails") or {}
    has_derived = any(
        isinstance(d, dict) and isinstance(d.get("derived_formula"), dict) for d in cd_pre.values()
    )
    sort_validation_err = _validate_sort_by_spec(
        tab_pre.get("sort_by"),
        tab_pre.get("columns") or [],
        has_derived_formula=has_derived,
        has_merges=bool(tab_pre.get("merges")),
    )
    if sort_validation_err:
        ctx.terminal_kind = "emit_tab_error"
        ctx.terminal_result = sort_validation_err
        return sort_validation_err

    t0 = time.monotonic()
    parsed = _recompute_emit_tab(
        parsed,
        ctx.tabs_context,
        pseudonymizer=getattr(ctx, "_pseudonymizer", None),
    )
    recompute_ms = round((time.monotonic() - t0) * 1000)

    # Application du tri APRÈS recompute : on trie les valeurs finales
    # (sommées), pas les placeholders LLM. La validation a déjà été faite
    # en pre-recompute — ici on n'attend que l'erreur "rows vides" qui
    # devient no-op anyway.
    sort_err = _apply_sort_by_to_tab(parsed.get("tab") or {})
    if sort_err:
        ctx.terminal_kind = "emit_tab_error"
        ctx.terminal_result = sort_err
        return sort_err

    metrics = parsed.get("_recompute_metrics") or {}
    no_source_hints = metrics.get("no_source_hints") or []
    match_samples = metrics.get("match_samples") or []
    source_tab_ties = metrics.get("source_tab_ties") or []

    final_result = {
        "type": "emit_tab",
        "description": parsed.get("description", ""),
        "tab": parsed["tab"],
        "new_tab": parsed.get("new_tab", True),
        "metrics": {
            "recompute_ms": recompute_ms,
            "recomputed": metrics.get("recomputed", 0),
            "trusted": metrics.get("trusted", 0),
            "no_source": metrics.get("no_source", 0),
            "no_source_hints": no_source_hints,
            "match_samples": match_samples,
            "source_tab_ties": source_tab_ties,
        },
    }
    # Non-terminal : on collecte l'emit pour que ``done`` le packe au commit
    # final. Pas de set ``ctx.terminal_kind`` ici.
    ctx.emits.append(final_result)
    _mirror_emit_to_tabs_context(parsed, ctx)

    ret: Dict[str, Any] = {
        "ok": True,
        "emit_index": len(ctx.emits) - 1,
        "recomputed": metrics.get("recomputed", 0),
        "trusted": metrics.get("trusted", 0),
        "no_source": metrics.get("no_source", 0),
        "message": (
            f"Onglet « {parsed.get('tab', {}).get('label', '')} » émis "
            f"(emit #{len(ctx.emits)} de ce run). Continue avec d'autres "
            f"actions ou appelle `done` pour clôturer."
        ),
    }
    if no_source_hints:
        ret["no_source_hints"] = no_source_hints
    if match_samples:
        ret["match_samples"] = match_samples
    if source_tab_ties:
        ret["source_tab_ties"] = source_tab_ties
    return ret


async def handle_rename_tab(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Renomme un onglet existant (label uniquement). **NON-TERMINAL** :
    chaînable avec d'autres actions, clôturer avec ``done``."""
    target_idx = args.get("target_tab_index")
    new_label = args.get("new_label")
    if not isinstance(target_idx, int) or target_idx < 0 or target_idx >= len(ctx.tabs_context):
        ctx.terminal_kind = "emit_tab_error"
        err = {"error": f"rename_tab: target_tab_index {target_idx} invalide."}
        ctx.terminal_result = err
        return err
    if not isinstance(new_label, str) or not new_label.strip():
        ctx.terminal_kind = "emit_tab_error"
        err = {"error": "rename_tab: new_label requis (string non-vide)."}
        ctx.terminal_result = err
        return err
    if len(new_label) > 200:
        ctx.terminal_kind = "emit_tab_error"
        err = {"error": f"rename_tab: new_label trop long ({len(new_label)} > 200 chars)."}
        ctx.terminal_result = err
        return err
    old_label = ctx.tabs_context[target_idx].get("label", f"tab {target_idx}")
    modification = {
        "type": "rename_tab",
        "description": f"Renommage de '{old_label}' en '{new_label}'.",
        "target_tab_index": target_idx,
        "old_label": old_label,
        "new_label": new_label,
    }
    ctx.modifications.append(modification)

    # Synchronisation in-memory : ``list_tabs`` doit voir le nouveau
    # label sans attendre ``done`` — sinon l'agent qui vérifie son
    # propre rename voit l'ancien label et croit que ça a échoué (même
    # pattern de panic-and-bricolage que pour ``emit_tab`` avant le fix).
    try:
        ctx.tabs_context[target_idx]["label"] = new_label
    except Exception as exc:
        logger.debug("rename_tab tabs_context mirror skipped: %s", exc, exc_info=True)

    return {
        "ok": True,
        "target_tab_index": target_idx,
        "old_label": old_label,
        "new_label": new_label,
        "message": (
            f"Onglet renommé en '{new_label}'. Continue avec d'autres actions "
            f"ou appelle `done` pour clôturer."
        ),
    }


async def handle_delete_tab(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Supprime un onglet. Refuse si actif (safety). **NON-TERMINAL** :
    chaînable, clôturer avec ``done``."""
    target_idx = args.get("target_tab_index")
    if not isinstance(target_idx, int) or target_idx < 0 or target_idx >= len(ctx.tabs_context):
        ctx.terminal_kind = "emit_tab_error"
        err = {"error": f"delete_tab: target_tab_index {target_idx} invalide."}
        ctx.terminal_result = err
        return err
    target_tab = ctx.tabs_context[target_idx]
    if target_tab.get("is_active"):
        # Safety : supprimer l'actif laisserait le frontend sans onglet de
        # référence. On refuse plutôt que de gérer le fallback côté backend.
        ctx.terminal_kind = "emit_tab_error"
        err = {
            "error": (
                f"delete_tab: impossible de supprimer l'onglet actif "
                f"(index {target_idx}). Change d'onglet actif d'abord ou choisis "
                "une autre action."
            )
        }
        ctx.terminal_result = err
        return err
    target_label = target_tab.get("label", f"tab {target_idx}")
    modification = {
        "type": "delete_tab",
        "description": f"Suppression de l'onglet '{target_label}'.",
        "target_tab_index": target_idx,
        "target_label": target_label,
    }
    ctx.modifications.append(modification)

    # Synchronisation in-memory : retire l'onglet et ré-indexe les
    # suivants. Sans cette mise à jour, ``list_tabs`` continue de
    # retourner le tab supprimé, et un agent qui chaîne plusieurs
    # ``delete_tab`` finit par référencer des indices décalés.
    try:
        del ctx.tabs_context[target_idx]
        for _i in range(target_idx, len(ctx.tabs_context)):
            ctx.tabs_context[_i]["index"] = _i
    except Exception as exc:
        logger.debug("delete_tab tabs_context mirror skipped: %s", exc, exc_info=True)

    return {
        "ok": True,
        "target_tab_index": target_idx,
        "target_label": target_label,
        "message": (
            f"Onglet '{target_label}' supprimé. Continue avec d'autres actions "
            f"ou appelle `done` pour clôturer."
        ),
    }


async def handle_patch_tab(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Terminal — modifie 1-N cellules d'un onglet existant sans rebuild.

    Validation minimale :
    - target_tab_index dans bornes.
    - patches dict non-vide.
    - chaque clé matche ``r,c`` avec r >= 0 et c >= 0 (pas de bounds row/col
      car le frontend peut avoir une grille plus grande que row_count côté
      backend ; on laisse le frontend gérer l'OOB strict).
    - valeurs = scalaires (string/number/null/bool) OU dict avec ``value``
      et/ou ``cellDetail``.
    """
    import re as _re

    target_idx = args.get("target_tab_index")
    patches = args.get("patches") or {}
    if not isinstance(target_idx, int) or target_idx < 0 or target_idx >= len(ctx.tabs_context):
        ctx.terminal_kind = "emit_tab_error"
        err = {"error": f"patch_tab: target_tab_index {target_idx} invalide."}
        ctx.terminal_result = err
        return err
    if not isinstance(patches, dict) or not patches:
        ctx.terminal_kind = "emit_tab_error"
        err = {"error": "patch_tab: patches requis (dict non-vide)."}
        ctx.terminal_result = err
        return err
    # Cap de taille (tâche #20) : même SSoT que les emits (sandbox
    # MAX_EMIT_OVERRIDES). Sans borne, un patches pathologique partait
    # entier dans ctx.modifications → terminal_result → JSON frontend.
    from app.services.ai.copilot_python_sandbox import MAX_EMIT_OVERRIDES

    if len(patches) > MAX_EMIT_OVERRIDES:
        ctx.terminal_kind = "emit_tab_error"
        err = {
            "error": (
                f"patch_tab: {len(patches)} patches, cap {MAX_EMIT_OVERRIDES}. "
                "Pour une réécriture aussi large, utilise emit_tab (rebuild "
                "de l'onglet) ou découpe en plusieurs patch_tab."
            )
        }
        ctx.terminal_result = err
        return err

    _RC_RE = _re.compile(r"^\s*(\d+)\s*,\s*(\d+)\s*$")
    validated: Dict[str, Any] = {}
    for key, val in patches.items():
        if not isinstance(key, str) or not _RC_RE.match(key):
            ctx.terminal_kind = "emit_tab_error"
            err = {"error": f"patch_tab: clé '{key}' invalide (attendu 'R,C' avec R,C ≥ 0)."}
            ctx.terminal_result = err
            return err
        if isinstance(val, dict):
            # Valeur-objet : {value?, cellDetail?}. Au moins l'un des deux.
            if "value" not in val and "cellDetail" not in val:
                ctx.terminal_kind = "emit_tab_error"
                err = {
                    "error": (
                        f"patch_tab: patch '{key}' = dict doit avoir 'value' et/ou 'cellDetail'."
                    )
                }
                ctx.terminal_result = err
                return err
            cd = val.get("cellDetail")
            if cd is not None and not isinstance(cd, dict):
                ctx.terminal_kind = "emit_tab_error"
                err = {"error": f"patch_tab: cellDetail de '{key}' doit être un objet."}
                ctx.terminal_result = err
                return err
        elif not (val is None or isinstance(val, (str, int, float, bool))):
            ctx.terminal_kind = "emit_tab_error"
            err = {
                "error": (
                    f"patch_tab: valeur de '{key}' doit être scalaire (str/num/bool/null) "
                    "ou dict {value?, cellDetail?}."
                )
            }
            ctx.terminal_result = err
            return err
        validated[key] = val

    target_label = ctx.tabs_context[target_idx].get("label", f"tab {target_idx}")
    modification = {
        "type": "patch_tab",
        "description": (f"Patch de {len(validated)} cellule(s) dans l'onglet '{target_label}'."),
        "target_tab_index": target_idx,
        "target_label": target_label,
        "patches": validated,
    }
    ctx.modifications.append(modification)
    return {
        "ok": True,
        "applied": len(validated),
        "target_tab_index": target_idx,
        "message": (
            f"Patch appliqué sur '{target_label}' ({len(validated)} cellules). "
            f"Continue avec d'autres actions ou appelle `done` pour clôturer."
        ),
    }


#: Cap sur la raison d'abandon affichée à l'utilisateur (fix 2026-06-10, bug
#: vécu « message d'erreur illisible ») : la raison est du TEXTE LIBRE LLM,
#: non borné avant le fix — des paragraphes entiers partaient dans la barre
#: de statut. 200 chars suffisent pour une raison ; le LLM n'a pas vocation
#: à « s'exprimer » vers l'UI (position produit David 2026-06-10).
_ABANDON_REASON_MAX_CHARS = 200


async def handle_abandon(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Terminal — l'agent renonce à la demande (faisabilité, ambiguïté, etc.)."""
    reason = args.get("reason", "Non spécifié")
    if not isinstance(reason, str) or not reason.strip():
        reason = "Non spécifié"
    reason = reason.strip()
    if len(reason) > _ABANDON_REASON_MAX_CHARS:
        reason = reason[:_ABANDON_REASON_MAX_CHARS].rstrip() + "…"
    ctx.terminal_kind = "abandon"
    # ``error_kind`` machine-readable → 422 côté handler (classification
    # sans matching de substring, fix 2026-06-11).
    ctx.terminal_result = {"error": f"Copilot a abandonné : {reason}", "error_kind": "abandon"}
    return {"ok": True, "message": f"Abandon enregistré : {reason}"}


async def handle_done(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Terminal — clôture le run et packe l'ensemble des emits + modifications
    accumulées au cours du run dans ``ctx.terminal_result``.

    Format de sortie :
    - Si exactement 1 emit et 0 modification : retourne directement le
      ``final_result`` de l'emit (rétrocompatible avec ``_applyCopilotResult``
      du frontend qui attend ``{type: "emit_tab", tab, ...}``).
    - Sinon : ``{type: "done", emits: [...], modifications: [...], summary}``.

    Si aucune action n'a été enregistrée (``done`` appelé sans emit/modif),
    on remonte une erreur — l'agent doit produire au moins une action
    visible OU appeler ``abandon`` avec un motif.
    """
    if not ctx.emits and not ctx.modifications:
        ctx.terminal_kind = "emit_tab_error"
        err = {
            "error": (
                "done: aucune action enregistrée dans ce run (ni emit_tab/"
                "emit_via_code, ni patch_tab/rename_tab/delete_tab). "
                "Si la demande est infaisable, utilise `abandon(reason)`. "
                "Sinon, produis au moins un onglet ou une modification "
                "avant d'appeler `done`."
            )
        }
        ctx.terminal_result = err
        return err

    ctx.terminal_kind = "done"
    summary_text = args.get("summary") if isinstance(args.get("summary"), str) else ""

    # Compat backward : 1 emit_tab + 0 modif → format historique direct
    # (le caller historique attend ``terminal_result = {"type": "emit_tab", "tab": ...}``).
    # **Restriction 2026-05-19** : limiter ce shortcut au cas où le seul emit
    # est PRÉCISÉMENT un ``emit_tab``. Si c'est ``emit_via_code`` (autre
    # shape), le shortcut générerait ``terminal_result["type"] = "<autre>"``
    # qui casse le bridge automation (``copilot_automation_bridge.py:437``
    # rejette tout terminal != emit_tab/done/abandon). On wrappe en format
    # ``done`` multi-actions pour que le bridge prenne le chemin Cas 4
    # (qui itère les ``emits`` et sait promouvoir).
    # Note : ``modify_tab_sql`` / ``patch_tab`` / ``rename_tab`` /
    # ``delete_tab`` vont dans ``ctx.modifications``, pas ``ctx.emits`` —
    # ils ne sont donc jamais candidats à ce shortcut par construction.
    if (
        len(ctx.emits) == 1
        and not ctx.modifications
        and (ctx.emits[0] or {}).get("type") == "emit_tab"
    ):
        single = dict(ctx.emits[0])
        if summary_text:
            single["summary"] = summary_text
        ctx.terminal_result = single
        return {
            "ok": True,
            "emits": 1,
            "modifications": 0,
            "message": "Run clôturé.",
        }

    ctx.terminal_result = {
        "type": "done",
        "emits": list(ctx.emits),
        "modifications": list(ctx.modifications),
        "summary": summary_text,
    }
    return {
        "ok": True,
        "emits": len(ctx.emits),
        "modifications": len(ctx.modifications),
        "message": (
            f"Run clôturé : {len(ctx.emits)} onglet(s) émis, "
            f"{len(ctx.modifications)} modification(s)."
        ),
    }


# ---------------------------------------------------------------------------
# Todo-list dynamique (plan_add / plan_update / plan_list)
# ---------------------------------------------------------------------------
#
# La validation et la mutation du plan en mémoire sont déléguées au module
# ``plan_tools_core`` partagé avec Iris (``agent_tools._handle_plan_*``).
# Ici on ne s'occupe plus que de la glue : extraire les args, propager le
# ``_plan_next_id`` du contexte, et sync vers le progress store pour le
# polling frontend. Les imports ``_core_*`` sont en haut de fichier.


async def _sync_plan_to_store(ctx: CopilotContext) -> None:
    """Écrit l'état courant du ctx.plan dans le progress store pour que le
    frontend puisse poller. No-op silencieux si pas de run_id ou user_id
    (tests, debug).
    """
    if not ctx.run_id or ctx.user_id is None:
        return
    from app.services.ai.copilot_progress_store import set_progress

    try:
        await set_progress(ctx.user_id, ctx.run_id, ctx.plan)
    except Exception as exc:  # Protection défensive — un bug store ne doit pas
        # casser le run copilot. On log pour audit mais on laisse passer.
        logger.warning("copilot_progress_store.set_progress failed: %s", exc)


async def handle_plan_add(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Ajoute une task au plan. Retourne l'id assigné et le status initial.

    Par défaut la task est ``"pending"`` — à toi d'appeler ``plan_update``
    avec ``"in_progress"`` quand tu commences à travailler dessus. Plusieurs
    tasks peuvent être ``in_progress`` en même temps si tu veux (pas de
    contrainte imposée). ``description`` est optionnel — utile pour te
    rappeler POURQUOI cette étape, pas seulement QUOI faire.
    """
    ok, _task, new_next_id, err = _core_add_task(
        ctx.plan,
        ctx._plan_next_id,
        args.get("subject"),
        args.get("description"),
    )
    if not ok:
        return {"error": f"plan_add: {err}"}

    ctx._plan_next_id = new_next_id
    await _sync_plan_to_store(ctx)
    return {
        "ok": True,
        "task_id": _task["id"],
        "status": _task["status"],
        "plan_size": len(ctx.plan),
    }


async def handle_plan_update(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Met à jour le status et/ou le subject d'une task existante.

    ``status`` doit être parmi {pending, in_progress, completed, cancelled}.
    ``cancelled`` est le statut honnête pour une étape initialement prévue
    mais qui s'est révélée inutile ou infaisable — préfère-le à supprimer
    la task pour garder une trace de ce qui a été décidé en cours de route.
    """
    ok, task, err = _core_update_task(
        ctx.plan,
        args.get("task_id"),
        args.get("status"),
        args.get("subject"),
    )
    if not ok:
        return {"error": f"plan_update: {err}"}

    await _sync_plan_to_store(ctx)
    return {
        "ok": True,
        "task_id": task["id"],
        "status": task["status"],
    }


async def handle_plan_list(
    _args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Retourne l'état courant du plan. Utile si tu veux te rappeler où tu
    en es sans avoir à remonter dans l'historique conversationnel.
    """
    return _core_list_plan(ctx.plan)


async def handle_explain_substitution(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Non-terminal — enregistre une traduction sémantique demande-user →
    valeur-source pour la rétro-injecter dans la réponse finale. Évite les
    substitutions silencieuses qui falsifient le résultat sans que
    l'utilisateur puisse vérifier.
    """
    original = args.get("original")
    replacement = args.get("replacement")
    reason = args.get("reason")
    for key, val in (
        ("original", original),
        ("replacement", replacement),
        ("reason", reason),
    ):
        if not isinstance(val, str) or not val.strip():
            return {
                "error": (
                    f"explain_substitution: `{key}` requis (string non-vide). "
                    "Les 3 champs (original, replacement, reason) sont obligatoires."
                ),
            }
    ctx.substitutions.append(
        {
            "original": original.strip(),
            "replacement": replacement.strip(),
            "reason": reason.strip(),
        }
    )
    return {
        "ok": True,
        "message": (
            f"Substitution enregistrée : '{original}' → '{replacement}'. "
            "Elle sera rétro-injectée dans la réponse finale. Continue ta tâche."
        ),
        "substitutions_count": len(ctx.substitutions),
    }


async def handle_run_python(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Exécute du Python d'EXPLORATION (pas d'émission).

    Réutilise le sandbox + `ctx.session` comme scratch partagé. Le LLM peut
    aggréger, vérifier, détecter des patterns — puis utiliser les résultats
    stockés dans `session` quand il écrit ensuite son `emit_via_code`.
    """
    from app.services.ai.copilot_python_sandbox import (
        SandboxError,
        run_exploration,
        run_sandboxed,
        wall_timeout_for,
    )

    code = args.get("code")
    if not isinstance(code, str) or not code.strip():
        return {"error": "run_python: `code` requis (string non-vide)."}

    # Session contaminée par un timeout mur précédent (eXamine 2026-06-10
    # CRITICAL) : le thread orphelin peut encore écrire dans ctx.session en
    # arrière-plan — relancer un sandbox sur le même dict = race (dict
    # changed size / agrégats corrompus silencieux). Fail-closed pour le
    # reste du run.
    if getattr(ctx, "sandbox_session_contaminated", False):
        return {
            "ok": False,
            "error": (
                "run_python: indisponible pour le reste de ce run — une "
                "exécution précédente a dépassé le temps-mur et peut encore "
                "écrire en arrière-plan. Termine avec les données déjà "
                "disponibles ou abandonne."
            ),
        }

    # Snapshot isolé via deep-copy ; cf. `_build_sandbox_tabs` pour les
    # détails (symétrie run_python ↔ emit_via_code, skip dense pour SQL tabs).
    sandbox_tabs = _build_sandbox_tabs(ctx)

    # **Hors event loop** (fix 2026-06-10) : le sandbox est synchrone
    # (settrace + exec) — l'exécuter dans la coroutine gelait TOUT Tornado
    # pour tous les users pendant jusqu'à 60s (et sans borne réelle sur les
    # opérations C-pures, cf. wall_timeout_for). to_thread libère l'event
    # loop ; wait_for pose une borne TEMPS-MUR dérivée du timeout coopératif
    # (SSoT sandbox). Thread-safety : ``ctx.session``/``sandbox_tabs`` ne
    # sont touchés par personne d'autre pendant l'await (les tools d'un run
    # s'exécutent séquentiellement). Limitation : au timeout mur, le thread
    # orphelin n'est pas tué (cf. docstring wall_timeout_for) — il peut
    # encore muter ``ctx.session`` en arrière-plan ; accepté et documenté,
    # l'upgrade subprocess reste la vraie isolation.
    try:
        result = await asyncio.wait_for(
            run_sandboxed(run_exploration, code, sandbox_tabs, ctx.session),
            timeout=wall_timeout_for(),
        )
    except asyncio.TimeoutError:
        ctx.sandbox_session_contaminated = True
        return {
            "ok": False,
            "error": (
                f"run_python: temps-mur dépassé ({wall_timeout_for():.0f}s). "
                "Ton code fait probablement une opération massive (tri/produit "
                "de grosses structures) — découpe le travail ou réduis les volumes."
            ),
        }
    except SandboxError as exc:
        # ``_safe_error_message`` (CWE-209, fix 2026-06-11) : la ligne 872 du
        # sandbox réinjecte l'exception runtime BRUTE du code généré par le
        # LLM (``{type}: {exc}``) — elle peut embarquer chemins serveur ou
        # secrets d'env. Ce message part tel quel au LLM cloud en tool_result.
        # Import LOCAL : le bridge importe copilot_agent qui importe ce module.
        from app.services.ai.copilot_automation_bridge import _safe_error_message

        # max_length=600 : le plus long message pédagogique du sandbox
        # (interdiction `.format()`, ~450 chars interpolés) doit passer
        # entier — le cap 300 par défaut amputerait la consigne de
        # correction. Le but sécurité est le strip, pas la longueur.
        return {
            "ok": False,
            "error": f"run_python: {_safe_error_message(exc, max_length=600)}",
        }

    # Retourne stdout + un aperçu du session (clés + taille estimée) pour
    # que le LLM sache ce qui est persistant. Bornes sur chaque repr pour
    # éviter que `repr(large_list)` matérialise des MB avant troncation.
    stdout = result["stdout"]
    session_preview: Dict[str, str] = {}
    for k in result["session_keys"][:20]:
        v = ctx.session.get(k)
        if isinstance(v, (list, tuple)):
            session_preview[k] = f"{type(v).__name__}[{len(v)}]"
        elif isinstance(v, dict):
            session_preview[k] = f"dict[{len(v)} keys]"
        elif isinstance(v, str):
            # Tronque AVANT repr pour éviter matérialisation de gros strings
            session_preview[k] = repr(v[:100]) + ("…" if len(v) > 100 else "")
        elif isinstance(v, (int, float, bool)) or v is None:
            session_preview[k] = repr(v)
        else:
            session_preview[k] = type(v).__name__

    return {
        "ok": True,
        # #18f — cap défensif si print() abondant, mais ANNONCÉ : sans le
        # marqueur, le LLM croit avoir vu tout le stdout de son script.
        "stdout": stdout[:100]
        + ([f"… (+{len(stdout) - 100} lignes tronquées)"] if len(stdout) > 100 else []),
        "session": session_preview,
        "note": (
            "`session` dict est PARTAGÉ entre tes appels run_python de ce turn. "
            "Stocke des agrégats dedans pour les réutiliser dans ton emit_via_code."
            if session_preview
            else "Rien stocké dans `session` pour l'instant. Tu peux y écrire "
            "`session['key'] = value` pour réutiliser entre appels."
        ),
    }


async def handle_emit_via_code(
    args: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Exécute du Python restreint qui appelle ``add_cell``/``add_override``
    dans des boucles → collecte les cellules → délègue au pipeline emit_tab.

    C'est l'équivalent pour le copilot de ce qu'un humain ferait en Python :
    3 boucles imbriquées (section × exercice × période) générant 135 cellules,
    au lieu d'énumérer 135 entrées JSON à la main. Nettement plus fiable sur
    les gros templates.

    Le flag ``preview: true`` renvoie metrics+uncovered sans commiter —
    le LLM peut itérer sur le code avant l'émission finale.
    """
    import copy as _copy
    from app.services.ai.copilot_python_sandbox import (
        SandboxError,
        run_code_with_helpers,
        run_sandboxed,
        wall_timeout_for,
    )

    code = args.get("code")
    if not isinstance(code, str) or not code.strip():
        return {"error": "emit_via_code: `code` requis (string non-vide)."}
    label = args.get("label")
    if not isinstance(label, str) or not label.strip():
        return {"error": "emit_via_code: `label` requis (string non-vide)."}
    # Calculé AVANT le sandbox (fix 2026-06-11, tâche #22) : les except
    # Timeout/SandboxError ci-dessous doivent connaître le mode preview
    # pour ne PAS poser de terminal_kind sur une simulation.
    preview_mode = bool(args.get("preview", False))

    # Snapshot isolé via deep-copy (isolation sandbox ↔ ctx). Cf.
    # `_build_sandbox_tabs` pour les détails (symétrie run_python ↔
    # emit_via_code, skip dense rows pour SQL tabs).
    sandbox_tabs = _build_sandbox_tabs(ctx)

    # Exécute le code dans le sandbox. On passe ctx.session : le LLM peut
    # utiliser les agrégats calculés dans les `run_python` précédents.
    # **Hors event loop** + borne temps-mur : même protection que
    # handle_run_python (cf. commentaire détaillé là-bas, fix 2026-06-10).
    # Garde contamination — même raison que handle_run_python.
    if getattr(ctx, "sandbox_session_contaminated", False):
        return {
            "ok": False,
            "stage": "sandbox",
            "error": (
                "emit_via_code: indisponible pour le reste de ce run — une "
                "exécution précédente a dépassé le temps-mur. Utilise emit_tab "
                "(JSON direct) avec les données déjà disponibles, ou abandonne."
            ),
        }

    try:
        result = await asyncio.wait_for(
            run_sandboxed(run_code_with_helpers, code, sandbox_tabs, session=ctx.session),
            timeout=wall_timeout_for(),
        )
    except asyncio.TimeoutError:
        # Contamination posée MÊME en preview (tâche #22) : le thread
        # orphelin peut encore muter ctx.session en arrière-plan — le
        # danger est réel quelle que soit l'intention (simulation ou pas).
        ctx.sandbox_session_contaminated = True
        error_payload = {
            "error": (
                f"emit_via_code: temps-mur dépassé ({wall_timeout_for():.0f}s). "
                "Découpe le travail ou réduis les volumes."
            )
        }
        # terminal_kind UNIQUEMENT hors preview (fix 2026-06-11, tâche #22) :
        # un preview est une SIMULATION — il ne doit pas muter l'état
        # terminal du run. NB (review #22) : dans la boucle agent ACTUELLE,
        # le dispatch break dès qu'un done/abandon est posé (copilot_agent
        # ~1134), donc le clobber d'un done par un preview suivant n'est pas
        # atteignable end-to-end aujourd'hui — cette garde est une défense
        # en profondeur au niveau handler (appels hors-loop, réordonnance-
        # ment futur de la boucle). Parité avec expand/validate/size,
        # déjà preview-aware.
        if not preview_mode:
            ctx.terminal_kind = "emit_tab_error"
            ctx.terminal_result = error_payload
        return {
            "ok": False,
            "stage": "sandbox",
            **error_payload,
        }
    except SandboxError as exc:
        # Symétrie avec expand/validate : on marque terminal_kind=emit_tab_error
        # pour que la boucle de l'agent reset et passe au turn suivant avec
        # le message d'erreur en tool_result (le LLM peut corriger son code).
        # ``_safe_error_message`` (CWE-209) : même raison que run_python — les
        # erreurs runtime du code LLM sont réinjectées brutes par le sandbox.
        from app.services.ai.copilot_automation_bridge import _safe_error_message

        # max_length=600 : cf. run_python (messages pédagogiques longs).
        error_payload = {"error": f"emit_via_code: {_safe_error_message(exc, max_length=600)}"}
        # Cf. commentaire du TimeoutError : pas de terminal_kind en preview.
        if not preview_mode:
            ctx.terminal_kind = "emit_tab_error"
            ctx.terminal_result = error_payload
        return {
            "ok": False,
            "stage": "sandbox",
            **error_payload,
        }

    cells = result["cells"]
    overrides = result["overrides"]
    logs = result["logs"]

    if not cells and not overrides:
        return {
            "ok": False,
            "stage": "sandbox",
            "error": (
                "emit_via_code: le code n'a produit aucune cellule "
                "(ni add_cell ni add_override appelés). Vérifie tes boucles."
            ),
            "logs": logs[:20],
        }

    # Construit un payload emit_tab-compatible
    emit_args: Dict[str, Any] = {
        "label": label,
        "new_tab": bool(args.get("new_tab", True)),
    }
    if "clone_structure_from" in args:
        emit_args["clone_structure_from"] = args["clone_structure_from"]
    # Merge static rows_overrides + code-generated overrides (code gagne
    # en cas de conflit — c'est le dernier écrit, plus spécifique).
    merged_overrides: Dict[str, Any] = {}
    static_ov = args.get("rows_overrides")
    if isinstance(static_ov, dict):
        merged_overrides.update(static_ov)
    merged_overrides.update(overrides)
    if merged_overrides:
        emit_args["rows_overrides"] = merged_overrides
    if cells:
        emit_args["cellDetails"] = cells

    parsed = _build_emit_parsed(emit_args)
    # ``preview_mode`` calculé en tête de fonction (tâche #22).

    # Cap de taille (tâche #20) : la génération add_cell/add_override est
    # déjà capée par le sandbox, mais le MERGE avec le rows_overrides
    # STATIQUE des args peut dépasser — et les cellDetails générées passent
    # ici aussi. Même sémantique qu'expand/validate.
    size_err = _validate_emit_payload_size(parsed)
    if size_err:
        if not preview_mode:
            ctx.terminal_kind = "emit_tab_error"
            ctx.terminal_result = size_err
        return {"ok": False, **size_err, "stage": "size", "logs": logs[:20]}

    # Travailler sur une copy en mode preview pour ne pas muter ctx
    parsed_work = _copy.deepcopy(parsed) if preview_mode else parsed

    expand_err = _expand_emit_tab(parsed_work, ctx.tabs_context, ctx.sheet_content)
    if expand_err:
        if not preview_mode:
            ctx.terminal_kind = "emit_tab_error"
            ctx.terminal_result = expand_err
        return {"ok": False, **expand_err, "stage": "expand", "logs": logs[:20]}
    # Re-check POST-expand (review #20) : cell_groups → cellDetails.
    size_err = _validate_emit_payload_size(parsed_work)
    if size_err:
        if not preview_mode:
            ctx.terminal_kind = "emit_tab_error"
            ctx.terminal_result = size_err
        return {"ok": False, **size_err, "stage": "size", "logs": logs[:20]}
    val_err = _validate_emit_tab(parsed_work, ctx.tabs_context)
    if val_err:
        if not preview_mode:
            ctx.terminal_kind = "emit_tab_error"
            ctx.terminal_result = val_err
        return {"ok": False, **val_err, "stage": "validate", "logs": logs[:20]}

    # Pré-validation sort_by AVANT recompute (fail-fast, parité avec
    # handle_emit_tab). Sans ça, emit_via_code ignorait silencieusement
    # un sort_by malformé (additionalProperties: True) — asymétrie API
    # flaggée en review adversariale.
    tab_pre = parsed_work.get("tab") or {}
    cd_pre = tab_pre.get("cellDetails") or {}
    has_derived = any(
        isinstance(d, dict) and isinstance(d.get("derived_formula"), dict) for d in cd_pre.values()
    )
    sort_validation_err = _validate_sort_by_spec(
        tab_pre.get("sort_by"),
        tab_pre.get("columns") or [],
        has_derived_formula=has_derived,
        has_merges=bool(tab_pre.get("merges")),
    )
    if sort_validation_err:
        if not preview_mode:
            ctx.terminal_kind = "emit_tab_error"
            ctx.terminal_result = sort_validation_err
        return {
            "ok": False,
            **sort_validation_err,
            "stage": "validate",
            "logs": logs[:20],
        }

    t0 = time.monotonic()
    parsed_work = _recompute_emit_tab(
        parsed_work,
        ctx.tabs_context,
        pseudonymizer=getattr(ctx, "_pseudonymizer", None),
    )
    recompute_ms = round((time.monotonic() - t0) * 1000)
    metrics = parsed_work.get("_recompute_metrics") or {}

    # Application du tri APRÈS recompute (parité avec handle_emit_tab).
    # En mode preview, le sort est appliqué aussi pour que les métriques
    # de couverture (uncovered_template_positions) reflètent l'ordre
    # final que le LLM verra au commit.
    sort_err_post = _apply_sort_by_to_tab(parsed_work.get("tab") or {})
    if sort_err_post:
        if not preview_mode:
            ctx.terminal_kind = "emit_tab_error"
            ctx.terminal_result = sort_err_post
        return {
            "ok": False,
            **sort_err_post,
            "stage": "sort",
            "logs": logs[:20],
        }

    if preview_mode:
        # Coverage check identique à preview_emit_tab (helper partagé).
        tab = parsed_work["tab"]
        rows = tab.get("rows") or []
        nrows = len(rows)
        ncols = len(tab.get("columns") or [])
        cd = tab.get("cellDetails") or {}
        coverage_meta = parsed_work.get("_coverage_meta") or {}
        template_positions = coverage_meta.get("template_numeric_positions", [])
        uncovered = _compute_uncovered_with_candidates(
            rows,
            nrows,
            ncols,
            cd,
            template_positions,
            ctx.tabs_context,
        )
        # Miroir d'exploration (même logique que preview_emit_tab).
        tabs_total = len(ctx.tabs_context)
        tabs_touched_sorted = sorted(ctx.tabs_touched)
        tabs_not_touched = [i for i in range(tabs_total) if i not in ctx.tabs_touched]
        result: Dict[str, Any] = {
            "ok": True,
            "stage": "preview",
            "grid_size": f"{nrows}×{ncols}",
            "cellDetails_count": len(cd),
            "code_generated_cells": len(cells),
            "code_generated_overrides": len(overrides),
            "recomputed": metrics.get("recomputed", 0),
            "no_source": metrics.get("no_source", 0),
            "derived_evaluated": metrics.get("derived_evaluated", 0),
            "derived_none": metrics.get("derived_none", 0),
            "tabs_touched": tabs_touched_sorted,
            "tabs_not_touched": tabs_not_touched,
            "logs": logs[:20],
            "next_action": (
                "Si metrics OK, rappelle emit_via_code avec le MÊME code sans "
                "`preview: true` pour commiter. Sinon ajuste ton code et re-preview."
            ),
        }
        if tabs_not_touched and len(cd) > 0:
            result.setdefault("warnings", []).append(
                f"ℹ️ {len(tabs_not_touched)}/{tabs_total} onglet(s) jamais sondés "
                f"(indices {tabs_not_touched}). Vérifie via `count_rows(idx, match=...)` "
                "avant de commit si l'un d'eux pouvait couvrir une position uncovered."
            )
        if uncovered and template_positions:
            result.setdefault("warnings", []).append(
                f"⚠️ Couverture incomplète : {len(uncovered)}/{len(template_positions)} "
                "positions numériques du template clone ne sont pas remplies. "
                + _UNCOVERED_WARNING_BODY
            )
        # [DEBUG TEMPORAIRE] Idem handle_preview_emit_tab : mémorise sans
        # l'exposer au LLM ici. L'interview est posée en post-run.
        if _uncovered_has_reference_sqls(uncovered):
            ctx._iris_debug_needs_interview = True
        no_source_hints = metrics.get("no_source_hints") or []
        if no_source_hints:
            result["no_source_hints"] = no_source_hints
        match_samples = metrics.get("match_samples") or []
        if match_samples:
            result["match_samples"] = match_samples
        source_tab_ties = metrics.get("source_tab_ties") or []
        if source_tab_ties:
            result["source_tab_ties"] = source_tab_ties
        if template_positions:
            result["template_numeric_positions_count"] = len(template_positions)
            result["covered_positions_count"] = len(template_positions) - len(uncovered)
            result["uncovered_template_positions"] = uncovered[:50]
            if len(uncovered) > 50:
                result["uncovered_truncated"] = f"... (+{len(uncovered) - 50} autres)"
        else:
            result["coverage_check"] = (
                "skipped — pas de `clone_structure_from` fourni. Si tu clones "
                "un template existant, passe son index pour activer le check."
            )
        return result

    # Commit mode : enregistre le résultat terminal
    no_source_hints = metrics.get("no_source_hints") or []
    match_samples = metrics.get("match_samples") or []
    source_tab_ties = metrics.get("source_tab_ties") or []
    final_result = {
        "type": "emit_tab",
        "description": (args.get("description") or f"Reconstruction via code : {label}"),
        "tab": parsed_work["tab"],
        "new_tab": parsed_work.get("new_tab", True),
        "metrics": {
            "recompute_ms": recompute_ms,
            "recomputed": metrics.get("recomputed", 0),
            "trusted": metrics.get("trusted", 0),
            "no_source": metrics.get("no_source", 0),
            "derived_evaluated": metrics.get("derived_evaluated", 0),
            "code_generated_cells": len(cells),
            "code_generated_overrides": len(overrides),
            "no_source_hints": no_source_hints,
            "match_samples": match_samples,
            "source_tab_ties": source_tab_ties,
        },
    }
    # Non-terminal : on collecte l'emit pour ``done`` (cf. handle_emit_tab)
    # ET on synchronise ``ctx.tabs_context`` pour que les outils suivants
    # voient l'onglet émis IMMÉDIATEMENT (cf. ``_mirror_emit_to_tabs_context``).
    ctx.emits.append(final_result)
    _mirror_emit_to_tabs_context(parsed_work, ctx)
    ret_commit: Dict[str, Any] = {
        "ok": True,
        "stage": "emit",
        "emit_index": len(ctx.emits) - 1,
        "cells_generated": len(cells),
        "overrides_generated": len(overrides),
        "recomputed": metrics.get("recomputed", 0),
        "no_source": metrics.get("no_source", 0),
        "message": (
            f"Onglet « {label} » émis via code ({len(cells)} cellDetails, "
            f"{len(overrides)} overrides ; emit #{len(ctx.emits)} de ce run). "
            f"Continue avec d'autres actions ou appelle `done` pour clôturer."
        ),
        "logs": logs[:20],
    }
    if no_source_hints:
        ret_commit["no_source_hints"] = no_source_hints
    if match_samples:
        ret_commit["match_samples"] = match_samples
    if source_tab_ties:
        ret_commit["source_tab_ties"] = source_tab_ties
    return ret_commit


COPILOT_TOOL_HANDLERS = {
    "list_tabs": handle_list_tabs,
    "read_tab_rows": handle_read_tab_rows,
    "count_rows": handle_count_rows,
    "search_workbook": handle_search_workbook,
    "aggregate": handle_aggregate,
    "ask_iris": handle_ask_iris,
    "modify_tab_sql": handle_modify_tab_sql,
    "preview_emit_tab": handle_preview_emit_tab,
    "emit_tab": handle_emit_tab,
    "patch_tab": handle_patch_tab,
    "rename_tab": handle_rename_tab,
    "delete_tab": handle_delete_tab,
    "run_python": handle_run_python,
    "emit_via_code": handle_emit_via_code,
    "abandon": handle_abandon,
    "done": handle_done,
    "explain_substitution": handle_explain_substitution,
    "plan_add": handle_plan_add,
    "plan_update": handle_plan_update,
    "plan_list": handle_plan_list,
}


async def dispatch_copilot_tool(
    tool_name: str,
    tool_input: Dict[str, Any],
    ctx: CopilotContext,
) -> Dict[str, Any]:
    """Dispatch un tool_call vers son handler. Retourne le résultat sérialisable
    qui sera envoyé au LLM comme tool_result.
    """
    handler = COPILOT_TOOL_HANDLERS.get(tool_name)
    if handler is None:
        return {"error": f"Outil inconnu : {tool_name}."}
    try:
        result = await handler(tool_input or {}, ctx)
    except Exception as exc:
        logger.exception("Copilot tool %s a levé une exception", tool_name)
        # ``_safe_error_message`` (CWE-209, fix 2026-06-11) : ce message part
        # tel quel au LLM CLOUD dans le tool_result — un str(exc) brut peut
        # contenir chemins serveur, credentials, IPs (la SSoT de sanitization
        # existait déjà côté bridge automation mais ce boundary l'oubliait ;
        # les données métier, elles, sont déjà anonymisées en amont).
        # Import LOCAL : le bridge importe copilot_agent qui importe ce
        # module (cycle au chargement).
        from app.services.ai.copilot_automation_bridge import _safe_error_message

        return {"error": f"Exception dans l'outil {tool_name} : {_safe_error_message(exc)}"}

    # Note importante (2026-04-22) : on NE fait PAS de miroir plan_status
    # injecté dans les tool_results. Le diagnostic du hang stress_noisy a
    # montré qu'ajouter un champ custom (n'importe lequel) dans un tool_result
    # de read_tab_rows fait HANG l'API Anthropic en mode extended thinking
    # — probablement une interaction cache prefix × thinking budget × shape
    # du tool_result. Impossible à contourner côté client sans désactiver
    # extended thinking. Le LLM peut appeler plan_list() s'il veut voir son
    # état ; les 3 outils plan_add/update/list restent dans COPILOT_TOOLS.
    return result
