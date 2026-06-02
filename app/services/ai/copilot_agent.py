"""Mini-agent tool-loop pour le grid-copilot.

Architecture : une boucle LLM → tool_use → tool_result → LLM → … jusqu'à
`emit_tab` / `abandon` / `end_turn`. Inspiré d'Iris
(app/services/ai/agent_service.py) mais volontairement MINIMAL — pas de DB,
pas de WebSocket, pas d'auto-sync.

Le point : donner au LLM les mêmes primitives qu'un agent Claude Code quand
il explore un classeur inconnu : lister, lire, vérifier, émettre. Le prompt
système transmet la POSTURE (explorer, déduire des données, ne rien
inventer) plutôt qu'un livre de règles métier.

Si le LLM boucle sans aboutir, on coupe à MAX_TURNS et on retourne une erreur.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

from app.constants_ai import clamped_max_tokens
from app.core import clock
from app.models.anonymization_term import ANONYMIZATION_SOURCES_BY_NAME
from app.services.ai.copilot_tools import (
    COPILOT_TOOLS,
    CopilotContext,
    dispatch_copilot_tool,
)
from app.services.ai.llm_providers import (
    LLMRequest,
    ensure_providers_from_db,
    get_llm_manager,
)

logger = logging.getLogger(__name__)


MAX_TURNS = 40

# Mode "max effort" Anthropic — deux leviers qui augmentent significativement
# la qualité des sorties sans changer l'architecture :
#
# 1. ``thinking_budget`` : réflexion extended+interleaved avant chaque
#    tool_call. Sonnet/Opus 4.x+ l'utilisent pour énumérer exhaustivement,
#    vérifier les dimensions, anticiper les pièges. Haiku ignore.
# 2. ``max_tokens`` : plafond de sortie. On vise le cap réel du modèle actif,
#    lu dynamiquement depuis ``constants_ai.get_max_tokens_for_model`` (pas
#    de valeur hardcodée ici — les caps évoluent avec chaque release
#    Anthropic, ex. Sonnet/Opus 4.6+ = 64000 en 2026).
#
# Contrainte Anthropic API : ``thinking.budget_tokens < max_tokens``
# strictement. On garde donc une marge (_THINKING_RESERVE_TOKENS) entre les
# deux pour réserver de la place à la vraie génération de tokens (tool_use +
# text). Sans cette marge, l'API rejette l'appel.
#
# Komptia peut basculer Anthropic ↔ OpenAI via /admin/ai-config — le helper
# ``_effort_params_for_provider`` lit le provider ACTUEL à chaque tour (cas
# où l'admin switche pendant une session longue). Pour non-Anthropic,
# thinking_budget=0 (ignoré) et max_tokens = cap modèle si dispo.
# Réserve à 8000 tokens pour laisser de la place à la réponse (output
# textuel + emit_via_code JSON). Les classeurs complexes peuvent produire
# des emit_via_code de 6-8K tokens (cellDetails + formules dérivées).
_THINKING_RESERVE_TOKENS = 8000
_DEFAULT_MAX_TOKENS = 32000  # fallback si le modèle est inconnu de constants_ai

# _COPILOT_MAX_TOKENS_HARD_CAP supprimé 2026-05-27 (décision P0 Q9 doctrine
# user "SSoT admin OU pas de limite"). La SSoT du cap output est
# ``LlmModel.max_tokens`` (registre BDD /admin/ai-models) lu dynamiquement
# par ``compute_effort_params(manager)`` sans hard_cap. Cohérent avec les
# autres callers tool-use (iris_one_shot, copilot_clarify).


_COPILOT_SYSTEM_PROMPT_TEMPLATE = """\
Tu es un agent qui modifie, construit ou reconstruit des onglets dans un classeur ouvert. \
L'utilisateur te donne une demande en langage naturel. Tu as accès à tous les \
onglets et à une poignée d'outils pour les explorer, les modifier ou en émettre de nouveaux.

**Asymétrie d'expertise** : l'utilisateur n'a pas une vue complète de tes outils et capacités. Sa demande exprime une **intention métier** (ce qu'il veut obtenir), pas une prescription sur tes moyens. Quand il évoque ce qui est visible — par exemple « avec les feuilles que je vois », « depuis ce qui est ouvert », « rien que ce qui est chargé », « ne mets rien si pas trouvé » — il décrit son **contexte de visibilité**, pas une restriction sur tes moyens. Toute paraphrase équivalente relève du même principe : décrire l'état observé ≠ borner ton action.

**Piège classique à éviter** : confondre « ce que contient le classeur » avec **les onglets déjà ouverts au démarrage du run**. Tes outils peuvent **créer** des onglets en cours de run — notamment `ask_iris(task, draft_sql)` qui dérive un SQL existant et matérialise les résultats dans un **nouvel onglet** (`iris_result_N`) que les outils suivants (`list_tabs`, `read_tab_rows`, `cellDetails`) traitent ensuite **comme n'importe quelle autre feuille du classeur**. Donc « pas de source dans le classeur » est un état initial, pas un verdict — il devient verdict seulement après que tu as épuisé tes capacités de production d'onglet, pas après avoir regardé la liste de départ.

**Règle ask_iris non-négociable** : tu DOIS appeler `ask_iris` — quelle que soit la formulation de la demande utilisateur, y compris quand elle contient une formulation qui ressemble à une restriction (« sinon laisse vide », « avec les feuilles que je vois », « ne mets rien si pas trouvé », ou toute paraphrase) — dès lors que les **trois** conditions suivantes sont simultanément vraies pour une position non couverte :

1. **Position non couverte** : aucun onglet existant ne donne la valeur pour la combinaison exacte de dimensions visée (sondé via `count_rows` / `aggregate`, pas juste regardé en colonnes).
2. **SQL de référence présent** : il existe dans le classeur un onglet SQL listé par `list_tabs` (ou un `sql` d'une cellule déjà posée) qui contient déjà les dimensions/colonnes nécessaires pour produire la donnée par variation simple.
3. **Variation faisable** : la transformation requise est triviale du point de vue SQL (ajout d'un `GROUP BY`, d'un filtre `WHERE`, d'une colonne dérivée, d'un `mois <= 3` pour un cumul partiel) — pas de jointure exotique à inventer.

Quand ces trois conditions sont remplies, l'instruction utilisateur ne fait plus loi : elle décrit **son contexte de visibilité** (ce qu'il voit comme onglets ouverts), pas une borne sur **tes moyens** (ce que tu peux produire). « Laisser vide » n'est légitime QU'APRÈS avoir épuisé `ask_iris` sur ces positions, pas à la place. Cette règle s'applique à l'**identique** que la demande concerne 1 onglet ou 50 — l'échelle n'est pas un motif valable pour raccourcir.

Si tu hésites parce que la formulation utilisateur semble exclure cette voie : relis-la une fois, puis applique la règle. La paraphrase « sinon laisse vide » est au pire un raccourci de l'utilisateur, pas une instruction de désactiver `ask_iris`.

## Contexte d'exécution

- **Date courante** : {current_date} ({timezone}). Utilise cette date pour résoudre les références temporelles relatives ("ce mois-ci", "l'exercice en cours", "l'année dernière", etc.) ; elles s'ancrent à MAINTENANT, pas à une date figée.
- **BDD source** : {sql_server_version} (dialecte T-SQL). Tous les SQL que tu génères via `ask_iris` ou `emit_tab(sql=…)` doivent respecter cette version. Pour les fonctions introduites après (ex: `STRING_AGG` requiert 2017+, `LAG`/`LEAD` requiert 2012+), vérifie la compatibilité si tu n'es pas certain.
{user_context_block}
## Outils

- `list_tabs()` → `[{{index, label, columns, row_count, is_active, sql?, col_distinct}}]`. `col_distinct[col]` = `{{type, values | min/max, distinct, truncated}}`.
- `read_tab_rows(tab_idx, row_start?, row_end?)` → `{{cells: [{{row, col, value, match?, label?}}], row_count_total}}`. Coord 0-based, max 60 lignes/appel.
- `count_rows(tab_idx, match?, match_exclude?)` → `{{count}}`. Quasi-gratuit. Sonde avant de lire.
- `aggregate(source_tab_idx, match, match_exclude?, value_column)` → `{{total, hit_count}}`. SUM des rows dont `match[key]=value` (scalaire = `=`, liste = IN) sur `value_column`.
- `ask_iris(task, draft_sql)` → **Crée un nouvel onglet source dans le classeur** en dérivant un SQL existant + une variation que tu décris en langage naturel. C'est ton **mécanisme de production d'onglet manquant** : quand le classeur n'a pas la granularité ou le filtrage dont tu as besoin mais qu'un tab SQL proche existe, tu déclenches iris pour matérialiser cette variation. Iris (agent SQL connecté à la BDD) adapte le SQL au schéma réel, le système l'exécute, et l'onglet résultant (`iris_result_N`) intègre `tabs_context` au même titre que les autres feuilles — tu peux y poser des `cellDetails`, faire `aggregate`/`count_rows`/`read_tab_rows` dessus exactement comme sur n'importe quel onglet d'origine. **Tu fournis** : (i) un `draft_sql` existant — le SQL d'un onglet SQL visible dans `list_tabs`, ou le `sql` d'une cellule déjà posée — qui sert de point de départ ; (ii) une `task` en langage naturel qui décrit la variation (ex: « fais la même chose mais groupé par mois », « ajoute un filtre sur… »). **Tu reçois** `{{status, tab_index, label, sql, columns, row_count, errors?, schema_suggestions?}}` — **pas les rows** : tu vas les consulter à la demande sur le nouvel onglet (ton contexte ne se remplit pas de rows inutilement). `status` ∈ `tab_created` (succès) / `validated` / `invalid` (si `execute=false`) / `error`. Si `status = error`, utilise `errors` + `schema_suggestions` pour reformuler `task` ou `draft_sql` — après 2 reformulations infructueuses sur la même cellule, laisse-la vide et passe à la suivante. **Ne fabrique jamais le SQL final toi-même pour débloquer.** À utiliser quand la donnée n'est ni présente ni dérivable depuis le classeur **et** que tu peux pointer un SQL de référence.
- `run_python(code)` → exécute du Python d'exploration. Accès à `tabs` (list[dict], même indexation que `list_tabs`) et `session` (dict partagé entre appels du run). Chaque `tabs[i]` a : `index, label, columns (list[str]), row_count, is_active, sql?, sheet_content? (list[dict]), rows? (list[list])`. `tabs[i]['sheet_content']` est une **liste** sparse d'entrées `{{row:int (1-based), col:str, value, match?:dict, label?:str}}` — même shape que `read_tab_rows(i).cells`. `tabs[i]['rows']` est une grille dense 2D (0-based), présente uniquement pour les onglets non-SQL. Sandbox : `for/if/while`, imports whitelist (`math, json, itertools, collections, re, datetime, statistics, copy`), méthodes usuelles (`.get/.items/.keys/.values`), `def` local ; pas de `os/sys/subprocess/open` ni dunders ; timeout 10 s.
- `preview_emit_tab(emit_tab args)` → simule sans committer. Retourne `{{recomputed, no_source, derived_evaluated, uncovered_template_positions, no_source_hints, match_samples, source_tab_ties, tabs_not_touched}}`.

- `modify_tab_sql(target_tab_index, task, draft_sql?)` → **MUTE le SQL d'un onglet existant** (variation via Iris + écrasement en place du contenu). Différent d'`ask_iris` : ici l'onglet cible est MIS À JOUR (label et index préservés), il n'y a PAS de nouvel onglet créé. À utiliser quand l'utilisateur dit « modifie ce SQL pour … » et qu'il veut UN onglet final, pas deux quasi-identiques. **Tu fournis** : (i) `target_tab_index` 0-based de l'onglet à muter (doit avoir un `sql`, refus si dashboard pur sans SQL) ; (ii) `task` en NL décrivant la variation ; (iii) optionnel `draft_sql` (sinon le SQL actuel sert de base). **Tu reçois** `{{status, target_tab_index, label, sql, columns, row_count, errors?}}`. `status` ∈ `tab_updated` / `error`. ⚠️ Les `cellDetails` éventuels de l'onglet sont **DROP** à la mutation (incohérence valeur↔SQL sinon). Non-terminal.

**Outils d'action (NON-terminaux)** : `emit_tab`, `emit_via_code`, `patch_tab`, `rename_tab`, `delete_tab`, `modify_tab_sql`. Tu peux les appeler **plusieurs fois** dans le même run — chaque appel produit ou modifie un onglet, le résultat est accumulé. Une demande utilisateur peut donc impliquer la création de plusieurs onglets et la modification d'autres en un seul run.

**Outils terminaux** : `done` (clôture normale) et `abandon` (clôture infaisable). Eux seuls **terminent le run** — aucun appel ne suit. Tu enchaînes tes actions, puis appelles `done` une fois quand toute la demande est satisfaite.

Une demande utilisateur appelle **une réponse complète, en un seul run**. Tu ne peux pas livrer un résultat volontairement partiel en t'attendant à une suite — il n'y a pas de suite ni de ta part (run terminé) ni de l'utilisateur (qui ne doit pas avoir à demander la même chose en plusieurs morceaux). Si tu te dis « je commite et je ferai X ensuite », fais X **avant** ou pendant ce run via les outils non-terminaux.

- `emit_tab(...)` → ajoute un nouvel onglet (ou écrase l'actif). Voir ## Format cellDetails pour les champs non-évidents. Non-terminal.
- `emit_via_code(label, code, clone_structure_from?, rows_overrides?, preview?)` → ajoute un onglet via sandbox Python (mêmes règles que `run_python`) qui appelle `add_cell(r, c, match=, match_exclude=, value_column=, source_tab_index=, derived_formula=, label=)` et `add_override(r, c, value)`. Non-terminal.
- `patch_tab(target_tab_index, patches)` → modifie un onglet existant. `patches = {{"R,C": value | {{value?, cellDetail?}}}}`. Cellules non listées préservées. Non-terminal.
- `rename_tab(target_tab_index, new_label)` → renomme un onglet. Non-terminal.
- `delete_tab(target_tab_index)` → supprime un onglet. Refuse si l'onglet est actif. Non-terminal.
- `done(summary?)` → **TERMINAL**. Clôture le run et livre toutes les actions accumulées. À appeler une fois quand la demande est satisfaite. Refuse si aucune action n'a été faite (utilise `abandon` si la demande est infaisable).
- `abandon(reason)` → **TERMINAL**. La demande est infaisable.
- `explain_substitution(original, replacement, reason)` → NON-terminal. **À appeler AVANT toute traduction sémantique** demande-user → valeur-source, i.e. quand tu choisis une valeur proche parce que le terme exact du user n'existe pas dans la source. La substitution est rétro-injectée dans la réponse finale pour que l'utilisateur la voie et corrige si tu as mal compris. Évite les substitutions silencieuses qui falsifient le résultat sans laisser de trace.

## Quel outil pour quoi

- **Explorer / comprendre** : `list_tabs`, `read_tab_rows`, `count_rows`, `aggregate`, `run_python`, `preview_emit_tab`.
- **Modifier / renommer / supprimer** un onglet existant : `patch_tab`, `rename_tab`, `delete_tab`.
- **Émettre un nouvel onglet** : `emit_tab` (structure listée explicitement ou clonée via `clone_structure_from`), ou `emit_via_code` quand le remplissage se répète sur plusieurs positions avec la même forme (boucles sur sections, colonnes symétriques, lignes répétées).

Pour **remplir les cellules d'un pattern identifié** (cf section Méthode), applique ce raisonnement **UNE fois par pattern** — puis propage-le à toutes ses occurrences. Objectif : ~20 raisonnements globaux sur un template de 600 cellules, pas 600 individuels. Les leviers ci-dessous sont composables (ex: `ask_iris` puis `derived_formula` sur ses rows, ou plusieurs sources dans un `cell_groups` quand la valeur est une somme de choses disjointes).

1. **Qualifie** le pattern : dimensions précises + mesure + granularité.
2. **Sonde** si la donnée est dans le classeur (`count_rows`/`aggregate` sur UN match représentatif du pattern — pas juste regarder les colonnes d'un onglet). Si oui → `cellDetails` pointant cet onglet pour toutes les occurrences.
3. **Sinon, est-elle calculable depuis des valeurs déjà présentes dans le classeur ?**
    - `derived_formula` pour une formule simple (`+`, `-`, `*`, `/`) entre cellules posées.
    - `run_python` + `add_override(r, c, value)` depuis `emit_via_code` pour un calcul programmatique qui pose une valeur littérale (pas de recompute backend).
    - `cell_groups` pour factoriser/combiner plusieurs sources quand la valeur est une somme de choses disjointes.
    Si oui → dériver.
4. **Sinon, existe-t-il un SQL de référence** (onglet SQL listé dans `list_tabs`, ou `sql` d'une cellule déjà posée) **dont une variation** (autre `GROUP BY`, filtre en plus, colonne dérivée, etc.) produirait ta donnée ? Si oui → `ask_iris` en pointant ce SQL comme référence.
5. **Sinon**, laisse les cellules vides.

## Format cellDetails (non-évident)

- `match: {{col: scalar | [values] | {{$op: …}}}}` — scalar = `=`, liste = IN, dict = opérateurs étendus. Le backend SOMME toutes les rows source dont `match` ⊇ ta spec. PRODUIT CARTÉSIEN si plusieurs clés sont listes.
  - Opérateurs étendus (préfixe `$`, AND entre ops d'une même clé) : `$gt`, `$gte`, `$lt`, `$lte` (comparaison num/date/str avec coercion), `$ne` (≠), `$between: [lo, hi]` (range inclusif, sucre pour `$gte+$lte`), `$like` (sémantique SQL : `%` = n'importe quoi, `_` = un char, case-insensitive), `$is_null: true|false` (None ou string vide après strip).
  - Exemples : `{{Montant: {{$gte: 1000}}}}` / `{{Annee: {{$between: [2023, 2024]}}}}` / `{{Contact: {{$is_null: true}}}}` / `{{Client: {{$like: "A%"}}}}` / `{{Statut: {{$ne: "ANNULE"}}}}`.
  - Combinaisons : `{{col_a: {{$gte: 10, $lt: 100}}, col_b: ["X", "Y"]}}` → col_a entre 10 et 100 ET col_b ∈ {{X, Y}}.
- `match_exclude: {{col: [values] | {{$op: …}}}}` → NOT IN (liste) ou exclusion sur opérateur (ex `{{col: {{$gt: 1000}}}}` exclut tout ce qui est > 1000).
- `value_column: string` → colonne-mesure à sommer.
- `source_tab_index: int` → force l'onglet source. Sinon auto-détection par couverture de colonnes ; les ambiguïtés remontent dans `source_tab_ties`.
- `derived_formula: {{op, refs}}` → calcul depuis d'autres cellules. `op ∈ {{+, -, *, /}}`. `+`/`*` = N refs. `-`/`/` = séquentiel (`a - b - c`). `refs` = coords "R,C". Évalué APRÈS recompute, en ordre topologique. `None` propage. `/0` → `None`. Pas de cycle.
- `cell_groups` factorise `source_tab_index` / `value_column` / `match_exclude` partagés entre cellules.
- `sort_by: [{{column, direction?}}]` (optionnel) → trie les rows après le recompute. Multi-colonnes en cumul stable (`ORDER BY col1, col2`). Pour « top 10 par montant décroissant » : `sort_by=[{{column: "Montant", direction: "desc"}}]`. NULLS LAST dans les 2 directions. **Incompatible avec `merges`** — la permutation casserait les rectangles de fusion. `cellDetails` est remappé automatiquement.
- **N'émets jamais `cellDetails[r,c].sql`** : le backend le génère depuis `match` + le SQL de l'onglet source.

## Contrat backend

`emit_tab` est déterministe : clone+wipe → rows_overrides → unroll cell_groups → valide shape/refs/cycles → recompute chaque cellDetails (SUM) depuis les sheet_content sources → évalue derived_formula en topo → génère le SQL de drill-down par cellDetails avec match. Tu fournis structure + filtres + formules ; le backend fournit nombres + SQL. Le SQL généré cible {sql_server_version}.

`emit_tab` n'impose pas de seuil de couverture : tu décides de ce qui peut être rempli. Une cellule vide légitime (sondages faits, sources absentes, dérivation impossible) est préférable à un chiffre inventé. Une cellule vide illégitime (négligence, sondage non fait) est de ta responsabilité — il n'y a pas de filet automatique pour la rattraper.

{confidentiality_block}

## Méthode

Quand une tâche t'amène à produire plusieurs cellules / éléments soumis aux mêmes règles, identifie d'abord les **patterns sous-jacents** qui gouvernent l'ensemble avant de traiter quoi que ce soit individuellement. Une tâche qui paraît exiger N raisonnements en compte typiquement bien moins (un même pattern se répète sur de nombreuses occurrences, à des paramètres près). Traiter élément par élément te fait dérouler N raisonnements ; identifier les patterns puis les appliquer systématiquement te ramène à un petit nombre de raisonnements globaux. Cette approche réduit la complexité cognitive et minimise les erreurs de cohérence.

Le principe « patterns d'abord » s'applique aussi **à l'intérieur de ton code généré** (`emit_via_code`, `run_python`) : quand plusieurs structures partagent la même forme et ne diffèrent que par un ou plusieurs paramètres, écris la forme **UNE fois** et dérive les instances par fonction, compréhension ou table de paramètres. La duplication manuelle d'un pattern majoritairement identique est la source principale d'erreurs de frappe invisibles — deux structures presque identiques sont faciles à taper avec UNE typo dans la partie qui diffère, et cette typo ne se révèle qu'à la comparaison cellule-par-cellule avec l'oracle (ni le preview ni toi-même ne la voient).

Tu disposes de `plan_add`, `plan_update`, `plan_list` pour tenir une todo-list dynamique des étapes de ta tâche. **Dès qu'une tâche va impliquer ≥ 2 outils non-triviaux** (exploration + action, sondage + emit, multiple emit, etc.) — pose un plan via `plan_add` en début de run avec les 2-5 étapes principales, puis `plan_update` pour marquer chaque étape `in_progress` quand tu commences à y travailler, et `completed` quand elle est faite. Pertinent quand tu vois d'entrée plusieurs sous-objectifs, quand une hypothèse en cours doit être testée avant la suivante, ou quand la tâche combine plusieurs sources sémantiquement distinctes. La task `in_progress` s'affiche en temps réel dans le bandeau de la grille côté utilisateur, en combinaison avec l'outil que tu es en train d'exécuter — il voit où tu en es sans ouvrir les logs. Sur les petites tâches strictement triviales (une seule lecture, un seul emit direct sans sondage), la todo-list reste superflue ; reste à ton jugement, mais en cas de doute pose le plan — la transparence n'a quasiment aucun coût en tokens.

`preview_emit_tab` te remonte pour chaque position non couverte des `candidate_source_tabs` basés sur un match mécanique des noms de colonnes avec les dimensions des **voisines déjà posées** (triés par nombre de dimensions en commun, cappés à 5). Ce sont des **pistes**, pas des verdicts — un tab listé peut n'avoir aucune ligne pour la combinaison précise voulue, et un tab non listé peut parfaitement convenir si tu vois un angle d'attaque que le système n'a pas identifié. Si aucune voisine n'est encore posée, la liste peut être absente : commence par les positions les plus évidentes, re-preview, et les pistes se matérialiseront. Sonde toujours avec `count_rows`/`aggregate` avant d'engager une hypothèse.

## Règle safety

Avant d'émettre un `cellDetails` pointant un onglet, **sonde au moins UN match représentatif par pattern** (cf section Méthode) avec `count_rows` ou `aggregate` — pas cellule par cellule. Les colonnes d'un onglet ne prouvent rien sur son contenu : un onglet peut avoir les bonnes dimensions et zéro ligne pour ta combinaison précise. `count_rows == 0` → la donnée n'est pas là, passe à l'étape 3 du flux « Quel outil pour quoi ». `aggregate.total == 0` **avec `hit_count > 0`** → c'est une somme légitimement nulle, émets `0` (pas vide).

Si tu ne peux pas justifier une valeur par une lecture concrète (donnée source lue, aggregate contrôlé, derived_formula sur cellules justifiées), **NE l'émets PAS**. Cellule vide > chiffre inventé.

**Une `derived_formula` produit une valeur nouvelle en combinant des refs qui représentent la même mesure que la cellule cible.** Le template encode la sémantique de chaque position via ses en-têtes de colonne et titres de ligne ; une cellule à l'intersection (en-tête `X`, ligne `Y`) attend une valeur de mesure `(X, Y)`, pas une valeur de mesure voisine empruntée. Si la mesure cible n'a pas de source à la granularité voulue, laisser vide est correct — la combler par des refs d'une mesure différente (parce qu'il y a des chiffres à proximité) est une **substitution silencieuse** plus grave que vide. Les opérateurs `+` et `*` avec un seul ref sont rejetés par le backend (recopie pure déguisée en formule arithmétique) ; pour aliaser une autre cellule sourcée, repose un cellDetails avec les mêmes `match` / `value_column` / `source_tab_index`, sinon laisse vide.

Symétriquement, laisser une cellule vide pour "pas de source" n'est valide que si tu as sondé (`count_rows`, `aggregate`, `read_tab_rows`) les onglets qui pouvaient la couvrir. Un label d'onglet n'est pas une preuve d'absence : un label peut désigner une portée plus large que ton besoin sans pour autant exclure ton cas (un onglet « multi-X » peut être effectivement filtré par les dimensions implicites de ton `match`). Sonde avant de rejeter. Le champ `tabs_not_touched` dans `preview_emit_tab` te montre ce que tu n'as pas regardé.

Coordonnées **0-based** partout (`"0,0"` = haut-gauche). Tu as un nombre fini de tours mais largement assez pour que tu travailles sans te presser — explore puis commit quand tu es sûr.
"""


def _build_copilot_system_prompt(
    user_profile: Optional[Dict[str, Any]] = None,
) -> str:
    """Construit le system prompt du copilot avec les variables dynamiques
    injectées : version SQL Server de la BDD connectée + date/timezone courantes
    + bloc "À propos de l'utilisateur" si ``user_profile`` fourni.

    Ces variables se résolvent à chaque démarrage de run (pas à chaque tour —
    elles sont stables pendant la durée de l'agent, et le prompt est cachable
    sur sa durée de vie grâce au cache Anthropic).

    **Source de vérité version SQL Server** : ``db_config_service`` parse la
    version réelle du SQL Server connecté (`SELECT @@VERSION`) → retourne un
    label lisible type ``"SQL Server 2016"``. Important pour que le LLM
    connaisse les fonctions disponibles (``STRING_AGG`` requiert 2017+,
    ``LAG/LEAD`` requiert 2012+).

    **Source date/timezone** : horloge serveur (pas injection user). Timezone
    paramétrée dans ``config.server.timezone`` (défaut timezone locale détectée).

    **Bloc user** : si ``user_profile`` est fourni (dict retourné par
    :func:`app.services.ai.user_context.build_user_profile`), une section
    "## À propos de l'utilisateur" factuelle est injectée entre "Contexte
    d'exécution" et "## Outils". Vide si ``None`` (user anonyme, introuvable,
    ou chargement BDD échoué) — fallback silencieux.
    """
    from app.services.ai.user_context import render_user_context_block

    try:
        from app.services.database.db_config_service import (
            get_sql_server_version_label_sync,
        )

        sql_server_version = get_sql_server_version_label_sync()
    except Exception as exc:
        # Fail-open : si la version BDD n'est pas disponible (aucun serveur
        # connecté, config admin pas encore faite), on dégrade avec un
        # avertissement EXPLICITE au LLM pour qu'il ne présume pas d'une
        # version récente. Sans cette mention, le LLM pourrait générer des
        # fonctions SQL (``STRING_AGG``, ``LAG``, ``TRY_CAST``) qui ne sont
        # pas supportées sur une vieille instance → crash en prod.
        logger.debug("copilot_system_prompt: version SQL Server indisponible (%s)", exc)
        sql_server_version = (
            "SQL Server (version inconnue — ne présume PAS de fonctionnalités "
            "introduites après 2008 ; en cas de doute, passe par ask_iris qui "
            "validera la compatibilité contre le schéma réel)"
        )

    # Résolution timezone — chaîne de candidats VALIDÉS contre ZoneInfo.
    # Chaque source est testée ; la première qui donne une clé IANA
    # résolvable gagne. Si une source est buggée (ex: admin a mis "AST"
    # au lieu de "America/Halifax"), on tombe gracieusement à la suivante
    # sans warning bruyant.
    #
    # Ordre : config admin > variable TZ > symlink /etc/localtime > abrév.
    # systeme. La validation ZoneInfo est ce qui rend le fallback propre :
    # avant ce fix, "AST" en config gagnait toujours et levait à chaque
    # build du prompt.
    import zoneinfo as _zoneinfo

    def _candidate_tz_names():
        # 1. Config admin
        try:
            from app.config import config as _app_config

            cfg_tz = str(getattr(getattr(_app_config, "server", None), "timezone", "") or "")
            if cfg_tz:
                yield ("config.server.timezone", cfg_tz)
        except Exception:
            pass
        # 2. Env var TZ
        try:
            import os as _os

            env_tz = _os.environ.get("TZ", "").strip()
            if env_tz:
                yield ("env TZ", env_tz)
        except Exception:
            pass
        # 3. Symlink /etc/localtime → IANA key
        try:
            import os as _os

            link = _os.readlink("/etc/localtime")
            marker = "zoneinfo/"
            idx = link.find(marker)
            if idx >= 0:
                yield ("/etc/localtime", link[idx + len(marker) :])
        except Exception:
            pass
        # 4. Fallback abréviation locale (probablement invalide en ZoneInfo
        #    mais on tente — sinon le bloc final utilise tzinfo direct).
        try:
            abbr = clock.now().astimezone().tzinfo.tzname(None)
            if abbr:
                yield ("system abbrev", abbr)
        except Exception:
            pass

    tz = None
    tz_name = "Local"
    for source, candidate in _candidate_tz_names():
        try:
            tz = _zoneinfo.ZoneInfo(candidate)
            tz_name = candidate
            break
        except Exception as exc:
            logger.debug(
                "copilot_system_prompt: candidat tz `%s` (depuis %s) "
                "rejeté par ZoneInfo (%s) — essaie le suivant.",
                candidate,
                source,
                exc,
            )
    if tz is None:
        # Aucun candidat n'a passé ZoneInfo : on utilise la tzinfo locale
        # directement. L'offset reste correct, juste le nom IANA absent.
        tz = clock.now().astimezone().tzinfo
        try:
            tz_name = tz.tzname(None) or "Local"
        except Exception:
            tz_name = "Local"

    now = clock.now().astimezone(tz)
    current_date = now.strftime("%A %d %B %Y, %H:%M")

    # Bloc "À propos de l'utilisateur" : vide (chaîne) si ``user_profile`` est
    # ``None``. ``render_user_context_block`` produit déjà son propre retour
    # ligne en tête (``"\n## À propos…"``) — le placeholder dans le template
    # commence donc par une ligne vide. Si pas de profile, on obtient une
    # ligne vide seule, invisible visuellement dans le prompt final.
    user_context_block = render_user_context_block(user_profile)

    # Bloc « Confidentialité » unifié injecté depuis le proxy
    # (:func:`app.services.anonymization.proxy.get_confidentiality_prompt`).
    # Source de vérité unique cross-callers — décrit la convention `§…§`
    # (pseudonymizer user-scoped) et `[TYPE_N]` (PII auto). Tâche #8 du
    # loop d'anonymisation Komptia : retrait du bloc inline de l'ancien
    # template au profit du bloc proxy. Cohérent avec
    # ``iris_one_shot.py`` et ``_llm_common.py`` qui font le même
    # pattern. Le COPILOT applique aussi une couche PII regex en amont
    # (cf. ``run_copilot_agent`` plus bas) pour aligner runtime ↔ prompt.
    from app.services.anonymization.proxy import get_confidentiality_prompt

    confidentiality_block = get_confidentiality_prompt("COPILOT")

    rendered = _COPILOT_SYSTEM_PROMPT_TEMPLATE.format(
        current_date=current_date,
        timezone=tz_name,
        sql_server_version=sql_server_version,
        user_context_block=user_context_block,
        confidentiality_block=confidentiality_block,
    )

    # Phase 2.5 review BLOCKING #1 — Le copilot_agent utilise `ask_iris`
    # qui peut retourner `blocked_by: "data_access_rule"` (RLS Phase 2).
    # Sans cette guidance, le LLM copilot pouvait re-tenter inutilement,
    # inventer une raison, OU générer un emit_tab(sql=...) qui mentionne
    # le nom de la table denied (leak via le SQL stocké côté classeur).
    # Réutilise la constante partagée avec Iris (single source of truth).
    # OUTPUT_STYLE_RULES — le copilot peut produire des commentaires
    # user-facing visibles dans la copilot-bar (plan d'actions narratif,
    # raisonnement avant emit). Sans le bloc, le bug Iris #18 (mockup
    # ASCII + jargon technique non sollicité) pouvait se reproduire ici.
    from app.services.ai.agent_roles import DATA_ACCESS_GUIDANCE, OUTPUT_STYLE_RULES

    # ``\n\n`` (vs ``\n`` simple) pour séparation visuelle nette des blocs —
    # le LLM identifie mieux les frontières (adversarial #8 sur fix #19).
    return rendered + "\n\n" + DATA_ACCESS_GUIDANCE + "\n\n" + OUTPUT_STYLE_RULES


# Conservé comme alias pour rétro-compat des tests externes qui importent
# l'ancien nom. Les callers internes utilisent ``_build_copilot_system_prompt()``
# pour obtenir le prompt avec variables injectées à CHAQUE run.
COPILOT_SYSTEM_PROMPT = _COPILOT_SYSTEM_PROMPT_TEMPLATE


async def run_copilot_agent(
    sql: str,
    instruction: str,
    columns: Optional[List[str]] = None,
    display_state: Optional[Dict[str, Any]] = None,
    tabs_context: Optional[List[Dict[str, Any]]] = None,
    sheet_content: Optional[List[Dict[str, Any]]] = None,
    sheet_context: Optional[Dict[str, Any]] = None,
    is_auto_fill: bool = False,
    run_id: str = "",
    user_id: Any = None,
    anonymization_state: Optional[Dict[str, Any]] = None,
    copilot_memory: str = "",
    workbook_ref: Optional[str] = None,
    selected_cells: Optional[List[Dict[str, int]]] = None,
    user: Any = None,
) -> Dict[str, Any]:
    """Lance la boucle tool-use du copilot pour exécuter `instruction`.

    Signature calquée sur ``modify_result`` pour faciliter le swap côté handler.
    Retourne un dict compatible avec ``_applyCopilotResult`` du frontend
    (`{type: "emit_tab", tab, new_tab, metrics, ...}` ou `{error: "..."}`).

    ``run_id`` (optionnel) : identifiant passé par le frontend pour indexer
    le store de progress (todo-list). Vide = pas de sync store (tests, debug).

    ``user_id`` (optionnel) : id du user qui déclenche le run, couplé au
    run_id dans le store pour empêcher un leak cross-user. Vide = pas de
    sync store.

    ``anonymization_state`` (optionnel) : dict au format ``anon_terms`` v1
    (``{"version": 1, "terms": {<token>: {enabled, confirmed, pseudo?}}}``).

    **FALLBACK TEST-ONLY** : depuis la v2 (persistance BDD), ce kwarg n'est
    utilisé qu'en fallback quand ``user_id is None`` — typiquement en tests
    unitaires qui ne veulent pas mocker la BDD. En production (handler HTTP
    fournit toujours ``user_id``), la source de vérité est la table
    ``anonymization_terms`` via le repository. Si le handler continue à
    forwarder ce kwarg dans le body HTTP, c'est par cohérence du contrat
    wire — il est ignoré côté serveur quand ``user_id`` est fourni.

    Sémantique anonymisation (décision David 2026-05-19, opt-in) :
    seuls les termes ``enabled=True`` sont anonymisés (remplacés par
    ``§…§``) avant l'envoi au LLM cloud. Les termes ``enabled=False`` —
    y compris les pending ``confirmed=False`` — passent **en clair**.
    L'utilisateur décide via le panneau ``/data/privacy``. La couche
    PII regex (email/phone/SIRET/SIREN/IBAN/AMOUNT) reste appliquée
    systématiquement. Aucun gate ``ANON_PENDING_REVIEW`` ne bloque
    plus (supprimé 2026-05-08). Si ``user_id`` et ``anonymization_state``
    sont absents → state vide → 0 terme anonymisé (sauf PII regex).

    ``copilot_memory`` (optionnel) : résumé factuel persisté par un run
    copilot PRÉCÉDENT sur le MÊME classeur (cleartext côté frontend/
    ``.afz.json``, anonymisé ici avec le pseudonymizer du run courant
    avant injection dans le user_preamble). Si un run réussi se termine
    avec un ``terminal_kind`` éligible, une nouvelle mémoire est générée
    via :func:`app.services.ai.copilot_memory.summarize_copilot_run` et
    exposée dans ``terminal_result["copilot_memory_new"]`` (cleartext).
    Vide = classeur neuf, pas de contexte hérité.
    """
    t_start = time.monotonic()
    # Auto-fill passe par l'ancien chemin (plus simple, ghost layer). L'agent
    # tool-loop est pour les instructions explicites de l'utilisateur.
    if is_auto_fill:
        return {"error": "L'agent copilot ne gère pas le mode auto-fill."}

    if not instruction or not instruction.strip():
        return {"error": "Instruction vide."}

    try:
        await ensure_providers_from_db()
    except Exception as exc:  # non-bloquant : fallback sur providers déjà chargés
        logger.debug("ensure_providers_from_db: %s", exc)

    manager = get_llm_manager()

    # --- Pseudonymisation opt-in pilotée utilisateur ---
    # Le SYSTÈME tokenise le classeur ; l'UTILISATEUR choisit (via le
    # panneau ``/data/privacy``) quels termes sont anonymisés. Seuls les
    # termes ``enabled=True`` sont remplacés par des ``§…§`` avant envoi
    # au LLM cloud (décision 2026-05-19 — sémantique opt-in).
    #
    # **Source de vérité** :
    #  - Si ``user_id`` est fourni (prod HTTP) → on LIT le state depuis la
    #    table ``anonymization_terms`` (repository async). Les nouveaux
    #    tokens détectés sont upsertés avec ``enabled=False, confirmed=False``
    #    pour que l'utilisateur les voie au prochain GET du panneau.
    #  - Sinon (tests unitaires, callers internes) → ``anonymization_state``
    #    kwarg sert de fallback. Évite de mocker la BDD dans chaque test.
    #
    # Aucun gate bloquant ``ANON_PENDING_REVIEW`` (supprimé 2026-05-08).
    # Les termes ``confirmed=False`` passent en clair par défaut. La
    # couche PII regex (``apply_builtin_pii`` plus bas) couvre toujours
    # email/phone/SIRET/SIREN/IBAN/AMOUNT systématiquement.
    from app.services.anonymization import extract as anon_terms

    current_tokens = anon_terms.extract_terms(tabs_context, sheet_content)

    if user_id is not None:
        try:
            from app.core.database import get_session_factory
            from app.services.anonymization import repository as anon_repo

            session_factory = get_session_factory()
            async with session_factory() as session:
                # Optim 2026-05-19 : ``scope_tokens=current_tokens`` restreint
                # la lecture aux termes potentiellement utiles pour ce run.
                # Sur un state user a 53k entries cross-classeurs et un
                # workbook de ~150 tokens, on lit 150 rows au lieu de 53k
                # (~660ms -> ~50ms mesure prod 2026-05-19). Trade-off : le
                # ``terminal_result["anonymization_state"]`` ne contiendra
                # que les termes du scope courant — c'etait deja un hint
                # cache pour le frontend (qui re-fetch /api/anonymization/terms
                # pour la vue complete cross-classeur).
                stored_state = await anon_repo.get_state_for_user(
                    session,
                    user_id,
                    scope_tokens=current_tokens,
                )
        except Exception as exc:
            # BDD indisponible : fail-closed. Mieux vaut refuser l'appel que
            # de laisser passer des cleartext au LLM sans l'opt-in utilisateur.
            logger.error(
                "copilot_agent: lecture state BDD user=%s échouée: %s",
                user_id,
                exc,
                exc_info=True,
            )
            return {
                "error": (
                    "Impossible de lire vos préférences d'anonymisation. "
                    "Réessayez dans un instant."
                ),
            }
    else:
        stored_state = anonymization_state

    reconciled_state, added_tokens, vanished_tokens = anon_terms.reconcile_state(
        current_tokens,
        stored_state,
    )

    # Persiste les nouveaux termes détectés dès maintenant (confirmed=False)
    # pour que le panneau GET suivant les voie. AUCUN gate ne bloque ce run :
    # les pending passent en clair par défaut (gate ``ANON_PENDING_REVIEW``
    # supprimé 2026-05-08 + opt-in David 2026-05-19, cf. docstring ci-dessus).
    #
    # **Guard quota** : on NE persiste QUE si l'ajout n'explose pas le cap
    # dynamique du user dérivé du quota disque (``get_user_term_cap``, depuis
    # 2026-05-19). Sans ce guard, un classeur généré pour contenir des milliers
    # de tokens uniques par requête saturerait la BDD. Tronqué alphabétiquement
    # pour comportement déterministe.
    if user_id is not None and added_tokens:
        try:
            from app.core.database import get_session_factory
            from app.services.anonymization import repository as anon_repo

            session_factory = get_session_factory()
            async with session_factory() as session:
                existing_count = await anon_repo.count_terms_for_user(session, user_id)
                user_term_cap = await anon_repo.get_user_term_cap(session, user_id)
                room_left = max(0, user_term_cap - existing_count)
                if room_left == 0:
                    logger.warning(
                        "copilot_agent: user=%s à la limite quota "
                        "(user_term_cap=%d, existing=%d), skip upsert "
                        "de %d nouveaux termes",
                        user_id,
                        user_term_cap,
                        existing_count,
                        len(added_tokens),
                    )
                else:
                    capped = sorted(added_tokens)[:room_left]
                    new_terms = {
                        t: reconciled_state["terms"][t]
                        for t in capped
                        if t in reconciled_state["terms"]
                    }
                    if new_terms:
                        # ``source`` / ``source_ref`` taggent l'origine pour
                        # le grouping par provenance dans /data/privacy.
                        # Le copilot_agent tourne TOUJOURS dans un contexte
                        # de classeur (sauvegardé ou non) → on force
                        # ``source="workbook"`` plutôt que de laisser
                        # tomber sur le default ORM ``"manual"`` qui
                        # produit le groupe « Origine inconnue » côté UI
                        # (bug observé 2026-05-20 : 564 termes orphelins
                        # quand workbook_ref=None pour un draft non sauvé).
                        # ``source_ref`` reste optionnel : un draft non
                        # sauvegardé apparaîtra sous « Classeurs » générique
                        # (label ``ref || 'Classeurs'`` dans privacy-page.js).
                        upsert_source = ANONYMIZATION_SOURCES_BY_NAME["workbook"]
                        await anon_repo.upsert_terms(
                            session,
                            user_id,
                            new_terms,
                            source=upsert_source,
                            source_ref=workbook_ref,
                        )
                        await session.commit()
                    if len(capped) < len(added_tokens):
                        logger.warning(
                            "copilot_agent: user=%s, %d/%d nouveaux termes "
                            "tronqués (quota disque user_term_cap=%d)",
                            user_id,
                            len(added_tokens) - len(capped),
                            len(added_tokens),
                            user_term_cap,
                        )
        except Exception as exc:
            # Non-fatal : le user les reverra au prochain send. Log pour
            # investigation sans exposer les tokens eux-mêmes.
            logger.warning(
                "copilot_agent: upsert nouveaux termes user=%s échoué (%d termes): %s",
                user_id,
                len(added_tokens),
                exc,
            )
    # Decision David 2026-05-19 (inverse 2026-05-08) : seuls les termes
    # ``enabled=True`` sont anonymises avant l'envoi au LLM cloud. Les
    # termes ``pending`` (``confirmed=False, enabled=False``) restent en
    # clair — c'est l'utilisateur qui decide quoi anonymiser via le
    # panneau ``/data/privacy``, pas le systeme par defaut.
    #
    # Rationale du retour a la semantique opt-in :
    #  - Le panneau ``/data/privacy`` doit refleter la realite. Si le
    #    systeme anonymise par defaut, le panneau ne sert qu'a "opt-out"
    #    pour les rares termes critiques — l'utilisateur n'a pas le
    #    controle reel.
    #  - La sur-anonymisation degrade le LLM : il voit des tokens §…§ qui
    #    cassent son raisonnement sur les donnees (impossible de joindre
    #    des references, comparer des noms, etc.).
    #  - La couche PII regex (``apply_builtin_pii`` plus bas dans cette
    #    fonction) protege toujours email/phone/SIRET/SIREN/IBAN/AMOUNT
    #    — les PII RGPD majeures ne fuient JAMAIS au LLM cloud.
    #  - Les noms propres / codes clients restent en clair tant que l'user
    #    ne les active pas. Acceptable car (a) l'organisation a autorise le
    #    cloud LLM par contrat, (b) c'est explicitement le choix user via
    #    le panneau.
    #
    # **PAS DE MUTATION DU STATE** ici : ``reconciled_state`` est passe tel
    # quel a ``build_user_pseudonymizer`` (ligne ~609) qui filtre
    # ``enabled=True`` en interne (extract.py:1511). Coherent avec proxy
    # et les autres call sites LLM cloud.
    pending = anon_terms.pending_terms(reconciled_state)
    if pending:
        logger.info(
            "copilot_agent: %d terme(s) non confirme(s) — laisses en clair "
            "(decision via /data/privacy). %d ajoute(s).",
            len(pending),
            len(added_tokens),
        )
        if vanished_tokens:
            logger.debug(
                "copilot_agent: %d termes du state non presents dans le scope "
                "courant (cross-classeur, normal sur state accumule).",
                len(vanished_tokens),
            )

    # Scope le pseudonymizer aux tokens du classeur courant : les termes
    # cross-classeur enabled=True qui ne peuvent pas matcher l'input actuel
    # ne chargent pas la regex de substitution. Gain perf proportionnel à
    # la taille du state global user vs classeur courant (5-10× observé
    # sur un state > 500 termes).
    pseudo = anon_terms.build_user_pseudonymizer(
        reconciled_state,
        scope_tokens=current_tokens,
    )
    logger.info(
        "copilot_agent: pseudonymizer prepared with %d entries "
        "(state_terms=%d, scoped_to_current=%d, added=%d).",
        len(pseudo),
        len(reconciled_state.get("terms", {})),
        len(current_tokens),
        len(added_tokens),
    )
    if vanished_tokens:
        logger.debug(
            "copilot_agent: pseudonymizer vanished=%d (cross-classeur, normal).",
            len(vanished_tokens),
        )
    tabs_context_anon = pseudo.anonymize(tabs_context) if tabs_context else tabs_context
    sheet_content_anon = pseudo.anonymize(sheet_content) if sheet_content else sheet_content
    instruction_anon = pseudo.anonymize_text(instruction)
    columns_anon = pseudo.anonymize(columns) if columns else columns
    sql_anon = pseudo.anonymize_text(sql) if sql else sql
    # display_state + sheet_context : non utilisés aujourd'hui par le
    # tool_loop, mais on les anonymise défensivement pour éviter une fuite
    # silencieuse si un futur commit les wire vers l'un des messages LLM
    # (fail-safe by construction).
    _ = pseudo.anonymize(display_state) if display_state else display_state
    _ = pseudo.anonymize(sheet_context) if sheet_context else sheet_context

    # Couche PII regex (proxy unifié — tâche #8) appliquée APRÈS le
    # pseudonymizer user-scoped. Capture les emails/SIRET/IBAN/téléphones/
    # montants que le pseudonymizer ne couvre pas (l'utilisateur n'a pas
    # forcément listé ses emails dans ``anonymization_terms``). Le bloc
    # « Confidentialité » du prompt système (injecté via
    # :func:`get_confidentiality_prompt("COPILOT")`) déclare au LLM la
    # convention `[TYPE_N]` en plus des `§…§` — runtime ↔ prompt aligné.
    #
    # ``pii_mapping`` et ``pii_counters`` sont partagés cross-payload
    # (instruction + tabs + sheet + columns + sql) pour que la même PII
    # apparaissant dans deux endroits différents reçoive le même token.
    # Stocké sur ``ctx`` pour que ``handle_ask_iris`` puisse aussi
    # restaurer côté outil avant exécution Sage.
    from app.services.anonymization.patterns import apply_builtin_pii
    from app.services.anonymization.proxy import (
        _pii_anonymize_recursive as _pii_anon_walk,
        _pii_restore_recursive as _pii_restore_walk,
    )

    pii_mapping: Dict[str, str] = {}
    pii_counters: Dict[str, int] = {}

    if instruction_anon:
        instruction_anon, _, _ = apply_builtin_pii(instruction_anon, pii_mapping, pii_counters)
    if sql_anon:
        sql_anon, _, _ = apply_builtin_pii(sql_anon, pii_mapping, pii_counters)
    if tabs_context_anon:
        tabs_context_anon = _pii_anon_walk(tabs_context_anon, pii_mapping, pii_counters)
    if sheet_content_anon:
        sheet_content_anon = _pii_anon_walk(sheet_content_anon, pii_mapping, pii_counters)
    if columns_anon:
        columns_anon = _pii_anon_walk(columns_anon, pii_mapping, pii_counters)

    ctx = CopilotContext(
        tabs_context=tabs_context_anon,
        sheet_content=sheet_content_anon,
        columns=columns_anon,
        sql=sql_anon,
        instruction=instruction_anon,
    )
    # Attache le pseudonymizer actif au contexte pour que `handle_ask_iris`
    # puisse désanonymiser le draft_sql avant exécution Sage et ré-anonymiser
    # les rows retournées (le LLM ne voit JAMAIS de cleartext).
    ctx._pseudonymizer = pseudo
    # Mapping PII regex partagé pour restore en fin de run (chainé
    # APRÈS ``pseudo.deanonymize``) et exposé pour ``handle_ask_iris``
    # / autres handlers tools qui ont besoin du cleartext.
    ctx._pii_mapping = pii_mapping
    ctx._pii_counters = pii_counters

    def _full_restore(payload: Any) -> Any:
        """Restore complet : pseudonymizer user-scoped puis PII regex.

        Ordre identique au proxy unifié
        (:func:`anonymize_for_llm.restore_fn`) — pseudonymizer d'abord
        car il a été appliqué en DERNIER à l'anonymisation, donc il
        doit être inversé en PREMIER au restore.

        ``pii_mapping`` est lu à l'appel (pas snapshot) — au fur et à
        mesure que les tools (``handle_ask_iris`` notamment) appellent
        ``apply_builtin_pii`` sur leurs résultats, ``pii_mapping``
        s'enrichit. Le restore final voit alors TOUS les tokens
        produits pendant le run (mid-run + initial). Cohérent avec le
        pattern de :mod:`iris_one_shot`. Si un futur refactor mute
        ``pii_mapping`` après le restore lock-in, il faudra snapshoter
        avec ``dict(pii_mapping)`` ici. Le pseudo, lui, est immuable
        après ``build_user_pseudonymizer`` — pas de risque.
        """
        if payload is None:
            return None
        # Guard ``pseudo``-may-be-None : aujourd'hui ``run_copilot_agent``
        # construit toujours un pseudo (cf. ligne ~574 ``build_user_pseudonymizer``),
        # mais un futur refactor pourrait introduire un mode sans user
        # (batch, tests). Aligne sur le pattern d'iris_one_shot — pas
        # de différence comportementale aujourd'hui, defense-in-depth contre
        # AttributeError silencieuse en hot-loop (appelé pour CHAQUE tool_input).
        result = payload
        if pseudo is not None and len(pseudo) > 0:
            result = pseudo.deanonymize(result)
        if pii_mapping:
            # Snapshot du mapping : si un futur refactor introduit du
            # parallel tool dispatch (parallel_tool_use Anthropic activé),
            # ``apply_builtin_pii`` pourrait muter ``pii_mapping`` pendant
            # qu'on itère dessus dans ``_pii_restore_walk`` → ``RuntimeError:
            # dict changed size during iteration``. Coût négligeable (<50
            # entrées typiquement), bénéfice : robuste à un changement de
            # stratégie de dispatch.
            result = _pii_restore_walk(result, dict(pii_mapping))
        return result

    # run_id + user_id pour la synchro progress store (todo-list). Les deux
    # doivent être présents pour que la sync s'active (isolation user stricte).
    ctx.run_id = run_id or ""
    ctx.user_id = user_id
    # Objet ORM ``User`` complet — propagé jusqu'à ``executor.execute`` via les
    # handlers de tool (``ask_iris``, ``modify_tab_sql``) pour activer le RLS
    # data_access. Distinct de ``user_id`` qui sert au pseudonymizer.
    ctx._user = user

    # Mémoire copilot : résumé factuel d'un run précédent sur le MÊME
    # classeur (persistance côté frontend dans le ``.afz.json``, relue via
    # le payload HTTP et passée ici).
    #
    # **Format storage** : la mémoire est stockée avec les tokens ``§…§``
    # INTACTS dans le ``.afz.json`` (choix sécurité v2 — cf section
    # "persistance anonymisée" à la fin du run). Empêche un leak cross-
    # user quand le classeur est partagé.
    #
    # **Traitement à la lecture** : on applique la pseudonymisation du run
    # courant pour que :
    #  1. Les tokens reconnus par l'user actuel se dé-anonymisent vers du
    #     cleartext (il voit ses propres données).
    #  2. Le cleartext résultant est RÉ-anonymisé avec les tokens du run
    #     COURANT (pour que les indices dans la mémoire correspondent à
    #     ce que le LLM va voir dans les tabs).
    #  3. Les tokens inconnus du pseudonymizer actuel (venant d'un autre
    #     user qui partageait le classeur) restent bruts — le LLM les
    #     verra mais n'aura aucune info pour les résoudre, ce qui est le
    #     comportement voulu (pas de leak).
    #
    # La sanitization finale (strip ``##``/``---``/``{}``) s'applique
    # dans :func:`_build_user_preamble` via ``sanitize_memory_for_prompt``.
    if copilot_memory:
        copilot_memory_cleartext = pseudo.deanonymize_text(copilot_memory)
        copilot_memory_anon = pseudo.anonymize_text(copilot_memory_cleartext)
    else:
        copilot_memory_anon = ""

    # Message utilisateur compact : instruction + liste courte des onglets pour
    # amorcer le raisonnement. Le LLM peut ensuite appeler list_tabs pour le détail.
    # Construit à partir des versions ANONYMISÉES — le LLM ne voit jamais cleartext.
    user_preamble = _build_user_preamble(
        instruction_anon,
        tabs_context_anon or [],
        sheet_content_anon or [],
        copilot_memory=copilot_memory_anon,
        selected_cells=selected_cells,
    )
    messages: List[Dict[str, Any]] = [
        {"role": "user", "content": user_preamble},
    ]

    # Profil utilisateur structuré (id, display_name, role) pour le bloc
    # "## À propos de l'utilisateur" du system prompt. Retourne ``None`` si
    # ``user_id`` absent ou user introuvable — dans ce cas le bloc est absent
    # du prompt (le template le rend comme chaîne vide). Fail-safe : toute
    # erreur BDD est avalée en WARNING dans ``build_user_profile`` ; le run
    # continue sans bloc profil plutôt que d'échouer.
    from app.services.ai.user_context import build_user_profile

    user_profile = await build_user_profile(user_id if isinstance(user_id, int) else None)

    # Résolution UNE fois par run des variables dynamiques du system prompt
    # (date/timezone + version SQL Server de la BDD connectée + profil user).
    # Les valeurs restent stables pendant la durée du run — le prompt est
    # donc cachable via le prompt caching Anthropic (ephemeral, TTL 1h si
    # endpoint éligible). Le bloc user est per-user donc cachable per-user.
    system_prompt = _build_copilot_system_prompt(user_profile=user_profile)

    # Audit log RGPD minimal : trace que des données ont été envoyées au
    # LLM externe, avec le profil d'anonymisation **configuré** par l'user.
    # On logge les COMPTES (jamais les termes eux-mêmes — zéro PII en log).
    #
    # **Sémantique des compteurs** : ``anonymized`` et ``cleartext`` reflètent
    # l'ÉTAT GLOBAL de l'utilisateur (tous classeurs confondus, v3), PAS
    # uniquement les termes qui toucheront cette requête précise. C'est un
    # choix délibéré : l'audit RGPD doit témoigner de la POSTURE de l'user
    # (ce qu'il a décidé de protéger vs laisser clair), pas de la substitution
    # effective qui dépend de quels tokens apparaissent dans l'input courant.
    # Un DPO qui demande "quelles valeurs X peut être envoyée au LLM ?"
    # regarde la table ``anonymization_terms`` pour ce user — pas ce log.
    _enabled_count = sum(
        1
        for entry in (reconciled_state.get("terms") or {}).values()
        if isinstance(entry, dict) and entry.get("enabled")
    )
    _clear_count = sum(
        1
        for entry in (reconciled_state.get("terms") or {}).values()
        if isinstance(entry, dict) and entry.get("confirmed") and not entry.get("enabled")
    )
    logger.info(
        "anon_audit user=%s run_id=%s anonymized=%d cleartext=%d "
        "pseudonym_entries=%d instruction_chars=%d",
        user_id if user_id is not None else "anon",
        run_id or "-",
        _enabled_count,
        _clear_count,
        len(pseudo),
        len(instruction or ""),
    )

    total_llm_ms = 0
    total_turns = 0
    for turn in range(MAX_TURNS):
        total_turns = turn + 1
        # Expose le numéro de turn (1-based) au ctx pour la boucle agent.
        ctx.turn_count = total_turns
        # Re-calcul à CHAQUE tour : si l'admin switch le provider via
        # /admin/ai-config pendant une session longue (Anthropic ↔ OpenAI),
        # les params s'adaptent au prochain appel au lieu de rester figés
        # sur l'ancien provider. Coût négligeable (1 getattr + 1 lookup dict).
        effort = _effort_params_for_provider(manager)
        request = LLMRequest(
            prompt="",  # messages portent la conversation
            system=system_prompt,
            temperature=0.2,
            max_tokens=effort["max_tokens"],
        )
        t_llm = time.monotonic()
        try:
            # thinking_budget active extended + interleaved thinking (header beta
            # `interleaved-thinking-2025-05-14`) pour Anthropic Sonnet/Opus 4.x+.
            # Sur Haiku / OpenAI / autre : ignoré silencieusement. Pour les modèles
            # adaptive (Sonnet 4.6+, Opus 4.6+, Mythos), le provider émet
            # `thinking.type.adaptive` + `output_config.effort=max` (cap dynamique
            # selon la difficulté, défaut le plus élevé).
            from app.services.ai.llm_runtime import (
                CallProfile,
                FallbackPolicy,
                RetryPolicy,
                call_llm_with_tools,
            )

            response = await call_llm_with_tools(
                CallProfile(
                    caller="copilot_workspace",
                    retry=RetryPolicy.NONE,  # boucle copilot gère ses propres retries via re-prompt
                    # Copilot SQL : génère du SQL exécuté sur les données
                    # client → chiffres sacrés, pas de fallback Ollama
                    # (cf. P1 #14, doctrine "résultats faux silencieux interdits").
                    fallback_policy=FallbackPolicy.NONE,
                ),
                request,
                tools=COPILOT_TOOLS,
                messages=messages,
                thinking_budget=effort["thinking_budget"],
            )
        except Exception as exc:
            # Log complet côté serveur (turn, type d'exception), message
            # client neutre — jamais de constante interne (MAX_TURNS, turn
            # courant) ni de trace détaillée qui ferait du serveur un
            # leaking oracle pour un attaquant.
            logger.error("Copilot agent LLM call failed at turn %d: %s", turn, exc)
            # Discriminer via ``LLMCallError.kind`` (post-llm_runtime) au lieu
            # de matcher ``str(exc).lower()`` qui ne match plus les messages
            # FR de notre LLMCallError ("⏳ Service LLM temporairement surchargé"
            # ne contient pas "overloaded" en lowercase).
            from app.services.ai.llm_runtime import LLMCallError as _LLMErr

            if isinstance(exc, _LLMErr):
                if exc.kind == "overloaded":
                    return {
                        "error": (
                            "⏳ Service LLM temporairement surchargé. "
                            "Ce n'est pas un bug de la demande — réessaie dans 1-2 minutes."
                        ),
                    }
                if exc.kind == "rate_limit":
                    return {
                        "error": (
                            "⏳ Quota LLM dépassé (rate limit). Réessaie dans " "quelques minutes."
                        ),
                    }
            return {"error": "Erreur interne du service LLM. Réessaie la demande."}
        total_llm_ms += round((time.monotonic() - t_llm) * 1000)

        content = response.get("content") or []
        # Task #18 (M6, 2026-05-22) — pas de scrub additionnel ici.
        # Adversarial review session 17 BLOCKING #3 : ajouter un scrub
        # AVANT `assert_safe_llm_blocks` (ligne ~976) MASQUE le fail-closed
        # (`DataAccessLeakDetectedError`) en remplaçant les noms denied par
        # `[…]` avant que l'assert les voie. La protection #106 (assert +
        # raise) reste la SSOT pour copilot_agent — elle est plus stricte
        # que le scrub et garantit que l'user voit un message d'erreur
        # explicite plutôt qu'un cellule cassée silencieusement.
        stop_reason = response.get("stop_reason")

        # **Phase 2.5.bis.6 (#106) — Garde-fou mode invisible sur sortie copilot.**
        # Le LLM peut halluciner un nom de table denied dans un block ``text``
        # (réflexion narrative finale, message d'erreur) ou ``thinking``
        # (raisonnement adaptive Sonnet 4.6+). Ces blocks finissent in fine
        # user-facing via ``ctx.terminal_result`` (affiché dans l'UI copilot)
        # OU dans le ``messages`` history qui peut être inspecté par d'autres
        # surfaces. On **fail-closed** via ``DataAccessLeakDetectedError`` ;
        # le caller (handlers/result_assistant.py) catche déjà tout
        # ``Exception`` et retourne ``INTERNAL_ERROR`` neutre au client.
        if user_id is not None and content:
            # **Phase 2.5.bis.6 follow-up (#120)** — Refactor pur : ce bloc
            # (concat text+thinking, concat tool_use.input, restore, assert)
            # vit maintenant dans ``assert_safe_llm_blocks`` côté
            # ``error_messages.py``. Comportement identique, code dédupliqué.
            from types import SimpleNamespace as _SimpleNamespace

            from app.services.data_access.error_messages import (
                DataAccessLeakDetectedError,
                assert_safe_llm_blocks,
            )

            _user_stub = _SimpleNamespace(id=user_id, role=None)
            _leak_msg = await assert_safe_llm_blocks(
                content,
                _user_stub,
                restore_fn=_full_restore,
                context_label="copilot_agent.run_copilot_agent",
                strict_when_no_user=True,
            )
            if _leak_msg is not None:
                logger.critical(
                    "copilot_agent: sortie LLM fuite un nom denied "
                    "user_id=%s turn=%d content_blocks=%d",
                    user_id,
                    turn,
                    len(content),
                )
                raise DataAccessLeakDetectedError(_leak_msg)

        # Détection précoce de stop_reason=max_tokens : la réponse est
        # TRONQUÉE à la limite output. Si on la ré-envoie telle quelle au
        # turn suivant, le dernier tool_use partiel produit un 400 API
        # (`invalid_request_error: tool_use.input is not valid JSON`). On
        # arrête net avec un message actionable plutôt que de renvoyer
        # une saleté qui va crasher au turn N+1.
        if stop_reason == "max_tokens":
            logger.warning(
                "Copilot turn %d: stop_reason=max_tokens — réponse tronquée, "
                "arrêt propre au lieu de propager un tool_use malformé.",
                turn,
            )
            return {
                "error": (
                    "Le LLM a atteint la limite max_tokens sur cette "
                    "génération — sa réponse est tronquée. Découpe la "
                    "tâche (ex : émets un onglet partiel puis étends via "
                    "`patch_tab`, ou simplifie la demande)."
                ),
            }

        # Accumule la réponse assistant (text + tool_use) telle quelle dans les
        # messages pour que le prochain appel voie la chaîne complète.
        messages.append({"role": "assistant", "content": content})

        # Collecte les tool_use blocks et les dispatche
        tool_use_blocks = [
            b for b in content if isinstance(b, dict) and b.get("type") == "tool_use"
        ]
        if tool_use_blocks:
            tool_results: List[Dict[str, Any]] = []
            for tb in tool_use_blocks:
                tool_name = tb.get("name") or ""
                tool_input = tb.get("input") or {}
                tool_use_id = tb.get("id") or ""
                logger.info(
                    "Copilot turn %d: tool=%s input_keys=%s",
                    turn,
                    tool_name,
                    list(tool_input.keys()) if isinstance(tool_input, dict) else None,
                )
                # Doctrine d'anonymisation Komptia : le LLM voit du tokenisé
                # (§…§ pseudo + [TYPE_N] PII) mais les handlers système doivent
                # recevoir du cleartext. Sans ce restore, un LLM qui sort
                # ``match={"TIERS": "§DUPONT§"}`` produit un filtre qui ne
                # matche aucune cellule (les cellules ont été anonymisées au
                # build du context et seraient comparées contre le token
                # tel quel) → 0 hit silencieux, boucles infinies de
                # reformulation. ``_full_restore`` chaîne pseudo + PII dans
                # le bon ordre (cf. closure ligne ~653).
                tool_input = _full_restore(tool_input)
                # Marque le tool comme "en cours" avant le dispatch — le
                # frontend polle cette valeur pour afficher "Lecture
                # onglet…" / "Création de l'onglet…" / etc. en plus du
                # plan_in_progress. Cumul = transparence maximale sans
                # logs. Best-effort : un échec d'écriture du store ne
                # doit pas crasher le dispatch (logue warning, continue).
                #
                # PAS de reset à None après dispatch : sur les tools
                # rapides (count_rows ~50ms), un cycle set→reset→set
                # complet en <1s rendrait l'info invisible au polling
                # 1s (review adv High #2). En gardant la dernière valeur,
                # le polling montre soit le tool en cours, soit le dernier
                # tool exécuté pendant que le LLM "réfléchit" (call_llm en
                # vol). Le finally du caller (clear_progress) purge tout
                # à la fin du run.
                if ctx.run_id and ctx.user_id is not None:
                    try:
                        from app.services.ai.copilot_progress_store import (
                            set_tool_in_use,
                        )

                        await set_tool_in_use(ctx.user_id, ctx.run_id, tool_name)
                    except Exception:  # noqa: BLE001
                        logger.debug(
                            "set_tool_in_use a levé (non critique)",
                            exc_info=True,
                        )
                result = await dispatch_copilot_tool(tool_name, tool_input, ctx)
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": json.dumps(result, ensure_ascii=False, default=str),
                    }
                )
                # Stop signal : done / abandon. Les autres outils-actions
                # (emit_tab, emit_via_code, patch_tab, rename_tab, delete_tab)
                # sont non-terminaux — leurs résultats sont collectés dans
                # ctx.emits / ctx.modifications et seront packés au commit
                # final via ``done``.
                if ctx.terminal_kind in ("done", "abandon"):
                    break
            # Append tool_results au user message suivant
            messages.append({"role": "user", "content": tool_results})
            # Si terminal déclenché, on sort tout de suite
            if ctx.terminal_kind == "done" and isinstance(ctx.terminal_result, dict):
                metrics_update = {
                    "llm_ms": total_llm_ms,
                    "total_ms": round((time.monotonic() - t_start) * 1000),
                    "turns": total_turns,
                    "pseudonym_entries": len(pseudo),
                }
                # Rétro-injection des substitutions sémantiques déclarées par
                # le LLM via ``explain_substitution``. L'utilisateur les voit
                # dans le résultat final pour pouvoir les vérifier (et
                # corriger si le LLM a mal traduit son terme).
                if ctx.substitutions:
                    metrics_update["substitutions"] = list(ctx.substitutions)
                ctx.terminal_result.setdefault("metrics", {}).update(metrics_update)
                # CRITIQUE — adversarial review 2026-05-19 finding #9 :
                # ``reconciled_state`` est SCOPE-FILTRÉ (cf. ligne 453
                # ``scope_tokens=current_tokens`` — optim perf 53k→150
                # rows). Le retourner tel quel au frontend serait
                # DESTRUCTIF : ``iris-grid.js:_setAnonymizationState``
                # ÉCRASE le state local + un PUT subsequent au backend
                # supprimerait les 52k+ termes cross-classeur absents
                # du scope (PUT terms a sémantique REPLACE, cf.
                # ``handlers/anonymization.py:255``).
                #
                # Solution : re-fetch SANS ``scope_tokens`` pour rétablir
                # la vue complète avant retour. Coût = 1 SELECT
                # supplémentaire (toujours négligeable vs un run
                # copilot multi-LLM-call). Préserve l'invariant frontend
                # "le state retourné par le backend = ce qu'il faut
                # avoir en cache local".
                if user_id is not None:
                    try:
                        from app.core.database import get_session_factory
                        from app.services.anonymization import repository as anon_repo_fp

                        session_factory_fp = get_session_factory()
                        async with session_factory_fp() as session_fp:
                            full_state = await anon_repo_fp.get_state_for_user(session_fp, user_id)
                        ctx.terminal_result["anonymization_state"] = full_state
                    except Exception:
                        # Fail-soft : si la re-lecture casse, on n'expose
                        # PAS le state scope-filtré (qui ferait perdre des
                        # données au PUT) — on n'expose RIEN. Le frontend
                        # gardera son cache local actuel jusqu'au prochain
                        # GET /api/anonymization/terms (ouverture modale
                        # Confidentialité ou refresh page).
                        logger.warning(
                            "copilot_agent: re-fetch full anon state KO, "
                            "skip anonymization_state in terminal_result",
                            exc_info=True,
                        )
                else:
                    # Pas de user_id (tests/scripts) : on retourne le
                    # ``reconciled_state`` puisqu'il n'y a pas de risque
                    # de PUT destructif (pas de session frontend).
                    ctx.terminal_result["anonymization_state"] = reconciled_state

                # Mémoire fin-de-run : appel LLM léger best-effort qui
                # résume la STRUCTURE et les DÉCISIONS apprises sur ce
                # classeur (pas les données) pour qu'un futur run n'ait
                # pas à re-explorer.
                #
                # **Persistance ANONYMISÉE** (choix sécurité v2) : le
                # résumé est stocké avec les tokens ``§…§`` INTACTS dans
                # le ``.afz.json``, PAS en cleartext. Rationale : un
                # classeur peut être partagé entre users (upload/download
                # commun). Si User A ne pseudonymise pas ``ENTITE_X`` et
                # que cet en clair apparaît dans la mémoire
                # ``.afz.json``, User B qui ouvre le classeur verrait
                # cette donnée partir dans son prompt LLM sans y avoir
                # consenti (purpose-limitation RGPD art. 5.1.b). En
                # stockant les tokens bruts, chaque user qui ouvre le
                # classeur les traduit avec SON propre pseudonymizer au
                # run suivant — les tokens connus se dé-anonymisent selon
                # son state, les inconnus restent des tokens.
                #
                # **Filtrage des tokens hallucinés** : si le LLM a produit
                # un ``§CLIENT_Z§`` qui n'est pas dans son propre
                # pseudonymizer du run courant (hallucination), on le
                # strip pour éviter qu'il corrompe le prompt du run
                # suivant (token orphelin qui ne se dé-anonymise jamais).
                #
                # Fail-safe : toute exception du LLM est silencieuse (log
                # WARNING) et ``copilot_memory_new`` reste absent.
                from app.services.ai.copilot_memory import (
                    filter_unknown_pseudonym_tokens,
                    summarize_copilot_run,
                )

                memory_anon = await summarize_copilot_run(ctx, manager)
                memory_for_storage: Optional[str] = None
                if memory_anon:
                    known_tokens = set(getattr(pseudo, "_reverse", {}).keys())
                    memory_for_storage = (
                        filter_unknown_pseudonym_tokens(memory_anon, known_tokens) or None
                    )

                # Dé-anonymisation finale : l'utilisateur voit cleartext dans
                # tab.rows, labels, match, descriptions (et patches pour le
                # type patch_tab). Les numériques et tokens hors-table passent
                # inchangés (fail-open, zéro blocage). Les métriques de
                # pseudonymisation restent en clair (count d'entrées — pas
                # de valeurs).
                #
                # **Attention** : ``copilot_memory_new`` doit être stockée
                # AVEC ses tokens ``§…§`` INTACTS dans le ``.afz.json``
                # pour empêcher un leak cross-user (cf commentaire
                # sécurité ci-dessus). On l'ajoute APRÈS la dé-anonymisation
                # pour échapper à la traversal.
                final_result = _full_restore(ctx.terminal_result)
                if memory_for_storage and isinstance(final_result, dict):
                    final_result["copilot_memory_new"] = memory_for_storage

                # [DEBUG TEMPORAIRE] Interview post-run : si pendant le run le
                # preview a détecté des positions uncovered avec
                # ``reference_sqls`` disponibles (flag ``_iris_debug_needs_interview``
                # levé par ``handle_preview_emit_tab`` / ``handle_emit_via_code``),
                # poser UNE question surprise au LLM maintenant que le run est
                # terminé. Le LLM n'a PAS vu cette question pendant son run —
                # son comportement n'est donc pas influencé. La réponse est
                # automatiquement capturée dans ``llm_log.md`` via le logger
                # provider. Non-bloquant : exception avalée en WARNING, le
                # terminal_result est retourné dans tous les cas.
                # À RETIRER avec les flags ``_iris_call_attempts`` /
                # ``_iris_debug_needs_interview`` quand le debug est terminé.
                if getattr(ctx, "_iris_debug_needs_interview", False):
                    try:
                        from app.services.ai.copilot_tools import (
                            _build_iris_refusal_interview_prompt,
                        )

                        interview_question = _build_iris_refusal_interview_prompt(ctx)
                        interview_messages = list(messages) + [
                            {"role": "user", "content": interview_question}
                        ]
                        from app.services.ai.llm_runtime import (
                            CallProfile,
                            call_llm_with_tools,
                            compute_effort_params,
                            is_response_truncated,
                        )

                        # Active extended thinking si Anthropic Sonnet/Opus.
                        # max_tokens conservateur (interview = question courte)
                        # mais le thinking_budget bénéficie du raisonnement
                        # interne pour formuler une question pertinente.
                        clarify_effort = compute_effort_params(manager)
                        interview_request = LLMRequest(
                            prompt="",
                            system=system_prompt,
                            temperature=0.2,
                            max_tokens=clamped_max_tokens(2000),
                        )
                        # RetryPolicy.STANDARD (défaut) — best-effort, le retry
                        # absorbe les 5xx/network transitoires.
                        clarify_response = await call_llm_with_tools(
                            CallProfile(caller="copilot_clarify"),
                            interview_request,
                            tools=[],
                            messages=interview_messages,
                            thinking_budget=clarify_effort["thinking_budget"],
                        )
                        # Détection troncature : ici tools=[] donc pas de risque
                        # de tool_use partiel, mais le log signale quand le
                        # thinking budget consomme tout (réponse vide → fail-safe
                        # déjà géré par le ``except`` plus bas qui avale les
                        # erreurs en WARNING — interview = best-effort).
                        if is_response_truncated(clarify_response):
                            logger.warning(
                                "[DEBUG] copilot_clarify atteint max_tokens — "
                                "réponse possiblement tronquée."
                            )
                    except Exception as _exc:
                        logger.warning(
                            "[DEBUG] interview post-run ask_iris refusal failed: %s",
                            _exc,
                        )
                return final_result
            if ctx.terminal_kind == "abandon":
                return _full_restore(ctx.terminal_result or {"error": "Copilot a abandonné."})
            if ctx.terminal_kind == "emit_tab_error":
                # Le LLM a appelé emit_tab avec des args invalides. On le laisse
                # corriger en next turn (reset flag pour retry).
                ctx.terminal_kind = None
                ctx.terminal_result = None
                continue
            continue

        # Pas de tool_use : le LLM a répondu par du texte final
        if stop_reason == "end_turn":
            text_blocks = [
                b.get("text", "")
                for b in content
                if isinstance(b, dict) and b.get("type") == "text"
            ]
            final_text = "\n".join(t for t in text_blocks if t).strip()
            if ctx.terminal_result:
                return _full_restore(ctx.terminal_result)
            # Le final_text du LLM contient potentiellement des tokens
            # anonymisés — on dé-anonymise avant d'afficher à l'utilisateur.
            # Chain pseudo + PII regex pour symétrie avec ``_full_restore``.
            final_text_clear = pseudo.deanonymize_text(final_text)
            if pii_mapping and isinstance(final_text_clear, str):
                final_text_clear = _pii_restore_walk(final_text_clear, pii_mapping)
            return {
                "error": (
                    "Le copilot a répondu sans émettre d'onglet. Message : "
                    f"{final_text_clear[:400] or '(vide)'}"
                ),
            }
        # Note : stop_reason=="max_tokens" est intercepté en AMONT de la boucle
        # tool_use (cf. le bloc early-return plus haut) pour éviter de
        # propager un tool_use tronqué au turn suivant. On ne peut donc pas
        # atterrir ici avec ce stop_reason. Garde un fallback défensif pour
        # tout autre stop_reason inattendu.
        if stop_reason and stop_reason != "tool_use":
            logger.warning("Copilot agent stop_reason inattendu: %s", stop_reason)
            return {"error": f"Arrêt LLM inattendu : {stop_reason}"}

    # Budget tours épuisé sans avoir atteint un outil terminal explicite
    # (``done`` / ``abandon``). On packe les actions DÉJÀ effectuées
    # (emit_tab, emit_via_code, patch_tab, rename_tab, delete_tab) dans le
    # retour pour ne RIEN perdre — même si l'agent n'a pas pu finaliser,
    # ce qu'il a produit est appliqué au classeur. Le frontend détecte
    # ``type == "max_turns_reached"`` et affiche le message d'invitation
    # à reprendre dans le chat ; les ``emits`` / ``modifications`` sont
    # appliqués comme un ``done`` classique.
    logger.warning(
        "Copilot agent: budget tours épuisé (MAX_TURNS=%d) — %d emits, %d modifications",
        MAX_TURNS,
        len(ctx.emits),
        len(ctx.modifications),
    )
    payload: Dict[str, Any] = {
        "type": "max_turns_reached",
        "message": (
            "L'agent a tourné un long moment sans aboutir explicitement. "
            "Ce qu'il a produit jusqu'ici a été appliqué. "
            "Si tu veux qu'il poursuive, tape simplement de quoi le relancer "
            "(par exemple « continue », « vas-y », « termine ») dans ta "
            "prochaine demande — il reprendra avec la mémoire de ce run."
        ),
        "emits": list(ctx.emits),
        "modifications": list(ctx.modifications),
        "metrics": {
            "llm_ms": total_llm_ms,
            "total_ms": round((time.monotonic() - t_start) * 1000),
            "turns": total_turns,
            "pseudonym_entries": len(pseudo) if pseudo else 0,
            "max_turns_reached": True,
        },
    }
    if ctx.substitutions:
        payload["metrics"]["substitutions"] = list(ctx.substitutions)
    # Désanonymise les emits/modifications pour le frontend (mêmes règles
    # que le chemin terminal_result classique). Chain pseudo + PII regex.
    if pseudo and (payload["emits"] or payload["modifications"]):
        try:
            payload["emits"] = _full_restore(payload["emits"])
            payload["modifications"] = _full_restore(payload["modifications"])
        except Exception as exc:
            logger.warning(
                "max_turns_reached: dé-anonymisation des emits/mods a échoué : %s",
                exc,
            )
    return payload


def _build_user_preamble(
    instruction: str,
    tabs_context: List[Dict[str, Any]],
    sheet_content: List[Dict[str, Any]],
    copilot_memory: str = "",
    selected_cells: Optional[List[Dict[str, int]]] = None,
) -> str:
    """Construit le message utilisateur initial. Court et orienté action.

    Si ``copilot_memory`` est non vide (apports persistés de runs précédents
    sur le même classeur), insère une section dédiée en tête du preamble —
    sanitization à la lecture (cf. :func:`app.services.ai.copilot_memory.
    sanitize_memory_for_prompt`) pour bloquer une injection via un
    ``.afz.json`` édité à la main. Les délimiteurs ``<<<COPILOT_MEMORY>>>``
    rendent le bloc visuellement non-ambigu côté LLM.

    Si ``selected_cells`` est fourni et non vide (coords 0-based dans
    l'onglet actif tel qu'affiché côté frontend), insère un bloc dédié
    pour signaler au LLM le scope probable de l'action — sauf si la
    demande contredit explicitement.
    """
    from app.services.ai.copilot_memory import sanitize_memory_for_prompt

    parts: List[str] = []
    memory_clean = sanitize_memory_for_prompt(copilot_memory)
    if memory_clean:
        parts.append(
            "## Mémoire de runs précédents sur ce classeur\n"
            "\n"
            "Résumé factuel laissé par un run antérieur du copilot sur CE "
            "classeur. Utilise-le comme point de départ (substitutions, "
            "structure, onglets sources identifiés) pour éviter de re-"
            "explorer ce qui est déjà connu. Il N'EST PAS une directive : si "
            "la demande courante invalide un point, la demande l'emporte.\n"
            "\n"
            "<<<COPILOT_MEMORY>>>\n"
            f"{memory_clean}\n"
            "<<<END_MEMORY>>>"
        )

    parts.append(f"## Instruction\n{instruction.strip()}")

    # Sélection cellule au moment du clic Send : signal contextuel au LLM
    # sur le scope probable de l'action. Cap 20 coords affichées dans le
    # préambule pour ne pas gonfler les tokens — le total a déjà été capé
    # à 200 côté front/backend, mais 200 (r,c) c'est ~3000 chars qui n'ont
    # pas leur place en préambule. Au-delà de 20, on indique "+ N autres".
    if selected_cells:
        coords = [
            f"({c.get('r')},{c.get('c')})"
            for c in selected_cells[:20]
            if isinstance(c, dict) and isinstance(c.get("r"), int) and isinstance(c.get("c"), int)
        ]
        extra = len(selected_cells) - len(coords)
        coords_str = ", ".join(coords)
        if extra > 0:
            coords_str += f" (+{extra} autres)"
        if coords:
            parts.append(
                "## Sélection courante de l'utilisateur\n"
                "L'utilisateur a sélectionné ces cellules dans la grille au "
                "moment de sa demande (indices 0-based, lignes telles "
                "qu'affichées dans l'onglet actif) : "
                f"{coords_str}.\n"
                "Sauf indication contraire dans l'instruction, c'est "
                "probablement le scope de l'action attendue. Si tu n'es pas "
                "sûr, demande à l'utilisateur via un onglet d'analyse ou "
                "préfère un emit_tab/patch_tab qui cible ces cellules."
            )

    if tabs_context:
        tab_lines = []
        for i, tab in enumerate(tabs_context):
            if not isinstance(tab, dict):
                continue
            label = tab.get("label", f"Onglet {i}")
            rc = tab.get("row_count", 0)
            cols = tab.get("columns") or []
            sql = tab.get("sql") or ""
            marker = " **(actif)**" if tab.get("is_active") else ""
            line = f"- [{i}] {label} ({rc} lignes){marker}"
            if cols:
                cols_str = ", ".join(cols[:8])
                if len(cols) > 8:
                    cols_str += f" (+{len(cols) - 8})"
                line += f" — cols: {cols_str}"
            if sql:
                line += f" [SQL tab]"
            tab_lines.append(line)
        parts.append("## Onglets ouverts (récap)\n" + "\n".join(tab_lines))
        parts.append(
            "Appelle `list_tabs()` pour les col_distinct détaillées, puis "
            "`read_tab_rows(<idx>)` sur le template à reproduire."
        )

    if sheet_content:
        # Petit teaser : quelques cellules de l'actif pour amorcer
        active_idx = next(
            (i for i, t in enumerate(tabs_context) if isinstance(t, dict) and t.get("is_active")),
            -1,
        )
        preview_count = min(12, len(sheet_content))
        preview = sheet_content[:preview_count]
        parts.append(
            f"## Actif (aperçu {preview_count} premières cellules — utilise "
            f"read_tab_rows({active_idx}, 0, 60) pour tout lire)\n"
            + json.dumps(preview, ensure_ascii=False, default=str)
        )

    return "\n\n".join(parts)


def _effort_params_for_provider(manager: Any) -> Dict[str, int]:
    """Thin wrapper sur :func:`compute_effort_params` du runtime unifié.

    Préserve la réserve thinking ``_THINKING_RESERVE_TOKENS`` (8K) propre au
    copilot. Le cap output passe désormais par la SSoT ``LlmModel.max_tokens``
    (registre BDD /admin/ai-models) — plus de hard_cap local hardcodé.
    Cohérent avec iris_one_shot, copilot_clarify qui appellent déjà
    ``compute_effort_params(manager)`` sans hard cap.
    """
    from app.services.ai.llm_runtime import compute_effort_params

    return compute_effort_params(
        manager,
        thinking_reserve_tokens=_THINKING_RESERVE_TOKENS,
    )
