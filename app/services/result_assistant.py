"""
Result Assistant — Modification one-shot des résultats SQL via LLM.

Reçoit le SQL courant + une instruction utilisateur, et retourne
soit un nouveau SQL à exécuter, soit des actions d'affichage frontend.
"""

import asyncio
import hashlib
import json
import logging
import re
import time
import uuid
from difflib import get_close_matches
from typing import Any, Dict, List, Optional, Tuple

from app.services.ai.llm_providers import (  # noqa: F401 — get_llm_manager est patché par les tests via ce ré-export
    LLMRequest,
    ensure_providers_from_db,
    get_llm_manager,
)
from app.services.ai.llm_runtime import (
    CallProfile,
    FallbackPolicy,
    LLMCallError,
    RetryPolicy,
    call_llm,
)
from app.constants_ai import clamped_max_tokens
from app.services.ai.cte_regex import CTE_HEADER_PATTERN, CTE_HEADER_RE
from app.services.ai.training_store import get_training_store
from app.services.anonymization import anonymize_for_llm
from app.services.anonymization.proxy import get_confidentiality_prompt
from app.services.database.sage_connector import get_sage_connector
from app.services.sheet_analyzer import (
    SheetAnalysis,
    analyze_sheet,
    format_analysis_for_prompt,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Proxy d'anonymisation — helper unifié pour les 8 LLM call sites
# ---------------------------------------------------------------------------


class ProxyAnonymizationError(Exception):
    """Levée quand le proxy d'anonymisation refuse l'appel LLM (fail-closed).

    Distincte de :class:`Exception` générique (LLM cloud down, parse JSON
    raté, etc.) pour que le caller puisse afficher un message dédié à
    l'utilisateur (« Anonymisation indisponible — vérifiez vos termes
    confidentialité ») au lieu de masquer la cause sous une erreur SQL
    ou un cte_error sans rapport.

    Wrap les ``RuntimeError`` du proxy (pseudonymizer incomplet,
    BDD ``anonymization_terms`` corrompue, collision de pseudo_middle
    silencieuse).
    """


async def _call_llm_anon(
    profile: CallProfile,
    request: LLMRequest,
    user_id: Optional[int],
    *,
    inject_style_rules: bool = True,
):
    """Wrappe :func:`call_llm` avec le proxy d'anonymisation Komptia.

    Pattern unifié pour les 8 call sites de ``result_assistant`` (tâche
    #8 du loop d'anonymisation) : (1) anonymise ``request.prompt`` via
    :func:`anonymize_for_llm` (couche PII regex + pseudonymizer
    user-scoped), (2) préfixe ``request.system`` avec le bloc
    « Confidentialité » du proxy, (3) délègue à ``call_llm``, (4)
    retourne ``(response, restore_fn)`` — le caller appelle
    ``restore_fn(response.content)`` pour obtenir le cleartext avant
    parsing JSON / extraction SQL.

    ``user_id=None`` (caller interne / tests) → couche PII regex
    seulement (pseudonymizer skip cheap). Le bloc « Confidentialité »
    est toujours injecté pour garantir la cohérence d'instruction au
    LLM (mention ``§…§`` même si vide — instruction parasite mineure
    cf. EPIC E19, à durcir tâche #17).

    Préserve ``prompt_cache_prefix`` du caller pour ne pas casser le
    cache Anthropic. Reconstruit ``LLMRequest`` via
    ``dataclasses.replace`` pour prendre en compte tout futur champ
    automatiquement (cf. EPIC E21).

    Raises:
        ProxyAnonymizationError: si le proxy refuse l'appel
            (pseudonymizer incomplet, fail-closed). Le caller doit
            afficher un message dédié à l'utilisateur.
        Exception: erreurs LLM cloud (rate limit, timeout, 5xx) —
            traitées comme avant par les except génériques des callers.
    """
    import dataclasses

    try:
        prompt_anon, restore_fn = await anonymize_for_llm(user_id, request.prompt, "COPILOT")
    except RuntimeError as exc:
        # Le proxy fail-closed quand le pseudonymizer est incohérent.
        # On wrappe pour distinguer du cas "LLM cloud down" et donner
        # au caller la possibilité de surfacer une erreur dédiée.
        raise ProxyAnonymizationError(str(exc)) from exc

    existing_system = request.system or ""
    # Injecte OUTPUT_STYLE_RULES pour couvrir les 8 call-sites de
    # result_assistant en un seul point (versioned_*, suggest_prompt_final,
    # correction SQL...) — sans ça, le bug Iris (mockup ASCII + jargon
    # technique non sollicité) corrigé task #18 pouvait se reproduire ici
    # côté result_assistant qui génère aussi des labels narratifs PDF +
    # suggestions user-facing.
    #
    # 3 sécurités (adversarial #3, #4, #5 sur fix #19) :
    #   • Position APRÈS ``existing_system`` : si le system spécifique
    #     impose un format JSON/SQL strict, il garde priorité (recency
    #     bias LLM). Place OUTPUT_STYLE_RULES en queue = soft guideline,
    #     ne contredit pas un format strict.
    #   • Anti-duplication : skip si ``existing_system`` contient déjà le
    #     bloc (caller historique qui aurait fait l'injection en amont).
    #   • Opt-out via ``inject_style_rules=False`` pour les sites SQL
    #     strict courts (« Tu corriges du SQL Server. » + ratio inflation
    #     prompt cassait le focus du LLM).
    from app.services.ai.agent_roles import OUTPUT_STYLE_RULES

    should_inject_style = inject_style_rules and "représentation visuelle" not in existing_system
    style_tail = ("\n\n" + OUTPUT_STYLE_RULES) if should_inject_style else ""
    new_system = (
        get_confidentiality_prompt("COPILOT")
        + ("\n\n" + existing_system if existing_system else "")
        + style_tail
    )
    safe_request = dataclasses.replace(
        request,
        prompt=prompt_anon,
        system=new_system,
    )

    # **Phase 3.4/3.5 (#65/#66) defense-in-depth** : on passe ``user=`` au
    # gate runtime ``call_llm``. Si le filtrage source amont (Phase α)
    # a un bug et qu'un nom denied passe dans le prompt, ``call_llm`` lève
    # ``InvisibleLeakError`` AVANT l'envoi au provider. Le caller catche
    # déjà l'exception générique → message FR neutre côté client.
    # ``role=None`` : suffisant pour le gate (admin bypass est géré via
    # ``has_restrictions=False`` au niveau de la view, pas du role direct).
    _user_for_gate = None
    if user_id is not None:
        from types import SimpleNamespace as _SimpleNamespace

        _user_for_gate = _SimpleNamespace(id=user_id, role=None)
    response = await call_llm(profile, safe_request, user=_user_for_gate)

    # **Phase 2.5.bis.ter (#103) — Garde-fou mode invisible sur sortie LLM.**
    # Toutes les sorties LLM de ``result_assistant`` finissent user-facing
    # (suggestions Iris, labels narratifs PDF, plans JSON, SQL généré).
    # Le LLM peut halluciner un nom de table denied (atomique OU via closure
    # transitive). On **fail-closed** via ``DataAccessLeakDetectedError``
    # ici — single source of truth pour les 8 call-sites du module.
    #
    # Pourquoi assert (raise) plutôt que scrub textuel : le content peut être
    # SQL/JSON structuré ; un scrub `→ […]` corromprait la syntaxe. Mieux
    # vaut un message d'erreur clair qu'un résultat partiellement mutilé.
    # Les callers existants ne catchent PAS encore ``DataAccessLeakDetectedError``
    # → propagation jusqu'au handler → error.html. Acceptable pour un
    # événement rare (LLM hallucine un nom interdit) ; la garantie sécurité
    # prime sur l'UX dégradée.
    if user_id is not None and response.content is not None:
        from types import SimpleNamespace as _SimpleNamespace

        from app.services.data_access.error_messages import (
            DataAccessLeakDetectedError,
            assert_safe_llm_response,
        )

        # **Adversarial review #103 BLOCKING-defense** : ``LLMResponse.content``
        # est typé ``str`` (cf. ``llm_providers.LLMResponse``). Si un futur
        # provider retourne autre chose (list[ContentBlock] / bytes / dict),
        # on ne veut pas silencieusement skip le check → on log WARNING fort
        # et fail-closed via raise (le caller catche ou propage à error.html).
        if not isinstance(response.content, str):
            logger.warning(
                "result_assistant._call_llm_anon: response.content type "
                "inattendu (%s) — type str attendu. Mode invisible check "
                "skip ce response (provider=%s, user_id=%s). Investiger : "
                "soit le provider a changé son contrat, soit un caller "
                "injecte un mock invalide.",
                type(response.content).__name__,
                response.provider,
                user_id,
            )
        elif response.content:
            cleartext_for_check = restore_fn(response.content)
            user_stub = _SimpleNamespace(id=user_id, role=None)
            leak_msg = await assert_safe_llm_response(
                cleartext_for_check,
                user_stub,
                context_label="result_assistant._call_llm_anon",
                strict_when_no_user=True,
            )
            if leak_msg is not None:
                logger.critical(
                    "result_assistant: sortie LLM fuite un nom denied "
                    "user_id=%s (content_len=%d)",
                    user_id,
                    len(response.content),
                )
                raise DataAccessLeakDetectedError(leak_msg)

            # **Adversarial review #103 CRITICAL #2 fix** : ``restore_fn`` est
            # appelé une fois ici et une 2e fois par le caller. Pour éviter
            # tout risque de double-restore non-idempotent (cas exotique :
            # cleartext contenant un pattern qui ressemble à un pseudo
            # ``§ENT_X§`` ou un placeholder PII ``[TYPE_N]``), on mute
            # ``response.content`` avec le cleartext. Le 2e appel de
            # ``restore_fn`` côté caller devient strictement no-op (pas
            # de pattern à matcher dans le cleartext).
            response.content = cleartext_for_check

    return response, restore_fn


# Tables extraites du SQL via regex (FROM, JOIN)
_TABLE_RE = re.compile(
    r"(?:FROM|JOIN)\s+(?:\[?(\w+)\]?\.)?(?:\[?(\w+)\]?\.)?(\[?\w+\]?)",
    re.IGNORECASE,
)

COPILOT_MODEL = ""  # Empty = use default model from config

# Caller niveau infini — ``sage_connector.execute()`` applique
# ``min(MAX_RESULT_ROWS, db_conn.max_rows)``. La valeur saisie via
# /admin/database est l'UNIQUE source de vérité du plafond effectif.
# Le rendu DOM est protégé par RENDER_LIMIT=200 côté JS (affichage progressif).
MAX_RESULT_ROWS = 1_000_000_000
_FILL_SQL_MAX_CONCURRENT = 5  # C5: max requêtes Sage simultanées pour fill_sql
_DETAIL_MAX_ROWS = 0  # Pas de limite — l'utilisateur voit toutes les lignes de détail

# Cache de déduplication pour éviter les appels LLM identiques en boucle.
# Clé = hash(instruction + sheet_content), valeur = timestamp.
_recent_requests: Dict[str, float] = {}
_DEDUP_TTL_SECONDS = 30

# Cache DDL schema — le DDL est invariant pendant une session (B3 fix).
# Clé = hash trié des noms de tables, valeur = (ddl_text, timestamp).
_ddl_cache: Dict[str, Tuple[str, float]] = {}
_DDL_CACHE_TTL = 300  # 5 minutes

# Regex pour extraire les colonnes GROUP BY d'un SQL
_GROUP_BY_RE = re.compile(
    r"GROUP\s+BY\s+([\w\s,.\[\]]+?)(?:\s+HAVING|\s+ORDER|\s*$|\s*\))",
    re.IGNORECASE,
)

# Regex pour extraire les colonnes SELECT d'un CTE single-table-of-head.
# Group 1 (de CTE_HEADER_PATTERN) = nom du CTE ; Group 2 (ajouté ici) = body SQL.
_CTE_SELECT_RE = re.compile(
    CTE_HEADER_PATTERN + r"(.*?)\)\s+SELECT",
    re.IGNORECASE | re.DOTALL,
)
_SELECT_COLUMNS_RE = re.compile(
    r"SELECT\s+(.*?)\s+FROM",
    re.IGNORECASE | re.DOTALL,
)


def _dedup_check(instruction: str, sheet_content: Optional[list]) -> bool:
    """Retourne True si la même requête a été envoyée récemment (< TTL)."""
    now = time.time()
    # Nettoyage des entrées expirées
    expired = [k for k, ts in _recent_requests.items() if now - ts > _DEDUP_TTL_SECONDS]
    for k in expired:
        _recent_requests.pop(k, None)

    content_str = json.dumps(sheet_content, sort_keys=True) if sheet_content else ""
    key = hashlib.md5((instruction + content_str).encode()).hexdigest()
    if key in _recent_requests:
        return True
    _recent_requests[key] = now
    return False


def _validate_fill_targets(
    cells: list[dict],
    sheet_content: Optional[list[dict]],
) -> tuple[list[dict], list[dict]]:
    """Validate that fill_sql cells target EMPTY positions only.

    Returns (valid_cells, rejected_cells). Cells targeting a position
    that already has a value in sheet_content are rejected.
    """
    if not sheet_content:
        return cells, []

    filled_positions: set[tuple] = set()
    for c in sheet_content:
        val = c.get("value")
        if val is not None and str(val).strip():
            filled_positions.add((c.get("row"), c.get("col")))

    valid: list[dict] = []
    rejected: list[dict] = []
    for cell in cells:
        pos = (cell.get("row"), cell.get("col"))
        if pos in filled_positions:
            rejected.append(cell)
        else:
            valid.append(cell)

    return valid, rejected


def _extract_cte_output_columns(sql: str) -> Optional[set[str]]:
    """Extract the output column names from a CTE definition.

    Returns set of (normalized) column names that the CTE exports.
    Handles aliases like "Col01.colCodeCollabo As codeExpertComptableSignataire".

    Returns None if no CTE found or parsing fails.
    """
    cte_match = _CTE_SELECT_RE.search(sql)
    if not cte_match:
        return None

    # Group 1 = nom du CTE (de CTE_HEADER_PATTERN), Group 2 = body SQL.
    cte_body = cte_match.group(2)

    select_match = _SELECT_COLUMNS_RE.search(cte_body)
    if not select_match:
        return None

    columns_str = select_match.group(1)

    columns = set()
    for col_part in columns_str.split(","):
        col_part = col_part.strip()

        if " AS " in col_part.upper():
            alias = col_part.split("AS")[-1].strip().lower()
            alias = alias.strip("[]")
            columns.add(alias)
        elif "." in col_part:
            col_name = col_part.split(".")[-1].strip()
            col_name = col_name.lower().strip("[]")
            columns.add(col_name)
        else:
            col_name = col_part.lower().strip("[]")
            if col_name and col_name != "*":
                columns.add(col_name)

    return columns if columns else None


def _validate_cte_column_usage(
    sql: str,
) -> tuple[bool, Optional[str]]:
    """Validate that a SQL with CTE uses only valid column names
    outside the CTE.

    Returns (is_valid, error_message).
    """
    if "WITH" not in sql.upper() or "AS (" not in sql.upper():
        return True, None

    cte_columns = _extract_cte_output_columns(sql)
    if not cte_columns:
        return True, None

    cte_end_match = re.search(r"\)\s*SELECT", sql, re.IGNORECASE)
    if not cte_end_match:
        return True, None

    outer_sql = sql[cte_end_match.end() :]

    table_alias_pattern = r"\b[A-Z][a-z]+\d+\.\w+"
    invalid_refs = re.findall(table_alias_pattern, outer_sql)

    if invalid_refs:
        unique_refs = set(invalid_refs)
        return False, (
            "CTE column error: Ces colonnes ne peuvent pas "
            "être utilisées en dehors du CTE : "
            f"{', '.join(sorted(unique_refs))}. "
            "Utilisez les noms de colonnes de sortie du CTE : "
            f"{', '.join(sorted(cte_columns))}"
        )

    return True, None


_COL_RE = re.compile(r"^[A-Z]{1,3}$")


def _validate_fill_cells_format(
    cells: list[dict],
) -> tuple[list[dict], list[dict]]:
    """C3: Validate fill_sql cells have correct row/col format and no duplicates.

    Returns (valid_cells, rejected_cells). Rejected cells get an ``error`` key.
    """
    valid: list[dict] = []
    rejected: list[dict] = []
    seen: set[tuple] = set()

    for cell in cells:
        row = cell.get("row")
        col = cell.get("col")

        # Row must be a positive integer
        if not isinstance(row, int) or row < 1:
            cell["error"] = f"row invalide ({row!r}) — entier positif attendu"
            rejected.append(cell)
            continue

        # Col must be a valid column letter (A–ZZZ)
        if not isinstance(col, str) or not _COL_RE.match(col):
            cell["error"] = f"col invalide ({col!r}) — lettre(s) majuscule(s) attendue(s)"
            rejected.append(cell)
            continue

        # Duplicate detection
        pos = (row, col)
        if pos in seen:
            cell["error"] = f"doublon — cellule [{row},{col}] déjà ciblée"
            rejected.append(cell)
            continue

        seen.add(pos)
        valid.append(cell)

    return valid, rejected


def _validate_match_keys(
    cells: list[dict],
    result_columns: list[str],
) -> tuple[list[dict], list[dict]]:
    """C3: Validate that match/match_exclude keys are actual columns in the result.

    Cells whose match or match_exclude dict references columns absent from the
    result are rejected with a diagnostic error message.

    ``match_exclude`` values must be **lists** (exclusion sets).
    """
    col_set = {c.lower() for c in result_columns}
    valid: list[dict] = []
    rejected: list[dict] = []

    for cell in cells:
        match_filters = cell.get("match")
        match_exclude = cell.get("match_exclude")

        has_match = match_filters and isinstance(match_filters, dict)
        has_exclude = match_exclude and isinstance(match_exclude, dict)

        if not has_match and not has_exclude:
            cell["error"] = "match absent — impossible de filtrer les résultats"
            rejected.append(cell)
            continue

        # Validate column names exist in result
        bad_keys: list[str] = []
        if has_match:
            bad_keys.extend(k for k in match_filters if k.lower() not in col_set)
        if has_exclude:
            bad_keys.extend(k for k in match_exclude if k.lower() not in col_set)
        if bad_keys:
            cell["error"] = (
                f"match: colonnes introuvables dans le résultat : {bad_keys}. "
                f"Colonnes disponibles : {result_columns}"
            )
            rejected.append(cell)
            continue

        # Validate match_exclude values are lists
        if has_exclude:
            bad_vals = [k for k, v in match_exclude.items() if not isinstance(v, list)]
            if bad_vals:
                cell["error"] = (
                    f"match_exclude: les valeurs doivent être des listes. "
                    f"Clés invalides : {bad_vals}"
                )
                rejected.append(cell)
                continue

        valid.append(cell)

    return valid, rejected


async def _get_distinct_values(
    tabs_context: Optional[List[Dict[str, Any]]],
    *,
    user_id: Optional[int] = None,
) -> Dict[str, List[str]]:
    """
    Extrait les valeurs distinctes des colonnes de dimension depuis le training store.

    Pour chaque onglet avec SQL, identifie les colonnes du GROUP BY
    et cherche leurs valeurs distinctes dans column_values du training store.

    **Phase α.1.bis.suite (#118)** — ``user_id`` propagé à
    ``get_enrichment_for_tables`` pour filtrer les tables denied (defense-
    in-depth). Si l'enforcer amont a un bug et qu'une table denied est
    dans ``tabs_context``, le filtre dans la méthode source la retire du
    résultat avant retour.

    Returns:
        {"col_name": ["val1", "val2", ...]} — toutes colonnes confondues.
    """
    if not tabs_context:
        return {}

    training_store = get_training_store()
    result: Dict[str, List[str]] = {}

    # Collecter les colonnes GROUP BY de tous les onglets
    group_by_cols: set = set()
    for tab in tabs_context:
        tab_sql = tab.get("sql", "")
        if not tab_sql:
            continue
        match = _GROUP_BY_RE.search(tab_sql)
        if match:
            cols_str = match.group(1)
            for col in cols_str.split(","):
                col_clean = col.strip().strip("[]").split(".")[-1].strip()
                if col_clean and not col_clean.isdigit():
                    group_by_cols.add(col_clean)

    if not group_by_cols:
        return {}

    # Chercher les valeurs via get_table_enrichment (qui contient column_values)
    # On extrait aussi les tables pour limiter la recherche
    all_tables = set()
    for tab in tabs_context:
        tab_sql = tab.get("sql", "")
        if tab_sql:
            all_tables.update(_extract_table_names(tab_sql))

    if not all_tables:
        return {}

    # **#118** — user_id propagé via le stub. Si None (caller interne /
    # tests), aucun filtrage (comportement legacy).
    _user_stub_for_enrich: Any = None
    if user_id is not None:
        from types import SimpleNamespace

        _user_stub_for_enrich = SimpleNamespace(id=user_id, role=None)
    enrichment = await training_store.get_enrichment_for_tables(
        sorted(all_tables), user=_user_stub_for_enrich
    )
    for _table_name, table_data in enrichment.items():
        column_values = table_data.get("column_values", {})
        for col_name, values in column_values.items():
            if col_name in group_by_cols and values:
                result[col_name] = values[:30]

    return result


SYSTEM_PROMPT = """\
Tu es un assistant expert en SQL Server intégré dans un tableau de bord comptable. \
L'utilisateur voit des résultats SQL et te parle naturellement pour les modifier.

Réponds UNIQUEMENT avec un JSON valide. Pas de texte avant/après.
Ne pose JAMAIS de question à l'utilisateur. Si le contexte est insuffisant, \
réponds avec : {"type": "fill", "description": "Contexte insuffisant pour déterminer les valeurs.", "cells": []}

## Réponses possibles

**"sql"** — Modifier les données (filtre, calcul, remplacement de valeurs, agrégation, etc.) :
```json
{"type": "sql", "description": "...", "sql": "...", "new_tab": false}
```
`new_tab: true` quand c'est une nouvelle question (structure différente), `false` pour un ajustement.

**"display"** — UNIQUEMENT pour ces 4 actions (rien d'autre) :
- `hide_column` : masquer une colonne → `{"action": "hide_column", "column": "nom"}`
- `show_column` : réafficher une colonne masquée → `{"action": "show_column", "column": "nom"}`
- `sort` : trier visuellement → `{"action": "sort", "column": "nom", "direction": "asc|desc"}`
- `rename_column` : renommer un en-tête → `{"action": "rename_column", "column": "nom", "new_name": "..."}`
```json
{"type": "display", "description": "...", "actions": [...]}
```
**Toute autre transformation de données** (convertir des valeurs, formatter, remplacer, calculer) \
→ utilise type "sql" avec CASE WHEN, ISNULL, CONVERT, etc. PAS type "display".

**"cell"** — Calculer une valeur unique pour une cellule :
```json
{"type": "cell", "description": "...", "sql": "SELECT SUM(...) ...", "detail_sql": "SELECT * FROM ... WHERE ..."}
```
`sql` = la valeur agrégée (1 ligne). `detail_sql` = les lignes de détail.

**"fill"** — Remplir plusieurs cellules d'un coup (listes, séries, en-têtes, etc.) :
```json
{"type": "fill", "description": "...", "cells": [{"row": 1, "col": "A", "value": "Janvier"}, {"row": 2, "col": "A", "value": "Février"}]}
```
`row` = numéro de ligne (1-based, comme dans le contenu de la feuille). `col` = nom de colonne. \
`value` = valeur à écrire (texte ou nombre). \
Utilise ce type quand l'utilisateur demande de remplir une colonne, une ligne, ou un bloc \
de cellules avec des valeurs connues (mois, jours, en-têtes, séquences, etc.). \
PAS besoin de SQL — génère directement les valeurs.

**"fill_sql"** — Remplir plusieurs cellules à partir d'une ou plusieurs requêtes SQL. \
Génère le MINIMUM de requêtes. Chaque requête retourne TOUTES les combinaisons \
nécessaires via GROUP BY. Puis mappe chaque cellule à une ligne du résultat :
```json
{"type": "fill_sql", "description": "...", "queries": [
  {"sql": "SELECT dim1, dim2, SUM(val) as total FROM ... WHERE ... GROUP BY dim1, dim2",
   "value_column": "total",
   "cells": [
     {"row": 2, "col": "D", "label": "...", "match": {"dim1": "X", "dim2": "Y"}},
     {"row": 3, "col": "D", "label": "...", "match": {"dim1": "Z", "dim2": "Y"}}
   ]}
]}
```
`queries` = liste de requêtes. Chaque requête a un `sql` (GROUP BY qui retourne toutes \
les combinaisons), un `value_column` (la colonne qui contient la valeur à afficher), \
et des `cells` dont le `match` filtre la ligne du résultat correspondante. \
Le backend exécute chaque requête UNE SEULE FOIS puis dispatche les valeurs. \
Utilise ce type quand l'utilisateur demande de compléter une feuille existante à partir \
des données d'autres onglets (remplir les cellules vides, pas créer une nouvelle structure).

**Comportement du match** : `match` filtre les lignes du résultat SQL. Si plusieurs lignes \
correspondent (ex: match sur une dimension alors que le GROUP BY en a deux), le backend \
somme automatiquement les valeurs numériques. Mais PRÉFÈRE un GROUP BY correct : \
pour un total, retire la dimension du GROUP BY plutôt que compter sur la somme automatique. \
Exemple : pour un total d'une catégorie tous exercices confondus, utilise `GROUP BY categorie` \
(sans exercice) plutôt que `GROUP BY exercice, categorie` avec un match sans exercice.

**"multi"** — Combiner fill + fill_sql en un seul appel (optimisation latence réseau) : \
Quand tu dois remplir À LA FOIS des labels/en-têtes textes (fill) ET des valeurs \
numériques SQL (fill_sql), retourne les deux dans une seule réponse :
```json
{"type": "multi", "labels": {"type": "fill", "cells": [...]}, "values": {"type": "fill_sql", "queries": [{"sql": "...", "value_column": "...", "cells": [...]}]}}
```
Cela accélère le traitement en évitant deux appels séquentiels.

**"clone_sheet"** — Reproduire une feuille existante. Quand l'utilisateur demande de \
"faire pareil que [onglet X]", de "reproduire la feuille Y ici" ou quand la feuille active \
ressemble à une feuille sœur :
```json
{"type": "clone_sheet", "description": "...", "source_tab_index": 6,
 "substitutions": [{"old": "<valeur_source>", "new": "<valeur_cible>"}],
 "value_source_tabs": [0, 2, 4],
 "new_tab": true,
 "excludes": [{"column": "<nom_colonne>", "values": ["<val_A>", "<val_B>"]}]}
```
- `source_tab_index` = index (0-based) de l'onglet dont on copie la **structure** (labels, \
agencement).
- `substitutions` = liste de remplacements textuels appliqués aux labels ET aux SQL sources. \
Peut être **vide `[]`** quand la source correspond DÉJÀ au besoin (transfert pur).
- `value_source_tabs` (optionnel) = liste d'onglets dans lesquels le backend va **piocher \
les valeurs** pour les cellules numériques de la cible. Lookup programmatique par \
(row_label + col_header), pas de SQL regénéré. Utilise ça quand l'utilisateur demande \
"reprends les valeurs des autres onglets / sinon laisse vide / ne recalcule pas ce qu'on a déjà".
- `new_tab` (bool, optionnel, défaut `false`) = **crée un nouvel onglet** avant d'appliquer \
le clone, plutôt que d'écrire dans la feuille active. Active ce champ dès que l'utilisateur \
demande "dans une autre feuille / un nouvel onglet / une nouvelle feuille / à côté". Si \
`source_tab_index` == onglet actif, le backend force automatiquement ce champ à true.
- `excludes` (liste d'objets `{column, values}`, optionnel) = **filtres métier** appliqués \
pendant le lookup des valeurs. Les cellules sœurs dont le `match[column]` vaut une des \
`values`, ou dont le label mentionne une des `values`, sont IGNORÉES. Utilise ce champ \
pour traduire les phrases "sauf X", "excluant Y", "tous les Z sauf A, B".\
\nExemple : "tous les codes d'une colonne sauf <V1>, <V2>, <V3>" → \
`excludes: [{"column": "<nom_colonne>", "values": ["<V1>", "<V2>", "<V3>"]}]`.

Règles clone_sheet :
- Substitution non vide qui apparaît dans les SQL sources → les valeurs numériques sont \
**recalculées** après substitution.
- Substitution purement cosmétique (titre seulement) ou `substitutions: []` → les valeurs \
numériques sont **copiées telles quelles** depuis la source.
- **Avant de proposer clone_sheet avec substitutions, vérifie si une feuille sœur contient \
DÉJÀ le périmètre demandé (mêmes filtres dans ses SQL)**. Si oui, utilise `substitutions: []` \
au lieu d'inventer une substitution cosmétique.

**"fill_plan"** — Remplir une grille entière via un pivot automatique (pas de limite de cellules). \
Quand le nombre de cellules est grand ou la structure est un tableau croisé :
```json
{"type": "fill_plan", "description": "...", "labels": [{"row": 1, "col": "A", "value": "Titre"}], \
"queries": [{"sql": "SELECT dim_row, dim_col, SUM(val) AS total FROM ... GROUP BY dim_row, dim_col", \
"value_column": "total", "row_dimension": "dim_row", "col_dimension": "dim_col", \
"start_row": 3, "start_col": "B"}]}
```
`row_dimension` = colonne SQL dont les valeurs deviennent les labels de LIGNES de la feuille. \
`col_dimension` = colonne SQL dont les valeurs deviennent les en-têtes de COLONNES. \
`value_column` = colonne contenant les valeurs numériques à afficher. \
`start_row`/`start_col` = position du coin haut-gauche des données (1-based / lettre). \
`labels` (optionnel) = cellules texte à placer en plus (titres, etc.). \
Le backend exécute le SQL, pivote les résultats, et génère TOUTES les cellules automatiquement \
(y compris les en-têtes de lignes et colonnes). Pas de limite de cellules. \
Si `col_dimension` est absent, les valeurs sont empilées verticalement. \
Préfère ce type pour les tableaux croisés, les structures complexes, ou quand il y a plus de 20 cellules.

**"emit_tab"** — ⭐ **TYPE PRIORITAIRE** pour toute reconstruction / reproduction d'onglet à partir \
de données déjà présentes dans le classeur (onglets sœurs avec `sheet_content`).

## Forme COMPACTE obligatoire (Haiku a 8192 tokens de sortie — sinon réponse tronquée)

**RÈGLES D'ÉMISSION** :
1. **N'émets JAMAIS `sql` dans les cellDetails.** Le backend dérive la SQL de drill-down depuis \
   `match` + `match_exclude` + `source_tab_index` + le SQL du tab source. Un SQL par cellule = \
   redondance massive qui tronque la réponse.
2. **Utilise `clone_structure_from: N`** où N = INDEX de l'onglet à reproduire. \
   ⚠️ **Cas le plus fréquent : l'utilisateur dit "fais la même chose que cette feuille" ou \
   cite le nom de l'onglet ACTIF → `clone_structure_from` = INDEX DE L'ACTIF**. \
   L'onglet actif est marqué `[index=N]` + `**(onglet actif …)**` dans "## Onglets ouverts" ; \
   son contenu est détaillé dans "## Cellules existantes (feuille active)". \
   **NE PAS confondre avec un autre onglet dont le nom ressemble** (ex: s'il existe un \
   "Ratio X Y" à côté d'un template actif "MODELE RATIO Z", et l'utilisateur dit "reproduis \
   MODELE RATIO Z", prends l'index du MODELE actif, PAS celui du "Ratio X Y" homonyme). \
   Vérifie la cohérence : tes coordonnées `cellDetails[R,C]` et `rows_overrides[R,C]` \
   doivent TOUTES être < `row_count` de l'onglet cloné. \
   N'émets NI `columns` NI `rows` NI `merges` quand tu utilises `clone_structure_from`. \
   Substituts textuels via `rows_overrides`.
3. **Utilise `cell_groups`** pour factoriser les champs partagés (`match_exclude`, \
   `value_column`, `source_tab_index`). Une section = un groupe.

Format complet accepté (exemple concret `<placeholders>` à substituer par les vrais noms de \
colonnes lus dans les onglets sources) :
```json
{"type": "emit_tab", "description": "...", "new_tab": true,
 "tab": {
   "label": "Titre unique de l'onglet",
   "clone_structure_from": 3,
   "rows_overrides": {"1,0": "Nouveau titre principal"},
   "cell_groups": [
     {
       "source_tab_index": 1,
       "value_column": "<colonne_mesure>",
       "match_exclude": {"<dim_a>": ["<v1>", "<v2>"]},
       "cells": {
         "10,1": {"match": {"<dim_b>": "<val>", "<dim_c>": 2023}, "label": "..."},
         "10,3": {"match": {"<dim_b>": "<val>", "<dim_c>": 2024}, "label": "..."}
       }
     },
     {
       "source_tab_index": 1,
       "value_column": "<colonne_mesure>",
       "match": {"<dim_a>": "<autre_val>"},
       "cells": { "30,1": {"match": {"<dim_c>": 2023}, "label": "..."}, ... }
     }
   ]
 }}
```

- `clone_structure_from: <tab_idx>` (int) : copie columns/rows/merges depuis ce tab. Skip les \
  champs `columns`/`rows`/`merges` si présent.
- `rows_overrides: {"R,C": value}` : substitutions textuelles après clone (ex: changement de \
  titre principal, de nom d'entité). Clé format `"R,C"` (0-based).
- `cell_groups` : liste de groupes. Chaque groupe partage `source_tab_index`, `value_column`, \
  et optionnellement `match_exclude`. Chaque cellule du groupe porte `match` (filtres exacts \
  spécifiques) et `label`. Le backend fusionne group-level + cell-level puis recalcule la valeur.
- **Règle None** : si une cellule dérivée a un opérande `None`, sa valeur finale est `None`.
- **Règle `new_tab`** : `true` par défaut sauf instruction explicite ("à la place", "écraser").

**match_exclude** — Pour exprimer "toutes les valeurs SAUF certaines" (ex: total hors certaines \
catégories), utilise `match_exclude` au lieu d'inventer des valeurs inexistantes comme "OTHER" :
```json
{"row": 7, "col": "H", "label": "Total autres", "match_exclude": {"categorie": ["CatA", "CatB", "CatC"]}}
```
Le backend filtre automatiquement les lignes exclues et SOMME les valeurs restantes. \
Tu peux combiner `match` et `match_exclude` sur une même cellule. \
Les valeurs dans `match_exclude` doivent être des **listes**. \
**Ne JAMAIS inventer de valeur comme "OTHER", "AUTRES", "RESTE"** — utilise `match_exclude`.

## ⚠️ ERREURS CRITIQUES À NE PAS FAIRE

❌ **ERREUR #1 — Retourner une cellule marquée "(existant)" avec la valeur "(existant)"** :

Si tu vois dans le JSON d'entrée :
```json
{"labels": {"type": "fill", "cells": [
  {"row": 3, "col": "C", "value": "(existant)"},
  {"row": 3, "col": "D", "value": "(existant)"}
]}}
```

Cela signifie : **Ces deux cellules sont DÉJÀ REMPLIES. Ne les touche pas du tout.**

❌ **FAUX** (INTERDIT) :
```json
{"type": "multi", "labels": {"type": "fill", "cells": [
  {"row": 3, "col": "C", "value": "(existant)"},
  {"row": 3, "col": "D", "value": "(existant)"}
]}}
```

✅ **CORRECT** :
```json
{"type": "multi", "labels": {"type": "fill", "cells": []}}
```

**Règle** : Si une cellule a `"value": "(existant)"` dans le JSON d'entrée, elle est MARQUÉE PAR LE SYSTÈME comme déjà remplie. \
Tu dois :
1. **L'ignorer complètement** — ne pas la retourner dans ta réponse
2. **Ne JAMAIS retourner une cellule avec** `"value": "(existant)"` — c'est une signature interne, pas une vraie valeur

Les cellules marquées "(existant)" doivent être ABSENTES de ta réponse. Comme si elles n'existaient pas.

❌ **ERREUR #2 — Confondre "cellule existante" et "cellule à ignorer"** :

Si le contenu de la feuille montre :
```json
{"row": 3, "col": "A", "value": "<libellé>"}
{"row": 3, "col": "B", "value": "(existant)"}
{"row": 3, "col": "C", "value": ""}
```

Cela signifie :
- [3,A] = "<libellé>" (texte rempli) → Tu PEUX l'utiliser comme contexte
- [3,B] = "(existant)" (marquée comme remplie) → Tu IGNORES COMPLÈTEMENT cette cellule
- [3,C] = "" (vraiment vide) → Tu PEUX la calculer et la remplir

## Vérification d'alignement grille (OBLIGATOIRE avant de répondre)
Chaque cellule de la feuille est au croisement d'une ligne et d'une colonne. \
Avant de répondre, vérifie pour CHAQUE cellule que tu génères :
1. Le **match** reflète à la fois la signification de sa ligne (label en début de ligne) \
ET la signification de sa colonne (header en haut de colonne).
2. Deux colonnes qui représentent des choses différentes ne peuvent PAS avoir le même match. \
Si elles ont des périmètres différents, elles nécessitent des requêtes séparées.
3. Les valeurs existantes sur le même axe indiquent le périmètre à respecter. \
Si une section "Sources SQL" est présente, elle montre le WHERE/GROUP BY exact de chaque cellule — \
utilise le même périmètre pour les cellules vides du même axe.
4. Les cellules vides qui SUIVENT des cellules remplies doivent CONTINUER la séquence, \
pas la recommencer. Si la dernière ligne remplie correspond à une période ou une valeur \
dans une série, les lignes vides suivantes doivent correspondre aux éléments SUIVANTS \
de cette série. Ne JAMAIS recréer une structure qui existe déjà — prolonge-la.
5. Avant de remplir une cellule vide, regarde TOUT ce qui entoure la cellule : \
les cellules voisines (au-dessus, en dessous, à gauche, à droite), leur valeur, \
leur requête SQL source, leur match (correspondance colonne/filtre), leur type de réponse, \
les en-têtes de ligne et de colonne. Tous ces éléments définissent la signification \
de la cellule vide et le SQL à générer pour la remplir.

## CRITIQUE — Cellules existantes = pattern à reproduire
Les cellules déjà remplies avec un `match` et/ou un `sql` source définissent le pattern \
exact pour les cellules voisines vides :
- Les cellules vides sur la **même ligne** doivent avoir les mêmes dimensions de ligne \
dans leur match, en variant uniquement la dimension de colonne.
- Les cellules vides sur la **même colonne** doivent avoir les mêmes dimensions de colonne \
dans leur match, en variant uniquement la dimension de ligne.
- **Ne JAMAIS retirer une dimension** du match quand elle est présente dans les cellules \
voisines existantes peu importe leur distance. Toutes les cellules d'une même zone partagent les mêmes clés de match.  
- **Cohérence GROUP BY / match** : chaque colonne non agrégée dans le GROUP BY DOIT \
apparaître comme clé dans le match de chaque cellule. Si le GROUP BY a N colonnes, \
chaque match doit avoir N clés. Sinon le backend somme des lignes non voulues → valeur fausse.
- Le SQL source d'une cellule existante montre les filtres WHERE exacts — réutilise \
les mêmes filtres pour les cellules vides de la même zone.

## {sql_server_version}
- Les CTE (`WITH ... AS`) doivent être au top level, jamais dans une sous-requête.
- Si la requête a un CTE, garde-le intact et modifie le SELECT final.
- **IMPORTANT** : un nom de CTE (ex: DonneesAvecCategorie) n'est PAS une table. \
Si tu génères un nouveau SQL qui utilise un CTE, tu DOIS inclure la définition complète \
`WITH NomCTE AS (SELECT ...) SELECT ... FROM NomCTE`. Ne jamais écrire \
`SELECT ... FROM NomCTE` sans le WITH qui le définit.
- **CRITIQUE — Colonnes de CTE** : dans la requête EXTÉRIEURE au CTE (le SELECT/WHERE après \
le `)`), tu ne peux PAS utiliser les alias de tables internes au CTE (ex: `T1.colonne`). \
Tu dois utiliser les **noms de colonnes de sortie** du CTE directement (ex: `colonne`). \
Les alias de tables définis dans le WITH n'existent QU'À L'INTÉRIEUR du WITH.\
\n**EXEMPLE D'ERREUR BANNNIE** :\
\n❌ **FAUX** :\
\n```\
WITH MyCTE AS (SELECT Col01.code AS employee_code FROM ...)\
\nSELECT employee_code FROM MyCTE WHERE Col01.code LIKE '%smith%'  <-- ERREUR !\
\n```\
\n✅ **CORRECT** :\
\n```\
WITH MyCTE AS (SELECT Col01.code AS employee_code FROM ...)\
\nSELECT employee_code FROM MyCTE WHERE employee_code LIKE '%smith%'  <-- VALIDE\
\n```\
\n**Règle simple** : une fois que tu quittes la partie `WITH ... AS (...)`, tu ne dois JAMAIS\
\nreférence les alias de tables originaux (Col01, Fac01, Lfa01, etc.). Utilise UNIQUEMENT\
\nles noms de sortie du CTE.
- GROUP BY : toute colonne dans SELECT/ORDER BY doit être dans GROUP BY ou une agrégation.
- **CRITIQUE — ISNULL dans GROUP BY** : JAMAIS de `ISNULL(col, X)` dans le SELECT/GROUP BY \
de la requête extérieure. Déplace TOUJOURS le ISNULL dans le CTE (ou sous-requête). \
Sinon SQL Server exige X dans le GROUP BY, ce qui fragmente les résultats. \
**FAUX** : `SELECT ISNULL(code, fallback) ... GROUP BY ISNULL(code, fallback), fallback` \
**CORRECT** : dans le CTE : `ISNULL(code, fallback) AS code`, puis dehors : `GROUP BY code`. \
Même règle pour COALESCE, CASE WHEN avec colonnes : déplace-les dans le CTE.
- **Ne JAMAIS ajouter DISTINCT** sauf si l'utilisateur le demande explicitement. \
Les doublons apparents sont souvent des lignes de détail légitimes. \
De même, n'ajoute pas ORDER BY sauf si le tri est demandé.
- Modifie le minimum nécessaire. Ne restructure que si l'utilisateur le demande.
- **CRITIQUE — Tous les filtres** : AVANT de répondre, relis l'instruction et VÉRIFIE \
que CHAQUE condition mentionnée par l'utilisateur est traduite en filtre WHERE. \
Un nom propre, une valeur, une période, une exclusion = un filtre. Rien ne doit être oublié.
- **Filtrage sur noms propres** : pour filtrer sur un nom de personne \
(expert-comptable, collaborateur, client, etc.), utilise TOUJOURS `LIKE '%nom%'` \
(pas d'égalité exacte `= 'nom'`). Les noms dans la base peuvent être des codes, \
des noms complets ou des variantes — `LIKE '%nom%'` couvre ces cas. \
Exemple : `WHERE colonne LIKE '%Dupont%'` et non `WHERE colonne = 'Dupont'`.
- **IMPORTANT** : quand tu crées une nouvelle requête (new_tab: true), CONSERVE TOUJOURS les \
conditions WHERE de la requête originale. L'utilisateur travaille dans un contexte filtré \
(entité, groupe, exercice, etc.) — ta nouvelle requête doit rester dans ce même périmètre.
- **fill_sql — Ciblage précis des cellules** : les `row` et `col` dans les `cells` doivent \
correspondre EXACTEMENT aux cellules VIDES de la feuille. Ne JAMAIS cibler une cellule déjà \
remplie (marquée "(existant)"). Vérifie les numéros de ligne dans le contenu de la feuille \
avant de mapper. Les lignes d'en-tête et les labels existants ne sont PAS à remplir.
- **CRITIQUE — Coordonnées tableur ≠ colonnes SQL** : Les positions [row, col] dans le contenu \
de la feuille (A, B, C, D...) sont des COLONNES DE LA FEUILLE, pas des colonnes SQL Server. \
Ne JAMAIS utiliser B3, C5, D10 etc. comme noms de colonnes dans une requête SQL. \
Pour calculer une somme de cellules existantes, utilise le type "cell" avec une formule. \
Pour des données SQL, utilise les vrais noms de colonnes de la base de données.
"""

# Lightweight prompt for the planning call (Call 1 of 2-call architecture).
# Classifies the instruction and determines what context Call 2 needs.
# For clone_sheet and simple display, the plan IS the final response.
PLANNING_PROMPT = """\
Tu es un planificateur pour un assistant SQL intégré dans un tableau de bord comptable.

L'utilisateur a donné une instruction. Tu dois analyser l'instruction et le contexte \
pour produire un PLAN JSON compact. Tu ne génères PAS de SQL, tu ne remplis PAS de cellules.

Réponds UNIQUEMENT avec un JSON valide. Pas de texte avant/après.

## Format du plan

```json
{
  "plan_type": "fill_sql",
  "description": "Résumé en 1 ligne de ce qui sera fait",
  "needs_schema": true,
  "source_tabs": [0, 2]
}
```

### Champs obligatoires

- **plan_type** : un parmi "sql", "display", "cell", "fill", "fill_sql", "multi", \
"clone_sheet", "fill_plan", "emit_tab". Choisis le type le plus adapté à l'instruction.

⚠️ **RÈGLE D'AIGUILLAGE CRITIQUE — emit_tab vs clone_sheet** :
- Si les valeurs numériques doivent être **calculées / agrégées** depuis les onglets \
sources (phrases comme « remplaçant les cellules pour lesquelles on a les valeurs dans les \
autres feuilles », « reprends les valeurs », « avec les chiffres de l'autre onglet », \
« même chose que X mais pour Y », « reconstruire », « refaire pour ») → **TOUJOURS emit_tab**.
- Si les valeurs doivent être **copiées verbatim** depuis un onglet qui contient DÉJÀ \
le résultat final pour le même périmètre (quasi jamais en pratique) → clone_sheet.
- Dans le doute → **emit_tab**. clone_sheet copie les valeurs de la source verbatim ; \
sur un template xlsx pur, ça donne silencieusement les mauvaises valeurs.
- **description** : résumé court de l'action prévue.
- **needs_schema** : `true` si tu auras besoin du DDL des tables pour écrire du SQL, \
`false` sinon (ex: fill de labels, display, clone_sheet).
- **source_tabs** : liste des index (0-based) des onglets dont tu auras besoin du \
contenu complet (SQL + aperçu) **pour CONSTRUIRE ta réponse** (rédiger un SQL, lire \
des données, etc.). C'est une méta-info pour que le backend pré-charge le contexte. \
**Ce champ ne déclenche AUCUNE action sur la feuille cible.** \
⚠️ Ne PAS confondre avec `value_source_tabs` (utilisé par clone_sheet — voir plus bas) \
qui lui déclenche un vrai lookup programmatique.

### Champs conditionnels (selon plan_type)

**Si plan_type = "clone_sheet"** (réponse directe, pas d'appel 2) :
```json
{
  "plan_type": "clone_sheet",
  "description": "...",
  "needs_schema": false,
  "source_tabs": [],
  "source_tab_index": 6,
  "substitutions": [{"old": "<valeur_source>", "new": "<valeur_cible>"}],
  "value_source_tabs": [0, 2, 4],
  "new_tab": true,
  "excludes": [{"column": "<nom_colonne>", "values": ["<val_A>", "<val_B>"]}]
}
```
- `source_tab_index` (int, requis) = l'onglet dont on copie la **structure** (labels, agencement).
- `substitutions` peut être **vide (`[]`)** quand la feuille source contient DÉJÀ le périmètre \
demandé : transfert pur. Quand non vide, les remplacements s'appliquent aux labels ET aux SQL \
sources (les valeurs numériques sont recalculées si le SQL change).
- `value_source_tabs` (liste d'int, optionnel) = **onglets dans lesquels le backend pioche \
les VALEURS numériques** (lookup programmatique par label + header, pas de SQL regénéré). \
À utiliser quand l'utilisateur demande "reprends les valeurs des autres feuilles / sinon \
laisse vide / utilise ce qu'on a déjà calculé".
- `new_tab` (bool, optionnel, défaut `false`) = **créer un nouvel onglet avant le clone** \
plutôt que d'écrire dans la feuille active. Active ce champ dès que l'utilisateur demande \
"dans une autre feuille / un nouvel onglet / une nouvelle feuille / à côté". Safeguard : \
si `source_tab_index` == onglet actif, le backend force automatiquement `new_tab: true`.
- `excludes` (liste `[{column, values}]`, optionnel) = **filtres métier** appliqués pendant \
le lookup `value_source_tabs`. Les cellules sœurs dont le `match[column]` vaut une des \
`values`, ou dont le label contient une des `values`, sont IGNORÉES. Utilise ce champ \
pour traduire les phrases "sauf X", "excluant Y", "tous les Z sauf A, B". \
Exemple : "tous les codes statistiques sauf FN, SOCIAL, JURIDIQUE" → \
`excludes: [{"column": "<colonne_code_stat>", "values": ["FN", "SOCIAL", "JURIDIQUE"]}]`.

⚠️ **NE PAS CONFONDRE** : le champ commun `source_tabs` est purement indicatif pour que \
le système pré-charge le contexte — il ne déclenche AUCUNE action. \
`value_source_tabs` (spécifique à clone_sheet) déclenche le VRAI lookup des valeurs. \
Si l'utilisateur demande de piocher dans plusieurs onglets, **mets ces onglets dans \
`value_source_tabs`**, PAS dans `source_tabs`.

**Si plan_type = "display"** (réponse directe, pas d'appel 2) :
```json
{
  "plan_type": "display",
  "description": "...",
  "needs_schema": false,
  "source_tabs": [],
  "actions": [{"action": "hide_column", "column": "nom"}]
}
```

**Si plan_type = "emit_tab"** (plan → Call 2 émet l'onglet complet) :
Le plan de Call 1 reste COMPACT — juste la méta. Call 2 (prompt SYSTEM_PROMPT principal) \
produira ensuite l'onglet complet avec rows + merges + cellDetails.
```json
{
  "plan_type": "emit_tab",
  "description": "Résumé : reconstruire [onglet] pour [entité/personne], exclure [...]",
  "needs_schema": false,
  "source_tabs": [0, 1, 3],
  "new_tab": true
}
```
- `source_tabs` = TOUS les onglets dont les données seront utilisées pour recomputer les \
valeurs (onglets SQL + onglets dashboard pertinents). Call 2 en recevra le `sheet_content` \
complet avec `match` par ligne.
- `new_tab: true` par défaut ; `false` uniquement si l'utilisateur demande d'écraser l'actif.
- **NE METS PAS** de champ `tab` dans ce plan — c'est la responsabilité de Call 2.

## Règles

### emit_tab (type privilégié pour reconstruction)
- Cas d'usage : « fais la même chose que [onglet X] mais pour [entité/personne Y] », \
« reproduis ce tableau en remplaçant les valeurs par celles des autres feuilles », \
« reconstruis le ratio pour Z », tout ce qui demande **CALCUL** (pas copie) de valeurs \
à partir d'onglets sources.
- Le plan de Call 1 indique juste `plan_type: "emit_tab"`, `source_tabs: [...]` (onglets \
à regarder) et `new_tab: true/false`. **PAS de champ `tab` dans Call 1** — c'est Call 2 \
qui émettra l'onglet complet avec rows + cellDetails + merges.
- `source_tabs` doit lister TOUS les onglets qui contiennent les données sources \
(onglets SQL + onglets dashboard qui ont les valeurs). **Inclure aussi l'onglet TEMPLATE** \
(celui dont la structure sera clonée) — il sera référencé par `clone_structure_from` en \
Call 2.
- `new_tab: true` par défaut. `false` uniquement si l'utilisateur demande explicitement \
d'écraser l'onglet actif (« à la place », « écraser », « ici »).
- Les exclusions métier (« sauf <code_X>, <code_Y> »), les filtres (« pour <entité_Z> »), \
les exclusions de codes → tout ça sera exprimé en Call 2 via les `match` / \
`match_exclude` des cellDetails (regroupées en `cell_groups` quand plusieurs cellules \
partagent les mêmes règles), pas dans le plan.

### clone_sheet (rare — copie verbatim uniquement)
- Quand l'utilisateur veut reproduire une feuille existante (même structure, labels).
- **Si la source correspond déjà au besoin** → `substitutions: []` (clone pur).
- **Si substitution modifie les SQL sources** (ex: changement de personne/entité qui apparaît \
dans les WHERE) → le backend recalcule les valeurs numériques.
- **Si substitution cosmétique** (juste un titre) → les valeurs numériques sont copiées telles quelles.
- **Si l'utilisateur demande de réutiliser les valeurs de plusieurs autres onglets** \
(phrases comme "reprends les valeurs des autres onglets", "sinon laisse vide", "ne recalcule \
pas ce qui existe déjà") → ajoute `value_source_tabs: [...]` avec les indices des onglets à \
consulter.
- **Si l'utilisateur demande « dans une autre feuille / un nouvel onglet / une nouvelle \
feuille / à côté / séparément »** → ajoute `new_tab: true`. **Obligatoire** si \
`source_tab_index` == onglet actif (sinon le backend forcera ce flag de toute façon).
- **Si l'utilisateur formule une exclusion métier** (« sauf X », « excluant Y », « tous les \
Z sauf A, B »)  → ajoute `excludes: [{"column": "<nom_colonne>", "values": ["A", "B"]}]`. \
Les cellules dont le `match[column]` ou le label contient une des `values` sont ignorées \
pendant le lookup.
- Si l'utilisateur demande de changer la structure (GROUP BY, colonnes, agrégation, période) \
→ c'est "sql" avec new_tab: true, PAS clone_sheet.

### Autres types
- **display** : UNIQUEMENT hide_column, show_column, sort, rename_column.
- **sql** : transformation de données (filtre, calcul, agrégation, remplacement NULL via \
ISNULL/COALESCE, ajout/suppression de colonnes, changement de structure du résultat).
- **fill_sql** / **fill_plan** : remplir des cellules VIDES via NOUVEAU SQL.
- **fill** : valeurs connues (labels, séries).
- **cell** : une seule valeur.
- **multi** : combiner fill + fill_sql.
- needs_schema = true pour tout ce qui nécessite d'écrire du SQL neuf (sql, fill_sql, cell, fill_plan).
- source_tabs : inclure les onglets dont les données sont nécessaires.
"""


def _get_versioned_prompt(prompt: str) -> str:
    """Remplace {sql_server_version} dans un prompt par le label réel (ex: 'SQL Server 2016')."""
    from app.services.database.db_config_service import get_sql_server_version_label_sync

    return prompt.replace("{sql_server_version}", get_sql_server_version_label_sync())


# Response types that can be returned directly from the planning call (no Call 2 needed).
_PLAN_DIRECT_TYPES = {"clone_sheet", "display"}


def _extract_table_names(sql: str) -> List[str]:
    """Extrait les noms de tables depuis une requête SQL."""
    tables = set()
    for match in _TABLE_RE.finditer(sql):
        table_name = match.group(3).strip("[]")
        tables.add(table_name)
    return sorted(tables)


async def _get_schema_context(
    table_names: List[str],
    user_id: Optional[int] = None,
) -> str:
    """Récupère la doc schéma pour les tables/vues référencées (lookup exact par nom).

    Résultats cachés en mémoire pendant _DDL_CACHE_TTL secondes (B3 fix).
    Le DDL est invariant pendant une session — inutile de re-fetch à chaque appel.

    Args:
        table_names: tables/vues à documenter.
        user_id: optionnel — Phase α.4 (#22/#52). Si fourni, on construit
            un stub user pour activer le filtrage mode invisible côté
            training_store. ``user_id=None`` = comportement legacy.
            ATTENTION : le cache DDL est partagé entre tous les users
            (cache_key par tables, pas par user). C'est intentionnel pour
            ne pas multiplier les entrées — mais ça signifie que le filtre
            mode invisible se fait au FETCH initial, pas au lookup cache.
            Si un user restreint fetche en premier, son DDL filtré sera
            servi à tous → BUG. Pour corriger en V2 : inclure user_id
            dans cache_key. Pour V1 : fail-safe = bypass cache si user_id
            fourni.
    """
    if not table_names:
        return ""

    # Cache check (B3) — même set de tables = même DDL.
    # Phase α.4 fail-safe : bypass cache si user_id fourni (V1).
    cache_key = "|".join(n.upper() for n in sorted(table_names))
    now = time.time()
    if user_id is None:
        cached = _ddl_cache.get(cache_key)
        if cached and (now - cached[1]) < _DDL_CACHE_TTL:
            logger.debug("DDL cache hit for %d tables", len(table_names))
            return cached[0]

    training_store = get_training_store()

    # Phase α.4 (#22/#52) — stub user pour mode invisible.
    user_stub: Any = None
    if user_id is not None:
        from types import SimpleNamespace

        user_stub = SimpleNamespace(id=user_id, role=None)

    # Lookup exact par table_name — tables ET vues
    ddl_results = await training_store.get_related_ddl_with_roles(
        table_names, n_results=len(table_names), user=user_stub
    )

    parts = []
    found_names = set()
    for item in ddl_results:
        ddl = item.get("ddl")
        name = item.get("table_name", "")
        if ddl:
            found_names.add(name.upper())
            entry = ddl
            # Ajouter les rôles sémantiques si disponibles
            table_role = item.get("table_role")
            if table_role:
                entry += f"\n-- Rôle: {table_role}"
            col_roles = item.get("column_roles", {})
            if col_roles:
                for col, role in col_roles.items():
                    entry += f"\n-- {col}: {role}"
            parts.append(entry)

    # Tables/vues sans DDL trouvé — fallback TF-IDF
    missing = [n for n in table_names if n.upper() not in found_names]
    if missing:
        query = " ".join(missing)
        # Phase α.4 — propager user_stub.
        fallback = await training_store.get_related_ddl(
            query, n_results=len(missing), user=user_stub
        )
        for item in fallback:
            content = item.get("content", "")
            if content:
                parts.append(content)

    result = "\n\n".join(parts)
    _ddl_cache[cache_key] = (result, now)
    return result


# Alias pour usage dans ``_extract_cte_block`` : on scanne un ``cte_block``
# déjà borné (commence par ``WITH``), donc ``CTE_HEADER_RE`` matche parfaitement.
_CTE_NAME_RE = CTE_HEADER_RE


def _extract_cte_block(sql: str) -> tuple[str | None, set[str]]:
    """Extrait le bloc WITH complet et les noms de CTE d'une requête SQL.

    Gère les CTEs multiples/imbriquées en comptant les parenthèses
    pour trouver le SELECT final de top-level.

    Returns:
        (cte_block, cte_names) — cte_block inclut "WITH ... ) ", cte_names en uppercase.
    """
    # Trouver le début du WITH
    with_match = re.match(r"\s*WITH\s+", sql, re.IGNORECASE)
    if not with_match:
        return None, set()

    # Parcourir le SQL en comptant les parenthèses pour trouver le SELECT final
    depth = 0
    i = with_match.end()
    cte_end = None
    while i < len(sql):
        ch = sql[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                # On est sorti de toutes les parenthèses CTE — chercher le SELECT qui suit
                rest = sql[i + 1 :].lstrip()
                if rest.upper().startswith("SELECT"):
                    cte_end = i + 1
                    break
                # Sinon c'est un "," suivi d'un autre CTE, on continue
        elif ch == "'" and depth > 0:
            # Sauter les chaînes littérales dans les CTEs
            i += 1
            while i < len(sql) and sql[i] != "'":
                i += 1
        i += 1

    if cte_end is None:
        return None, set()

    cte_block = sql[:cte_end].rstrip()
    cte_names = {m.group(1).upper() for m in _CTE_NAME_RE.finditer(cte_block)}
    return cte_block, cte_names


def _truncate_sheet_content_for_llm(
    sheet_content: List[Dict[str, Any]],
    max_cells: int = 300,
) -> List[Dict[str, Any]]:
    """Plafonne la taille du sheet_content envoyé au LLM.

    Le backend recompute utilise le sheet_content COMPLET (via tabs_context
    passé à _recompute_emit_tab) ; cette troncature n'affecte QUE l'aperçu
    envoyé au LLM dans le prompt Call 2. Stratégie : échantillon à pas
    uniforme pour préserver la diversité (dimensions couvertes) + marker
    _meta indiquant la troncature.
    """
    if not sheet_content or len(sheet_content) <= max_cells:
        return sheet_content
    stride = max(1, len(sheet_content) // max_cells)
    sampled = sheet_content[::stride][:max_cells]
    sampled.append(
        {
            "row": 0,
            "col": "_meta",
            "value": (
                f"(échantillon {len(sampled)}/{len(sheet_content)} pour budget prompt — "
                "le backend voit l'intégralité pour le recompute)"
            ),
        }
    )
    return sampled


def _build_structured_sheet_json(sheet_content: list[dict]) -> str | None:
    """Build structured JSON from sheet content (same format as fill_sql output).

    Groups cells into labels (text) and queries (numeric with source_sql).
    Extracts match from SQL if not provided.
    """
    if not sheet_content:
        return None

    labels = []
    by_sql: dict[str, list[dict]] = {}
    no_sql_values = []

    for c in sheet_content:
        src = c.get("source_sql")
        cell_entry: dict = {"row": c.get("row"), "col": c.get("col")}
        if c.get("label"):
            cell_entry["label"] = c["label"]
        cell_entry["value"] = c.get("value")
        stored_match = c.get("match")
        cell_match = stored_match if isinstance(stored_match, dict) else {}
        if src:
            sql_match = _extract_match_from_sql(src)
            if sql_match:
                # Merge: SQL-extracted conditions fill gaps in stored match.
                # Stored match overrides on conflict (it's the authoritative source).
                merged = dict(sql_match)
                merged.update(cell_match)
                cell_match = merged
        if cell_match:
            cell_entry["match"] = cell_match

        val_str = str(c.get("value", ""))
        is_num = False
        try:
            float(val_str)
            is_num = True
        except (ValueError, TypeError):
            pass

        if src:
            base_sql = _normalize_detail_sql(src)
            by_sql.setdefault(base_sql, []).append(cell_entry)
        elif is_num:
            no_sql_values.append(cell_entry)
        else:
            labels.append(cell_entry)

    existing_data: dict = {}
    all_label_cells = labels + no_sql_values
    if all_label_cells:
        existing_data["labels"] = {"cells": all_label_cells}
    if by_sql:
        queries = []
        for src_sql, cells in by_sql.items():
            queries.append({"sql": src_sql, "cells": cells})
        existing_data["values"] = {"queries": queries}

    if not existing_data:
        return None

    # Compact JSON (pas d'indent) : ~2.5× plus petit pour le budget prompt.
    return json.dumps(existing_data, ensure_ascii=False, separators=(",", ":"))


def _extract_match_from_sql(sql: str) -> dict | None:
    """Extract match filters from a drill-down SQL's WHERE clause.

    Drill-down SQL has cell-specific conditions like:
      AND [periode] = '2023/2024' AND [responsable] = 'XYZ'
    These ARE the match filters for that cell.
    We extract simple equality conditions (= 'value' and = number), not IN/NOT IN.
    Brackets around column names are optional (handles both [col] and col).
    """
    where_match = re.search(r"\bWHERE\b(.+?)$", sql, re.IGNORECASE | re.DOTALL)
    if not where_match:
        return None

    where_clause = where_match.group(1)
    # Remove ORDER BY/GROUP BY at end
    for kw in ("ORDER BY", "GROUP BY"):
        kw_pos = re.search(r"\b" + kw + r"\b", where_clause, re.IGNORECASE)
        if kw_pos:
            where_clause = where_clause[: kw_pos.start()]

    # Split by AND and check each condition individually.
    # This prevents false positives from CASE WHEN expressions or functions.
    conditions = re.split(r"\bAND\b", where_clause, flags=re.IGNORECASE)

    result = {}
    for cond in conditions:
        cond = cond.strip()
        if not cond:
            continue
        # Skip IN/NOT IN conditions (not cell-specific)
        if " IN " in cond.upper():
            continue
        # col = 'value' (string equality, brackets optional)
        str_match = re.match(r"\[?(\w+)\]?\s*=\s*'([^']*)'", cond)
        if str_match:
            result[str_match.group(1)] = str_match.group(2)
            continue
        # col = number (numeric equality, brackets optional)
        num_match = re.match(r"\[?(\w+)\]?\s*=\s*(\d+(?:\.\d+)?)\s*$", cond)
        if num_match:
            col, val = num_match.group(1), num_match.group(2)
            if col not in result:
                try:
                    result[col] = int(val) if "." not in val else float(val)
                except ValueError:
                    result[col] = val

    return result if result else None


def _normalize_detail_sql(sql: str) -> str:
    """Normalise un drill-down SQL pour grouper les cellules partageant la même base.

    Les drill-down SQL diffèrent par les conditions WHERE spécifiques à chaque cellule
    (ex: AND [<dim_a>] = '<val>' AND [<dim_b>] = '<val>').
    On extrait le CTE + SELECT + FROM + les conditions communes du WHERE.
    """
    # Trouver la position du WHERE
    where_match = re.search(r"\bWHERE\b", sql, re.IGNORECASE)
    if not where_match:
        return sql

    before_where = sql[: where_match.end()]

    # Séparer les conditions du WHERE par AND
    where_clause = sql[where_match.end() :]
    # Retirer ORDER BY/GROUP BY à la fin
    for kw in ("ORDER BY", "GROUP BY"):
        kw_match = re.search(r"\b" + kw + r"\b", where_clause, re.IGNORECASE)
        if kw_match:
            where_clause = where_clause[: kw_match.start()]

    conditions = re.split(r"\bAND\b", where_clause, flags=re.IGNORECASE)
    conditions = [c.strip() for c in conditions if c.strip()]

    # Les conditions communes sont celles qui utilisent IN(...) ou NOT IN(...)
    # Les conditions spécifiques sont celles qui utilisent = 'valeur' (égalité simple)
    common = []
    for cond in conditions:
        # Condition spécifique : [col] = 'valeur' (pas IN)
        if re.match(r"\[?\w+\]?\s*=\s*'[^']*'", cond) and " IN " not in cond.upper():
            continue  # skip cell-specific condition
        common.append(cond)

    if not common:
        return before_where
    return before_where + " " + " AND ".join(common)


def _fix_missing_cte(original_sql: str, generated_sql: str) -> str:
    """Si le SQL généré référence un CTE du SQL original sans le définir, préfixe le CTE.

    Problème courant : le LLM écrit ``SELECT ... FROM MyCTE`` sans inclure
    le ``WITH MyCTE AS (...)`` qui le définit.  SQL Server retourne alors
    « Nom d'objet 'MyCTE' non valide ».

    Cette correction est générique (pas liée à une BDD spécifique).
    """
    if not original_sql or not generated_sql:
        return generated_sql

    gen_upper = generated_sql.upper().strip()

    # Si le SQL généré a déjà un WITH, on suppose que le LLM l'a inclus
    if gen_upper.startswith("WITH "):
        return generated_sql

    # Extraire le bloc CTE du SQL original
    cte_block, cte_names = _extract_cte_block(original_sql)
    if not cte_block or not cte_names:
        return generated_sql

    # Vérifier si le SQL généré référence un CTE sans le définir
    referenced = set()
    for m in re.finditer(r"(?:FROM|JOIN)\s+(\w+)", generated_sql, re.IGNORECASE):
        name = m.group(1).upper()
        if name in cte_names:
            referenced.add(name)

    if not referenced:
        return generated_sql

    logger.info("Auto-fix CTE: préfixe %s CTE(s) manquant(s) au SQL généré", len(referenced))
    return f"{cte_block}\n{generated_sql}"


def _make_detail_sql(cell_sql: str, max_rows: int = 0) -> str:
    """Generate a detail SQL from an aggregated cell SQL.

    Replaces the final 'SELECT SUM(...) FROM' with 'SELECT [TOP N] * FROM'
    to show the individual rows behind the aggregated value.
    Preserves the CTE block intact.
    If *max_rows* > 0, injects ``TOP max_rows`` to limit detail output.
    """
    # Split: CTE block (WITH ... AS (...)) + final SELECT
    cte_match = re.match(
        r"(WITH\s+.+?\)\s*)(?=SELECT\b)",
        cell_sql,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if cte_match:
        cte_block = cte_match.group(1)
        final_select = cell_sql[cte_match.end() :]
    else:
        cte_block = ""
        final_select = cell_sql

    # Replace the SELECT ... FROM with SELECT [TOP N] * FROM in the final SELECT only
    top_clause = f"TOP {max_rows} " if max_rows > 0 else ""
    new_select = re.sub(
        r"^SELECT\s+.+?\s+FROM\b",
        f"SELECT {top_clause}* FROM",
        final_select,
        count=1,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if new_select == final_select:
        return ""
    return cte_block + new_select


_VALID_RESPONSE_TYPES = {
    "sql",
    "display",
    "cell",
    "fill",
    "fill_sql",
    "multi",
    "clone_sheet",
    "fill_plan",
    "emit_tab",
}


_COL_LETTER_RE = re.compile(r"^[A-Z]{1,3}$")


# Hard caps on LLM-emitted tab shape to prevent memory explosion / DoS.
# L'app stocke et affiche déjà des classeurs gigantesques (.afz.json
# observés jusqu'à 15 MiB ; iris-grid.js rend par paquets de 200 lignes
# avec un bouton "Afficher plus"). Le LLM est borné en sortie par les
# tokens output Anthropic, pas par un cap arbitraire ici. Aucune limite
# de taille n'est imposée côté backend sur les contenus (rows, columns,
# cellDetails, sql, match). La seule contrainte de forme qui reste est
# la cohérence shape (rows[i] doit avoir len(columns)).
#
# **Exception** : le label d'onglet est borné. Un label sert d'identifiant
# UI affiché dans la liste des onglets, dans les bandeaux, dans les logs.
# Une string de plusieurs MiB ferait crasher l'affichage de la liste
# classeurs (DOM lent, scroll cassé) sans bénéfice fonctionnel — un nom
# d'onglet n'a aucune raison réaliste de dépasser quelques centaines de
# caractères. Le cap est UI/log, pas un rattrapage de comportement.
_EMIT_TAB_MAX_LABEL_LEN = 500
_EMIT_TAB_ALLOWED_DETAIL_KEYS = frozenset(
    {
        "sql",
        "match",
        "match_exclude",
        "value_column",
        "source_tab_index",
        "label",
        "derived_formula",
    }
)
_EMIT_TAB_DERIVED_OPS = frozenset({"+", "-", "*", "/"})


def _max_referenced_row(tab: Dict[str, Any]) -> Optional[int]:
    """Retourne la plus grande coordonnée de ligne référencée par le LLM dans
    les cellDetails / rows_overrides / cell_groups / derived_formula.refs.
    Sert à détecter qu'un clone_structure_from pointe vers un tab trop petit.
    """
    max_row = -1

    def _parse_r(key: Any) -> Optional[int]:
        if not isinstance(key, str) or "," not in key:
            return None
        try:
            return int(key.split(",", 1)[0].strip())
        except ValueError:
            return None

    # cellDetails keys + derived_formula.refs (une ref peut pointer
    # vers une row plus grande que la clé elle-même).
    cd = tab.get("cellDetails")
    if isinstance(cd, dict):
        for key, detail in cd.items():
            r = _parse_r(key)
            if r is not None and r > max_row:
                max_row = r
            if not isinstance(detail, dict):
                continue
            derived = detail.get("derived_formula")
            if isinstance(derived, dict):
                for ref in derived.get("refs") or []:
                    rr = _parse_r(ref)
                    if rr is not None and rr > max_row:
                        max_row = rr
    # rows_overrides keys
    ro = tab.get("rows_overrides")
    if isinstance(ro, dict):
        for key in ro:
            r = _parse_r(key)
            if r is not None and r > max_row:
                max_row = r
    # cell_groups[*].cells keys
    groups = tab.get("cell_groups")
    if isinstance(groups, list):
        for g in groups:
            if not isinstance(g, dict):
                continue
            cells = g.get("cells")
            if isinstance(cells, dict):
                for key in cells:
                    r = _parse_r(key)
                    if r is not None and r > max_row:
                        max_row = r
    return max_row if max_row >= 0 else None


def _expand_emit_tab(
    parsed: Dict[str, Any],
    tabs_context: Optional[List[Dict[str, Any]]],
    active_sheet_content: Optional[List[Dict[str, Any]]] = None,
) -> Optional[Dict[str, str]]:
    """Expanse la forme compacte d'emit_tab en forme complète avant validation.

    - ``tab.clone_structure_from`` (int) : copie columns/rows/merges du tab source.
      Essentiel pour les gros templates (MODELE RATIO2 = 64×17) — permet au LLM
      de ne pas réémettre la structure complète dans sa réponse, bottleneck output
      token sur Haiku (8K cap). Si le tab source est l'onglet actif, son
      ``sheet_content`` est passé via ``active_sheet_content`` (il n'est PAS dans
      tabs_context car le frontend ne duplique pas).
    - ``tab.rows_overrides`` (dict "R,C" -> value) : applique des substitutions
      textuelles après clone (ex: titre principal, nom d'entité).
    - ``tab.cell_groups`` (list) : groupes partageant ``match_exclude``,
      ``value_column``, ``source_tab_index``. Unrolled en ``cellDetails``. Évite
      la redondance quand plusieurs dizaines de cellules partagent la même règle
      d'agrégation.

    Retourne None en cas de succès (parsed mutated in-place), sinon un dict
    d'erreur prêt à remonter au handler.
    """
    if not isinstance(parsed, dict):
        return {"error": "emit_tab: réponse n'est pas un objet JSON."}
    tab = parsed.get("tab")
    if not isinstance(tab, dict):
        return {"error": "emit_tab: champ 'tab' manquant ou invalide."}

    # 1. clone_structure_from : copie columns/rows/merges depuis un tab source.
    # Garde-fou : si le LLM a choisi un tab trop petit pour les cellDetails
    # (cas typique : confusion entre deux onglets au nom similaire), on
    # auto-swap vers l'onglet actif si ses dimensions couvrent le besoin.
    clone_from = tab.get("clone_structure_from")
    if clone_from is not None:
        if not isinstance(clone_from, int):
            return {"error": "emit_tab: clone_structure_from doit être un entier."}
        if not tabs_context or clone_from < 0 or clone_from >= len(tabs_context):
            return {
                "error": (
                    f"emit_tab: clone_structure_from={clone_from} hors bornes "
                    f"(max={len(tabs_context or []) - 1})."
                )
            }
        source_tab = tabs_context[clone_from]
        source_row_count = int(source_tab.get("row_count") or 0)
        max_ref_row = _max_referenced_row(tab)
        if max_ref_row is not None and source_row_count and max_ref_row >= source_row_count:
            active_idx = next(
                (i for i, t in enumerate(tabs_context) if t.get("is_active")),
                -1,
            )
            if active_idx >= 0 and active_idx != clone_from:
                active_tab = tabs_context[active_idx]
                active_row_count = int(active_tab.get("row_count") or 0)
                if active_row_count > max_ref_row:
                    logger.warning(
                        "emit_tab: clone_structure_from=%d (row_count=%d) trop petit "
                        "pour cellDetails référençant row %d. Auto-swap vers l'actif "
                        "[index=%d, row_count=%d].",
                        clone_from,
                        source_row_count,
                        max_ref_row,
                        active_idx,
                        active_row_count,
                    )
                    clone_from = active_idx
                    tab["clone_structure_from"] = active_idx
                    source_tab = active_tab
        src_cols = source_tab.get("columns") or []
        if not src_cols:
            return {
                "error": (
                    f"emit_tab: tab source [{clone_from}] n'a pas de columns — "
                    "impossible de cloner la structure."
                )
            }
        # Quand le tab source est l'onglet ACTIF, son sheet_content n'est PAS
        # dans tabs_context (le frontend évite la duplication) — on injecte
        # alors le active_sheet_content passé en paramètre.
        source_for_rebuild = dict(source_tab)
        if source_tab.get("is_active") and not source_tab.get("sheet_content"):
            if active_sheet_content:
                source_for_rebuild["sheet_content"] = active_sheet_content
        if "columns" not in tab or not tab.get("columns"):
            tab["columns"] = list(src_cols)
        if "rows" not in tab or not tab.get("rows"):
            rebuilt_rows = _rebuild_rows_from_sheet_content(source_for_rebuild, len(src_cols))
            tab["rows"] = rebuilt_rows
        if "merges" not in tab or not tab.get("merges"):
            tab["merges"] = list(source_tab.get("merges") or [])

        # CRITIQUE — par défaut, WIPE les cellules numériques du template cloné.
        # Sans ça, les chiffres de l'entité source d'origine restent affichés
        # pour l'entité cible quand le recompute ne trouve pas de source —
        # incident "données fausses silencieusement".
        # Le LLM doit émettre cellDetails (+ recompute) ou rows_overrides pour les
        # remplir. Labels texte préservés (sections, périodes, colonnes).
        # Override possible via tab.preserve_source_values=true (rare).
        #
        # En parallèle du wipe, on mémorise les positions numériques du template
        # dans ``parsed["_coverage_meta"]`` — ces positions servent au coverage
        # checker de ``preview_emit_tab`` pour lister les trous structurels.
        # Purement structurel : aucun jugement sur le SENS des cellules (pas de
        # scan de labels type "Total" ou "OCTOBRE"). Marche sur n'importe quel
        # template, n'importe quel domaine.
        template_numeric_positions: List[str] = []
        if not tab.get("preserve_source_values"):
            rows = tab.get("rows") or []
            wiped_count = 0
            for r_idx, row in enumerate(rows):
                if not isinstance(row, list):
                    continue
                for c_idx, val in enumerate(row):
                    if val is None:
                        continue
                    is_numeric = False
                    if isinstance(val, (int, float)) and not isinstance(val, bool):
                        is_numeric = True
                    elif isinstance(val, str):
                        s = val.strip()
                        if s:
                            try:
                                float(s)
                                is_numeric = True
                            except (TypeError, ValueError):
                                pass
                    if is_numeric:
                        row[c_idx] = None
                        wiped_count += 1
                        template_numeric_positions.append(f"{r_idx},{c_idx}")
            logger.info(
                "emit_tab clone_structure_from=%d : %d cellules numériques wipées "
                "(seront remplies par cellDetails recompute ou restent None).",
                clone_from,
                wiped_count,
            )
        if template_numeric_positions:
            parsed.setdefault("_coverage_meta", {})[
                "template_numeric_positions"
            ] = template_numeric_positions

    # 2. rows_overrides : substitutions textuelles (R,C) -> valeur
    rows_overrides = tab.get("rows_overrides")
    if rows_overrides is not None:
        if not isinstance(rows_overrides, dict):
            return {"error": "emit_tab: rows_overrides doit être un objet."}
        rows = tab.get("rows") or []
        for key, value in rows_overrides.items():
            if not isinstance(key, str) or "," not in key:
                return {
                    "error": (
                        f"emit_tab: rows_overrides clé '{key}' invalide " "(format attendu 'R,C')."
                    )
                }
            try:
                rr = int(key.split(",", 1)[0].strip())
                cc = int(key.split(",", 1)[1].strip())
            except ValueError:
                return {"error": (f"emit_tab: rows_overrides clé '{key}' non-entiers.")}
            if rr < 0 or rr >= len(rows):
                continue  # silently skip out-of-bounds override (template resized)
            if cc < 0 or cc >= len(rows[rr]):
                continue
            rows[rr][cc] = value

    # 3. cell_groups : unroll en cellDetails
    groups = tab.get("cell_groups")
    if groups is not None:
        if not isinstance(groups, list):
            return {"error": "emit_tab: cell_groups doit être une liste."}
        cell_details = tab.get("cellDetails") or {}
        if not isinstance(cell_details, dict):
            return {"error": "emit_tab: cellDetails doit être un objet."}
        for g_idx, group in enumerate(groups):
            if not isinstance(group, dict):
                return {"error": f"emit_tab: cell_groups[{g_idx}] doit être un objet."}
            shared_match_exclude = group.get("match_exclude")
            shared_value_column = group.get("value_column")
            shared_source_tab = group.get("source_tab_index")
            shared_sql = group.get("sql")
            cells = group.get("cells") or {}
            if not isinstance(cells, dict):
                return {"error": (f"emit_tab: cell_groups[{g_idx}].cells doit être un objet.")}
            for key, cell in cells.items():
                if not isinstance(cell, dict):
                    return {
                        "error": (
                            f"emit_tab: cell_groups[{g_idx}].cells['{key}'] " "doit être un objet."
                        )
                    }
                expanded = dict(cell)
                if shared_match_exclude is not None and "match_exclude" not in expanded:
                    expanded["match_exclude"] = shared_match_exclude
                if shared_value_column is not None and "value_column" not in expanded:
                    expanded["value_column"] = shared_value_column
                if shared_source_tab is not None and "source_tab_index" not in expanded:
                    expanded["source_tab_index"] = shared_source_tab
                if shared_sql is not None and "sql" not in expanded:
                    expanded["sql"] = shared_sql
                cell_details[key] = expanded
        tab["cellDetails"] = cell_details
        # On retire cell_groups pour que la validation stricte ne les voie pas
        del tab["cell_groups"]

    return None


def _rebuild_rows_from_sheet_content(
    source_tab: Dict[str, Any],
    ncols: int,
) -> List[List[Any]]:
    """Reconstitue la grille 2D d'un tab source depuis son sheet_content aplati.

    Utilisé par clone_structure_from : le frontend émet les rows d'un onglet sous
    forme aplatie (list of {row, col, value, match?}) dans sheet_content ; il
    faut reconstituer la matrice 2D pour la recopier dans le nouvel onglet.

    **Important** : le frontend plafonne sheet_content à 500 cellules (cap
    `MAX_ACTIVE_CELLS`) — la dernière row présente peut être inférieure à la
    vraie taille du tab. On se base donc sur ``row_count`` (toujours exact)
    comme dimension de la grille, pas sur le max des entrées sheet_content.
    """
    columns = source_tab.get("columns") or []
    col_to_idx = {c: i for i, c in enumerate(columns)}
    sheet_content = source_tab.get("sheet_content") or []
    # Dimension définitive = row_count du tab source (non tronqué par le cap
    # sheet_content). Fallback sur max(row) si row_count manquant.
    real_row_count = int(source_tab.get("row_count") or 0)
    max_row = 0
    for cell in sheet_content:
        if not isinstance(cell, dict):
            continue
        r = cell.get("row")
        if isinstance(r, int) and r > max_row:
            max_row = r
    nrows = max(real_row_count, max_row)
    if nrows == 0:
        return []
    rows: List[List[Any]] = [[None] * ncols for _ in range(nrows)]
    for cell in sheet_content:
        if not isinstance(cell, dict):
            continue
        r = cell.get("row")
        col = cell.get("col")
        if not isinstance(r, int) or r < 1:
            continue
        ci = col_to_idx.get(col)
        if ci is None:
            continue
        if r - 1 >= len(rows):
            continue
        rows[r - 1][ci] = cell.get("value")
    return rows


def _sql_literal(v: Any) -> str:
    """Échappe une valeur scalaire pour SQL Server (T-SQL)."""
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def _sql_bracket_identifier(name: str) -> str:
    """Échappe un identifiant pour usage dans ``[name]`` en T-SQL. Double les
    ``]`` comme T-SQL l'exige (``a]b`` → ``[a]]b]``). Protège contre
    l'injection via un nom de colonne malicieux (defense-in-depth : les noms
    peuvent provenir d'entrées contrôlées par le LLM).
    """
    return "[" + str(name).replace("]", "]]") + "]"


def _build_match_conditions(
    match: Optional[Dict[str, Any]],
    match_exclude: Optional[Dict[str, List[Any]]] = None,
) -> List[str]:
    """Compose la liste des conditions SQL (``[col] = v`` / ``IN`` / ``NOT IN``)
    pour un match + match_exclude donnés. Helper partagé par
    :func:`_build_drill_down_sql` et :func:`_build_derived_drill_down_sql`.
    Les identifiants sont échappés via :func:`_sql_bracket_identifier`.
    """
    conds: List[str] = []
    for k, v in (match or {}).items():
        if not isinstance(k, str) or not k:
            continue
        col = _sql_bracket_identifier(k)
        if isinstance(v, list):
            if not v:
                continue
            vals = ", ".join(_sql_literal(x) for x in v)
            conds.append(f"{col} IN ({vals})")
        else:
            conds.append(f"{col} = {_sql_literal(v)}")
    for k, vs in (match_exclude or {}).items():
        if not isinstance(k, str) or not vs:
            continue
        col = _sql_bracket_identifier(k)
        vals = ", ".join(_sql_literal(x) for x in vs)
        conds.append(f"{col} NOT IN ({vals})")
    return conds


def _split_cte_from_source_sql(source_sql: str) -> Optional[Tuple[str, str, Optional[str]]]:
    """Sépare un ``source_sql`` en (cte_block, cte_name, original_where).

    Retourne ``None`` si le SQL n'a pas de CTE de tête ``WITH name AS (...)``
    — le fallback via :func:`_append_conditions_to_where` doit être utilisé.
    """
    # Header CTE depuis ``app.services.ai.cte_regex.CTE_HEADER_PATTERN`` (single
    # source of truth). Group 1 (outer) = bloc WITH complet ; Group 2 (de
    # CTE_HEADER_PATTERN) = nom du CTE.
    cte_match = re.match(
        r"(?is)\s*(" + CTE_HEADER_PATTERN + r".*?\))\s*SELECT\b",
        source_sql,
    )
    if not cte_match:
        return None
    cte_block = cte_match.group(1)
    cte_name = cte_match.group(2)
    rest = source_sql[cte_match.end() :]
    where_match = re.search(
        r"(?is)\bWHERE\b\s+(.+?)(?=\bGROUP\s+BY\b|\bORDER\s+BY\b|;|$)",
        rest,
    )
    original_where = where_match.group(1).strip() if where_match else None
    return cte_block, cte_name, original_where


def _build_drill_down_sql(
    source_sql: str,
    match: Dict[str, Any],
    match_exclude: Optional[Dict[str, List[Any]]] = None,
) -> str:
    """Construit la SQL de drill-down d'une cellule emit_tab à partir :
    - du ``source_sql`` du tab source (CTE + SELECT agrégé + WHERE + GROUP BY)
    - du ``match`` (dim → valeur ou liste de valeurs IN)
    - du ``match_exclude`` (dim → liste de valeurs NOT IN)

    Stratégie : on garde le CTE (`WITH ... AS (...)`) intact, on remplace le
    SELECT agrégé par ``SELECT * FROM <CTE_name>``, et on accroche au WHERE
    existant les conditions match / match_exclude. Le drill-down expose ainsi
    les lignes DÉTAILLÉES qui composent la cellule agrégée.
    """
    if not source_sql or not isinstance(source_sql, str):
        return ""
    split = _split_cte_from_source_sql(source_sql)
    if split is None:
        return _append_conditions_to_where(source_sql, match, match_exclude)
    cte_block, cte_name, original_where = split

    conds = _build_match_conditions(match, match_exclude)
    all_conds: List[str] = []
    if original_where:
        all_conds.append(f"({original_where})")
    all_conds.extend(conds)
    where_clause = " AND ".join(all_conds)

    if where_clause:
        return f"{cte_block}\nSELECT * FROM {cte_name}\nWHERE {where_clause}"
    return f"{cte_block}\nSELECT * FROM {cte_name}"


def _append_conditions_to_where(
    sql: str,
    match: Dict[str, Any],
    match_exclude: Optional[Dict[str, List[Any]]],
) -> str:
    """Fallback pour SQL sans CTE : on ajoute les conditions au WHERE existant."""
    conds: List[str] = []
    for k, v in (match or {}).items():
        if isinstance(v, list):
            if not v:
                continue
            vals = ", ".join(_sql_literal(x) for x in v)
            conds.append(f"[{k}] IN ({vals})")
        else:
            conds.append(f"[{k}] = {_sql_literal(v)}")
    for k, vs in (match_exclude or {}).items():
        if not vs:
            continue
        vals = ", ".join(_sql_literal(x) for x in vs)
        conds.append(f"[{k}] NOT IN ({vals})")
    if not conds:
        return sql
    addition = " AND ".join(conds)
    if re.search(r"(?i)\bWHERE\b", sql):
        return re.sub(
            r"(?is)(\bWHERE\b\s+)(.+?)(\bGROUP\s+BY\b|\bORDER\s+BY\b|;|$)",
            lambda m: m.group(1)
            + m.group(2).strip()
            + " AND "
            + addition
            + " "
            + (m.group(3) or ""),
            sql,
            count=1,
        )
    # Ajouter un WHERE juste avant GROUP BY / ORDER BY / fin
    if re.search(r"(?i)\bGROUP\s+BY\b", sql):
        return re.sub(r"(?i)\bGROUP\s+BY\b", f"WHERE {addition} GROUP BY", sql, count=1)
    if re.search(r"(?i)\bORDER\s+BY\b", sql):
        return re.sub(r"(?i)\bORDER\s+BY\b", f"WHERE {addition} ORDER BY", sql, count=1)
    return sql.rstrip().rstrip(";") + f" WHERE {addition}"


# ── Drill-down SQL pour cellules ``derived_formula`` ──────────────────────
#
# Une cellule ``derived_formula`` calcule une valeur par combinaison d'autres
# cellules (``op`` ∈ {+, -, *, /}, ``refs`` = coords ``"R,C"``). Le backend
# évaluait déjà la valeur numérique (via :func:`_evaluate_derived_formulas`),
# mais ne générait **aucun** SQL de drill-down pour ces cellules → le frontend
# affichait un point violet mensonger (cellDetail présent) puis le clic ne
# produisait rien. Cette section corrige ce trou : on descend récursivement
# dans la formule jusqu'aux cellules terminales (``match`` + ``source_sql``
# drillable), puis on assemble un UNION ALL qui expose toutes les lignes
# sources avec deux colonnes d'annotation : ``__source_cell`` (coord de la
# leaf d'origine) et ``__contribution`` (rôle logique : ``+``, ``-``, ``num``,
# ``denom``).
#
# Conventions :
# - Une ref vers ``rows_overrides`` (valeur saisie directement), ou vers une
#   cellule ``match`` dont le tab source n'a pas de SQL, ou vers une cellule
#   template vide : **skip silencieux** (pas drillable par définition).
# - Si **aucune** leaf drillable n'est collectée, ``_build_derived_drill_down_sql``
#   retourne ``""`` → la cellule n'a pas de ``sql`` écrit → le contrat UI
#   ``_cellHasRealDetail`` côté frontend refusera d'afficher le point violet.
# - Les opérateurs non-additifs (``-``, ``/``) propagent le rôle en
#   conséquence : pour ``a - b - c`` la première ref hérite ``+`` et les
#   suivantes sont inversées ; pour ``a / b / c`` la première est le
#   numérateur et les suivantes reçoivent le suffixe ``_denom``. Pour ``*``
#   il n'y a pas de sémantique SQL claire (la multiplication de lignes n'a
#   pas de sens), mais le drill-down reste informatif : on montre les lignes
#   sources des deux côtés, marquées du même rôle que le parent.


def _invert_derived_role(role: str) -> str:
    """Inverse le préfixe additif d'un rôle (+ ↔ -) en conservant le suffixe
    (ex: ``+_denom`` → ``-_denom``). Utilisé pour propager le signe au
    travers d'une soustraction imbriquée.
    """
    base, _, suffix = role.partition("_")
    inverted = "-" if base == "+" else ("+" if base == "-" else base)
    if suffix:
        return f"{inverted}_{suffix}"
    return inverted


def _combine_derived_role(parent_role: str, op: Optional[str], index: int) -> str:
    """Calcule le rôle d'une ref enfant en fonction de l'op parent.

    - ``+`` et ``*`` : l'enfant hérite strictement du rôle parent.
    - ``-`` : premier enfant hérite ; suivants reçoivent le rôle inversé.
    - ``/`` : premier enfant hérite (numérateur) ; suivants reçoivent le
      suffixe ``_denom`` ajouté au rôle parent (si déjà présent, conservé).
    - Op inconnu : fallback = rôle parent (inchangé). Les ops invalides sont
      déjà rejetées à la validation (:func:`_validate_derived_formula_shape`),
      donc ce fallback est une simple sécurité.
    """
    if op in ("+", "*") or op is None:
        return parent_role
    if op == "-":
        if index == 0:
            return parent_role
        return _invert_derived_role(parent_role)
    if op == "/":
        if index == 0:
            return parent_role
        if parent_role.endswith("_denom"):
            return parent_role
        return f"{parent_role}_denom"
    return parent_role


def _resolve_source_sql_for_match(
    detail: Dict[str, Any],
    tabs_context: List[Dict[str, Any]],
    *,
    strict_hint: bool = False,
) -> Optional[Tuple[str, List[str]]]:
    """Pour un cellDetail avec ``match``, retrouve ``(source_sql, source_columns)``.

    - Si ``source_tab_index`` pointe vers un tab valide avec un ``sql`` :
      retourne ce tab.
    - Si ``source_tab_index`` pointe vers un tab valide **sans** ``sql`` :
        * ``strict_hint=True`` (utilisé par ``_collect_derived_leaves``) →
          ``None``. Le LLM a explicitement désigné cette source ; si elle
          n'est pas drillable, on ne doit pas silencieusement cibler un
          autre tab (risque de données fausses affichées à l'utilisateur).
        * ``strict_hint=False`` (boucle match legacy) → fallback pour
          compat ascendante avec les LLMs qui oublient ``source_tab_index``.
    - Si ``source_tab_index`` absent / out of bounds → fallback : 1er tab
      avec ``sql`` dont ``columns`` ⊇ ``match.keys()``.
    - Aucun candidat → ``None``.
    """
    if not isinstance(detail, dict):
        return None
    match = detail.get("match")
    if not isinstance(match, dict) or not match:
        return None
    src_idx = detail.get("source_tab_index")
    hint_was_valid = False
    if isinstance(src_idx, int) and 0 <= src_idx < len(tabs_context):
        hint_was_valid = True
        hint_tab = tabs_context[src_idx] if isinstance(tabs_context[src_idx], dict) else None
        if hint_tab:
            hinted = hint_tab.get("sql")
            if hinted:
                return hinted, list(hint_tab.get("columns") or [])
    if strict_hint and hint_was_valid:
        return None
    match_keys = set(match.keys())
    for t in tabs_context:
        if not isinstance(t, dict):
            continue
        t_sql = t.get("sql")
        if not t_sql:
            continue
        cols = list(t.get("columns") or [])
        if match_keys.issubset(set(cols)):
            return t_sql, cols
    return None


def _extract_cte_body(cte_block: str) -> Optional[str]:
    """Extrait le corps ``<body>`` d'un ``WITH <name> AS (<body>)``.
    Retourne ``None`` si le bloc ne match pas ce pattern.

    Header CTE depuis ``app.services.ai.cte_regex.CTE_HEADER_PATTERN`` (single
    source of truth). Group 1 = nom du CTE (de CTE_HEADER_PATTERN) ;
    Group 2 = body SQL.
    """
    match = re.match(
        r"(?is)\s*" + CTE_HEADER_PATTERN + r"(.*)\)\s*$",
        cte_block.strip(),
    )
    if not match:
        return None
    return match.group(2).strip()


def _collect_derived_leaves(
    cell_details: Dict[str, Any],
    tabs_context: List[Dict[str, Any]],
    root_key: str,
    *,
    _path_stack: Optional[set] = None,
    _role: str = "+",
) -> List[Tuple[str, str, List[str], str, Dict[str, Any], Dict[str, Any]]]:
    """Descend récursivement dans la formule de ``root_key`` et collecte les
    leaves drillables (cellules avec ``match`` + ``source_sql`` résolu).

    Returns: liste de tuples
    ``(leaf_key, source_sql, source_columns, role, match, match_exclude)``.

    Les refs non drillables sont **silencieusement ignorées** :
    - cellule avec ``rows_overrides`` pure (pas de ``match``, pas de ``derived_formula``)
    - cellule ``match`` dont le tab source désigné n'a pas de ``sql``
      (respect strict du hint ``source_tab_index`` — pas de redirection silencieuse
      vers un autre tab)
    - cellule vide/template (absente de ``cell_details``)
    - cellule avec seulement un ``label``

    ``_path_stack`` est un marqueur de CHEMIN courant (DFS) qui garantit
    qu'on ne revient pas sur une cellule dans la même lignée d'appels —
    protection défensive contre les cycles (déjà rejetés à la validation,
    mais re-check ici protège les classeurs restaurés d'un état corrompu).
    On ajoute avant la récursion et on retire après, pour qu'une même
    cellule puisse apparaître dans des branches parallèles (ex: ratio
    ``A/B`` où ``A = X + Y`` et ``B = X`` — ``X`` doit être collecté
    2 fois, une fois comme numérateur, une fois comme dénom).
    """
    if _path_stack is None:
        _path_stack = set()
    if root_key in _path_stack:
        return []  # cycle défensif sur le chemin courant

    detail = cell_details.get(root_key)
    if not isinstance(detail, dict):
        return []

    formula = detail.get("derived_formula")
    if isinstance(formula, dict) and isinstance(formula.get("refs"), list):
        op = formula.get("op")
        refs = formula.get("refs") or []
        leaves: List[Tuple[str, str, List[str], str, Dict[str, Any], Dict[str, Any]]] = []
        _path_stack.add(root_key)
        try:
            for i, ref in enumerate(refs):
                if not isinstance(ref, str):
                    continue
                child_role = _combine_derived_role(_role, op, i)
                leaves.extend(
                    _collect_derived_leaves(
                        cell_details,
                        tabs_context,
                        ref,
                        _path_stack=_path_stack,
                        _role=child_role,
                    )
                )
        finally:
            _path_stack.discard(root_key)
        return leaves

    # Pas une formule → leaf terminale : doit avoir un match + source_sql
    # avec respect strict du hint ``source_tab_index`` (un LLM qui désigne
    # explicitement le tab 3 ne doit pas se retrouver routé vers le tab 0).
    resolved = _resolve_source_sql_for_match(detail, tabs_context, strict_hint=True)
    if not resolved:
        return []
    source_sql, source_cols = resolved
    match = detail.get("match") or {}
    match_exclude = detail.get("match_exclude") or {}
    return [(root_key, source_sql, source_cols, _role, dict(match), dict(match_exclude))]


def _build_derived_drill_down_sql(
    cell_details: Dict[str, Any],
    tabs_context: List[Dict[str, Any]],
    root_key: str,
) -> str:
    """Construit un SQL de drill-down complet pour une cellule
    ``derived_formula``, en UNION ALL de toutes les leaves drillables.

    **Garanties de validité SQL Server** (anti-régression BLOCKER B1) :

    1. SQL Server rejette ``FROM (WITH cte AS (…) SELECT …) AS alias`` (un
       ``WITH`` ne peut pas vivre à l'intérieur d'une table dérivée). On
       évite cette imbrication en extrayant les CTE au niveau top.
    2. ``UNION ALL`` exige le même nombre et des types compatibles entre
       les SELECTs — si les sources ont des schémas divergents, le SQL
       sera rejeté au runtime. On refuse préventivement de générer un SQL
       dans ce cas (fail-closed : retourne ``""`` → contrat UI "pas de
       point violet" respecté plutôt qu'une promesse mensongère).

    **Stratégie** (en fonction des sources des leaves) :

    - **1 seule source avec CTE** : extraction du CTE une fois en tête,
      N SELECTs qui référencent le CTE par nom. Cas principal (RATIO2).
    - **1 seule source sans CTE** : UNION ALL de N sous-requêtes wrappées
      (``FROM (<leaf_sql>) AS alias``). Sûr car pas de WITH imbriqué.
    - **Sources multiples, toutes avec CTE, colonnes identiques** :
      clause ``WITH`` combinée avec renommages anti-collision
      (``WITH __leaf_0_CteA AS (…), __leaf_1_CteB AS (…)``), puis
      N SELECTs référençant chacun leur CTE par nom.
    - **Sources multiples sans CTE, colonnes identiques** : UNION ALL
      de sous-requêtes wrappées.
    - **Mix CTE + sans-CTE, OU colonnes incompatibles** : fail-closed ""
      (le frontend n'affichera pas de point violet).

    Retourne ``""`` si aucune leaf drillable n'est collectée.
    """
    leaves = _collect_derived_leaves(cell_details, tabs_context, root_key)
    if not leaves:
        return ""

    root_detail = cell_details.get(root_key) or {}
    root_formula = root_detail.get("derived_formula") or {}
    root_op = root_formula.get("op", "?")
    root_refs = root_formula.get("refs", [])
    header = (
        f"-- Drill-down cellule derived {root_key} "
        f"(op={root_op}, refs={list(root_refs)}, leaves={len(leaves)})\n"
    )

    # Analyse des leaves : présence CTE + compatibilité schéma.
    split_infos = []  # liste de tuples (leaf_info, split | None)
    for leaf in leaves:
        _leaf_key, src_sql, _src_cols, _role, _match, _match_excl = leaf
        split_infos.append((leaf, _split_cte_from_source_sql(src_sql)))

    all_have_cte = all(split is not None for _leaf, split in split_infos)
    none_have_cte = all(split is None for _leaf, split in split_infos)

    # Homogénéité des colonnes : si multi-sources, les schémas doivent
    # matcher pour que UNION ALL fonctionne. On compare les listes de
    # colonnes (ordre + noms). Tuple() pour rendre hashable.
    unique_col_sets = {tuple(leaf[2]) for leaf in leaves if leaf[2]}
    unique_sources = {leaf[1] for leaf in leaves}
    columns_compatible = len(unique_col_sets) <= 1  # 0 ou 1 ensemble de colonnes

    # Mix CTE / sans-CTE : fail-closed (impossible de combiner proprement).
    if not all_have_cte and not none_have_cte:
        return ""

    # Multi-sources avec schémas incompatibles : fail-closed (UNION ALL
    # rejeté au runtime, aucune valeur à promettre à l'UI).
    if len(unique_sources) > 1 and not columns_compatible:
        return ""

    if all_have_cte:
        # Optimisation same-source : si toutes les leaves pointent vers le
        # MÊME ``source_sql``, on garde une seule clause CTE avec son nom
        # original — SQL plus lisible et plus court.
        if len(unique_sources) == 1:
            split = split_infos[0][1]
            assert split is not None  # all_have_cte garantit non-None
            cte_block, cte_name, original_where = split
            selects = []
            for leaf, _split in split_infos:
                leaf_key, _src_sql, _src_cols, role, match, match_exclude = leaf
                conds = _build_match_conditions(match, match_exclude)
                all_conds: List[str] = []
                if original_where:
                    all_conds.append(f"({original_where})")
                all_conds.extend(conds)
                where_clause = " AND ".join(all_conds) if all_conds else "1=1"
                safe_key = str(leaf_key).replace("'", "''")
                safe_role = str(role).replace("'", "''")
                selects.append(
                    f"SELECT '{safe_key}' AS __source_cell, "
                    f"'{safe_role}' AS __contribution, {cte_name}.* "
                    f"FROM {cte_name} WHERE {where_clause}"
                )
            if not selects:
                return ""
            return header + cte_block + "\n" + "\nUNION ALL\n".join(selects)

        # Multi-sources (toutes CTE) : clause WITH combinée avec renommages
        # anti-collision. Chaque SELECT référence son CTE unique par nom.
        cte_clauses = []
        selects = []
        for i, (leaf, split) in enumerate(split_infos):
            if split is None:  # défensif, impossible ici (all_have_cte=True)
                continue
            cte_block, cte_name, original_where = split
            body = _extract_cte_body(cte_block)
            if body is None:
                # CTE malformé vs regex (rare) → fail-closed pour ce SQL
                return ""
            unique_cte_name = f"__leaf_{i}_{cte_name}"
            cte_clauses.append(f"{unique_cte_name} AS (\n{body}\n)")

            leaf_key, _src_sql, _src_cols, role, match, match_exclude = leaf
            conds = _build_match_conditions(match, match_exclude)
            all_conds: List[str] = []
            if original_where:
                all_conds.append(f"({original_where})")
            all_conds.extend(conds)
            where_clause = " AND ".join(all_conds) if all_conds else "1=1"

            safe_key = str(leaf_key).replace("'", "''")
            safe_role = str(role).replace("'", "''")
            selects.append(
                f"SELECT '{safe_key}' AS __source_cell, "
                f"'{safe_role}' AS __contribution, {unique_cte_name}.* "
                f"FROM {unique_cte_name} WHERE {where_clause}"
            )
        if not selects:
            return ""
        with_clause = "WITH " + ",\n".join(cte_clauses) + "\n"
        return header + with_clause + "\nUNION ALL\n".join(selects)

    # Toutes leaves sans CTE : UNION ALL de sous-requêtes wrappées.
    # Pas de WITH au niveau top ni dans les sous-requêtes → SQL Server OK.
    parts = []
    for i, (leaf, _split) in enumerate(split_infos):
        leaf_key, src_sql, _src_cols, role, match, match_exclude = leaf
        inlined = _build_drill_down_sql(src_sql, match, match_exclude)
        if not inlined:
            continue
        # Refus défensif : si _build_drill_down_sql a quand même retourné un
        # SQL qui commence par WITH (regex de _split_cte plus strict que le
        # runtime), on skip pour ne pas produire un SQL invalide.
        if re.match(r"(?is)\s*WITH\s+\w+", inlined):
            continue
        safe_key = str(leaf_key).replace("'", "''")
        safe_role = str(role).replace("'", "''")
        alias = f"__leaf_{i}"
        parts.append(
            f"SELECT '{safe_key}' AS __source_cell, "
            f"'{safe_role}' AS __contribution, {alias}.* "
            f"FROM (\n{inlined}\n) AS {alias}"
        )
    if not parts:
        return ""
    return header + "\nUNION ALL\n".join(parts)


def _validate_emit_tab(
    parsed: Dict[str, Any],
    tabs_context: Optional[List[Dict[str, Any]]],
) -> Optional[Dict[str, str]]:
    """Valide la forme d'une réponse emit_tab. Retourne None si OK, sinon
    un dict ``{"error": "..."}`` prêt à remonter au handler HTTP.

    Le parsed est supposé déjà avoir été passé par _expand_emit_tab (clone
    structure, rows_overrides, cell_groups unrolled).
    """
    if not isinstance(parsed, dict):
        return {"error": "emit_tab: réponse n'est pas un objet JSON."}
    tab = parsed.get("tab")
    if not isinstance(tab, dict):
        return {"error": "emit_tab: champ 'tab' manquant ou invalide."}

    label = tab.get("label")
    if not isinstance(label, str) or not label.strip():
        return {"error": "emit_tab: tab.label doit être une string non-vide."}
    if len(label) > _EMIT_TAB_MAX_LABEL_LEN:
        return {
            "error": (
                f"emit_tab: tab.label trop long ({len(label)} > "
                f"{_EMIT_TAB_MAX_LABEL_LEN} chars)."
            )
        }

    columns = tab.get("columns")
    if not isinstance(columns, list) or not columns:
        return {"error": "emit_tab: tab.columns doit être une liste non-vide."}
    for c in columns:
        if not isinstance(c, str):
            return {"error": "emit_tab: toutes les tab.columns doivent être des strings."}

    rows = tab.get("rows")
    if not isinstance(rows, list):
        return {"error": "emit_tab: tab.rows doit être une liste."}
    ncols = len(columns)
    for r_idx, row in enumerate(rows):
        if not isinstance(row, list):
            return {"error": f"emit_tab: tab.rows[{r_idx}] n'est pas une liste."}
        if len(row) != ncols:
            return {
                "error": (
                    f"emit_tab: tab.rows[{r_idx}] a {len(row)} cellules, "
                    f"attendu {ncols} (cohérence avec tab.columns)."
                )
            }

    nrows = len(rows)
    merges = tab.get("merges")
    if merges is not None:
        if not isinstance(merges, list):
            return {"error": "emit_tab: tab.merges doit être une liste."}
        # Validation tolérante : on skip les merges malformés / hors bornes
        # plutôt que de rejeter toute la réponse. Cas typique : clone depuis
        # un template dont le sheet_content a été tronqué par le cap frontend
        # → dimension reconstituée légèrement différente de la source originale,
        # quelques merges dépassent. Pertes mineures acceptables, on log.
        kept_merges: List[Dict[str, Any]] = []
        for m_idx, m in enumerate(merges):
            if not isinstance(m, dict):
                logger.warning(
                    "emit_tab: tab.merges[%d] ignoré (pas un objet)",
                    m_idx,
                )
                continue
            bad_types = False
            for key in ("r1", "c1", "r2", "c2"):
                if not isinstance(m.get(key), int):
                    bad_types = True
                    break
            if bad_types:
                logger.warning(
                    "emit_tab: tab.merges[%d] ignoré (coords non entières)",
                    m_idx,
                )
                continue
            if m["r1"] > m["r2"] or m["c1"] > m["c2"]:
                logger.warning(
                    "emit_tab: tab.merges[%d] ignoré (rectangle invalide)",
                    m_idx,
                )
                continue
            if m["r1"] < 0 or m["r2"] >= nrows or m["c1"] < 0 or m["c2"] >= ncols:
                logger.warning(
                    "emit_tab: tab.merges[%d] ignoré (hors bornes %d×%d)",
                    m_idx,
                    nrows,
                    ncols,
                )
                continue
            kept_merges.append(m)
        tab["merges"] = kept_merges

    cell_details = tab.get("cellDetails")
    if cell_details is not None:
        if not isinstance(cell_details, dict):
            return {"error": "emit_tab: tab.cellDetails doit être un objet."}
        for key, detail in cell_details.items():
            if not isinstance(key, str) or "," not in key:
                return {
                    "error": (
                        f"emit_tab: tab.cellDetails clé '{key}' invalide " "(format attendu 'R,C')."
                    )
                }
            parts = key.split(",", 1)
            try:
                rr = int(parts[0].strip())
                cc = int(parts[1].strip())
            except ValueError:
                return {
                    "error": (
                        f"emit_tab: tab.cellDetails clé '{key}' n'a pas des " "entiers parsables."
                    )
                }
            if rr < 0 or rr >= nrows or cc < 0 or cc >= ncols:
                return {
                    "error": (
                        f"emit_tab: tab.cellDetails['{key}'] hors bornes "
                        f"(grille {nrows}×{ncols})."
                    )
                }
            if not isinstance(detail, dict):
                return {"error": (f"emit_tab: tab.cellDetails['{key}'] doit être un objet.")}
            # Drop any non-whitelisted keys in-place — évite de laisser passer des
            # champs arbitraires qu'un futur code frontend pourrait dereferencer.
            unknown = [k for k in detail if k not in _EMIT_TAB_ALLOWED_DETAIL_KEYS]
            for uk in unknown:
                del detail[uk]
            sql_val = detail.get("sql")
            if sql_val is not None:
                if not isinstance(sql_val, str):
                    return {
                        "error": (f"emit_tab: tab.cellDetails['{key}'].sql doit être une string.")
                    }
            lbl = detail.get("label")
            if lbl is not None:
                if not isinstance(lbl, str):
                    return {
                        "error": (f"emit_tab: tab.cellDetails['{key}'].label doit être une string.")
                    }
                if len(lbl) > _EMIT_TAB_MAX_LABEL_LEN:
                    return {
                        "error": (
                            f"emit_tab: tab.cellDetails['{key}'].label trop long "
                            f"({len(lbl)} > {_EMIT_TAB_MAX_LABEL_LEN} chars)."
                        )
                    }
            vcol = detail.get("value_column")
            if vcol is not None and not isinstance(vcol, str):
                return {
                    "error": (
                        f"emit_tab: tab.cellDetails['{key}'].value_column doit être une string."
                    )
                }
            stix = detail.get("source_tab_index")
            if stix is not None and not isinstance(stix, int):
                return {
                    "error": (
                        f"emit_tab: tab.cellDetails['{key}'].source_tab_index doit être un entier."
                    )
                }
            # Validation schéma pré-vol (option B, 2026-04-27, étendue) :
            # 1. ``source_tab_index`` DOIT être dans les bornes de tabs_context
            #    Sinon le recompute fait du fallback auto-detect silencieux
            #    qui peut sélectionner un tab incompatible (vu sur le run
            #    18:49 où ``MONTHLY_SRC=2`` pointait vers le vide → fallback
            #    sur tab 0 sans colonne ``mois`` → 120 cellules no_source).
            # 2. ``value_column`` DOIT exister dans ``source_tab.columns``.
            #    Avant ce guard, un value_column erroné passait la validation
            #    puis tombait dans le recompute en générant des cellules
            #    None silencieuses.
            #
            # Le LLM reçoit un message structuré qui nomme :
            # - le source_tab_index hors bornes + nombre de tabs disponibles
            # - les colonnes du tab visé quand value_column est mauvais
            # → corrigeable d'un seul coup au lieu de commit puis découvrir
            # le warning post-hoc.
            #
            # **Skip si tabs_context absent** (callers internes/tests qui
            # n'ont pas de classeur).
            # Checks 1 (bornes) et 3 (clés de match) sont INDÉPENDANTS de
            # value_column : un index OOR ou un match sur une dimension absente
            # produisent des données fausses (auto-detect d'un tab incompatible /
            # 0 hit no_source) quel que soit value_column. Les gater derrière
            # ``vcol is not None`` laissait silencieusement passer ces cas quand
            # le LLM omettait value_column. Seul Check 2 (value_column ∈ colonnes
            # du tab) requiert vcol.
            if stix is not None and isinstance(tabs_context, list):
                # Check 1 : source_tab_index dans les bornes
                if not (0 <= stix < len(tabs_context)):
                    return {
                        "error": (
                            f"emit_tab: tab.cellDetails['{key}'].source_tab_index="
                            f"{stix} hors bornes (le classeur a {len(tabs_context)} "
                            f"onglet(s), indices valides : 0..{len(tabs_context) - 1}). "
                            f"Vérifie via `list_tabs()` les indices disponibles AVANT "
                            f"d'écrire `source_tab_index`. Si tu veux un onglet qui "
                            f"n'existe pas encore, crée-le d'abord via `ask_iris()` "
                            f"puis pointe sur l'index retourné."
                        )
                    }
                # Check 2 : value_column dans tab.columns (requiert value_column)
                src_tab = tabs_context[stix]
                src_cols = src_tab.get("columns") if isinstance(src_tab, dict) else None
                if vcol is not None and isinstance(src_cols, list) and src_cols and vcol not in src_cols:
                    preview = list(src_cols)[:15]
                    suffix = "…" if len(src_cols) > 15 else ""
                    src_label = (
                        src_tab.get("label", f"tab[{stix}]")
                        if isinstance(src_tab, dict)
                        else f"tab[{stix}]"
                    )
                    return {
                        "error": (
                            f"emit_tab: tab.cellDetails['{key}'].value_column="
                            f"'{vcol}' n'existe pas dans les colonnes de "
                            f"{src_label!r} (source_tab_index={stix}). "
                            f"Colonnes disponibles : {preview}{suffix}. "
                            f"Soit corrige le `value_column`, soit pointe vers "
                            f"un autre `source_tab_index` qui contient "
                            f"'{vcol}'."
                        )
                    }
                # Check 3 : si match contient des clés non-présentes dans
                # source_tab.columns (typique : ``mois`` quand le tab source
                # est annuel sans granularité mensuelle), 0 hits → no_source
                # silencieux. Validation : toutes les clés du match doivent
                # exister dans source_tab.columns.
                cell_match = detail.get("match")
                if isinstance(cell_match, dict) and isinstance(src_cols, list) and src_cols:
                    missing_keys = [mk for mk in cell_match.keys() if mk not in src_cols]
                    if missing_keys:
                        preview = list(src_cols)[:15]
                        suffix = "…" if len(src_cols) > 15 else ""
                        src_label = (
                            src_tab.get("label", f"tab[{stix}]")
                            if isinstance(src_tab, dict)
                            else f"tab[{stix}]"
                        )
                        return {
                            "error": (
                                f"emit_tab: tab.cellDetails['{key}'].match contient "
                                f"des clés absentes du tab source : {missing_keys}. "
                                f"{src_label!r} (source_tab_index={stix}) expose les "
                                f"colonnes : {preview}{suffix}. Pour matcher sur "
                                f"{missing_keys}, soit utilise un tab source qui "
                                f"contient ces dimensions, soit appelle `ask_iris` "
                                f"avec un GROUP BY qui les ajoute."
                            )
                        }
            match = detail.get("match")
            if match is not None:
                if not isinstance(match, dict):
                    return {
                        "error": (
                            f"emit_tab: tab.cellDetails['{key}'].match doit être un objet plat."
                        )
                    }
                for mk, mv in match.items():
                    if not isinstance(mk, str):
                        return {
                            "error": (f"emit_tab: tab.cellDetails['{key}'].match clé non-string.")
                        }
                    # mv = scalaire (égalité) OU liste de scalaires (IN, pour cumuls
                    # type `mois: [10,11,12,1,2,3]` ou `annee: [2023, 2024]`).
                    if isinstance(mv, list):
                        for lv in mv:
                            if not isinstance(lv, (str, int, float, bool)):
                                return {
                                    "error": (
                                        f"emit_tab: tab.cellDetails['{key}'].match['{mk}'] "
                                        "liste contient un élément non-scalaire."
                                    )
                                }
                    elif not isinstance(mv, (str, int, float, bool)):
                        return {
                            "error": (
                                f"emit_tab: tab.cellDetails['{key}'].match['{mk}'] "
                                "doit être scalaire ou liste de scalaires "
                                "(pas de forme complexe type {op:'like'})."
                            )
                        }
            match_exclude = detail.get("match_exclude")
            if match_exclude is not None:
                if not isinstance(match_exclude, dict):
                    return {
                        "error": (
                            f"emit_tab: tab.cellDetails['{key}'].match_exclude "
                            "doit être un objet."
                        )
                    }
                for mk, mv in match_exclude.items():
                    if not isinstance(mk, str):
                        return {
                            "error": (
                                f"emit_tab: tab.cellDetails['{key}'].match_exclude "
                                "clé non-string."
                            )
                        }
                    if not isinstance(mv, list):
                        return {
                            "error": (
                                f"emit_tab: tab.cellDetails['{key}'].match_exclude['{mk}'] "
                                "doit être une liste."
                            )
                        }
                    for vv in mv:
                        if not isinstance(vv, (str, int, float, bool)):
                            return {
                                "error": (
                                    f"emit_tab: tab.cellDetails['{key}'].match_exclude"
                                    f"['{mk}'] contient une valeur non-scalaire."
                                )
                            }
            derived = detail.get("derived_formula")
            if derived is not None:
                # L1 — mutex : une cellule est SOIT recomputée depuis une
                # source (match + value_column) SOIT dérivée d'autres cellules
                # (derived_formula). Les deux ensemble produiraient un overwrite
                # silencieux (recompute fill → derived écrase).
                if detail.get("match"):
                    return {
                        "error": (
                            f"emit_tab: tab.cellDetails['{key}'] définit à la "
                            "fois `match` et `derived_formula` — incompatible "
                            "(le derived écraserait la valeur recomputée). "
                            "Utilise l'un OU l'autre."
                        )
                    }
                df_err = _validate_derived_formula_shape(key, derived, nrows, ncols)
                if df_err:
                    return df_err

        # Détection de cycles entre derived_formula (A réfère B qui réfère A).
        # Fait après la validation de forme — toutes les refs sont parsables.
        cycle_err = _detect_derived_formula_cycles(cell_details)
        if cycle_err:
            return cycle_err
    # tabs_context inutilisé ici — réservé pour extensions futures (ex: vérifier
    # que les colonnes référencées dans match existent dans un onglet source).
    _ = tabs_context
    return None


def _validate_derived_formula_shape(
    cell_key: str,
    derived: Any,
    nrows: int,
    ncols: int,
) -> Optional[Dict[str, str]]:
    """Valide la forme d'un derived_formula pour UNE cellule.

    Format attendu : ``{"op": "+" | "-" | "*" | "/", "refs": ["R,C", ...]}``.
    Les refs pointent vers d'autres cellules de la MÊME grille (coordonnées
    0-based). Pas de nesting — pour composer, l'émetteur crée des cellules
    intermédiaires chacune avec son propre derived_formula.
    """
    if not isinstance(derived, dict):
        return {
            "error": (
                f"emit_tab: tab.cellDetails['{cell_key}'].derived_formula "
                "doit être un objet {op, refs}."
            )
        }
    op = derived.get("op")
    if op not in _EMIT_TAB_DERIVED_OPS:
        return {
            "error": (
                f"emit_tab: tab.cellDetails['{cell_key}'].derived_formula.op "
                f"doit être l'un de {sorted(_EMIT_TAB_DERIVED_OPS)} (reçu: {op!r})."
            )
        }
    refs = derived.get("refs")
    if not isinstance(refs, list) or not refs:
        return {
            "error": (
                f"emit_tab: tab.cellDetails['{cell_key}'].derived_formula.refs "
                "doit être une liste non-vide de coordonnées 'R,C'."
            )
        }
    # Tous les opérateurs exigent au moins 2 refs.
    #
    # `-` et `/` : 1 ref n'a pas de sens (besoin de 2 opérandes).
    #
    # `+` et `*` : 1 ref est syntaxiquement une recopie déguisée (`X + 0` ≡ X,
    # `X * 1` ≡ X). Le pattern observé (stress_noisy iter9 et antérieurs) :
    # le LLM pose `derived_formula={op:'+', refs:[autre_cellule]}` pour
    # AFFIRMER une valeur sans source, en utilisant la cellule voisine de
    # sémantique différente comme support — ex: copier REALISE dans la case
    # ATTERRISSAGE quand la donnée mensuelle d'atterrissage n'existe pas.
    # C'est une substitution silencieuse plus grave qu'une cellule vide.
    # Si l'intention est légitimement "même valeur que X parce qu'aliasing",
    # c'est UNE source partagée → utiliser un cellDetails avec match/value_column
    # identique, pas un derived_formula "recopie". Cellule vide > recopie
    # déguisée d'une mesure incorrecte.
    if len(refs) < 2:
        return {
            "error": (
                f"emit_tab: tab.cellDetails['{cell_key}'].derived_formula "
                f"op='{op}' exige au moins 2 refs (1 ref = recopie déguisée — "
                "si tu veux la même valeur qu'une autre cellule sourcée, utilise "
                "un cellDetails avec les mêmes match/value_column/source_tab_index ; "
                "si la cellule cible représente une mesure différente sans source, "
                "laisse vide)."
            )
        }
    # Canonicalise les coords de la cellule elle-même pour la self-ref check.
    # Comparer des tuples (rr, cc) plutôt que des strings — une string comme
    # "5, 3" et "5,3" parsent vers les mêmes coords mais diffèrent textuellement.
    try:
        key_rr = int(cell_key.split(",", 1)[0].strip())
        key_cc = int(cell_key.split(",", 1)[1].strip())
    except (ValueError, AttributeError):
        key_rr, key_cc = -1, -1

    for ref in refs:
        if not isinstance(ref, str) or "," not in ref:
            return {
                "error": (
                    f"emit_tab: tab.cellDetails['{cell_key}'].derived_formula.refs "
                    f"contient '{ref}' (format attendu 'R,C')."
                )
            }
        try:
            rr = int(ref.split(",", 1)[0].strip())
            cc = int(ref.split(",", 1)[1].strip())
        except (ValueError, AttributeError):
            return {
                "error": (
                    f"emit_tab: tab.cellDetails['{cell_key}'].derived_formula.refs "
                    f"contient '{ref}' (coords non entières)."
                )
            }
        if rr < 0 or rr >= nrows or cc < 0 or cc >= ncols:
            return {
                "error": (
                    f"emit_tab: tab.cellDetails['{cell_key}'].derived_formula "
                    f"ref '{ref}' hors bornes (grille {nrows}×{ncols})."
                )
            }
        # Self-reference : comparaison par tuple (rr, cc) — robuste à
        # "5,3" vs "5, 3" vs "\t5,3" etc.
        if (rr, cc) == (key_rr, key_cc):
            return {
                "error": (
                    f"emit_tab: tab.cellDetails['{cell_key}'].derived_formula "
                    "se réfère à elle-même."
                )
            }
    return None


def _detect_derived_formula_cycles(
    cell_details: Dict[str, Any],
) -> Optional[Dict[str, str]]:
    """Détecte les cycles dans le graphe de dépendance entre derived_formula.

    Cas typique : A = f(B), B = f(A) → loop infinie à l'évaluation. On rejette
    à la validation via DFS ITÉRATIF avec 3 couleurs (blanc/gris/noir). Un
    back-edge vers un nœud gris (en cours d'exploration) indique un cycle.

    Implémentation itérative pour éviter ``RecursionError`` sur des chaînes
    de cellDetails longues qui dépasseraient la limite de récursion Python
    (~1000) — pas de cap sur le nombre de cellDetails côté backend, donc
    l'agent peut produire des onglets de taille arbitraire.
    """
    # Construit le graphe : cell_key -> set(refs qui ont aussi un derived_formula)
    graph: Dict[str, List[str]] = {}
    for key, detail in cell_details.items():
        if not isinstance(detail, dict):
            continue
        derived = detail.get("derived_formula")
        if not isinstance(derived, dict):
            continue
        refs = derived.get("refs") or []
        # On ne garde que les refs qui sont elles-mêmes des formules
        # (une ref vers une cellule simple n'introduit pas de cycle).
        dependent_refs = [
            ref
            for ref in refs
            if isinstance(ref, str)
            and ref in cell_details
            and isinstance(cell_details[ref], dict)
            and isinstance(cell_details[ref].get("derived_formula"), dict)
        ]
        graph[key] = dependent_refs

    WHITE, GRAY, BLACK = 0, 1, 2
    color = {k: WHITE for k in graph}

    # DFS itératif : pile de frames (node, iterator_over_neighbors). À chaque
    # pas on avance un pas dans les voisins ; si on retourne sur un nœud GRAY
    # → cycle. À l'épuisement des voisins → node devient BLACK, on dépile.
    for start in graph:
        if color[start] != WHITE:
            continue
        stack: List[tuple] = [(start, iter(graph.get(start, [])))]
        color[start] = GRAY
        path_order = [start]
        cycle: Optional[List[str]] = None
        while stack:
            node, it = stack[-1]
            try:
                neighbor = next(it)
            except StopIteration:
                color[node] = BLACK
                stack.pop()
                if path_order and path_order[-1] == node:
                    path_order.pop()
                continue
            if neighbor not in color:
                continue
            if color[neighbor] == GRAY:
                # Back-edge → cycle. Extrait le sous-chemin.
                if neighbor in path_order:
                    idx = path_order.index(neighbor)
                    cycle = path_order[idx:] + [neighbor]
                else:
                    cycle = [neighbor, neighbor]  # fallback défensif
                break
            if color[neighbor] == BLACK:
                continue
            color[neighbor] = GRAY
            path_order.append(neighbor)
            stack.append((neighbor, iter(graph.get(neighbor, []))))
        if cycle is not None:
            return {
                "error": ("emit_tab: cycle détecté dans derived_formula : " + " → ".join(cycle))
            }
    return None


def _emit_tab_scalar_eq(a: Any, b: Any) -> bool:
    """Égalité tolérante entre scalaires pour le matching emit_tab.

    Traite séparément les cas :
    - ``bool`` : strictement mêmes types (``True != 1`` pour éviter la coercion
      Python ``1 == True``).
    - nombres : comparaison ``float(a) == float(b)`` (règle ``2023 == 2023.0``,
      cas fréquent quand SQL Server retourne DECIMAL).
    - autres : égalité stricte ou égalité de ``str().strip()`` (tolère espaces).
    """
    type_a_bool = isinstance(a, bool)
    type_b_bool = isinstance(b, bool)
    if type_a_bool or type_b_bool:
        return type_a_bool and type_b_bool and a == b
    if a == b:
        return True
    # Essai comparaison numérique (gère 2023 == 2023.0 et "2023" == 2023)
    try:
        return float(a) == float(b)
    except (TypeError, ValueError):
        pass
    try:
        return str(a).strip() == str(b).strip()
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Diagnose no_source : explique POURQUOI un match n'a matché aucune ligne
# source, pour que le LLM voie "JURIDIQUE n'existe pas dans lfaCodeStatistique
# (proche: JURID)" au lieu de juste "no_source: 53". Pur signal enrichi — ne
# bloque jamais l'emit, ne fallback sur rien de non-canonique. Skip la
# validation quand l'info n'est pas fiable (col_distinct absent ou truncated).
# ---------------------------------------------------------------------------
# `0.45` (plus bas que le défaut 0.6 de difflib) : on veut détecter les typos
# proches type "JURIDIQUE"↔"JURID" (ratio ≈ 0.48) sans exiger un seuil trop
# strict. 0.6 raterait ce cas. Empirique sur les 4 runs de 2026-04-18.
_DIAGNOSE_CLOSEST_COUNT = 3
_DIAGNOSE_CLOSEST_CUTOFF = 0.45
_DIAGNOSE_MAX_COLUMNS_LISTED = 30


def _find_candidate_source_tab(
    match_keys: set,
    tabs_context: List[Dict[str, Any]],
    source_tab_index_hint: Optional[int],
) -> Optional[tuple]:
    """Trouve l'onglet source qui couvre toutes les clés de match.

    Priorité au hint `source_tab_index_hint` s'il est valide et couvre les
    clés ; sinon recherche le meilleur fit (colonnes overlap, priorité aux
    onglets avec sheet_content — la vraie donnée, pas juste le schéma).

    Partagé entre _recompute_emit_tab (qui calcule) et _diagnose_no_source
    (qui explique), pour que les deux pointent vers le MÊME onglet — sinon
    le diagnostic cite les valeurs d'une autre colonne que celle qu'on a
    vraiment regardée (L4 review adversariale).

    Retourne (idx, tab) ou None.
    """
    if (
        isinstance(source_tab_index_hint, int)
        and not isinstance(source_tab_index_hint, bool)
        and 0 <= source_tab_index_hint < len(tabs_context)
    ):
        t = tabs_context[source_tab_index_hint]
        if isinstance(t, dict) and match_keys.issubset(set(t.get("columns") or [])):
            return (source_tab_index_hint, t)
    best: Optional[tuple] = None
    best_score = -1
    for idx, t in enumerate(tabs_context):
        if not isinstance(t, dict):
            continue
        cols = set(t.get("columns") or [])
        if not match_keys.issubset(cols):
            continue
        has_data = bool(t.get("sheet_content"))
        score = (10 if has_data else 0) + len(match_keys & cols)
        if score > best_score:
            best = (idx, t)
            best_score = score
    return best


def _diagnose_source_column(
    tab: Dict[str, Any],
    col_name: str,
) -> Optional[Dict[str, Any]]:
    """Lit col_distinct[col_name] d'un onglet source pour diagnose.

    Retourne None si col_distinct absent / colonne non présente / info illisible
    → la validation skip silencieusement cette colonne (pas de faux positif).
    Sinon retourne soit {type:"numeric", min, max, distinct_count}
    soit {type:"string", values:list, truncated:bool, distinct_count}.
    """
    col_distinct = tab.get("col_distinct")
    if not isinstance(col_distinct, dict):
        return None
    info = col_distinct.get(col_name)
    if not isinstance(info, dict):
        return None
    if info.get("type") == "numeric":
        return {
            "type": "numeric",
            "min": info.get("min"),
            "max": info.get("max"),
            "distinct_count": info.get("distinct"),
        }
    values = info.get("values")
    if not isinstance(values, list):
        return None
    return {
        "type": "string",
        "values": [str(v) for v in values],
        "truncated": bool(info.get("truncated")),
        "distinct_count": info.get("distinct", len(values)),
    }


def _diagnose_value_in_column(
    value: Any,
    col_info: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Vérifie si `value` existe dans les distincts d'une colonne source.

    Retourne None si la valeur est trouvée OU si on ne peut pas se prononcer
    (col_distinct truncated et valeur absente du visible → peut exister dans
    la partie non-visible, pas de faux positif). Sinon retourne un dict de
    diagnose {reason, closest_values|source_min|source_max, distinct_count}.

    Coercion numérique tolérante (cohérente avec _emit_tab_scalar_eq) : une
    valeur string parsable en float est traitée comme numérique contre une
    colonne numérique. Empêche le bypass silencieux quand le LLM écrit
    `{annee: "2030"}` au lieu de `{annee: 2030}`.
    """
    if col_info["type"] == "numeric":
        if isinstance(value, bool):
            return None  # booléens pas comparables numériquement ici
        try:
            vf = float(value)  # couvre int, float, et strings parsables
        except (TypeError, ValueError):
            return None
        mn, mx = col_info.get("min"), col_info.get("max")
        if mn is None or mx is None:
            return None
        if mn <= vf <= mx:
            return None
        return {
            "reason": "numeric_out_of_range",
            "source_min": mn,
            "source_max": mx,
            "distinct_count": col_info.get("distinct_count"),
        }
    # string
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return None
    target = str(value).strip()
    target_cf = target.casefold()
    known_list = col_info["values"]
    for known in known_list:
        if str(known).strip().casefold() == target_cf:
            return None
    # Pas trouvé. Si truncated, on skip (peut exister ailleurs).
    if col_info.get("truncated"):
        return None
    closest = get_close_matches(
        target,
        known_list,
        n=_DIAGNOSE_CLOSEST_COUNT,
        cutoff=_DIAGNOSE_CLOSEST_CUTOFF,
    )
    # NOTE: on ne retourne PAS `known_list[:10]` (source_sample) — les valeurs
    # brutes de col_distinct peuvent contenir des données confidentielles
    # (noms de tiers, comptes). closest_values + distinct_count portent déjà
    # l'info actionnable sans leak raw.
    return {
        "reason": "value_not_in_source",
        "closest_values": closest,
        "distinct_count": col_info.get("distinct_count"),
    }


def _diagnose_no_source(
    match: Dict[str, Any],
    tabs_context: List[Dict[str, Any]],
    source_tab_index_hint: Optional[int],
) -> List[Dict[str, Any]]:
    """Diagnose POURQUOI un match échoue à matcher une source. Retourne une
    liste d'erreurs structurées (peut être vide si tout passe la validation
    conservatrice). N'altère rien — pur diagnostic.

    Stratégie :
    - Trouve l'onglet candidat via _find_candidate_source_tab (même logique
      que _recompute_emit_tab — évite le drift).
    - Si aucun onglet ne couvre les clés → reason="key_not_in_any_tab" + liste
      des colonnes existantes.
    - Sinon pour chaque (key, value) du match, vérifie que value est dans
      col_distinct[key] de l'onglet (tolérant case/whitespace). Si truncated
      ou col_distinct absent → skip silencieux (pas de faux positif). Sinon
      produit une erreur avec closest_values ou source_min/max.
    """
    if not match:
        return []
    match_keys = set(match.keys())

    candidate = _find_candidate_source_tab(
        match_keys,
        tabs_context,
        source_tab_index_hint,
    )
    if candidate is None:
        all_columns: set = set()
        for t in tabs_context:
            if isinstance(t, dict):
                all_columns.update(t.get("columns") or [])
        missing = sorted([k for k in match_keys if k not in all_columns])
        return [
            {
                "match_key": None,
                "match_value": None,
                "reason": "key_not_in_any_tab",
                "missing_keys": missing,
                "available_columns": sorted(all_columns)[:_DIAGNOSE_MAX_COLUMNS_LISTED],
            }
        ]

    candidate_idx, candidate_tab = candidate
    errors: List[Dict[str, Any]] = []
    for mk, mv in match.items():
        col_info = _diagnose_source_column(candidate_tab, mk)
        if col_info is None:
            continue  # pas d'info fiable → skip
        values_to_check = mv if isinstance(mv, list) else [mv]
        for v in values_to_check:
            diag = _diagnose_value_in_column(v, col_info)
            if diag is None:
                continue
            errors.append(
                {
                    "match_key": mk,
                    "match_value": v,
                    "source_tab_index": candidate_idx,
                    **diag,
                }
            )
    return errors


#: Opérateurs étendus dans la grammaire ``match`` / ``match_exclude``.
#: Préfixe ``$`` (style MongoDB) pour ne pas collisionner avec d'éventuels
#: noms de colonnes Sage. Si un dict ``match["col"]`` contient au moins une
#: clé de cet ensemble, on dispatch vers ``_emit_tab_match_op``. Sinon (dict
#: sans op connu, scalaire, list) on conserve la sémantique legacy.
_MATCH_OPS = frozenset({"$gt", "$gte", "$lt", "$lte", "$ne", "$between", "$like", "$is_null"})


def _is_match_op_dict(val: Any) -> bool:
    """True si ``val`` est un dict dont au moins une clé est un opérateur
    ``$op`` reconnu. Permet de dispatcher entre la grammaire étendue et le
    fallback legacy (un dict sans op connu → traité comme valeur scalaire,
    ce qui ne matchera quasiment jamais, mais pas de crash)."""
    if not isinstance(val, dict):
        return False
    return any(k in _MATCH_OPS for k in val)


def _coerce_numeric_or_none(x: Any) -> Optional[float]:
    """``x`` → float si parsable, sinon None. ``bool`` ≠ numérique (anti
    coercion Python ``True == 1``). Strings : on strip() avant parse."""
    if isinstance(x, bool):
        return None
    if isinstance(x, (int, float)):
        return float(x)
    if isinstance(x, str):
        try:
            return float(x.strip())
        except (TypeError, ValueError):
            return None
    return None


def _coerce_iso_date_or_none(x: Any) -> Optional[Any]:
    """``x`` → ``date``/``datetime`` si parsable ISO, sinon None. Permet
    de comparer ``$gte "2024-01-01"`` à une valeur ``"2024-06-15"`` comme
    des dates (chronologique) et pas comme des strings (lexical)."""
    if hasattr(x, "isoformat") and not isinstance(x, str):
        return x
    if not isinstance(x, str):
        return None
    import datetime as _dt

    s = x.strip()
    if len(s) < 8:
        return None
    try:
        if "T" in s or " " in s:
            normalized = s.replace(" ", "T")[:19]
            return _dt.datetime.fromisoformat(normalized)
        return _dt.date.fromisoformat(s[:10])
    except (ValueError, TypeError):
        return None


def _emit_tab_cmp_op(actual: Any, sym: str, expected: Any) -> bool:
    """Compare ``actual sym expected`` avec coercion num → date → str.

    Stratégie :
    1. Tentative numérique sur les deux côtés (couvre les cas SQL Server
       DECIMAL retourné en string "1000.50").
    2. Tentative date ISO sur les deux côtés (couvre les "$gte": "2024-01-01").
    3. Fallback string comparison (lexicographique, peut être surprenant
       mais déterministe — le LLM ne devrait pas utiliser $gt sur du texte
       arbitraire).
    ``None`` côté actual OU expected → False (NULL n'est jamais > ou <).
    """
    if actual is None or expected is None:
        return False
    # 1. Numérique
    na = _coerce_numeric_or_none(actual)
    ne = _coerce_numeric_or_none(expected)
    if na is not None and ne is not None:
        if sym == ">":
            return na > ne
        if sym == ">=":
            return na >= ne
        if sym == "<":
            return na < ne
        if sym == "<=":
            return na <= ne
    # 2. Date ISO
    da = _coerce_iso_date_or_none(actual)
    de = _coerce_iso_date_or_none(expected)
    if da is not None and de is not None:
        try:
            if sym == ">":
                return da > de
            if sym == ">=":
                return da >= de
            if sym == "<":
                return da < de
            if sym == "<=":
                return da <= de
        except TypeError:
            pass
    # 3. String fallback
    try:
        sa = str(actual).strip()
        se = str(expected).strip()
        if sym == ">":
            return sa > se
        if sym == ">=":
            return sa >= se
        if sym == "<":
            return sa < se
        if sym == "<=":
            return sa <= se
    except (TypeError, ValueError):
        return False
    return False


def _emit_tab_match_op(actual: Any, op_dict: Dict[str, Any]) -> bool:
    """Évalue un dict d'opérateurs ``$op`` contre ``actual``. AND entre les
    opérateurs (toutes les contraintes doivent matcher). Les clés non-``$``
    sont ignorées silencieusement (typos LLM rares ; les ops inconnus ``$xx``
    aussi). Une seule contrainte qui échoue → False immédiat.
    """
    for op, expected in op_dict.items():
        if op == "$is_null":
            is_null = actual is None or (isinstance(actual, str) and actual.strip() == "")
            if bool(expected) != is_null:
                return False
            continue
        if op == "$ne":
            if _emit_tab_scalar_eq(actual, expected):
                return False
            continue
        if op == "$like":
            if not isinstance(expected, str) or actual is None:
                return False
            # Refus si le pattern contient des chars NUL — ils sont
            # utilisés en interne comme placeholders pour distinguer
            # `%`/`_` LIKE de leur version escape. Un NUL injecté
            # (data binaire leak, prompt-injection) confondrait avec
            # le placeholder et permettrait d'injecter un wildcard
            # non-prévu. Pas attendu dans des données Sage normales.
            if "\x00" in expected:
                return False
            import re as _re

            # SQL LIKE → regex Python : ``%`` = ``.*``, ``_`` = ``.``.
            # Note : ``%`` et ``_`` ne sont PAS des metachars regex et ne
            # sont donc pas escapés par ``re.escape`` — on ne peut pas les
            # remplacer après escape. On utilise des placeholders uniques
            # ``\x00P\x00`` / ``\x00U\x00`` qui survivent à ``re.escape``
            # sans transformation, puis on les remplace par leur regex
            # cible. La garde NUL ci-dessus empêche l'injection.
            ph_percent = "\x00P\x00"
            ph_underscore = "\x00U\x00"
            prepared = expected.replace("%", ph_percent).replace("_", ph_underscore)
            pattern = (
                "^"
                + _re.escape(prepared).replace(ph_percent, ".*").replace(ph_underscore, ".")
                + "$"
            )
            try:
                # Match insensible à la casse (sémantique SQL Server par
                # défaut, collation ``SQL_Latin1_General_CP1_CI_AS``).
                # Sage Coala utilise la collation par défaut. Documenté
                # dans le system prompt copilot pour que le LLM s'aligne.
                if _re.fullmatch(pattern, str(actual), flags=_re.IGNORECASE) is None:
                    return False
            except _re.error:
                return False
            continue
        if op == "$between":
            if not isinstance(expected, list) or len(expected) != 2:
                return False
            lo, hi = expected
            if not (_emit_tab_cmp_op(actual, ">=", lo) and _emit_tab_cmp_op(actual, "<=", hi)):
                return False
            continue
        if op in ("$gt", "$gte", "$lt", "$lte"):
            sym = {"$gt": ">", "$gte": ">=", "$lt": "<", "$lte": "<="}[op]
            if not _emit_tab_cmp_op(actual, sym, expected):
                return False
            continue
        # Op inconnu : on logue un warning (debuggabilité — un LLM qui
        # tape `$gtee` doit pouvoir le voir dans les logs serveur sans
        # crasher son run) puis on ignore la contrainte. Toute clé
        # commençant par `$` qui n'est pas dans `_MATCH_OPS` est suspecte ;
        # les clés sans `$` (qui pourraient être des noms de colonnes
        # mal placés) sont aussi traçées.
        if isinstance(op, str) and op.startswith("$"):
            logger.warning(
                "_emit_tab_match_op: opérateur inconnu '%s' ignoré "
                "(valeur=%r). Vérifie l'orthographe (ops connus: %s).",
                op,
                expected,
                sorted(_MATCH_OPS),
            )
    return True


def _emit_tab_null_means_no_match() -> bool:
    """Documentation : sémantique des NULL dans la grammaire ``match``.

    Le helper retourne toujours True ; sa raison d'être est de servir
    de point d'ancrage pour la docstring qui suit (qui ne s'affiche
    pas si elle est posée sur une string littérale).

    **Sémantique des NULL** :
    - ``$gt/$gte/$lt/$lte`` sur ``actual=None`` → False (comme SQL standard,
      NULL comparison = unknown = False côté WHERE).
    - ``$ne X`` sur ``actual=None`` → **True** (divergence Python vs SQL
      trinaire : SQL traiterait comme UNKNOWN = exclu, Python traite
      None ≠ X comme True). Pour exclure les NULL, utiliser
      ``$is_null: false`` explicitement.
    - ``$is_null: true`` matche ``None``, ``""``, ``"   "`` (whitespace).
    - ``$like`` sur ``actual=None`` → False.
    """
    return True


def _emit_tab_match_value(actual: Any, expected: Any) -> bool:
    """Check si ``actual`` matche ``expected`` dans une clé de match.

    Grammaire :
    - ``expected`` dict avec clés ``$op`` (cf. ``_MATCH_OPS``) → opérateurs
      étendus (``$gte``, ``$lt``, ``$between``, ``$like``, ``$is_null``,
      ``$ne``). AND entre les ops.
    - ``expected`` liste → IN (actual doit matcher AU MOINS un élément).
      Permet d'exprimer des cumuls type "Oct-Mars" via ``mois: [10,11,12,1,2,3]``
      ou "années N-2 à N" via ``annee: [2023, 2024, 2025]``.
    - ``expected`` scalaire → égalité tolérante (cf. _emit_tab_scalar_eq).
    """
    if isinstance(expected, dict) and _is_match_op_dict(expected):
        return _emit_tab_match_op(actual, expected)
    if isinstance(expected, list):
        for e in expected:
            if _emit_tab_scalar_eq(actual, e):
                return True
        return False
    return _emit_tab_scalar_eq(actual, expected)


def _emit_tab_in_excluded(val: Any, excluded: Any) -> bool:
    """Check si ``val`` est dans la spec d'exclusion. Étendu à la grammaire
    ``$op`` pour parité avec ``_emit_tab_match_value`` (un user peut vouloir
    exclure un range, un pattern LIKE, etc.).
    """
    if isinstance(excluded, dict) and _is_match_op_dict(excluded):
        return _emit_tab_match_op(val, excluded)
    if isinstance(excluded, list):
        for e in excluded:
            if _emit_tab_scalar_eq(val, e):
                return True
        return False
    return False


def _evaluate_derived_formulas(
    parsed: Dict[str, Any],
) -> tuple:
    """Évalue les cellules ayant un ``derived_formula`` en les résolvant dans
    l'ordre topologique de leurs dépendances.

    Règles :
    - Une ref dont la valeur est None ou non-numérique → propage None (le
      résultat de la formule sera None, marqué comme évalué mais vide).
    - Division par zéro → None.
    - Cycle impossible à ce stade (rejeté par ``_validate_emit_tab`` en amont).

    Retourne (count_evaluated, count_none) pour les métriques.
    """
    tab = parsed.get("tab") or {}
    rows = tab.get("rows") or []
    cell_details = tab.get("cellDetails") or {}
    if not rows or not cell_details:
        return 0, 0

    nrows = len(rows)
    ncols = len(rows[0]) if rows else 0

    # Récupère toutes les cellules qui ont un derived_formula valide
    formula_cells: Dict[str, Dict[str, Any]] = {}
    for key, detail in cell_details.items():
        if not isinstance(detail, dict):
            continue
        derived = detail.get("derived_formula")
        if isinstance(derived, dict) and derived.get("op") in _EMIT_TAB_DERIVED_OPS:
            formula_cells[key] = derived

    if not formula_cells:
        return 0, 0

    # Ordre topologique : résoudre d'abord les cellules dont toutes les refs
    # sont "prêtes" (= ne sont pas des formules non encore évaluées).
    resolved: set = set()
    evaluated = 0
    none_count = 0
    # Pire cas = len(formula_cells) itérations (chaque itération en résout ≥1).
    # Si à une itération rien n'est résolu, c'est qu'il reste un cycle (déjà
    # censé être rejeté à la validation — on sort en warn défensif).
    for _iteration in range(len(formula_cells) + 1):
        progress = False
        for key, derived in list(formula_cells.items()):
            if key in resolved:
                continue
            refs: List[str] = derived.get("refs") or []
            # Toutes les refs qui sont elles-mêmes des formules doivent être
            # résolues avant d'évaluer celle-ci.
            deps_unresolved = any(ref in formula_cells and ref not in resolved for ref in refs)
            if deps_unresolved:
                continue
            # Collecte les valeurs de chaque ref
            values: List[Optional[float]] = []
            for ref in refs:
                try:
                    rr, cc = ref.split(",", 1)
                    rr, cc = int(rr.strip()), int(cc.strip())
                except (ValueError, AttributeError):
                    values.append(None)
                    continue
                if rr < 0 or rr >= nrows or cc < 0 or cc >= ncols:
                    values.append(None)
                    continue
                v = rows[rr][cc]
                if v is None or isinstance(v, bool):
                    values.append(None)
                    continue
                # Chokepoint anonymisation : si v est un token `§...§`
                # (override d'une valeur anonymisée par l'utilisateur),
                # désanonymise avant float(). Sans pseudonymizer, le helper
                # logge un WARNING explicite plutôt que de silencieusement
                # injecter None. Cf. audit anon-leaks 2026-04-27.
                from app.services.anonymization.pseudonymizer import coerce_to_numeric as _coerce

                parsed = _coerce(
                    v,
                    pseudonymizer=None,  # pas dispo dans ce scope statique
                    context_hint=f"_evaluate_derived_formulas ref={ref!r}",
                )
                values.append(parsed)

            op = derived.get("op")
            try:
                rr_dst, cc_dst = key.split(",", 1)
                rr_dst, cc_dst = int(rr_dst.strip()), int(cc_dst.strip())
            except (ValueError, AttributeError):
                resolved.add(key)
                progress = True
                continue
            if rr_dst < 0 or rr_dst >= nrows or cc_dst < 0 or cc_dst >= ncols:
                resolved.add(key)
                progress = True
                continue

            result = _apply_derived_op(op, values)
            if result is None:
                rows[rr_dst][cc_dst] = None
                none_count += 1
            else:
                rows[rr_dst][cc_dst] = round(result, 6)
            evaluated += 1
            resolved.add(key)
            progress = True

        if not progress:
            remaining = set(formula_cells.keys()) - resolved
            if remaining:
                logger.warning(
                    "derived_formula: %d cellules non résolues (cycle ou ref "
                    "vers formule inexistante) : %s",
                    len(remaining),
                    list(remaining)[:5],
                )
            break

    return evaluated, none_count


def _apply_derived_op(op: str, values: List[Optional[float]]) -> Optional[float]:
    """Applique l'opérateur sur une liste de valeurs, avec propagation None,
    fail-closed sur division par zéro ET sur résultat non-fini (inf, NaN).

    Les valeurs non finies (inf/NaN) en entrée ou en sortie remontent None pour
    éviter de polluer silencieusement la grille avec des artéfacts float.
    """
    import math

    if not values or any(v is None for v in values):
        return None
    # Garde d'entrée : rejette les valeurs non-finies (inf, nan, -inf) qui
    # pourraient venir d'un cast float('inf') côté reader ou d'une accumulation
    # défaillante en amont.
    for v in values:
        try:
            if not math.isfinite(float(v)):  # type: ignore[arg-type]
                return None
        except (TypeError, ValueError):
            return None
    if op == "+":
        result = sum(values)  # type: ignore[arg-type]
    elif op == "*":
        result = 1.0
        for v in values:
            result *= v  # type: ignore[operator]
    elif op == "-":
        # a - b - c - ... (séquentiel)
        result = float(values[0])  # type: ignore[arg-type]
        for v in values[1:]:
            result -= v  # type: ignore[operator]
    elif op == "/":
        # a / b / c / ... (séquentiel). Division par 0 → None.
        result = float(values[0])  # type: ignore[arg-type]
        for v in values[1:]:
            if v == 0:
                return None
            result /= v  # type: ignore[operator]
    else:
        # Fail-loud plutôt que silencieux : si un nouvel op est ajouté à
        # ``_EMIT_TAB_DERIVED_OPS`` sans update ici, on veut un crash visible
        # plutôt que des cellules mystérieusement vides (règle "données
        # fausses silencieusement 100× pire qu'un crash").
        raise ValueError(
            f"_apply_derived_op: op '{op}' non implémenté — ajouter le cas "
            "quand on étend _EMIT_TAB_DERIVED_OPS."
        )
    # Garde de sortie : rejette inf/nan (peut apparaître via 1e308 * 1e308 etc.)
    if not math.isfinite(result):
        return None
    return result


def _recompute_emit_tab(
    parsed: Dict[str, Any],
    tabs_context: Optional[List[Dict[str, Any]]],
    pseudonymizer: Optional[Any] = None,
) -> Dict[str, Any]:
    """Recalcule programmatiquement les valeurs numériques de chaque cellule
    dont cellDetails fournit ``match`` (+ éventuellement ``match_exclude`` et
    ``value_column``), en sommant les entrées correspondantes des ``sheet_content``
    des onglets sources. Mode anti-hallucination.

    Stratégie :
    1. Pour chaque cell detail avec ``match`` non-vide, trouve les onglets
       candidats (ceux dont ``columns`` couvrent les clés de ``match``).
    2. Prend l'onglet avec la spécificité maximale (plus de colonnes matchant).
    3. Somme les ``sheet_content[i].value`` où ``sheet_content[i].match`` ⊇
       ``cell.match`` (égalité exacte tolérante) et dont le ``col`` correspond
       à ``value_column`` si fourni.
    4. Rejette les rangées matchant ``match_exclude``.
    5. Si somme calculée ≠ valeur LLM de plus de 1 % (ou LLM = None/non-numérique)
       → overwrite ; sinon garde la valeur LLM (trust).
    Retourne le dict ``parsed`` modifié in-place + une clé ``_recompute_metrics``.
    """
    tab = parsed.get("tab") or {}
    rows = tab.get("rows") or []
    cell_details = tab.get("cellDetails") or {}
    tabs_context = tabs_context or []

    recomputed = 0
    trusted = 0
    no_source = 0
    # Raw list of (cell_key, match, source_tab_index_hint) pour les no_source.
    # Groupé et diagnostiqué à la fin (dédup par match signature → 1 hint pour
    # 53 cellules avec la même faute).
    no_source_raw: List[tuple] = []
    # Détection cross-product : une cellule avec ≥2 clés-listes dans match
    # (ex: {annee:[2023,2024], mois:[10,11,12]}) somme le PRODUIT CARTÉSIEN
    # (2×3 = 6 combos) — pas 2 paires (2023,10) et (2024,11). Le LLM croit
    # souvent que c'est des paires. On collecte les rows matchées pour qu'il
    # voie concrètement ce qui a été sommé. Pas de block : pure info.
    # Format: (cell_key, match, samples [top 5 sc_match dicts], hit_count).
    cross_product_raw: List[tuple] = []
    # Détection source_tab_ties : une cellule avec match couvert par 2+ onglets
    # à la même spécificité max. Le picker prend le 1er par ordre d'index —
    # silencieux. Pur signal pour le LLM (pas de blocage, pas de fallback) :
    # "tu as des sources candidates multiples, précise si besoin".
    # Format: (cell_key, match_keys_tuple, tied_indices_tuple, picked_idx).
    source_tab_ties_raw: List[tuple] = []

    for key, detail in cell_details.items():
        if not isinstance(detail, dict):
            continue
        match = detail.get("match")
        if not isinstance(match, dict) or not match:
            continue
        value_column = detail.get("value_column")
        match_exclude = detail.get("match_exclude") or {}

        try:
            r_str, c_str = key.split(",", 1)
            r = int(r_str.strip())
            c = int(c_str.strip())
        except (ValueError, AttributeError):
            continue
        if r < 0 or r >= len(rows):
            continue
        if c < 0 or c >= len(rows[r]):
            continue

        match_keys = set(match.keys())
        source_tab_index_hint = detail.get("source_tab_index")
        # effective_hint_used : True seulement si le hint est valide ET
        # couvre les clés du match. Un hint invalide (OOR, ou tab sans
        # sheet_content, ou tab qui ne couvre pas match_keys) retombe sur
        # l'auto-detect et le LLM n'a PAS effectivement choisi → ties
        # doivent être signalés (F1 review).
        effective_hint_used = False
        candidates: List[tuple] = []
        if isinstance(source_tab_index_hint, int) and 0 <= source_tab_index_hint < len(
            tabs_context
        ):
            t = tabs_context[source_tab_index_hint]
            if isinstance(t, dict) and (t.get("sheet_content") or []):
                tab_cols = set(t.get("columns") or [])
                if match_keys.issubset(tab_cols):
                    candidates.append(
                        (
                            len(match_keys & tab_cols),
                            source_tab_index_hint,
                            t.get("sheet_content") or [],
                        )
                    )
                    effective_hint_used = True
        if not candidates:
            for t_idx, t in enumerate(tabs_context):
                if not isinstance(t, dict):
                    continue
                sheet_content = t.get("sheet_content") or []
                if not sheet_content:
                    continue
                tab_cols = set(t.get("columns") or [])
                if not match_keys.issubset(tab_cols):
                    continue
                candidates.append((len(match_keys & tab_cols), t_idx, sheet_content))

        if not candidates:
            no_source += 1
            no_source_raw.append((key, match, source_tab_index_hint))
            continue
        candidates.sort(key=lambda x: -x[0])
        _, _src_idx, sheet_content = candidates[0]

        # [DEBUG TEMPORAIRE 2026-04-27] Trace le tab effectivement pické
        # par auto-detect, et un échantillon des 3 premiers sc_cells avec
        # leurs col/value pour voir si le format match les attentes du
        # value_column. Sans ça impossible de debug "match a trouvé N
        # lignes mais aucune n'a value_column=X" — on ne sait pas QUEL
        # tab a été pické ni à QUOI ressemblent ses entries.
        if logger.isEnabledFor(logging.DEBUG):
            sample_cols = [
                (sc.get("col"), type(sc.get("value")).__name__)
                for sc in (sheet_content[:5] if isinstance(sheet_content, list) else [])
                if isinstance(sc, dict)
            ]
            logger.debug(
                "emit_tab recompute SOURCE PICKED cell=(%d,%d) "
                "auto_detect_idx=%d (hint=%s, used=%s) "
                "sheet_content_len=%d sample_(col,type)=%s",
                r,
                c,
                _src_idx,
                source_tab_index_hint,
                effective_hint_used,
                len(sheet_content) if isinstance(sheet_content, list) else 0,
                sample_cols,
            )

        # Tie-break silencieux détecté : 2+ onglets au même score max ET le
        # LLM n'a PAS effectivement pické un tab (hint absent ou invalide).
        # Dédupliqué après la boucle (85 cellules même match_keys → 1 entrée).
        # - best_score > 0 : évite le signal pour des tabs qui ne couvrent
        #   strictement rien (F3 review).
        # - sorted(tied_indices) : signature stable même si l'enum change
        #   d'ordre dans un refactor futur (F2 review).
        if not effective_hint_used and len(candidates) >= 2:
            best_score = candidates[0][0]
            if best_score > 0:
                tied_indices = tuple(sorted(c[1] for c in candidates if c[0] == best_score))
                if len(tied_indices) >= 2:
                    match_keys_tuple = tuple(sorted(match.keys()))
                    source_tab_ties_raw.append((key, match_keys_tuple, tied_indices, _src_idx))

        total = 0.0
        hit_count = 0  # rows matching match + value_column
        match_hit_count = 0  # rows matching match only (before value_column filter)
        # Cross-product detection : ≥2 clés dont la valeur est une liste
        # non-vide → candidat pour collecter les samples matchés (voir en bas
        # de boucle). Évite la coût pour les cas simples (1 seule liste ou
        # que des scalaires).
        list_key_count = sum(1 for mv in match.values() if isinstance(mv, list) and len(mv) > 0)
        collect_samples = list_key_count >= 2
        samples: List[Dict[str, Any]] = []  # liste des sc_match matchés
        for sc_cell in sheet_content:
            if not isinstance(sc_cell, dict):
                continue
            sc_match = sc_cell.get("match")
            if not isinstance(sc_match, dict):
                continue
            all_match = True
            for mk, mv in match.items():
                # mv peut être scalaire (égalité) ou liste (IN)
                if not _emit_tab_match_value(sc_match.get(mk), mv):
                    all_match = False
                    break
            if not all_match:
                continue
            excluded = False
            for ek, evs in match_exclude.items():
                if _emit_tab_in_excluded(sc_match.get(ek), evs):
                    excluded = True
                    break
            if excluded:
                continue
            match_hit_count += 1
            if value_column and sc_cell.get("col") != value_column:
                continue
            val = sc_cell.get("value")
            # Chokepoint anonymisation : si la valeur est un token `§...§`
            # (l'utilisateur a anonymisé une valeur numérique via add_mapping),
            # désanonymise avant float(). Sinon WARNING explicite — plus de
            # silent drop. Cf. audit anon-leaks 2026-04-27.
            from app.services.anonymization.pseudonymizer import coerce_to_numeric as _coerce

            numeric_val = _coerce(
                val,
                pseudonymizer=pseudonymizer,
                context_hint=f"_recompute_emit_tab cell=({r},{c}) col={value_column!r}",
            )
            if numeric_val is None:
                continue
            val = numeric_val
            total += numeric_val
            hit_count += 1
            # Collecte un échantillon projeté sur les clés du match (pas
            # tout sc_match) pour que le LLM voie quelles valeurs de SES
            # clés ont matché. Cap à 10 pour couvrir les cas où les rows
            # "contaminantes" arrivent plus tard dans sheet_content.
            if collect_samples and len(samples) < 10:
                projected = {mk: sc_match.get(mk) for mk in match.keys()}
                projected["_value"] = val
                samples.append(projected)

        # [DEBUG TEMPORAIRE 2026-04-27] Trace par cellule des paramètres
        # effectifs au recompute. Le dump final strippe ``match_exclude``
        # et le SQL drilldown ne reflète pas toujours ce qui a été
        # SOMMÉ. Cette trace expose la vérité brute pour traquer les bugs
        # de divergence (cell value ≠ SUM attendue à partir du match).
        # À RETIRER une fois le bug "BILAN exclu sans raison" diagnostiqué.
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "emit_tab recompute trace cell=(%d,%d): match=%s match_exclude=%s "
                "value_column=%r source_tab=%s match_hits=%d value_hits=%d total=%.2f",
                r,
                c,
                match,
                match_exclude,
                value_column,
                source_tab_index_hint,
                match_hit_count,
                hit_count,
                total,
            )

        # Stocke le diagnostic cross-product pour les cellules à ≥2 clés-listes
        # AYANT matché du monde. hit_count=0 est déjà traité par no_source.
        if collect_samples and hit_count > 0:
            cross_product_raw.append((key, match, samples, hit_count))

        # Distinguish honest "no matching source" from "match matched but value_column
        # never aligned" — the latter is a likely LLM typo. Fail-closed: set None +
        # warn rather than silently trust the LLM number.
        if hit_count == 0:
            if match_hit_count > 0 and value_column:
                logger.warning(
                    "emit_tab recompute: cellule (%d,%d) match a trouvé %d lignes "
                    "mais aucune n'a value_column=%r. Vérifier la cohérence du "
                    "nom de colonne-mesure. Cellule mise à None (fail-closed).",
                    r,
                    c,
                    match_hit_count,
                    value_column,
                )
                rows[r][c] = None
                recomputed += 1
            else:
                no_source += 1
                no_source_raw.append((key, match, source_tab_index_hint))
            continue

        # Arrondi défensif : prévient les « 123456.78999999997 » d'accumulation float
        total = round(total, 6)

        llm_val = rows[r][c]
        needs_overwrite = False
        if llm_val is None or not isinstance(llm_val, (int, float)) or isinstance(llm_val, bool):
            needs_overwrite = True
        else:
            denom = abs(total) if abs(total) > 1e-9 else 1.0
            if abs(llm_val - total) / denom > 0.01:
                needs_overwrite = True

        if needs_overwrite:
            rows[r][c] = total
            recomputed += 1
        else:
            trusted += 1

    # Diagnose les no_source : groupe par signature de match (JSON) pour
    # dédupliquer (53 cellules avec {lfaCodeStatistique:'JURIDIQUE'} → 1 seul
    # hint avec affected_cells_count=53). Pour chaque groupe, appelle
    # _diagnose_no_source qui lit col_distinct et propose closest_values.
    # Pur diagnostic — ne bloque rien.
    no_source_hints: List[Dict[str, Any]] = []
    if no_source_raw:
        groups: Dict[str, Dict[str, Any]] = {}
        for cell_key, m, hint_idx in no_source_raw:
            # Signature strict : PAS de `default=str` — on ne veut pas qu'un
            # datetime coercé collisionne avec une vraie string de même repr
            # (L2 review adversariale). Les match values sont déjà validées
            # scalaires par _validate_emit_tab ; un type exotique hit le
            # fallback `__raw_{cell_key}` → pas de dédup forcée.
            try:
                sig = json.dumps(
                    {"m": m, "h": hint_idx},
                    sort_keys=True,
                )
            except (TypeError, ValueError):
                sig = f"__raw_{cell_key}"
            bucket = groups.get(sig)
            if bucket is None:
                groups[sig] = {
                    "match": m,
                    "source_tab_index_hint": hint_idx,
                    "cell_keys": [cell_key],
                }
            else:
                bucket["cell_keys"].append(cell_key)
        for bucket in groups.values():
            errs = _diagnose_no_source(
                bucket["match"],
                tabs_context,
                bucket["source_tab_index_hint"],
            )
            if not errs:
                continue  # rien d'actionnable pour ce groupe (truncated / type
                # incompatible / col_distinct absent) — pas de faux positif
            cell_keys = bucket["cell_keys"]
            hint: Dict[str, Any] = {
                "match": bucket["match"],
                "affected_cells_count": len(cell_keys),
                "affected_cell_keys": cell_keys[:5],
                "errors": errs,
            }
            no_source_hints.append(hint)
        no_source_hints.sort(
            key=lambda h: -h.get("affected_cells_count", 0),
        )
        # Cap : un tool_result LLM ne doit pas exploser. 20 groupes distincts
        # couvrent largement les cas réels (jsp: 1 seul groupe pour 53 cells).
        no_source_hints = no_source_hints[:20]

    # Cross-product samples : groupe par signature de match (même dédup que
    # no_source_hints). Expose pour chaque match à ≥2 list-keys distincts :
    # - hit_count : nombre de rows sommées (LLM compare avec son attente)
    # - samples : top 5 rows matchées (projection sur les clés du match)
    # Le LLM voit concrètement {(annee:2023, mois:10), ..., (annee:2024,
    # mois:10)} et réalise que (2024, 10) n'était pas voulu.
    cross_product_samples: List[Dict[str, Any]] = []
    if cross_product_raw:
        cp_groups: Dict[str, Dict[str, Any]] = {}
        for cell_key, m, cell_samples, hit_count in cross_product_raw:
            try:
                sig = json.dumps(m, sort_keys=True)
            except (TypeError, ValueError):
                sig = f"__raw_cp_{cell_key}"
            bucket = cp_groups.get(sig)
            if bucket is None:
                cp_groups[sig] = {
                    "match": m,
                    "samples": cell_samples,  # échantillon du 1er cell
                    "cell_keys": [cell_key],
                    "hit_count": hit_count,
                }
            else:
                bucket["cell_keys"].append(cell_key)
        for bucket in cp_groups.values():
            cross_product_samples.append(
                {
                    "match": bucket["match"],
                    "hit_count": bucket["hit_count"],
                    "affected_cells_count": len(bucket["cell_keys"]),
                    "affected_cell_keys": bucket["cell_keys"][:5],
                    "sample_matched_rows": bucket["samples"],
                }
            )
        # Trie par hit_count DESC (les plus volumineux d'abord = candidats
        # cross-product les plus probables).
        cross_product_samples.sort(
            key=lambda x: -x.get("hit_count", 0),
        )
        cross_product_samples = cross_product_samples[:20]

    # source_tab_ties : dédup par (match_keys_signature, tied_indices). Une
    # seule entrée agrège toutes les cellules qui utilisent les mêmes clés
    # de match et ont les mêmes candidats tied. Évite 85 warnings identiques.
    # On expose les INDICES uniquement — les labels sont récupérables via
    # list_tabs. Éviter la duplication d'un label (potentiellement sensible :
    # nom client, entité) dans plusieurs canaux de tool_result (F4 review).
    source_tab_ties: List[Dict[str, Any]] = []
    if source_tab_ties_raw:
        tie_groups: Dict[str, Dict[str, Any]] = {}
        for cell_key, mk_tuple, tied_indices, picked_idx in source_tab_ties_raw:
            sig = f"{mk_tuple!r}|{tied_indices!r}"
            bucket = tie_groups.get(sig)
            if bucket is None:
                tie_groups[sig] = {
                    "match_keys": list(mk_tuple),
                    "candidate_tab_indices": list(tied_indices),
                    "picked_tab_index": picked_idx,
                    "cell_keys": [cell_key],
                }
            else:
                bucket["cell_keys"].append(cell_key)
        for bucket in tie_groups.values():
            source_tab_ties.append(
                {
                    "match_keys": bucket["match_keys"],
                    "candidate_tab_indices": bucket["candidate_tab_indices"],
                    "picked_tab_index": bucket["picked_tab_index"],
                    "affected_cells_count": len(bucket["cell_keys"]),
                    # Aligné à 20 comme no_source_hints/match_samples — permet au
                    # LLM de cibler chirurgicalement les cellules affectées plutôt
                    # que de tout ré-émettre (F6 review).
                    "affected_cell_keys": bucket["cell_keys"][:20],
                }
            )
        source_tab_ties.sort(
            key=lambda t: -t.get("affected_cells_count", 0),
        )
        # Cap aligné avec no_source_hints / match_samples (F5 review).
        source_tab_ties = source_tab_ties[:20]

    parsed.setdefault("_recompute_metrics", {}).update(
        {
            "recomputed": recomputed,
            "trusted": trusted,
            "no_source": no_source,
            "no_source_hints": no_source_hints,
            "match_samples": cross_product_samples,
            "source_tab_ties": source_tab_ties,
        }
    )
    logger.info(
        "emit_tab recompute: %d recomputed, %d trusted, %d no-source, %d "
        "hint group(s), %d cross-product sample group(s), %d source-tab tie group(s)",
        recomputed,
        trusted,
        no_source,
        len(no_source_hints),
        len(cross_product_samples),
        len(source_tab_ties),
    )

    # Évaluation des derived_formula : exécuté APRÈS le recompute, donc une
    # formule peut référencer n'importe quelle cellule déjà remplie (par match,
    # rows_overrides, ou valeur littérale). Propage None si une ref est vide ;
    # divise par zéro → None (fail-closed, pas d'infini/NaN dans la grille).
    derived_evaluated, derived_none = _evaluate_derived_formulas(parsed)
    parsed["_recompute_metrics"]["derived_evaluated"] = derived_evaluated
    parsed["_recompute_metrics"]["derived_none"] = derived_none

    # Génération des SQL de drill-down pour chaque cellDetails.
    # Sans ça, les cellules ont cellDetails.sql = "" et l'utilisateur ne peut
    # pas cliquer pour voir les lignes sources (incident observé 2026-04-18).
    #
    # Deux passes :
    # 1. Cellules avec ``match`` → SQL composé via _build_drill_down_sql
    #    (CTE source + SELECT * WHERE (original) AND match).
    # 2. Cellules avec ``derived_formula`` → SQL UNION ALL des drill-downs
    #    des leaves terminales, avec colonnes d'annotation (__source_cell,
    #    __contribution) pour que l'utilisateur comprenne quelles lignes
    #    contribuent à quel composant de la formule.
    #
    # Les cellDetails qui n'aboutissent à AUCUN SQL drillable (match sans
    # source SQL, derived sans aucune leaf drillable, label seul, etc.) sont
    # laissés sans ``sql``. Le contrat UI côté frontend (``_cellHasRealDetail``
    # dans iris-grid.js) refusera alors d'afficher l'indicateur de drill-down.
    drill_count_match = 0
    drill_count_derived = 0
    for key, detail in cell_details.items():
        if not isinstance(detail, dict):
            continue
        if detail.get("sql"):
            continue  # SQL déjà fourni (via emit direct) — ne pas écraser
        if detail.get("derived_formula"):
            continue  # Traité dans la 2e passe
        match = detail.get("match")
        if not isinstance(match, dict) or not match:
            continue
        resolved = _resolve_source_sql_for_match(detail, tabs_context)
        if not resolved:
            continue
        source_sql, _source_cols = resolved
        match_exclude = detail.get("match_exclude") or {}
        drill_sql = _build_drill_down_sql(source_sql, match, match_exclude)
        if drill_sql:
            detail["sql"] = drill_sql
            drill_count_match += 1

    # 2e passe : cellules derived_formula. On tourne APRÈS la 1ère passe
    # exprès : comme ça si un test fournit des cellules match+derived
    # mélangées (interdit actuellement par le mutex, mais défensif), les
    # SQL match sont déjà posés et _collect_derived_leaves peut descendre.
    for key, detail in cell_details.items():
        if not isinstance(detail, dict):
            continue
        if detail.get("sql"):
            continue  # SQL déjà fourni (LLM direct) OU posé en 1ère passe
        if not detail.get("derived_formula"):
            continue
        drill_sql = _build_derived_drill_down_sql(cell_details, tabs_context, key)
        if drill_sql:
            detail["sql"] = drill_sql
            drill_count_derived += 1

    total_drill = drill_count_match + drill_count_derived
    if total_drill > 0:
        logger.info(
            "emit_tab : %d SQL drill-down générés (match=%d, derived=%d).",
            total_drill,
            drill_count_match,
            drill_count_derived,
        )
    metrics = parsed.setdefault("_recompute_metrics", {})
    metrics["drill_down_sql_generated"] = total_drill
    metrics["drill_down_sql_match"] = drill_count_match
    metrics["drill_down_sql_derived"] = drill_count_derived

    return parsed


# Motifs indiquant que l'utilisateur veut RÉUTILISER des valeurs déjà disponibles
# dans les autres feuilles plutôt que de les recalculer. Quand ces motifs matchent
# l'instruction ET que `value_source_tabs` est vide mais `source_tabs` non vide
# (cas où le LLM s'est trompé de champ), on utilise source_tabs comme fallback.
_REUSE_INTENT_RE = re.compile(
    r"\b("
    r"r[ée]utilis\w*"  # réutilise, reutilisant, …
    r"|repren\w+"  # reprends, reprenant, …
    r"|r[ée]cup[ée]r\w*"  # récupère, recuperer, …
    r"|recopi\w+"  # recopier, recopie, …
    r"|pioche\w*|piocher"
    r"|sinon\s+(vide|laiss\w+\s+vide)"
    r"|laiss\w+\s+vide"
    r"|ne\s+recalcul\w+"
    r"|sans\s+recalcul\w*"
    r"|ce\s+qu\S+on\s+a\s+d[ée]j[àa]"
    r"|valeurs?\s+d[ée]j[àa]"
    r"|valeurs?\s+(des?|dans\s+les)\s+autres"
    r"|autres?\s+(onglets?|feuilles?)"
    r")\b",
    re.IGNORECASE,
)


def _user_wants_reuse(instruction: str) -> bool:
    """Heuristique : l'instruction suggère-t-elle que l'utilisateur veut
    réutiliser des valeurs déjà présentes dans les autres feuilles ?"""
    if not instruction:
        return False
    return bool(_REUSE_INTENT_RE.search(instruction))


# Caps de sécurité : évite qu'un plan LLM malformé cause un DoS
# (évaluation combinatoire dans _resolve_cells_from_siblings).
_MAX_SUBSTITUTIONS = 100
_MAX_VALUE_SOURCE_TABS = 20
_MAX_EXCLUDES = 50
_MAX_EXCLUDE_VALUES = 100


def _clean_clone_sheet_fields(
    raw_plan: Dict[str, Any],
    tabs_context: Optional[List[Dict[str, Any]]],
    source_idx: int,
) -> Dict[str, Any]:
    """Validation + normalisation UNIQUE des champs variables de clone_sheet.

    Appelé depuis :
      - `_validate_plan` (chemin 2-call)
      - handler `clone_sheet` (chemin direct + chemin single-call fallback)

    Évite la duplication de règles entre les deux chemins (qui produisait des
    divergences silencieuses quand un seul des deux était modifié).

    Returns: dict avec clés toujours présentes, valeurs normalisées :
      substitutions (list), value_source_tabs (list[int]), new_tab (bool),
      excludes (list[{column, values}]).
    """
    max_tab_idx = (len(tabs_context) - 1) if tabs_context else -1

    # substitutions — liste de {old, new}, tronquée à _MAX_SUBSTITUTIONS
    subs_raw = raw_plan.get("substitutions", [])
    if not isinstance(subs_raw, list):
        subs_raw = []
    clean_subs: List[Dict[str, str]] = []
    for s in subs_raw[:_MAX_SUBSTITUTIONS]:
        if not isinstance(s, dict):
            continue
        old_v = s.get("old")
        new_v = s.get("new", "")
        if not isinstance(old_v, str) or not old_v.strip():
            continue
        if not isinstance(new_v, str):
            new_v = str(new_v)
        clean_subs.append({"old": old_v, "new": new_v})

    # value_source_tabs — indices valides ≠ source_idx
    vst_raw = raw_plan.get("value_source_tabs") or []
    if not isinstance(vst_raw, list):
        vst_raw = []
    value_src_tabs = [
        i
        for i in vst_raw[:_MAX_VALUE_SOURCE_TABS]
        if isinstance(i, int) and 0 <= i <= max_tab_idx and i != source_idx
    ]

    # new_tab — bool
    new_tab = bool(raw_plan.get("new_tab", False))

    # excludes — liste de {column: str, values: non-empty list[str]}
    excludes_raw = raw_plan.get("excludes") or []
    clean_excludes: List[Dict[str, Any]] = []
    if isinstance(excludes_raw, list):
        for ex in excludes_raw[:_MAX_EXCLUDES]:
            if not isinstance(ex, dict):
                continue
            col = ex.get("column")
            vals = ex.get("values")
            if not isinstance(col, str) or not col.strip():
                continue
            if not isinstance(vals, list) or not vals:
                continue
            clean_vals = [
                str(v) for v in vals[:_MAX_EXCLUDE_VALUES] if v is not None and str(v).strip()
            ]
            if not clean_vals:
                continue
            clean_excludes.append({"column": col.strip(), "values": clean_vals})

    # target_labels — facultatif, mais propagé si présent (pour le lookup)
    tl_raw = raw_plan.get("target_labels")
    target_labels: Dict[str, Any] = {}
    if isinstance(tl_raw, dict):
        for k in ("row_labels_col", "col_headers_row"):
            if k in tl_raw:
                target_labels[k] = tl_raw[k]

    return {
        "substitutions": clean_subs,
        "value_source_tabs": value_src_tabs,
        "new_tab": new_tab,
        "excludes": clean_excludes,
        "target_labels": target_labels,
    }


def _norm_text(val: Any) -> str:
    """Normalise un texte pour comparaison (lower, trim, espaces compactés)."""
    if val is None:
        return ""
    s = str(val).strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s


def _col_letter_to_index(col: str) -> int:
    """Convertit une lettre de colonne (A, B, ..., AA) en index 0-based. -1 si invalide."""
    if not isinstance(col, str) or not _COL_LETTER_RE.match(col):
        return -1
    idx = 0
    for ch in col:
        idx = idx * 26 + (ord(ch) - ord("A") + 1)
    return idx - 1


def _extract_labels(
    sheet: List[Dict[str, Any]],
    row_labels_col: Optional[str],
    col_headers_row: Optional[int],
) -> tuple[Dict[int, str], Dict[str, str]]:
    """Extrait les labels de ligne et les headers de colonne d'une feuille.

    - row_labels_col : lettre de colonne qui contient les labels de ligne (ex: "A").
    - col_headers_row : numéro 1-based de la ligne contenant les headers.

    Si les paramètres sont None, heuristique : première colonne contenant du texte
    non numérique pour les rows, première ligne contenant >=2 headers textuels pour
    les colonnes.

    Retourne (row_label_by_row, col_header_by_col).
    """
    if not sheet:
        return {}, {}

    # Indexer les cellules par (row, col) avec valeur non vide
    cells: Dict[tuple, str] = {}
    for c in sheet:
        val = c.get("value")
        if val is None or str(val).strip() == "":
            continue
        cells[(c.get("row"), c.get("col"))] = str(val).strip()

    def _is_numeric(val: str) -> bool:
        try:
            float(val)
            return True
        except (ValueError, TypeError):
            return False

    # --- Détecter row_labels_col ---
    # Une colonne est éligible comme "labels de ligne" si elle contient au moins une
    # valeur textuelle et aucune valeur numérique (sinon c'est probablement une
    # colonne de données). On choisit la colonne avec le PLUS de labels, tie-break
    # par ordre alphabétique (A avant B, etc.).
    if not row_labels_col:
        col_text_counts: Dict[str, int] = {}
        col_num_counts: Dict[str, int] = {}
        for (_r, c), v in cells.items():
            if not isinstance(c, str):
                continue
            if _is_numeric(v):
                col_num_counts[c] = col_num_counts.get(c, 0) + 1
            else:
                col_text_counts[c] = col_text_counts.get(c, 0) + 1
        eligible = [
            c for c, n in col_text_counts.items() if n >= 1 and col_num_counts.get(c, 0) == 0
        ]
        eligible.sort(key=lambda x: (-col_text_counts[x], len(x), x))
        row_labels_col = eligible[0] if eligible else None

    # --- Détecter col_headers_row ---
    if not col_headers_row:
        row_text_counts: Dict[int, int] = {}
        row_num_counts: Dict[int, int] = {}
        for (r, _c), v in cells.items():
            if not isinstance(r, int):
                continue
            if _is_numeric(v):
                row_num_counts[r] = row_num_counts.get(r, 0) + 1
            else:
                row_text_counts[r] = row_text_counts.get(r, 0) + 1
        eligible_rows = [
            r for r, n in row_text_counts.items() if n >= 1 and row_num_counts.get(r, 0) == 0
        ]
        # Priorité aux lignes avec le plus de headers, puis la ligne la plus haute
        eligible_rows.sort(key=lambda r: (-row_text_counts[r], r))
        col_headers_row = eligible_rows[0] if eligible_rows else None

    row_label_by_row: Dict[int, str] = {}
    col_header_by_col: Dict[str, str] = {}

    if row_labels_col:
        for (r, c), v in cells.items():
            if c == row_labels_col and isinstance(r, int):
                row_label_by_row[r] = v

    if col_headers_row:
        for (r, c), v in cells.items():
            if r == col_headers_row and isinstance(c, str):
                col_header_by_col[c] = v

    return row_label_by_row, col_header_by_col


def _cell_matches_excludes(cell: Dict[str, Any], excludes: List[Dict[str, Any]]) -> bool:
    """True si la cellule sœur doit être exclue d'après les règles ``excludes``.

    Pour chaque règle {column, values} :
    - Si ``cell['match']`` contient column → on compare la valeur stockée (case-
      insensitive, trim) à chaque value. Match = exclure.
    - Sinon (pas de match ou column absent) → fallback sur ``cell['label']`` :
      si le label contient (case-insensitive) une des values, on exclut.

    Les règles sont en OR : si UNE SEULE règle matche, la cellule est exclue.
    """
    if not excludes:
        return False
    cell_match = cell.get("match") if isinstance(cell, dict) else None
    cell_label = _norm_text(cell.get("label", "") if isinstance(cell, dict) else "")
    for rule in excludes:
        if not isinstance(rule, dict):
            continue
        col = rule.get("column")
        vals = rule.get("values") or []
        norm_vals = [_norm_text(v) for v in vals if v is not None]
        norm_vals = [nv for nv in norm_vals if nv]
        if not col or not norm_vals:
            continue
        # Path 1 : match sémantique disponible ET la valeur stockée est renseignée.
        # Si match[col] est None/"", on considère qu'il n'y a pas d'info utile sur
        # cette colonne pour cette cellule → on passe au fallback label plutôt que
        # de skipper (évite un faux négatif silencieux sur cellule semi-structurée).
        if isinstance(cell_match, dict) and col in cell_match:
            norm_cell_val = _norm_text(cell_match[col])
            if norm_cell_val:
                if norm_cell_val in norm_vals:
                    return True
                # Column renseigné mais valeur ≠ exclusions — cette règle ne
                # matche pas, on passe à la suivante (on NE fait PAS le fallback
                # label ici pour éviter les faux positifs).
                continue
            # match[col] vide → on tombe sur le fallback label ci-dessous
        # Path 2 : fallback label textuel
        if cell_label:
            for nv in norm_vals:
                if nv in cell_label:
                    return True
    return False


def _resolve_cells_from_siblings(
    sheet_content: List[Dict[str, Any]],
    tabs_context: List[Dict[str, Any]],
    source_tabs: List[int],
    target_labels_cfg: Dict[str, Any],
    excludes: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Lookup multi-feuilles : pour chaque cellule (row, col) au croisement d'un
    label de ligne et d'un header de colonne de la feuille active, cherche une
    cellule équivalente dans les feuilles sœurs listées.

    Utilisé par le handler ``clone_sheet`` quand la réponse LLM contient un
    champ ``value_source_tabs`` (= onglets dans lesquels piocher les valeurs
    pour les cellules numériques). Aucune requête SQL n'est exécutée.

    Quand ``excludes`` est fourni (liste de {column, values}), les cellules
    sœurs qui matchent les règles d'exclusion sont ignorées — le lookup
    cherche alors la cellule suivante (ou laisse vide si aucune ne passe).

    Stratégie de matching (dans l'ordre) :
    1. Sœur a exactement la même coordonnée (row, col) avec un label/header
       compatible → copie la valeur.
    2. Sœur a une cellule dont `label` contient les deux (row_label, col_header)
       de la cible, case-insensitive → copie la valeur.
    3. Sœur a une cellule dont (row_label_sibling, col_header_sibling) ==
       (row_label_target, col_header_target) → copie la valeur.

    Retourne une liste de dicts {row, col, value?, label?, match?, source_tab?}.
    Les cellules sans correspondance ont value=None.
    """
    # Cible : labels + headers
    row_labels_col = target_labels_cfg.get("row_labels_col") if target_labels_cfg else None
    col_headers_row = target_labels_cfg.get("col_headers_row") if target_labels_cfg else None

    target_rows, target_cols = _extract_labels(
        sheet_content,
        row_labels_col,
        col_headers_row,
    )

    # Positions déjà remplies dans la cible → ne pas écraser
    filled_positions: set = set()
    for c in sheet_content:
        val = c.get("value")
        if val is not None and str(val).strip():
            filled_positions.add((c.get("row"), c.get("col")))

    # Pas de labels → on ne peut rien faire
    if not target_rows or not target_cols:
        return []

    # Pré-indexer chaque feuille source :
    #  - sibling_indices : mapping (norm(row_label), norm(col_header)) → cellule sœur
    #  - coord_indices : mapping (row, col) → cellule sœur (pour lookup par coordonnée)
    #  - label_indices : liste de (cellule, label_normalisé) pour lookup par label textuel
    sibling_indices: Dict[int, Dict[tuple, tuple]] = {}
    coord_indices: Dict[int, Dict[tuple, dict]] = {}
    label_indices: Dict[int, List[tuple]] = {}

    for tab_idx in source_tabs:
        if tab_idx < 0 or tab_idx >= len(tabs_context):
            continue
        tab = tabs_context[tab_idx]
        tab_label = tab.get("label", f"Onglet {tab_idx + 1}")
        sib_cells = tab.get("sheet_content") or []
        if not sib_cells:
            continue
        sib_rows, sib_cols = _extract_labels(sib_cells, None, None)
        idx_label: Dict[tuple, tuple] = {}
        idx_coord: Dict[tuple, dict] = {}
        idx_by_label_text: List[tuple] = []

        for c in sib_cells:
            r, col = c.get("row"), c.get("col")
            val = c.get("value")
            idx_coord[(r, col)] = c

            # Skip empty values early
            if val is None or str(val).strip() == "":
                continue

            # Entrée "par label textuel" — utile quand les coords sœur ne matchent pas
            # la structure cible mais que la cellule porte un label descriptif.
            c_label = c.get("label")
            if c_label:
                idx_by_label_text.append((_norm_text(c_label), c, tab_label))

            # Indexation par (row_label, col_header) — nécessite que la cellule
            # soit AU CROISEMENT d'un row labellisé et d'une col headerisée, et
            # qu'elle ne soit PAS elle-même un label/header (sinon une cellule de
            # type "Exercice 2024" ne devrait pas apparaître comme valeur).
            # ATTENTION : historiquement la condition était `r not in sib_rows` (bug
            # inversé) qui rendait cet index toujours vide — silencieusement désactivant
            # le lookup le plus précis.
            row_lab = sib_rows.get(r)
            col_hdr = sib_cols.get(col)
            is_own_label = row_lab is not None and _norm_text(val) == _norm_text(row_lab)
            is_own_header = col_hdr is not None and _norm_text(val) == _norm_text(col_hdr)
            if row_lab and col_hdr and not is_own_label and not is_own_header:
                key = (_norm_text(row_lab), _norm_text(col_hdr))
                if key not in idx_label:
                    idx_label[key] = (val, c, tab_label)

            # Indexation via le `match` sémantique de la cellule, si présent
            c_match = c.get("match")
            if isinstance(c_match, dict) and c_match:
                # Pour chaque paire (row_lab, col_hdr) qu'on pourrait déduire du match,
                # on laisse le lookup principal se faire via label — idx_by_label_text
                # est souvent plus riche.
                pass

        sibling_indices[tab_idx] = idx_label
        coord_indices[tab_idx] = idx_coord
        label_indices[tab_idx] = idx_by_label_text

    results: List[Dict[str, Any]] = []
    for target_row, row_lab in target_rows.items():
        for target_col, col_hdr in target_cols.items():
            if (target_row, target_col) in filled_positions:
                continue
            # La cellule (target_row, target_col) est-elle au croisement ligne-label / col-header ?
            # On ignore si target_col == row_labels_col (c'est la colonne des labels)
            if target_col == row_labels_col:
                continue
            if target_row == col_headers_row:
                continue

            n_row = _norm_text(row_lab)
            n_col = _norm_text(col_hdr)
            key = (n_row, n_col)
            found_value = None
            found_source = None
            found_label = None
            found_match = None

            # 1. Lookup par (row_label, col_header) parfaitement aligné
            for tab_idx in source_tabs:
                idx = sibling_indices.get(tab_idx)
                if not idx:
                    continue
                if key in idx:
                    val, cell_dict, tab_label = idx[key]
                    if val is not None and str(val).strip():
                        # Appliquer les exclusions métier (ex: "sauf FN, SOCIAL")
                        if excludes and _cell_matches_excludes(cell_dict, excludes):
                            continue
                        found_value = val
                        found_source = tab_label
                        found_label = cell_dict.get("label")
                        found_match = cell_dict.get("match")
                        break

            # 2. Lookup par label de cellule : la sœur a une cellule dont le label
            #    textuel contient à la fois row_label et col_header (ordre libre).
            if found_value is None and n_row and n_col:
                for tab_idx in source_tabs:
                    idx_labels = label_indices.get(tab_idx) or []
                    best = None  # (cellule, tab_label)
                    for norm_lab, cell, tab_label in idx_labels:
                        if not norm_lab:
                            continue
                        if n_row in norm_lab and n_col in norm_lab:
                            if excludes and _cell_matches_excludes(cell, excludes):
                                continue
                            best = (cell, tab_label)
                            break
                    if best:
                        cell, tab_label = best
                        val = cell.get("value")
                        if val is not None and str(val).strip():
                            found_value = val
                            found_source = tab_label
                            found_label = cell.get("label")
                            found_match = cell.get("match")
                            break

            # 3. Fallback : coordonnée identique avec sanity check sur le label
            if found_value is None:
                for tab_idx in source_tabs:
                    idx = coord_indices.get(tab_idx)
                    if not idx:
                        continue
                    cell = idx.get((target_row, target_col))
                    if not cell:
                        continue
                    val = cell.get("value")
                    if val is None or not str(val).strip():
                        continue
                    # Sanity check : si on a un label cellule, il doit mentionner le row_lab ou col_hdr
                    c_label = _norm_text(cell.get("label", ""))
                    if c_label:
                        if n_row not in c_label and n_col not in c_label:
                            continue
                    # Exclusions métier
                    if excludes and _cell_matches_excludes(cell, excludes):
                        continue
                    found_value = val
                    found_source = tabs_context[tab_idx].get("label", f"Onglet {tab_idx + 1}")
                    found_label = cell.get("label")
                    found_match = cell.get("match")
                    break

            results.append(
                {
                    "row": target_row,
                    "col": target_col,
                    "value": found_value,
                    "label": found_label or f"{row_lab} · {col_hdr}",
                    "match": found_match,
                    "source_tab": found_source,
                }
            )

    return results


def _parse_llm_response(content: str) -> Optional[Dict[str, Any]]:
    """Parse la réponse JSON du LLM.

    Gère : texte pur JSON, JSON dans des fences markdown, et le cas où
    le LLM se corrige (2 blocs JSON — on prend le dernier valide).
    """
    text = content.strip()
    # Retirer les fences markdown
    text = re.sub(r"```(?:json)?\s*\n?", "", text).strip()

    # Fast path : tout le texte est du JSON valide
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # Extraire TOUS les blocs JSON {...} de haut niveau
    # (respecte l'imbrication des accolades et les chaînes entre guillemets)
    candidates = _extract_json_blocks(text)
    if not candidates:
        return None

    # Préférer le DERNIER bloc avec un type reconnu
    # (quand le LLM se corrige, la dernière version est la bonne)
    for c in reversed(candidates):
        if c.get("type") in _VALID_RESPONSE_TYPES:
            return c

    # Fallback : dernier bloc valide
    return candidates[-1]


def _extract_json_blocks(text: str) -> list[dict]:
    """Extraire tous les objets JSON de haut niveau d'un texte."""
    blocks = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "{":
            depth = 0
            start = i
            in_string = False
            escape_next = False
            while i < n:
                ch = text[i]
                if escape_next:
                    escape_next = False
                elif ch == "\\" and in_string:
                    escape_next = True
                elif ch == '"' and not escape_next:
                    in_string = not in_string
                elif not in_string:
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            try:
                                parsed = json.loads(text[start : i + 1])
                                if isinstance(parsed, dict):
                                    blocks.append(parsed)
                            except json.JSONDecodeError:
                                pass
                            break
                i += 1
        i += 1
    return blocks



def _validate_plan(
    plan: Optional[Dict[str, Any]], tabs_context: Optional[List]
) -> Optional[Dict[str, Any]]:
    """Validate plan from Call 1. Returns cleaned plan or None (triggers single-call fallback)."""
    if not plan or not isinstance(plan, dict):
        return None

    plan_type = plan.get("plan_type") or plan.get("type", "")
    if plan_type not in _VALID_RESPONSE_TYPES:
        logger.warning("Plan validation: unknown plan_type=%r", plan_type)
        return None

    # Normalize: ensure we use plan_type consistently
    validated = {
        "plan_type": plan_type,
        "description": plan.get("description", ""),
        "needs_schema": bool(plan.get("needs_schema", False)),
        "source_tabs": [],
    }

    # Validate source_tabs indices
    max_idx = len(tabs_context) - 1 if tabs_context else -1
    raw_tabs = plan.get("source_tabs", [])
    if isinstance(raw_tabs, list):
        validated["source_tabs"] = [i for i in raw_tabs if isinstance(i, int) and 0 <= i <= max_idx]

    # clone_sheet: validate source_tab_index puis déléguer la normalisation
    # des champs variables à _clean_clone_sheet_fields (source unique, partagée
    # avec le handler pour éviter toute divergence silencieuse).
    if plan_type == "clone_sheet":
        if not tabs_context:
            logger.warning("Plan validation: clone_sheet without tabs_context")
            return None
        src_idx = plan.get("source_tab_index")
        if not isinstance(src_idx, int) or src_idx < 0 or src_idx > max_idx:
            logger.warning(
                "Plan validation: invalid source_tab_index=%r (max=%d)", src_idx, max_idx
            )
            return None
        validated["source_tab_index"] = src_idx
        cleaned = _clean_clone_sheet_fields(plan, tabs_context, src_idx)
        validated.update(cleaned)

    # display: pass through actions
    if plan_type == "display":
        actions = plan.get("actions")
        if not actions or not isinstance(actions, list):
            logger.warning("Plan validation: display plan without actions")
            return None
        validated["actions"] = actions

    # emit_tab peut arriver :
    # - (direct path) plan complet avec `tab` → on préserve pour le dispatch
    # - (2-call path) plan metadata seulement → Call 2 produira le tab
    if plan_type == "emit_tab":
        if "tab" in plan:
            validated["tab"] = plan["tab"]
        validated["new_tab"] = plan.get("new_tab", True)

    return validated


def _build_planning_context(
    instruction: str,
    sql: str,
    columns: Optional[List[str]],
    tabs_context: Optional[List[Dict[str, Any]]],
    sheet_content: Optional[List[Dict[str, Any]]],
    sheet_context: Optional[Dict[str, Any]] = None,
) -> str:
    """Build lightweight user prompt for Call 1 (planning).

    Includes: instruction, tab summaries, active sheet cells (structured JSON).
    Much smaller than full context — typically 2-5K tokens.
    """
    parts = []

    # Tab summaries (lightweight: label, row_count, columns, SQL snippet)
    if tabs_context and len(tabs_context) > 1:
        tab_lines = []
        for i, tab in enumerate(tabs_context):
            tab_sql = tab.get("sql", "")
            label = tab.get("label", f"Onglet {i + 1}")
            row_count = tab.get("row_count", 0)
            is_active = tab.get("is_active", False)
            marker = " **(actif)**" if is_active else ""
            cols = tab.get("columns", [])
            cols_str = ", ".join(cols[:10])
            if len(cols) > 10:
                cols_str += f" (+{len(cols) - 10})"
            line = f"- [{i}] {label} ({row_count} lignes){marker}"
            if cols_str:
                line += f"\n  Colonnes : {cols_str}"
            if tab_sql:
                snippet = tab_sql[:200].replace("\n", " ")
                if len(tab_sql) > 200:
                    snippet += "..."
                line += f"\n  SQL : `{snippet}`"
            # Sibling sheet content (JSON summary)
            sibling = tab.get("sheet_content")
            if not is_active and not tab_sql and sibling:
                sib_json = _build_structured_sheet_json(sibling)
                if sib_json:
                    line += f"\n  Contenu :\n```json\n{sib_json}\n```"
            tab_lines.append(line)
        parts.append("## Onglets ouverts\n" + "\n\n".join(tab_lines))
    elif sql:
        parts.append(f"## Requête SQL actuelle\n```sql\n{sql}\n```")
        if columns:
            parts.append(f"Colonnes : {', '.join(columns)}")

    # Active sheet cells (structured JSON — same format as fill_sql output)
    if sheet_content:
        sheet_json = _build_structured_sheet_json(sheet_content)
        if sheet_json:
            parts.append(f"## Cellules existantes (feuille active)\n```json\n{sheet_json}\n```")

    # If FILL_SINGLE_CELL_ONLY, add explicit constraint
    if sheet_context and sheet_context.get("operation") == "FILL_SINGLE_CELL_ONLY":
        target_col = sheet_context.get("target_cell", {}).get("col", "?")
        parts.append(
            f"## CONTEXTE : Cellule unique\n"
            f"L'utilisateur remplit UNE SEULE CELLULE : **{target_col}**\n"
            f"Réponse requise : **type 'cell'** avec `sql` (requête agrégée "
            f"retournant 1 valeur) et optionnellement `detail_sql`.\n"
            f"Ne réponds JAMAIS avec fill_sql, fill_plan ou multi."
        )

    parts.append(f"## Instruction de l'utilisateur\n{instruction}")

    return "\n\n".join(parts)


def _build_execution_context(
    plan: Dict[str, Any],
    instruction: str,
    sql: str,
    columns: Optional[List[str]],
    display_state: Optional[Dict[str, Any]],
    tabs_context: Optional[List[Dict[str, Any]]],
    sheet_content: Optional[List[Dict[str, Any]]],
    schema_context: str,
    analysis_prompt: str,
    distinct_values: Optional[Dict[str, List[str]]],
    sheet_context: Optional[Dict[str, Any]] = None,
) -> Tuple[str, Optional[str]]:
    """Build targeted user prompt for Call 2 (execution) based on plan.

    Only includes context that the plan says it needs (relevant tabs, schema).
    Returns (user_prompt, cache_prefix_or_none).
    """
    source_tabs = plan.get("source_tabs", [])
    needs_schema = plan.get("needs_schema", False)

    stable_parts = []
    dynamic_parts = []

    # Plan summary for the executor
    plan_json = json.dumps(plan, ensure_ascii=False, indent=None)
    dynamic_parts.append(f"## Plan (déterminé à l'étape précédente)\n```json\n{plan_json}\n```")

    # Tab context — tabs référencés par le plan PLUS l'onglet actif en metadata
    # seulement (label + row_count + columns, sans sheet_content qui est déjà
    # en top-level). Inclure l'actif est essentiel pour que le LLM connaisse son
    # index et puisse écrire clone_structure_from correctement — sans ça il
    # pattern-match sur des noms de tabs similaires et se trompe de source.
    if tabs_context:
        included_indices = set(source_tabs)
        active_idx = -1
        for i, tab in enumerate(tabs_context):
            if tab.get("is_active"):
                active_idx = i
                break
        # On garde l'actif dans la liste (pour son index + métadata) ;
        # le sheet_content sera skippé plus bas via le check is_active.
        if active_idx >= 0:
            included_indices.add(active_idx)

        if len(tabs_context) > 1:
            tab_parts = []
            for i, tab in enumerate(tabs_context):
                if i not in included_indices:
                    continue
                tab_sql = tab.get("sql", "")
                tab_label = tab.get("label", f"Onglet {i + 1}")
                tab_cols = tab.get("columns", [])
                row_count = tab.get("row_count", 0)
                is_active = tab.get("is_active", False)
                # Marqueur visible avec INDEX explicite — le LLM doit pouvoir
                # référencer `clone_structure_from: N` sans deviner.
                marker = (
                    " **(onglet actif — contenu détaillé dans 'Cellules existantes')**"
                    if is_active
                    else ""
                )
                entry = f"### [index={i}] {tab_label} ({row_count} lignes){marker}"
                if tab_cols and tab_sql:
                    entry += f"\nColonnes : {', '.join(tab_cols)}"
                if tab_sql:
                    entry += f"\n```sql\n{tab_sql}\n```"
                # col_distinct (full vocab for included tabs)
                col_distinct = tab.get("col_distinct")
                if col_distinct and isinstance(col_distinct, dict):
                    lines = []
                    for col_name, info in col_distinct.items():
                        if not isinstance(info, dict):
                            continue
                        if info.get("type") == "numeric":
                            lines.append(
                                f"{col_name}: {info['distinct']} valeurs numériques "
                                f"(min={info['min']}, max={info['max']})"
                            )
                        else:
                            vals = info.get("values", [])
                            vals_str = ", ".join(str(v) for v in vals)
                            suffix = ""
                            if info.get("truncated"):
                                suffix = f" (+{info['distinct'] - len(vals)} autres)"
                            lines.append(f"{col_name}: {vals_str}{suffix}")
                    if lines:
                        entry += "\n**Aperçu** :\n" + "\n".join(lines)
                # Fallback: sample_rows if col_distinct absent
                sample = tab.get("sample_rows")
                if not col_distinct and sample and isinstance(sample, list) and len(sample) > 0:
                    first = sample[0]
                    if isinstance(first, dict):
                        keys = list(first.keys())[:8]
                        hdr = " | ".join(keys)
                        rows_lines = [
                            " | ".join(
                                str(row.get(k, ""))[:20] if row.get(k) is not None else ""
                                for k in keys
                            )
                            for row in sample
                        ]
                        entry += f"\n**Aperçu** :\n{hdr}\n" + "\n".join(rows_lines)
                # Sibling sheet content — inclut aussi les onglets SQL (rows
                # aplaties avec match dans _getTabsContext côté frontend), pour que
                # Call 2 puisse générer emit_tab.cellDetails[R,C].match correctement.
                # Échantillonné à 300 cells max par onglet pour tenir dans le budget
                # prompt — le recompute backend utilise la version complète.
                sibling = tab.get("sheet_content")
                if not is_active and sibling:
                    sib_sample = _truncate_sheet_content_for_llm(sibling, max_cells=300)
                    sib_json = _build_structured_sheet_json(sib_sample)
                    if sib_json:
                        entry += f"\n```json\n{sib_json}\n```"
                tab_parts.append(entry)

            if distinct_values:
                dv_lines = []
                for col_name, values in distinct_values.items():
                    vals_str = ", ".join(f"'{v}'" for v in values[:15])
                    dv_lines.append(f"- **{col_name}** : [{vals_str}]")
                tab_parts.append(
                    "### Valeurs distinctes des colonnes de dimension\n" + "\n".join(dv_lines)
                )

            stable_parts.append("## Onglets ouverts\n" + "\n\n".join(tab_parts))
        else:
            if sql:
                stable_parts.append(f"## Requête SQL actuelle\n```sql\n{sql}\n```")
                if columns:
                    stable_parts.append(f"## Colonnes du résultat\n{', '.join(columns)}")

    # Structural analysis
    if analysis_prompt:
        dynamic_parts.append(analysis_prompt)

    # Active sheet cells
    if sheet_content:
        active_json = _build_structured_sheet_json(sheet_content)
        if active_json:
            dynamic_parts.append(
                f"## Cellules existantes (feuille active)\n```json\n{active_json}\n```"
            )

    # Display state
    if display_state:
        hidden = display_state.get("hiddenCols", [])
        if hidden:
            dynamic_parts.append(f"## Colonnes masquées\n{hidden}")
        sort_col = display_state.get("sortColIndex", -1)
        sort_dir = display_state.get("sortDirection")
        if sort_col >= 0 and sort_dir and columns and sort_col < len(columns):
            dynamic_parts.append(f"## Tri actuel\n{columns[sort_col]} {sort_dir}")

    # Schema (only if plan says it's needed)
    if needs_schema and schema_context:
        stable_parts.append(f"## Schéma des tables\n{schema_context}")

    # Original instruction
    dynamic_parts.append(f"## Instruction de l'utilisateur\n{instruction}")

    # If FILL_SINGLE_CELL_ONLY, add explicit constraint
    if sheet_context and sheet_context.get("operation") == "FILL_SINGLE_CELL_ONLY":
        target_col = sheet_context.get("target_cell", {}).get("col", "?")
        dynamic_parts.append(
            f"## CONTEXTE : Cellule unique\n"
            f"L'utilisateur remplit UNE SEULE CELLULE : **{target_col}**\n"
            f"Réponse requise : **type 'cell'** avec `sql` (requête agrégée "
            f"retournant 1 valeur) et optionnellement `detail_sql`.\n"
            f"Ne réponds JAMAIS avec fill_sql, fill_plan ou multi."
        )

    cache_prefix = "\n\n".join(stable_parts) if stable_parts else None
    user_prompt = "\n\n".join(dynamic_parts)

    return user_prompt, cache_prefix


async def modify_result(
    sql: str,
    instruction: str,
    columns: Optional[List[str]] = None,
    display_state: Optional[Dict[str, Any]] = None,
    tabs_context: Optional[List[Dict[str, Any]]] = None,
    sheet_content: Optional[List[Dict[str, Any]]] = None,
    is_auto_fill: bool = False,
    sheet_context: Optional[Dict[str, Any]] = None,
    user_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Modifie un résultat SQL selon l'instruction utilisateur.

    Args:
        user_id: Identifiant de l'utilisateur qui déclenche la modification.
            Utilisé pour injecter un bloc "À propos de l'utilisateur"
            (strictement factuel, informatif) dans les prompts LLM.
            ``None`` (caller interne ou tests) → bloc profil absent.

    Returns:
        Dict avec type, description, et soit sql+columns+rows (sql),
        soit actions (display).
    """
    t_start = time.monotonic()  # B6: wall-clock timing

    # Mesure du temps pour ensure_providers_from_db
    t_ensure_start = time.monotonic()
    await ensure_providers_from_db()
    t_ensure_end = time.monotonic()
    logger.debug("ensure_providers_from_db took %.3fs", t_ensure_end - t_ensure_start)

    # Profil utilisateur structuré pour injection dans les prompts LLM. Fail-
    # safe : ``None`` si user introuvable ou BDD KO → pas de bloc, pas
    # d'interruption du service.
    from app.services.ai.user_context import (
        build_user_profile,
        render_user_context_block,
    )

    user_profile = await build_user_profile(user_id)
    user_context_block = render_user_context_block(user_profile)

    def _with_user_block(system_prompt: str) -> str:
        """Helper local : suffixe le ``user_context_block`` sur un system
        prompt si non-vide. Factorise 5 copies du même pattern.
        """
        if user_context_block:
            return system_prompt + "\n\n" + user_context_block
        return system_prompt

    # Déduplication : éviter les appels LLM identiques en boucle (B1 fix)
    if _dedup_check(instruction, sheet_content):
        logger.debug("Dedup: identical request skipped (instruction=%s)", instruction[:80])
        return {"cells": [], "skipped": True}

    # Extraire tables de TOUS les onglets pour le schéma
    all_table_names = set(_extract_table_names(sql))
    if tabs_context:
        for tab in tabs_context:
            tab_sql = tab.get("sql", "")
            if tab_sql:
                all_table_names.update(_extract_table_names(tab_sql))

    # B3 fix : skip DDL pour auto-fill quand le SQL source est déjà dans le contexte.
    # Le LLM a déjà les tables/colonnes via les requêtes SQL des onglets —
    # le DDL brut est redondant et coûte ~8-10K tokens par appel.
    has_sql_context = tabs_context and any(tab.get("sql") for tab in tabs_context)
    if is_auto_fill and has_sql_context:
        schema_context = ""
    else:
        t_schema_start = time.monotonic()
        # Phase α.4 — propager user_id.
        schema_context = await _get_schema_context(sorted(all_table_names), user_id=user_id)
        t_schema_end = time.monotonic()
        logger.debug("_get_schema_context took %.3fs", t_schema_end - t_schema_start)

    # Récupérer les valeurs distinctes des colonnes de dimension (E0e)
    # Pour auto-fill : les sample_rows contiennent les vraies valeurs.
    # Les distinct_values du training store peuvent être obfusquées
    # (obfusquées/tronquées) et induire le LLM en erreur.
    distinct_values = (
        None if is_auto_fill else await _get_distinct_values(tabs_context, user_id=user_id)
    )

    # Analyse structurelle — uniquement pour les instructions manuelles.
    # L'auto-fill n'utilise PAS l'analyzer : le LLM voit la grille et décide seul.
    sheet_analysis: Optional[SheetAnalysis] = None
    analysis_prompt = ""
    if not is_auto_fill:
        active_tab_label = None
        if tabs_context:
            for tab in tabs_context:
                if tab.get("is_active"):
                    active_tab_label = tab.get("label")
                    break
        if sheet_content:
            sheet_analysis = analyze_sheet(
                sheet_content, tabs_context, active_tab_label, distinct_values
            )
            if sheet_analysis and sheet_analysis.confidence >= 0.5:
                analysis_prompt = format_analysis_for_prompt(sheet_analysis)

    # Construire le prompt utilisateur
    user_parts = []

    # Contexte multi-onglets (SQL + valeurs distinctes de chaque onglet)
    if tabs_context and len(tabs_context) > 1:
        tab_parts = []
        for i, tab in enumerate(tabs_context):
            tab_sql = tab.get("sql", "")
            tab_label = tab.get("label", f"Onglet {i + 1}")
            tab_cols = tab.get("columns", [])
            row_count = tab.get("row_count", 0)
            is_active = tab.get("is_active", False)
            marker = (
                " **(onglet actif — celui que l'utilisateur veut modifier)**" if is_active else ""
            )
            entry = f"### {tab_label} ({row_count} lignes){marker}"
            if tab_cols and tab_sql:
                entry += f"\nColonnes : {', '.join(tab_cols)}"
            if tab_sql:
                entry += f"\n```sql\n{tab_sql}\n```"
            # Distinct values per column — vocabulaire complet pour le LLM
            col_distinct = tab.get("col_distinct")
            if col_distinct and isinstance(col_distinct, dict):
                lines = []
                for col_name, info in col_distinct.items():
                    if not isinstance(info, dict):
                        continue
                    if info.get("type") == "numeric":
                        lines.append(
                            f"{col_name}: {info['distinct']} valeurs numériques "
                            f"(min={info['min']}, max={info['max']})"
                        )
                    else:
                        vals = info.get("values", [])
                        vals_str = ", ".join(str(v) for v in vals)
                        suffix = ""
                        if info.get("truncated"):
                            suffix = f" (+{info['distinct'] - len(vals)} autres)"
                        lines.append(f"{col_name}: {vals_str}{suffix}")
                if lines:
                    entry += "\n**Aperçu** :\n" + "\n".join(lines)
            # Fallback: ancien format sample_rows si col_distinct absent
            sample = tab.get("sample_rows")
            if not col_distinct and sample and isinstance(sample, list) and len(sample) > 0:
                first = sample[0]
                if isinstance(first, dict):
                    keys = list(first.keys())[:8]
                    hdr = " | ".join(keys)
                    rows_lines = [
                        " | ".join(
                            str(row.get(k, ""))[:20] if row.get(k) is not None else "" for k in keys
                        )
                        for row in sample
                    ]
                    entry += f"\n**Aperçu** :\n{hdr}\n" + "\n".join(rows_lines)
            # Feuilles sœurs : même format JSON que la feuille active
            sibling = tab.get("sheet_content")
            if not is_active and not tab_sql and sibling:
                sib_json = _build_structured_sheet_json(sibling)
                if sib_json:
                    entry += f"\n```json\n{sib_json}\n```"
            tab_parts.append(entry)

        # Ajouter les valeurs distinctes des colonnes de dimension
        if distinct_values:
            dv_lines = []
            for col_name, values in distinct_values.items():
                vals_str = ", ".join(f"'{v}'" for v in values[:15])
                dv_lines.append(f"- **{col_name}** : [{vals_str}]")
            tab_parts.append(
                "### Valeurs distinctes des colonnes de dimension\n" + "\n".join(dv_lines)
            )

        user_parts.append("## Onglets ouverts\n" + "\n\n".join(tab_parts))
    else:
        if sql:
            user_parts.append(f"## Requête SQL actuelle\n```sql\n{sql}\n```")
            if columns:
                user_parts.append(f"## Colonnes du résultat\n{', '.join(columns)}")
        else:
            user_parts.append(
                "## Onglet actif — Feuille construite manuellement (pas de SQL)\n"
                'Pour type "sql", utilise toujours `new_tab: true` (ne pas écraser le contenu).'
            )

    # Analyse structurelle (si disponible)
    if analysis_prompt:
        user_parts.append(analysis_prompt)

    # Feuille active — même format JSON structuré que fill_sql
    if sheet_content and not is_auto_fill:
        active_json = _build_structured_sheet_json(sheet_content)
        if active_json:
            user_parts.append(
                f"## Cellules existantes (feuille active)\n```json\n{active_json}\n```"
            )

    if display_state:
        hidden = display_state.get("hiddenCols", [])
        if hidden:
            user_parts.append(f"## Colonnes masquées\n{hidden}")
        sort_col = display_state.get("sortColIndex", -1)
        sort_dir = display_state.get("sortDirection")
        if sort_col >= 0 and sort_dir and columns and sort_col < len(columns):
            user_parts.append(f"## Tri actuel\n{columns[sort_col]} {sort_dir}")

    if schema_context:
        user_parts.append(f"## Schéma des tables\n{schema_context}")

    # E0c: instruction auto-fill ou manuelle
    plan = None  # Défini dans le else (2-call), mais référencé après les deux branches
    if is_auto_fill:
        filled_count = len([c for c in (sheet_content or []) if c.get("value")])
        if filled_count < 1:
            logger.debug("Auto-fill: <2 cellules, skipping")
            return {"cells": [], "skipped": True}

        # Séparer le contexte en partie stable (cacheable) et dynamique
        # Stable : SQL tabs, sœurs, schéma — ne change pas entre les triggers
        # Dynamique : grille, cellules vides — change à chaque édition
        stable_parts = []
        dynamic_parts = []
        hit_dynamic = False
        for part in user_parts:
            if not hit_dynamic and ("Feuille active" in part or "Cellules vides" in part):
                hit_dynamic = True
            if hit_dynamic:
                dynamic_parts.append(part)
            else:
                stable_parts.append(part)

        cache_prefix = "\n\n".join(stable_parts) if stable_parts else None
        dynamic_context = "\n\n".join(dynamic_parts)

        # OPTIMISATION : un seul appel LLM combiné au lieu de deux appels parallèles
        # Élimine ~3.5s de latence réseau (sauve 50% du temps)

        sheet_json = _build_structured_sheet_json(sheet_content) or "[]"

        combined_prompt = (
            dynamic_context
            + f"\n\n## Cellules existantes (même format que fill_sql)\n```json\n{sheet_json}\n```\n\n"
            "## Auto-fill\n\n"
            "Ce JSON montre les cellules DÉJÀ REMPLIES. Toutes les autres "
            "sont vides.\n\n"
            "Les cellules existantes avec un `match` et/ou un `sql` source "
            "sont des **EXEMPLES DU PATTERN** à reproduire pour les "
            "cellules voisines vides :\n"
            "- Réutilise les **mêmes dimensions** (mêmes clés de match) "
            "en variant uniquement les valeurs\n"
            "- Réutilise la **même structure SQL** (mêmes WHERE/GROUP BY) "
            "en adaptant les filtres\n"
            "- Chaque dimension dans le GROUP BY DOIT être dans le match "
            "de chaque cellule\n\n"
            "Analyse le pattern existant et complète logiquement :\n"
            '- Labels (textes) → type "fill"\n'
            '- Valeurs numériques depuis SQL → type "fill_sql" ou '
            '"fill_plan"\n'
            '- Les deux → type "multi"\n'
            '- Tableau croisé / structure complexe → type "fill_plan"\n\n'
            "**IMPORTANT** : Génère TOUTES les cellules nécessaires, "
            "sans limite. Ne t'arrête PAS à 20 ou 30 cellules — remplis "
            "la feuille entièrement.\n\n"
            "Cible UNIQUEMENT les cellules VIDES (absentes du JSON). "
            "Réponds directement en JSON, pas de existing_cells."
        )

        # Injection du profil user (factuel, informatif) en suffixe du system
        # prompt via le helper local ``_with_user_block``. Appliqué à CHAQUE
        # appel LLM user-facing de ce service (auto-fill, planning,
        # exécution, retry).
        versioned_system = _with_user_block(_get_versioned_prompt(SYSTEM_PROMPT))
        llm_request = LLMRequest(
            prompt=combined_prompt,
            system=versioned_system,
            model=COPILOT_MODEL,
            temperature=0.2,
            max_tokens=clamped_max_tokens(16384),
            prompt_cache_prefix=cache_prefix,
        )
        combined_raw = None
        response = None
        restore_fn_anon = None
        for attempt in range(2):
            try:
                t_llm_start = time.monotonic()
                response, restore_fn_anon = await _call_llm_anon(
                    CallProfile(
                        caller="copilot_cell_suggest",
                        retry=RetryPolicy.NONE,  # retry custom x2 géré par le for attempt
                        fallback_policy=FallbackPolicy.NONE,  # SQL → chiffres sacrés (P1 #14)
                    ),
                    llm_request,
                    user_id,
                )
                t_llm_end = time.monotonic()
                logger.debug(
                    "LLM call took %.3fs (attempt %d)", t_llm_end - t_llm_start, attempt + 1
                )
                # Restaure les placeholders proxy (`§…§` + `[TYPE_N]`)
                # AVANT parsing JSON pour que le résultat downstream
                # (cells/labels/values) contienne le cleartext.
                combined_raw = restore_fn_anon(response.content) if response else None
                break
            except (asyncio.TimeoutError, ConnectionError, OSError) as exc:
                logger.warning(
                    "Auto-fill LLM call attempt %d failed (retryable): %s", attempt + 1, exc
                )
                if attempt == 1:
                    combined_raw = None
            except LLMCallError as exc:
                # Cas "IA non configurée" : retour structuré pour que le
                # handler propage un message FR clair au client (toast),
                # plutôt qu'un ``skipped: llm_error`` opaque qui masque
                # une erreur de config admin actionnable.
                if getattr(exc, "kind", None) == "not_configured":
                    logger.info("Auto-fill skip — IA non configurée : %s", exc)
                    return {
                        "cells": [],
                        "skipped": True,
                        "reason": "not_configured",
                        "message": str(exc),
                    }
                logger.warning("Auto-fill LLM call failed (non-retryable): %s", exc)
                combined_raw = None
                break
            except Exception as exc:
                logger.warning("Auto-fill LLM call failed (non-retryable): %s", exc)
                combined_raw = None
                break

        # Parser la réponse combinée
        if not combined_raw:
            return {"cells": [], "skipped": True, "reason": "llm_error"}

        # Essayer parser comme réponse "multi"
        parsed = _parse_llm_response(combined_raw)
        if not parsed:
            return {"error": "Auto-fill: réponse LLM invalide."}

        # Si c'est un "multi", extraire labels et values
        if parsed.get("type") == "multi":
            labels_obj = parsed.get("labels")
            values_obj = parsed.get("values")

            label_cells = []
            if labels_obj and labels_obj.get("type") == "fill":
                label_cells = labels_obj.get("cells", [])

            # Utiliser values_obj comme résultat principal, ou labels_obj si pas de values
            if values_obj:
                parsed = values_obj
            elif labels_obj:
                parsed = labels_obj
            else:
                logger.warning("Auto-fill: réponse 'multi' sans labels ni values — ignorée")
                return {"cells": [], "skipped": True}

            if label_cells:
                parsed["_label_cells"] = label_cells

        # Sinon, c'est un "fill" ou "fill_sql" direct — garder tel quel

        llm_ms = 0

    else:
        # ── 2-call architecture: Plan → Execute ──
        # Sauf pour FILL_SINGLE_CELL_ONLY (=cellule) : single-call direct
        is_single_cell = sheet_context and sheet_context.get("operation") == "FILL_SINGLE_CELL_ONLY"
        request_id = uuid.uuid4().hex[:8]
        user_prompt = ""
        plan = None
        plan_llm_ms = 0

        if not is_single_cell:
            try:
                planning_ctx = _build_planning_context(
                    instruction,
                    sql,
                    columns,
                    tabs_context,
                    sheet_content,
                    sheet_context,
                )
                versioned_planning = _with_user_block(_get_versioned_prompt(PLANNING_PROMPT))
                plan_request = LLMRequest(
                    prompt=planning_ctx,
                    system=versioned_planning,
                    model=COPILOT_MODEL,
                    temperature=0.1,
                    max_tokens=clamped_max_tokens(2048),
                )
                plan_response, plan_restore_fn = await _call_llm_anon(
                    CallProfile(
                        caller="copilot_cell_plan",
                        retry=RetryPolicy.NONE,
                        fallback_policy=FallbackPolicy.NONE,
                    ),
                    plan_request,
                    user_id,
                )
                plan_llm_ms = round(plan_response.duration_seconds * 1000)
                # Restore proxy tokens (`§…§` + `[TYPE_N]`) avant parsing :
                # le ``plan`` peut référencer des labels/values qui ont été
                # tokenisés à l'envoi.
                plan_content_clear = plan_restore_fn(plan_response.content)
                logger.info(
                    "[%s] Call 1 (plan) took %dms",
                    request_id,
                    plan_llm_ms,
                )
                logger.debug(
                    "[%s] Plan raw: %s",
                    request_id,
                    plan_content_clear[:500],
                )
                plan_parsed = _parse_llm_response(plan_content_clear)
                plan = _validate_plan(plan_parsed, tabs_context)
                if plan:
                    logger.info(
                        "[%s] Plan: type=%s, needs_schema=%s, " "tabs=%s",
                        request_id,
                        plan["plan_type"],
                        plan["needs_schema"],
                        plan.get("source_tabs", []),
                    )
            except LLMCallError as exc:
                # Court-circuit not_configured : pas la peine de tomber sur
                # le single-call fallback qui levera la même erreur. Retourne
                # directement la réponse structurée que le handler convertira
                # en HTTP 503 + message FR utile.
                if getattr(exc, "kind", None) == "not_configured":
                    logger.info("[%s] Plan skip — IA non configurée", request_id)
                    return {
                        "skipped": True,
                        "reason": "not_configured",
                        "message": str(exc),
                    }
                logger.warning(
                    "[%s] Call 1 failed, falling back to " "single-call: %s",
                    request_id,
                    exc,
                )
                plan = None
            except Exception as exc:
                logger.warning(
                    "[%s] Call 1 failed, falling back to " "single-call: %s",
                    request_id,
                    exc,
                )
                plan = None

        # ── Direct responses (clone_sheet, display) — skip Call 2 ──
        if plan and plan["plan_type"] in _PLAN_DIRECT_TYPES:
            parsed = dict(plan)
            parsed["type"] = parsed.pop("plan_type")
            parsed.pop("needs_schema", None)
            # On garde `source_tabs` pour le handler clone_sheet qui peut s'en
            # servir comme fallback si le LLM a confondu avec `value_source_tabs`.
            llm_ms = plan_llm_ms
            logger.info("[%s] Direct response (type=%s), no Call 2", request_id, parsed["type"])

        elif plan:
            # ── Call 2: Execution (targeted context based on plan) ──
            user_prompt, exec_cache = _build_execution_context(
                plan=plan,
                instruction=instruction,
                sql=sql,
                columns=columns,
                display_state=display_state,
                tabs_context=tabs_context,
                sheet_content=sheet_content,
                schema_context=schema_context,
                analysis_prompt=analysis_prompt,
                distinct_values=distinct_values,
                sheet_context=sheet_context,
            )

            versioned_exec = _with_user_block(_get_versioned_prompt(SYSTEM_PROMPT))

            # Garde budget : Anthropic refuse si prompt > 200K tokens. On estime
            # à chars/3.5 (ratio conservateur pour français). Cible : garder au
            # moins 20K tokens pour max_tokens réponse. Si ça ne passe pas, on
            # abandonne avec un message actionnable plutôt que de laisser
            # l'httpx 400 remonter bruyamment.
            estimated_tokens = int((len(user_prompt) + len(versioned_exec)) / 3.5)
            TOKEN_BUDGET = 175_000
            if estimated_tokens > TOKEN_BUDGET:
                logger.error(
                    "[%s] Call 2 prompt trop long estimé (%d tokens > %d). "
                    "Source_tabs=%s — réduis le nombre d'onglets ou cap SIBLING_MAX_CELLS_SQL.",
                    request_id,
                    estimated_tokens,
                    TOKEN_BUDGET,
                    plan.get("source_tabs", []),
                )
                return {
                    "error": (
                        f"Contexte trop volumineux pour le LLM "
                        f"(~{estimated_tokens} tokens estimés, max {TOKEN_BUDGET}). "
                        "Essaie de fermer les onglets non utilisés ou de simplifier la demande."
                    )
                }

            exec_request = LLMRequest(
                prompt=user_prompt,
                system=versioned_exec,
                model=COPILOT_MODEL,
                temperature=0.2,
                max_tokens=clamped_max_tokens(16384),
                prompt_cache_prefix=exec_cache,
            )

            try:
                response, exec_restore_fn = await _call_llm_anon(
                    CallProfile(
                        caller="copilot_cell_exec",
                        retry=RetryPolicy.NONE,
                        fallback_policy=FallbackPolicy.NONE,
                    ),
                    exec_request,
                    user_id,
                )
            except LLMCallError as exc:
                if getattr(exc, "kind", None) == "not_configured":
                    logger.info("[%s] Call 2 skip — IA non configurée", request_id)
                    return {
                        "skipped": True,
                        "reason": "not_configured",
                        "message": str(exc),
                    }
                # ``LLMCallError`` est garanti FR-safe par
                # ``_map_error_to_user_message`` — pas de leak (URL, clé).
                # Détail technique log côté serveur uniquement.
                logger.error("[%s] Call 2 (exec) failed: %s", request_id, exc, exc_info=True)
                return {"error": str(exc), "kind": getattr(exc, "kind", "generic")}
            except Exception as exc:
                # Exception non mappée : ne PAS leak ``str(exc)`` au client
                # (httpx.HTTPStatusError contient l'URL provider, RuntimeError
                # peut contenir le base_url custom). Stack côté serveur, message
                # générique côté client. Doctrine BaseHandler ``_Messages.INTERNAL_ERROR``.
                logger.error("[%s] Call 2 (exec) failed: %s", request_id, exc, exc_info=True)
                return {"error": "Erreur interne du service LLM. Réessayez la demande."}

            llm_ms = round(response.duration_seconds * 1000)
            logger.info(
                "[%s] Call 2 (exec) took %dms, plan_type=%s, total=%dms",
                request_id,
                llm_ms,
                plan["plan_type"],
                plan_llm_ms + llm_ms,
            )

            # Restore proxy tokens AVANT parsing JSON (cf. EPIC E4 :
            # parse-anon-puis-restore évite les chars JSON-spéciaux dans
            # les valeurs cleartext susceptibles de casser ``json.loads``).
            exec_content_clear = exec_restore_fn(response.content)
            parsed = _parse_llm_response(exec_content_clear)
            if not parsed:
                logger.warning(
                    "[%s] Failed to parse Call 2: %s", request_id, exec_content_clear[:500]
                )
                return {"error": "Réponse LLM invalide. Essayez de reformuler."}

        else:
            # ── Fallback: single-call (plan failed or validation rejected) ──
            logger.info("[%s] Fallback to single-call", request_id)
            # Contrainte cellule unique pour les requêtes =cellule
            if is_single_cell and sheet_context:
                tc = sheet_context.get("target_cell", {})
                target_col = tc.get("col", "?")
                user_parts.append(
                    f"## CONTEXTE : Cellule unique\n"
                    f"L'utilisateur remplit UNE SEULE CELLULE : "
                    f"**{target_col}**\n"
                    f"Réponse requise : **type 'cell'** avec `sql` "
                    f"(requête agrégée retournant 1 valeur) et "
                    f"optionnellement `detail_sql`.\n"
                    f"Ne réponds JAMAIS avec fill_sql, fill_plan "
                    f"ou multi."
                )
            user_parts.append(f"## Instruction de l'utilisateur\n{instruction}")

            manual_stable = []
            manual_dynamic = []
            hit_dyn = False
            for part in user_parts:
                if not hit_dyn and (
                    "Feuille active" in part
                    or "Contenu de la feuille" in part
                    or "Instruction de l'utilisateur" in part
                ):
                    hit_dyn = True
                if hit_dyn:
                    manual_dynamic.append(part)
                else:
                    manual_stable.append(part)

            user_prompt = "\n\n".join(manual_dynamic) if manual_dynamic else "\n\n".join(user_parts)
            manual_cache = "\n\n".join(manual_stable) if manual_stable else None

            versioned_manual = _with_user_block(_get_versioned_prompt(SYSTEM_PROMPT))
            request = LLMRequest(
                prompt=user_prompt,
                system=versioned_manual,
                model=COPILOT_MODEL,
                temperature=0.2,
                max_tokens=clamped_max_tokens(16384),
                prompt_cache_prefix=manual_cache,
            )

            try:
                response, manual_restore_fn = await _call_llm_anon(
                    CallProfile(
                        caller="copilot_cell_retry",
                        retry=RetryPolicy.NONE,
                        fallback_policy=FallbackPolicy.NONE,
                    ),
                    request,
                    user_id,
                )
            except LLMCallError as exc:
                if getattr(exc, "kind", None) == "not_configured":
                    logger.info("Manual fallback skip — IA non configurée")
                    return {
                        "skipped": True,
                        "reason": "not_configured",
                        "message": str(exc),
                    }
                logger.error("LLM call failed for result-modify: %s", exc, exc_info=True)
                # FR-safe : message déjà sanitizé par ``_map_error_to_user_message``.
                return {"error": str(exc), "kind": getattr(exc, "kind", "generic")}
            except Exception as exc:
                # Exception non mappée : pas de leak ``str(exc)`` au client.
                logger.error("LLM call failed for result-modify: %s", exc, exc_info=True)
                return {"error": "Erreur interne du service LLM. Réessayez la demande."}

            llm_ms = round(response.duration_seconds * 1000)

            # Restore proxy tokens (`§…§` + `[TYPE_N]`) avant parsing.
            manual_content_clear = manual_restore_fn(response.content)
            parsed = _parse_llm_response(manual_content_clear)
            if not parsed:
                logger.warning("Failed to parse LLM response: %s", manual_content_clear[:500])
                return {"error": "Réponse LLM invalide. Essayez de reformuler."}

    result_type = parsed.get("type", "")
    description = parsed.get("description", "Modification appliquée")
    new_tab = bool(parsed.get("new_tab", False))

    # FILL_SINGLE_CELL_ONLY : forcer type "cell" si le LLM a
    # retourné fill_sql/multi/fill — extraire la cellule ciblée.
    if (
        sheet_context
        and sheet_context.get("operation") == "FILL_SINGLE_CELL_ONLY"
        and result_type in ("fill_sql", "multi", "fill")
    ):
        target = sheet_context.get("target_cell", {})
        t_row = target.get("row")
        t_col = target.get("col")
        # Extraire le SQL de la première query fill_sql
        queries = parsed.get("queries") or []
        if result_type == "multi":
            vals = parsed.get("values") or {}
            queries = vals.get("queries") or []
        if queries and queries[0].get("sql"):
            parsed = {
                "type": "cell",
                "description": description,
                "sql": queries[0]["sql"],
            }
            result_type = "cell"
            logger.info(
                "FILL_SINGLE_CELL_ONLY: converted %s→cell " "for [%s,%s]",
                parsed.get("type"),
                t_row,
                t_col,
            )
        elif result_type == "fill":
            # fill = labels, extraire la valeur de la cellule
            cells = parsed.get("cells") or []
            val = None
            for c in cells:
                if c.get("row") == t_row and c.get("col") == t_col:
                    val = c.get("value")
                    break
            if val is None and cells:
                val = cells[0].get("value")
            if val is not None:
                return {
                    "type": "cell",
                    "description": description,
                    "value": val,
                }

    # Log mismatch plan_type vs result_type pour diagnostic
    if plan and plan.get("plan_type") and result_type != plan["plan_type"]:
        logger.info(
            "Plan/exec type mismatch: plan=%s, result=%s. Description: %s",
            plan["plan_type"],
            result_type,
            description[:120],
        )

    # Auto-fill : bloquer display/sql/cell — seuls fill et fill_sql sont autorisés.
    # Le LLM peut décider de renommer des colonnes ou modifier le SQL sans qu'on
    # lui demande — en auto-fill c'est dangereux (corrompt la grille).
    if is_auto_fill and result_type not in ("fill", "fill_sql", "fill_plan", "multi"):
        logger.warning(
            "Auto-fill: type %r bloqué (seuls fill/fill_sql autorisés). " "Description: %s",
            result_type,
            description[:100],
        )
        return {"cells": [], "skipped": True}

    # Si modification SQL : exécuter la nouvelle requête (avec retry sur erreur)
    if result_type == "sql":
        new_sql = parsed.get("sql", "").strip()
        if not new_sql:
            return {"error": "Le LLM n'a pas généré de SQL."}
        new_sql = _fix_missing_cte(sql, new_sql)

        connector = get_sage_connector()
        try:
            query_result = await connector.execute(new_sql, max_rows=MAX_RESULT_ROWS)
        except Exception as first_exc:
            # Premier échec : renvoyer l'erreur au LLM pour qu'il corrige
            first_err = str(first_exc).split("\n")[0] if "\n" in str(first_exc) else str(first_exc)
            logger.warning("SQL failed, retrying with LLM fix: %s", first_err)

            retry_prompt = (
                f"{user_prompt}\n\n"
                f"---\n\n"
                f"⚠️ **CORRECTION** : ta réponse précédente a produit une erreur SQL Server.\n\n"
                f"**Erreur** :\n```\n{first_err}\n```\n\n"
                f"**SQL fautif** :\n```sql\n{new_sql}\n```\n\n"
                f"Corrige le SQL en tenant compte de l'erreur. "
                f"Renvoie le JSON corrigé (même format)."
            )
            versioned_retry = _with_user_block(_get_versioned_prompt(SYSTEM_PROMPT))
            retry_request = LLMRequest(
                prompt=retry_prompt,
                system=versioned_retry,
                model=COPILOT_MODEL,
                temperature=0.1,
                max_tokens=clamped_max_tokens(4096),
            )
            try:
                retry_response, retry_restore_fn = await _call_llm_anon(
                    CallProfile(
                        caller="copilot_cell_retry",
                        retry=RetryPolicy.NONE,
                        fallback_policy=FallbackPolicy.NONE,
                    ),
                    retry_request,
                    user_id,
                )
                # Restore avant parsing : le SQL corrigé doit contenir
                # les vraies valeurs PII pour matcher les rows Sage.
                retry_content_clear = retry_restore_fn(retry_response.content)
                retry_parsed = _parse_llm_response(retry_content_clear)
                if retry_parsed and retry_parsed.get("type") == "sql":
                    fixed_sql = retry_parsed.get("sql", "").strip()
                    if fixed_sql:
                        fixed_sql = _fix_missing_cte(sql, fixed_sql)
                        description = retry_parsed.get("description", description)
                        new_tab = bool(retry_parsed.get("new_tab", new_tab))
                        query_result = await connector.execute(fixed_sql, max_rows=MAX_RESULT_ROWS)
                        new_sql = fixed_sql
                        logger.info("SQL retry succeeded after LLM fix")
                    else:
                        raise first_exc
                else:
                    raise first_exc
            except Exception as retry_exc:
                # Deuxième échec : abandonner
                logger.error("SQL retry also failed: %s", retry_exc, exc_info=True)
                err_msg = (
                    str(first_exc).split("\n")[0] if "\n" in str(first_exc) else str(first_exc)
                )
                return {"error": f"Erreur d'exécution SQL : {err_msg}"}

        rows_data = [list(row) for row in query_result.rows]
        sql_ms = query_result.execution_time_ms or 0
        total_ms = round((time.monotonic() - t_start) * 1000)
        logger.info(
            "result-modify(sql) metrics: llm=%dms sql=%dms total=%dms",
            llm_ms,
            sql_ms,
            total_ms,
        )
        return {
            "type": "sql",
            "description": description,
            "new_tab": new_tab,
            "sql": new_sql,
            "columns": query_result.columns,
            "rows": rows_data,
            "row_count": query_result.row_count,
            "execution_time_ms": query_result.execution_time_ms,
            "truncated": query_result.truncated,
            "metrics": {"llm_ms": llm_ms, "sql_ms": sql_ms, "total_ms": total_ms},
        }

    elif result_type == "cell":
        cell_sql = parsed.get("sql", "").strip()
        detail_sql = parsed.get("detail_sql", "").strip()
        if not cell_sql:
            return {"error": "Le LLM n'a pas généré de SQL " "pour la cellule."}
        cell_sql = _fix_missing_cte(sql, cell_sql)
        if detail_sql:
            detail_sql = _fix_missing_cte(sql, detail_sql)
        else:
            # Auto-generate detail SQL: replace SELECT aggregation with SELECT *
            detail_sql = _make_detail_sql(cell_sql)
        try:
            connector = get_sage_connector()
            # 1. Exécuter le SQL agrégé pour la valeur de la cellule
            value_result = await connector.execute(cell_sql, max_rows=1)
            value = None
            if value_result.rows:
                first_row = value_result.rows[0]
                value = first_row[0] if first_row else None

            # 2. Exécuter le SQL de détail pour l'onglet (si fourni)
            detail_columns = []
            detail_rows = []
            detail_count = 0
            detail_sql_used = detail_sql or cell_sql
            if detail_sql:
                try:
                    detail_result = await connector.execute(detail_sql, max_rows=MAX_RESULT_ROWS)
                    detail_columns = detail_result.columns
                    detail_rows = [list(row) for row in detail_result.rows]
                    detail_count = detail_result.row_count
                except Exception as detail_exc:
                    logger.warning("Detail SQL failed, falling back to cell SQL: %s", detail_exc)
                    detail_sql_used = cell_sql
            if not detail_rows:
                # Fallback : utiliser le résultat agrégé
                detail_columns = value_result.columns
                detail_rows = [list(row) for row in value_result.rows]
                detail_count = value_result.row_count

            return {
                "type": "cell",
                "description": description,
                "value": value,
                "sql": detail_sql_used,
                "columns": detail_columns,
                "rows": detail_rows,
                "row_count": detail_count,
            }
        except Exception as exc:
            logger.error("Cell SQL execution failed: %s", exc, exc_info=True)
            err_msg = str(exc).split("\n")[0] if "\n" in str(exc) else str(exc)
            return {"error": f"Erreur SQL : {err_msg}"}

    elif result_type == "fill":
        cells = parsed.get("cells", [])
        if not cells or not isinstance(cells, list):
            cells = []
        # Filtrer les overwrites (cellules déjà dans sheet_content)
        filled_pos: set = set()
        if sheet_content:
            for sc in sheet_content:
                if sc.get("value") and str(sc["value"]).strip():
                    filled_pos.add((sc.get("row"), sc.get("col")))
        # Validate cell format — each must have row, col, value
        validated = []
        for cell in cells:
            if not isinstance(cell, dict):
                continue
            row = cell.get("row")
            col = cell.get("col")
            value = cell.get("value")
            if row is None or col is None or value is None:
                continue
            # FIX: LLM parfois retourne "(existant)" pour les cellules remplies — les ignorer
            if str(value).strip() == "(existant)":
                continue
            if (row, col) in filled_pos:
                continue  # Overwrite filtré
            validated.append({"row": row, "col": col, "value": value})
        # Fusionner les _label_cells — filtrer contre validated ET sheet_content
        label_cells = parsed.get("_label_cells", [])
        if label_cells:
            occupied = {(c["row"], c["col"]) for c in validated}
            if sheet_content:
                for sc in sheet_content:
                    if sc.get("value") and str(sc["value"]).strip():
                        occupied.add((sc.get("row"), sc.get("col")))
            for lc in label_cells:
                if isinstance(lc, dict) and (lc.get("row"), lc.get("col")) not in occupied:
                    validated.append(
                        {
                            "row": lc["row"],
                            "col": lc["col"],
                            "value": lc.get("value", ""),
                        }
                    )
        if not validated:
            return {"error": "Aucune cellule à remplir."}
        return {
            "type": "fill",
            "description": description,
            "cells": validated,
        }

    elif result_type == "fill_sql":
        queries = parsed.get("queries", [])
        if not queries or not isinstance(queries, list):
            return {"error": "Aucune requête fill_sql."}

        connector = get_sage_connector()
        all_cells: list[dict] = []
        errors_count = 0

        # Diagnostic: log when same match targets different columns (likely LLM error)
        for q in queries:
            if not isinstance(q, dict):
                continue
            cells_in_q = q.get("cells", [])
            match_to_cols: dict[str, set] = {}
            for c in cells_in_q:
                if not isinstance(c, dict):
                    continue
                m = c.get("match") or {}
                me = c.get("match_exclude") or {}
                if not m and not me:
                    continue  # empty match = global aggregate, skip
                sig = json.dumps(m, sort_keys=True) + "|" + json.dumps(me, sort_keys=True)
                match_to_cols.setdefault(sig, set()).add(c.get("col", ""))
            for sig, cols in match_to_cols.items():
                if len(cols) > 1:
                    logger.warning(
                        "fill_sql: même match pour %d colonnes différentes (%s) — "
                        "les valeurs seront identiques. Match: %s",
                        len(cols),
                        ", ".join(sorted(cols)),
                        sig,
                    )

        # C5: Parallélisation — exécuter les queries fill_sql en parallèle
        sem = asyncio.Semaphore(_FILL_SQL_MAX_CONCURRENT)

        async def _process_one_query(q):
            """Traite une query fill_sql. Retourne (cells_list, errors_count, timing)."""
            local_cells: list[dict] = []
            local_errors = 0
            local_sql_ms = 0
            local_detail_ms_parts: list[float] = []
            local_retry_llm_ms = 0

            _empty_timing = {"sql_ms": 0, "detail_ms": 0, "retry_llm_ms": 0}
            if not isinstance(q, dict):
                return local_cells, local_errors, _empty_timing
            q_sql = q.get("sql", "").strip()
            if not q_sql:
                return local_cells, local_errors, _empty_timing
            q_sql = _fix_missing_cte(sql, q_sql)
            value_col = q.get("value_column", "")
            cells = q.get("cells", [])
            if not cells:
                return local_cells, local_errors, _empty_timing

            # C3a: Validation format — row/col valides, pas de doublons
            cells, fmt_rejected = _validate_fill_cells_format(cells)
            if fmt_rejected:
                logger.warning(
                    "fill_sql: %d cellule(s) rejetée(s) — format invalide : %s",
                    len(fmt_rejected),
                    [(r.get("row"), r.get("col"), r.get("error")) for r in fmt_rejected],
                )
                for r in fmt_rejected:
                    local_cells.append(
                        {
                            "row": r.get("row"),
                            "col": r.get("col"),
                            "label": r.get("label", ""),
                            "value": None,
                            "error": r.get("error", "Format invalide"),
                        }
                    )
                    local_errors += 1
            if not cells:
                return local_cells, local_errors, _empty_timing

            # FIX: LLM sometimes returns "(existant)" marker — filter these out
            cells = [c for c in cells if str(c.get("value", "")).strip() != "(existant)"]

            # A6: Validation — rejeter les cellules qui ciblent des positions déjà remplies
            cells, rejected = _validate_fill_targets(cells, sheet_content)
            if rejected:
                logger.warning(
                    "fill_sql: %d cellule(s) rejetée(s) — ciblent des positions remplies : %s",
                    len(rejected),
                    [(r.get("row"), r.get("col")) for r in rejected],
                )
                for r in rejected:
                    local_cells.append(
                        {
                            "row": r.get("row"),
                            "col": r.get("col"),
                            "label": r.get("label", ""),
                            "value": None,
                            "error": "Cellule déjà remplie — position ignorée",
                        }
                    )
                    local_errors += 1
            if not cells:
                return local_cells, local_errors, _empty_timing

            # 0. PRÉ-VALIDATION CTE : détecter les erreurs de colonne avant exécution
            cte_valid, cte_error = _validate_cte_column_usage(q_sql)
            if not cte_valid:
                logger.warning("fill_sql CTE validation failed: %s", cte_error)
                # Appeler le LLM directement pour corriger, sans essayer d'exécuter
                retry_prompt = (
                    f"Corrige ce SQL qui a une erreur CTE.\n\n"
                    f"**Erreur** :\n```\n{cte_error}\n```\n\n"
                    f"**SQL fautif** :\n```sql\n{q_sql}\n```\n\n"
                    f"Renvoie UNIQUEMENT le SQL corrigé, sans explication, "
                    f"sans fences markdown, sans JSON."
                )
                try:
                    retry_resp, retry_restore_fn = await _call_llm_anon(
                        CallProfile(
                            caller="copilot_cell_retry",
                            retry=RetryPolicy.NONE,
                            fallback_policy=FallbackPolicy.NONE,
                        ),
                        LLMRequest(
                            prompt=retry_prompt,
                            system="Tu corriges du SQL Server.",
                            model=COPILOT_MODEL,
                            temperature=0.1,
                            max_tokens=clamped_max_tokens(8192),
                        ),
                        user_id,
                        # Opt-out OUTPUT_STYLE_RULES : prompt SQL strict ultra-court
                        # (9 tokens system). Inflation prompt cassait le focus du
                        # LLM (cf. adversarial #4 sur fix #19). L'output est du
                        # SQL brut, parsé en aval — risque mockup ASCII = nul.
                        inject_style_rules=False,
                    )
                    # Le SQL retourné contient les vrais litéraux PII
                    # pour matcher les rows Sage — restore obligatoire.
                    fixed_sql = retry_restore_fn(retry_resp.content).strip()
                    fixed_sql = re.sub(r"```(?:sql)?\s*\n?", "", fixed_sql).strip()
                    fixed_sql = _fix_missing_cte(sql, fixed_sql)
                    q_sql = fixed_sql
                    logger.info("fill_sql CTE pre-validation correction succeeded")
                except Exception as exc:
                    logger.warning("fill_sql CTE correction failed: %s", exc)
                    for c in cells:
                        local_cells.append(
                            {
                                "row": c.get("row"),
                                "col": c.get("col"),
                                "label": c.get("label", ""),
                                "value": None,
                                "error": cte_error,
                            }
                        )
                        local_errors += 1
                    return local_cells, local_errors, _empty_timing

            # 1. Exécuter la requête UNE SEULE FOIS (avec retry LLM sur erreur)
            try:
                async with sem:
                    query_result = await connector.execute(q_sql, max_rows=MAX_RESULT_ROWS)
                local_sql_ms = query_result.execution_time_ms or 0
            except Exception as first_exc:
                first_err = str(first_exc).split("\n")[0]
                logger.warning("fill_sql query failed, retrying: %s", first_err)
                # Enrichir le retry avec le schéma DDL des tables du SQL fautif
                # pour que le LLM corrige avec les vrais noms de colonnes
                retry_schema = ""
                try:
                    failed_tables = sorted(_extract_table_names(q_sql))[:6]
                    if failed_tables:
                        # Phase α.4 — propager user_id.
                        retry_schema = await _get_schema_context(failed_tables, user_id=user_id)
                        if len(retry_schema) > 4000:
                            retry_schema = retry_schema[:4000] + "\n-- (tronqué)"
                except Exception:
                    pass  # best-effort, on retry quand même sans schéma
                schema_section = ""
                if retry_schema:
                    schema_section = (
                        f"\n\n**Schéma des tables référencées** :\n"
                        f"```\n{retry_schema}\n```\n\n"
                        f"Utilise UNIQUEMENT les colonnes listées ci-dessus.\n"
                    )
                retry_prompt = (
                    f"Corrige ce SQL qui a produit une erreur.\n\n"
                    f"**Erreur** :\n```\n{first_err}\n```\n\n"
                    f"**SQL fautif** :\n```sql\n{q_sql}\n```\n"
                    f"{schema_section}\n"
                    f"Renvoie UNIQUEMENT le SQL corrigé, sans explication, "
                    f"sans fences markdown, sans JSON."
                )
                try:
                    retry_resp, retry_restore_fn = await _call_llm_anon(
                        CallProfile(
                            caller="copilot_cell_retry",
                            retry=RetryPolicy.NONE,
                            fallback_policy=FallbackPolicy.NONE,
                        ),
                        LLMRequest(
                            prompt=retry_prompt,
                            system="Tu corriges du SQL Server.",
                            model=COPILOT_MODEL,
                            temperature=0.1,
                            max_tokens=clamped_max_tokens(8192),
                        ),
                        user_id,
                        # Opt-out OUTPUT_STYLE_RULES — cf. site #1 plus haut :
                        # SQL strict ultra-court, inflation prompt cassait
                        # le focus (adversarial #4 sur fix #19).
                        inject_style_rules=False,
                    )
                    local_retry_llm_ms = round(retry_resp.duration_seconds * 1000)
                    # Restore avant exécution Sage : sinon `WHERE col = '[EMAIL_1]'`
                    # ne match aucune row. Le restore réinjecte la PII réelle.
                    fixed_sql = retry_restore_fn(retry_resp.content).strip()
                    fixed_sql = re.sub(r"```(?:sql)?\s*\n?", "", fixed_sql).strip()
                    fixed_sql = _fix_missing_cte(sql, fixed_sql)
                    async with sem:
                        query_result = await connector.execute(fixed_sql, max_rows=MAX_RESULT_ROWS)
                    local_sql_ms = query_result.execution_time_ms or 0
                    q_sql = fixed_sql
                    logger.info("fill_sql retry succeeded")
                except Exception as retry_exc:
                    logger.warning("fill_sql retry also failed: %s", retry_exc)
                    err_msg = first_err
                    for c in cells:
                        local_cells.append(
                            {
                                "row": c.get("row"),
                                "col": c.get("col"),
                                "label": c.get("label", ""),
                                "value": None,
                                "error": err_msg,
                            }
                        )
                        local_errors += 1
                    return local_cells, local_errors, _empty_timing

            # 2. Indexer les résultats : liste de dicts {col_name: value}
            col_names = query_result.columns
            rows_as_dicts = [
                {col_names[j]: row[j] for j in range(len(col_names))} for row in query_result.rows
            ]

            # C3b: Valider value_column avant de matcher
            val_col_idx = None
            if value_col and value_col in col_names:
                val_col_idx = col_names.index(value_col)
            elif value_col:
                logger.warning(
                    "fill_sql: value_column %r introuvable dans les résultats %s — "
                    "fallback sur la dernière colonne",
                    value_col,
                    col_names,
                )

            # C3c: Valider les clés match des cellules contre les colonnes du résultat
            cells, match_rejected = _validate_match_keys(cells, col_names)
            if match_rejected:
                logger.warning(
                    "fill_sql: %d cellule(s) rejetée(s) — clés match invalides",
                    len(match_rejected),
                )
                for r in match_rejected:
                    local_cells.append(
                        {
                            "row": r.get("row"),
                            "col": r.get("col"),
                            "label": r.get("label", ""),
                            "value": None,
                            "error": r.get("error", "Clés match invalides"),
                        }
                    )
                    local_errors += 1
            if not cells:
                return local_cells, local_errors, _empty_timing

            # 4. Générer le detail SQL (SELECT TOP N * au lieu de GROUP BY agrégé)
            detail_sql = _make_detail_sql(q_sql, max_rows=_DETAIL_MAX_ROWS)

            # 5. Pour chaque cellule, matcher une ligne du résultat
            detail_tasks: list[tuple[dict, str, str]] = []
            for c in cells:
                if not isinstance(c, dict):
                    continue
                if c.get("row") is None or c.get("col") is None:
                    continue
                match_filters = c.get("match") or {}
                match_exclude = c.get("match_exclude")
                label = c.get("label", "")
                result_cell: dict = {"row": c["row"], "col": c["col"], "label": label}

                # Chercher la/les ligne(s) qui matchent
                matched_value = None
                match_found = False
                for idx, row_dict in enumerate(rows_as_dicts):
                    # Positive match: all keys must equal
                    if match_filters and not all(
                        str(row_dict.get(k, "")).strip().lower() == str(v).strip().lower()
                        for k, v in match_filters.items()
                    ):
                        continue

                    # A5: Exclusion match — row must NOT match any excluded value
                    if match_exclude:
                        excluded = False
                        for ek, ev_list in match_exclude.items():
                            row_val = str(row_dict.get(ek, "")).strip().lower()
                            if any(str(ev).strip().lower() == row_val for ev in ev_list):
                                excluded = True
                                break
                        if excluded:
                            continue

                    match_found = True

                    # Extract value from matched row
                    raw_val = (
                        query_result.rows[idx][val_col_idx]
                        if val_col_idx is not None
                        else query_result.rows[idx][-1]
                    )

                    if raw_val is not None:
                        try:
                            num = float(raw_val)
                            if matched_value is None:
                                matched_value = num
                            else:
                                matched_value = matched_value + num
                        except (TypeError, ValueError):
                            # Non-numérique : premier match wins
                            if matched_value is None:
                                matched_value = raw_val
                                if not match_exclude:
                                    break

                # Arrondir pour éviter les dérives float sur données comptables
                if isinstance(matched_value, float):
                    matched_value = round(matched_value, 2)
                result_cell["value"] = matched_value

                # Détail drill-down : préparer pour exécution parallèle
                if detail_sql and (match_filters or match_exclude):
                    where_parts = []
                    for mk, mv in match_filters.items():
                        safe_val = str(mv).replace("'", "''")
                        where_parts.append(f"[{mk}] = '{safe_val}'")
                    # A5: NOT IN clauses for match_exclude
                    if match_exclude:
                        for ek, ev_list in match_exclude.items():
                            safe_vals = ", ".join(
                                f"'{str(v).replace(chr(39), chr(39) * 2)}'" for v in ev_list
                            )
                            where_parts.append(f"[{ek}] NOT IN ({safe_vals})")
                    extra_where = " AND ".join(where_parts)
                    cell_detail_sql = re.sub(
                        r"\bGROUP\s+BY\b.*$",
                        "",
                        detail_sql,
                        flags=re.IGNORECASE | re.DOTALL,
                    ).rstrip()
                    has_where = bool(re.search(r"\bWHERE\b", cell_detail_sql, re.IGNORECASE))
                    keyword = "AND" if has_where else "WHERE"
                    cell_detail_sql += f" {keyword} {extra_where}"
                    detail_tasks.append((result_cell, cell_detail_sql, label))

                # C3d: Diagnostic quand aucune ligne ne matche
                if matched_value is None:
                    local_errors += 1
                    if match_found:
                        # Des lignes matchent mais toutes les valeurs sont NULL
                        result_cell["value"] = None
                        result_cell["error"] = "Lignes trouvées mais toutes les valeurs sont NULL"
                    elif (match_filters or match_exclude) and rows_as_dicts:
                        avail = {}
                        all_keys = list(match_filters.keys())
                        if match_exclude:
                            all_keys.extend(match_exclude.keys())
                        for k in all_keys:
                            vals = sorted({str(r.get(k, "")).strip() for r in rows_as_dicts})
                            avail[k] = vals[:10]
                        filters_desc: dict = {}
                        if match_filters:
                            filters_desc["match"] = match_filters
                        if match_exclude:
                            filters_desc["match_exclude"] = match_exclude
                        result_cell["error"] = (
                            f"Aucune ligne ne correspond au filtre {filters_desc}. "
                            f"Valeurs disponibles : {avail}"
                        )
                    elif not rows_as_dicts:
                        result_cell["error"] = "La requête n'a retourné aucun résultat"
                local_cells.append(result_cell)

            # C5: Exécuter les requêtes detail en parallèle
            if detail_tasks:

                async def _fetch_detail(rc, det_sql, lbl):
                    try:
                        async with sem:
                            det_result = await connector.execute(det_sql, max_rows=_DETAIL_MAX_ROWS)
                        local_detail_ms_parts.append(det_result.execution_time_ms or 0)
                        rc["detail"] = {
                            "sql": det_sql,
                            "columns": det_result.columns,
                            "rows": [list(r) for r in det_result.rows],
                            "row_count": det_result.row_count,
                            "description": lbl,
                        }
                    except Exception as det_exc:
                        logger.debug("fill_sql detail failed: %s", det_exc)

                await asyncio.gather(
                    *[_fetch_detail(rc, ds, lb) for rc, ds, lb in detail_tasks],
                    return_exceptions=True,
                )

            return (
                local_cells,
                local_errors,
                {
                    "sql_ms": local_sql_ms,
                    "detail_ms": sum(local_detail_ms_parts),
                    "retry_llm_ms": local_retry_llm_ms,
                },
            )

        # C5: Exécuter toutes les queries en parallèle
        query_results = await asyncio.gather(
            *[_process_one_query(q) for q in queries],
            return_exceptions=True,
        )

        # B6: Agréger métriques de timing par query
        total_sql_ms = 0
        total_detail_ms = 0
        total_retry_llm_ms = 0
        queries_executed = 0
        detail_queries_executed = 0
        for res in query_results:
            if isinstance(res, Exception):
                logger.warning("fill_sql query processing failed: %s", res)
                continue
            cells_res, errs, timing = res
            all_cells.extend(cells_res)
            errors_count += errs
            total_sql_ms += timing.get("sql_ms", 0)
            total_detail_ms += timing.get("detail_ms", 0)
            total_retry_llm_ms += timing.get("retry_llm_ms", 0)
            if timing.get("sql_ms", 0) > 0:
                queries_executed += 1
            detail_queries_executed += len([c for c in cells_res if c.get("detail")])

        success_count = sum(1 for r in all_cells if r.get("value") is not None)

        total_ms = round((time.monotonic() - t_start) * 1000)
        metrics = {
            "llm_ms": llm_ms,
            "retry_llm_ms": total_retry_llm_ms,
            "sql_ms": round(total_sql_ms),
            "detail_sql_ms": round(total_detail_ms),
            "total_ms": total_ms,
            "queries_count": queries_executed,
            "detail_queries_count": detail_queries_executed,
        }
        logger.info(
            "result-modify(fill_sql) metrics: llm=%dms sql=%dms detail=%dms "
            "retry_llm=%dms total=%dms queries=%d detail_queries=%d "
            "cells=%d/%d",
            llm_ms,
            round(total_sql_ms),
            round(total_detail_ms),
            total_retry_llm_ms,
            total_ms,
            queries_executed,
            detail_queries_executed,
            success_count,
            success_count + errors_count,
        )

        # Fusionner les label_cells (appel parallèle auto-fill) si présentes
        # Filtrer contre all_cells ET sheet_content (pas d'overwrite)
        label_cells = parsed.get("_label_cells", [])
        if label_cells:
            occupied = {(c.get("row"), c.get("col")) for c in all_cells}
            if sheet_content:
                for sc in sheet_content:
                    if sc.get("value") and str(sc["value"]).strip():
                        occupied.add((sc.get("row"), sc.get("col")))
            for lc in label_cells:
                if isinstance(lc, dict) and (lc.get("row"), lc.get("col")) not in occupied:
                    # FIX: LLM parfois retourne "(existant)" — les ignorer
                    if str(lc.get("value", "")).strip() != "(existant)":
                        all_cells.append(lc)

        # Filtrer les cellules sans valeur (rejetées par _validate_fill_targets)
        all_cells = [c for c in all_cells if c.get("value") is not None]

        return {
            "type": "fill_sql",
            "description": description,
            "cells": all_cells,
            "success_count": success_count,
            "errors_count": errors_count,
            "metrics": metrics,
        }

    elif result_type == "fill_plan":
        plan_queries = parsed.get("queries", [])
        plan_labels = parsed.get("labels", [])
        if not plan_queries:
            return {"error": "fill_plan: aucune requête."}

        all_cells = []
        # Add static labels first
        for lbl in plan_labels:
            if isinstance(lbl, dict) and lbl.get("row") and lbl.get("col") and lbl.get("value"):
                all_cells.append({"row": lbl["row"], "col": lbl["col"], "value": lbl["value"]})

        col_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        for pq in plan_queries:
            pq_sql = pq.get("sql", "")
            val_col = pq.get("value_column", "")
            row_dim = pq.get("row_dimension", "")
            col_dim = pq.get("col_dimension")
            start_row = int(pq.get("start_row", 2))
            start_col_str = str(pq.get("start_col", "B")).upper()
            start_col_idx = col_letters.index(start_col_str) if start_col_str in col_letters else 1

            if not pq_sql or not val_col:
                continue

            # Execute the SQL
            try:
                query_result = await connector.execute_query(pq_sql)
            except Exception as exc:
                logger.warning("fill_plan query failed: %s", exc)
                continue

            if not query_result or not query_result.rows:
                continue

            cols_lower = [c.lower() for c in query_result.columns]
            val_idx = next((i for i, c in enumerate(cols_lower) if c == val_col.lower()), None)
            row_dim_idx = (
                next((i for i, c in enumerate(cols_lower) if c == row_dim.lower()), None)
                if row_dim
                else None
            )
            col_dim_idx = (
                next((i for i, c in enumerate(cols_lower) if c == col_dim.lower()), None)
                if col_dim
                else None
            )

            if val_idx is None:
                continue

            # Build pivot
            row_values = []  # ordered unique values for row dimension
            col_values = []  # ordered unique values for col dimension
            seen_rows = {}
            seen_cols = {}

            for row in query_result.rows:
                if row_dim_idx is not None:
                    rv = str(row[row_dim_idx]) if row[row_dim_idx] is not None else ""
                    if rv and rv not in seen_rows:
                        seen_rows[rv] = len(row_values)
                        row_values.append(rv)
                if col_dim_idx is not None:
                    cv = str(row[col_dim_idx]) if row[col_dim_idx] is not None else ""
                    if cv and cv not in seen_cols:
                        seen_cols[cv] = len(col_values)
                        col_values.append(cv)

            # Generate column headers
            if col_values:
                for ci, cv in enumerate(col_values):
                    col_letter = (
                        col_letters[start_col_idx + ci]
                        if (start_col_idx + ci) < len(col_letters)
                        else None
                    )
                    if col_letter:
                        all_cells.append(
                            {
                                "row": start_row - 1,
                                "col": col_letter,
                                "value": cv,
                            }
                        )

            # Generate row labels + values
            for row in query_result.rows:
                rv = (
                    str(row[row_dim_idx])
                    if row_dim_idx is not None and row[row_dim_idx] is not None
                    else ""
                )
                cv = (
                    str(row[col_dim_idx])
                    if col_dim_idx is not None and row[col_dim_idx] is not None
                    else ""
                )
                val = row[val_idx]

                if row_dim_idx is not None and rv in seen_rows:
                    r_offset = seen_rows[rv]
                else:
                    r_offset = 0

                target_row = start_row + r_offset

                # Row label (column A or start_col - 1)
                label_col_idx = start_col_idx - 1
                if label_col_idx >= 0 and rv:
                    label_col = col_letters[label_col_idx]
                    # Only add label once per row
                    f"{target_row},{label_col}"
                    if not any(
                        c.get("row") == target_row and c.get("col") == label_col for c in all_cells
                    ):
                        all_cells.append({"row": target_row, "col": label_col, "value": rv})

                # Value cell
                if col_dim_idx is not None and cv in seen_cols:
                    c_offset = seen_cols[cv]
                else:
                    c_offset = 0

                target_col_idx = start_col_idx + c_offset
                if target_col_idx < len(col_letters) and val is not None:
                    target_col = col_letters[target_col_idx]
                    cell_entry = {
                        "row": target_row,
                        "col": target_col,
                        "value": round(float(val), 2) if val is not None else None,
                        "label": f"{rv} · {cv}" if rv and cv else rv or cv,
                    }
                    all_cells.append(cell_entry)

        if not all_cells:
            return {"error": "fill_plan: aucune cellule générée."}

        # Cap at 500 cells
        all_cells = all_cells[:500]

        return {
            "type": "fill",
            "description": description,
            "cells": all_cells,
        }

    elif result_type == "display":
        actions = parsed.get("actions", [])
        if not actions:
            return {"error": "Aucune action d'affichage retournée."}
        return {
            "type": "display",
            "description": description,
            "actions": actions,
        }

    elif result_type == "clone_sheet":
        source_idx = parsed.get("source_tab_index")
        if source_idx is None or not isinstance(source_idx, int):
            return {"error": "clone_sheet: source_tab_index manquant ou invalide."}
        # Bounds check : le chemin single-call fallback peut amener un plan non
        # validé ici. Refuser explicitement les indices hors limites plutôt que
        # de propager un value inutile côté frontend.
        max_tab_idx = (len(tabs_context) - 1) if tabs_context else -1
        if source_idx < 0 or source_idx > max_tab_idx:
            return {
                "error": (
                    f"clone_sheet: source_tab_index hors limites "
                    f"(got {source_idx}, max {max_tab_idx})."
                )
            }
        # Délègue la validation + normalisation des champs variables au helper
        # partagé pour garantir l'identité des règles entre le chemin validé
        # et le chemin single-call fallback.
        cleaned = _clean_clone_sheet_fields(parsed, tabs_context, source_idx)
        clean_subs = cleaned["substitutions"]
        value_src_tabs = cleaned["value_source_tabs"]

        # Fallback : le LLM confond parfois `source_tabs` (méta) et
        # `value_source_tabs` (lookup). Si l'instruction indique clairement
        # une intention de RÉUTILISATION et que value_source_tabs est vide
        # alors que source_tabs liste des onglets → on interprète source_tabs
        # comme une intention de lookup et on s'en sert.
        warnings: list[str] = []
        if not value_src_tabs:
            raw_source_tabs = parsed.get("source_tabs") or []
            fallback_src = [
                i
                for i in raw_source_tabs
                if isinstance(i, int) and 0 <= i <= max_tab_idx and i != source_idx
            ]
            if fallback_src and _user_wants_reuse(instruction):
                value_src_tabs = fallback_src
                warnings.append(
                    "Le plan a listé les onglets dans `source_tabs` (méta) au lieu "
                    "de `value_source_tabs` (action). Interprétation corrigée : "
                    f"lookup effectué dans {value_src_tabs}."
                )
                logger.info(
                    "clone_sheet: fallback source_tabs → value_source_tabs=%s "
                    "(intention 'réutilisation' détectée dans l'instruction)",
                    value_src_tabs,
                )

        # new_tab + excludes viennent du helper (déjà normalisés/validés).
        new_tab = cleaned["new_tab"]
        excludes = cleaned["excludes"]

        # Fallback intelligent : si source_tab_index == onglet actif,
        # cloner sur soi-même n'a pas de sens → forcer new_tab=true même si
        # le LLM ne l'a pas demandé. Évite le "rien à cloner" silencieux.
        active_idx = next(
            (i for i, t in enumerate(tabs_context or []) if t.get("is_active")),
            -1,
        )
        if not new_tab and source_idx == active_idx and active_idx >= 0:
            new_tab = True
            warnings.append(
                "Onglet source = onglet actif : création automatique d'un nouvel "
                "onglet pour éviter le clone-sur-soi-même."
            )
            logger.info(
                "clone_sheet: fallback new_tab=true (source == active == %d)",
                source_idx,
            )

        reused_cells: list[dict] = []
        lookup_ms = 0
        if value_src_tabs and tabs_context:
            # La "structure cible" après clone = celle de la feuille source
            # (onglet source_idx). On utilise son sheet_content comme référence
            # de labels + croisements attendus. Si source_tab n'a pas de
            # sheet_content (ex: onglet SQL), on retombe sur la feuille active.
            source_tab = tabs_context[source_idx] if 0 <= source_idx <= max_tab_idx else {}
            source_sheet = source_tab.get("sheet_content") or sheet_content or []
            target_labels_cfg = cleaned["target_labels"]
            lookup_start = time.monotonic()
            try:
                all_resolved = _resolve_cells_from_siblings(
                    sheet_content=source_sheet,
                    tabs_context=tabs_context,
                    source_tabs=value_src_tabs,
                    target_labels_cfg=target_labels_cfg,
                    excludes=excludes,
                )
                reused_cells = [c for c in all_resolved if c.get("value") not in (None, "")]
                logger.info(
                    "clone_sheet: %d cellule(s) piochée(s) depuis onglets %s "
                    "(excludes=%d règle(s))",
                    len(reused_cells),
                    value_src_tabs,
                    len(excludes),
                )
            except Exception as exc:
                logger.warning(
                    "clone_sheet: lookup value_source_tabs a échoué : %s",
                    exc,
                )
                warnings.append(f"Lookup des valeurs a échoué : {exc}")
            lookup_ms = round((time.monotonic() - lookup_start) * 1000)

        # Warning : l'utilisateur voulait réutiliser mais aucune source dispo
        if (not value_src_tabs) and _user_wants_reuse(instruction):
            warnings.append(
                "Instruction demande de réutiliser les valeurs des autres onglets, "
                "mais aucun onglet source n'a été identifié par le plan. "
                "Aucune valeur ne sera piochée — seule la structure sera clonée."
            )
        # Warning : les exclusions ont tout filtré → message plus précis que
        # le générique "Rien à cloner" côté frontend.
        if value_src_tabs and excludes and not reused_cells:
            warnings.append(
                f"Les {len(excludes)} règle(s) d'exclusion ont filtré toutes les "
                "cellules candidates. Vérifiez que les `column` et `values` "
                "correspondent bien aux données des onglets sources."
            )

        total_ms = round((time.monotonic() - t_start) * 1000)

        return {
            "type": "clone_sheet",
            "description": description,
            "source_tab_index": source_idx,
            "substitutions": clean_subs,
            "value_source_tabs": value_src_tabs,
            "new_tab": new_tab,
            "excludes": excludes,
            "reused_cells": reused_cells,
            "warnings": warnings,
            "metrics": {
                "llm_ms": llm_ms,
                "lookup_ms": lookup_ms,
                "total_ms": total_ms,
                "reused_count": len(reused_cells),
                "excludes_count": len(excludes),
            },
        }

    elif result_type == "emit_tab":
        # Étape 1 : expanse les formes compactes (clone_structure_from,
        # rows_overrides, cell_groups) en forme complète. On passe aussi
        # sheet_content top-level car c'est là que vivent les cellules de
        # l'onglet actif (dédupliqué par le frontend).
        expand_err = _expand_emit_tab(parsed, tabs_context, sheet_content)
        if expand_err:
            return expand_err
        # Étape 2 : valide la forme complète.
        err = _validate_emit_tab(parsed, tabs_context)
        if err:
            return err
        recompute_start = time.monotonic()
        parsed = _recompute_emit_tab(parsed, tabs_context)
        recompute_ms = round((time.monotonic() - recompute_start) * 1000)

        new_tab_flag = parsed.get("new_tab")
        if new_tab_flag is None:
            new_tab_flag = True
        new_tab_flag = bool(new_tab_flag)

        total_ms = round((time.monotonic() - t_start) * 1000)
        recompute_metrics = parsed.get("_recompute_metrics") or {}
        return {
            "type": "emit_tab",
            "description": description,
            "tab": parsed["tab"],
            "new_tab": new_tab_flag,
            "metrics": {
                "llm_ms": llm_ms,
                "recompute_ms": recompute_ms,
                "total_ms": total_ms,
                "recomputed": recompute_metrics.get("recomputed", 0),
                "trusted": recompute_metrics.get("trusted", 0),
                "no_source": recompute_metrics.get("no_source", 0),
            },
        }

    return {"error": f"Type de modification inconnu : {result_type}"}


SUGGEST_PROMPT = """\
Tu es un assistant expert en SQL Server intégré dans un tableau de bord comptable. \
L'utilisateur a cliqué sur une cellule vide et tapé "=" pour obtenir des suggestions.

Tu vois la feuille active avec ses cellules existantes (labels, valeurs, SQL sources) \
et les onglets ouverts avec leurs requêtes SQL et aperçus de données.

Propose exactement 6 suggestions de valeurs calculables à partir des données EXISTANTES. \
Chaque suggestion = une phrase courte en français décrivant CE QUE la cellule devrait contenir.

Réponds UNIQUEMENT avec un JSON valide :
```json
{"suggestions": ["suggestion 1", "suggestion 2", ...]}
```

## Raisonnement par position

La cellule vide est au croisement d'une LIGNE et d'une COLONNE. Avant de suggérer :
1. Regarde le label de la LIGNE (cellule la plus à gauche sur la même ligne)
2. Regarde le header de la COLONNE (cellule en haut de la même colonne)
3. Regarde les cellules VOISINES remplies — leur valeur ET leur SQL source/match
4. La suggestion #1 doit correspondre EXACTEMENT à ce croisement ligne×colonne

## Règles

- **Suggestion 1** = la valeur la plus évidente pour ce croisement ligne×colonne
- **Suggestions 2-3** = variantes du même croisement (filtres différents, somme vs détail)
- **Suggestions 4-5** = agrégations utiles (total ligne, total colonne, pourcentage)
- **Suggestion 6** = analytique (écart, ratio, comparaison)
- Propose UNIQUEMENT des calculs réalisables avec les colonnes SQL visibles dans les onglets
- N'invente JAMAIS de concepts absents des données (pas de "budget", "prévisionnel", \
"objectif", "tendance" sauf si ces mots existent dans les colonnes/labels)
- Utilise les VRAIS noms de colonnes/valeurs visibles
- Sois concret et spécifique, pas de formulations vagues ou génériques
"""


async def suggest_cell_values(
    column_name: str,
    cell_position: Optional[Dict[str, Any]] = None,
    columns: Optional[List[str]] = None,
    sheet_content: Optional[List[Dict[str, Any]]] = None,
    tabs_context: Optional[List[Dict[str, Any]]] = None,
    user_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Génère des suggestions LLM pour remplir une cellule.

    Si le sheet analyzer détermine la signification de la cellule avec confiance,
    retourne 1 seule suggestion (détermination) sans appeler le LLM.
    Sinon, fallback vers 6 suggestions via LLM.

    ``user_id`` (optionnel) : identifiant de l'utilisateur pour injection du
    bloc "À propos de l'utilisateur" dans le prompt LLM quand on passe en
    fallback LLM. ``None`` (tests, callers internes) → pas de bloc.
    """
    await ensure_providers_from_db()

    # Profil user pour injection en suffixe du SUGGEST_PROMPT lors de
    # l'appel LLM. Chargé seulement si on s'y rend (early-return
    # déterministe court-circuite le coût BDD si l'analyzer suffit).
    from app.services.ai.user_context import (
        build_user_profile,
        render_user_context_block,
    )

    # Tenter la détermination programmatique (E0b)
    if sheet_content and cell_position:
        target_row = cell_position.get("row")
        target_col = column_name or cell_position.get("col", "")
        distinct_values = await _get_distinct_values(tabs_context, user_id=user_id)

        active_tab_label = None
        if tabs_context:
            for tab in tabs_context:
                if tab.get("is_active"):
                    active_tab_label = tab.get("label")
                    break

        analysis = analyze_sheet(sheet_content, tabs_context, active_tab_label, distinct_values)
        # L'analyse programmatique donne un sens approximatif de la
        # cellule, mais les suggestions LLM sont toujours meilleures.
        # On garde le meaning comme première suggestion parmi les 6.
        if analysis.confidence >= 0.5 and analysis.empty_cells:
            for cell_meaning in analysis.empty_cells:
                if cell_meaning.row == target_row and cell_meaning.col == target_col:
                    logger.info(
                        "Sheet analyzer hint for [%s, %s]: %s",
                        target_row,
                        target_col,
                        cell_meaning.meaning,
                    )
                    break

    # Fallback : appel LLM pour 6 suggestions
    # ── Même format de contexte riche que modify_result / auto-fill ──
    # Le LLM voit les onglets (SQL + aperçu), les cellules structurées en JSON,
    # et la position exacte de la cellule cible.

    has_sql_context = tabs_context and any(tab.get("sql") for tab in tabs_context)
    schema_context = ""
    if not has_sql_context:
        all_table_names: set = set()
        if tabs_context:
            for tab in tabs_context:
                tab_sql = tab.get("sql", "")
                if tab_sql:
                    all_table_names.update(_extract_table_names(tab_sql))
        if all_table_names:
            # Phase α.4 — propager user_id.
            schema_context = await _get_schema_context(sorted(all_table_names), user_id=user_id)

    user_parts = []

    # Onglets ouverts — même format que modify_result (SQL + colonnes + aperçu)
    if tabs_context:
        tab_parts = []
        for i, tab in enumerate(tabs_context):
            tab_sql = tab.get("sql", "")
            tab_label = tab.get("label", f"Onglet {i + 1}")
            tab_cols = tab.get("columns", [])
            row_count = tab.get("row_count", 0)
            is_active = tab.get("is_active", False)
            marker = " **(onglet actif)**" if is_active else ""
            entry = f"### {tab_label} ({row_count} lignes){marker}"
            if tab_cols and tab_sql:
                entry += f"\nColonnes : {', '.join(tab_cols)}"
            if tab_sql:
                entry += f"\n```sql\n{tab_sql}\n```"
            col_distinct = tab.get("col_distinct")
            if col_distinct and isinstance(col_distinct, dict):
                lines = []
                for col_name, info in col_distinct.items():
                    if not isinstance(info, dict):
                        continue
                    if info.get("type") == "numeric":
                        lines.append(
                            f"{col_name}: {info['distinct']} valeurs numériques "
                            f"(min={info['min']}, max={info['max']})"
                        )
                    else:
                        vals = info.get("values", [])
                        vals_str = ", ".join(str(v) for v in vals)
                        suffix = ""
                        if info.get("truncated"):
                            suffix = f" (+{info['distinct'] - len(vals)} autres)"
                        lines.append(f"{col_name}: {vals_str}{suffix}")
                if lines:
                    entry += "\n**Aperçu** :\n" + "\n".join(lines)
            tab_parts.append(entry)
        user_parts.append("## Onglets ouverts\n" + "\n\n".join(tab_parts))

    # Cellules existantes — format JSON structuré (même que auto-fill)
    if sheet_content:
        sheet_json = _build_structured_sheet_json(sheet_content)
        if sheet_json:
            user_parts.append(
                f"## Cellules existantes (feuille active)\n```json\n{sheet_json}\n```"
            )
        else:
            user_parts.append("## Feuille vide\nAucune cellule remplie.")
    else:
        user_parts.append("## Feuille vide\nAucune cellule remplie.")

    # Cellule cible
    pos_info = ""
    if cell_position:
        pos_info = (
            f" (ligne {cell_position.get('row', '?')}, "
            f"colonne {column_name or cell_position.get('col', '?')})"
        )
    user_parts.append(f"## Cellule à remplir{pos_info}")

    if schema_context:
        user_parts.append(f"## Schéma des tables\n{schema_context}")

    user_prompt = "\n\n".join(user_parts) if user_parts else "Aucun contexte disponible."

    # Bloc profil user injecté en suffixe du SUGGEST_PROMPT. Chargé ici (pas
    # au début) pour court-circuiter le lookup BDD quand l'analyzer tranche
    # programmatiquement en amont (early-return).
    user_profile = await build_user_profile(user_id)
    user_context_block = render_user_context_block(user_profile)
    suggest_prompt_final = SUGGEST_PROMPT
    if user_context_block:
        suggest_prompt_final = SUGGEST_PROMPT + "\n\n" + user_context_block

    request = LLMRequest(
        prompt=user_prompt,
        system=suggest_prompt_final,
        model=COPILOT_MODEL,
        temperature=0.5,
        max_tokens=clamped_max_tokens(1024),
    )

    try:
        response, suggest_restore_fn = await _call_llm_anon(
            CallProfile(
                caller="copilot_cell_cleanup",
                retry=RetryPolicy.NONE,
                fallback_policy=FallbackPolicy.NONE,
            ),
            request,
            user_id,
        )
    except LLMCallError as exc:
        # Cas IA non configurée : retour structuré pour que le handler
        # surface un toast FR clair à l'utilisateur, plutôt qu'un
        # ``suggestions: []`` silencieux qu'on prendrait pour « pas
        # de suggestion pertinente trouvée ».
        if getattr(exc, "kind", None) == "not_configured":
            logger.info("Suggest skip — IA non configurée")
            return {
                "suggestions": [],
                "skipped": True,
                "reason": "not_configured",
                "message": str(exc),
            }
        logger.error("LLM suggest failed: %s", exc, exc_info=True)
        return {"suggestions": []}
    except Exception as exc:
        logger.error("LLM suggest failed: %s", exc, exc_info=True)
        return {"suggestions": []}

    # Restore proxy tokens (`§…§` + `[TYPE_N]`) avant parsing JSON :
    # les suggestions peuvent contenir des valeurs (noms de colonnes,
    # exemples) qui ont été tokenisées à l'envoi.
    suggest_content_clear = suggest_restore_fn(response.content)
    parsed = _parse_llm_response(suggest_content_clear)
    if parsed and isinstance(parsed.get("suggestions"), list):
        return {"suggestions": parsed["suggestions"][:8]}

    return {"suggestions": []}
