"""Compression déterministe d'historique de boucle d'outils LLM (SSoT partagée).

Quand un agent enchaîne beaucoup de tours d'outils (`copilot_agent`,
`report_planner_agent`, …), l'historique `messages` cumulé peut dépasser le
context window du modèle — ou, sur un compte à faible rate-limit (Anthropic
Tier 1 = 50k tokens/min), déclencher un 429. Cette compression remplace les
vieux `tool_result` volumineux par leurs métadonnées (déterministe, SANS appel
LLM secondaire), en gardant les N derniers messages intacts.

Extrait de `report_planner_agent.py` (la factorisation `agent_tool_loop.py`
partagée évoquée dans son docstring, décision 2026-05-09) pour que toutes les
boucles d'outils partagent UNE implémentation — pas de copie divergente.

Vit dans `app/services/ai/` car `reporting/` dépend déjà de `ai/` (sens unique) :
les deux packages peuvent importer ici sans cycle. Le free-loop Iris
(`agent_service.IrisAgent._compress_tool_loop_if_needed`) garde sa propre
variante (méthode liée à `self._compress_tool_content`) — convergence ultérieure
possible, hors scope.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

#: Pourcentage du budget input du modèle au-delà duquel on compresse. 75%
#: laisse une marge confortable pour la réponse + le system prompt. Aligné sur
#: ``agent_service`` (Iris) et l'historique ``report_planner``.
_COMPRESS_TRIGGER_PCT = 0.75

#: Nombre de messages récents GARDÉS INTACTS. 10 ≈ 5 paires (assistant +
#: user/tool_results) → visibilité fine sur les 5 derniers tours.
_COMPRESS_KEEP_RECENT = 10

#: Taille minimale (chars) au-delà de laquelle un tool_result vaut la peine
#: d'être compressé.
_TOOL_RESULT_COMPRESSIBLE_LEN = 500


def _estimate_messages_tokens(messages: List[Dict[str, Any]]) -> int:
    """Estimation rough des tokens cumulés (4 chars ≈ 1 token, latin)."""
    total_chars = 0
    for m in messages:
        content = m.get("content", "")
        if isinstance(content, str):
            total_chars += len(content)
        else:
            try:
                total_chars += len(json.dumps(content, ensure_ascii=False, default=str))
            except (TypeError, ValueError):
                total_chars += len(str(content))
    return total_chars // 4


def _compress_tool_result_payload(raw: str) -> str:
    """Compresse un tool_result JSON en gardant l'essentiel (déterministe, sans
    appel LLM secondaire).

    On garde une ALLOWLIST de champs informationnels (status, ok, dataset_id,
    agg, groups_count, row_count, error, columns, hit_count…) et on drop les
    payloads volumineux (rows, groups, cells, distinct_sample). Le LLM voit
    qu'il a fait l'appel et son résultat de haut niveau, mais perd les détails
    fins (déjà consommés au tour où le tool a été appelé).

    ⚠️ L'allowlist est l'UNION des champs porteurs de TOUS les callers câblés
    (report_planner + copilot). Câbler une nouvelle boucle d'outils ⇒ vérifier
    que SES champs d'état/diagnostic y figurent, sinon ses vieilles étapes
    compressées deviennent ``{"_compressed": true}`` (état perdu).

    NB : on ne touche JAMAIS aux ``tool_use`` blocks (inputs du LLM) — contrat
    input/output côté API préservé.
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw[:_TOOL_RESULT_COMPRESSIBLE_LEN] + "...[compressed-trunc]"
    if not isinstance(data, dict):
        return raw[:_TOOL_RESULT_COMPRESSIBLE_LEN] + "...[compressed-trunc]"

    summary: Dict[str, Any] = {"_compressed": True}
    for key in (
        "ok",
        "success",
        "error",
        "reason",
        "dataset_id",
        "datasets",
        "label",
        "row_count",
        "row_count_total",
        "rows_returned",
        "rows_processed",
        "rows_filtered_out",
        "agg",
        "group_by",
        "value_column",
        "groups_count",
        "truncated",
        "truncation_warning",
        # Troncature SOURCE (≠ tool-level) : DOIT survivre à la compression,
        # sinon le caller perd l'info « agrégat partiel » et présente des
        # chiffres faux comme exhaustifs.
        "source_truncated",
        "source_truncation_warning",
        "rows_skipped_over_cap",
        "count",
        "total",
        "columns",
        "section_index",
        "total_sections",
        "stored_chars",
        "overwritten",
        "title",
        "sections_emitted",
        "has_intro",
        "next_start",
        # — Copilot (ask_iris / read_tab_rows / count_rows / aggregate / fill) :
        #   champs d'ÉTAT + diagnostic porteurs. L'allowlist est l'UNION des
        #   champs de TOUS les callers câblés (report_planner + copilot) —
        #   l'ÉTENDRE quand une nouvelle boucle est câblée, sinon une vieille
        #   étape compressée devient {"_compressed": true} (status/erreur perdus).
        #   Revue B1-F2/X-1/B1-F3. Tous scalaires/petites listes ou dicts → les
        #   gros payloads (rows/cells/groups) restent droppés ; ``sql``/listes
        #   sont tronqués par la logique ci-dessous.
        "status",
        "sql",
        "errors",
        "schema_suggestions",
        "blocked_by",
        "tab_index",
        "hit_count",
        "exclude_hits",
        "matched",
        "written",
    ):
        if key in data:
            value = data[key]
            if isinstance(value, list) and len(value) > 30:
                summary[key] = value[:30]
                summary[f"{key}_truncated_count"] = len(value)
            elif isinstance(value, str) and len(value) > 200:
                summary[key] = value[:200] + "..."
            else:
                summary[key] = value
    # On droppe explicitement les gros payloads (rows, groups, cells, sample).
    return json.dumps(summary, ensure_ascii=False, default=str)


def _maybe_compress_messages(
    messages: List[Dict[str, Any]],
    *,
    context_window: int,
    reserved_output: int,
    caller: str = "llm-agent",
) -> int:
    """Compresse les vieux tool_results IN-PLACE si ``messages`` dépasse
    ``_COMPRESS_TRIGGER_PCT`` du budget input. Garde les
    ``_COMPRESS_KEEP_RECENT`` derniers messages intacts.

    Args:
        messages: liste de messages (mutée IN-PLACE).
        context_window: fenêtre du modèle actif (cf. constants_ai).
        reserved_output: tokens réservés pour la réponse (effort["max_tokens"]).
        caller: étiquette pour le log (ex: "copilot", "report_planner").

    Returns:
        Nombre de blocs compressés (0 si pas nécessaire). Loggé en INFO.
    """
    if context_window <= 0 or reserved_output <= 0:
        return 0
    budget_input = max(1000, context_window - reserved_output)
    threshold = int(budget_input * _COMPRESS_TRIGGER_PCT)
    estimated = _estimate_messages_tokens(messages)
    if estimated < threshold:
        return 0

    end_idx = max(0, len(messages) - _COMPRESS_KEEP_RECENT)
    if end_idx == 0:
        return 0  # tout est récent, rien à compresser

    compressed = 0
    for i in range(end_idx):
        msg = messages[i]
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") != "tool_result":
                continue  # JAMAIS toucher aux tool_use
            raw = block.get("content", "")
            if not isinstance(raw, str) or len(raw) <= _TOOL_RESULT_COMPRESSIBLE_LEN:
                continue
            block["content"] = _compress_tool_result_payload(raw)
            compressed += 1

    if compressed:
        new_estimated = _estimate_messages_tokens(messages)
        logger.info(
            "%s: compression mid-loop — %d blocs compressés, "
            "~%d tokens → ~%d tokens (seuil %d, budget %d)",
            caller,
            compressed,
            estimated,
            new_estimated,
            threshold,
            budget_input,
        )
    return compressed
