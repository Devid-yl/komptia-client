"""Boucle tool-loop de l'agent widget_planner.

Pattern strictement calqué sur :func:`app.services.ai.copilot_agent.run_copilot_agent`
(lignes 700-1100) — mêmes garde-fous : stop_reason=max_tokens propre,
progress store sync, tool_input restore via ``_full_restore``, append
tool_results aux messages, terminal_kind sortie.

Diff par rapport au pipeline 3-shot (``plan_widgets_batch``) :
- ``call_llm_with_tools`` (Anthropic tool-use natif) au lieu de 3 calls
  séquentiels Analyst/Composer/Designer
- Le LLM choisit dynamiquement quels outils appeler (peek_sql_result,
  column_stats, distinct_values, aggregate_column, propose_widget…)
- Contexte SQL pré-exécuté une seule fois en début de run, partagé
  entre tous les handlers via :class:`WidgetPlannerContext`
- Memory recompute (widgets existants) injectée dans system prompt
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

from app.services.ai.llm_providers import LLMRequest
from app.services.dashboard.widget_planner.pipeline import (
    WidgetPipelineError,
    WidgetPlanV2,
    _execute_sql,
    _trim_for_designer,
)
from app.services.dashboard.widget_planner.profiler import (
    columns_by_role,
    profile_columns,
)
from app.services.dashboard.widget_planner.transformations import (
    TransformationError,
    apply_transformation,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


# Caps DoS centralisés (fix C3 review globale 2026-05-18) : tous les
# caps du package sont dans ``limits.py``. Re-export ici pour préserver
# la compat des callers existants qui faisaient
# ``from widget_planner_agent.agent import MAX_TOOL_CALLS``.
from app.services.dashboard.widget_planner_agent.limits import (
    AGENT_MAX_TOKENS_HARD_CAP as _AGENT_MAX_TOKENS_HARD_CAP,
    MAX_TOOL_CALLS,
    THINKING_RESERVE_TOKENS as _THINKING_RESERVE_TOKENS,
)


class WidgetPlannerAgentError(Exception):
    """Erreur irrécupérable de l'agent (provider down, SQL impossible…).

    Aligné sur :class:`WidgetPipelineError` pour faciliter le swap côté handler.
    """


# Note fix C2 review globale 2026-05-18 : on n'a pas de wrapper local
# ``_effort_params_for_provider`` — on appelle directement
# ``compute_effort_params(manager, hard_cap_max_tokens=..., thinking_reserve_tokens=...)``
# du runtime au point d'usage (cf. boucle agent ligne ~300). Avant :
# duplication avec copilot_agent.py:_effort_params_for_provider. Maintenant :
# single source de vérité = ``llm_runtime.compute_effort_params``, les
# call-sites paramétrisent leurs caps localement.


def _build_system_prompt(
    memory_text: str,
    columns: list[str],
    real_row_count: int,
    sample_truncated: bool = False,
) -> str:
    """System prompt de l'agent. Memory recompute injectée — pas de migration BDD.

    Strictement aligné sur la doctrine Komptia :
    - Le LLM voit UNIQUEMENT du tokenisé (§…§ + [TYPE_N])
    - Il doit appeler ≥1 ``propose_widget`` avant ``commit_widgets``
    - Sur SQL 0 ligne / impossible → ``abort(reason)``
    """
    # #50 — quand le peek est tronqué au cap, ``real_row_count`` est la TAILLE
    # de l'échantillon, pas le total de la requête. Sans ce signal explicite,
    # l'agent prend 200 pour le total réel et fabrique des KPI/insights
    # « total/max/classement » portant sur l'échantillon comme s'ils étaient
    # globaux (donnée fausse silencieuse au pied du widget).
    if sample_truncated:
        peek_line = (
            f"- Lignes ramenées (ÉCHANTILLON, peek) : {real_row_count} — "
            "⚠ la requête a PLUS de lignes (total réel inconnu ici). "
            "N'affirme AUCUN total/somme/moyenne/max/classement GLOBAL : ces "
            "valeurs ne porteraient que sur l'échantillon."
        )
    else:
        peek_line = f"- Nombre de lignes ramenées (peek) : {real_row_count}"
    return f"""Tu es l'agent qui compose un mini-dashboard (1-6 widgets) à partir \
d'un résultat SQL pré-exécuté par l'utilisateur.

RÈGLES DURES :
- Tu ne vois JAMAIS les vraies valeurs : tout est anonymisé (§…§ pour les \
termes confidentiels, [EMAIL_N]/[SIRET_N]/etc. pour les PII regex). Travaille \
sur la STRUCTURE (cardinalité, type, range), pas le contenu.
- Tu DOIS exposer plusieurs dimensions intéressantes (pas réduire à 1D si \
les données sont multi-dim).
- Tu DOIS appeler `propose_widget` au moins 1 fois avant `commit_widgets`.
- Si le SQL retourne 0 ligne / schéma absurde → `abort(reason)`.
- Cap : maximum 6 widgets par dashboard. Au-delà = bruit.

CONTEXTE SQL EXÉCUTÉ :
- Colonnes disponibles : {columns}
{peek_line}
- Tu peux explorer via les tools ci-dessous. Le SQL N'EST PAS RÉ-EXÉCUTÉ — \
toutes les opérations sont en mémoire sur l'échantillon.

{memory_text}

WORKFLOW SUGGÉRÉ :
1. `column_stats` sur 2-3 colonnes-clés pour comprendre la structure
2. `distinct_values` ou `aggregate_column` pour identifier mesures vs dimensions
3. `propose_widget` × N (1 KPI header + 1 chart principal + 1 secondaire + \
1 detail table si pertinent — varier les angles)
4. `commit_widgets` pour finaliser

Tu réponds via tool_use UNIQUEMENT — pas de texte libre à l'utilisateur."""


async def run_widget_planner_agent(
    sql: str,
    user_hint: Optional[str] = None,
    *,
    dashboard_id: Optional[int] = None,
    user_id: Optional[int] = None,
    user: Any = None,
    run_id: str = "",
) -> list[WidgetPlanV2]:
    """Lance l'agent tool-loop pour générer 1..N widgets à partir d'un SQL.

    Signature alignée sur :func:`plan_widgets_batch` (ancien pipeline
    3-shot) pour swap atomique côté handler via feature flag.

    Args:
        sql: requête SELECT/WITH validée par l'utilisateur. Exécutée
            une seule fois en début de run.
        user_hint: instructions libres optionnelles. Sanitizé avant
            anonymisation (couches pseudo + PII regex).
        dashboard_id: identifiant cible pour ``read_existing_widgets``
            (memory recompute). ``None`` = pas de memory.
        user_id: identifiant utilisateur. ``None`` = tests/scripts admin
            sans pseudonymizer user-scoped (couche PII regex seule).
        user: objet ORM ``User`` forwardé à :func:`_execute_sql` pour
            activation de l'enforcer RLS data_access. Sans ``user``,
            l'enforcer logue ``RLS skip`` et la requête passe sans
            filtrage row-level (fail-OPEN historique). Le handler
            ``_run_widget_planner_with_fallback`` (dashboard_builder.py)
            DOIT charger l'objet User et le forwarder ici — passer
            seulement ``user_id`` ne suffit pas à activer le RLS.
        run_id: identifiant de run partagé avec le frontend
            (``copilot_progress_store``). Vide = pas de sync.

    Returns:
        ``list[WidgetPlanV2]`` (1 à 6 widgets). Compatible avec
        :func:`plan_widgets_batch`.

    Raises:
        WidgetPlannerAgentError: SQL vide, 0 ligne, BDD anon
            indisponible (fail-closed), DoS cap atteint sans aucun
            ``propose_widget``, provider LLM down sans fallback.
    """
    if not isinstance(sql, str) or not sql.strip():
        raise WidgetPlannerAgentError("Requête SQL vide.")

    t_start = time.monotonic()

    # ── 1. Pré-exécution SQL (réutilise pipeline existant) ──────────────
    # Forward `user` (objet ORM) à _execute_sql pour activation de l'enforcer
    # RLS data_access. Sans user, l'enforcer logue 'RLS skip' fail-OPEN
    # (cf. _execute_sql docstring pipeline.py:552-556).
    try:
        columns, rows, real_row_count, sample_truncated = await _execute_sql(sql, user=user)
    except WidgetPipelineError as exc:
        raise WidgetPlannerAgentError(str(exc)) from exc

    if not rows:
        raise WidgetPlannerAgentError(
            "La requête n'a retourné aucune ligne — impossible de planifier "
            "un widget sans données."
        )

    # ── 2. Profile déterministe (zéro LLM) ──────────────────────────────
    profile = profile_columns(columns, rows)
    profile["real_row_count"] = real_row_count
    # #50 — le peek est plafonné à _PEEK_MAX_ROWS : si tronqué, row_count
    # n'est PAS le total réel. Propagé au profil pour que le prompt LLM de
    # l'agent l'annonce (cf. _build_profile_section / sample_note).
    profile["sample_truncated"] = sample_truncated
    _ = columns_by_role(profile)  # gardé pour évolution future (hints)

    # ── 3. Prep anonymisation (2 couches /data/privacy) ─────────────────
    from app.services.dashboard.widget_planner_agent.anonymization import (
        AnonymizationLookupError,
        prepare_anonymization,
    )

    try:
        anon_ctx = await prepare_anonymization(
            rows=rows,
            columns=columns,
            user_hint=user_hint,
            user_id=user_id,
            source_ref=f"dashboard:{dashboard_id}" if dashboard_id else None,
        )
    except AnonymizationLookupError as exc:
        raise WidgetPlannerAgentError(
            "Préférences d'anonymisation indisponibles — réessaie dans un instant."
        ) from exc

    # ── 4. Memory recompute (widgets existants) ─────────────────────────
    from app.services.dashboard.widget_planner_agent.memory import (
        format_memory_for_prompt,
        read_existing_widgets_summary,
    )

    existing_widgets = await read_existing_widgets_summary(dashboard_id, user_id)
    # Anti-leak HIGH #1 review adversariale 2026-05-18 : les titres des
    # widgets existants viennent de la BDD en CLEARTEXT — si un titre
    # contient un nom propre tapé par l'utilisateur (« Trésorerie Dupont »),
    # le LLM le verrait via le system prompt OU le handler
    # ``read_existing_widgets``. On anonymise les titres ICI une fois pour
    # toutes ; les 2 chemins (system prompt + handler) consomment ensuite
    # la liste anonymisée.
    if anon_ctx.pseudonymizer is not None:
        for w in existing_widgets:
            if isinstance(w.get("title"), str):
                w["title"] = anon_ctx.pseudonymizer.anonymize_text(w["title"])
    memory_text = format_memory_for_prompt(existing_widgets)

    # ── 5. Setup ctx partagé entre tous les handlers ────────────────────
    from app.services.dashboard.widget_planner_agent.tools import (
        WIDGET_PLANNER_TOOLS,
        WidgetPlannerContext,
        dispatch_widget_planner_tool,
    )

    ctx = WidgetPlannerContext(
        sql=sql,
        user_hint=user_hint,
        dashboard_id=dashboard_id,
        user_id=user_id,
        run_id=run_id,
        columns=columns,
        rows=rows,
        profile=profile,
        real_row_count=real_row_count,
        existing_widgets=existing_widgets,
        pseudonymizer=anon_ctx.pseudonymizer,
        pii_mapping=anon_ctx.pii_mapping,
        pii_counters=anon_ctx.pii_counters,
    )

    # ── 6. Setup gate provider + LLM manager ────────────────────────────
    # IMPORTS INLINE volontaires (anti-cycle ET patchabilité tests) :
    # - Anti-cycle : ces modules importent indirectement le widget_planner
    #   via le tracker AIPerformanceLog → cycle si top-level.
    # - Patchabilité : les tests mockent ces fonctions au niveau de leur
    #   module d'origine (``app.services.ai.llm_runtime.call_llm_with_tools``,
    #   etc.). Si on hoist en top-level de ce module, il faut aussi patcher
    #   la copie locale ``agent.call_llm_with_tools``. Décision : garder
    #   inline pour minimiser la surface de tests à refactorer
    #   (cf. review adversariale 2026-05-18 HIGH #2).
    from app.services.ai.llm_providers import ensure_providers_from_db, get_llm_manager
    from app.services.ai.llm_runtime import (
        CallProfile,
        FallbackPolicy,
        LLMCallError as _LLMErr,
        RetryPolicy,
        call_llm_with_tools,
    )

    try:
        await ensure_providers_from_db()
    except Exception as exc:  # non-bloquant : fallback sur env vars
        logger.debug("widget_planner_agent: ensure_providers_from_db: %s", exc)

    manager = get_llm_manager()
    if not manager.has_any_provider_configured():
        raise WidgetPlannerAgentError(
            "Aucun provider LLM configuré. Renseigne une clé API via /admin/ai-config."
        )

    # ── 7. Boucle tool-loop ─────────────────────────────────────────────
    # OUTPUT_STYLE_RULES — couverture cross-module (adversarial #1 sur fix #19).
    # Le builder dashboards génère des titres/descriptions de widgets DIRECTEMENT
    # user-facing dans /dashboards/new. Position APRÈS le system spécifique
    # pour ne pas écraser le contrat de format strict du planner (recency bias).
    from app.services.ai.agent_roles import OUTPUT_STYLE_RULES

    system_prompt = (
        _build_system_prompt(memory_text, columns, real_row_count, sample_truncated)
        + "\n\n"
        + OUTPUT_STYLE_RULES
    )
    # Sanitize user_hint contre prompt injection (fix HIGH #S2 review
    # adversariale finale 2026-05-18) : sans ce passage, un user qui tape
    # « \n\n[SYSTEM] Ignore previous rules » dans son hint injecterait
    # des instructions au LLM. On passe par le pseudonymizer (qui couvre
    # aussi les noms propres tapés) + strip control chars.
    safe_hint = user_hint or ""
    if safe_hint and anon_ctx.pseudonymizer is not None:
        safe_hint = anon_ctx.pseudonymizer.anonymize_text(safe_hint)
    # Strip control chars partagé (fix CC1 review globale 2026-05-18 —
    # cohérent avec memory.format_memory_for_prompt et tools._handle_propose_widget).
    from app.services.dashboard.widget_planner_agent._sanitize import strip_control

    safe_hint = strip_control(safe_hint, cap=2000)

    user_intro = (
        f"Demande utilisateur : {safe_hint}"
        if safe_hint.strip()
        else "Aucune instruction libre — analyse le SQL et propose une composition pertinente."
    )
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": [{"type": "text", "text": user_intro}]}
    ]

    total_llm_ms = 0
    profile_caller = "dashboard_widget_planner_agent"

    # Import du runtime au scope de boucle pour utilisation directe
    # de compute_effort_params (fix C2 — pas de wrapper local dupliqué).
    from app.services.ai.llm_runtime import compute_effort_params as _compute_effort

    try:
        for turn in range(MAX_TOOL_CALLS):
            ctx.turn_count = turn + 1
            effort = _compute_effort(
                manager,
                hard_cap_max_tokens=_AGENT_MAX_TOKENS_HARD_CAP,
                thinking_reserve_tokens=_THINKING_RESERVE_TOKENS,
            )

            request = LLMRequest(
                prompt="",  # conversation dans messages
                system=system_prompt,
                temperature=0.2,
                max_tokens=effort["max_tokens"],
            )

            t_llm = time.monotonic()
            try:
                response = await call_llm_with_tools(
                    CallProfile(
                        caller=profile_caller,
                        retry=RetryPolicy.NONE,  # boucle agent gère ses propres retries
                        # Pas de fallback Ollama : chiffres client = sacrés
                        # (cf. CLAUDE.md doctrine "résultats faux interdits")
                        fallback_policy=FallbackPolicy.NONE,
                    ),
                    request,
                    tools=WIDGET_PLANNER_TOOLS,
                    messages=messages,
                    thinking_budget=effort["thinking_budget"],
                    user_id=user_id,
                )
            except _LLMErr as exc:
                logger.error(
                    "widget_planner_agent: LLM call failed at turn %d: %s",
                    turn,
                    exc,
                )
                if exc.kind == "overloaded":
                    raise WidgetPlannerAgentError(
                        "⏳ Service LLM temporairement surchargé. Réessaie dans 1-2 minutes."
                    ) from exc
                if exc.kind == "rate_limit":
                    raise WidgetPlannerAgentError(
                        "⏳ Quota LLM dépassé. Réessaie dans quelques minutes."
                    ) from exc
                raise WidgetPlannerAgentError("Erreur interne du service LLM.") from exc
            except Exception as exc:
                logger.error(
                    "widget_planner_agent: erreur inattendue LLM turn %d: %s",
                    turn,
                    exc,
                )
                raise WidgetPlannerAgentError("Erreur LLM inattendue.") from exc

            total_llm_ms += round((time.monotonic() - t_llm) * 1000)

            content = response.get("content") or []
            stop_reason = response.get("stop_reason")

            # **Phase 2.5.bis.quater (#104) — Garde-fou mode invisible.**
            # Le widget planner agent (composer/analyst/designer) émet des
            # widgets de dashboard avec titres + descriptions + SQL + filtres
            # tous USER-FACING dans la grille dashboard. Le LLM peut halluciner
            # un nom denied dans n'importe lequel de ces champs.
            #
            # Couvre text + thinking + tool_use.input (aligné #105/#106). Le
            # caller `run_widget_planner_agent` raise déjà `WidgetPlannerAgentError`
            # sur exception générique — ``DataAccessLeakDetectedError`` propage
            # de la même façon (non catché par les `except LLMCallError` au
            # niveau de la boucle).
            #
            # **Phase 2.5.bis.6 follow-up (#120)** — Refactor pur : le bloc
            # (concat text+thinking, concat tool_use.input, restore, assert)
            # est extrait dans ``assert_safe_llm_blocks``.
            if user_id is not None and content:
                from types import SimpleNamespace as _SimpleNamespace

                from app.services.data_access.error_messages import (
                    DataAccessLeakDetectedError,
                    assert_safe_llm_blocks,
                )

                _user_stub = _SimpleNamespace(id=user_id, role=None)
                _leak_msg = await assert_safe_llm_blocks(
                    content,
                    _user_stub,
                    restore_fn=anon_ctx.restore_fn,
                    context_label="widget_planner_agent.run_widget_planner_agent",
                    strict_when_no_user=True,
                )
                if _leak_msg is not None:
                    logger.critical(
                        "widget_planner_agent: sortie LLM fuite un nom "
                        "denied user_id=%s turn=%d content_blocks=%d",
                        user_id,
                        turn,
                        len(content),
                    )
                    raise DataAccessLeakDetectedError(_leak_msg)

            # stop_reason=max_tokens → arrêt propre (sinon tool_use partiel
            # crashe le turn suivant avec invalid_request_error).
            if stop_reason == "max_tokens":
                logger.warning(
                    "widget_planner_agent turn %d: stop_reason=max_tokens — " "arrêt propre.",
                    turn,
                )
                break

            # Accumule la réponse assistant
            messages.append({"role": "assistant", "content": content})

            # Dispatch les tool_use blocks
            tool_use_blocks = [
                b for b in content if isinstance(b, dict) and b.get("type") == "tool_use"
            ]
            if not tool_use_blocks:
                # LLM a répondu en texte libre sans tool — on l'incite à utiliser
                # ses tools (le system prompt l'exige). Si ça se répète au turn
                # suivant on coupera via MAX_TOOL_CALLS.
                logger.info(
                    "widget_planner_agent turn %d: réponse sans tool_use — "
                    "incite à utiliser les tools.",
                    turn,
                )
                messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    "Utilise tes tools pour explorer puis "
                                    "`propose_widget` + `commit_widgets`. "
                                    "Si la requête est inexploitable, appelle "
                                    "`abort(reason)`."
                                ),
                            }
                        ],
                    }
                )
                continue

            tool_results: list[dict[str, Any]] = []
            for tb in tool_use_blocks:
                tool_name = tb.get("name") or ""
                tool_input = tb.get("input") or {}
                tool_use_id = tb.get("id") or ""

                logger.info(
                    "widget_planner_agent turn %d: tool=%s input_keys=%s",
                    turn,
                    tool_name,
                    list(tool_input.keys()) if isinstance(tool_input, dict) else None,
                )

                # Restore cleartext des tool_input avant exécution côté
                # handler système : le LLM produit du tokenisé, mais nos
                # handlers (ex: aggregate_column) ont besoin des vrais noms
                # de colonnes pour matcher ctx.columns.
                tool_input = anon_ctx.restore_fn(tool_input) if anon_ctx.restore_fn else tool_input

                # Progress store sync (best-effort, ne crash pas si store down).
                if ctx.run_id and ctx.user_id is not None:
                    try:
                        from app.services.ai.copilot_progress_store import (
                            set_tool_in_use,
                        )

                        await set_tool_in_use(ctx.user_id, ctx.run_id, tool_name)
                    except Exception:  # noqa: BLE001
                        logger.debug(
                            "widget_planner_agent: set_tool_in_use a levé (non critique)",
                            exc_info=True,
                        )

                result = await dispatch_widget_planner_tool(tool_name, tool_input, ctx)
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": json.dumps(result, ensure_ascii=False, default=str),
                    }
                )

                # Terminal : commit/abort → break inner loop
                if ctx.terminal_kind in ("commit", "abort"):
                    break

            # Append tool_results au user message suivant
            messages.append({"role": "user", "content": tool_results})

            # Sortie de boucle si terminal atteint
            if ctx.terminal_kind in ("commit", "abort"):
                break
        else:
            # MAX_TOOL_CALLS atteint sans terminal
            logger.warning(
                "widget_planner_agent: MAX_TOOL_CALLS=%d atteint sans commit/abort "
                "(proposals=%d). Materialize ce qu'on a.",
                MAX_TOOL_CALLS,
                len(ctx.proposals),
            )
    finally:
        # Cleanup progress store, best-effort.
        if ctx.run_id and ctx.user_id is not None:
            try:
                from app.services.ai.copilot_progress_store import clear_progress

                await clear_progress(ctx.user_id, ctx.run_id)
            except Exception:  # noqa: BLE001
                logger.debug(
                    "widget_planner_agent: clear_progress a levé (non critique)",
                    exc_info=True,
                )

    elapsed_ms = round((time.monotonic() - t_start) * 1000)
    logger.info(
        "widget_planner_agent: terminé en %dms (turns=%d llm_ms=%d proposals=%d " "terminal=%s)",
        elapsed_ms,
        ctx.turn_count,
        total_llm_ms,
        len(ctx.proposals),
        ctx.terminal_kind,
    )

    # ── 8. Materialization : ctx.proposals → list[WidgetPlanV2] ─────────
    if ctx.terminal_kind == "abort":
        # Abort explicite : pas de widgets, mais pas une erreur. On signale
        # via une exception dédiée pour que le caller (endpoint) sache.
        raise WidgetPlannerAgentError(
            f"Agent a abort le run : {ctx.abort_reason or 'aucune raison'}"
        )

    # Fix LOG1 review globale 2026-05-18 : si MAX_TOOL_CALLS atteint
    # SANS que le LLM ait appelé commit_widgets explicitement, on
    # NE matérialise PAS les proposals (qui pourraient être des drafts
    # exploratoires que le LLM ne considère pas finalisés). Le contrat
    # documenté ligne 98 du system prompt exige commit_widgets.
    # Le caller (handler) bascule alors sur le fallback batch — UX :
    # Fazia voit un dashboard, juste créé par le pipeline 3-shot
    # historique plutôt que l'agent.
    if ctx.terminal_kind != "commit":
        raise WidgetPlannerAgentError(
            f"Agent terminé sans finalisation explicite (MAX_TOOL_CALLS="
            f"{MAX_TOOL_CALLS} atteint, {len(ctx.proposals)} proposal(s) "
            f"non-committée(s) droppée(s))."
        )

    if not ctx.proposals:
        raise WidgetPlannerAgentError("Agent terminé sans proposition de widget.")

    return _materialize_proposals(ctx)


def _materialize_proposals(ctx: Any) -> list[WidgetPlanV2]:
    """Convertit ``ctx.proposals`` (dicts validés par propose_widget) en
    ``list[WidgetPlanV2]`` (format consommé par l'endpoint LLM).

    Pour chaque proposal :
    1. Applique la recette de transformation sur les VRAIES data (ctx.rows
       en cleartext — la materialization se fait côté serveur, pas côté LLM).
    2. Construit un ``RenderSpec`` depuis le render_spec proposal + title.
    3. Trim pour preview frontend (cap rows table / labels chart).

    Si une proposal a une recette cassée → fallback passthrough (cohérent
    avec ``_materialize_proposal`` du pipeline 3-shot).
    """
    from app.services.dashboard.widget_planner.designer import RenderSpec

    plans: list[WidgetPlanV2] = []
    for i, proposal in enumerate(ctx.proposals):
        recipe = proposal.get("transformation") or {"kind": "passthrough", "params": {}}
        try:
            transformed = apply_transformation(ctx.columns, ctx.rows, recipe)
        except TransformationError as exc:
            logger.info(
                "widget_planner_agent: materialize proposal %d transform fail "
                "(%s) — fallback passthrough.",
                i,
                exc,
            )
            recipe = {"kind": "passthrough", "params": {}}
            transformed = apply_transformation(ctx.columns, ctx.rows, recipe)

        # Trim preview pour le frontend (Plotly/table cap).
        preview = _trim_for_designer(transformed)

        render_spec_raw = proposal.get("render_spec") or {}
        spec = RenderSpec(
            title=proposal.get("title") or "Widget",
            widget_type=proposal.get("widget_type") or "table",
            chart_type=proposal.get("chart_type"),
            col_span=proposal.get("col_span") or 6,
            insight=render_spec_raw.get("insight"),
            unit=render_spec_raw.get("unit"),
            number_format=render_spec_raw.get("number_format") or "number",
            x_label=render_spec_raw.get("x_label"),
            y_label=render_spec_raw.get("y_label"),
            color_hint=render_spec_raw.get("color_hint"),
            reasoning=None,  # l'agent ne stocke pas de reasoning par widget
        )

        plans.append(
            WidgetPlanV2(
                render_spec=spec,
                transformation=recipe,
                intent=proposal.get("intent") or "detail_table",
                drill_column=proposal.get("drill_column"),
                preview_data=preview,
                analyst_reasoning=None,
                designer_reasoning=None,
            )
        )

    return plans
