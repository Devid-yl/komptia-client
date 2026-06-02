"""Agent tool-loop pour la planification de rapports IA.

Pattern emprunté à ``app/services/ai/copilot_agent.py:run_copilot_agent``
(boucle ``for turn in range(MAX_TURNS): call_llm_with_tools → dispatch →
append messages``) mais adapté au reporting :

* **Pas de mémoire run-to-run** (chaque rapport est indépendant).
* **Pas de pseudonymizer BDD** (passe par le proxy unifié
  :func:`app.services.anonymization.anonymize_for_llm` comme le mode oneshot
  — un seul appel au début, restore à la fin).
* **Pas de streaming** (POST simple, le frontend attend un PDF final).
* **Tools dédiés au reporting** : ``list_datasets``, ``inspect_dataset``,
  ``read_dataset_sample``, ``aggregate_dataset``, ``count_rows_dataset``,
  ``emit_report_intro``, ``emit_report_section``, ``finalize_report``.

Pourquoi ce mode plutôt que le oneshot existant ?
    Le mode oneshot (cf. :func:`app.services.reporting.llm_report_planner.plan_report`
    branche "non-agent") sérialise tous les datasets en markdown dans UN
    SEUL prompt, ce qui plafonne au ``max_input_tokens`` du modèle actif.
    Pour un classeur volumineux, la requête est rejetée. Avec ce tool-loop,
    le LLM accède aux données en **lazy** :

    - les rows ne sont JAMAIS envoyées d'un bloc dans le prompt initial
    - le LLM appelle ``aggregate_dataset`` (côté Python, scale O(n)) pour
      les analyses en gros
    - ``read_dataset_sample`` renvoie max 60 lignes par appel pour du
      "spot-check" ciblé

    Le caller (``plan_report``) choisit oneshot vs agent automatiquement
    selon la taille (cf. dispatcher hybride).

Le fichier est volontairement court (boucle ~60 lignes) et inspiré
directement de ``copilot_agent.py``. Une factorisation future en
``app/services/ai/agent_tool_loop.py`` partagé reste possible (cf.
discussion architecture du 2026-05-09 entre David et Claude — décision :
on ne migre pas les autres boucles maintenant, on prouve la valeur sur
le code neuf d'abord).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

from app.services.ai.llm_providers import LLMRequest, get_llm_manager
from app.services.ai.llm_runtime import (
    CallProfile,
    LLMCallError,
    RetryPolicy,
    call_llm_with_tools,
    compute_effort_params,
)
from app.services.anonymization import anonymize_for_llm
from app.services.anonymization.proxy import get_confidentiality_prompt
from app.services.reporting.report_planner_tools import (
    REPORT_TOOLS,
    ReportAgentState,
    dispatch_report_tool,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constantes — bornes du run.
#
# **Statut** (review #9 du 2026-05-09) : ces 3 valeurs sont des PROTECTIONS
# SERVEUR (pas des préférences user-tunable via /admin/...). Elles encadrent
# le comportement du runtime pour empêcher OOM/runaway. Si elles devaient
# évoluer, c'est un changement de design (justifié par observation) — pas
# une option à exposer dans une UI admin.
# ---------------------------------------------------------------------------

#: Nombre maximum de tours de boucle. Plus large que copilot (40) car la
#: planification d'un rapport multi-sections demande plus d'exploration
#: (inspect + aggregate + count + emit × N sections, jusqu'à 20 sections
#: cap dur). 80 est calé sur "20 sections × 4 tools/section en moyenne".
MAX_TURNS = 80

#: Cap mémoire HARD sur la taille totale (bytes) des rows accumulées sur
#: tous les datasets fournis. Au-delà, fail-fast avant tout appel LLM —
#: les agrégations Python ne tiendraient plus en RAM. 100 MB d'estimation
#: ≈ 200-400 MB réels (overhead Python). Cap dur protège du crash Tornado.
#: Configurable via env ``KOMPTIA_REPORT_MEMORY_CAP_MB`` (défaut 100) pour les
#: cabinets clients ayant des rapports volumineux légitimes — même pattern
#: que ``workbook_loader.MAX_LOAD_WORKBOOK_BYTES`` (doctrine zéro hardcode).
MEMORY_HARD_CAP_BYTES = int(os.environ.get("KOMPTIA_REPORT_MEMORY_CAP_MB", "100")) * 1024 * 1024

#: Soft default pour ``max_tokens`` de la réponse LLM (chaque turn). Clampé
#: au cap du modèle via :func:`clamped_max_tokens` — donc pas de magic int
#: sur les call-sites concrets (cf. CLAUDE.md règle anti-hardcode).
_DEFAULT_TURN_MAX_TOKENS = 16000

#: Compression mid-loop : trigger quand l'historique cumulé dépasse ce
#: pourcentage du budget input du modèle actif. Pattern aligné
#: ``agent_service.py:1189`` (Iris). 75% laisse une marge confortable pour
#: une réponse complète au turn suivant + le system prompt.
_COMPRESS_TRIGGER_PCT = 0.75

#: Nombre de messages récents à GARDER INTACTS lors de la compression.
#: 10 = ~5 paires (assistant + user/tool_results). Suffisant pour que le
#: LLM garde une visibilité fine sur ses 5 derniers tours, et compresse
#: tout ce qui est plus ancien.
_COMPRESS_KEEP_RECENT = 10

#: Seuil au-delà duquel un tool_result est compressible. Sous ce seuil, ça
#: vaut moins le coup d'altérer le message (peu de gain).
_TOOL_RESULT_COMPRESSIBLE_LEN = 500


# Import paresseux pour éviter le cycle d'import (llm_report_planner →
# report_planner_agent → llm_report_planner pour _validate_plan).
def _get_validators():
    from app.services.reporting import llm_report_planner as planner

    return planner._validate_plan, planner.ReportPlanError, planner.ReportPlan


def _estimate_row_bytes(row: Any) -> int:
    """Estimation conservative de la RAM occupée par une row dict.

    ``sys.getsizeof`` ne regarde que le header de la struct (~232 bytes pour
    un dict, indépendant du contenu) — mensonger pour notre besoin. Ici on
    compte un overhead fixe par champ + la taille des strings + une borne
    pour les autres types. Sur-estime intentionnellement de 1.5-2× pour
    laisser de la marge à l'intern Python et au reste du runtime.
    """
    if not isinstance(row, dict):
        return 200  # objet quelconque → conservative
    total = 240  # dict header + hash table baseline
    for k, v in row.items():
        # Chaque entrée dict : ~56 bytes (key+value pointers, hash slot)
        total += 56 + len(str(k))
        if isinstance(v, str):
            total += 56 + len(v)  # str header + chars (UTF-8 ~ 1B/char ascii)
        elif isinstance(v, (int, float)):
            total += 28  # PyLong/PyFloat header
        elif isinstance(v, bool) or v is None:
            total += 16
        else:
            total += 200  # dict/list/Decimal/datetime — borne haute
    return total


# Détecteur de tokens proxy résiduels — appelé après ``restore_fn`` pour
# vérifier qu'aucune sentinelle n'a survécu (cas où le LLM a inventé un
# token absent du mapping ou utilisé un format ressemblant). Si un token
# résiduel atteint le PDF, l'utilisateur voit ``§nn_42§`` ou ``[EMAIL_99]``
# au lieu de la vraie valeur — incident UX (pas un PII leak, mais un
# signal de bug à investiguer).
_RESIDUAL_TOKEN_PATTERN = re.compile(
    r"§[A-Za-z0-9_]{1,40}§|\[(?:EMAIL|PHONE|SIRET|SIREN|IBAN|AMOUNT|DATE)_\d+\]"
)


def _scan_residual_tokens(plan_dict: Dict[str, Any]) -> int:
    """Scanne le plan post-restore pour détecter des tokens proxy fantômes.
    Retourne le nombre de tokens trouvés (loggé en warning par le caller).
    """
    count = 0

    def _scan(value: Any) -> None:
        nonlocal count
        if isinstance(value, str):
            count += len(_RESIDUAL_TOKEN_PATTERN.findall(value))
        elif isinstance(value, dict):
            for v in value.values():
                _scan(v)
        elif isinstance(value, list):
            for v in value:
                _scan(v)

    _scan(plan_dict)
    return count


def _estimate_messages_tokens(messages: List[Dict[str, Any]]) -> int:
    """Estimation rough des tokens cumulés dans ``messages``. Pattern aligné
    ``agent_service.py:6745-6753`` : 4 chars ≈ 1 token (heuristique latine).
    """
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
    """Compresse un tool_result JSON en gardant l'essentiel (déterministe,
    sans appel LLM secondaire). Pattern adapté de ``agent_service.py:6972``.

    On garde les champs informationnels (status, ok, dataset_id, agg,
    groups_count, row_count, error, columns…) et on drop les payloads
    volumineux (rows, groups, distinct_sample). Le LLM voit ainsi qu'il a
    fait l'appel et avec quel résultat de haut niveau, mais perd les
    détails fins (qu'il a déjà consommés au tour où le tool a été appelé).

    NB : on ne touche JAMAIS aux ``tool_use`` blocks (les inputs du LLM)
    pour préserver le contrat input/output côté API.
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw[:_TOOL_RESULT_COMPRESSIBLE_LEN] + "...[compressed-trunc]"
    if not isinstance(data, dict):
        return raw[:_TOOL_RESULT_COMPRESSIBLE_LEN] + "...[compressed-trunc]"

    # Champs essentiels conservés (info de haut niveau, sans données brutes)
    summary: Dict[str, Any] = {"_compressed": True}
    for key in (
        "ok",
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
        # #27 — troncature SOURCE (≠ tool-level) : DOIT survivre à la compression
        # mid-loop, sinon le planner perd l'info « agrégat partiel » et présente
        # des chiffres faux comme exhaustifs.
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
    ):
        if key in data:
            value = data[key]
            # Tronque listes volumineuses (columns à 30 max — assez pour le LLM)
            if isinstance(value, list) and len(value) > 30:
                summary[key] = value[:30]
                summary[f"{key}_truncated_count"] = len(value)
            elif isinstance(value, str) and len(value) > 200:
                summary[key] = value[:200] + "..."
            else:
                summary[key] = value
    # On droppe explicitement les gros payloads (rows, groups, distinct_sample)
    return json.dumps(summary, ensure_ascii=False, default=str)


def _maybe_compress_messages(
    messages: List[Dict[str, Any]],
    *,
    context_window: int,
    reserved_output: int,
) -> int:
    """Compresse les vieux tool_results IN-PLACE si les messages dépassent
    ``_COMPRESS_TRIGGER_PCT`` du budget input. Garde les
    ``_COMPRESS_KEEP_RECENT`` derniers messages intacts.

    Args:
        messages: la liste de messages (mutée IN-PLACE).
        context_window: fenêtre du modèle actif (cf. constants_ai).
        reserved_output: tokens réservés pour la réponse LLM (effort["max_tokens"]).

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

    # Garde les N derniers intacts
    end_idx = max(0, len(messages) - _COMPRESS_KEEP_RECENT)
    if end_idx == 0:
        return 0  # rien à compresser, tout est récent

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
            "report_planner_agent: compression mid-loop — %d blocs compressés, "
            "~%d tokens → ~%d tokens (seuil %d, budget %d)",
            compressed,
            estimated,
            new_estimated,
            threshold,
            budget_input,
        )
    return compressed


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def run_report_agent(
    datasets: List[Dict[str, Any]],
    *,
    user_prompt: Optional[str] = None,
    user_title_hint: Optional[str] = None,
    max_output_tokens: Optional[int] = None,
    user_id: Optional[int] = None,
    cancel_event: Optional[asyncio.Event] = None,
):
    """Boucle tool-loop pour générer un ``ReportPlan`` à partir de N datasets.

    Args:
        datasets: liste ``[{id, label, columns, rows, row_count}]``. Mêmes
            contraintes que :func:`plan_report` du mode oneshot — chaque
            dataset DOIT avoir un ``id`` unique référencé par les sections.
        user_prompt: instructions utilisateur, optionnelles. Anonymisées via
            le proxy avant envoi LLM.
        user_title_hint: titre imposé, optionnel. Anonymisé.
        max_output_tokens: cap sur ``max_tokens`` à chaque turn LLM. Si
            ``None``, utilise :data:`_DEFAULT_TURN_MAX_TOKENS` clampé au
            modèle actif.
        user_id: id user pour activer la couche pseudonymizer user-scoped
            du proxy. ``None`` = scripts admin / batch.
        cancel_event: ``asyncio.Event`` set par le handler quand le client
            HTTP ferme la connexion (cf.
            :meth:`ReportGenerateLLMHandler.on_connection_close`). Vérifié à
            chaque tour de boucle. Si set : rescue avec sections déjà
            émises (auto-finalize, titre par défaut), sinon raise. Évite
            de continuer à brûler du LLM sur un client parti.

    Returns:
        :class:`app.services.reporting.llm_report_planner.ReportPlan` validé,
        avec valeurs réelles restaurées via le ``restore_fn`` du proxy.

    Raises:
        :class:`app.services.reporting.llm_report_planner.ReportPlanError`
        si :
        - Aucun dataset fourni
        - Volume mémoire > :data:`MEMORY_HARD_CAP_BYTES`
        - Le LLM épuise :data:`MAX_TURNS` sans appeler ``finalize_report``
        - Le LLM atteint ``stop_reason=max_tokens``
        - ``finalize_report`` jamais appelé et stop_reason terminal autre
        - Le plan retourné échoue la validation (
          :func:`llm_report_planner._validate_plan`)
    """
    _validate_plan, ReportPlanError, ReportPlan = _get_validators()

    # 1. Garde-fous d'entrée -------------------------------------------------
    if not datasets:
        raise ReportPlanError("Aucun dataset fourni")

    for ds in datasets:
        if ds.get("id") is None:
            raise ReportPlanError("Dataset sans id")

    # Hard cap mémoire — refus net au-delà : les agrégations Python ne
    # tiendraient pas, et la serialization json (tool_results) ferait
    # exploser le payload réseau au LLM.
    #
    # Review #3 du 2026-05-09 : ``sys.getsizeof`` sous-estime ~5-20× la
    # vraie RAM (il ne regarde que le header de la struct, pas le contenu
    # référencé). On utilise donc une estimation explicite par champ.
    total_bytes = 0
    for ds in datasets:
        rows = ds.get("rows") or []
        # Échantillonne 100 rows pour la moyenne (évite O(n×m) sur 1M rows).
        sample_size = min(100, len(rows))
        if sample_size > 0:
            avg = sum(_estimate_row_bytes(rows[i]) for i in range(sample_size)) / sample_size
            total_bytes += int(avg * len(rows))
        if total_bytes > MEMORY_HARD_CAP_BYTES:
            raise ReportPlanError(
                f"Volume de données trop important pour le mode agent "
                f"(>{MEMORY_HARD_CAP_BYTES // (1024 * 1024)} MB de rows estimés). "
                f"Réduisez la sélection ou pré-agrégez côté SQL."
            )

    # 2. Anonymisation (pattern aligné avec mode oneshot) --------------------
    # Single source of truth : un seul appel proxy qui anonymise datasets +
    # textes utilisateur en cohérence (mêmes pii_counters partagés). Le
    # restore_fn appliqué à la fin sur le plan complet.
    full_input: Dict[str, Any] = {
        "datasets": [
            {
                "id": ds["id"],
                "label": ds.get("label") or f"Dataset {ds['id']}",
                "columns": ds.get("columns") or [],
                "row_count": ds.get("row_count", len(ds.get("rows") or [])),
                "rows": ds.get("rows") or [],
                # #27 — propager la troncature SOURCE jusqu'au state de l'agent.
                # Cette reconstruction (whitelist de clés avant anonymisation)
                # DROPPAIT le flag → les tools l'exposaient à vide (costume sans
                # corps). C'est un booléen structurel (pas de PII) : l'anonymiseur
                # le laisse intact.
                "truncated": bool(ds.get("truncated")),
            }
            for ds in datasets
        ],
        "user_prompt": user_prompt or "",
        "user_title_hint": user_title_hint or "",
    }
    anon_input, restore_fn = await anonymize_for_llm(user_id, full_input, "REPORT")
    anon_datasets: List[Dict[str, Any]] = list(anon_input.get("datasets") or [])
    sanitized_user_prompt = (anon_input.get("user_prompt") or "").strip() or None
    sanitized_title_hint = (anon_input.get("user_title_hint") or "").strip() or None

    # 3. State partagé --------------------------------------------------------
    state = ReportAgentState(
        datasets_by_id={ds["id"]: ds for ds in anon_datasets},
        restore_fn=restore_fn,
    )

    # 4. Construction du prompt système + user preamble -----------------------
    # OUTPUT_STYLE_RULES — couverture cross-module (adversarial #1 sur fix #19).
    # Les rapports PDF générés ici contiennent des titres / descriptions /
    # commentaires narratifs DIRECTEMENT user-facing. Sans le bloc, le bug Iris
    # #18 (mockup ASCII + jargon technique non sollicité) peut se reproduire
    # dans les PDF. Position APRÈS le system spécifique pour ne pas écraser le
    # contrat de format strict du planner (recency bias LLM).
    from app.services.ai.agent_roles import OUTPUT_STYLE_RULES

    system_prompt = (
        get_confidentiality_prompt("REPORT")
        + "\n\n"
        + _build_system_prompt()
        + "\n\n"
        + OUTPUT_STYLE_RULES
    )
    user_preamble = _build_user_preamble(anon_datasets, sanitized_user_prompt, sanitized_title_hint)
    messages: List[Dict[str, Any]] = [
        {"role": "user", "content": user_preamble},
    ]

    # Audit log RGPD minimal (gap #1 du 2026-05-09, pattern
    # copilot_agent.py:733-752). Counts UNIQUEMENT — jamais les termes
    # eux-mêmes (zéro PII en log). Témoigne de la POSTURE d'anonymisation
    # de l'utilisateur au moment du run, pour traçabilité DPO.
    _enabled_count = 0
    _cleartext_count = 0
    if user_id is not None:
        try:
            from app.core.database import get_session_factory
            from app.services.anonymization import repository as anon_repo

            async with get_session_factory()() as session:
                stored = await anon_repo.get_state_for_user(session, user_id)
            terms_dict = stored.get("terms", {}) if isinstance(stored, dict) else {}
            _enabled_count = sum(
                1 for e in terms_dict.values() if isinstance(e, dict) and e.get("enabled")
            )
            _cleartext_count = sum(
                1
                for e in terms_dict.values()
                if isinstance(e, dict) and e.get("confirmed") and not e.get("enabled")
            )
        except Exception as exc:  # noqa: BLE001 — best-effort, non-bloquant
            logger.warning("anon_audit lookup failed user=%s: %s", user_id, exc)
    logger.info(
        "anon_audit caller=report_planner_agent user=%s anonymized=%d " "cleartext=%d datasets=%d",
        user_id if user_id is not None else "anon",
        _enabled_count,
        _cleartext_count,
        len(datasets),
    )

    # 5. Boucle tool-use (inspirée copilot_agent.py:756 — voir module
    # docstring pour la justification de la non-factorisation).
    t_start = time.monotonic()
    total_llm_ms = 0
    manager = get_llm_manager()

    for turn in range(MAX_TURNS):
        state.turn_count = turn + 1

        # Gap A du 2026-05-09 — check cancel_event AVANT chaque appel LLM.
        # Si le client HTTP a fermé la connexion (handler a set le flag via
        # on_connection_close), on rescue plutôt que de gaspiller un appel
        # LLM de plus. Pattern aligné agent_service.py:2282/4288.
        if cancel_event is not None and cancel_event.is_set():
            logger.info(
                "report_planner_agent: cancel_event set au turn %d "
                "(client déconnecté, sections=%d)",
                turn,
                len(state.emitted_sections),
            )
            if state.emitted_sections:
                state.emitted_title = (user_title_hint or "Rapport d'analyse (annulé)").strip()[
                    :200
                ]
                state.finalized = True
                break
            raise ReportPlanError(
                "Génération annulée — aucune section produite avant la déconnexion."
            )

        # Gap #3 du 2026-05-09 — recalcul effort params À CHAQUE TOUR
        # (pattern copilot_agent.py:765). Si l'admin switch le provider
        # via /admin/ai-config en plein run, les params s'adaptent au
        # tour suivant. Sur Anthropic Sonnet/Opus 4.x+, ``thinking_budget``
        # active l'extended thinking — gain significatif pour la
        # planification multi-sections (raisonnement, choix d'agrégations
        # pertinentes, anticipation des pièges du dataset).
        # ``hard_cap_max_tokens`` respecte le cap user si fourni.
        effort = compute_effort_params(
            manager,
            hard_cap_max_tokens=max_output_tokens or _DEFAULT_TURN_MAX_TOKENS,
        )

        # Gap B du 2026-05-09 — compression mid-loop. Sur 80 tours avec des
        # aggregate_dataset retournant 1000 groupes (~50 KB JSON chacun) +
        # read_dataset_sample (60 rows × 500 chars), l'historique cumulé
        # peut atteindre 500K+ tokens. Au-delà du context window du modèle
        # actif, l'API rejette. La compression déterministe (sans appel LLM
        # secondaire) remplace les vieux tool_results par leurs métadonnées
        # et libère du budget input. On ne touche JAMAIS aux 10 derniers
        # messages (visibilité fine préservée). Skip les 5 premiers tours
        # (overhead inutile sur petits runs).
        if turn >= 5:
            try:
                from app.constants_ai import get_context_window_for_model

                _ctx_window = get_context_window_for_model(manager.default_model_name)
            except Exception:
                _ctx_window = 0
            if _ctx_window > 0:
                _maybe_compress_messages(
                    messages,
                    context_window=_ctx_window,
                    reserved_output=effort["max_tokens"],
                )

        # ``temperature=0.3`` (vs copilot 0.2) : la planification de rapport
        # produit de la prose (commentaires d'analyse, intro, titres) où un
        # peu de variabilité aide la qualité littéraire. Le copilot, lui,
        # édite des classeurs où le déterminisme est plus important pour
        # éviter que la même instruction génère deux structures de tab
        # différentes (review #16 du 2026-05-09 — divergence justifiée).
        request = LLMRequest(
            prompt="",  # messages portent la conversation
            system=system_prompt,
            temperature=0.3,
            max_tokens=effort["max_tokens"],
        )

        t_llm = time.monotonic()
        try:
            response = await call_llm_with_tools(
                CallProfile(
                    caller="report_planner_agent",
                    # La boucle gère ses propres erreurs (re-prompt si besoin)
                    # — on ne veut pas que le runtime retry des erreurs LLM
                    # transitoires en cachant des bugs côté tool_results.
                    retry=RetryPolicy.NONE,
                ),
                request,
                tools=REPORT_TOOLS,
                messages=messages,
                user_id=user_id,
                thinking_budget=effort["thinking_budget"],
            )
        except LLMCallError as exc:
            # Mappe les kinds courants vers des messages user-friendly FR
            # (pattern aligné copilot_agent.py:806-823).
            logger.error(
                "report_planner_agent: LLM error turn %d kind=%s: %s",
                turn,
                getattr(exc, "kind", "?"),
                exc,
            )
            if exc.kind == "overloaded":
                raise ReportPlanError(
                    "⏳ Service LLM temporairement surchargé. Réessaie dans 1-2 minutes."
                ) from exc
            if exc.kind == "rate_limit":
                raise ReportPlanError(
                    "⏳ Quota LLM dépassé (rate limit). Réessaie dans quelques minutes."
                ) from exc
            raise ReportPlanError(f"Erreur LLM : {exc}") from exc
        except Exception as exc:  # noqa: BLE001 — dernière barrière
            logger.error(
                "report_planner_agent: unexpected error turn %d: %s",
                turn,
                exc,
                exc_info=True,
            )
            raise ReportPlanError(
                f"Erreur interne pendant la génération : {type(exc).__name__}"
            ) from exc

        total_llm_ms += round((time.monotonic() - t_llm) * 1000)

        content = response.get("content") or []
        stop_reason = response.get("stop_reason")

        # **Phase 2.5.bis.quinquies (#105) — Garde-fou mode invisible.**
        # Le LLM peut halluciner un nom de table denied dans les sections
        # narratives du rapport (``commentary``, ``description``, ``title``)
        # qui finissent dans le PDF user-facing + l'email envoyé. On
        # **fail-closed** via ``DataAccessLeakDetectedError`` ; le caller
        # catche déjà ``Exception`` et raise ``ReportPlanError`` (mappé
        # côté handler vers un message FR neutre).
        #
        # Couvre text + thinking + tool_use.input (fix CRITIQUE aligné #106).
        #
        # **Phase 2.5.bis.6 follow-up (#120)** — Refactor pur : le bloc
        # (concat text+thinking, concat tool_use.input, restore, assert)
        # est extrait dans ``assert_safe_llm_blocks``. Comportement identique.
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
                restore_fn=restore_fn,
                context_label="report_planner_agent.run_report_agent",
                strict_when_no_user=True,
            )
            if _leak_msg is not None:
                logger.critical(
                    "report_planner_agent: sortie LLM fuite un nom "
                    "denied user_id=%s turn=%d content_blocks=%d",
                    user_id,
                    turn,
                    len(content),
                )
                raise DataAccessLeakDetectedError(_leak_msg)

        # Détection précoce stop_reason=max_tokens — la réponse est tronquée,
        # donc le dernier tool_use peut être JSON-malformé.
        #
        # Review #12 du 2026-05-09 : avant de fail, on tente un rescue : si
        # AU MOINS une section a été émise via les tool_use VALIDES qui
        # précèdent dans le même content (les emit_report_section antérieurs
        # se sont déjà exécutés via le dispatch du turn N-1, donc déjà dans
        # state.emitted_sections), on auto-finalize plutôt que de jeter le
        # travail. Sinon fail-fast.
        if stop_reason == "max_tokens":
            logger.warning(
                "report_planner_agent: turn %d stop_reason=max_tokens — "
                "réponse tronquée (sections déjà émises: %d)",
                turn,
                len(state.emitted_sections),
            )
            if state.emitted_sections:
                state.emitted_title = (user_title_hint or "Rapport d'analyse").strip()[:200]
                state.finalized = True
                logger.warning(
                    "report_planner_agent: rescue post-max_tokens avec %d sections "
                    "émises et titre par défaut '%s'",
                    len(state.emitted_sections),
                    state.emitted_title,
                )
                break
            raise ReportPlanError(
                "Le LLM a atteint la limite max_tokens avant d'émettre la "
                "moindre section — sa réponse est tronquée. Réduisez la "
                "sélection ou simplifiez les instructions."
            )

        # Accumule la réponse assistant telle quelle (text + tool_use) dans
        # les messages pour que le prochain appel voie la conversation
        # complète — REQUIS par l'API tool-use.
        messages.append({"role": "assistant", "content": content})

        # Collecte et dispatche les tool_use blocks
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
                    "report_planner_agent turn %d: tool=%s",
                    turn,
                    tool_name,
                )
                result = dispatch_report_tool(tool_name, tool_input, state)
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        # ensure_ascii=False : préserve les accents/UTF-8 dans
                        # les valeurs (commentary FR par exemple). default=str
                        # tolère les types non-JSON (Decimal/datetime venus de
                        # SQL Server) en fallback string.
                        "content": json.dumps(result, ensure_ascii=False, default=str),
                    }
                )

            messages.append({"role": "user", "content": tool_results})

            # Terminal signal : finalize_report a été appelé avec succès.
            # On sort tout de suite plutôt que d'attendre un end_turn.
            if state.finalized:
                break

            # Sinon, on continue la boucle (le LLM doit pouvoir réagir aux
            # tool_results — soit appeler d'autres tools soit finalize).
            continue

        # Pas de tool_use : le LLM a répondu par du texte final
        if stop_reason == "end_turn":
            if not state.finalized:
                # Le LLM s'est arrêté sans finalize. Deux cas :
                # 1. Aucune section émise → vraie erreur, fail-fast.
                # 2. >=1 section émise → rescue : on auto-finalize avec un
                #    titre par défaut plutôt que de jeter le travail (review
                #    #11 du 2026-05-09 — ne pas perdre 5 min de calcul agent
                #    parce que le LLM a oublié l'appel terminal).
                if not state.emitted_sections:
                    logger.warning(
                        "report_planner_agent: end_turn sans finalize ni section (turn %d)",
                        turn,
                    )
                    raise ReportPlanError(
                        "Le LLM a terminé sans produire de section ni appeler "
                        "finalize_report. Réessayez la génération."
                    )
                logger.warning(
                    "report_planner_agent: end_turn sans finalize MAIS %d sections "
                    "émises — auto-finalize avec titre par défaut (rescue)",
                    len(state.emitted_sections),
                )
                state.emitted_title = (user_title_hint or "Rapport d'analyse").strip()[:200]
                state.finalized = True
            break

        # Stop_reason inattendu (rare — pause_turn, refusal…). Log + fail.
        if stop_reason and stop_reason != "tool_use":
            logger.warning(
                "report_planner_agent: stop_reason inattendu '%s' turn %d",
                stop_reason,
                turn,
            )
            raise ReportPlanError(f"Arrêt LLM inattendu : {stop_reason}")

        # Garde anti-boucle morte (review #5 du 2026-05-09) : si le LLM
        # renvoie un content vide AVEC stop_reason="tool_use" (ou None),
        # on est dans un état dégénéré. Sans cette garde, la boucle "for"
        # poursuit silencieusement jusqu'à MAX_TURNS — message d'erreur
        # final trompeur ("MAX_TURNS épuisé") qui masque le vrai problème.
        if not tool_use_blocks:
            logger.warning(
                "report_planner_agent: turn %d réponse vide sans signal terminal "
                "(stop_reason=%s, content_blocks=%d)",
                turn,
                stop_reason,
                len(content),
            )
            raise ReportPlanError(
                "Le LLM a renvoyé une réponse vide sans signal terminal. "
                "Le modèle est peut-être saturé — réessayez dans 1-2 minutes."
            )

    else:
        # Sortie naturelle de la boucle for sans break = MAX_TURNS épuisé.
        # Gap #5 du 2026-05-09 : si N sections déjà émises, rescue avec
        # titre par défaut au lieu de jeter le travail (cohérent avec les
        # rescues existants sur max_tokens et end_turn). Pattern aligné
        # copilot_agent.py:1078-1116.
        logger.warning(
            "report_planner_agent: budget tours épuisé sans finalize " "(sections=%d, intro=%s)",
            len(state.emitted_sections),
            state.emitted_intro is not None,
        )
        if state.emitted_sections:
            state.emitted_title = (user_title_hint or "Rapport d'analyse").strip()[:200]
            state.finalized = True
            logger.warning(
                "report_planner_agent: rescue post-budget avec %d sections émises",
                len(state.emitted_sections),
            )
        else:
            # Aucune section émise — vraiment échec. Message générique sans
            # leak des constantes internes (gap #4 du 2026-05-09 — pattern
            # copilot_agent.py:798-800 « jamais de constante interne dans
            # un message client, leaking oracle »).
            raise ReportPlanError(
                "L'analyse n'a pas abouti dans le budget alloué. "
                "Réduisez la sélection ou simplifiez les instructions."
            )

    # 6. Construction du ReportPlan -----------------------------------------
    if not state.emitted_sections:
        raise ReportPlanError("Aucune section émise par le LLM")
    if not state.emitted_title:
        raise ReportPlanError("Pas de titre fourni via finalize_report")

    # On reconstruit la STRUCTURE attendue par _validate_plan (compatible
    # 1:1 avec le format que produisait l'ancien JSON LLM en mode oneshot).
    plan_anon: Dict[str, Any] = {
        "title": state.emitted_title,
        "introduction": state.emitted_intro,
        "sections": state.emitted_sections,
    }

    # Restore AVANT validation (cf. justification dans
    # llm_report_planner.plan_report:202-205 — la validation tronque, et
    # tronquer un token §§§ produirait un faux positif au PII-leak).
    plan_restored = restore_fn(plan_anon)
    if not isinstance(plan_restored, dict):
        plan_restored = {}

    # **Adversarial review #105 BLOCKING fix** — Check final sur ``plan_restored``.
    # 4 chemins de rescue (cancel_event, max_tokens, end_turn sans finalize,
    # budget épuisé) ``break`` la boucle SANS le check intra-turn. Le plan
    # final atterrit ensuite dans le PDF user-facing + email. Sans ce check
    # supplémentaire, un nom denied inséré au turn N et rescue au turn N+1
    # leak via le PDF.
    if user_id is not None and plan_restored:
        try:
            import json as _json_for_plan_check
            from types import SimpleNamespace as _SimpleNamespace

            from app.services.data_access.error_messages import (
                DataAccessLeakDetectedError,
                assert_safe_llm_response,
            )

            _plan_serialized = _json_for_plan_check.dumps(
                plan_restored, ensure_ascii=False, default=str
            )
            _user_stub_final = _SimpleNamespace(id=user_id, role=None)
            _leak_msg_final = await assert_safe_llm_response(
                _plan_serialized,
                _user_stub_final,
                context_label="report_planner_agent.final_plan",
                strict_when_no_user=True,
            )
            if _leak_msg_final is not None:
                logger.critical(
                    "report_planner_agent: plan final fuite un nom denied "
                    "user_id=%s sections=%d (chemin rescue probable)",
                    user_id,
                    len(state.emitted_sections),
                )
                raise DataAccessLeakDetectedError(_leak_msg_final)
        except DataAccessLeakDetectedError:
            raise
        except Exception:  # noqa: BLE001 — defensive (fail-open au pire si check crash)
            logger.warning(
                "report_planner_agent: check plan final a crashé (fail-open). " "user_id=%s",
                user_id,
                exc_info=True,
            )

    # Détection tokens proxy résiduels (review #1 du 2026-05-09). Si le
    # LLM a inventé un token absent du mapping, restore_fn le laisse tel
    # quel — il finirait dans le PDF. On loggue WARNING pour investigation
    # sans bloquer (le PDF reste utilisable mais avec un libellé bizarre,
    # signal que le prompt système doit être renforcé).
    residual = _scan_residual_tokens(plan_restored)
    if residual:
        logger.warning(
            "report_planner_agent: %d token(s) proxy résiduel(s) dans le plan final — "
            "le LLM a probablement inventé un token absent du mapping. À investiguer.",
            residual,
        )

    # Réutilise la validation single source of truth — pas de duplication.
    # On valide contre les datasets ORIGINAUX (avec rows réelles) car la
    # validation peut référencer dataset.columns (et certaines validations
    # de chart pourraient utiliser le schéma — futur-proof).
    validated = _validate_plan(plan_restored, datasets)

    total_ms = round((time.monotonic() - t_start) * 1000)
    logger.info(
        "report_planner_agent: terminé — turns=%d llm_ms=%d total_ms=%d sections=%d tools=%s",
        state.turn_count,
        total_llm_ms,
        total_ms,
        len(validated["sections"]),
        dict(state.tool_call_counts),
    )

    return ReportPlan(
        title=validated["title"],
        introduction=validated.get("introduction"),
        sections=validated["sections"],
    )


# ---------------------------------------------------------------------------
# Prompt building
# ---------------------------------------------------------------------------


def _build_system_prompt() -> str:
    """System prompt domain-neutral, oriente le LLM vers l'usage des tools."""
    return (
        "Tu es un analyste de données qui rédige des rapports professionnels en français.\n"
        "\n"
        "Tu reçois N jeux de données et tu dois construire un rapport structuré "
        "(introduction, sections avec graphiques agrégés et commentaires d'analyse).\n"
        "\n"
        "## Contraintes IMPORTANTES sur l'accès aux données\n"
        "Tu n'as PAS accès aux lignes brutes dans le prompt initial — uniquement "
        "aux métadonnées (id, label, colonnes, nombre de lignes). Pour analyser "
        "un dataset, tu DOIS utiliser les tools fournis :\n"
        "\n"
        "- `list_datasets()` : voir la liste des datasets disponibles\n"
        "- `inspect_dataset(dataset_id)` : voir les colonnes, leurs types, "
        "  les valeurs distinctes (échantillon)\n"
        "- `aggregate_dataset(dataset_id, group_by, value_column, agg)` : "
        "  AGRÉGATION GROUPÉE — c'est l'outil PRINCIPAL pour analyser les "
        "  gros datasets (>100 lignes). Évite read_dataset_sample sur les "
        "  gros datasets : tu vas paginer 60 lignes à la fois et épuiser "
        "  ton budget de tours pour rien.\n"
        "- `count_rows_dataset(dataset_id, where)` : compter avec filtres\n"
        "- `read_dataset_sample(dataset_id, row_start, row_end)` : lire un "
        "  petit échantillon de lignes (max 60 par appel) — utile pour comprendre "
        "  le format des données ou pour des spot-checks ciblés UNIQUEMENT.\n"
        "\n"
        "## Émission du rapport\n"
        "Quand tu as collecté assez d'informations, émets le rapport via :\n"
        "\n"
        "- `emit_report_intro(text)` : paragraphe d'introduction (optionnel, "
        "  une seule fois). Cap 4000 caractères.\n"
        "- `emit_report_section(title, dataset_id, description, charts, commentary)` : "
        "  une section. Maximum 20 sections au total.\n"
        "- `finalize_report(title)` : OBLIGATOIRE EN FIN — c'est l'unique signal "
        "  que tu as terminé. Sans finalize_report, ton run échoue.\n"
        "\n"
        "## Format des graphiques (PRÉ-AGRÉGÉS — données finales)\n"
        "Les graphiques que tu fournis dans `emit_report_section.charts` doivent "
        "contenir les données FINALES déjà calculées (pas de référence à des "
        "colonnes — le moteur ne fait que tracer ce que tu fournis). Trois formats :\n"
        "\n"
        "BAR : `{type:'bar', title, x_label?, y_label?, bars:[{label, value}, ...]}`\n"
        "  - Max 30 barres. value = nombre fini.\n"
        "LINE : `{type:'line', title, x_label?, y_label?, series:[{name, points:[{x,y}, ...]}]}`\n"
        "  - Max 8 séries, 100 points par série. Pour évolutions/comparaisons.\n"
        "PIE : `{type:'pie', title, slices:[{label, value}, ...]}`\n"
        "  - Max 10 tranches. value > 0. Pour répartitions.\n"
        "\n"
        "## Méthode recommandée\n"
        "1. Appelle `list_datasets()` puis `inspect_dataset()` sur les datasets pertinents.\n"
        "2. Pour chaque axe d'analyse pertinent, utilise `aggregate_dataset()` pour "
        "   obtenir les chiffres exacts. Ne devine JAMAIS un chiffre — les commentaires "
        "   doivent citer des valeurs que tu as réellement obtenues via les tools.\n"
        "3. Émet les sections au fur et à mesure via `emit_report_section()`.\n"
        "4. Quand tu as fini, appelle `finalize_report(title)` — c'est OBLIGATOIRE.\n"
        "\n"
        "Tu décides de la longueur, du nombre de sections, du nombre de graphiques. "
        "Sois concis et pertinent — ne génère pas du texte pour faire du volume."
    )


def _build_user_preamble(
    anon_datasets: List[Dict[str, Any]],
    user_prompt: Optional[str],
    user_title_hint: Optional[str],
) -> str:
    """Premier message user — métadonnées des datasets + instructions, PAS les rows.

    Le LLM va les chercher lui-même via les tools — c'est tout l'intérêt
    du mode agent vs oneshot.
    """
    parts: List[str] = []

    if user_prompt:
        parts.append(f"Instructions de l'utilisateur :\n{user_prompt}")
        parts.append("")

    if user_title_hint:
        parts.append(f'Titre imposé : "{user_title_hint}".')
    else:
        parts.append("Propose un titre adapté au contenu.")

    parts.append("")
    parts.append(
        f"Tu disposes de {len(anon_datasets)} jeu(x) de données. "
        "Voici leurs métadonnées (les lignes ne sont PAS ici — utilise les tools "
        "pour y accéder) :"
    )
    parts.append("")

    for ds in anon_datasets:
        ds_id = ds.get("id")
        label = ds.get("label", f"Dataset {ds_id}")
        row_count = ds.get("row_count", len(ds.get("rows") or []))
        cols = ds.get("columns") or []
        cols_preview = ", ".join(cols[:8])
        if len(cols) > 8:
            cols_preview += f", … (+{len(cols) - 8} autres)"
        line = (
            f"- **Dataset {ds_id}** « {label} » — {row_count:,} lignes, "
            f"{len(cols)} colonnes : {cols_preview}".replace(",", " ")
        )
        # #27 — la troncature SOURCE doit être visible DÈS les métadonnées : sinon
        # le planner lit « N lignes » comme le total réel et présente des agrégats
        # partiels comme exhaustifs (données fausses silencieuses). Marqueur ajouté
        # APRÈS le ``.replace(",", " ")`` pour ne pas mâcher sa ponctuation.
        if ds.get("truncated"):
            line += (
                " — ⚠ TRONQUÉ À LA SOURCE : le total réel dépasse ces lignes ; "
                "tout agrégat/comptage sera PARTIEL, à signaler explicitement."
            )
        parts.append(line)

    parts.append("")
    parts.append(
        "Commence par `list_datasets()` puis `inspect_dataset()` sur les datasets "
        "qui te semblent les plus riches. Pour les analyses, privilégie "
        "`aggregate_dataset()` — ne paginie pas les gros datasets ligne par ligne."
    )
    return "\n".join(parts)
