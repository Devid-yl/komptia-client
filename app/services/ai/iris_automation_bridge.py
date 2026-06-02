"""Bridge headless ``AgentService.run()`` ↔ step ``iris`` d'automation DAG.

Objectif
--------

Permettre à un step ``iris`` d'une automatisation Komptia d'invoquer le MÊME
agent Iris que la page ``/iris`` (``AgentService.run()``), sans WebSocket,
en mode background. Pattern miroir de ``copilot_automation_bridge.py``
(qui fait la même chose pour ``copilot_agent``).

Doctrine
--------

- **Zéro duplication agent** : on appelle ``AgentService.run()`` existant,
  on ne réimplémente PAS l'agent. Cf. demande user 2026-05-26 « les mêmes
  agents existants juste en backend ».
- **Conv transient par run** : pas de ``get_or_create_active_conversation``
  (qui sert au mode page/widget). On crée une conv FRESH avec
  ``source=ConversationSource.AUTOMATION`` pour traçabilité + isolation +
  anti-pollution mémoire user (cf. Task #31).
- **Headless consumer** : on consomme l'``AsyncGenerator`` que
  ``AgentService.run()`` yield (pas de WebSocket). On agrège
  ``text_delta`` / ``tool_use`` / ``tool_result`` / ``done`` / ``error`` /
  ``abandon`` en un ``IrisAutomationResult``.
- **Fail-closed** :
  - ``ask_user_clarification`` désactivé par la whitelist tools
    (cf. ``AUTOMATION_TOOL_CLASSIFICATION``).
  - Cancel_event propagé.
  - Erreur LLM/provider → ``IrisAutomationError`` (message safe sanitizé).
  - Timeout wall-clock (param ``timeout_seconds``).

Architecture
------------

::

    DAG executor                                  iris_automation_bridge
    ============                                  ======================
    step_type == "iris"
        ↓
    run_iris_for_automation(instruction, user, ...)  ──┐
                                                       │
                                                       ↓
                                  create transient Conversation(source=AUTOMATION)
                                                       ↓
                                  AgentService.run(message=instruction, ...,
                                                   source="automation",
                                                   cancel_event=...)
                                                       ↓
                                          consume events headless:
                                          - text_delta → accumulate
                                          - tool_use   → record + handler runs
                                          - tool_result → record
                                          - done       → terminal result
                                          - error      → IrisAutomationError
                                          - abandon    → IrisAutomationResult(abort=True)
                                                       ↓
                                          map → IrisAutomationResult
                                                       ↓
    IrisAutomationResult ←──────────────────────────────┘
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.models.conversation import Conversation, ConversationSource

logger = logging.getLogger(__name__)


class IrisAutomationError(Exception):
    """Erreur consommable par le DAG executor (message utilisateur safe).

    Le ``message`` exposé via ``str(exc)`` est garanti sans path absolu,
    sans API key, sans IP privée (passe par ``_safe_error_message``).

    Task #25 (2026-05-27) — `category` permet à l'executor + UI de
    différencier les 4 cas du contrat Komptia axe 5 :

    - ``"business"`` (a) : abort métier prévu par Iris (ex: incohérence
      données détectée). Message FR clair, pas de retry auto pertinent.
    - ``"transient"`` (b) : erreur transitoire (rate-limit LLM, budget
      atteint, provider lent). Retry possible (réessayer dans X minutes).
    - ``"system"`` (c) : erreur système (LLM provider down, BDD down,
      anonymizer crash). Notif admin via bouton "Signaler" → mail à l'«
      Email support » configuré dans /admin/smtp-config. Page d'erreur dédiée.
    - ``"network"`` (d) : NON applicable en backend run (cron sans
      browser). Géré côté UI /automations/N/runs/M si l'user load la
      page pendant qu'il est offline.
    """

    def __init__(self, message: str, *, category: str = "system"):
        super().__init__(message)
        self.category = category


@dataclass
class IrisAutomationResult:
    """Résultat d'un run Iris en mode automation backend.

    Le DAG executor consomme ce résultat pour décider de la suite :
    - ``decision_summary`` : texte court (1-2 phrases) décrivant la décision
      finale prise par Iris. Tracé dans ``StepExecution.step_output`` pour
      l'observabilité (cf. Task #17 panneau Décisions Iris).
    - ``variables`` : dict ``{name: value}`` à fusionner dans
      ``DAGRunContext.variables`` (interpolable aval via ``{{step.var}}``,
      cf. Task #14). Vide tant que Task #10 (``set_run_variable`` tool)
      n'est pas implémentée — Iris ne peut écrire que via ce tool futur.
    - ``aborted`` : ``True`` si Iris a appelé ``abandon`` ou si erreur fatale.
      Le step est marqué ``failed``, les descendants sont skipped (fail policy
      ``abort`` par défaut du DAG).
    - ``abort_reason`` : raison sanitizée (visible UI + audit).
    - ``trace`` : liste chronologique des tools appelés (nom + résumé court).
      Pour debug + audit log (cf. Task #33).
    - ``llm_cost_usd`` : coût LLM cumulé du run (lu via ``llm_call_tracker``
      qui tracke automatiquement par caller scope).
    - ``conversation_id`` : id de la conv transient créée (audit + debug).
    """

    decision_summary: str = ""
    variables: Dict[str, Any] = field(default_factory=dict)
    aborted: bool = False
    abort_reason: Optional[str] = None
    trace: List[Dict[str, Any]] = field(default_factory=list)
    llm_cost_usd: float = 0.0
    conversation_id: Optional[int] = None
    turns_used: int = 0


# ---------------------------------------------------------------------------
# Sanitisation des messages d'erreur (pattern miroir copilot bridge)
# ---------------------------------------------------------------------------


_SAFE_ERROR_MAX_LEN: int = 300


def _categorize_error(raw: Any) -> str:
    """Task #25 (2026-05-27) — Catégorise une erreur Iris pour UX 4-cas.

    Heuristique basée sur le message d'erreur (avant sanitization) :
    - rate-limit, 429, quota, budget → "transient" (retry possible)
    - provider, connection, timeout, 5xx → "system" (notif admin)
    - "uncertain", "ambigu", "data" → "business" (Iris a décidé d'abort)
    - défaut → "system"

    Pas une science exacte — sert à orienter le message UI + retry hints.
    """
    if raw is None:
        return "system"
    text = str(raw).lower()
    # Transient : retry pertinent
    if any(
        kw in text
        for kw in ("rate limit", "rate_limit", "429", "quota", "budget", "throttle")
    ):
        return "transient"
    # Business : Iris a abandonné volontairement
    if any(kw in text for kw in ("uncertain", "incohérent", "incoherent", "abort_run", "abandon")):
        return "business"
    # System : reste
    return "system"


def _safe_error_message(raw: Any) -> str:
    """Sanitise un message d'erreur avant exposition au DAG executor.

    Strip : paths Unix/Windows, API keys (sk-ant-, Bearer, etc.),
    credentials inline (password=, token=), IPs privées RFC1918. Cap à
    ``_SAFE_ERROR_MAX_LEN`` chars avec ellipsis.

    Pattern miroir de ``copilot_automation_bridge._safe_error_message``
    pour cohérence (mais inline ici pour ne pas créer une dépendance
    inutile entre les deux bridges qui peuvent évoluer indépendamment).
    """
    if raw is None:
        return "erreur inconnue"
    text = str(raw)
    text = re.sub(r"/(Users|home|var|etc|tmp|root|opt)/[^\s'\"]+", "<path>", text)
    text = re.sub(r"\b[A-Za-z]:\\[\w\\.\-]+", "<path>", text)
    text = re.sub(
        r"\b(sk-ant-\S+|sk-[a-zA-Z0-9_-]{20,}|Bearer\s+\S+)",
        "<redacted>",
        text,
    )
    text = re.sub(
        r"(password|pwd|token|secret|api[-_]?key)\s*=\s*[^;\s'\"]+",
        r"\1=***",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b",
        "<ip>",
        text,
    )
    if len(text) > _SAFE_ERROR_MAX_LEN:
        text = text[: _SAFE_ERROR_MAX_LEN - 1].rstrip() + "…"
    return text or "erreur inconnue"


# ---------------------------------------------------------------------------
# Conv transient (pas de get_or_create — fresh par run automation)
# ---------------------------------------------------------------------------


async def _create_transient_conversation(
    user_id: int, automation_id: int, step_id: Optional[int]
) -> int:
    """Crée une Conversation FRESH avec ``source=AUTOMATION`` pour ce run.

    Pas de ``get_or_create_active_conversation`` (qui sert au mode page/widget
    pour réutiliser une conv active). En automation, chaque run a sa propre
    conv pour :
    - traçabilité (1 run = 1 conv distincte)
    - isolation (pas de pollution cross-runs ni cross-automations)
    - audit (conversation_id propre dans AuditLog cf. Task #33)
    """
    from app.core.database import get_session

    async with get_session() as session:
        conv = Conversation(
            user_id=user_id,
            agent_role="iris",  # même rôle que /iris page (SQL_EXPERT forcé en runtime)
            source=ConversationSource.AUTOMATION.value,
            is_active=False,  # transient : pas de réutilisation par UI
            message_count=0,
            total_tokens=0,
            title=(
                f"[automation #{automation_id}"
                + (f" step #{step_id}" if step_id else "")
                + "]"
            )[:200],
        )
        session.add(conv)
        await session.commit()
        return conv.id


# ---------------------------------------------------------------------------
# Consumer headless de l'AsyncGenerator AgentService.run()
# ---------------------------------------------------------------------------


async def _consume_agent_stream(
    agent_service: Any,
    *,
    message: str,
    conversation_id: int,
    user: Any,
    cancel_event: Optional[asyncio.Event],
    upstream_variables: Optional[Dict[str, Any]] = None,
    upstream_step_outputs: Optional[Dict[int, Dict[str, Any]]] = None,
    allowed_skip_targets: Optional[set] = None,
) -> IrisAutomationResult:
    """Consomme l'``AsyncGenerator`` que ``IrisAgent.run()`` yield.

    Agrège les événements en un ``IrisAutomationResult``. Pas de WebSocket
    — on lit le stream et on persiste juste ce qui sert le DAG.

    Le bridge prépare un ``automation_context`` dict mutable PARTAGÉ avec
    l'agent : les handlers DAG-aware (Tasks #10/#11) mutent ses clés
    ``_automation_*`` ; après le run, on lit ces mutations pour peupler
    ``IrisAutomationResult.variables/route/skip/abort``.

    Args:
        upstream_variables: variables des steps amont (DAGRunContext.variables)
            — visibles via ``get_run_variable`` côté Iris.
        upstream_step_outputs: outputs des steps amont (``{step_id: {kind,
            payload}}``) — visibles via ``get_step_output`` côté Iris.

    Événements gérés (cf. ``IrisAgent.run`` docstring) :
        - ``text_delta`` : accumulated (fallback decision_summary)
        - ``text_complete`` : remplace l'accumulation du tour
        - ``tool_use`` / ``tool_result`` : ajoutés à ``trace``
        - ``clarification`` : FAIL-CLOSED (anti-régression sécu)
        - ``error`` : converti en ``IrisAutomationError`` ou abort
        - ``done`` : terminal — extrait ``turn_count``
    """
    from app.services.ai.agent_automation_tools import _ensure_automation_context
    from app.services.ai.agent_roles import AgentRole

    # Prépare le dict automation_context partagé (mutations visibles côté
    # handlers via context — same dict by reference).
    automation_context: Dict[str, Any] = {}
    _ensure_automation_context(automation_context)
    if upstream_variables:
        automation_context["_automation_upstream_variables"] = dict(upstream_variables)
    if upstream_step_outputs:
        automation_context["_automation_step_outputs"] = dict(upstream_step_outputs)
    # Fix CRIT #5 — Expose la liste des descendants topologiques autorisés
    # pour `skip_steps` (fail-closed si vide/None — Iris ne peut rien skipper).
    if allowed_skip_targets is not None:
        automation_context["_automation_allowed_skip_targets"] = set(allowed_skip_targets)

    result = IrisAutomationResult(conversation_id=conversation_id)
    accumulated_text: List[str] = []
    final_done_event: Optional[Dict[str, Any]] = None

    # Fix MAJOR #6 (adversarial 2026-05-27) : wrap async generator dans
    # ``contextlib.aclosing`` pour garantir `gen.aclose()` même sur `break`
    # ou exception. Sinon les ressources détenues par le generator (DB
    # session, cursor pyodbc, fire-and-forget tasks) restent ouvertes au
    # GC — comportement fragile, contrevient à `feedback_asyncio_create_task_strong_ref`.
    try:
        gen = agent_service.run(
            message=message,
            conversation_id=conversation_id,
            user=user,
            role=AgentRole.SQL_EXPERT,
            mode="execution",
            cancel_event=cancel_event,
            source=ConversationSource.AUTOMATION.value,
            automation_context=automation_context,
        )
        async with contextlib.aclosing(gen) as managed_gen:
            async for event in managed_gen:
                event_type = event.get("type")

                if event_type == "text_delta":
                    # Streaming text — accumule pour fallback decision_summary
                    accumulated_text.append(event.get("content", ""))
                elif event_type == "text_complete":
                    # Texte complet du tour : remplace l'accumulation si présent
                    content = event.get("content", "")
                    if content:
                        accumulated_text = [content]
                elif event_type == "tool_use":
                    # Trace : nom du tool + input court avec marker truncation.
                    tool_name = event.get("tool", "?")
                    tool_input = event.get("input", {})
                    _raw = str(tool_input)
                    input_short = _raw[:197] + "…" if len(_raw) > 200 else _raw
                    result.trace.append(
                        {"event": "tool_use", "tool": tool_name, "input": input_short}
                    )
                elif event_type == "tool_result":
                    tool_name = event.get("tool", "?")
                    tool_result_data = event.get("result", {})
                    _raw = str(tool_result_data)
                    result_short = _raw[:197] + "…" if len(_raw) > 200 else _raw
                    result.trace.append(
                        {"event": "tool_result", "tool": tool_name, "result": result_short}
                    )
                elif event_type == "clarification":
                    # Fix MAJOR #11 — check précis source tool
                    source_tool = event.get("tool") or event.get("source_tool") or ""
                    if source_tool == "ask_user_clarification" or not source_tool:
                        raise IrisAutomationError(
                            "Iris a tenté de demander une clarification utilisateur "
                            "en mode automation via ``ask_user_clarification`` "
                            "(interdit par whitelist fail-closed)."
                        )
                    logger.warning(
                        "iris_automation: clarification event reçu depuis tool=%r "
                        "(non bloquant — tool autorisé)",
                        source_tool,
                    )
                    result.trace.append(
                        {"event": "clarification_ignored", "tool": source_tool}
                    )
                elif event_type == "error":
                    err_msg = _safe_error_message(event.get("message", "erreur inconnue"))
                    result.aborted = True
                    result.abort_reason = err_msg
                    break
                elif event_type == "done":
                    final_done_event = event
                    break

    except IrisAutomationError:
        raise
    except (KeyboardInterrupt, SystemExit):
        # Ne JAMAIS catch ces exceptions critiques (BLE001 best practice).
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("iris_automation run_agent crash", exc_info=True)
        # Task #25 — catégorise pour UX 4-cas
        category = _categorize_error(exc)
        raise IrisAutomationError(
            f"Erreur d'exécution Iris : {_safe_error_message(exc)}",
            category=category,
        ) from None

    # Construire le decision_summary depuis le texte accumulé (fallback) ou
    # depuis le done event si présent.
    if final_done_event:
        # Métadonnées du done : tokens, cost (le tracker llm_call_tracker
        # cumule déjà côté BDD via caller scope, on lit juste pour info ici).
        result.turns_used = int(final_done_event.get("turn_count", 0) or 0)

    text = " ".join(s for s in accumulated_text if s).strip()
    if text:
        # Cap à 500 chars pour ne pas exploser StepExecution.step_output
        result.decision_summary = text if len(text) <= 500 else text[:499] + "…"
    elif not result.aborted:
        # Aucun texte produit ET pas abort → décision vide (à signaler)
        result.decision_summary = "(aucune décision produite par Iris)"

    # ── Task #18 — Récupérer le coût LLM cumulé du run (SSoT existante) ──
    # `llm_call_tracker.get_conversation_cost_usd` agrège
    # ``AIPerformanceLog.cost_usd_snapshot`` par conversation_id. Permet au
    # circuit-breaker `automation.max_llm_cost_eur` (cf. `dag_executor.py`)
    # de comptabiliser correctement les appels Iris en automation.
    #
    # Fix CRIT #1+#2 (adversarial 2026-05-27) :
    # - La fonction retourne **tuple `(cost_usd, null_count)`**, pas un dict
    # - `AIPerformanceLog.conversation_id` est `String(64)` → convertir l'int
    #   en str AVANT la query (sinon mismatch type qui retourne 0.0 silencieux)
    # - Passer `user_id` pour isolation cross-user (défense en profondeur)
    try:
        from app.services.ai.llm_call_tracker import get_conversation_cost_usd

        user_id_int = getattr(user, "id", None)
        cost_usd, _null_count = await get_conversation_cost_usd(
            str(conversation_id),
            user_id=user_id_int,
        )
        result.llm_cost_usd = float(cost_usd or 0.0)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:  # noqa: BLE001 — fail-soft (audit non-critique)
        logger.warning(
            "iris_automation: échec lecture cost via get_conversation_cost_usd",
            exc_info=True,
        )

    # ── Task #10/#11 — Lire les mutations du context automation ──────────
    # Les handlers DAG-aware (set_run_variable, route_to, skip_steps,
    # abort_run) ont muté ``automation_context`` pendant le run. On lit
    # maintenant ces clés pour peupler le résultat final.
    result.variables = dict(automation_context.get("_automation_run_variables", {}))

    abort_info = automation_context.get("_automation_abort")
    if abort_info:
        # Abort explicite via abort_run tool. Override l'éventuel abort
        # détecté via event "error".
        result.aborted = True
        result.abort_reason = abort_info.get("reason")

    skip_ids = automation_context.get("_automation_skip_steps") or []
    if skip_ids:
        # Stocker pour que le DAG executor consomme via la trace.
        result.trace.append(
            {
                "event": "skip_steps",
                "step_ids": list(skip_ids),
                "reasons": dict(
                    automation_context.get("_automation_skip_reasons", {})
                ),
            }
        )

    route_edges = automation_context.get("_automation_route_to_edges")
    if route_edges is not None:
        result.trace.append({"event": "route_to", "edge_ids": list(route_edges)})

    return result


# ---------------------------------------------------------------------------
# Entry point public — appelé par l'executor depuis le handler step_type=iris
# ---------------------------------------------------------------------------


async def run_iris_for_automation(
    *,
    instruction: str,
    user: Any,
    automation_id: int,
    step_id: Optional[int] = None,
    cancel_event: Optional[asyncio.Event] = None,
    upstream_variables: Optional[Dict[str, Any]] = None,
    upstream_step_outputs: Optional[Dict[int, Dict[str, Any]]] = None,
    allowed_skip_targets: Optional[set] = None,
) -> IrisAutomationResult:
    """Invoque Iris en mode backend pour un step d'automatisation.

    Args:
        instruction: Le prompt user en langage naturel (depuis
            ``step_cfg["instruction"]`` du step ``iris``).
        user: Objet ORM ``User`` complet du propriétaire de l'automation
            (cf. ``AutomationExecutor._load_runtime_user``). Critique pour
            la propagation RLS data_access (mode invisible cf. Task #28).
        automation_id: ID de l'automation parent (pour titre conv + audit).
        step_id: ID du step (optionnel — pour audit + titre conv).
        cancel_event: Event ``asyncio.Event`` pour interrompre le run en
            cours (propagé à ``AgentService.run()`` qui check à chaque tour).

    Returns:
        ``IrisAutomationResult`` agrégé. Le DAG executor consomme
        ``decision_summary``, ``variables``, ``aborted``, ``trace`` pour
        décider de la suite.

    Raises:
        IrisAutomationError: instruction vide, user invalide, ou erreur
            fatale (provider down, etc.). Message sanitizé safe pour
            l'exposition UI/logs.
    """
    instruction = (instruction or "").strip()
    if not instruction:
        raise IrisAutomationError(
            "Instruction vide pour le step Iris. Décrivez en quelques mots "
            "la décision attendue (ex: « si > 100 anomalies, abandon »)."
        )

    user_id = getattr(user, "id", None)
    if not isinstance(user_id, int) or user_id <= 0:
        raise IrisAutomationError(
            "user_id invalide pour le step Iris (impossible de propager "
            "les permissions data_access). Vérifiez que l'automation a un "
            "propriétaire actif."
        )

    # 1. Créer conv transient (source=AUTOMATION, anti-pollution)
    try:
        conversation_id = await _create_transient_conversation(
            user_id=user_id, automation_id=automation_id, step_id=step_id
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("iris_automation: échec création conv transient", exc_info=True)
        raise IrisAutomationError(
            f"Impossible de créer la conversation Iris : {_safe_error_message(exc)}"
        ) from None

    # 2. Instancier IrisAgent (lazy import pour éviter cycle)
    from app.services.ai.agent_service import IrisAgent

    agent_service = IrisAgent()

    logger.info(
        "iris_automation start (user_id=%s, automation_id=%s, step_id=%s, conv_id=%s, instr_len=%d)",
        user_id,
        automation_id,
        step_id,
        conversation_id,
        len(instruction),
    )

    # 3. Consommer le stream headless avec upstream context
    result = await _consume_agent_stream(
        agent_service,
        message=instruction,
        conversation_id=conversation_id,
        user=user,
        cancel_event=cancel_event,
        upstream_variables=upstream_variables,
        upstream_step_outputs=upstream_step_outputs,
        allowed_skip_targets=allowed_skip_targets,
    )

    logger.info(
        "iris_automation end (conv_id=%s, aborted=%s, turns=%d, trace_len=%d)",
        conversation_id,
        result.aborted,
        result.turns_used,
        len(result.trace),
    )

    # 4. Task #33 — Audit log atomique de la décision Iris (forensics +
    #    compliance cabinet comptable). Fail-soft : un échec audit ne doit
    #    PAS faire échouer le step Iris (la décision a déjà été prise).
    await _log_iris_decision(
        user_id=user_id,
        automation_id=automation_id,
        step_id=step_id,
        instruction=instruction,
        result=result,
    )

    return result


# ---------------------------------------------------------------------------
# Task #33 P6.6 — Audit log atomique des décisions Iris
# ---------------------------------------------------------------------------


async def _log_iris_decision(
    *,
    user_id: int,
    automation_id: int,
    step_id: Optional[int],
    instruction: str,
    result: IrisAutomationResult,
) -> None:
    """Log atomique de la décision Iris dans ``AuditLog``.

    Pattern conforme à la décision P0 Q8 (2026-05-27) :
    - Utilise la table ``AuditLog`` existante (pas de nouvelle table)
    - Retention gérée par ``db_retention._get_retention_days(env_var)``
      (ENV var ``AUDIT_LOG_IRIS_RETENTION_DAYS`` default 90 jours)
    - Fail-soft : un échec audit ne fait PAS échouer le step Iris
      (la décision a déjà été prise, l'audit est une garantie de
      traçabilité — pas une condition d'exécution)

    Détails persistés (capés à 4KB JSON par ``_cap_details`` de
    ``audit_log.py``) :
    - automation_id, step_id, conversation_id
    - instruction tronquée (500 chars)
    - decision_summary
    - aborted + abort_reason
    - variables écrites (noms seulement, pas les valeurs)
    - turns_used, trace_length
    """
    from app.core.database import get_session
    from app.models.audit import AuditAction
    from app.services.audit.audit_log import audit_event

    # Fix CRIT #4 (adversarial 2026-05-27) : anti-leak PII dans audit_logs.
    # L'instruction user + decision_summary du LLM contiennent potentiellement
    # des noms clients / SIRET / montants (= données les plus sensibles du
    # cabinet comptable). Anonymisation OBLIGATOIRE avant insertion BDD
    # (audit log persiste 90 jours, queryable par tout admin).
    instruction_safe = instruction[:500] if instruction else ""
    decision_safe = result.decision_summary[:500] if result.decision_summary else ""
    abort_reason_safe = result.abort_reason[:500] if result.abort_reason else None

    try:
        from app.services.anonymization import anonymize_for_llm

        if instruction_safe:
            instruction_safe, _ = await anonymize_for_llm(
                user_id, instruction_safe, "IRIS_CHAT"
            )
        if decision_safe:
            decision_safe, _ = await anonymize_for_llm(
                user_id, decision_safe, "IRIS_CHAT"
            )
        if abort_reason_safe:
            abort_reason_safe, _ = await anonymize_for_llm(
                user_id, abort_reason_safe, "IRIS_CHAT"
            )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:  # noqa: BLE001 — fail-soft : audit est défensif
        # Si l'anonymisation crash, on logue avec un placeholder safe
        # (jamais raw data en BDD audit).
        logger.warning(
            "iris_automation: échec anonymisation audit log — placeholders posés",
            exc_info=True,
        )
        instruction_safe = "[ANONYMIZATION_FAILED]"
        decision_safe = "[ANONYMIZATION_FAILED]"
        abort_reason_safe = "[ANONYMIZATION_FAILED]" if result.aborted else None

    details = {
        "automation_id": automation_id,
        "step_id": step_id,
        "conversation_id": result.conversation_id,
        "instruction": instruction_safe,
        "decision_summary": decision_safe,
        "aborted": result.aborted,
        "abort_reason": abort_reason_safe,
        "variables_written": sorted(result.variables.keys()),
        "turns_used": result.turns_used,
        "trace_length": len(result.trace),
        "llm_cost_usd": result.llm_cost_usd,
    }

    try:
        async with get_session() as session:
            await audit_event(
                session,
                user_id=user_id,
                action=AuditAction.IRIS_AUTOMATION_DECISION,
                entity_type="automation_step",
                entity_id=step_id,
                details=details,
            )
            await session.commit()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:  # noqa: BLE001 — fail-soft
        logger.warning(
            "iris_automation: échec audit_log de la décision (non bloquant). "
            "automation=%s step=%s conv=%s",
            automation_id,
            step_id,
            result.conversation_id,
            exc_info=True,
        )
