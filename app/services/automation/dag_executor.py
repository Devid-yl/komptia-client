"""
Executeur DAG pour les automatisations Phase 2.

Complementaire de `executor.py` (lineaire par `step_order`) : cette
implementation s'active quand une automation a des `edges` definies. La
traversee est topologique (Kahn), les nodes independants s'executent en
parallele, les donnees passent via `step_outputs[step_id]`.

Strategie strangler fig (design §6) :
- `executor.py` reste intact et gere les workflows linearies sans edges.
- Ce module gere les workflows DAG (au moins 1 edge definie).
- Le router vit dans `executor.execute_automation` : inspection de
  `automation.edges` pour choisir le chemin.

Design :
- Pas de dependance circulaire avec executor.py : les helpers communs
  (`_execute_query`, `_generate_nl_sql`, etc.) sont passes via le
  `AutomationExecutor` injecte comme dependance (duck-typed).
- Pas de context mutable global : chaque node lit ses inputs depuis
  `step_outputs[parent_id]` et ecrit dans `step_outputs[self.id]`.
- Fail policy configurable au niveau automation (`abort` defaut, `abort_all`,
  `best_effort`).
- Trace_id UUID propage a chaque step_execution.
- Parallelisme par niveau via `asyncio.gather` + semaphore configurable.

Limites Phase 2a :
- Fan-in workbook (merge des classeurs parents) supporte — mais aucun node
  ne le consomme vraiment encore (node `format`/copilot en Phase 2c).
- Pas de spill parquet : si un step_output > MAX_ROWS_PER_STEP_OUTPUT,
  troncature + warning. Phase 2d introduira le spill.
- Pas de retry automatique (on reutilise le retry par step du linear,
  a l'echelle d'un seul node).
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple

from app.core import clock
from app.models.automation import Automation
from app.models.automation_edge import AutomationEdge
from app.models.automation_step import AutomationStep
from app.services.automation.dag_step_error import format_step_error_message
from app.services.automation.workbook_service import (
    merge_workbooks,
    workbook_row_count,
    workbook_snapshot_for_db,
)
from app.utils.logger import get_logger

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


logger = get_logger(__name__)


# Semaphore max pour le parallelisme DAG. Borne protective pour ne pas
# noyer Sage / SMTP / LLM avec des dizaines de nodes concurrents.
# 2026-05-27 (Task #41) : ENV-configurable car lié à la capacité machine
# (CPU/RAM/connections pool). Default 4 = valeur historique.
# Override via ``KOMPTIA_DAG_MAX_PARALLEL_NODES`` (instance-spécifique).
import os as _os_for_env  # noqa: E402

try:
    DEFAULT_MAX_PARALLEL_NODES: int = int(
        _os_for_env.environ.get("KOMPTIA_DAG_MAX_PARALLEL_NODES", "4")
    )
    if DEFAULT_MAX_PARALLEL_NODES < 1:
        DEFAULT_MAX_PARALLEL_NODES = 4
except (TypeError, ValueError):
    DEFAULT_MAX_PARALLEL_NODES = 4


# =============================================================================
# Types internes
# =============================================================================


@dataclass
class DAGRunContext:
    """Contexte d'un run DAG. Immutable entre nodes sauf step_outputs."""

    automation_id: int
    execution_id: int
    user_id: int
    trace_id: str

    # step_id -> workbook produit par ce node (ou None si failed/skipped)
    step_outputs: Dict[int, Optional[Dict[str, Any]]] = field(default_factory=dict)

    # step_id -> fichier produit par ce node (rapport PDF, export CSV/Excel).
    # Permet au step `email` aval de recuperer les fichiers de TOUS ses parents
    # directs via les edges du DAG, pas seulement le dernier execute (sinon
    # un fan-in [rapport_A, rapport_B, export_csv] -> email n'enverrait que
    # le dernier fichier — bug fan-in casse).
    step_output_files: Dict[int, str] = field(default_factory=dict)

    # Variables inter-nodes (ex: {{node_name.var}}) — herite du comportement
    # WorkflowContext.variables pour retro-compat.
    variables: Dict[str, Any] = field(default_factory=dict)

    # Trigger payload (webhook body, scheduled_at, manual user_id)
    trigger_data: Dict[str, Any] = field(default_factory=dict)

    # Nodes exclus du traversal a cause d'un node parent failed (fail_policy="abort").
    # Ils sont marques "skipped" dans leur StepExecution.
    skipped_descendants: Set[int] = field(default_factory=set)

    # Si fail_policy="abort_all" et un node failed → True, on arrete tout.
    abort_all_triggered: bool = False

    # Phase 2d : compteurs pour le circuit-breaker (max_llm_cost, max_rows,
    # max_duration). Accumules au fur et a mesure de l'execution.
    cumulative_llm_cost_eur: float = 0.0
    cumulative_rows_out: int = 0
    run_started_at_monotonic: float = 0.0
    circuit_breaker_tripped: Optional[str] = None  # raison si actif

    # Cluster-T 2026-05-26 — Cap admin de rows (mirror
    # ``automation.max_total_rows``). Posé au démarrage du DAG runner
    # pour permettre le check fan-in OOM AVANT merge (vs après merge
    # via _check_circuit_breaker qui est trop tard). None = pas de cap.
    max_total_rows_cap: Optional[int] = None


@dataclass
class StepExecutionRecord:
    """Resultat d'execution d'un node, pour persister dans F_STEP_EXECUTION."""

    step_id: int
    step_order: int
    step_name: str
    step_type: str
    status: str  # pending/running/success/failed/skipped
    attempt_number: int = 1
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_ms: float = 0.0
    rows_in: int = 0
    rows_out: int = 0
    warnings: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    # Phase 2.5.6 (#77) — Classe de l'exception qui a fait planter le step.
    # Utilisé par ``executor.execute_automation`` (branche ``_has_failed``)
    # pour détecter spécifiquement ``DataAccessDeniedError`` et déclencher
    # l'auto-pause de l'automation. Sans ce field, le top-level
    # ``except Exception`` ne voit JAMAIS l'exception (catchée localement
    # par ``_execute_node_with_output`` et transformée en status='failed').
    error_class: Optional[str] = None
    trace_id: Optional[str] = None
    step_input: Optional[Dict[str, Any]] = None
    step_output: Optional[Dict[str, Any]] = None
    config_snapshot: Optional[Dict[str, Any]] = None
    sql_executed: Optional[str] = None
    # Phase 2d / 2e : metrics LLM (Optional, remontees par les adapters qui
    # invoquent un LLM via `extras`).
    llm_tokens_in: Optional[int] = None
    llm_tokens_out: Optional[int] = None
    llm_cost_eur: Optional[float] = None


# =============================================================================
# Traversee topologique (Kahn)
# =============================================================================


def topological_levels(
    steps: List[AutomationStep],
    edges: List[AutomationEdge],
) -> List[List[int]]:
    """Tri topologique par niveaux (algo de Kahn).

    Un "niveau" = ensemble des nodes dont tous les parents ont deja ete
    traites. Les nodes d'un meme niveau peuvent s'executer en parallele.

    Args:
        steps: Liste des AutomationStep (enabled uniquement recommande).
        edges: Liste des AutomationEdge.

    Returns:
        List[List[int]] : liste de niveaux, chaque niveau = liste d'ids.
        Les nodes d'un meme niveau sont sans dependance mutuelle.

    Raises:
        ValueError : si un cycle est detecte (theoriquement impossible
            apres validate_structural, mais defense-in-depth runtime).
    """
    step_ids: Set[int] = {s.id for s in steps}
    # in_degree[id] = nombre de parents pas encore traites
    in_degree: Dict[int, int] = {sid: 0 for sid in step_ids}
    # children[id] = liste des enfants
    children: Dict[int, List[int]] = {sid: [] for sid in step_ids}

    for edge in edges:
        if edge.from_step_id not in step_ids or edge.to_step_id not in step_ids:
            # Edge qui reference un step hors scope (ex: step disabled filtre).
            # Ignore pour le traversal mais remonte en warning au caller.
            continue
        children[edge.from_step_id].append(edge.to_step_id)
        in_degree[edge.to_step_id] += 1

    # Niveau 0 = tous les nodes sans parent
    current_level: List[int] = sorted([sid for sid, deg in in_degree.items() if deg == 0])
    levels: List[List[int]] = []
    processed: Set[int] = set()

    while current_level:
        levels.append(current_level)
        next_level: List[int] = []
        for sid in current_level:
            processed.add(sid)
            for child_id in children[sid]:
                in_degree[child_id] -= 1
                if in_degree[child_id] == 0:
                    next_level.append(child_id)
        current_level = sorted(next_level)

    # Detection de cycle : si un node n'a pas ete processe, cycle.
    remaining = step_ids - processed
    if remaining:
        raise ValueError(
            f"Cycle detecte dans le DAG (nodes restants: {sorted(remaining)}). "
            f"validate_structural aurait du bloquer ca en amont."
        )

    return levels


# =============================================================================
# Construction du workbook d'entree (fan-in)
# =============================================================================


def build_node_input(
    node: AutomationStep,
    parent_edges: List[AutomationEdge],
    step_outputs: Dict[int, Optional[Dict[str, Any]]],
    context: Optional["DAGRunContext"] = None,
) -> Optional[Dict[str, Any]]:
    """Construit le workbook d'entree d'un node a partir de ses parents.

    - 0 parent : retourne None (node source).
    - 1 parent data : retourne directement step_outputs[parent_id].
    - N parents data (fan-in) : fusion des onglets via `merge_workbooks`.
    - Parents `data_type='trigger'` : IGNORES de la fusion. Ils ne
      transmettent que le signal « j'ai fini » au DAG executor (qui
      les considere comme prerequis topologiques pour declencher
      ce node), sans transmettre de donnees. Cas typique : « envoie
      un mail quand A et B ont fini, sans attacher leurs donnees ».

    Si un parent data a un output None (failed/skipped en mode
    best_effort), il est ignore de la fusion (et ajoute un warning).
    """
    if not parent_edges:
        return None

    # Filtrer les edges trigger : ils ne portent pas de donnees, ils
    # servent uniquement au sequencement topologique. Le DAG executor
    # garantit deja que le node ne demarre que quand TOUS ses parents
    # (trigger inclus) ont fini — voir niveaux Kahn ligne 690+.
    data_edges = [e for e in parent_edges if getattr(e, "data_type", None) != "trigger"]

    if not data_edges:
        # Tous les parents sont trigger → ce node ne recoit aucune
        # donnee, juste le signal d'execution. Coherent avec le contrat
        # « connexion = sequencement, pas transmission ».
        return None

    parent_workbooks: List[Dict[str, Any]] = []
    missing_parents: List[int] = []
    for edge in data_edges:
        parent_output = step_outputs.get(edge.from_step_id)
        if parent_output is None:
            missing_parents.append(edge.from_step_id)
            continue
        parent_workbooks.append(parent_output)

    if not parent_workbooks:
        # Tous les parents data sont failed → pas d'input utilisable
        return None

    if len(parent_workbooks) == 1 and not missing_parents:
        # Copie defensive : en fan-out (1 parent -> N enfants), chaque enfant
        # doit recevoir un workbook independant. Sans cette copie, une mutation
        # in-place dans un adapter (ex. .tabs.append, .warnings.append) pollue
        # le workbook vu par les siblings ET altere step_outputs[parent_id]
        # qui devient l'input des grands-enfants. Aligne sur la copie defensive
        # de merge_workbooks (workbook_service.py:165-167). Surcout : 1 shallow
        # dict + N shallow tab dicts — negligeable vs. l'I/O du workbook.
        sole_parent = parent_workbooks[0]
        # Garde defensive : si le checkpoint resume_state stocke un payload
        # corrompu en BDD (non-dict apres deserialisation JSON), on preserve
        # le comportement pre-fix plutot que crasher sur `dict(non_dict)`.
        if not isinstance(sole_parent, dict):
            return sole_parent
        new_wb = dict(sole_parent)
        tabs = sole_parent.get("tabs")
        if isinstance(tabs, list):
            new_wb["tabs"] = [dict(t) if isinstance(t, dict) else t for t in tabs]
        warnings = sole_parent.get("warnings")
        if isinstance(warnings, list):
            new_wb["warnings"] = list(warnings)
        return new_wb

    # Cluster-T 2026-05-26 — Fan-in OOM check AVANT merge. Sans cette
    # garde, 5 parents × 100k rows = 500k rows chargés en RAM par
    # ``merge_workbooks`` avant que ``_check_circuit_breaker`` post-node
    # ne lève. Pour les déploiements limités RAM (cabinet single-tenant
    # 4 GB), c'est suffisant pour OOM.
    #
    # Si ``context`` est None (callers tests anciens) ou si le cap n'est
    # pas configuré, on skip — admin a explicitement autorisé du illimité.
    if context is not None:
        automation_max_total_rows = getattr(context, "max_total_rows_cap", None)
        if automation_max_total_rows is not None and automation_max_total_rows > 0:
            from app.services.automation.workbook_service import (
                count_total_rows_in_workbooks,
            )

            incoming_rows = count_total_rows_in_workbooks(parent_workbooks)
            projected = context.cumulative_rows_out + incoming_rows
            if projected > automation_max_total_rows:
                logger.warning(
                    "Cluster-T fan-in OOM check: projected=%d > cap=%d "
                    "(incoming=%d + cumulative=%d). Abort merge.",
                    projected,
                    automation_max_total_rows,
                    incoming_rows,
                    context.cumulative_rows_out,
                )
                raise FanInTooLargeError(
                    f"Fan-in OOM: projection {projected} rows > cap "
                    f"{automation_max_total_rows} (incoming {incoming_rows}, "
                    f"cumulative {context.cumulative_rows_out}). "
                    f"Augmentez max_total_rows ou filtrez les parents."
                )

    merged = merge_workbooks(parent_workbooks)
    if missing_parents:
        merged.setdefault("warnings", []).append(
            f"Parents failed/skipped ignores a la fusion: {missing_parents}"
        )
    return merged


class FanInTooLargeError(Exception):
    """Cluster-T 2026-05-26 — Levée quand un fan-in projeterait un
    nombre de rows > automation.max_total_rows. Distincte des autres
    erreurs runtime pour permettre au DAG executor de signaler
    proprement le step failed avec le motif exact."""

    pass


# =============================================================================
# Execution d'un node via adapter
# =============================================================================


# Signature de l'adapter : (node, input_workbook, context) -> (output_workbook, record_extras)
#
# `record_extras` peut porter :
# - `sql_executed` : SQL effectif envoye a Sage (nodes SQL)
# - `warnings` : liste de str warnings non-fatals
# - `config_snapshot` : config resolue (apres {{variables}})
# - `llm_tokens_in`, `llm_tokens_out`, `llm_cost_eur` : metrics LLM (Phase 2e)
# - `output_file` : path du fichier produit (nodes report)
#
# **CONTRAT DE MUTATION** (IMPORTANT) :
# - L'adapter DOIT retourner le output_workbook (le dag_executor le stocke
#   dans context.step_outputs[node.id] lui-meme, apres le gather).
# - L'adapter NE DOIT PAS muter `context.step_outputs`, `context.cumulative_*`,
#   `context.circuit_breaker_tripped`, `context.skipped_descendants`,
#   `context.abort_all_triggered`. Ces champs appartiennent au dag_executor
#   qui les met a jour en post-traitement SEQUENTIEL (hors gather) pour
#   eviter les races sur les nodes paralleles.
# - L'adapter PEUT muter `context.variables[...]` (ex: `_output_file` pour
#   propager le path d'un rapport aux nodes suivants).
NodeExecutor = Callable[
    [AutomationStep, Optional[Dict[str, Any]], DAGRunContext],
    Awaitable[Tuple[Optional[Dict[str, Any]], Dict[str, Any]]],
]


def _merge_input_warnings(
    input_workbook: Optional[Dict[str, Any]], extras: Dict[str, Any]
) -> List[str]:
    """Combine les warnings de l'``input_workbook`` avec ceux du step (``extras``).

    Fix #10 2026-06-11 (donnée fausse SILENCIEUSE). En fan-in, quand un parent a
    échoué, ``build_node_input`` pose un warning « Parents failed/skipped ignores
    a la fusion » DANS ``input_workbook['warnings']``. Avant ce fix, le record du
    step downstream ne reprenait QUE ``extras['warnings']`` → le warning de
    fan-in était perdu et un rapport bâti sur des données PARTIELLES (un parent
    disparu) ne portait aucune trace visible (statut « success »).

    On combine donc les deux sources, en préservant l'ordre (warnings d'input
    d'abord — ils décrivent les données consommées) et en dédupliquant.
    """
    combined: List[str] = []
    seen: set = set()
    src_in = input_workbook.get("warnings") if isinstance(input_workbook, dict) else None
    for _w in (src_in or []):
        if isinstance(_w, str) and _w not in seen:
            seen.add(_w)
            combined.append(_w)
    for _w in (extras.get("warnings") or []):
        if isinstance(_w, str) and _w not in seen:
            seen.add(_w)
            combined.append(_w)
    return combined


async def _execute_node_with_output(
    node: AutomationStep,
    input_workbook: Optional[Dict[str, Any]],
    context: DAGRunContext,
    executor_adapter: NodeExecutor,
) -> Tuple[StepExecutionRecord, Optional[Dict[str, Any]]]:
    """Execute un node et retourne (record, output_workbook) pour que le
    dag_executor puisse peupler step_outputs lui-meme (le contrat avec
    l'adapter est : il retourne output_workbook, on le stocke).
    """
    started_at = clock.now()
    t_start = time.perf_counter()
    rows_in = workbook_row_count(input_workbook) if input_workbook else 0

    # #18 fix 2026-06-11 — RETRY par step (OPT-IN, défaut max_retries=0). Honore
    # ``node.max_retries`` / ``node.retry_delay_seconds``, jusqu'ici IGNORÉS par
    # le DAG (le commentaire d'en-tête « pas de retry » était stale ; le canvas
    # expose pourtant ces champs → promesse sans code). Mêmes bornes que le
    # chemin linéaire (0-5 tentatives supplémentaires, délai 1-60 s). SÛR côté
    # LIVRAISON : un sink (email/report/export) RELÂCHE son claim d'idempotence
    # sur l'échec qui déclenche le retry (Cluster-E #5b) → la ré-tentative
    # re-exécute sans skip silencieux, et sans DOUBLE-ENVOI (l'email ne lève que
    # si sent_count==0, donc rien n'est parti ; un envoi partiel ne lève pas →
    # pas de retry). ``WaitForResponse`` n'est JAMAIS retry (suspension, pas échec).
    # ⚠️ COÛT : le retry rejoue l'adapter ENTIER, donc les appels LLM
    # intermédiaires d'un step report (``plan_report``) sont RE-FACTURÉS à chaque
    # tentative si l'échec survient APRÈS l'appel LLM (pas de cache inter-essais).
    # Acceptable car opt-in (défaut 0) — l'utilisateur qui active le retry sur un
    # step report accepte ce coût ; documenté ici pour ne pas le masquer.
    raw_retries = getattr(node, "max_retries", 0)
    max_retries = min(max(raw_retries, 0), 5) if isinstance(raw_retries, int) else 0
    raw_delay = getattr(node, "retry_delay_seconds", 5)
    retry_delay = min(max(raw_delay, 1), 60) if isinstance(raw_delay, int) else 5
    max_attempts = max_retries + 1

    from app.core.exceptions import WaitForResponse as _WaitForResponse

    attempt = 0
    while True:
        attempt += 1
        try:
            output_workbook, extras = await executor_adapter(node, input_workbook, context)
            break  # succès → sort de la boucle de retry
        except Exception as exc:
            # WaitForResponse n'est PAS une erreur — c'est un signal de
            # suspension (attente d'une réponse externe). On NE retry PAS : on
            # marque le step `waiting` et on remonte l'exception pour que
            # dag_executor stoppe la cascade SANS marquer l'execution failed.
            if isinstance(exc, _WaitForResponse):
                duration_ms = (time.perf_counter() - t_start) * 1000
                logger.info(
                    "DAG node waiting: step_id=%d name='%s' type='%s' wait_token_id=%s",
                    node.id,
                    node.name,
                    node.step_type,
                    getattr(exc, "wait_token_id", None),
                )
                wait_record = StepExecutionRecord(
                    step_id=node.id,
                    step_order=node.step_order or 0,
                    step_name=node.name,
                    step_type=node.step_type,
                    status="waiting",
                    attempt_number=attempt,
                    started_at=started_at,
                    finished_at=None,
                    duration_ms=duration_ms,
                    rows_in=rows_in,
                    rows_out=0,
                    error_message=None,
                    trace_id=context.trace_id,
                    step_input=(
                        workbook_snapshot_for_db(input_workbook) if input_workbook else None
                    ),
                )
                exc.step_record = wait_record  # type: ignore[attr-defined]
                raise

            # Échec : retry si des tentatives restent (sinon record failed).
            if attempt < max_attempts:
                logger.warning(
                    "DAG node retry: step_id=%d name='%s' tentative %d/%d échouée "
                    "(%s) — nouvelle tentative dans %d s.",
                    node.id,
                    node.name,
                    attempt,
                    max_attempts,
                    type(exc).__name__,
                    retry_delay,
                )
                await asyncio.sleep(retry_delay)
                continue

            duration_ms = (time.perf_counter() - t_start) * 1000
            logger.error(
                "DAG node failed: step_id=%d name='%s' type='%s' error=%s (apres %d tentative(s))",
                node.id,
                node.name,
                node.step_type,
                exc,
                attempt,
                exc_info=True,
            )
            record = StepExecutionRecord(
                step_id=node.id,
                step_order=node.step_order or 0,
                step_name=node.name,
                step_type=node.step_type,
                status="failed",
                attempt_number=attempt,
                started_at=started_at,
                finished_at=clock.now(),
                duration_ms=duration_ms,
                rows_in=rows_in,
                rows_out=0,
                error_message=format_step_error_message(exc),
                # Phase 2.5.6 (#77) — propage la classe d'exception pour que le
                # caller détecte les ``DataAccessDeniedError`` (auto-pause RLS).
                error_class=type(exc).__name__,
                trace_id=context.trace_id,
                step_input=workbook_snapshot_for_db(input_workbook) if input_workbook else None,
            )
            return record, None

    duration_ms = (time.perf_counter() - t_start) * 1000
    rows_out = workbook_row_count(output_workbook) if output_workbook else 0
    input_snap = workbook_snapshot_for_db(input_workbook) if input_workbook else None
    output_snap = workbook_snapshot_for_db(output_workbook) if output_workbook else None

    record = StepExecutionRecord(
        step_id=node.id,
        step_order=node.step_order or 0,
        step_name=node.name,
        step_type=node.step_type,
        status="success",
        attempt_number=attempt,
        started_at=started_at,
        finished_at=clock.now(),
        duration_ms=duration_ms,
        rows_in=rows_in,
        rows_out=rows_out,
        warnings=_merge_input_warnings(input_workbook, extras),
        trace_id=context.trace_id,
        step_input=input_snap,
        step_output=output_snap,
        config_snapshot=extras.get("config_snapshot"),
        sql_executed=extras.get("sql_executed"),
        llm_tokens_in=extras.get("llm_tokens_in"),
        llm_tokens_out=extras.get("llm_tokens_out"),
        llm_cost_eur=extras.get("llm_cost_eur"),
    )

    # Propager le fichier produit (rapport PDF, export csv/excel) dans
    # step_output_files indexe par node.id : permet a un step `email` aval
    # de recuperer les fichiers de TOUS ses parents directs (fan-in
    # multi-fichiers), pas seulement le dernier execute.
    out_file = extras.get("output_file")
    if out_file is not None:
        context.step_output_files[node.id] = str(out_file)

    return record, output_workbook


def _purge_consumed_outputs(
    context: DAGRunContext,
    edges: List[AutomationEdge],
    *,
    processed_ids: Set[int],
    processed_so_far: Set[int],
) -> None:
    """Libere les step_outputs des parents dont tous les enfants ont ete traites.

    Evite la retention memoire de workbooks inutiles sur des workflows
    longs (fan-out + gros classeurs). On purge conservativement : un parent
    est libere uniquement si TOUS ses enfants sont dans processed_ids
    ∪ processed_so_far.
    """
    # Pre-compute enfants de chaque node
    children: Dict[int, List[int]] = {}
    for edge in edges:
        children.setdefault(edge.from_step_id, []).append(edge.to_step_id)

    # Les candidats a purger : nodes processes dans ce niveau OU avant
    candidates = processed_ids | processed_so_far
    # Un parent peut etre purge si tous ses enfants sont processes
    already_in_outputs = set(context.step_outputs.keys())
    for parent_id in list(already_in_outputs):
        child_ids = children.get(parent_id, [])
        if not child_ids:
            # Sink : pas de consommateur, on garde pour le caller (results finaux)
            continue
        if all(cid in candidates for cid in child_ids):
            # Tous les enfants ont ete traites → plus besoin du parent
            del context.step_outputs[parent_id]


async def execute_node(
    node: AutomationStep,
    input_workbook: Optional[Dict[str, Any]],
    context: DAGRunContext,
    executor_adapter: NodeExecutor,
) -> StepExecutionRecord:
    """Execute un node via l'adapter, produit un StepExecutionRecord.

    L'adapter est injecte pour decoupler ce module de l'implementation
    concrete (qui vit dans `executor.py` et fait les vrais appels SQL/SMTP/LLM).
    """
    started_at = clock.now()
    t_start = time.perf_counter()
    rows_in = workbook_row_count(input_workbook) if input_workbook else 0

    try:
        output_workbook, extras = await executor_adapter(node, input_workbook, context)
        duration_ms = (time.perf_counter() - t_start) * 1000
        rows_out = workbook_row_count(output_workbook) if output_workbook else 0

        # Snapshot tronque pour stockage en BDD
        input_snap = workbook_snapshot_for_db(input_workbook) if input_workbook else None
        output_snap = workbook_snapshot_for_db(output_workbook) if output_workbook else None

        return StepExecutionRecord(
            step_id=node.id,
            step_order=node.step_order or 0,
            step_name=node.name,
            step_type=node.step_type,
            status="success",
            started_at=started_at,
            finished_at=clock.now(),
            duration_ms=duration_ms,
            rows_in=rows_in,
            rows_out=rows_out,
            warnings=_merge_input_warnings(input_workbook, extras),
            trace_id=context.trace_id,
            step_input=input_snap,
            step_output=output_snap,
            config_snapshot=extras.get("config_snapshot"),
            sql_executed=extras.get("sql_executed"),
        )
    except Exception as exc:
        duration_ms = (time.perf_counter() - t_start) * 1000
        logger.error(
            "DAG node failed: step_id=%d name='%s' type='%s' error=%s",
            node.id,
            node.name,
            node.step_type,
            exc,
            exc_info=True,
        )
        return StepExecutionRecord(
            step_id=node.id,
            step_order=node.step_order or 0,
            step_name=node.name,
            step_type=node.step_type,
            status="failed",
            started_at=started_at,
            finished_at=clock.now(),
            duration_ms=duration_ms,
            rows_in=rows_in,
            rows_out=0,
            error_message=format_step_error_message(exc),
            # Parite avec ``_execute_node_with_output`` (ligne 455) : propage la
            # classe d'exception pour que le check ``getattr(rec, "error_class",
            # None) == "DataAccessDeniedError"`` cote executor declenche
            # l'auto-pause RLS (Phase 2.5.6 #77). Sans ce champ, ``execute_node``
            # (callsite tests + futur runtime) renvoyait des records ou
            # ``error_class`` etait None apres reload BDD.
            error_class=type(exc).__name__,
            trace_id=context.trace_id,
            step_input=workbook_snapshot_for_db(input_workbook) if input_workbook else None,
        )


# =============================================================================
# Fail policy : calcul des descendants a skipper
# =============================================================================


def compute_descendants(
    start_ids: Set[int],
    edges: List[AutomationEdge],
) -> Set[int]:
    """BFS : renvoie tous les descendants transitifs de `start_ids`.

    Utilise pour fail_policy="abort" : quand un node echoue, on skip tous
    ses descendants transitifs (mais pas les branches independantes).
    """
    children: Dict[int, List[int]] = {}
    for edge in edges:
        children.setdefault(edge.from_step_id, []).append(edge.to_step_id)

    descendants: Set[int] = set()
    queue: List[int] = list(start_ids)
    while queue:
        cur = queue.pop(0)
        for child in children.get(cur, []):
            if child not in descendants:
                descendants.add(child)
                queue.append(child)
    return descendants


def compute_ancestors(
    start_ids: Set[int],
    edges: List[AutomationEdge],
) -> Set[int]:
    """BFS inverse : renvoie tous les ancetres transitifs de `start_ids`.

    Utilise par le step `email` pour collecter les fichiers produits par
    TOUS ses ancetres (rapport PDF, export csv/excel) — pas seulement le
    parent direct. Cas d'usage : fan-in [rapport_A, rapport_B] -> email
    doit attacher les deux PDFs ; aussi
    source -> format -> rapport -> email : email doit recuperer le PDF
    du rapport (ancetre) sans le confondre avec un quelconque "fichier
    source" (les sources ne produisent pas de fichier).
    """
    parents: Dict[int, List[int]] = {}
    for edge in edges:
        parents.setdefault(edge.to_step_id, []).append(edge.from_step_id)

    ancestors: Set[int] = set()
    queue: List[int] = list(start_ids)
    while queue:
        cur = queue.pop(0)
        for parent in parents.get(cur, []):
            if parent not in ancestors:
                ancestors.add(parent)
                queue.append(parent)
    return ancestors


# =============================================================================
# Pipeline DAG : point d'entree principal
# =============================================================================


def _check_circuit_breaker(context: DAGRunContext, automation: Automation) -> Optional[str]:
    """Verifie les limites circuit-breaker. Retourne une raison si depassement.

    Args:
        context: DAGRunContext avec compteurs cumulatifs.
        automation: Automation avec les seuils (peuvent etre None = illimite).

    Returns:
        str raison si trip, None sinon.
    """
    if (
        automation.max_llm_cost_eur is not None
        and context.cumulative_llm_cost_eur > automation.max_llm_cost_eur
    ):
        return (
            f"max_llm_cost_eur depasse: "
            f"{context.cumulative_llm_cost_eur:.4f} > {automation.max_llm_cost_eur}"
        )
    if (
        automation.max_total_rows is not None
        and context.cumulative_rows_out > automation.max_total_rows
    ):
        return (
            f"max_total_rows depasse: "
            f"{context.cumulative_rows_out} > {automation.max_total_rows}"
        )
    if automation.max_duration_seconds is not None:
        import time as _time

        elapsed = _time.monotonic() - context.run_started_at_monotonic
        if elapsed > automation.max_duration_seconds:
            return (
                f"max_duration_seconds depasse: "
                f"{elapsed:.1f}s > {automation.max_duration_seconds}s"
            )
    return None


async def run_dag_pipeline(
    session: "AsyncSession",
    automation: Automation,
    execution_id: int,
    executor_adapter: NodeExecutor,
    *,
    trigger_data: Optional[Dict[str, Any]] = None,
    max_parallel: int = DEFAULT_MAX_PARALLEL_NODES,
    edges_override: Optional[List[AutomationEdge]] = None,
    resume_state: Optional[Dict[str, Any]] = None,
    on_level_complete: Optional[Any] = None,
) -> Tuple[DAGRunContext, List[StepExecutionRecord]]:
    """Execute un workflow DAG. Retourne (context_final, records_par_step).

    Args:
        session: Session SQLAlchemy async (pour loader les relations).
        automation: Automation avec `steps` et `edges` deja eager-loaded.
        execution_id: ID de l'`Execution` parent.
        executor_adapter: Callable qui sait executer un node (injecte par
            `AutomationExecutor` pour acceder aux helpers DB/SMTP/LLM).
        trigger_data: Payload du trigger (webhook body, etc.).
        max_parallel: Borne de parallelisme par niveau.
        edges_override: Si fourni, utilise cette liste d'edges au lieu de
            ``automation.edges``. Utilise par le routing D1 cycle 15 pour
            synthétiser une chaîne linéaire en mémoire quand une auto a
            des steps mais pas encore d'edges persistées (rétro-compat
            avec les autos créées avant la phase DAG).
        on_level_complete: Callback async optionnel invoqué APRÈS chaque niveau
            du DAG avec ``all_records`` (cumulatif). Sert au flush INCRÉMENTAL
            des StepExecution pour la progression live du moniteur (ENGINE-2).
            Si ``None`` (ex. chemin resume), aucun flush incrémental — la
            persistance finale via ``_persist_dag_step_results`` reste garantie.
            Best-effort : une exception du callback est loggée, le run continue.

    Returns:
        (DAGRunContext, List[StepExecutionRecord]) : contexte final pour
        audit et liste des records a persister dans F_STEP_EXECUTION.
    """
    trace_id = str(uuid.uuid4())
    context = DAGRunContext(
        automation_id=automation.id,
        execution_id=execution_id,
        user_id=automation.user_id,
        trace_id=trace_id,
        trigger_data=trigger_data or {},
        run_started_at_monotonic=time.monotonic(),
        # Cluster-T 2026-05-26 — Mirror le cap admin pour permettre
        # le fan-in OOM check AVANT merge_workbooks.
        max_total_rows_cap=getattr(automation, "max_total_rows", None),
    )

    # Injecter trigger_data en variables {{trigger.*}} (retro-compat avec
    # le linear executor qui fait la meme chose).
    for ns, values in (trigger_data or {}).items():
        if isinstance(values, dict):
            for k, v in values.items():
                context.variables[f"{ns}.{k}"] = v
        else:
            context.variables[ns] = values

    all_steps = list(automation.steps)
    active_steps = [s for s in all_steps if s.is_enabled]
    steps_by_id: Dict[int, AutomationStep] = {s.id: s for s in active_steps}
    all_steps_by_id: Dict[int, AutomationStep] = {s.id: s for s in all_steps}
    # D1 cycle 15 : si edges_override fourni, on l'utilise (cas synthèse linéaire
    # pour autos sans edges persistées). Sinon, source de vérité = BDD.
    edges_list = list(edges_override) if edges_override is not None else list(automation.edges)

    if not active_steps:
        logger.warning("DAG run: aucune etape active pour automation %d", automation.id)
        return context, []

    # Defense in depth (design §3 safety) : un step desactive AU MILIEU d'une
    # chaine DAG ne doit pas laisser ses descendants s'executer avec un input
    # vide. On detecte toutes les edges qui referencent un disabled et on
    # skip transitivement les descendants (meme logique que fail_policy="abort").
    #
    # Semantique fan-in (aligne sur dag_validator.py:654-742 fix task #22) :
    # un target avec plusieurs parents N'EST POISONED que si TOUS ses parents
    # sont disabled (ou eux-memes poisoned transitivement). Sinon, les
    # parents enabled fournissent une fallback source valide et le target
    # doit runner. Avant le fix (task #35), un seul parent disabled
    # empoisonnait le target meme avec des parents enabled — promesse
    # validator (DAG valide) != executeur (skip silencieux).
    #
    # Algorithme : fixed-point. Pour les cas diamond (A->B; A->C; B->D; C->D
    # avec B disabled), D doit runner car C (autre parent) est enabled.
    # compute_descendants seul propage trop largement (B->D ferait poison D
    # sans regarder le 2eme parent C). Le fixed-point regarde la condition
    # "tous mes parents sont poisoned" a chaque iteration jusqu'a stabilisation.
    disabled_ids: Set[int] = {s.id for s in all_steps if not s.is_enabled}
    if disabled_ids:
        # incoming_edges[target_id] = set des from_step_id qui pointent vers target_id.
        # Pas de defaultdict pour eviter un nouvel import — setdefault suffit.
        incoming_edges: Dict[int, Set[int]] = {}
        for edge in edges_list:
            incoming_edges.setdefault(edge.to_step_id, set()).add(edge.from_step_id)
        # Seed = disabled. Un node devient poisoned si TOUS ses parents
        # sont poisoned (transitivement). Pas de short-circuit possible
        # car un node peut etre revisite si un de ses parents devient
        # poisoned plus tard dans l'iteration.
        poisoned: Set[int] = set(disabled_ids)
        changed = True
        while changed:
            changed = False
            for target_id, sources in incoming_edges.items():
                if target_id not in poisoned and sources.issubset(poisoned):
                    poisoned.add(target_id)
                    changed = True
        context.skipped_descendants.update(poisoned)
        logger.warning(
            "DAG run %d: %d step(s) desactive(s) au milieu du graphe, "
            "descendants marques skipped pour eviter des donnees silencieusement fausses: %s",
            execution_id,
            len(disabled_ids),
            sorted(context.skipped_descendants),
        )

    # Pre-calcul : parents de chaque node (pour build_node_input)
    parents_by_node: Dict[int, List[AutomationEdge]] = {}
    for edge in edges_list:
        if edge.to_step_id in steps_by_id and edge.from_step_id in steps_by_id:
            parents_by_node.setdefault(edge.to_step_id, []).append(edge)

    try:
        levels = topological_levels(active_steps, edges_list)
    except ValueError as exc:
        logger.error("DAG run %d: cycle detecte a l'execution: %s", execution_id, exc)
        raise

    fail_policy = (automation.fail_policy or "abort").lower()
    if fail_policy not in ("abort", "abort_all", "best_effort"):
        fail_policy = "abort"

    sem = asyncio.Semaphore(max(1, max_parallel))
    all_records: List[StepExecutionRecord] = []
    processed_so_far: Set[int] = set()

    # Reprise apres un step waiting (cf. resume_automation_job).
    # `resume_state` pre-remplit step_outputs/step_output_files avec les
    # outputs des steps deja executes AVANT le wait, et `skip_step_ids`
    # liste les steps a NE PAS re-executer (on les considere comme deja
    # `success`, leur output est deja dans step_outputs). Le DAG continue
    # naturellement avec les niveaux Kahn aval.
    skip_step_ids: Set[int] = set()
    if resume_state:
        pre_outputs = resume_state.get("step_outputs") or {}
        pre_files = resume_state.get("step_output_files") or {}
        skip_step_ids = set(resume_state.get("skip_step_ids") or [])
        # Hydrater le context AVANT la boucle pour que build_node_input
        # voie les outputs des parents au moment de calculer l'input du
        # premier node a re-executer.
        for sid, wb in pre_outputs.items():
            context.step_outputs[int(sid)] = wb
        for sid, path in pre_files.items():
            context.step_output_files[int(sid)] = path
        # Marquer ces ids comme deja processed pour le purge memoire.
        processed_so_far.update(skip_step_ids)
        logger.info(
            "DAG run %d (RESUME): %d steps deja calcules, skip ids=%s",
            execution_id,
            len(skip_step_ids),
            sorted(skip_step_ids),
        )

    logger.info(
        "DAG run %d: trace_id=%s, %d niveaux, fail_policy=%s, max_parallel=%d",
        execution_id,
        trace_id,
        len(levels),
        fail_policy,
        max_parallel,
    )

    for level_idx, level_step_ids in enumerate(levels):
        # Circuit-breaker : si deja trip par un niveau precedent, on skip tout
        if context.circuit_breaker_tripped:
            for sid in level_step_ids:
                node = steps_by_id[sid]
                all_records.append(
                    StepExecutionRecord(
                        step_id=node.id,
                        step_order=node.step_order or 0,
                        step_name=node.name,
                        step_type=node.step_type,
                        status="skipped",
                        attempt_number=1,
                        started_at=clock.now(),
                        finished_at=clock.now(),
                        duration_ms=0.0,
                        error_message=(
                            f"Skipped (circuit-breaker: {context.circuit_breaker_tripped})"
                        ),
                        trace_id=trace_id,
                    )
                )
            continue
        if context.abort_all_triggered:
            # fail_policy="abort_all" : marquer tous les restants comme skipped
            for sid in level_step_ids:
                node = steps_by_id[sid]
                all_records.append(
                    StepExecutionRecord(
                        step_id=node.id,
                        step_order=node.step_order or 0,
                        step_name=node.name,
                        step_type=node.step_type,
                        status="skipped",
                        attempt_number=1,
                        started_at=clock.now(),
                        finished_at=clock.now(),
                        duration_ms=0.0,
                        error_message="Skipped (fail_policy=abort_all, upstream failed)",
                        trace_id=trace_id,
                    )
                )
                context.skipped_descendants.add(sid)
            continue

        # Filtrer les nodes skipped en cas de fail_policy="abort"
        nodes_to_run: List[AutomationStep] = []
        for sid in level_step_ids:
            # Resume : les steps deja executes AVANT le wait sont dans
            # `skip_step_ids`, leurs outputs sont deja dans context. On
            # ne les re-execute PAS et on n'ajoute PAS de StepExecutionRecord
            # (les rows BDD existent deja en BDD via le run initial).
            if sid in skip_step_ids:
                continue
            if sid in context.skipped_descendants:
                node = steps_by_id[sid]
                all_records.append(
                    StepExecutionRecord(
                        step_id=node.id,
                        step_order=node.step_order or 0,
                        step_name=node.name,
                        step_type=node.step_type,
                        status="skipped",
                        attempt_number=1,
                        started_at=clock.now(),
                        finished_at=clock.now(),
                        duration_ms=0.0,
                        error_message="Skipped (ancestor failed, fail_policy=abort)",
                        trace_id=trace_id,
                    )
                )
                continue
            nodes_to_run.append(steps_by_id[sid])

        if not nodes_to_run:
            continue

        # Execution parallele du niveau avec semaphore.
        # On collecte a la fois le record (pour persistance) ET le output
        # brut (pour alimenter step_outputs — responsabilite du dag_executor,
        # plus de l'adapter, pour eviter le couplage fragile).
        async def _guarded_exec(
            node_arg: AutomationStep,
        ) -> Tuple[StepExecutionRecord, Optional[Dict[str, Any]]]:
            async with sem:
                # Phase 2d : pre-check circuit-breaker AVANT d'executer l'adapter.
                # Evite de materialiser un gros workbook alors qu'on va le
                # jeter juste apres (le post-check tirait trop tard).
                pre_trip = _check_circuit_breaker(context, automation)
                if pre_trip is not None:
                    context.circuit_breaker_tripped = pre_trip
                    skip_record = StepExecutionRecord(
                        step_id=node_arg.id,
                        step_order=node_arg.step_order or 0,
                        step_name=node_arg.name,
                        step_type=node_arg.step_type,
                        status="skipped",
                        attempt_number=1,
                        started_at=clock.now(),
                        finished_at=clock.now(),
                        duration_ms=0.0,
                        error_message=f"Skipped (circuit-breaker: {pre_trip})",
                        trace_id=context.trace_id,
                    )
                    return skip_record, None
                input_wb = build_node_input(
                    node_arg,
                    parents_by_node.get(node_arg.id, []),
                    context.step_outputs,
                    context=context,
                )
                rec, output_wb = await _execute_node_with_output(
                    node_arg, input_wb, context, executor_adapter
                )
                return rec, output_wb

        # Cas special : WaitForResponse leve par un node → on stoppe le
        # DAG proprement sans marquer failed. On utilise return_exceptions=True
        # uniquement pour intercepter ce cas (les autres exceptions sont
        # deja transformees en record.status='failed' par
        # _execute_node_with_output, donc elles ne remontent pas ici en
        # temps normal — sauf pour WaitForResponse qui re-raise).
        from app.core.exceptions import WaitForResponse as _WaitForResponse

        gather_results = await asyncio.gather(
            *[_guarded_exec(n) for n in nodes_to_run],
            return_exceptions=True,
        )
        wait_signal: Optional[_WaitForResponse] = None
        level_results: List[Tuple[StepExecutionRecord, Optional[Dict[str, Any]]]] = []
        for r in gather_results:
            if isinstance(r, _WaitForResponse):
                # Recupere le record attache par _execute_node_with_output
                wait_record = getattr(r, "step_record", None)
                if wait_record is not None:
                    level_results.append((wait_record, None))
                if wait_signal is None:
                    wait_signal = r
            elif isinstance(r, BaseException):
                # Les autres exceptions ne devraient PAS remonter ici (deja
                # transformees en record.status='failed' par
                # _execute_node_with_output). Si on en voit une, on
                # log + on re-raise pour ne pas masquer un bug.
                logger.error(
                    "DAG run %d: exception non-attendue dans gather",
                    execution_id,
                    exc_info=r,
                )
                raise r
            else:
                level_results.append(r)

        # Post-traitement : collecter les outputs + appliquer fail policy
        for record, output_wb in level_results:
            all_records.append(record)
            if record.status == "success":
                # Le dag_executor est la seule source de verite pour step_outputs.
                # Garanti : si success → output stocke. Si failed → None.
                context.step_outputs[record.step_id] = output_wb
                # Phase 2d : accumulation post-gather (sequentielle, pas de race).
                # Les adapters NE DOIVENT PAS muter context.cumulative_* — ils
                # retournent les mesures via StepExecutionRecord (rows_out) ou
                # via `record.llm_tokens_*` / `record.llm_cost_eur` (Phase 2e
                # quand les adapters LLM tracent le cost via extras).
                context.cumulative_rows_out += record.rows_out or 0
                # Accumulation du cout LLM si renseigne (sinon 0.0, aucun effet).
                # Les adapters LLM futurs (format) devront remonter
                # `llm_cost_eur` dans extras pour que ce seuil soit effectif.
                cost = getattr(record, "llm_cost_eur", None) or 0.0
                context.cumulative_llm_cost_eur += float(cost)
            elif record.status == "failed":
                if fail_policy == "abort_all":
                    context.abort_all_triggered = True
                    logger.warning(
                        "DAG run %d: fail_policy=abort_all declenche par step %d",
                        execution_id,
                        record.step_id,
                    )
                elif fail_policy == "abort":
                    descendants = compute_descendants({record.step_id}, edges_list)
                    context.skipped_descendants.update(descendants)
                    logger.info(
                        "DAG run %d: step %d failed, skip %d descendants (%s)",
                        execution_id,
                        record.step_id,
                        len(descendants),
                        sorted(descendants),
                    )
                # best_effort : None dans step_outputs → build_node_input
                # retourne None pour les descendants. L'adapter doit tolerer
                # input=None (cf. contrat dans le design).
                context.step_outputs[record.step_id] = None

        # Purge memoire : retirer les outputs des parents dont tous les
        # descendants ont deja consomme (reduction fuite memoire sur
        # workflows longs avec gros workbooks).
        _purge_consumed_outputs(
            context,
            edges_list,
            processed_ids={r.step_id for r, _ in level_results},
            processed_so_far=processed_so_far,
        )
        processed_so_far.update({r.step_id for r, _ in level_results})

        # ENGINE-2 — persistance INCRÉMENTALE des StepExecution après chaque
        # niveau pour que le moniteur live voie la progression (0/Y → i/Y) au
        # lieu d'un 0% figé jusqu'au commit final. Best-effort + idempotent côté
        # callback (skip les rows déjà persistées) → jamais de doublon ; un flush
        # qui échoue n'interrompt pas le run (le commit final backstop rattrape).
        if on_level_complete is not None:
            try:
                await on_level_complete(all_records)
            except Exception as _flush_exc:  # noqa: BLE001 — best-effort
                logger.warning(
                    "DAG run %d: flush incrémental niveau %d échoué (%s), continue",
                    execution_id,
                    level_idx,
                    _flush_exc,
                )

        # Phase 2d : check circuit-breaker apres chaque niveau
        tripped = _check_circuit_breaker(context, automation)
        if tripped:
            context.circuit_breaker_tripped = tripped
            logger.warning(
                "DAG run %d: circuit-breaker declenche (%s) — skip des niveaux restants",
                execution_id,
                tripped,
            )

        # Suspension par WaitForResponse : on stoppe la boucle de niveaux
        # et on remonte un signal au caller (execute_automation) qui
        # transitionnera l'execution vers waiting.
        if wait_signal is not None:
            logger.info(
                "DAG run %d: suspendu (wait_token_id=%s) — stop des niveaux restants",
                execution_id,
                getattr(wait_signal, "wait_token_id", None),
            )
            context.wait_signal = wait_signal  # type: ignore[attr-defined]
            return context, all_records

    return context, all_records
