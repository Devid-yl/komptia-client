"""Service ``PipelineRunner`` — orchestration de ``scripts/pipeline.py`` depuis Iris.

Wrapper async qui :

- Crée un ``PipelineRun`` BDD, alloue un ``output_dir`` unique
  (``outputs/runs/{run_id}/``), capture un snapshot de freshness schéma.
- Lance ``scripts.pipeline.run_pipeline()`` in-process avec
  ``progress_callback``, ``cancel_event``, et un ``AskUserBridge`` pour
  les Q/A interactifs (remplace les ``input()`` synchrones).
- Persiste chaque ``PipelinePhaseExecution`` au fur et à mesure
  (1 ligne par tuple ``(run_id, phase_id, attempt_number)``).
- Émet des events via ``PipelineEventBus`` que le WebSocket Iris peut
  multiplexer vers les onglets connectés.
- Supporte ``cancel`` (asyncio.Event), ``pause`` (snapshot + libération de
  la coroutine), ``goto_phase`` (relance ciblée avec marquage des
  attempts précédents en ``is_superseded``).

Doctrine :

- **Pas d'état serveur en RAM seul** — toute information durable passe
  par BDD ou filesystem. Si le serveur redémarre, le run est marqué
  ``failed`` (orphelin) lors d'une passe de cleanup au boot.
- **Output_dir unique par run** — règle absolue pour multi-users.
  ``outputs/runs/42/run.json`` ≠ ``outputs/runs/43/run.json``. Pas
  de chemin global hardcodé. La création du dossier est atomique
  (mkdir(exist_ok=False) suivi d'un check) ; collision → abort + log.
- **Confidentialité des artefacts** — les chemins absolus ne fuient pas
  côté UI (le handler les normalise en URLs ``/api/iris/pipeline/{id}/
  artifacts/{phase}``).
- **Coût borné** — un quota ``PIPELINE_MAX_RUNS_PER_DAY`` par user est
  enforced **côté handler** (pas ici — séparation des responsabilités).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import config
from app.core import clock
from app.core.database import get_session_factory
from app.models.pipeline_run import (
    PipelineMode,
    PipelinePhaseExecution,
    PipelinePhaseStatus,
    PipelineRun,
    PipelineRunStatus,
    TriggeredVia,
)
from app.services.ai.pipeline_ask_user_bridge import (
    AskUserBridge,
    reset_current_bridge,
    set_current_bridge,
)
from app.services.ai.pipeline_event_bus import get_event_bus

logger = logging.getLogger(__name__)

# Racine du dossier des runs. Un sous-dossier par run_id.
# Configurable via env pour les tests / déploiements custom.
#
# Défaut SOUS data/ (volume Docker persistant) : sinon les artefacts (run.json
# de resume, run.sql, _debug_traces) atterrissent dans le repo root, HORS du
# volume → perdus à chaque rebuild `make up`, et les chemins stockés en BDD
# (PipelineRun.output_dir) deviennent orphelins → reprise de run cassée.
PIPELINE_RUNS_ROOT = Path(
    os.environ.get("PIPELINE_RUNS_ROOT") or str(config.data_dir / "pipeline_runs")
)

# Quota journalier par user. Centralisé ici (single source of truth) — TOUS
# les call-sites (handler API, WS, tool LLM) passent par ``start_pipeline_run``
# qui enforce le quota. Configurable via env.
PIPELINE_MAX_RUNS_PER_DAY = int(os.environ.get("PIPELINE_MAX_RUNS_PER_DAY", "10"))


class QuotaExceededError(RuntimeError):
    """Levée par ``start_pipeline_run`` quand le user a dépassé son quota."""

    def __init__(self, user_id: int, limit: int) -> None:
        super().__init__(f"User {user_id} a dépassé le quota journalier ({limit} runs/24h).")
        self.user_id = user_id
        self.limit = limit


# Lock per-user pour sérialiser ``start_pipeline_run`` — évite la race
# "compute count + insert" qui ferait dépasser le quota (fix #19 review adv).
_USER_START_LOCKS: Dict[int, asyncio.Lock] = {}
_USER_START_LOCKS_GUARD = asyncio.Lock()


async def _get_user_start_lock(user_id: int) -> asyncio.Lock:
    async with _USER_START_LOCKS_GUARD:
        lock = _USER_START_LOCKS.get(user_id)
        if lock is None:
            lock = asyncio.Lock()
            _USER_START_LOCKS[user_id] = lock
    return lock


# Labels lisibles pour les phases (alignés sur PHASES_ORDER de pipeline.py).
#
# **Source de vérité technique** : ``scripts.pipeline.PHASES_ORDER``
# (tuple immutable d'ordre d'exécution). Ces labels en sont une vue UI.
#
# **Cohérence** : un test unit (``test_pipeline_phase_labels_align``)
# vérifie que les ids de ``PHASE_LABELS`` matchent ceux de ``PHASES_ORDER``.
# Si on ajoute une phase côté pipeline.py, le test fail et oblige à
# mettre à jour ce dict + le frontend ``iris-pipeline.js#PHASE_ORDER``.
PHASE_LABELS: Dict[str, str] = {
    "1.1-1.2": "Phase 1.1+1.2 — Extract + Expand",
    "1.2.4": "Phase 1.2.4 — Concept Disambiguation (détection ambiguïtés DDL)",
    "1.2.5": "Phase 1.2.5 — Filter entités",
    "1.2.6": "Phase 1.2.6 — Curate routing",
    "1.3-1.4": "Phase 1.3+1.4 — Search BDD",
    "1.5": "Phase 1.5 — Scoring + FK subgraph",
    "2": "Phase 2 — Rerank LLM",
    "3": "Phase 3 — Concept Fact Sheets",
    "4": "Phase 4 — SQL Composer",
}


def _phase_label(phase_id: str) -> str:
    """Retourne le label humain d'une phase, fallback sur l'ID brut."""

    return PHASE_LABELS.get(phase_id, f"Phase {phase_id}")


# ── Constantes pour ``resume_pipeline_run`` (T3b) ────────────────────────
#
# Mapping phase_id → champ de ``PipelineState`` (cf. ``scripts.pipeline``)
# que la phase MUTE. Source de vérité technique : ``PHASES_ORDER`` dans
# ``scripts.pipeline``. Test de garde
# ``test_phase_state_fields_align_with_pipeline_phases_order`` détecte
# tout drift et oblige à mettre à jour ce dict ici quand une phase est
# ajoutée/renommée côté pipeline.
_PHASE_STATE_FIELDS: Dict[str, str] = {
    "1.1-1.2": "extracted",
    "1.2.4": "disambiguated",
    "1.2.5": "filtered",
    "1.2.6": "curated",
    "1.3-1.4": "search",
    "1.5": "scored",
    "2": "reranks",
    "3": "factsheets",
    "4": "sql_final",
}

# Ordre canonique des phases — doit matcher ``PHASES_ORDER`` côté pipeline.
_PHASE_ORDER_IDS: tuple[str, ...] = (
    "1.1-1.2",
    "1.2.4",
    "1.2.5",
    "1.2.6",
    "1.3-1.4",
    "1.5",
    "2",
    "3",
    "4",
)

# Phases dont le champ d'état peut légitimement rester ``None`` même après
# exécution complète du run → à EXCLURE de la validation "phase amont
# complétée" du resume (sinon tout resume depuis une phase aval échouerait
# à tort, y compris sur des runs réels parfaitement valides).
#
# 1.2.4 (Concept Disambiguation) est aujourd'hui DÉTECTION-SEULE : la pipeline
# ne peuple JAMAIS ``state.disambiguated`` (stub — intégration Q-user "à venir
# dans une PR suivante", cf. ``PipelineState.disambiguated`` dans
# scripts.pipeline). Elle figure dans ``PHASES_ORDER`` (donc dans les miroirs
# ci-dessus, requis par les tests d'alignement anti-drift) mais ne produit pas
# d'état. Quand elle peuplera réellement ``disambiguated``, la RETIRER de ce set.
_OPTIONAL_PHASE_IDS: frozenset[str] = frozenset({"1.2.4"})

# Whitelist des champs autorisés dans ``state_overrides`` du tool
# ``pipeline_resume``. Tout autre champ → refus fail-closed (anti
# injection LLM qui voudrait écraser ``user_id`` ou ``output_dir``).
#
# Volontairement RESTRICTIF :
# - Champs ``started_at`` et ``phase_durations`` exclus : ce sont des
#   fields télémétrie/audit. Permettre leur mutation laisserait le LLM
#   forger des timestamps dans ``run.json`` (visibles UI/logs/audit).
#   Aucun cas d'usage légitime de resume.
# - ``query`` est inclus pour permettre une reformulation explicite si
#   l'agent diagnostique un mauvais wording.
_PIPELINE_STATE_OVERRIDE_FIELDS: frozenset[str] = frozenset(
    {
        "query",
        "extracted",
        "disambiguated",
        "filtered",
        "curated",
        "search",
        "scored",
        "reranks",
        "factsheets",
        "sql_final",
        "concept_resolution",
        "final_sql",
    }
)

# Cap dur sur la taille sérialisée des ``state_overrides`` — anti-DoS
# storage (un LLM hallucinant un override énorme ne doit pas faire
# exploser le run.json sur disque).
_STATE_OVERRIDES_MAX_BYTES: int = 64 * 1024  # 64 KiB


class ResumeValidationError(ValueError):
    """Levée par ``resume_pipeline_run`` quand les paramètres sont invalides.

    Distincte de ``QuotaExceededError`` pour qu'un caller (handler API ou
    tool LLM) puisse différencier "ta demande est invalide" (4xx-like)
    vs "tu as épuisé ton quota" (429-like).
    """


# Lock par source_run_id — ferme la fenêtre TOCTOU entre check ownership /
# status / RAM-registry et la lecture du run.json source. Sans ce lock,
# un second appel concurrent sur le MÊME source_run pourrait passer entre
# le `_REGISTRY.get()` check (vide) et `_create_and_start_run` (qui register
# un nouveau runner) — résultat : 2 nouveaux runs partant du même état.
# Granularité fine : ne bloque pas les resumes sur DIFFÉRENTS source runs.
_RESUME_SOURCE_LOCKS: Dict[int, asyncio.Lock] = {}
_RESUME_SOURCE_LOCKS_GUARD = asyncio.Lock()


async def _get_resume_source_lock(source_run_id: int) -> asyncio.Lock:
    """Lock applicatif par source_run_id pour resume_pipeline_run."""

    async with _RESUME_SOURCE_LOCKS_GUARD:
        lock = _RESUME_SOURCE_LOCKS.get(source_run_id)
        if lock is None:
            lock = asyncio.Lock()
            _RESUME_SOURCE_LOCKS[source_run_id] = lock
    return lock


async def _capture_schema_snapshot() -> str:
    """Capture une signature courte du dernier sync schéma réussi.

    Lecture du modèle ``SchemaSync`` (table ``schema_sync``). Retourne
    ``"unknown"`` si aucun sync persisté ou erreur de lecture (fail-safe :
    le snapshot est purement informatif, on ne bloque pas le run).
    """

    try:
        from app.models.ai_performance import SchemaSync

        async with get_session_factory()() as session:
            stmt = (
                select(SchemaSync)
                .where(SchemaSync.success.is_(True))
                .order_by(SchemaSync.created_at.desc())
                .limit(1)
            )
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            if row is None:
                return "unknown"
            ts = row.created_at
            if ts is None:
                return "unknown"
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts.isoformat()
    except Exception:  # noqa: BLE001
        logger.exception("PipelineRunner: failed to capture schema snapshot")
        return "unknown"


def _allocate_output_dir(run_id: int) -> Path:
    """Alloue un dossier dédié à un run.

    Lève si le dossier existe déjà (signe d'un bug : un run précédent
    n'a pas été cleanup, ou collision d'IDs). Le caller traite l'exception
    en marquant le run failed.

    Note : appelé via ``asyncio.to_thread`` côté ``start_pipeline_run``
    pour ne pas bloquer l'event loop sur disque lent (fix #22 review adv).
    """

    output_dir = PIPELINE_RUNS_ROOT / str(run_id)
    output_dir.mkdir(parents=True, exist_ok=False)
    return output_dir


def _build_pipeline_failed_event(
    *,
    message: str,
    error_kind: str,
    exception_class: str,
    traceback_text: Optional[str],
    unresolved_concept: Optional[str],
) -> Dict[str, Any]:
    """Construit le payload ``pipeline_failed`` publié sur l'event bus.

    ``recoverable_via`` dépend du TYPE d'erreur, PAS de la présence d'un nom de
    concept : un ``concept_unresolved`` est TOUJOURS récupérable via
    ``ask_user_clarification`` — y compris le cas « requête vide » qui lève
    ``ConceptUnresolvedError(concept_name="")`` → ``unresolved_concept=None``.
    Avant (review du snapshot 20b8902), le flag était gaté par
    ``if unresolved_concept:`` → il manquait sur requête vide et Iris traitait
    l'échec comme dur au lieu de proposer une reformulation.

    La stacktrace est tronquée à 4096 chars (T12, 2026-05-26) : exposée à Iris
    dans l'event pour diagnostic ; le ``tb`` complet reste persisté en BDD via
    ``mark_failed`` côté caller.
    """
    event: Dict[str, Any] = {
        "type": "pipeline_failed",
        "message": message,
        "error_kind": error_kind,
        "exception_class": exception_class,
        "traceback": (
            traceback_text[-4096:]
            if traceback_text and len(traceback_text) > 4096
            else traceback_text
        ),
    }
    if error_kind == "concept_unresolved":
        # Recovery-actionable pour le bridge / Iris : appeler
        # ``ask_user_clarification`` pose la question à l'utilisateur sans crasher.
        event["recoverable_via"] = "ask_user_clarification"
        if unresolved_concept:
            event["unresolved_concept"] = unresolved_concept
    return event


class PipelineRunner:
    """Orchestre un ``PipelineRun`` actif.

    Une instance par run actif en RAM. Les instances sont gérées par un
    registry singleton (cf. ``RunRegistry`` plus bas).
    """

    def __init__(
        self,
        run: PipelineRun,
        *,
        resume_mode: bool = False,
        additional_context: Optional[str] = None,
    ):
        self._run_id = run.id
        self._user_id = run.user_id
        # Conversation Iris d'origine — propagée à ``run_pipeline`` pour attribuer
        # les appels LLM de la pipeline (le chemin le plus coûteux) à la bonne
        # conversation dans ``AIPerformanceLog.conversation_id`` (sinon NULL →
        # sous-évaluation silencieuse de la puce coût /iris). Colonne simple déjà
        # chargée (ORM-async-safe, même pattern que ``_user_id``).
        self._conversation_id = run.conversation_id
        self._request_id = run.request_id  # corrélation AIPerformanceLog
        self._output_dir = Path(run.output_dir)
        # Phase d'arrêt demandée (feature preview Iris — None = run complet).
        # Capturé ici (run détaché après commit/refresh, colonne simple déjà
        # chargée — même pattern ORM-async-safe que ``_user_id``). Lu par
        # ``_build_pipeline_kwargs`` pour passer ``stop_after_phase`` à la
        # pipeline.
        self._stop_after_phase = run.stop_after_phase
        self._cancel_event = asyncio.Event()
        self._task: Optional[asyncio.Task[Any]] = None
        # Timer de grace (auto-cancel quand plus aucun subscriber WS).
        # Permet à l'user de refresh sa page sans perdre son run : si un
        # WS resubscribe avant la fin du grace, le timer est annulé.
        self._grace_cancel_task: Optional[asyncio.Task[Any]] = None
        # Watchdog "no-subscriber-ever" — auto-cancel si personne ne se
        # subscribe au run dans les 30s du start (couvre refresh prématuré,
        # bug frontend, panneau pas chargé).
        self._start_watchdog_task: Optional[asyncio.Task[Any]] = None
        self._ask_user_bridge = AskUserBridge(run_id=run.id)
        # Compteurs locaux pour ne pas re-lire la BDD à chaque event.
        self._tokens_input = 0
        self._tokens_output = 0
        self._cost_usd = 0.0
        # Mode resume (T3b) : si True, ``_build_pipeline_kwargs`` passe
        # ``resume=True`` à ``run_pipeline`` qui rechargera le ``run.json``
        # pré-écrit dans ``output_dir`` (cf. ``resume_pipeline_run``).
        self._resume_mode = resume_mode
        # Task #93 PR3 (2026-05-21) — ADD-only : contexte complémentaire
        # ajouté par Iris (cf. ``_handle_run_pipeline`` agent_tools.py).
        # Optionnel, propagé à ``run_pipeline(additional_context=...)``.
        self._additional_context = additional_context

    @property
    def run_id(self) -> int:
        return self._run_id

    @property
    def cancel_event(self) -> asyncio.Event:
        return self._cancel_event

    @property
    def ask_user_bridge(self) -> AskUserBridge:
        return self._ask_user_bridge

    # ── Cycle de vie ──────────────────────────────────────────────────────

    async def start(self) -> None:
        """Lance la pipeline en background task.

        Idempotent : si un task est déjà actif, no-op. La méthode retourne
        immédiatement — le run continue en arrière-plan et émet ses events
        via le bus.

        Pose aussi un ``start_watchdog`` : si aucun subscriber WS pipeline
        n'arrive dans les 30s, cancel auto. Évite qu'un run lancé sans que
        le frontend ait pu attacher (ex : user refresh AVANT que le
        tool_result run_pipeline n'atteigne iris.js) consomme des tokens
        LLM dans le vide.
        """

        if self._task is not None and not self._task.done():
            logger.warning(
                "PipelineRunner.start: run_id=%s already has active task",
                self._run_id,
            )
            return

        self._task = asyncio.create_task(self._run_safe(), name=f"pipeline-{self._run_id}")
        # Watchdog "no-subscriber-ever". Annulé au premier subscribe via
        # ``abort_grace_cancel`` (qui couvre aussi les 2 timers — start
        # watchdog ET grace cancel — par simplicité d'API côté handler WS).
        self._start_watchdog_task = asyncio.create_task(
            self._start_watchdog(timeout_seconds=30.0),
            name=f"pipeline-start-watchdog-{self._run_id}",
        )

    async def _start_watchdog(self, timeout_seconds: float = 30.0) -> None:
        """Cancel le run si aucun subscriber n'arrive dans le délai.

        Couvre le cas où le frontend ne reçoit/traite jamais le tool_result
        ``run_pipeline`` (refresh prématuré, bug JS, panneau pas chargé).
        Sans ce watchdog, le runner tourne dans le vide jusqu'à crash
        crédit Anthropic ou achèvement de toutes les phases — gros gaspillage.
        """

        try:
            await asyncio.sleep(timeout_seconds)
            if self._task is None or self._task.done():
                return
            bus = get_event_bus()
            if await bus.has_subscribers(self._run_id):
                logger.info(
                    "PipelineRunner.start_watchdog: subscriber present "
                    "(run_id=%s) — keeping run alive",
                    self._run_id,
                )
                return
            logger.warning(
                "PipelineRunner.start_watchdog: no subscriber after %.0fs "
                "(run_id=%s) — cancelling to save LLM tokens",
                timeout_seconds,
                self._run_id,
            )
            await self.cancel(by_user_id=None)
            await get_event_bus().publish(
                self._run_id,
                {"type": "pipeline_cancelled_no_subscriber"},
            )
        except asyncio.CancelledError:
            logger.info(
                "PipelineRunner.start_watchdog aborted by subscribe " "(run_id=%s)",
                self._run_id,
            )

    async def schedule_grace_cancel(self, grace_seconds: float = 60.0) -> None:
        """Lance un timer qui cancel le run si personne ne resubscribe.

        À appeler quand le DERNIER subscriber WS se déconnecte (refresh
        de page). Si l'user revient sous ``grace_seconds``, ``abort_grace_cancel``
        annule le timer et le run continue. Sinon le run est annulé pour
        ne pas brûler des tokens LLM dans le vide.

        Idempotent : si un timer est déjà actif, no-op.
        """

        if self._grace_cancel_task is not None and not self._grace_cancel_task.done():
            return  # déjà programmé
        if self._task is None or self._task.done():
            return  # le run est déjà terminé, rien à canceler
        logger.info(
            "PipelineRunner.schedule_grace_cancel: run_id=%s, grace=%.0fs",
            self._run_id,
            grace_seconds,
        )

        async def _grace_then_cancel() -> None:
            try:
                await asyncio.sleep(grace_seconds)
                # Re-vérifie : entre-temps quelqu'un peut avoir resubscribe
                # (abort_grace_cancel n'est pas garanti 100% sur le timing
                # du Lock du bus). Double-check via has_subscribers.
                bus = get_event_bus()
                if await bus.has_subscribers(self._run_id):
                    logger.info(
                        "PipelineRunner.grace expired but subscribers present "
                        "(run_id=%s) — keeping run alive",
                        self._run_id,
                    )
                    return
                if self._task is None or self._task.done():
                    return
                logger.info(
                    "PipelineRunner.grace_cancel firing: run_id=%s " "(no subscriber after %.0fs)",
                    self._run_id,
                    grace_seconds,
                )
                await self.cancel(by_user_id=None)
                # Event spécifique pour distinguer du cancel utilisateur
                await get_event_bus().publish(
                    self._run_id,
                    {"type": "pipeline_cancelled_grace_timeout"},
                )
            except asyncio.CancelledError:
                # Le grace a été abort proprement par un resubscribe.
                logger.info(
                    "PipelineRunner.grace_cancel aborted by resubscribe " "(run_id=%s)",
                    self._run_id,
                )

        self._grace_cancel_task = asyncio.create_task(
            _grace_then_cancel(),
            name=f"pipeline-grace-{self._run_id}",
        )

    def abort_grace_cancel(self) -> None:
        """Annule les 2 timers liés à l'attente d'un subscriber.

        - ``_start_watchdog_task`` : timer "personne n'est jamais venu"
          (firing 30s après start si aucun subscriber).
        - ``_grace_cancel_task`` : timer "le dernier subscriber a quitté"
          (firing 60s après last-disconnect si personne ne resubscribe).

        Appelé sur tout ``subscribe``. Idempotent (no-op si pas actif).
        """

        for attr in ("_start_watchdog_task", "_grace_cancel_task"):
            task: Optional[asyncio.Task[Any]] = getattr(self, attr, None)
            if task is None or task.done():
                continue
            task.cancel()
            setattr(self, attr, None)
            logger.info(
                "PipelineRunner.abort: run_id=%s, %s aborted by subscribe",
                self._run_id,
                attr,
            )

    async def cancel(self, by_user_id: Optional[int] = None) -> None:
        """Demande l'annulation du run.

        - Set le ``cancel_event`` (la pipeline le check entre phases).
        - Annule les Q/A pendants.
        - Met à jour le status BDD ``cancelled`` (si pas déjà terminal).
        - Le task continue jusqu'à la prochaine vérification, puis sort
          via ``asyncio.CancelledError``.
        """

        self._cancel_event.set()
        await self._ask_user_bridge.cancel_all(reason="run_cancelled")
        await _update_run_status(self._run_id, lambda r: r.mark_cancelled(by_user_id=by_user_id))
        await get_event_bus().publish(
            self._run_id,
            {"type": "pipeline_cancelled", "by_user_id": by_user_id},
        )

    async def wait(self, timeout: Optional[float] = None) -> None:
        """Attend la fin du task. Lève ``asyncio.TimeoutError`` si timeout."""

        if self._task is None:
            return
        await asyncio.wait_for(self._task, timeout=timeout)

    # ── Exécution principale ──────────────────────────────────────────────

    async def _run_safe(self) -> None:
        """Wrapper ``_run`` avec catch global.

        Toute exception remontée se traduit par ``mark_failed`` côté BDD
        et un event ``pipeline_failed`` côté bus. Pas de propagation vers
        le caller (le task est fire-and-forget).
        """

        try:
            await self._run()
        except asyncio.CancelledError:
            # Cancel propre — le status a déjà été marqué dans cancel()
            logger.info("PipelineRunner: run_id=%s cancelled cleanly", self._run_id)
        except Exception as exc:  # noqa: BLE001
            tb = traceback.format_exc()
            # Fix L8++ #63 (2026-05-20) : si l'exception est un
            # ``ConceptUnresolvedError`` (concept non résolu par Phase 2.5
            # → Phase 4 crash), on émet un payload STRUCTURÉ que le bridge
            # agent_service propage à Iris. Iris peut alors appeler
            # ``ask_user_clarification`` pour demander à l'utilisateur de
            # préciser le concept manquant, au lieu de voir la pipeline
            # crasher avec un message obscur. Sans ce fix, la pipeline
            # crash sur des concepts mal nommés ("montant TTC" run #7) et
            # l'utilisateur n'a aucun moyen de récupérer.
            error_kind = "unhandled"
            unresolved_concept: Optional[str] = None
            try:
                from scripts.pipeline import ConceptUnresolvedError as _CUE

                if isinstance(exc, _CUE):
                    error_kind = "concept_unresolved"
                    unresolved_concept = getattr(exc, "concept_name", None) or None
            except ImportError:
                # scripts.pipeline pas importable (cas dégénéré au boot) —
                # fallback safe : on traite comme erreur générique.
                pass

            logger.exception(
                "PipelineRunner: run_id=%s failed (error_kind=%s, concept=%r)",
                self._run_id,
                error_kind,
                unresolved_concept,
            )
            # Capture ``exc`` et ``tb`` via default-arg pour que la lambda
            # garde une référence forte — sinon Python clear l'exception à la
            # fin du ``except`` (PEP 3134) et flake8 le signale en F821.
            await _update_run_status(
                self._run_id, lambda r, _e=exc, _tb=tb: r.mark_failed(str(_e), _tb)
            )
            failed_event = _build_pipeline_failed_event(
                message=str(exc),
                error_kind=error_kind,
                exception_class=type(exc).__name__,
                traceback_text=tb,
                unresolved_concept=unresolved_concept,
            )
            await get_event_bus().publish(self._run_id, failed_event)

    async def _run(self) -> None:
        """Boucle principale : prépare contexte + invoque ``run_pipeline``.

        Le caller a déjà créé le ``PipelineRun`` BDD et alloué l'output_dir.
        """

        # Charge en avance request_id + user_id pour poser request_scope
        # (corrélation logs LLM avec PipelineRun, cf. axe 5 contrat Komptia).
        try:
            from app.utils.request_context import request_scope as _request_scope
        except ImportError:
            _request_scope = None  # type: ignore[assignment]

        request_id_for_scope: Optional[str] = None
        async with get_session_factory()() as session:
            run = await session.get(PipelineRun, self._run_id)
            if run is not None:
                request_id_for_scope = run.request_id

        # Pose le bridge ContextVar pour cette coroutine
        bridge_token = set_current_bridge(self._ask_user_bridge)
        scope_cm = (
            _request_scope(request_id=request_id_for_scope, user_id=self._user_id)
            if _request_scope is not None and request_id_for_scope
            else None
        )
        try:
            if scope_cm is not None:
                scope_cm.__enter__()
            # Marquer running + capture freshness
            schema_version = await _capture_schema_snapshot()
            await _update_run_status(
                self._run_id,
                lambda r: (r.mark_running(), setattr(r, "schema_version_at_start", schema_version)),
            )
            await get_event_bus().publish(
                self._run_id,
                {
                    "type": "pipeline_started",
                    "schema_version_at_start": schema_version,
                },
            )

            # Charger params depuis BDD
            run_data = await _load_run_data(self._run_id)
            if run_data is None:
                raise RuntimeError(f"PipelineRun {self._run_id} disparu de la BDD")

            # Import lazy : évite charger ~9000 lignes au boot serveur si
            # personne ne lance la pipeline.
            from scripts.pipeline import run_pipeline as pipeline_run_pipeline

            progress_cb = self._make_progress_callback()

            # Invocation in-process. La pipeline accepte ces params APRÈS
            # le refactor du Lot 4 (output_dir + cancel_event +
            # progress_callback). Avant le refactor, elle ignore ces kwargs
            # → comportement historique conservé pour rétro-compat.
            kwargs = self._build_pipeline_kwargs(run_data, progress_cb)
            try:
                state = await pipeline_run_pipeline(**kwargs)
            except TypeError as exc:
                # Si run_pipeline n'accepte pas encore les kwargs (Lot 4
                # pas encore appliqué), on log et fail proprement avec
                # message actionnable. Évite un silence qui ferait croire
                # à un bug ailleurs.
                logger.error(
                    "PipelineRunner: scripts.pipeline.run_pipeline ne supporte "
                    "pas encore les kwargs requis (output_dir, cancel_event, "
                    "progress_callback). Refactor pipeline.py requis. "
                    "Détail: %s",
                    exc,
                )
                raise RuntimeError(
                    "Pipeline runner non finalisé : scripts/pipeline.py ne "
                    "supporte pas encore l'invocation in-process avec "
                    "supervision. Compléter le refactor (Lot 4) avant usage."
                ) from exc

            # État final
            final_sql = getattr(state, "final_sql", None) or ""
            # Feature preview Iris — un arrêt PROPRE à une phase intermédiaire
            # est signalé EXPLICITEMENT par la pipeline via
            # ``state.terminal_reason == "stopped_clean"`` (JAMAIS inféré de
            # l'absence de final_sql : un crash/cancel a aussi final_sql vide —
            # CRIT-B, docs/design/iris_stop_at_phase.md). Dans ce cas : pas de
            # SQL → on saute les post-checks (row_count/grain n'ont aucun sens
            # sans SQL) et on marque STOPPED_EARLY au lieu de SUCCESS.
            terminal_reason = getattr(state, "terminal_reason", None)
            stopped_early = terminal_reason == "stopped_clean"
            # La pipeline peut RETOURNER (sans lever) un state failed — ex:
            # phase non convertie (NotImplementedError gérée puis return). On
            # le traite comme un échec, JAMAIS comme un succès (CRIT-B).
            returned_failed = terminal_reason == "failed"
            row_count_warning = False
            grain_validation = None
            # Post-checks (row_count/grain) seulement pour un vrai run complet
            # avec SQL — ni pour un arrêt intermédiaire ni pour un échec.
            if not stopped_early and not returned_failed:
                row_count_warning = await self._post_check_row_count(final_sql)
                # F9 — Validation post-exec du grain. Best-effort : si la
                # pipeline a produit un SQL ET un expected_grain ET use_sage,
                # on exécute COUNT(*) sur Sage et on compare. Non bloquant.
                grain_validation = await self._post_check_grain(state, run_data["use_sage"])
            # Task #73 — récap final : exposer les Q/A de qa_session pour que
            # l'UI Iris affiche (a) les hypothèses retenues automatiquement par
            # Iris (Q sans réponse user ou auto-submited vides), et (b) les
            # réponses utilisateur prises en compte (audit & rappel).
            auto_assumptions: list[dict] = []
            user_answers: list[dict] = []
            try:
                from app.services.ai import user_qa_session as _qa_session

                qa_entries = _qa_session.read_session() or []
                for entry in qa_entries:
                    if not isinstance(entry, dict):
                        continue
                    answer = (entry.get("answer") or "").strip()
                    base = {
                        "phase": entry.get("phase", "?"),
                        "question": entry.get("question", ""),
                        "concept": entry.get("concept"),
                    }
                    if answer:
                        # L'utilisateur a explicitement répondu — on garde
                        # pour rappel dans le récap (« tu m'as dit X »).
                        user_answers.append({**base, "answer": answer})
                    else:
                        # Pas de réponse (Phase 3 auto-submit OU user a laissé
                        # vide en Phase 1.2.5/1.2.6/4 mismatches) → Iris a
                        # tranché par défaut. À exposer pour correction ciblée.
                        auto_assumptions.append(base)
            except Exception as _qa_exc:  # noqa: BLE001
                logger.warning(
                    "PipelineRunner: lecture qa_session pour récap final "
                    "échouée (%s) — événement pipeline_complete envoyé sans "
                    "auto_assumptions/user_answers.",
                    _qa_exc,
                )
            # Statut + event terminal. Arrêt intermédiaire propre →
            # STOPPED_EARLY (pas de SQL) ; sinon SUCCESS. L'event est publié
            # APRÈS le commit du statut (``_update_run_status`` commit en
            # premier) pour qu'un client qui (re)connecte lise un statut
            # cohérent en BDD — T7, anti « zombie SUCCESS sans event reçu ».
            if stopped_early:
                _applied = await _update_run_status(
                    self._run_id, lambda r: r.mark_stopped_early()
                )
                # B8 — ne publie l'event terminal QUE si le mark a réellement pris.
                # Si un cancel concurrent a déjà committé CANCELLED, mark_stopped_early
                # est un no-op (garde B2) → on n'émet pas un « complete » qui
                # contredirait la BDD (le handler cancel publie son propre event).
                if _applied:
                    await get_event_bus().publish(
                        self._run_id,
                        {
                            "type": "pipeline_complete",
                            # Pas de SQL : HYPOTHÈSE intermédiaire à valider, jamais
                            # une réponse finale (carte front T16 / is_hypothesis).
                            "final_sql": None,
                            "terminal_reason": "stopped_clean",
                            "stopped_after_phase": self._stop_after_phase,
                            "is_hypothesis": True,
                            "auto_assumptions": auto_assumptions,
                            "user_answers": user_answers,
                        },
                    )
            elif returned_failed:
                # CRIT-B (review adversariale finale) : la pipeline a retourné
                # un state ``terminal_reason="failed"`` SANS lever (ex: phase non
                # convertie). On le marque FAILED — surtout PAS success — et on
                # publie l'event d'échec SSoT (symétrique au chemin exception
                # ci-dessus). Sinon un run crashé serait présenté comme complété.
                _failed_msg = (
                    "La pipeline s'est arrêtée sur une erreur interne "
                    "(phase non finalisée). Relance une nouvelle requête."
                )
                _applied = await _update_run_status(
                    self._run_id, lambda r, _m=_failed_msg: r.mark_failed(_m, None)
                )
                if _applied:  # B8 — pas d'event si déjà terminal (race cancel)
                    await get_event_bus().publish(
                        self._run_id,
                        _build_pipeline_failed_event(
                            message=_failed_msg,
                            error_kind="pipeline_internal",
                            exception_class="PipelineReturnedFailed",
                            traceback_text=None,
                            unresolved_concept=None,
                        ),
                    )
            else:
                _applied = await _update_run_status(
                    self._run_id,
                    lambda r: r.mark_success(final_sql, row_count_warning=row_count_warning),
                )
                if _applied:  # B8 — pas d'event « complete » si déjà terminal (race cancel)
                    await get_event_bus().publish(
                        self._run_id,
                        {
                            "type": "pipeline_complete",
                            "final_sql": final_sql,
                            "terminal_reason": "completed",
                            "row_count_warning": row_count_warning,
                            "auto_assumptions": auto_assumptions,
                            # F9 — grain_validation peut être None (skip si
                            # conditions pas réunies) ou un dict status/actual/...
                            "grain_validation": grain_validation,
                            "user_answers": user_answers,
                        },
                    )
        finally:
            if scope_cm is not None:
                try:
                    scope_cm.__exit__(None, None, None)
                except Exception:  # noqa: BLE001
                    logger.exception("PipelineRunner: request_scope __exit__ failed")
            reset_current_bridge(bridge_token)
            # Délai de grâce 60s puis fermeture du canal (fix #14 — empêche
            # croissance non bornée de PipelineEventBus._channels après runs
            # terminaux).
            asyncio.create_task(self._close_event_channel_after_grace())

    async def _close_event_channel_after_grace(self) -> None:
        """Ferme le canal du bus 60s après la fin du run.

        Délai de grâce : laisse aux clients qui rejoignent le panneau juste
        après la fin une chance de voir les events finaux via replay buffer.
        """

        try:
            await asyncio.sleep(60)
            await get_event_bus().close_channel(self._run_id)
            await _REGISTRY.unregister(self._run_id)
            # B7 — évince les locks de phase de ce run terminé (anti croissance
            # non bornée des dicts en RAM, axe 21).
            await _evict_phase_locks_for_run(self._run_id)
        except asyncio.CancelledError:
            pass
        except Exception:  # noqa: BLE001
            logger.exception(
                "PipelineRunner: close_event_channel grace failed (run=%s)",
                self._run_id,
            )

    def _build_pipeline_kwargs(
        self,
        run_data: Dict[str, Any],
        progress_cb: Callable[..., Awaitable[None]],
    ) -> Dict[str, Any]:
        """Construit les kwargs pour ``run_pipeline()``.

        Mappe les champs BDD vers la signature attendue après refactor.
        """

        kwargs: Dict[str, Any] = {
            "query": run_data["query_nl"],
            "block_all_views": run_data["block_all_views"],
            "use_sage": run_data["use_sage"],
            "mode": run_data["mode"],
            # Hooks ajoutés par le refactor (Lot 4)
            "output_dir": self._output_dir,
            "cancel_event": self._cancel_event,
            "progress_callback": progress_cb,
            # T3b — pipeline_resume : si ``True``, ``run_pipeline`` recharge
            # le ``run.json`` pré-écrit dans ``output_dir`` et reprend
            # après la dernière phase complétée du state tronqué.
            "resume": self._resume_mode,
            # Couche 2 confidentialité — propage l'identité du propriétaire du
            # run pour que la pipeline pseudonymise la phrase NL via
            # /data-privacy avant envoi cloud (cf. ContextVar
            # ``_pipeline_user_id`` dans scripts/pipeline.py). Sans ça, un nom
            # de client tapé par l'utilisateur partait en clair chez le LLM.
            "user_id": self._user_id,
            # Attribution du coût LLM pipeline à la conversation Iris (puce coût
            # /iris). ``str`` car ``AIPerformanceLog.conversation_id`` = String(64).
            "conversation_id": (
                str(self._conversation_id) if self._conversation_id is not None else None
            ),
        }
        # Task #93 PR3 (2026-05-21) — ADD-only : propager le contexte
        # complémentaire à ``run_pipeline``. Le param est optionnel côté
        # ``run_pipeline`` (défaut None) donc on l'ajoute seulement si
        # Iris a fourni quelque chose. Pas un dict.setdefault pour
        # éviter d'écraser un futur usage de la clé.
        if self._additional_context:
            kwargs["additional_context"] = self._additional_context
        # Feature preview Iris — n'ajoute le param que s'il est positionné
        # (param optionnel côté run_pipeline, défaut None = run complet). Le
        # helper ``_build_phases_to_run`` côté pipeline valide la phase
        # (fail-closed sur valeur inconnue).
        if self._stop_after_phase:
            kwargs["stop_after_phase"] = self._stop_after_phase
        return kwargs

    def _make_progress_callback(
        self,
    ) -> Callable[[str, str, Optional[Dict[str, Any]]], Awaitable[None]]:
        """Fabrique le callback que la pipeline appellera entre phases.

        Signature attendue côté pipeline :
            ``await progress_callback(phase_id: str, status: str, meta: dict | None)``

        ``status`` ∈ {"start", "complete", "failed"}. ``meta`` peut contenir
        ``tokens_input``, ``tokens_output``, ``cost_usd``,
        ``artifact_path``, ``error_message``, etc.
        """

        async def _cb(
            phase_id: str,
            status: str,
            meta: Optional[Dict[str, Any]] = None,
        ) -> None:
            meta = meta or {}
            now = clock.now()

            if status == "start":
                await self._persist_phase_start(phase_id, now)
                await get_event_bus().publish(
                    self._run_id,
                    {
                        "type": "phase_start",
                        "phase_id": phase_id,
                        "phase_label": _phase_label(phase_id),
                        "started_at": now.isoformat(),
                    },
                )
            elif status == "complete":
                # Persiste la phase + agrège les coûts depuis AIPerformanceLog.
                # _persist_phase_complete met à jour self._tokens_* / _cost_usd
                # et retourne la durée calculée (now - started_at) pour qu'on
                # puisse la propager au bus → bridge agent_service → frontend.
                # Sans ce return, le payload arrivait sans ``duration_seconds``
                # et le bridge publiait ``elapsed_ms=0`` au tool_result Iris
                # (= bug "0ms" affiché en UI pour toutes les phases passées).
                duration_s = await self._persist_phase_complete(phase_id, now, meta)
                await self._persist_aggregated_costs()
                await get_event_bus().publish(
                    self._run_id,
                    {
                        "type": "phase_complete",
                        "phase_id": phase_id,
                        "phase_label": _phase_label(phase_id),
                        "finished_at": now.isoformat(),
                        "duration_seconds": duration_s,
                        "tokens_input": int(meta.get("tokens_input", 0) or 0),
                        "tokens_output": int(meta.get("tokens_output", 0) or 0),
                        "cost_usd": float(meta.get("cost_usd", 0.0) or 0.0),
                        "artifact_path_relative": _relative_artifact_path(
                            meta.get("artifact_path"), self._output_dir
                        ),
                        "metadata_summary": meta.get("metadata_summary"),
                    },
                )
            elif status == "failed":
                duration_s = await self._persist_phase_failed(phase_id, now, meta)
                await get_event_bus().publish(
                    self._run_id,
                    {
                        "type": "phase_failed",
                        "phase_id": phase_id,
                        "phase_label": _phase_label(phase_id),
                        "duration_seconds": duration_s,
                        "error_message": meta.get("error_message", "Unknown error"),
                    },
                )
            elif status == "progress":
                # Event intermédiaire pour les phases longues (Phase 3 probes,
                # Phase 1.5 scoring). Pas persisté en BDD — pur transport UI.
                await get_event_bus().publish(
                    self._run_id,
                    {
                        "type": "phase_progress",
                        "phase_id": phase_id,
                        "phase_label": _phase_label(phase_id),
                        "message": meta.get("message", ""),
                        "percent": meta.get("percent"),
                    },
                )

        return _cb

    # ── Persistance ──────────────────────────────────────────────────────

    async def _persist_phase_start(self, phase_id: str, now: datetime) -> None:
        """Crée la ligne ``PipelinePhaseExecution`` active pour la phase.

        Le calcul du ``attempt_number`` + insert sont sérialisés via lock
        applicatif granulaire ``(run_id, phase_id)`` (fix #5 review adv) :
        élimine la race "2 callers lisent max=N et insèrent N+1 en
        parallèle". Pour les retries explicites (goto_phase futur), le
        marquage ``is_superseded`` se fera APRÈS commit du nouvel attempt
        via ``_supersede_previous_attempts()``.
        """

        lock = await _get_phase_attempt_lock(self._run_id, phase_id)
        async with lock:
            async with get_session_factory()() as session:
                attempt = await _next_attempt_number(session, self._run_id, phase_id)
                phase_exec = PipelinePhaseExecution(
                    pipeline_run_id=self._run_id,
                    phase_id=phase_id,
                    phase_label=_phase_label(phase_id),
                    attempt_number=attempt,
                    status=PipelinePhaseStatus.RUNNING,
                    started_at=now,
                )
                session.add(phase_exec)

                # Met à jour current_phase côté run
                run = await session.get(PipelineRun, self._run_id)
                if run is not None:
                    run.current_phase = phase_id

                await session.commit()

    async def _persist_phase_complete(
        self, phase_id: str, now: datetime, meta: Dict[str, Any]
    ) -> Optional[float]:
        """Persiste la phase terminée et retourne sa durée en secondes.

        La durée est calculée à partir de ``started_at`` (BDD) — c'est
        l'unique source de vérité utilisée à la fois pour la persistance
        (``phase_exec.duration_seconds``) et le payload bus consommé par le
        bridge agent_service → frontend Iris. Retourne ``None`` si
        ``started_at`` est absent (phase recréée sans préalable).
        """
        async with get_session_factory()() as session:
            phase_exec = await _get_active_phase_exec(session, self._run_id, phase_id)
            if phase_exec is None:
                logger.warning(
                    "PipelineRunner: phase_complete sans phase_start préalable "
                    "(run_id=%s, phase_id=%s) — création d'une ligne",
                    self._run_id,
                    phase_id,
                )
                phase_exec = PipelinePhaseExecution(
                    pipeline_run_id=self._run_id,
                    phase_id=phase_id,
                    phase_label=_phase_label(phase_id),
                    attempt_number=1,
                    status=PipelinePhaseStatus.SUCCESS,
                    started_at=now,
                )
                session.add(phase_exec)
            else:
                phase_exec.status = PipelinePhaseStatus.SUCCESS
            phase_exec.finished_at = now
            phase_started_at: Optional[datetime] = None
            if phase_exec.started_at is not None:
                started = phase_exec.started_at
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                phase_started_at = started
                phase_exec.duration_seconds = (now - started).total_seconds()

            # ── Agrégation coûts/tokens depuis AIPerformanceLog ─────────
            # Plutôt que de demander à pipeline.py de pousser ces meta
            # (cf. fix #6 review adversariale), on les agrège en lisant
            # AIPerformanceLog filtré par request_id du run + plage
            # temporelle de la phase. AIPerformanceLog est rempli
            # automatiquement par LLMManager via llm_call_tracker.
            agg_in, agg_out, agg_cost = await self._aggregate_llm_costs(
                session,
                started_at=phase_started_at,
                ended_at=now,
            )
            # Préférer les meta explicites si fournies (dépreciable mais
            # utile pour les phases programmatiques sans appel LLM).
            phase_exec.tokens_input = int(
                meta.get("tokens_input", agg_in) if meta.get("tokens_input") is not None else agg_in
            )
            phase_exec.tokens_output = int(
                meta.get("tokens_output", agg_out)
                if meta.get("tokens_output") is not None
                else agg_out
            )
            phase_exec.cost_usd_snapshot = float(
                meta.get("cost_usd", agg_cost) if meta.get("cost_usd") is not None else agg_cost
            )
            artifact_path = meta.get("artifact_path")
            if artifact_path is not None:
                phase_exec.artifact_path = str(artifact_path)
            metadata_summary = meta.get("metadata_summary")
            if metadata_summary is not None:
                # Sérialise si dict, garde tel quel si str
                if isinstance(metadata_summary, (dict, list)):
                    phase_exec.metadata_summary = json.dumps(
                        metadata_summary, ensure_ascii=False, default=str
                    )
                else:
                    phase_exec.metadata_summary = str(metadata_summary)

            run = await session.get(PipelineRun, self._run_id)
            if run is not None:
                run.last_completed_phase = phase_id

            # Capture des valeurs AVANT commit : `expire_on_commit` (défaut
            # SQLAlchemy) invalide les attributs après ``session.commit()``
            # et un accès post-commit déclenche un lazy-load — interdit en
            # contexte async (MissingGreenlet). Cf. `feedback_*` mémoire.
            duration_seconds = phase_exec.duration_seconds
            tokens_in_committed = phase_exec.tokens_input
            tokens_out_committed = phase_exec.tokens_output
            cost_committed = phase_exec.cost_usd_snapshot

            await session.commit()

            # Mémoire locale pour _persist_aggregated_costs
            self._tokens_input += tokens_in_committed
            self._tokens_output += tokens_out_committed
            self._cost_usd += cost_committed

            return duration_seconds

    async def _aggregate_llm_costs(
        self,
        session: AsyncSession,
        *,
        started_at: Optional[datetime],
        ended_at: datetime,
    ) -> tuple[int, int, float]:
        """Agrège les coûts LLM depuis AIPerformanceLog pour la phase.

        Filtre par ``request_id`` (corrélation runtime LLM ↔ PipelineRun) +
        plage temporelle ``[started_at, ended_at]``. Retourne ``(0, 0, 0.0)``
        si pas de logs trouvés (phase programmatique, ou avant que
        AIPerformanceLog ait flushé).
        """

        if not self._request_id or started_at is None:
            return (0, 0, 0.0)
        try:
            from sqlalchemy import func as _sa_func

            from app.models.ai_performance import AIPerformanceLog

            stmt = select(
                _sa_func.coalesce(_sa_func.sum(AIPerformanceLog.prompt_tokens), 0),
                _sa_func.coalesce(_sa_func.sum(AIPerformanceLog.completion_tokens), 0),
                _sa_func.coalesce(_sa_func.sum(AIPerformanceLog.cost_usd_snapshot), 0.0),
            ).where(
                AIPerformanceLog.request_id == self._request_id,
                AIPerformanceLog.created_at >= started_at,
                AIPerformanceLog.created_at <= ended_at,
            )
            result = await session.execute(stmt)
            row = result.one_or_none()
            if row is None:
                return (0, 0, 0.0)
            return (int(row[0] or 0), int(row[1] or 0), float(row[2] or 0.0))
        except Exception:  # noqa: BLE001
            logger.exception("_aggregate_llm_costs failed (run_id=%s)", self._run_id)
            return (0, 0, 0.0)

    async def _persist_phase_failed(
        self, phase_id: str, now: datetime, meta: Dict[str, Any]
    ) -> Optional[float]:
        """Persiste la phase en échec et retourne sa durée en secondes.

        Symétrique à ``_persist_phase_complete`` — la durée est calculée
        depuis ``started_at`` (BDD) et retournée pour propagation au bus.
        Retourne ``None`` si ``started_at`` est absent.
        """
        async with get_session_factory()() as session:
            phase_exec = await _get_active_phase_exec(session, self._run_id, phase_id)
            if phase_exec is None:
                phase_exec = PipelinePhaseExecution(
                    pipeline_run_id=self._run_id,
                    phase_id=phase_id,
                    phase_label=_phase_label(phase_id),
                    attempt_number=1,
                    status=PipelinePhaseStatus.FAILED,
                    started_at=now,
                )
                session.add(phase_exec)
            else:
                phase_exec.status = PipelinePhaseStatus.FAILED
            phase_exec.finished_at = now
            if phase_exec.started_at is not None:
                started = phase_exec.started_at
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                phase_exec.duration_seconds = (now - started).total_seconds()
            phase_exec.error_message = str(meta.get("error_message", "")) or None
            phase_exec.error_traceback = meta.get("error_traceback")
            # Capture avant commit pour éviter MissingGreenlet (cf.
            # _persist_phase_complete).
            duration_seconds = phase_exec.duration_seconds
            await session.commit()
            return duration_seconds

    async def _persist_aggregated_costs(self) -> None:
        async with get_session_factory()() as session:
            run = await session.get(PipelineRun, self._run_id)
            if run is None:
                return
            run.total_tokens_input = self._tokens_input
            run.total_tokens_output = self._tokens_output
            run.total_cost_usd = self._cost_usd
            await session.commit()

    async def _post_check_row_count(self, final_sql: str) -> bool:
        """Indique si l'exécution finale a produit 0 lignes (warning UI).

        Implémentation actuelle (deferred fix #15) : la pipeline ne
        l'exécute pas (Phase 4 = composer, pas exécuteur). Le runner
        regarde si un marker ``zero_rows.flag`` a été écrit dans
        l'output_dir — branchement futur côté handler quand l'UI
        exécutera le SQL pour afficher les résultats.

        Heuristique en attendant : si TOUTES les probes Phase 3 ont
        retourné 0 rows, c'est un signal fort. Le runner pourra checker
        ça dans une version future.
        """

        marker = self._output_dir / "zero_rows.flag"
        return marker.exists()

    async def _post_check_grain(
        self,
        state: Any,
        use_sage: bool,
    ) -> Optional[dict]:
        """F9 (2026-05-21) — Validation post-exec du grain.

        Branche ``scripts.pipeline.validate_grain_post_exec`` sur le SQL
        généré par Phase 4 SI les 3 conditions sont réunies :
            1. ``use_sage=True`` (sinon pas de connector réel à interroger)
            2. ``state.sql_final["sql"]`` non vide (Phase 4 a produit du SQL)
            3. ``state.sql_final["expected_grain"]`` non None (Phase 4 IR
               mode + factsheets ont permis l'estimation)

        Retourne le dict ``{actual_grain, expected_grain, ratio, status,
        message, elapsed_ms}`` produit par le validateur, OU ``None`` si
        les conditions ne sont pas réunies (skip silencieux — pas d'erreur).

        Best-effort : tout échec (import, connector, timeout) → log + None.
        """
        if not use_sage:
            return None
        sql_final = getattr(state, "sql_final", None) or {}
        if not isinstance(sql_final, dict):
            return None
        sql = sql_final.get("sql") or ""
        expected_grain = sql_final.get("expected_grain")
        if not sql or expected_grain is None:
            return None
        try:
            from scripts.pipeline import validate_grain_post_exec
            from app.services.database.sage_connector import get_sage_connector

            connector = get_sage_connector()
            result = await validate_grain_post_exec(
                sql=sql,
                expected_grain=expected_grain,
                connector=connector,
            )
            # Log structuré pour traçabilité — visible côté serveur, pas surfacé
            # à l'UI (le client le reçoit via pipeline_complete event s'il veut).
            logger.info(
                "F9 grain validation: status=%s actual=%s expected=%s ratio=%s elapsed_ms=%s",
                result.get("status"),
                result.get("actual_grain"),
                result.get("expected_grain"),
                result.get("ratio"),
                result.get("elapsed_ms"),
            )
            return result
        except Exception as exc:  # noqa: BLE001
            logger.warning("F9 grain validation skippée (raison non bloquante): %s", exc)
            return None


# ── Fonctions utilitaires (BDD) ────────────────────────────────────────


async def _load_run_data(run_id: int) -> Optional[Dict[str, Any]]:
    """Charge les paramètres immutables d'un run (lecture seule).

    Sépare la lecture (kwargs pipeline) des écritures (status updates) pour
    minimiser les sessions ouvertes.
    """

    async with get_session_factory()() as session:
        run = await session.get(PipelineRun, run_id)
        if run is None:
            return None
        mode_value = run.mode.value if hasattr(run.mode, "value") else str(run.mode)
        return {
            "query_nl": run.query_nl,
            "mode": mode_value,
            "block_all_views": run.block_all_views,
            "use_sage": run.use_sage,
        }


async def _update_run_status(run_id: int, mutator: Callable[[PipelineRun], Any]) -> Any:
    """Charge un run, applique un mutateur, commit. Catch + log si absent.

    Retourne le résultat du mutateur (B8) : les ``mark_*`` terminaux renvoient
    un ``bool`` (True = transition appliquée, False = run déjà terminal). Le
    caller peut ainsi ne publier l'event terminal QUE si la transition a pris
    (cohérence event ↔ BDD, anti event « complete » sur un run déjà annulé).
    Retourne ``None`` si le run est introuvable.
    """

    async with get_session_factory()() as session:
        run = await session.get(PipelineRun, run_id)
        if run is None:
            logger.warning("_update_run_status: run_id=%s introuvable", run_id)
            return None
        result = mutator(run)
        await session.commit()
        return result


async def _next_attempt_number(session: AsyncSession, run_id: int, phase_id: str) -> int:
    """Retourne le prochain ``attempt_number`` pour une phase d'un run.

    **Important (fix #5+#20 review adversariale)** : ne marque PAS les
    attempts précédents ``is_superseded``. Cette responsabilité revient
    à ``_supersede_previous_attempts()`` à appeler APRÈS commit du nouvel
    attempt — pour ne pas perdre la traçabilité si l'insert échoue.

    Le ``attempt_number`` est calculé sous lock applicatif via
    ``_get_phase_attempt_lock(run_id, phase_id)`` côté caller — sérialise
    les `_next_attempt_number` concurrents pour le même tuple, élimine
    la race "deux callers lisent max=N et insèrent N+1 en parallèle".
    """

    stmt = select(PipelinePhaseExecution).where(
        PipelinePhaseExecution.pipeline_run_id == run_id,
        PipelinePhaseExecution.phase_id == phase_id,
    )
    result = await session.execute(stmt)
    rows = list(result.scalars().all())
    if not rows:
        return 1
    return max(r.attempt_number for r in rows) + 1


async def _supersede_previous_attempts(
    session: AsyncSession,
    run_id: int,
    phase_id: str,
    *,
    keep_attempt: int,
) -> None:
    """Marque les attempts != keep_attempt comme ``is_superseded=True``.

    À appeler APRÈS commit du nouvel attempt actif (typiquement après
    un futur goto_phase). Seul le ``keep_attempt`` reste actif.
    """

    stmt = select(PipelinePhaseExecution).where(
        PipelinePhaseExecution.pipeline_run_id == run_id,
        PipelinePhaseExecution.phase_id == phase_id,
        PipelinePhaseExecution.attempt_number != keep_attempt,
        PipelinePhaseExecution.is_superseded.is_(False),
    )
    result = await session.execute(stmt)
    for row in result.scalars().all():
        row.is_superseded = True


# Lock applicatif par (run_id, phase_id) — ne bloque pas les phases
# d'autres runs (granularité fine).
_PHASE_ATTEMPT_LOCKS: Dict[tuple, asyncio.Lock] = {}
_PHASE_ATTEMPT_LOCKS_GUARD = asyncio.Lock()


async def _get_phase_attempt_lock(run_id: int, phase_id: str) -> asyncio.Lock:
    key = (run_id, phase_id)
    async with _PHASE_ATTEMPT_LOCKS_GUARD:
        lock = _PHASE_ATTEMPT_LOCKS.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _PHASE_ATTEMPT_LOCKS[key] = lock
    return lock


async def _evict_phase_locks_for_run(run_id: int) -> None:
    """B7 (bug hunt, axe 21) — évince les ``_PHASE_ATTEMPT_LOCKS`` d'un run
    TERMINÉ pour éviter une croissance non bornée (~9 entrées/run ; le mode
    preview multiplie les runs).

    SÛR : la clé est ``(run_id, phase_id)`` ; après la fin d'un run, ses phases
    ne sont jamais ré-attaquées — un resume crée un NOUVEAU run_id (clés
    distinctes). On NE touche PAS ``_RESUME_SOURCE_LOCKS`` (une source terminée
    reste resumable → son lock est réutilisé ; l'évincer rouvrirait la fenêtre
    double-resume que B6 ferme) ni ``_USER_START_LOCKS`` (borné par le nombre
    d'utilisateurs, pas par les runs).
    """
    async with _PHASE_ATTEMPT_LOCKS_GUARD:
        for _k in [k for k in _PHASE_ATTEMPT_LOCKS if k and k[0] == run_id]:
            _PHASE_ATTEMPT_LOCKS.pop(_k, None)


async def _get_active_phase_exec(
    session: AsyncSession, run_id: int, phase_id: str
) -> Optional[PipelinePhaseExecution]:
    """Récupère l'attempt actif (non superseded) d'une phase pour un run."""

    stmt = (
        select(PipelinePhaseExecution)
        .where(
            PipelinePhaseExecution.pipeline_run_id == run_id,
            PipelinePhaseExecution.phase_id == phase_id,
            PipelinePhaseExecution.is_superseded.is_(False),
        )
        .order_by(PipelinePhaseExecution.attempt_number.desc())
        .limit(1)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


def _relative_artifact_path(artifact_path: Any, output_dir: Path) -> Optional[str]:
    """Convertit un chemin artefact absolu en chemin relatif au run.

    Permet à l'UI de demander ``GET /api/iris/pipeline/{id}/artifacts/{rel}``
    sans exposer de chemins serveur en clair.
    """

    if artifact_path is None:
        return None
    try:
        return str(Path(str(artifact_path)).resolve().relative_to(output_dir.resolve()))
    except (ValueError, OSError):
        return None


# ── Registry des runs actifs (RAM) ───────────────────────────────────


class _RunRegistry:
    """Garde les ``PipelineRunner`` actifs en mémoire processus."""

    def __init__(self) -> None:
        self._runners: Dict[int, PipelineRunner] = {}
        self._lock = asyncio.Lock()

    async def register(self, runner: PipelineRunner) -> None:
        async with self._lock:
            self._runners[runner.run_id] = runner

    async def get(self, run_id: int) -> Optional[PipelineRunner]:
        async with self._lock:
            return self._runners.get(run_id)

    async def unregister(self, run_id: int) -> None:
        async with self._lock:
            self._runners.pop(run_id, None)


_REGISTRY = _RunRegistry()



# ── API publique : factory + lookup ─────────────────────────────────


async def start_pipeline_run(
    *,
    user_id: int,
    query_nl: str,
    mode: PipelineMode = PipelineMode.IR,
    # task #82 — vues incluses par défaut (cf. doctrine `pipeline_run.py`).
    block_all_views: bool = False,
    use_sage: bool = True,
    conversation_id: Optional[int] = None,
    triggered_via: TriggeredVia = TriggeredVia.IRIS_CHAT,
    request_id: Optional[str] = None,
    additional_context: Optional[str] = None,
    stop_after_phase: Optional[str] = None,
) -> PipelineRun:
    """Crée un ``PipelineRun`` BDD, alloue son output_dir, lance le runner.

    Retourne l'instance ``PipelineRun`` (déjà commitée). Le run tourne en
    background ; l'appelant peut subscribe au bus pour suivre la progression.

    **Contrôle d'accès** : l'auth (user_id valide) reste de la
    responsabilité du caller. Mais le **quota journalier** est enforcé ICI
    (single source of truth) : tous les call-sites — handler REST, WS,
    tool LLM — passent par cette fonction et ne peuvent shortcut le quota.

    Lève ``QuotaExceededError`` si le user a dépassé
    ``PIPELINE_MAX_RUNS_PER_DAY`` runs dans les dernières 24h.

    Quota check + création BDD sont sous lock per-user (fix #19) pour
    sérialiser les double-clic et empêcher 2 callers concurrents de
    passer ensemble en lisant ``count=N-1``.
    """

    # Lock per-user — sérialise compute_count + insert dans la même
    # section critique. SQLite + Tornado mono-process → suffisant.
    user_lock = await _get_user_start_lock(user_id)
    async with user_lock:
        # Quota check (single source of truth — fix #4 + atomicité fix #19)
        from datetime import timedelta
        from sqlalchemy import func as _sa_func

        cutoff = clock.now() - timedelta(hours=24)
        async with get_session_factory()() as session:
            stmt = (
                select(_sa_func.count(PipelineRun.id))
                .where(PipelineRun.user_id == user_id)
                .where(PipelineRun.created_at >= cutoff)
            )
            result = await session.execute(stmt)
            count_today = int(result.scalar() or 0)
        if count_today >= PIPELINE_MAX_RUNS_PER_DAY:
            raise QuotaExceededError(user_id=user_id, limit=PIPELINE_MAX_RUNS_PER_DAY)

        return await _create_and_start_run(
            user_id=user_id,
            query_nl=query_nl,
            mode=mode,
            block_all_views=block_all_views,
            use_sage=use_sage,
            conversation_id=conversation_id,
            triggered_via=triggered_via,
            request_id=request_id,
            additional_context=additional_context,
            stop_after_phase=stop_after_phase,
        )


async def _create_and_start_run(
    *,
    user_id: int,
    query_nl: str,
    mode: PipelineMode,
    block_all_views: bool,
    use_sage: bool,
    conversation_id: Optional[int],
    triggered_via: TriggeredVia,
    request_id: Optional[str],
    initial_state_dict: Optional[Dict[str, Any]] = None,
    resume_mode: bool = False,
    additional_context: Optional[str] = None,
    stop_after_phase: Optional[str] = None,
    resumed_from_run_id: Optional[int] = None,
) -> PipelineRun:
    """Helper interne — extrait du body de ``start_pipeline_run`` pour
    rester appelable sous lock sans relancer le quota check.

    Args:
        initial_state_dict: si fourni, écrit dans ``output_dir/run.json``
            APRÈS allocation du dossier et AVANT le start du runner. Utilisé
            par ``resume_pipeline_run`` (T3b) pour pré-populer un state
            tronqué que la pipeline relit en mode ``resume=True``.
        resume_mode: si True, le ``PipelineRunner`` créé passe ``resume=True``
            à ``run_pipeline``. Doit être cohérent avec
            ``initial_state_dict`` non-None.
    """

    # Création BDD d'abord (transaction courte, sans output_dir final).
    #
    # BLOCKING #3 review pipeline (race output_dir) — note explicite : si
    # le serveur crashe entre ``_allocate_output_dir`` (mkdir) et ``commit``,
    # un dossier reste sur disque sans row BDD. Le filet
    # ``cleanup_orphan_run_directories()`` (appelé au boot par main.py)
    # détecte ces orphelins et les supprime — pas de leak disque ni de
    # collision id au boot suivant. La séquence ici n'est donc PAS
    # atomique au sens strict, mais l'invariant "tout dossier sans row BDD
    # est nettoyé au prochain boot" est préservé.
    async with get_session_factory()() as session:
        run = PipelineRun(
            user_id=user_id,
            conversation_id=conversation_id,
            query_nl=query_nl,
            mode=mode,
            block_all_views=block_all_views,
            use_sage=use_sage,
            status=PipelineRunStatus.PENDING,
            output_dir="",  # placeholder, mis à jour ci-dessous
            request_id=request_id or uuid.uuid4().hex[:16],
            triggered_via=triggered_via,
            # Feature preview Iris — None pour un run complet (dont les
            # resume, qui repartent jusqu'au SQL). Persisté dès la création
            # pour que le runner (capture __init__) le passe à run_pipeline.
            stop_after_phase=stop_after_phase,
            # B6 — si ce run est une continuation (resume), trace sa source pour
            # l'idempotence anti double-resume.
            resumed_from_run_id=resumed_from_run_id,
        )
        session.add(run)
        await session.flush()  # obtient run.id sans commit
        run_id = run.id

        # Alloue l'output_dir (peut lever si collision). Wrappé dans
        # asyncio.to_thread pour ne pas bloquer l'event loop sur disque
        # lent (fix #22 review adv).
        try:
            output_dir = await asyncio.to_thread(_allocate_output_dir, run_id)
        except FileExistsError:
            run.status = PipelineRunStatus.FAILED
            run.error_message = (
                f"Conflit output_dir : {PIPELINE_RUNS_ROOT / str(run_id)} existe déjà"
            )
            await session.commit()
            raise

        run.output_dir = str(output_dir)
        await session.commit()
        await session.refresh(run)

    # T3b — Pré-écrit le state tronqué si on est en mode resume. AVANT
    # ``runner.start()`` pour que ``run_pipeline(resume=True)`` trouve
    # bien ``run.json`` au load. Écriture atomique (tmp + os.replace).
    #
    # Si l'écriture échoue (disque plein, EROFS, antivirus lock), on a
    # déjà commité un PipelineRun en PENDING. Sans le mark FAILED ici,
    # on créerait un zombie en BDD (status PENDING ad vitam, slot quota
    # consommé 24h, dossier sur disque vide). Fix : on rattrape, on
    # marque FAILED + error_message actionnable, et on re-raise pour que
    # le caller voie l'échec.
    if initial_state_dict is not None:
        run_json_path = output_dir / "run.json"
        try:
            await asyncio.to_thread(_write_initial_state_json, run_json_path, initial_state_dict)
        except Exception as write_exc:  # noqa: BLE001
            logger.exception(
                "_create_and_start_run: failed to pre-write run.json "
                "(run_id=%s) — marking FAILED to avoid PENDING zombie",
                run_id,
            )
            try:
                async with get_session_factory()() as cleanup_session:
                    zombie = await cleanup_session.get(PipelineRun, run_id)
                    if zombie is not None and not zombie.is_terminal():
                        zombie.mark_failed(
                            f"Échec d'initialisation du state resume : {write_exc}",
                            None,
                        )
                        await cleanup_session.commit()
            except Exception:  # noqa: BLE001
                logger.exception(
                    "_create_and_start_run: cleanup mark_failed failed " "(run_id=%s)",
                    run_id,
                )
            raise

    runner = PipelineRunner(
        run,
        resume_mode=resume_mode,
        additional_context=additional_context,
    )
    await _REGISTRY.register(runner)
    await runner.start()
    return run


# ── Helpers ``resume_pipeline_run`` (T3b) ──────────────────────────────


def _write_initial_state_json(path: Path, state_dict: Dict[str, Any]) -> None:
    """Écrit un state initial dans ``run.json`` avant le start de la pipeline.

    Utilisé par ``resume_pipeline_run`` pour pré-peupler le snapshot que
    ``pipeline.run_pipeline(resume=True)`` va relire via
    ``PipelineState.load()``.

    Écriture atomique (tmp + os.replace) — cohérent avec
    ``PipelineState.save()`` côté pipeline. Évite qu'un crash en plein
    write produise un ``run.json`` tronqué qui ferait crasher le load au
    démarrage.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(
            json.dumps(state_dict, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise RuntimeError(f"_write_initial_state_json failed for {path}: {exc}") from exc


def _load_run_json_safe(path: Path) -> Dict[str, Any]:
    """Charge ``run.json`` en retournant un dict, sans ``SystemExit``.

    ``PipelineState.load()`` lève ``SystemExit`` quand le fichier est
    introuvable — comportement adapté à un script CLI mais inacceptable
    dans un tool LLM (crash le serveur). Cette helper retourne le dict
    brut et laisse le caller gérer ``OSError`` / ``json.JSONDecodeError``
    proprement.
    """

    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise json.JSONDecodeError("run.json doit contenir un objet JSON", text, 0)
    return data


def _truncate_state_at_phase(state: Dict[str, Any], from_phase: str) -> Dict[str, Any]:
    """Reset à ``None`` les champs des phases ≥ ``from_phase``.

    Préserve les champs amont (extracted, filtered, ...), ``query`` et
    ``started_at``. Reset aussi ``concept_resolution`` (Phase 2.5 IR,
    consommé par Phase 4) et ``final_sql`` (dérivé de Phase 4) quand on
    rejoue Phase 4 ou plus en amont.

    Retourne un nouveau dict (n'altère pas l'argument). Le caller reste
    libre de poser des ``state_overrides`` par-dessus.

    Lève ``ValueError`` si ``from_phase`` n'est pas dans
    ``_PHASE_ORDER_IDS`` (caller public ``resume_pipeline_run`` valide
    en amont — cette fonction est privée et ne devrait jamais voir un
    ``from_phase`` non canonique).
    """

    out = dict(state)
    from_idx = _PHASE_ORDER_IDS.index(from_phase)
    for pid in _PHASE_ORDER_IDS[from_idx:]:
        attr = _PHASE_STATE_FIELDS[pid]
        out[attr] = None
    # Phase 2.5 (concept_resolution) est utilisée par Phase 4 mode IR.
    # Reset si on rejoue Phase 4 (donc dès qu'on tronque à 4 ou avant).
    if from_idx <= _PHASE_ORDER_IDS.index("4"):
        out["concept_resolution"] = None
    # final_sql est le dérivé de Phase 4. Toujours reset puisqu'on
    # va rejouer au moins une phase (final_sql doit refléter le run en
    # cours, pas l'ancien).
    out["final_sql"] = None
    return out


#: Statuts source DEPUIS lesquels un resume est autorisé (T15, fail-closed).
#: Whitelist plutôt que blacklist : tout statut non listé est refusé par
#: défaut (un futur statut ajouté à l'enum ne devient pas resumable par
#: accident). PENDING/RUNNING sont gérés AVANT par un check dédié (message
#: « annule d'abord »). FAILED/CANCELLED sont EXCLUS : leur ``run.json`` est
#: tronqué/incohérent (crash ou annulation mid-phase) → reprendre dessus
#: construirait du SQL sur des phases incomplètes (CRIT-B). Resumables :
#: SUCCESS (re-jouer depuis une phase), PAUSED (checkpoint durable),
#: STOPPED_EARLY (continuer un run « preview » arrêté volontairement).
_RESUMABLE_SOURCE_STATUSES: frozenset[PipelineRunStatus] = frozenset(
    {
        PipelineRunStatus.SUCCESS,
        PipelineRunStatus.PAUSED,
        PipelineRunStatus.STOPPED_EARLY,
    }
)


async def resume_pipeline_run(
    *,
    user_id: int,
    source_run_id: int,
    from_phase: str,
    state_overrides: Optional[Dict[str, Any]] = None,
    triggered_via: TriggeredVia = TriggeredVia.IRIS_CHAT,
    request_id: Optional[str] = None,
) -> PipelineRun:
    """Reprend un ``PipelineRun`` existant à partir d'une phase donnée.

    Crée un **NOUVEAU** ``PipelineRun`` (préserve l'historique du source
    pour audit) qui :

    - Réutilise ``query_nl`` / ``mode`` / ``block_all_views`` /
      ``use_sage`` / ``conversation_id`` du source.
    - Pré-écrit un ``run.json`` tronqué aux phases < ``from_phase`` dans
      le nouveau ``output_dir``.
    - Apply ``state_overrides`` (whitelist sur champs ``PipelineState``).
    - Lance la pipeline avec ``resume=True`` — la pipeline relit le
      snapshot et reprend après la dernière phase non-None.

    Sécurité (defense-in-depth) :

    - **Ownership** : ``source_run.user_id == user_id`` — sinon refuse
      avec un message générique 404-like (anti-leak existence cross-user).
    - **from_phase** : doit être dans ``_PHASE_ORDER_IDS``.
    - **state_overrides** : whitelist + cap 64 KiB sérialisé (anti-DoS
      storage / anti-injection LLM).
    - **Source non actif** : ``status`` ∉ ``{PENDING, RUNNING}`` ET pas
      de ``PipelineRunner`` actif en RAM — anti race.
    - **Source terminée proprement** (T15, fail-closed) : ``status`` ∈
      :data:`_RESUMABLE_SOURCE_STATUSES` (SUCCESS / PAUSED / STOPPED_EARLY).
      FAILED/CANCELLED refusés — leur snapshot est tronqué (CRIT-B).
    - **Phases amont complètes** : pour ``from_phase=N``, toutes les
      phases ``< N`` doivent avoir leur champ state non-None dans le
      snapshot — sinon resume incohérent (Phase N consommerait du None).
    - **Quota** : réutilise ``PIPELINE_MAX_RUNS_PER_DAY``. Un resume
      compte comme un run normal pour le quota (pas de privilège).

    Args:
        user_id: utilisateur qui fait la demande (ownership + quota).
        source_run_id: ID du ``PipelineRun`` à reprendre.
        from_phase: ID de phase canonique (cf. ``_PHASE_ORDER_IDS``).
        state_overrides: patches optionnels sur le state pré-resume.
        triggered_via: origine du run (par défaut IRIS_CHAT).
        request_id: corrélation logs LLM (réutilise ou génère).

    Returns:
        Le nouveau ``PipelineRun`` (déjà commité, runner registered et
        started en background).

    Raises:
        ResumeValidationError: paramètres invalides (4xx-like).
        QuotaExceededError: quota journalier dépassé (429-like).
        FileExistsError: collision output_dir (rarissime — runner
            précédent n'a pas été cleanup).
    """

    # ── Validation from_phase (statique, pas de I/O) ──────────────────
    if from_phase not in _PHASE_ORDER_IDS:
        valid = ", ".join(_PHASE_ORDER_IDS)
        raise ResumeValidationError(f"from_phase invalide '{from_phase}'. Valides : {valid}")

    # ── Validation state_overrides (statique) ─────────────────────────
    if state_overrides is not None:
        if not isinstance(state_overrides, dict):
            raise ResumeValidationError("state_overrides doit être un objet (dict) si fourni.")
        invalid_keys = sorted(set(state_overrides.keys()) - _PIPELINE_STATE_OVERRIDE_FIELDS)
        if invalid_keys:
            allowed = ", ".join(sorted(_PIPELINE_STATE_OVERRIDE_FIELDS))
            raise ResumeValidationError(
                f"state_overrides : clés interdites {invalid_keys}. " f"Autorisées : {allowed}"
            )
        try:
            serialized = json.dumps(state_overrides, ensure_ascii=False, default=str)
        except (TypeError, ValueError) as exc:
            raise ResumeValidationError(f"state_overrides non JSON-sérialisable : {exc}") from exc
        if len(serialized.encode("utf-8")) > _STATE_OVERRIDES_MAX_BYTES:
            raise ResumeValidationError(
                f"state_overrides dépasse {_STATE_OVERRIDES_MAX_BYTES} octets " f"sérialisé."
            )

    # Locks imbriqués :
    # - ``user_lock`` (per-user) sérialise quota check + create BDD
    #   (cohérent avec ``start_pipeline_run``).
    # - ``source_lock`` (per-source-run) ferme la fenêtre TOCTOU entre
    #   check ownership/status/RAM-registry et le read du run.json source.
    #   Sans lui, 2 callers concurrents (admin + user via 2 onglets, ou
    #   2 tool calls LLM consécutifs) pourraient tous deux passer le
    #   check « pas de runner actif » avant que le premier ne register.
    user_lock = await _get_user_start_lock(user_id)
    source_lock = await _get_resume_source_lock(source_run_id)
    async with user_lock, source_lock:
        # ── Charger source_run + ownership check ─────────────────────
        async with get_session_factory()() as session:
            source_run = await session.get(PipelineRun, source_run_id)
            if source_run is None or source_run.user_id != user_id:
                # 404-like : pas de leak existence cross-user via timing
                # ou message différent.
                raise ResumeValidationError(f"Run #{source_run_id} introuvable.")

            # ⚠️ Ordre des checks après ownership = sécurité-critique.
            # Le « encore actif » divulgue l'existence + status — il DOIT
            # rester APRÈS le check ownership pour que seul le owner le
            # voie.
            if source_run.status in (
                PipelineRunStatus.PENDING,
                PipelineRunStatus.RUNNING,
            ):
                status_str = (
                    source_run.status.value
                    if hasattr(source_run.status, "value")
                    else str(source_run.status)
                )
                raise ResumeValidationError(
                    f"Run #{source_run_id} est encore actif "
                    f"(status={status_str}). Annule-le d'abord avant de "
                    f"le reprendre."
                )

            # Fail-closed (T15, CRIT-B) : seul un run terminé PROPREMENT est
            # resumable (whitelist :data:`_RESUMABLE_SOURCE_STATUSES`). Un run
            # FAILED/CANCELLED a un run.json tronqué/incohérent (crash ou
            # annulation mid-phase) — reprendre dessus construirait du SQL sur
            # des phases incomplètes. On refuse plutôt que de produire un
            # résultat silencieusement faux.
            if source_run.status not in _RESUMABLE_SOURCE_STATUSES:
                _st = (
                    source_run.status.value
                    if hasattr(source_run.status, "value")
                    else str(source_run.status)
                )
                raise ResumeValidationError(
                    f"Run #{source_run_id} (status={_st}) ne peut pas être "
                    f"repris : il s'est terminé en échec ou a été annulé, son "
                    f"état est incomplet. Relance une nouvelle requête plutôt "
                    f"que de reprendre celui-ci."
                )

            # B6 (bug hunt) — idempotence anti double-resume : refuser si la
            # source a DÉJÀ un run de continuation ENCORE ACTIF (non-terminal).
            # Cas : bouton « Continuer » rejoué au refresh / multi-onglet (B4
            # mitige côté front, mais l'API ou un double tool-call LLM peuvent
            # aussi déclencher 2 resume). On est sous le source_lock déjà tenu :
            # ce check + la création de l'enfant (plus bas, même lock) sont
            # sérialisés pour la même source → pas de course. Un enfant TERMINAL
            # ne bloque PAS (re-resume = intention neuve, légitime).
            _existing_child = await session.execute(
                select(PipelineRun.id)
                .where(
                    PipelineRun.resumed_from_run_id == source_run_id,
                    PipelineRun.status.not_in(tuple(PipelineRunStatus.terminal())),
                )
                .limit(1)
            )
            if _existing_child.scalar_one_or_none() is not None:
                raise ResumeValidationError(
                    f"Une reprise du run #{source_run_id} est déjà en cours. "
                    f"Attends qu'elle se termine avant d'en relancer une."
                )

            # Snapshot des params source pour réutilisation hors-session.
            # Toutes les valeurs sont matérialisées AVANT la sortie du
            # ``async with session`` (évite tout lazy-load post-detach).
            source_query = source_run.query_nl
            # Capture .value pour éviter toute fragilité enum cross-session.
            source_mode_value = (
                source_run.mode.value if hasattr(source_run.mode, "value") else str(source_run.mode)
            )
            source_block = source_run.block_all_views
            source_use_sage = source_run.use_sage
            source_conv = source_run.conversation_id
            source_output_dir = Path(source_run.output_dir)

        # Defense-in-depth : si un runner est actif en RAM (status BDD
        # stale après crash partiel), refuse aussi.
        active_runner = await _REGISTRY.get(source_run_id)
        if active_runner is not None:
            raise ResumeValidationError(
                f"Run #{source_run_id} a un runner actif. Annule-le "
                f"d'abord avant de le reprendre."
            )

        # ── Path traversal defense (axe 8 contrat Komptia) ───────────
        # ``source_run.output_dir`` vient de la BDD. Une corruption (admin
        # SQL, migration foireuse) pourrait y mettre ``/etc/somewhere``.
        # On refuse si le chemin n'est PAS sous PIPELINE_RUNS_ROOT —
        # évite que ``_load_run_json_safe`` lise un fichier hors zone.
        try:
            source_resolved = source_output_dir.resolve()
            runs_root_resolved = PIPELINE_RUNS_ROOT.resolve()
            source_resolved.relative_to(runs_root_resolved)
        except (ValueError, OSError) as exc:
            logger.error(
                "resume_pipeline_run: source output_dir hors PIPELINE_RUNS_ROOT "
                "(run_id=%s, output_dir=%s)",
                source_run_id,
                source_output_dir,
            )
            raise ResumeValidationError(
                f"Run #{source_run_id} a un dossier de sortie invalide. " "Contacte un admin."
            ) from exc

        # ── Charger run.json source (load custom, pas SystemExit) ────
        run_json_path = source_output_dir / "run.json"
        if not await asyncio.to_thread(run_json_path.is_file):
            raise ResumeValidationError(
                f"Snapshot run.json introuvable pour le run #{source_run_id} "
                f"(le dossier a peut-être été nettoyé)."
            )
        try:
            source_state = await asyncio.to_thread(_load_run_json_safe, run_json_path)
        except (OSError, json.JSONDecodeError) as exc:
            raise ResumeValidationError(
                f"Snapshot run.json corrompu pour le run #{source_run_id} : {exc}"
            ) from exc

        # ── Tronquer state aux phases < from_phase ───────────────────
        truncated_state = _truncate_state_at_phase(source_state, from_phase)

        # ── Valider que les phases amont ont bien tourné ─────────────
        from_idx = _PHASE_ORDER_IDS.index(from_phase)
        for amont_pid in _PHASE_ORDER_IDS[:from_idx]:
            if amont_pid in _OPTIONAL_PHASE_IDS:
                # Phase détection-seule : son champ d'état n'est jamais peuplé,
                # exiger sa "complétion" ferait échouer tout resume légitime.
                # Cf. ``_OPTIONAL_PHASE_IDS``.
                continue
            attr = _PHASE_STATE_FIELDS[amont_pid]
            if truncated_state.get(attr) is None:
                raise ResumeValidationError(
                    f"Resume depuis phase '{from_phase}' impossible : la "
                    f"phase amont '{amont_pid}' (champ '{attr}') n'a pas "
                    f"été complétée dans le run source."
                )

        # ── Apply state_overrides (whitelist déjà validée) ───────────
        if state_overrides:
            for key, value in state_overrides.items():
                truncated_state[key] = value

        # ── Quota check (single source of truth, cohérent avec start) ─
        from datetime import timedelta
        from sqlalchemy import func as _sa_func

        cutoff = clock.now() - timedelta(hours=24)
        async with get_session_factory()() as session:
            stmt = (
                select(_sa_func.count(PipelineRun.id))
                .where(PipelineRun.user_id == user_id)
                .where(PipelineRun.created_at >= cutoff)
            )
            result = await session.execute(stmt)
            count_today = int(result.scalar() or 0)
        if count_today >= PIPELINE_MAX_RUNS_PER_DAY:
            raise QuotaExceededError(user_id=user_id, limit=PIPELINE_MAX_RUNS_PER_DAY)

        # ── Crée + start le nouveau run avec state pré-populé ────────
        # Reconvertit en enum (ORM accepte enum, on a capturé .value pour
        # robustesse cross-session).
        try:
            source_mode = PipelineMode(source_mode_value)
        except ValueError as exc:
            # Mode inconnu en BDD (corruption ou enum migré sans handle).
            raise ResumeValidationError(
                f"Run #{source_run_id} a un mode inconnu : " f"'{source_mode_value}'."
            ) from exc

        return await _create_and_start_run(
            user_id=user_id,
            query_nl=source_query,
            mode=source_mode,
            block_all_views=source_block,
            use_sage=source_use_sage,
            conversation_id=source_conv,
            triggered_via=triggered_via,
            request_id=request_id,
            initial_state_dict=truncated_state,
            resume_mode=True,
            # B6 — trace la source : le nouveau run est une continuation de
            # source_run_id. Sert au check d'idempotence (refuse un 2e resume
            # tant que cet enfant est non-terminal).
            resumed_from_run_id=source_run_id,
        )


async def get_runner(run_id: int, user_id: int) -> Optional[PipelineRunner]:
    """Retourne le runner actif pour un run_id, ou None.

    BLOCKING #4 review pipeline : un caller doit fournir ``user_id`` pour
    prouver son ownership. Si le runner existe mais appartient à un autre
    user, on retourne ``None`` (404 cohérent avec les autres handlers,
    pas de leak d'existence cross-user via timing).

    Le check d'ownership se fait sur ``runner._user_id`` (capturé à
    register). Pour l'audit/admin il faudra une variante explicite
    (à ajouter quand le besoin émergera, pas avant).
    """

    runner = await _REGISTRY.get(run_id)
    if runner is None:
        return None
    if not isinstance(user_id, int) or user_id <= 0:
        return None
    # Le runner stocke son user_id depuis le PipelineRun à register.
    runner_user_id = getattr(runner, "_user_id", None)
    if runner_user_id != user_id:
        # Pas un raise/log warning : ne JAMAIS leak l'existence du run
        # via un message d'erreur différent. Comportement identique à
        # "run inexistant" pour un attaquant.
        return None
    return runner


async def cleanup_orphan_run_directories() -> int:
    """Cleanup au boot serveur des dossiers ``outputs/runs/{N}`` orphelins.

    Cas typique : le serveur crashe entre ``session.flush()`` (qui alloue
    l'id BDD + crée le dossier) et ``session.commit()`` (qui persiste le
    row). La transaction rollback → pas de row BDD, mais le dossier reste
    sur disque. Au prochain démarrage, l'id sera réutilisé par SQLite et
    ``mkdir(exist_ok=False)`` lèvera ``FileExistsError`` → l'utilisateur
    voit "Conflit interne".

    Cette fonction scanne ``PIPELINE_RUNS_ROOT``, liste les sous-dossiers
    nommés par un entier, et supprime ceux dont l'id N'EXISTE PAS dans
    ``pipeline_runs``. Idempotent. À appeler une fois au boot.

    Aussi : supprime les dossiers des runs ``status in (failed, cancelled)``
    plus vieux que 24h sans subscriber actif (libère le disque).

    Retourne le nombre de dossiers supprimés.
    """

    import shutil

    if not PIPELINE_RUNS_ROOT.exists():
        return 0

    count = 0
    # IDs présents dans la BDD
    async with get_session_factory()() as session:
        stmt = select(PipelineRun.id)
        result = await session.execute(stmt)
        existing_ids = {row[0] for row in result.all()}

    for child in PIPELINE_RUNS_ROOT.iterdir():
        if not child.is_dir():
            continue
        try:
            run_id = int(child.name)
        except ValueError:
            # Sous-dossier au nom non numérique — laissé en place
            continue
        if run_id not in existing_ids:
            try:
                shutil.rmtree(child)
                count += 1
                logger.info(
                    "cleanup_orphan_run_directories: removed %s (no BDD row)",
                    child,
                )
            except OSError:
                logger.exception("cleanup_orphan_run_directories: rmtree failed (%s)", child)

    return count


async def reconcile_orphan_runs() -> int:
    """Réconcilie au boot les runs ACTIFS orphelins (fantômes post-restart).

    Un ``PipelineRun`` en statut ``PENDING`` ou ``RUNNING`` n'a de sens que
    s'il existe un ``PipelineRunner`` EN MÉMOIRE (registre volatil
    ``_REGISTRY``) qui le pilote. Tout redémarrage serveur (deploy, crash,
    auto-reload dev) vide ce registre. Un run resté ``pending``/``running``
    en BDD après un boot est donc un FANTÔME : plus aucun process ne le fait
    avancer. Conséquences observables :

    - Côté UI (historique + status WS) il reste « en cours » à vie.
    - Il est INreprenable : ``start_resume`` refuse un source en
      ``PENDING``/``RUNNING`` (« encore actif ») → l'utilisateur ne peut ni
      le terminer, ni le relancer proprement.

    On les marque ``FAILED`` via ``mark_failed`` (SSoT du cycle de vie du
    modèle — pose status + error_message + finished_at + duration). Idempotent.

    ⚠️ ``PAUSED`` est VOLONTAIREMENT exclu : un run en pause est un point de
    reprise DURABLE conçu pour survivre au redémarrage (``start_resume``
    l'autorise explicitement). Le marquer failed détruirait la feature resume.

    À appeler UNE fois au boot, AVANT que le serveur n'accepte des connexions
    (sinon race avec un nouveau run légitime qui démarre). Au boot il n'y a
    par construction aucun runner en mémoire, donc tout PENDING/RUNNING est
    nécessairement orphelin — aucun faux positif possible.

    Retourne le nombre de runs réconciliés.
    """

    reconciled = 0
    async with get_session_factory()() as session:
        # SSoT : statuts actifs-volatils (PENDING/RUNNING) — cf. adversarial A6 #9.
        # PAUSED exclu (checkpoint durable resumable, pas de runner requis).
        stmt = select(PipelineRun).where(
            PipelineRun.status.in_(tuple(PipelineRunStatus.active_volatile()))
        )
        result = await session.execute(stmt)
        orphans = result.scalars().all()
        for run in orphans:
            run.mark_failed(
                "Run interrompu par un redémarrage du serveur — aucun "
                "process ne le pilotait plus. Relance ta requête."
            )
            reconciled += 1
        if reconciled:
            await session.commit()
            logger.info(
                "reconcile_orphan_runs: %d run(s) fantôme(s) marqué(s) FAILED",
                reconciled,
            )
    return reconciled


async def cancel_run(run_id: int, by_user_id: int) -> bool:
    """Annule un run actif. Retourne True si l'annulation a été demandée.

    Si le run n'a pas de runner actif (déjà terminé, ou serveur redémarré),
    on met juste à jour le status BDD si c'est encore possible.

    BLOCKING #5 review pipeline : ownership check sur le fallback BDD.
    Sans ce check un user pouvait canceller le run d'un autre user via le
    fallback (le path runner-actif est protégé par le handler WS, mais le
    fallback était exposé en libre).
    """

    if not isinstance(by_user_id, int) or by_user_id <= 0:
        return False

    runner = await _REGISTRY.get(run_id)
    if runner is not None:
        # Defense-in-depth : valider ownership runner aussi (le caller WS
        # est censé l'avoir fait, mais ce n'est pas un coût).
        runner_user_id = getattr(runner, "_user_id", None)
        if runner_user_id != by_user_id:
            return False
        await runner.cancel(by_user_id=by_user_id)
        return True

    # Fallback : pas de runner en RAM → status DB seulement.
    # Vérifier ownership AVANT mark_cancelled.
    async with get_session_factory()() as session:
        run = await session.get(PipelineRun, run_id)
        if run is None:
            return False
        if run.user_id != by_user_id:
            # Pas le propriétaire → refuse. Comportement identique à
            # "run inexistant" pour ne pas leak l'existence cross-user.
            return False
        if run.is_terminal():
            return False
        run.mark_cancelled(by_user_id=by_user_id)
        await session.commit()
    return True


#: Fenêtre de grâce (s) avant d'annuler un run dont le bridge chat s'est fermé
#: SANS cancel explicite (fermeture/refresh d'onglet, coupure WS). Laisse une
#: courte fenêtre au cas où l'utilisateur reviendrait. Env-configurable
#: (doctrine anti-hardcode).
PIPELINE_CHAT_GRACE_SECONDS = float(os.environ.get("PIPELINE_CHAT_GRACE_SECONDS", "30"))


async def stop_run_from_chat(run_id: int, by_user_id: int, *, immediate: bool) -> bool:
    """Stoppe un run lancé depuis le chat Iris quand son bridge se ferme AVANT
    la fin (Stop explicite, fermeture/refresh d'onglet, coupure WS).

    ``immediate=True`` (Stop explicite) → ``cancel`` direct. Sinon →
    ``schedule_grace_cancel`` (fenêtre ``PIPELINE_CHAT_GRACE_SECONDS`` ; la
    grace se ré-annule si un subscriber revient — cf. ``has_subscribers``).
    Ownership-checked. No-op (``False``) si le runner n'est plus en RAM (déjà
    terminé / autre process). Idempotent côté runner (cancel/grace le sont).

    Sans ça, un run orphelin continue à brûler des crédits LLM + requêter Sage
    après que l'utilisateur a quitté ou annulé (audit UX PIPE-1).
    """
    if not isinstance(by_user_id, int) or by_user_id <= 0:
        return False
    runner = await _REGISTRY.get(run_id)
    if runner is None:
        return False
    if getattr(runner, "_user_id", None) != by_user_id:
        return False
    if immediate:
        await runner.cancel(by_user_id=by_user_id)
    else:
        await runner.schedule_grace_cancel(grace_seconds=PIPELINE_CHAT_GRACE_SECONDS)
    return True
