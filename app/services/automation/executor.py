"""
Exécuteur d'automatisations
Moteur principal pour exécuter les automatisations planifiées
"""

import asyncio
import contextvars
import os
import threading
import traceback
from html import escape as html_escape  # noqa: F401 — re-export utilisé par test_executor_workflow
from pathlib import Path
from typing import Optional, Dict, Any, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload

from app.core import clock
from app.config import config
from app.utils.logger import get_logger
from app.models.automation import Automation
from app.models.automation_edge import AutomationEdge
from app.models.automation_step import AutomationStep
from app.models.execution import Execution
from app.core.database import get_session_factory
from app.services.database.query_executor import QueryExecutor
from app.services.email.template_names import EmailTemplate as _EmailTemplate

logger = get_logger(__name__)

#: **Phase 2.5.6.bis (#99)** — Seuil d'échecs consécutifs non-RLS avant
#: auto-pause. Au-delà, l'automatisation est marquée ``is_active=False``
#: + ``paused_reason='too_many_failures'``. Reset à 0 sur 1ère exécution
#: réussie. 5 est un compromis : permet quelques échecs transitoires (LLM
#: down 5min, BDD lente) sans s'acharner sur une auto vraiment cassée.
MAX_CONSECUTIVE_FAILURES: int = 5


def _resolve_smtp_from_name(smtp_config: Dict[str, Any]) -> str:
    """Retourne ``from_name`` SMTP : valeur explicite OU branding global.

    Pas de hardcode "Komptia" / "Cabinet X" ici (axe 6 : généricité).
    """
    explicit = smtp_config.get("from_name")
    if explicit:
        return str(explicit)
    from app.services.branding import get_smtp_from_name

    return get_smtp_from_name()


async def _categorize_sql_error_for_automation(exc: BaseException, fallback_msg: str) -> str:
    """**P2.5 (audit 2026-05-26)** — Catégorise une exception SQL via le helper
    SSoT :func:`sanitize_sql_for_client` pour produire un message FR actionnable.

    Le helper retourne ``category="unknown"`` quand aucun signal SQL n'est
    détecté (ni SQLSTATE, ni keyword) → dans ce cas, on retourne ``fallback_msg``
    (typiquement ``str(exc)`` pour KomptiaError ou message générique).

    Args:
        exc: l'exception remontée par le DAG / step / sink.
        fallback_msg: message à utiliser si la catégorisation ne révèle pas une
            erreur SQL identifiable. Pour KomptiaError, ``str(exc)`` est riche
            (contient SQLSTATE depuis P1.1). Pour les autres, mieux vaut
            « Une erreur est survenue... » que de leak ``str(exc)`` brut.

    Returns:
        Message FR actionnable adapté.
    """
    try:
        from app.services.data_access.error_messages import sanitize_sql_for_client

        # ``user=None`` : path automation système, sanitization PII pas requise
        # ici (l'email d'échec va à l'owner, pas au LLM ni à un user externe).
        payload = await sanitize_sql_for_client(exc, user=None, audience="user")
        category = payload.get("category", "unknown")
        if category != "unknown":
            return payload["message"]
    except Exception:  # noqa: BLE001 — fail-safe : ne jamais casser le path d'erreur
        pass
    return fallback_msg or "Une erreur est survenue lors de l'exécution de l'automatisation."


class AutomationExecutor:
    """Exécuteur d'automatisations planifiées"""

    # Cluster-K (K1) 2026-05-26 — FALLBACK timeout uniquement (utilisé si
    # ``automation.max_duration_seconds`` n'est pas configuré côté admin).
    # Avant : constant 300s écrasait silencieusement la config admin
    # (anti-pattern ``feedback_no_double_cap`` : double cap caché en aval).
    # Maintenant : helper ``_resolve_execution_timeout(automation)`` lit
    # l'admin config en priorité ; ce constant n'est utilisé QUE quand
    # ``max_duration_seconds is None`` (auto historique sans setting).
    EXECUTION_TIMEOUT_SECONDS = 300
    # Timeouts par étape (en secondes) pour éviter qu'une étape bloque tout le pipeline
    # La somme (45+150+90=285s) doit rester < EXECUTION_TIMEOUT_SECONDS (300s)
    STEP_TIMEOUT_SQL_GEN = 45  # Génération NL → SQL
    STEP_TIMEOUT_SQL_EXEC = 150  # Exécution SQL sur Sage
    STEP_TIMEOUT_REPORT = 90  # Génération du rapport (PDF/CSV)
    # Cluster-K (K2) 2026-05-26 — Supprimé l'ancien ``MAX_RESULT_ROWS = 1B``
    # qui était un double cap silencieux. L'admin SSoT = ``db_conn.max_rows``
    # via /admin/database (et l'override per-auto ``automation.max_total_rows``).
    # On passe ``None`` à ``query_executor.execute`` (Optional[int], "no cap"
    # depuis cette couche). Le connector applique seul son cap admin.

    def __init__(self):
        # Le générateur utilise la config depuis la BDD
        self.query_executor = QueryExecutor()
        self.output_dir = config.data_dir / "automation_reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_execution_timeout(self, automation: Automation) -> int:
        """Cluster-K (K1) 2026-05-26 — Retourne le timeout effectif en
        secondes pour cette automation. SSoT admin :
        ``automation.max_duration_seconds`` (Optional[int]).

        Si non configuré (None) → fallback ``EXECUTION_TIMEOUT_SECONDS``
        (5 min). Si admin met une valeur > 5 min, on respecte (anti
        double-cap : pas de plafond caché qui écraserait l'admin).

        Defensive coercion : si la valeur est non-int (Mock dans les
        tests legacy, str BDD corruption, etc.), fallback safe au
        constant — éviter `TypeError: '>' not supported`.
        """
        admin_value = getattr(automation, "max_duration_seconds", None)
        if admin_value is None:
            return self.EXECUTION_TIMEOUT_SECONDS
        try:
            admin_int = int(admin_value)
        except (TypeError, ValueError):
            return self.EXECUTION_TIMEOUT_SECONDS
        if admin_int > 0:
            return admin_int
        return self.EXECUTION_TIMEOUT_SECONDS

    async def execute_automation(
        self,
        automation_id: int,
        manual: bool = False,
        trigger_data: Optional[Dict[str, Any]] = None,
        trigger_source: Optional[str] = None,
        triggered_by_user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Exécute une automatisation complète.

        Args:
            automation_id: ID de l'automatisation
            manual: True si exécution manuelle (backward-compat)
            trigger_data: Données de déclenchement (webhook payload, etc.)
            trigger_source: scheduled / webhook / manual / replay (Phase 2b).
                Si None, derive de `manual` : True → "manual", False → "scheduled".
            triggered_by_user_id: User.id si manual/replay, None sinon.

        Returns:
            Dict avec résultat de l'exécution
        """
        if trigger_source is None:
            trigger_source = "manual" if manual else "scheduled"
        execution = None
        execution_id = None

        try:
            # Créer session async
            session_factory = get_session_factory()
            async with session_factory() as session:
                # Kill-switch global admin : refuse TOUTES les nouvelles
                # executions (manual + scheduled + webhook) si le flag est
                # actif. Couvre tous les chemins — pas seulement le handler
                # UI. Les runs en cours ne sont pas interrompus.
                from app.models.feature_flag import FLAG_AUTOMATIONS_DISABLED
                from app.services.automation.feature_flag_service import is_truthy

                if await is_truthy(session, FLAG_AUTOMATIONS_DISABLED, default=False):
                    logger.warning(
                        "Execution automation %d refusee (kill-switch admin actif)",
                        automation_id,
                    )
                    return {
                        "success": False,
                        "error": "Les executions d'automatisations sont temporairement desactivees par l'administrateur.",
                    }

                # Charger l'automatisation
                automation = await self._load_automation(session, automation_id)
                if not automation:
                    raise ValueError(f"Automatisation {automation_id} introuvable")

                if not automation.is_active and not manual:
                    logger.warning("Automatisation %d inactive, execution annulee", automation_id)
                    return {"success": False, "error": "Automatisation inactive"}

                # Cancel-on-next-run : si l'auto a une (ou des) execution(s)
                # precedente(s) en attente d'une reponse externe (status=
                # 'waiting' suite a un step email_wait_response), on les
                # annule proprement avant de demarrer la nouvelle exec.
                # Logique : un nouveau run cron/manuel/webhook indique que
                # le user veut re-jouer, donc l'attente precedente devient
                # caduque (on ne veut pas 2 instances waiting concurrentes,
                # ni reprendre une vieille reponse alors que les data ont
                # change). Notification email best-effort aux destinataires
                # via cancel_pending_waits_for_automation.
                try:
                    from app.services.automation.wait_resume import (
                        cancel_pending_waits_for_automation,
                    )

                    cancelled = await cancel_pending_waits_for_automation(
                        automation_id,
                        reason=(
                            "Annulee : nouvelle execution declenchee " f"(source={trigger_source})"
                        ),
                    )
                    if cancelled:
                        logger.info(
                            "execute_automation: %d execution(s) waiting "
                            "annulee(s) pour auto %d (cancel-on-next-run)",
                            cancelled,
                            automation_id,
                        )
                except Exception:  # noqa: BLE001 — best-effort
                    logger.warning(
                        "execute_automation: cancel_pending_waits echec pour "
                        "auto %d (continue le nouveau run)",
                        automation_id,
                        exc_info=True,
                    )

                # Créer l'exécution AVANT le load runtime_user — si l'user
                # est introuvable/desactive, on doit pouvoir marquer
                # l'Execution failed proprement plutot que return un dict
                # sans execution_id (rétro-compat avec test_executor_failures).
                execution = Execution(
                    automation_id=automation_id,
                    trigger_source=trigger_source,
                    triggered_by_user_id=triggered_by_user_id,
                    trigger_payload=trigger_data,
                )
                execution.mark_running()
                session.add(execution)
                await session.commit()
                await session.refresh(execution)
                execution_id = execution.id

                # S1 — Charge runtime_user APRES création Execution.
                # Fail-open avec log CRITICAL : si user introuvable/desactive,
                # on continue le run avec RLS BYPASSEE (log warning explicite)
                # plutot que crasher toute l'automation business-critical.
                # Le warning runtime + log permet detection sans blocage.
                # ContextVar par-task asyncio (isolation N runs concurrent).
                try:
                    runtime_user = await self._load_runtime_user(automation.user_id)
                except ValueError as e:
                    if not manual:
                        # A7-C5 — Run DÉCLENCHÉ (scheduled/webhook) dont le
                        # propriétaire est introuvable/désactivé. Continuer avec
                        # RLS BYPASSÉE serait une escalade de privilège : l'auto
                        # d'un compte révoqué accéderait à TOUTES les données
                        # source sans la moindre restriction RLS. Fail-CLOSED :
                        # on marque l'Execution failed et on abort. (L'infra est
                        # prévue pour ça — cf. commentaire « Créer l'exécution
                        # AVANT le load runtime_user ».)
                        logger.critical(
                            "S1 FAIL-CLOSED — user %d non chargeable (%s) — "
                            "automation %d (trigger=%s) REFUSÉE : pas de RLS "
                            "bypass sur un run déclenché. Investiguer urgemment.",
                            automation.user_id,
                            e,
                            automation_id,
                            trigger_source,
                        )
                        execution.mark_failed(
                            error_message=(
                                "Propriétaire de l'automatisation introuvable ou "
                                "désactivé — exécution refusée (fail-closed)."
                            )
                        )
                        await session.commit()
                        return {
                            "success": False,
                            "error": "Propriétaire désactivé — exécution refusée.",
                            "execution_id": execution_id,
                        }
                    # Run MANUAL : un humain authentifié l'a explicitement
                    # déclenché et en assume la responsabilité → on conserve le
                    # fail-open historique (avec log CRITICAL pour détection).
                    logger.critical(
                        "S1 RLS BYPASS — user %d non chargeable (%s) — "
                        "automation %d (manual) continue avec RLS desactivee. "
                        "Investiguer urgemment.",
                        automation.user_id,
                        e,
                        automation_id,
                    )
                    runtime_user = None
                _current_runtime_user_var.set(runtime_user)

                logger.info(
                    "Demarrage execution #%d (automation=%d, manual=%s)",
                    execution.id,
                    automation_id,
                    manual,
                )

                # D1 cycle 15 — Pipeline DAG unifié.
                #
                # Avant : 3 chemins distincts (DAG, linéaire, legacy mono-step)
                # qui dupliquaient la logique de gestion d'erreur, de notifs,
                # de fail-policy. Maintenant : 1 seul chemin DAG. Si l'auto
                # n'a pas d'edges persistées mais a des steps, on synthétise
                # une chaîne linéaire en mémoire (rétro-compat). Si elle n'a
                # ni steps ni edges, on tombe sur le pipeline legacy mono-step
                # (qui ne peut pas être modélisé en DAG car il n'y a aucun
                # node configuré — c'est un cas dégradé pour autos legacy
                # créées avant Phase 1).
                has_steps = bool(automation.steps)
                has_edges = bool(automation.edges)

                # Pipeline avec timeout global pour eviter les executions infinies.
                # Cluster-K (K1) 2026-05-26 — lecture admin SSoT prioritaire
                # via ``_resolve_execution_timeout`` (au lieu du constant
                # qui écrasait silencieusement).
                effective_timeout = self._resolve_execution_timeout(automation)
                try:
                    if has_edges or has_steps:
                        synthesized = (
                            self._synthesize_linear_edges(automation)
                            if has_steps and not has_edges
                            else None
                        )
                        results, output_file = await asyncio.wait_for(
                            self._run_dag_pipeline(
                                session,
                                automation,
                                execution.id,
                                trigger_data,
                                edges_override=synthesized,
                            ),
                            timeout=effective_timeout,
                        )
                    else:
                        # Legacy mono-step : SQL → exécution → rapport (sans
                        # configuration DAG/steps). Ce path reste pour les
                        # autos historiques. Les nouvelles autos passent
                        # toutes par steps + edges (donc DAG).
                        _sql_query, results, output_file = await asyncio.wait_for(
                            self._run_pipeline(session, automation, execution.id),
                            timeout=effective_timeout,
                        )
                except asyncio.TimeoutError:
                    raise TimeoutError(
                        f"Execution depassee ({effective_timeout}s). "
                        "La requete ou la generation de rapport est trop longue."
                    )

                # ────────────────────────────────────────────────
                # Calcul du status REEL depuis les step_executions.
                # Avant : `mark_success` etait appele systematiquement
                # quand `_run_dag_pipeline` retournait sans exception. Or
                # le DAG executor avec `fail_policy=abort` propage propre-
                # ment les erreurs (marque step_executions comme failed/
                # skipped et retourne `(results=[], output_file=None)`)
                # — il ne raise pas. Resultat : F_EXECUTION.status='success'
                # alors que tous les steps ont fail. UX trompeuse, l'user
                # ne voyait aucune trace d'erreur dans /executions ni
                # /automations/history. Cf. incident David 2026-05-08
                # exec#2 (toutes sources timeout SQL Server, status='success').
                #
                # Logique :
                #   any(step.status='failed')                    → 'failed'
                #   all(sink.status='skipped')                   → 'failed'
                #   any(step='failed') BUT au moins 1 sink ok    → 'partial'
                #     (cas fail_policy='continue' avec fan-out)
                #   else                                         → 'success'
                # ────────────────────────────────────────────────
                from sqlalchemy import select as _select
                from app.models.step_execution import StepExecution

                _step_execs = (
                    (
                        await session.execute(
                            _select(StepExecution).where(StepExecution.execution_id == execution.id)
                        )
                    )
                    .scalars()
                    .all()
                )
                _has_failed = any(s.status == "failed" for s in _step_execs)
                _has_waiting = any(s.status == "waiting" for s in _step_execs)
                _all_skipped = bool(_step_execs) and all(s.status == "skipped" for s in _step_execs)
                # Identifier les sinks (steps terminaux : email, report,
                # export_workbook, save_to_datastore) qui ont reussi
                from app.services.automation.dag_validator import TERMINAL_NODE_TYPES

                _sink_step_ids = {
                    s.id
                    for s in (automation.steps or [])
                    if (s.step_type.value if hasattr(s.step_type, "value") else s.step_type)
                    in TERMINAL_NODE_TYPES
                }
                _sinks_executed = [s for s in _step_execs if s.step_id in _sink_step_ids]
                _any_sink_success = any(s.status == "success" for s in _sinks_executed)
                bool(_sinks_executed) and not _any_sink_success

                output_file_path = str(output_file) if output_file is not None else None

                if _has_waiting:
                    # Un step email_wait_response a suspendu l'execution.
                    # On NE marque PAS success/failed/partial — on laisse
                    # status='waiting' (deja pose par l'adapter via
                    # exec_row.mark_waiting()). Le resume se fera quand le
                    # destinataire repondra (POST /automations/wait/{token}).
                    # Refresh pour obtenir l'etat cohérent (mark_waiting
                    # a été commit dans une session séparée par l'adapter).
                    await session.refresh(execution)
                    if execution.status != "waiting":
                        # Defense in depth : si pour une raison X la
                        # transition n'a pas eu lieu, on la fait ici.
                        execution.mark_waiting()
                        await session.commit()
                    _status_label = "waiting"
                    logger.info(
                        "Execution #%d suspendue (waiting) — reprise au submit " "du destinataire",
                        execution.id,
                    )
                    return {
                        "success": False,
                        "status": "waiting",
                        "execution_id": execution.id,
                        "rows": len(results),
                        "output_file": None,
                    }

                if _has_failed and not _any_sink_success:
                    # Echec total : aucun sink terminal n'a produit de livrable.
                    _failed_steps = [s for s in _step_execs if s.status == "failed"]
                    _agg_error = self._aggregate_step_errors(_failed_steps)
                    execution.mark_failed(
                        error_message=_agg_error,
                        error_traceback=None,
                    )
                    _status_label = "failed"

                    # Phase 2.5.6 (#77) — Auto-pause sur refus data_access.
                    # ``DataAccessDeniedError`` est catchée localement par
                    # ``_execute_node_with_output`` (dag_executor.py) qui
                    # la transforme en ``record.status='failed'`` + propage
                    # ``record.error_class='DataAccessDeniedError'``. Sans
                    # cette détection ici, l'auto retomberait dans le path
                    # générique et re-tenterait à chaque scheduled run alors
                    # que l'admin a posé un deny qui ne changera pas tout
                    # seul → spam emails d'échec + gaspillage compute.
                    _is_data_access_denied = any(
                        getattr(s, "error_class", None) == "DataAccessDeniedError"
                        for s in _failed_steps
                    )
                    if _is_data_access_denied and automation.is_active:
                        automation.is_active = False
                        # **Phase 2.5.6.ter (#100)** — Traçabilité raison.
                        automation.paused_reason = "data_access_denied"
                        automation.paused_at = clock.now()
                        logger.warning(
                            "Auto %d auto-paused (data_access_rule, DAG path) — "
                            "user_id=%d. Au moins un step a échoué sur "
                            "DataAccessDeniedError. Réactivable via toggle UI "
                            "/automations après ajustement des permissions.",
                            automation_id,
                            automation.user_id,
                        )
                elif _has_failed and _any_sink_success:
                    # Partial : fail_policy=continue + fan-out, certains
                    # sinks ont produit, d'autres ont echoue.
                    _failed_steps = [s for s in _step_execs if s.status == "failed"]
                    _agg_error = self._aggregate_step_errors(_failed_steps)
                    execution.mark_partial(
                        error_message=_agg_error,
                        result_rows=len(results),
                        output_file_path=output_file_path,
                    )
                    _status_label = "partial"
                elif _all_skipped:
                    # Defense in depth : tous les steps skipped (cas tres
                    # rare ou impossible vu la logique DAG, mais on prefere
                    # marquer failed plutot que success silencieux).
                    execution.mark_failed(
                        error_message=("Aucune etape n'a ete executee (tous skipped)."),
                    )
                    _status_label = "failed"
                else:
                    execution.mark_success(
                        result_rows=len(results),
                        output_file_path=output_file_path,
                    )
                    _status_label = "success"

                # **Phase 2.5.6.bis (#99)** — Compteur d'échecs consécutifs
                # non-RLS. Reset à 0 sur success. Incrément sur failed
                # (sauf si _is_data_access_denied qui a son propre path
                # auto-pause via #77). Au seuil MAX_CONSECUTIVE_FAILURES,
                # auto-pause avec ``paused_reason='too_many_failures'``.
                #
                # Cluster-U 2026-05-26 — Remplacé le read-modify-write
                # `automation.consecutive_failure_count += 1` (race en
                # multi-instance APScheduler) par un atomic UPDATE SQL
                # `SET count = count + 1`. SQLite serialize les UPDATE
                # dans la même transaction, donc safe pour 2 executors
                # concurrents qui fail le même automation_id.
                from sqlalchemy import update as _sa_update

                if _status_label == "success":
                    if automation.consecutive_failure_count > 0:
                        await session.execute(
                            _sa_update(Automation)
                            .where(Automation.id == automation_id)
                            .values(consecutive_failure_count=0)
                        )
                        automation.consecutive_failure_count = 0
                elif _status_label == "failed" and not _is_data_access_denied:
                    # Cluster-U — atomic increment (vs Python +=1 racy)
                    await session.execute(
                        _sa_update(Automation)
                        .where(Automation.id == automation_id)
                        .values(consecutive_failure_count=Automation.consecutive_failure_count + 1)
                    )
                    # Refresh la valeur pour le check seuil (1 SELECT
                    # dans la même transaction = safe)
                    await session.refresh(automation, ["consecutive_failure_count"])
                    if (
                        automation.consecutive_failure_count >= MAX_CONSECUTIVE_FAILURES
                        and automation.is_active
                    ):
                        automation.is_active = False
                        automation.paused_reason = "too_many_failures"
                        automation.paused_at = clock.now()
                        logger.warning(
                            "Auto %d auto-paused après %d échecs consécutifs "
                            "non-RLS (LLM/SMTP/BDD/timeout). Réactivable via "
                            "toggle UI après diagnostic.",
                            automation_id,
                            automation.consecutive_failure_count,
                        )

                # A7-C2 — Une automation ``schedule_type=='once'`` n'a qu'UNE
                # exécution planifiée. Quand cette exécution PLANIFIÉE se termine
                # (succès OU échec — terminal dans les deux cas), on la désactive
                # immédiatement. Sans ça elle reste ``is_active=True`` alors que
                # son job ``DateTrigger`` one-shot a disparu du jobstore → au
                # reboot, ``load_active_automations`` la ré-ajouterait avec un
                # ``run_date`` PASSÉ → re-fire silencieux (si délai ≤
                # ``misfire_grace_time``) ou job zombie « actif » invisible. On NE
                # désactive PAS sur un trigger ``manual``/``replay`` (test ponctuel
                # de l'utilisateur — il ne veut pas perdre son unique
                # planification). La garde ``and automation.is_active`` évite
                # d'écraser un ``paused_reason`` plus spécifique déjà posé ci-dessus
                # (data_access_denied / too_many_failures).
                if (
                    automation.schedule_type == "once"
                    and trigger_source == "scheduled"
                    and automation.is_active
                ):
                    automation.is_active = False
                    automation.paused_reason = "once_completed"
                    automation.paused_at = clock.now()
                    logger.info(
                        "Auto %d (schedule_type=once) désactivée après son unique "
                        "exécution planifiée (status=%s) — ne sera plus replanifiée.",
                        automation_id,
                        _status_label,
                    )

                await session.commit()

                logger.info(
                    "Execution #%d terminee : status=%s (%d lignes, %s)",
                    execution.id,
                    _status_label,
                    len(results),
                    "workflow" if has_steps else "legacy",
                )

                # Envoyer par email si recipients configures (mode legacy uniquement)
                # En mode workflow, l'email est une etape explicite du workflow
                if _status_label == "success" and not has_steps and automation.recipients:
                    await self._send_email(session, automation, execution, output_file)

                # Notification email selon le status :
                # - success : seulement si notify_on_success
                # - partial / failed : toujours (notify_on_failure OU explicite)
                if _status_label == "success":
                    if automation.notify_on_success:
                        await self._send_execution_notification(
                            session, automation, execution, success=True
                        )
                elif automation.notify_on_failure or _is_data_access_denied:
                    # Couvre 'failed' ET 'partial'. L'utilisateur doit savoir
                    # qu'il y a eu un probleme, meme partiel.
                    # **Phase 2.5.6.quater (#101)** — Override
                    # ``notify_on_failure`` quand l'échec est data_access :
                    # l'user doit savoir qu'un de ses accès a été retiré,
                    # sinon l'auto se tait à jamais (cf. justification dans
                    # legacy path ligne ~540).
                    await self._send_execution_notification(
                        session, automation, execution, success=False
                    )

                return {
                    "success": _status_label == "success",
                    "status": _status_label,
                    "execution_id": execution.id,
                    "rows": len(results),
                    # Coherent avec output_file_path en BDD : None si pas de
                    # sink report (DAG analyse-only). Eviter "None" litteral
                    # dans le JSON exposé au caller.
                    "output_file": str(output_file) if output_file is not None else None,
                }

        except Exception as e:
            error_detail = str(e)
            error_trace = traceback.format_exc()

            logger.error(
                "Erreur execution automatisation %d",
                automation_id,
                exc_info=True,
            )

            # Phase 2.5.6 (#77) — Détection refus data_access (RLS).
            # ``DataAccessDeniedError`` est levée par l'enforcer quand l'auto
            # exécute une SQL qui touche une table interdite par règle deny
            # (closure transitive incluse). Importé dynamiquement pour éviter
            # un cycle au boot. Sans ce flag, l'auto retomberait dans le
            # path générique et continuerait à tenter chaque scheduled run
            # — gaspillage compute + spam d'échecs au propriétaire.
            try:
                from app.services.data_access.enforcer import DataAccessDeniedError

                is_data_access_denied = isinstance(e, DataAccessDeniedError)
            except ImportError:
                # Boot très précoce ou module absent : on désactive juste
                # l'auto-pause RLS, le path générique reste fonctionnel.
                is_data_access_denied = False

            # User-safe message: expose custom app errors and timeout/validation,
            # but not raw system exceptions (connection strings, stack details)
            from app.core.exceptions import KomptiaError

            if is_data_access_denied:
                # ``e.user_message`` est déjà générique mode-invisible
                # (cf. Phase 3.1, ne mentionne JAMAIS le nom de la table
                # bloquée). On l'enrichit pour expliquer la mise en pause.
                user_msg = (
                    f"{e.user_message} "
                    "Cette automatisation a été mise en pause automatiquement "
                    "car elle ne peut plus s'exécuter avec vos droits actuels."
                )
            elif isinstance(e, (TimeoutError, ValueError, KomptiaError)):
                # P2.5 (audit 2026-05-26) — Pour les KomptiaError (QueryError,
                # SageConnectionError, etc.), depuis P1.1 ``str(e)`` contient
                # déjà ``[SQLSTATE] message ODBC`` actionnable. On enrichit via
                # le helper SSoT P2.1 pour avoir un hint catégoriel FR au lieu
                # d'un str(e) brut qui peut être technique (ex: « [42S22]
                # Invalid column name 'CODE_TIERS' » → « La requête référence
                # une table ou un champ qui n'existe pas... »).
                user_msg = await _categorize_sql_error_for_automation(e, error_detail)
            else:
                # P2.5 — Avant : whitelist trop étroite → tout pyodbc.Error /
                # ConnectionError / OSError tombait sur le message générique
                # « Une erreur est survenue lors de l'exécution de
                # l'automatisation. » → impossible de diagnostiquer côté UI
                # /executions ni dans l'email d'échec. Maintenant : on tente
                # de catégoriser via le helper SSoT P2.1. Si l'erreur ressemble
                # à du SQL (SQLSTATE, keywords « timeout », « invalid object
                # name », etc.) → hint catégoriel FR. Sinon → fallback générique
                # (PAS ``str(e)`` brut : exception non-Komptia peut contenir
                # paths/stack/secrets non-sanitizés).
                user_msg = await _categorize_sql_error_for_automation(
                    e, "Une erreur est survenue lors de l'exécution de l'automatisation."
                )

            # Toujours marquer l'exécution comme échouée (évite les exécutions bloquées RUNNING)
            if execution:
                try:
                    execution_id = execution.id
                    session_factory = get_session_factory()
                    async with session_factory() as session:
                        execution = await session.get(Execution, execution_id)
                        if execution is None:
                            logger.warning(
                                f"Execution {execution_id} not found during error "
                                f"handling (possibly deleted)"
                            )
                            return {
                                "success": False,
                                "error": "Exécution introuvable",
                                "execution_id": execution_id,
                            }
                        execution.mark_failed(user_msg, error_trace)

                        # Phase 2.5.6 (#77) — Auto-pause sur refus data_access.
                        # Une auto qui échoue sur ``DataAccessDeniedError`` ne
                        # se résoudra PAS toute seule : l'admin a changé les
                        # permissions, retry chaque heure va juste générer du
                        # bruit + emails d'échec pour rien. On la marque
                        # ``is_active=False`` jusqu'à intervention humaine.
                        # Le propriétaire (ou un admin) peut la réactiver via
                        # le toggle UI de ``/automations``.
                        auto_for_pause = None
                        if is_data_access_denied:
                            auto_for_pause = await self._load_automation(session, automation_id)
                            if auto_for_pause and auto_for_pause.is_active:
                                auto_for_pause.is_active = False
                                # **Phase 2.5.6.ter (#100)** — Traçabilité.
                                auto_for_pause.paused_reason = "data_access_denied"
                                auto_for_pause.paused_at = clock.now()
                                logger.warning(
                                    "Auto %d auto-paused (data_access_rule) — "
                                    "user_id=%d. Réactivable via toggle UI "
                                    "/automations ou après ajustement des "
                                    "permissions par l'admin.",
                                    automation_id,
                                    auto_for_pause.user_id,
                                )
                        await session.commit()

                        # Notification d'echec si activee
                        auto_for_notif = (
                            auto_for_pause
                            if auto_for_pause is not None
                            else await self._load_automation(session, automation_id)
                        )
                        # **Phase 2.5.6.quater (#101)** — Forcer notif sur
                        # auto-pause RLS, même si ``notify_on_failure=False``.
                        # Justification : l'user/admin doit savoir qu'un de
                        # ses accès a été retiré, sinon l'auto se tait à
                        # jamais et il s'en rend compte trop tard (typiquement
                        # le mardi quand le rapport mensuel n'est pas livré).
                        # Pour les autres erreurs (timeout, LLM down), on
                        # respecte le toggle utilisateur.
                        _force_notif = is_data_access_denied
                        if auto_for_notif and (auto_for_notif.notify_on_failure or _force_notif):
                            await self._send_execution_notification(
                                session,
                                auto_for_notif,
                                execution,
                                success=False,
                                error_message=user_msg,
                            )
                except SQLAlchemyError:
                    logger.error(
                        "Erreur sauvegarde echec execution %d",
                        execution_id,
                        exc_info=True,
                    )

            return {
                "success": False,
                "error": user_msg,
                "execution_id": execution_id,
            }

    async def _run_pipeline(
        self, session: AsyncSession, automation: Automation, execution_id: int
    ) -> tuple:
        """Pipeline complet : SQL → exécution → rapport.

        Chaque étape a son propre timeout pour identifier précisément
        quelle étape bloque (au lieu du seul timeout global de 300s).
        """
        try:
            sql_query = await asyncio.wait_for(
                self._get_sql_query(session, automation, execution_id),
                timeout=self.STEP_TIMEOUT_SQL_GEN,
            )
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"Génération SQL dépassée ({self.STEP_TIMEOUT_SQL_GEN}s). "
                "La requête en langage naturel est peut-être trop complexe."
            )

        try:
            results = await asyncio.wait_for(
                self._execute_query(session, sql_query, execution_id),
                timeout=self.STEP_TIMEOUT_SQL_EXEC,
            )
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"Exécution SQL dépassée ({self.STEP_TIMEOUT_SQL_EXEC}s). "
                "La requête retourne peut-être trop de données ou Sage est lent."
            )

        try:
            output_file = await asyncio.wait_for(
                self._generate_report(automation, execution_id, results),
                timeout=self.STEP_TIMEOUT_REPORT,
            )
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"Génération rapport dépassée ({self.STEP_TIMEOUT_REPORT}s). "
                f"Trop de données ({len(results)} lignes) pour la génération PDF."
            )

        return sql_query, results, output_file

    async def _run_workflow_pipeline(
        self,
        session: AsyncSession,
        automation: Automation,
        execution_id: int,
        trigger_data: Optional[Dict[str, Any]] = None,
    ) -> tuple:
        """Pipeline multi-etapes lineaire (mode workflow n8n-style).

        ⚠️ DEPRECATED — D1 cycle 15 : ``execute_automation`` n'appelle plus
        ce chemin pour les nouvelles exécutions. Les autos qui ont des
        steps mais pas d'edges passent maintenant par ``_run_dag_pipeline``
        avec ``edges_override`` synthétisés. Cette méthode reste publiée
        pour rétro-compat avec les tests unitaires (test_retry_logic,
        test_step_execution) qui exercent directement la logique linéaire
        de retry/skip — mais elle n'est plus dans le hot-path.

        Suppression complète prévue dans un cycle ultérieur après :
        1. Migration des tests vers tests qui exercent la logique
           équivalente côté DAG (run_dag_pipeline).
        2. Audit qu'aucune régression de comportement n'apparaît
           (notamment retry-policy step-level, fail-policy abort/skip).

        Execute les etapes dans l'ordre. Les etapes extract/report/email
        sont gerees ici (necessitent DB/SMTP). Les etapes de transformation
        et validation sont deleguees au WorkflowEngine.

        Persiste un StepExecution par etape pour le suivi detaille.

        Args:
            trigger_data: Données de déclenchement (webhook payload, etc.)
                Injectées comme variables initiales dans le contexte.

        Returns:
            (results, output_file) - resultats finaux et fichier genere
        """
        import time

        from app.services.automation.workflow_engine import (
            WorkflowContext,
            capture_step_variables,
            get_workflow_engine,
            resolve_template_variables,
        )

        get_workflow_engine()
        context = WorkflowContext(
            automation_id=automation.id,
            execution_id=execution_id,
            user_id=automation.user_id,
        )

        # Injecter les données de déclenchement comme variables initiales
        # Accessibles via {{webhook.body}}, {{webhook.method}}, etc.
        if trigger_data:
            for namespace, values in trigger_data.items():
                if isinstance(values, dict):
                    for key, val in values.items():
                        context.variables[f"{namespace}.{key}"] = val
                else:
                    context.variables[namespace] = values

        # Filtrer les etapes actives, triees par step_order
        active_steps = sorted(
            [s for s in automation.steps if s.is_enabled],
            key=lambda s: s.step_order,
        )

        if not active_steps:
            raise ValueError("Aucune etape active dans le workflow")

        output_file = None
        step_records = []  # Collecte des resultats par etape

        step_idx = 0
        while step_idx < len(active_steps):
            step = active_steps[step_idx]

            # Verifier si on saute vers une etape specifique (then_goto / else_goto)
            if context.skip_to_step:
                if step.name == context.skip_to_step:
                    # On a atteint l'etape cible — effacer le goto et executer normalement
                    context.skip_to_step = None
                else:
                    logger.info(
                        "Workflow etape %d (%s) sautee (goto vers '%s')",
                        step.step_order,
                        step.name,
                        context.skip_to_step,
                    )
                    step_records.append(
                        {
                            "step_id": step.id,
                            "step_order": step.step_order,
                            "step_name": step.name,
                            "step_type": step.step_type,
                            "status": "skipped",
                            "attempt_number": 1,
                            "started_at": clock.now(),
                            "finished_at": clock.now(),
                            "duration_ms": 0.0,
                        }
                    )
                    step_idx += 1
                    continue

            # Verifier si une etape condition a demande de sauter le reste
            if context.skip_remaining:
                logger.info(
                    "Workflow etape %d (%s) sautee (condition non remplie)",
                    step.step_order,
                    step.name,
                )
                step_records.append(
                    {
                        "step_id": step.id,
                        "step_order": step.step_order,
                        "step_name": step.name,
                        "step_type": step.step_type,
                        "status": "skipped",
                        "attempt_number": 1,
                        "started_at": clock.now(),
                        "finished_at": clock.now(),
                        "duration_ms": 0.0,
                    }
                )
                step_idx += 1
                continue

            step_cfg = dict(step.config or {})
            # Injecter les metadonnees pour le moteur
            step_cfg["_step_name"] = step.name
            step_cfg["_step_order"] = step.step_order

            # Resoudre les templates {{step.var}} dans la config
            if context.variables:
                resolved_cfg, unresolved = resolve_template_variables(step_cfg, context.variables)
                if isinstance(resolved_cfg, dict):
                    step_cfg = resolved_cfg
                if unresolved:
                    logger.debug(
                        "Workflow etape %d (%s): variables non resolues: %s",
                        step.step_order,
                        step.name,
                        unresolved,
                    )

            step_type = step.step_type

            # Retry config (bounded for safety, defensive against non-int values)
            raw_retries = getattr(step, "max_retries", 0)
            max_retries = min(max(raw_retries, 0), 5) if isinstance(raw_retries, int) else 0
            raw_delay = getattr(step, "retry_delay_seconds", 5)
            retry_delay = min(max(raw_delay, 1), 60) if isinstance(raw_delay, int) else 5
            max_attempts = max_retries + 1

            for attempt in range(1, max_attempts + 1):
                rows_in = len(context.rows)
                step_start = time.perf_counter()
                step_started_at = clock.now()
                step_warnings = []

                try:
                    if step_type == "extract_sql":
                        # Extraction SQL directe
                        sql = step_cfg.get("sql", "")
                        if not sql:
                            raise ValueError(f"Etape '{step.name}': requete SQL manquante")
                        try:
                            results = await asyncio.wait_for(
                                self._execute_query(session, sql, execution_id),
                                timeout=self.STEP_TIMEOUT_SQL_EXEC,
                            )
                        except asyncio.TimeoutError:
                            raise TimeoutError(
                                f"Etape '{step.name}': execution SQL depassee "
                                f"({self.STEP_TIMEOUT_SQL_EXEC}s)"
                            )
                        context.rows = results
                        context.columns = list(results[0].keys()) if results else []
                        logger.info(
                            "Workflow etape %d (%s): %d lignes extraites",
                            step.step_order,
                            step.name,
                            len(results),
                        )

                    elif step_type == "report":
                        # Rapport PDF analyse par l'IA (le linear pipeline ne
                        # gere QUE le mode IA, aligne avec le DAG executor).
                        # Le linear path consomme ses rows comme un dataset
                        # unique vs le DAG qui supporte le fan-in multi-tabs.
                        single_tab = [
                            {
                                "label": automation.name or "Donnees",
                                "columns": list(context.columns or []),
                                "rows": list(context.rows or []),
                            }
                        ]
                        try:
                            output_file = await asyncio.wait_for(
                                self._generate_llm_report(
                                    automation,
                                    execution_id,
                                    tabs=single_tab,
                                    user_prompt=(step_cfg.get("prompt") or "").strip() or None,
                                    user_title_hint=(step_cfg.get("title") or "").strip() or None,
                                ),
                                timeout=self.STEP_TIMEOUT_REPORT,
                            )
                        except asyncio.TimeoutError:
                            raise TimeoutError(
                                f"Etape '{step.name}': generation rapport depassee "
                                f"({self.STEP_TIMEOUT_REPORT}s)"
                            )
                        context.generated_files.append(str(output_file))
                        logger.info(
                            "Workflow etape %d (%s): rapport PDF (IA) genere",
                            step.step_order,
                            step.name,
                        )

                    elif step_type == "email":
                        # Envoyer par email
                        recipients = step_cfg.get("recipients", [])
                        subject = step_cfg.get("subject", f"Rapport: {automation.name}")
                        if recipients and context.generated_files:
                            file_path = Path(context.generated_files[-1])
                            await self._send_workflow_email(
                                session,
                                automation,
                                execution_id,
                                recipients,
                                subject,
                                file_path,
                                context,
                            )
                            logger.info(
                                "Workflow etape %d (%s): email envoye a %d destinataires",
                                step.step_order,
                                step.name,
                                len(recipients),
                            )
                        elif not recipients:
                            step_warnings.append(
                                f"Etape '{step.name}': aucun destinataire configure"
                            )
                            context.warnings.append(step_warnings[-1])
                        elif not context.generated_files:
                            step_warnings.append(
                                f"Etape '{step.name}': aucun fichier a joindre "
                                "(ajoutez une etape Rapport avant)"
                            )
                            context.warnings.append(step_warnings[-1])

                    else:
                        # Le linear pipeline est un mode legacy simple (steps
                        # sans edges) — il ne supporte que extract_sql,
                        # report (PDF/IA) et email. Les sources
                        # /datastore (load_workbook, load_saved_query),
                        # l'export plat (export_workbook) et le format IA
                        # (format_copilot) ne sont disponibles qu'en mode
                        # DAG (canvas /automations/N/edit) qui apporte le
                        # fan-in/fan-out necessaire. Pour utiliser ces
                        # types, l'utilisateur doit ajouter au moins un
                        # edge dans son automation.
                        raise ValueError(
                            f"Etape '{step.name}' : type '{step_type}' non "
                            "supporte par le moteur lineaire. Convertissez "
                            "votre automation en pipeline DAG (au moins une "
                            "connexion entre etapes) pour utiliser ce type."
                        )

                    # Succes — enregistrer le resultat de l'etape
                    elapsed_ms = (time.perf_counter() - step_start) * 1000
                    step_records.append(
                        {
                            "step_id": step.id,
                            "step_order": step.step_order,
                            "step_name": step.name,
                            "step_type": step.step_type,
                            "status": "success",
                            "attempt_number": attempt,
                            "started_at": step_started_at,
                            "finished_at": clock.now(),
                            "duration_ms": elapsed_ms,
                            "rows_in": rows_in,
                            "rows_out": len(context.rows),
                            "warnings": step_warnings if step_warnings else None,
                        }
                    )
                    # Capturer les variables de sortie pour les etapes suivantes
                    extra_vars = self._build_step_extra_vars(
                        step_type, step_cfg, context, output_file
                    )
                    capture_step_variables(
                        ctx=context, step_name=step.name, step_type=step_type, extra=extra_vars
                    )

                    if attempt > 1:
                        logger.info(
                            "Workflow etape %d (%s): reussie a la tentative %d/%d",
                            step.step_order,
                            step.name,
                            attempt,
                            max_attempts,
                        )
                    break  # Success — exit retry loop

                except Exception as e:
                    elapsed_ms = (time.perf_counter() - step_start) * 1000
                    is_last_attempt = attempt >= max_attempts

                    # Record this attempt (status: "retried" if more attempts, "failed" if last)
                    # P3.1 — format propre pour pyodbc.Error : extrait SQLSTATE
                    # + message [SQL Server] lisible. Avant : str(pyodbc.Error)
                    # donnait ``('42S22', '[Microsoft][ODBC Driver 17 for SQL
                    # Server][SQL Server]Invalid column name CODE_TIERS (207)
                    # (SQLExecDirectW)')`` tronqué à 120 chars dans
                    # `_aggregate_step_errors` → la colonne fautive disparaissait.
                    from app.services.automation.dag_step_error import (
                        format_step_error_message as _fsm,
                    )

                    step_records.append(
                        {
                            "step_id": step.id,
                            "step_order": step.step_order,
                            "step_name": step.name,
                            "step_type": step.step_type,
                            "status": "failed" if is_last_attempt else "retried",
                            "attempt_number": attempt,
                            "started_at": step_started_at,
                            "finished_at": clock.now(),
                            "duration_ms": elapsed_ms,
                            "rows_in": rows_in,
                            "error_message": _fsm(e),
                            # P5.5 (audit 2026-05-26) — Ajout du ``error_class``
                            # pour parité avec le DAG executor (dag_executor.py:454).
                            # Sans ce champ, le post-process échec ne peut pas
                            # détecter ``DataAccessDeniedError`` côté legacy
                            # path → l'auto-pause RLS (Phase 2.5.6 #77) ne
                            # s'active PAS, l'auto retente chaque cron run et
                            # spam le propriétaire d'emails d'échec.
                            "error_class": type(e).__name__,
                        }
                    )

                    if is_last_attempt:
                        # Plus de TRY_CATCH legacy : une erreur finale fait echouer
                        # l'etape. La Phase 2 introduira `fail_policy` au niveau
                        # workflow + edges error futurs pour un equivalent DAG.
                        await self._persist_step_results(execution_id, step_records)
                        raise
                    else:
                        logger.warning(
                            "Workflow etape %d (%s): tentative %d/%d echouee (%s), "
                            "retry dans %ds...",
                            step.step_order,
                            step.name,
                            attempt,
                            max_attempts,
                            str(e),
                            retry_delay,
                        )
                        await asyncio.sleep(retry_delay)

            step_idx += 1

        # Pas de fallback CSV automatique : si l'utilisateur n'a pas declare
        # de step `report` (PDF) ou `export_workbook` (csv/excel), pas de
        # fichier produit. Coherent avec la vision "tout doit etre explicite"
        # — un livrable necessite un step de sortie declare.

        # Persister les resultats par etape (session separee pour durabilite)
        await self._persist_step_results(execution_id, step_records)

        return context.rows, output_file

    @staticmethod
    def _synthesize_linear_edges(automation: Automation) -> List[AutomationEdge]:
        """Crée en mémoire une chaîne linéaire d'edges step[i]→step[i+1].

        Utilisé par D1 cycle 15 pour router via le DAG les autos qui ont
        des steps mais pas encore d'edges persistées (cas rétro-compat
        avec les autos créées avant Phase 1 du DAG, ou imports legacy).

        Pourquoi en mémoire et pas en BDD : on ne veut pas modifier la
        donnée du user à son insu. Si le user édite l'auto au canvas
        plus tard, il pourra repartir d'un blank-slate ou accepter la
        proposition linéaire (UX TODO future).

        Le data_type est fixé à ``"workbook"`` (le plus commun en chaîne
        extract → format → report). Adversarial cycle 15 #4 : ``"any"``
        n'est pas dans ``EDGE_DATA_TYPES`` du validator → si l'auto était
        sauvegardée avec ces edges synthétisés persistés, le validator
        rejetterait au save suivant. ``"workbook"`` est valide partout
        et compatible avec la plupart des step types (extract, format,
        export). Pour les chaînes atypiques (ex: extract → email direct),
        l'utilisateur doit éditer dans le canvas pour fixer le data_type
        explicitement.

        Args:
            automation: Automation avec ses steps eager-loadés (au minimum
                ``steps`` doit être chargé).

        Returns:
            Liste d'``AutomationEdge`` non persistés. ``len() == 0`` si
            l'auto a 0 ou 1 step actif (pas d'arête à créer).
        """
        # Adversarial cycle 18 #9 : snapshot des attributs requis dans des
        # tuples locaux AVANT toute opération d'I/O. Découple le helper du
        # cycle de vie SQLAlchemy : si un futur refacto déplace l'appel
        # APRÈS un session.commit() (qui expire les Mapped[] avec
        # ``expire_on_commit=True`` par défaut), le helper ne crashera pas
        # avec `MissingGreenlet` — il aura déjà ses valeurs scalaires en
        # mémoire. Cohérent avec le pattern utilisé partout ailleurs dans
        # executor (cf. `auto_id = automation.id` ligne ~155).
        try:
            steps_snapshot = [(s.id, s.step_order, bool(s.is_enabled)) for s in automation.steps]
            automation_id_snapshot = automation.id
        except Exception:  # noqa: BLE001 — fail-safe : caller obtient liste vide
            return []

        # Ne considérer que les steps actifs et les trier par step_order
        # (l'ordre user-facing dans /automations/N/edit).
        active = sorted(
            ((sid, sord) for sid, sord, enabled in steps_snapshot if enabled),
            key=lambda t: t[1],
        )
        if len(active) < 2:
            return []

        edges: List[AutomationEdge] = []
        for i in range(len(active) - 1):
            # Adversarial cycle 18 #14 : on construit l'instance SANS la
            # passer à une session SQLAlchemy. Le caller ne doit JAMAIS
            # faire `session.add(edge)` sur ces instances (foot-gun :
            # Bdd FK valides + automation_id correct → l'INSERT
            # passerait sans bruit et créerait une edge fantôme persistée).
            # Le metadata_json `synthesized=True` permet à un script de
            # nettoyage futur de détecter ces edges si elles passaient
            # accidentellement en BDD.
            edge = AutomationEdge(
                automation_id=automation_id_snapshot,
                from_step_id=active[i][0],
                to_step_id=active[i + 1][0],
                data_type="workbook",  # Adversarial #4 : valeur dans EDGE_DATA_TYPES
                metadata_json={"synthesized": True, "source": "linear_fallback"},
            )
            edges.append(edge)
        return edges

    async def _run_dag_pipeline(
        self,
        session: AsyncSession,
        automation: Automation,
        execution_id: int,
        trigger_data: Optional[Dict[str, Any]] = None,
        edges_override: Optional[List[AutomationEdge]] = None,
    ) -> tuple:
        """Pipeline DAG (Phase 2) : traversee topologique + parallelisme par niveau.

        Prereq : `automation.edges` non-vide et `validate_structural` passe.
        Le DAG est parcouru niveau par niveau (algorithme de Kahn). Les nodes
        d'un meme niveau s'executent en parallele via `asyncio.gather` avec
        un semaphore borne.

        Chaque node consomme son workbook d'entree (fusion des outputs des
        parents en fan-in) et produit un workbook en sortie stocke dans
        `step_outputs[node.id]`. Les descendants des nodes failed sont
        marques skipped selon la fail_policy.

        Returns:
            (rows, output_file) pour compat avec _run_pipeline/linear.
            - rows : rows du dernier onglet du dernier workbook produit (sink).
            - output_file : fichier produit par le dernier node report/email.
        """
        from app.services.automation.dag_executor import run_dag_pipeline

        adapter = _build_executor_adapter(self, session, automation, execution_id)
        context, records = await run_dag_pipeline(
            session,
            automation,
            execution_id,
            adapter,
            trigger_data=trigger_data,
            edges_override=edges_override,
        )

        # Persister les step executions avec les snapshots observabilite
        await self._persist_dag_step_results(execution_id, records)

        # Remonter les resultats pour compat avec le format (rows, output_file).
        # On prend le dernier node sink (email/report) execute avec succes ;
        # s'il n'y en a pas, on retourne vide.
        # B7 fix — output_file lu via context.step_output_files[step_id]
        # (peuple par dag_executor depuis extras["output_file"]). Avant : on
        # lisait context.variables["_output_file"] qui etait race-condition
        # last-writer-wins entre nodes paralleles. Maintenant on itere
        # records EN ORDRE INVERSE (donc dernier sink success en tete) et
        # on prend son output. Pour fan-out 2 reports, on garde le 1er
        # success rencontre — comportement deterministe (vs random race).
        output_file: Optional[str] = None
        last_rows: List[Dict[str, Any]] = []
        for record in records:
            if record.status != "success":
                continue
            wb = context.step_outputs.get(record.step_id)
            if wb:
                for tab in wb.get("tabs", []):
                    last_rows = list(tab.get("rows", []))
        # Output file : on cherche le dernier sink success (le plus aval).
        # Adversarial #11 cycle 16 : `records` est ordonné par level (Kahn)
        # mais asyncio.gather au sein d'un même level ne garantit PAS l'ordre
        # de complétion. Pour deux records au même level (ex: fan-out 2 reports
        # parallèles), l'ordre dans `records` dépend du race scheduler. On
        # trie par (step_order, step_id) avant le reverse pour un comportement
        # 100% déterministe : à fan-out égal, on prend le step au plus grand
        # step_order (donc le plus récemment ajouté par l'user au canvas) ;
        # à step_order égal (théoriquement impossible vu UNIQUE), on tranche
        # par step_id stable. Plus de "last-writer-wins selon planning OS".
        sorted_records = sorted(
            records,
            key=lambda r: (
                getattr(r, "step_order", 0),
                getattr(r, "step_id", 0),
            ),
        )
        for record in reversed(sorted_records):
            if record.status != "success":
                continue
            f = context.step_output_files.get(record.step_id)
            if f:
                output_file = f
                break

        return last_rows, output_file

    async def _persist_dag_step_results(
        self,
        execution_id: int,
        records: List[Any],
    ) -> None:
        """Persiste les StepExecutionRecord du run DAG dans F_STEP_EXECUTION.

        Utilise une session separee pour isoler les resultats (meme pattern
        que _persist_step_results).
        """
        if not records:
            return
        # Import local — sinon NameError au runtime DAG (bug decouvert par
        # tests/integration/test_automation_e2e_full_pipeline.py 2026-05-07).
        # Le module-level import explose les imports circulaires (StepExecution
        # importe Execution importe Automation importe ...), d'ou l'import lazy.
        from app.models.step_execution import StepExecution

        session_factory = get_session_factory()
        async with session_factory() as session:
            for rec in records:
                se = StepExecution(
                    execution_id=execution_id,
                    step_id=rec.step_id,
                    step_order=rec.step_order,
                    step_name=rec.step_name,
                    step_type=rec.step_type,
                    status=rec.status,
                    attempt_number=rec.attempt_number,
                    started_at=rec.started_at,
                    finished_at=rec.finished_at,
                    duration_ms=rec.duration_ms,
                    rows_in=rec.rows_in,
                    rows_out=rec.rows_out,
                    warnings=rec.warnings,
                    error_message=rec.error_message,
                    # P5.5 (audit 2026-05-26) — propage error_class du dataclass
                    # vers le modèle BDD pour que le check ``getattr(s,
                    # "error_class", None)`` côté ``execute_automation`` ligne
                    # ~422 détecte enfin ``DataAccessDeniedError`` après reload.
                    error_class=rec.error_class,
                    trace_id=rec.trace_id,
                    step_input=rec.step_input,
                    step_output=rec.step_output,
                    config_snapshot=rec.config_snapshot,
                    sql_executed=rec.sql_executed,
                )
                session.add(se)
            await session.commit()

    async def _persist_step_results(
        self, execution_id: int, step_records: List[Dict[str, Any]]
    ) -> None:
        """Persiste les resultats d'execution par etape dans une session separee.

        Utilise une session independante pour que les resultats survivent
        meme si la session principale est rollback (ex: erreur apres une etape).
        """
        if not step_records:
            return

        from app.models.step_execution import StepExecution

        try:
            session_factory = get_session_factory()
            async with session_factory() as step_session:
                for record in step_records:
                    step_exec = StepExecution(
                        execution_id=execution_id,
                        **record,
                    )
                    step_session.add(step_exec)
                await step_session.commit()
                logger.info(
                    "Step executions persistees: %d etapes (execution %d)",
                    len(step_records),
                    execution_id,
                )
        except (SQLAlchemyError, RuntimeError):
            # RuntimeError si BDD non initialisee (tests unitaires)
            # SQLAlchemyError si erreur DB
            # Best-effort: ne pas casser le pipeline pour du tracking
            logger.error(
                "Erreur sauvegarde step executions (execution %d)",
                execution_id,
                exc_info=True,
            )

    @staticmethod
    def _build_step_extra_vars(
        step_type: str,
        step_cfg: Dict[str, Any],
        context: Any,
        output_file: Optional[Path],
    ) -> Dict[str, Any]:
        """Construit les variables supplementaires specifiques a un type d'etape.

        Ces variables sont capturees apres l'execution de chaque etape
        et rendues disponibles aux etapes suivantes via {{step_name.var}}.
        """
        if step_type == "extract_sql":
            return {"sql": step_cfg.get("sql", "")}

        if step_type == "report":
            extra = {"format": step_cfg.get("format", "csv")}
            if output_file is not None:
                extra["file_path"] = str(output_file)
            return extra

        if step_type == "email":
            recipients = step_cfg.get("recipients", [])
            return {"recipient_count": len(recipients) if recipients else 0}

        if step_type == "aggregate":
            return {"group_count": len(context.rows)}

        if step_type == "set_variable":
            # Capturer les noms des variables definies
            assignments = step_cfg.get("assignments", [])
            var_names = []
            if isinstance(assignments, list):
                for a in assignments:
                    if isinstance(a, dict) and a.get("name"):
                        var_names.append(a["name"])
            return {
                "assignment_count": len(var_names),
                "variable_names": var_names,
            }

        return {}

    @staticmethod
    def _aggregate_step_errors(failed_step_executions) -> str:
        """Compose un message d'erreur agrégé pour `Execution.error_message`.

        Liste les step_name + cause courte, max 3 ; si plus, ajoute
        "(+N autres)". Le message est destiné à apparaitre dans
        `/executions` et dans l'email de notification d'echec, donc
        FR clair, pas de stack trace.
        """
        if not failed_step_executions:
            return "Echec d'execution (aucun detail disponible)."
        # Tri stable par step_id pour rendre le message deterministe
        # (utile pour idempotency / dedup notifications).
        sorted_failures = sorted(failed_step_executions, key=lambda s: s.step_id or 0)
        head = sorted_failures[:3]
        more = len(sorted_failures) - len(head)
        parts = []
        for s in head:
            name = (s.step_name or f"etape {s.step_id}").strip()
            err = (s.error_message or "erreur inconnue").strip()
            # Tronquer chaque cause individuelle : un timeout SQL Server
            # qui ramene 500 chars de "ODBC ... " spam ferait deborder
            # l'email subject + le badge UI. 120 chars suffisent pour
            # une cause humainement lisible.
            if len(err) > 120:
                err = err[:117] + "..."
            parts.append(f"« {name} » : {err}")
        msg = " | ".join(parts)
        if more > 0:
            msg += f" (+{more} autre{'s' if more > 1 else ''})"
        return msg

    async def _load_runtime_user(self, user_id: int) -> Any:
        """Charge un User pour usage dans un step DAG (Iris one-shot,
        report IA). Verifie ``is_active`` et eager-load ``company`` :
            - is_active : un user desactive ne doit pas continuer a
              executer ses automations (surtout si pgmise par admin).
            - company : eager-load explicite parce que les call-sites
              consomment ``user.company.name`` apres fermeture de la
              session SQLAlchemy ; sans eager-load = MissingGreenlet.
        Retourne l'objet apres expunge pour qu'il soit utilisable hors
        session sans declencher de lazy-load surprise.
        """
        from app.models.user import User
        from sqlalchemy import select

        async with get_session_factory()() as session:
            # Cycle 9 fix régression S1 : User n'a pas de relation `company`
            # (vérifié — les relations sont sessions/search_history/saved_queries/
            # automations/storage/conversations/preferences/anonymization_terms/
            # data_access_rules). Le commentaire historique mentionnant
            # ``user.company.name`` est obsolète. Le PDF generator lit le
            # nom de société via un autre chemin (cf. report_builder).
            result = await session.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            if user is None:
                raise ValueError(f"Utilisateur {user_id} introuvable")
            if not getattr(user, "is_active", True):
                raise ValueError(
                    f"Utilisateur {user_id} desactive — " "automation refusee (fail-closed)"
                )
            # Detache pour eviter lazy-load apres fermeture de session.
            session.expunge(user)
            return user

    @staticmethod
    def _tabs_to_datasets(tabs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convertit les onglets d'un workbook DAG vers le format
        attendu par ``plan_report`` : un dataset par onglet, avec id
        sequentiel (la planificateur en a besoin pour referencer ses
        sections par dataset_id)."""
        datasets: List[Dict[str, Any]] = []
        for idx, tab in enumerate(tabs):
            rows = list(tab.get("rows") or [])
            columns = list(tab.get("columns") or [])
            label = tab.get("label") or f"Onglet {idx + 1}"
            datasets.append(
                {
                    "id": idx,
                    "label": label,
                    "columns": columns,
                    "rows": rows,
                    "row_count": len(rows),
                }
            )
        return datasets

    def _safe_output_path(self, filename: str) -> Path:
        """Construit un Path sous ``self.output_dir`` apres verification
        anti path-traversal et anti symlink. Levee ``ValueError`` si la
        cible sort de ``output_dir`` ou si c'est un lien symbolique."""
        output_path = self.output_dir / filename
        if output_path.is_symlink():
            raise ValueError("Chemin de sortie invalide: lien symbolique interdit")
        try:
            output_path.resolve().relative_to(self.output_dir.resolve())
        except ValueError:
            raise ValueError("Chemin de sortie invalide: hors repertoire autorise")
        # A7-F9 — réservation atomique anti-collision (perte de données
        # silencieuse). Un simple exists()-check serait TOCTOU (l'export CSV
        # écrit via `await asyncio.to_thread` APRÈS un yield, et les nodes d'un
        # même niveau DAG tournent en parallèle). On délègue au SSoT
        # `reserve_unique_output_path` (création exclusive O_EXCL, partagé avec
        # les fallbacks CSV de report_generator).
        from app.services.automation.workbook_export import reserve_unique_output_path

        return reserve_unique_output_path(output_path)

    # D3 phase 3 cycle 21 : extraction vers workbook_loader.py.
    # Wrappers conservés pour compat tests qui patchent ces methods.
    MAX_LOAD_WORKBOOK_BYTES = 50 * 1024 * 1024  # alias pour compat

    async def _load_workbook_from_datastore(
        self,
        user_id: int,
        relative_path: str,
        step_name: str,
    ) -> Dict[str, Any]:
        """Délègue à :func:`workbook_loader.load_workbook_from_datastore`."""
        from app.services.automation.workbook_loader import load_workbook_from_datastore

        return await load_workbook_from_datastore(user_id, relative_path, step_name)

    @staticmethod
    def _parse_tabs_selector(raw: Any, all_tabs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Délègue à :func:`workbook_loader.parse_tabs_selector`."""
        from app.services.automation.workbook_loader import parse_tabs_selector

        return parse_tabs_selector(raw, all_tabs)

    async def _generate_workbook_export(
        self,
        automation: Automation,
        execution_id: int,
        tabs: List[Dict[str, Any]],
        output_format: str,
        filename_hint: Optional[str],
        anonymize: bool = False,
    ) -> Path:
        """Convertit des onglets de classeur en fichier Excel ou CSV.

        Branche sur les composants existants :
        - excel → ``build_iris_xlsx`` (le meme que le bouton Export Excel
          des classeurs cote frontend) : re-execute les SQL tabs avec RLS,
          construit un .xlsx multi-feuilles, hyperlinks cellDetails, etc.
        - csv → matérialisation puis csv.writer sur la PREMIERE feuille
          du classeur fusionne (cf. contrat user : « si le classeur fusionne
          a plusieurs feuilles on prend la premiere »).

        Le path est valide via ``_safe_output_path`` (anti-traversal + symlink).
        """
        from app.services.automation.workbook_export import sanitize_filename_hint

        if not tabs:
            raise ValueError(f"Automation {automation.id}: aucun onglet a exporter")

        timestamp = clock.now().strftime("%Y%m%d_%H%M%S")
        base = sanitize_filename_hint(
            filename_hint, default=f"auto_{automation.id}_exec_{execution_id}"
        )
        # Suffixe `_anonymise` pour distinguer un export anonymisé d'un clair.
        suffix = "_anonymise" if anonymize else ""
        stem = f"{base}_{timestamp}{suffix}"

        fmt = (output_format or "excel").lower()

        # Charge le runtime user pour la RLS de la re-execution SQL.
        user = await self._load_runtime_user(automation.user_id)

        if fmt == "excel":
            from app.services.export.iris_xlsx_builder import build_iris_xlsx

            payload = {"tabs": tabs}
            # `anonymize` appliqué côté builder (après matérialisation SQL),
            # fail-closed : un terme /data/privacy non applicable fait échouer
            # le step plutôt que de produire un fichier où la vraie valeur
            # fuiterait — comportement voulu pour un envoi automatisé.
            result = await build_iris_xlsx(payload, user, anonymize=anonymize)
            output_path = self._safe_output_path(f"{stem}.xlsx")
            output_path.write_bytes(result["content"])
            return output_path

        if fmt == "csv":
            from app.services.export.iris_xlsx_builder import (
                materialize_workbook_sql_tabs,
            )
            from app.services.automation.workbook_service import tab_to_dict_rows

            materialization = await materialize_workbook_sql_tabs(
                tabs,
                user,
                rls_source="automation_export_csv",
                logger_prefix=f"automation_export_csv[auto={automation.id}]",
            )
            hydrated_tabs = materialization["tabs"]
            if not hydrated_tabs:
                raise ValueError(f"Automation {automation.id}: aucun onglet apres materialisation")
            # Anonymisation après matérialisation SQL (sur données fraîches),
            # avant l'écriture CSV. Fail-closed (RuntimeError propagé → step échoue).
            if anonymize:
                from app.services.anonymization.export_filter import (
                    anonymize_tabs_for_export,
                )

                hydrated_tabs = await anonymize_tabs_for_export(
                    getattr(user, "id", None), hydrated_tabs
                )
            first_tab = hydrated_tabs[0]
            output_path = self._safe_output_path(f"{stem}.csv")

            def _write_csv_first_tab() -> None:
                from app.services.export.csv_export import to_csv_bytes

                dict_rows = tab_to_dict_rows(first_tab)
                columns = list(first_tab.get("columns") or [])
                if not columns and dict_rows:
                    columns = list(dict_rows[0].keys())
                # SSoT `to_csv_bytes` : BOM UTF-8 + sanitisation anti-injection
                # formule (CWE-1236) sur en-têtes ET cellules. Ce CSV part vers
                # des destinataires EXTERNES par email ; un pseudonyme /data-privacy
                # ou une valeur Sage `=cmd|...` ne doit jamais devenir une formule
                # exécutable à l'ouverture Excel (review adversariale 2026-06-01).
                output_path.write_bytes(to_csv_bytes(dict_rows, columns))

            await asyncio.to_thread(_write_csv_first_tab)
            return output_path

        raise ValueError(f"Format d'export invalide '{output_format}' (attendu : excel, csv)")

    async def _generate_llm_report(
        self,
        automation: Automation,
        execution_id: int,
        tabs: List[Dict[str, Any]],
        user_prompt: Optional[str],
        user_title_hint: Optional[str],
    ) -> Path:
        """Genere un rapport PDF analytique via l'IA des rapports.

        Cable sur la meme chaine que ``POST /api/reports/generate-llm``
        (cf. ``ReportGenerateLLMHandler``) :
            1. ``plan_report`` planifie le rapport (LLM + anonymisation
               niveau 2 bidirectionnelle, restauree dans le plan retourne).
            2. ``build_pdf_from_plan`` execute le plan et genere le PDF
               multi-sections avec graphiques.

        Le PDF est ecrit dans ``self.output_dir`` (au meme endroit que
        l'export plat) pour que le step ``email`` aval puisse l'attacher
        sans logique conditionnelle supplementaire.
        """
        # Imports locaux : llm_report_planner depend de app.services.ai.*
        # qui peut elever des cycles si hoiste au top-level.
        from app.services.reporting.llm_report_executor import build_pdf_from_plan
        from app.services.reporting.llm_report_planner import (
            ReportPlanError,
            plan_report,
        )

        if not tabs:
            raise ValueError(
                f"Automation {automation.id}: aucun onglet a analyser pour le rapport IA"
            )

        # Charger le User (le PDF generator lit user.company.name pour
        # le pied de page entreprise — eager-loaded par _load_runtime_user).
        user = await self._load_runtime_user(automation.user_id)

        # Materialise les SQL tabs (un classeur peut contenir des onglets
        # SQL non hydrates — emis par format_copilot via emit_tab(sql=...)
        # ou charges via load_workbook depuis un .afz.json sauvegarde).
        # Sans ca le rapport tournerait sur des rows vides → analyse sur
        # vide silencieuse (cf. incident exec #8 du 2026-05-09).
        from app.services.export.iris_xlsx_builder import (
            materialize_workbook_sql_tabs,
        )

        materialization = await materialize_workbook_sql_tabs(
            tabs,
            user,
            rls_source="automation_report_pdf",
            logger_prefix=f"automation_report[auto={automation.id}]",
        )
        hydrated_tabs = materialization["tabs"]
        # materialize_workbook_sql_tabs retourne rows en array-of-arrays
        # (isArrayFormat=True). plan_report / build_pdf_from_plan attendent
        # rows en List[Dict]. Conversion via tab_to_dict_rows (single source
        # de vérité côté workbook_service).
        from app.services.automation.workbook_service import tab_to_dict_rows

        for tab in hydrated_tabs:
            tab["rows"] = tab_to_dict_rows(tab)
            tab["isArrayFormat"] = False
        datasets = self._tabs_to_datasets(hydrated_tabs)

        # Phase 1 — Planification IA
        try:
            plan = await plan_report(
                datasets,
                user_prompt=user_prompt,
                user_title_hint=user_title_hint,
                user_id=automation.user_id,
            )
        except ReportPlanError as exc:
            raise ValueError(f"Echec planification rapport IA : {exc}") from exc

        # Phase 2 — Execution du plan -> bytes PDF.
        # build_pdf_from_plan est CPU-bound (PDF generation), to_thread
        # pour ne pas bloquer la boucle asyncio.
        datasets_by_id = {ds["id"]: ds for ds in datasets}
        pdf_bytes = await asyncio.to_thread(build_pdf_from_plan, plan, datasets_by_id, user)

        timestamp = clock.now().strftime("%Y%m%d_%H%M%S")
        filename = f"auto_{automation.id}_exec_{execution_id}_{timestamp}.pdf"
        output_path = self._safe_output_path(filename)

        output_path.write_bytes(pdf_bytes)
        return output_path

    async def _generate_report_from_context(
        self,
        automation: Automation,
        execution_id: int,
        results: List[Dict[str, Any]],
        output_format: str,
        title: str,
    ) -> Path:
        """Genere un rapport a partir du contexte workflow."""
        timestamp = clock.now().strftime("%Y%m%d_%H%M%S")
        ext = output_format if output_format != "excel" else "xlsx"
        filename = f"auto_{automation.id}_exec_{execution_id}_{timestamp}.{ext}"
        output_path = self._safe_output_path(filename)

        if output_format == "csv":
            self._generate_csv(output_path, results)
        elif output_format == "excel":
            self._generate_excel(output_path, results)
        elif output_format == "pdf":
            pdf_obj = type("A", (), {"name": title, "description": ""})()
            self._generate_pdf(output_path, pdf_obj, results)
            csv_fallback = output_path.with_suffix(".csv")
            if csv_fallback.exists() and not output_path.exists():
                output_path = csv_fallback
        else:
            self._generate_csv(output_path, results)

        return output_path

    async def _send_workflow_email(
        self,
        session: AsyncSession,
        automation: Automation,
        execution_id: int,
        recipients: List[str],
        subject: str,
        file_path: Path,
        context: Any,
    ) -> None:
        """Délègue à :func:`email_dispatcher.send_workflow_step_email`.

        Wrapper conservé pour compat tests qui patchent
        ``executor._send_workflow_email``. La logique réelle est dans
        :mod:`app.services.automation.email_dispatcher` (D3 phase 2).

        Cluster-R 2026-05-26 — Résout ``owner_is_active`` via lookup
        ``User.is_active`` AVANT de déléguer (mirror exact de
        ``_send_email`` legacy pour garantir le contrat S7 : compte
        désactivé = pas de leak applicatif). Fail-closed : exception
        lookup ou user orphelin → owner_active=False.
        """
        from app.services.automation.email_dispatcher import send_workflow_step_email

        smtp_config = await self._load_smtp_config(session)

        # Cluster-R (S7) — Pré-résolution owner_is_active. Avant ce fix,
        # le DAG step email envoyait même pour comptes désactivés
        # (fail-OPEN, leak compliance / bypass RGPD soft-delete).
        owner_active = False
        try:
            from app.models.user import User

            user = await session.get(User, automation.user_id)
            if user is not None:
                owner_active = bool(getattr(user, "is_active", False))
        except Exception:  # noqa: BLE001 — best-effort, log puis fail-closed
            logger.warning(
                "Erreur lookup owner pour DAG step email automation %d (user %s)",
                automation.id,
                automation.user_id,
                exc_info=True,
            )

        await send_workflow_step_email(
            smtp_config=smtp_config,
            automation_id=automation.id,
            recipients=recipients,
            subject=subject,
            file_path=file_path,
            rows_count=len(context.rows),
            warnings=context.warnings,
            owner_is_active=owner_active,
            automation_user_id=automation.user_id,
            execution_id=execution_id,
        )

    async def _load_automation(
        self, session: AsyncSession, automation_id: int
    ) -> Optional[Automation]:
        """Charge une automatisation avec ses etapes ET ses aretes DAG eager-loadees.

        L'eager-load des edges est critique : le router execute_automation
        inspecte `automation.edges` pour choisir DAG vs lineaire. Un lazy-load
        a ce moment-la provoque MissingGreenlet hors session async.
        """
        result = await session.execute(
            select(Automation)
            .options(
                selectinload(Automation.steps),
                selectinload(Automation.edges),
            )
            .where(Automation.id == automation_id)
        )
        return result.scalar_one_or_none()

    async def _get_sql_query(
        self, session: AsyncSession, automation: Automation, execution_id: int
    ) -> str:
        """
        Génère ou récupère la requête SQL

        Args:
            session: Session DB
            automation: Automatisation
            execution_id: ID exécution (pour logs)

        Returns:
            Requête SQL à exécuter
        """
        if automation.query_type == "sql":
            # SQL direct
            logger.info(
                "SQL direct pour execution #%d (automation=%d)",
                execution_id,
                automation.id,
            )
            return automation.query_text

        else:
            raise ValueError(
                f"Type de requête invalide: {automation.query_type}. "
                "Seul 'sql' est supporté — pour générer du SQL depuis du NL, "
                "utilise la page /iris puis le bouton 'Enregistrer' pour "
                "obtenir un .sql à rejouer via load_saved_query."
            )

    async def _execute_query(
        self, session: AsyncSession, sql_query: str, execution_id: int
    ) -> List[Dict[str, Any]]:
        """
        Exécute la requête SQL sur la base Sage

        Args:
            session: Session DB
            sql_query: Requête SQL
            execution_id: ID exécution (pour logs)

        Returns:
            Liste de résultats
        """
        logger.info("Execution SQL pour execution #%d", execution_id)

        # S1 — Propage runtime_user / rls_source au QueryExecutor pour
        # appliquer les RLS (Row-Level Security) du proprietaire de
        # l'automation, IDENTIQUES a celles du preview (preview_service.py
        # appliquait deja, le runtime ne le faisait pas — fuite cross-user
        # via auto planifiees). Lu via ContextVar (set au debut d'
        # execute_automation, isole par tache asyncio — pas race entre runs
        # concurrent).
        runtime_user = _current_runtime_user_var.get()
        rls_kwargs: Dict[str, Any] = {}
        if runtime_user is not None:
            rls_kwargs = {"user": runtime_user, "rls_source": "automation_run"}
        else:
            logger.warning(
                "_execute_query sans runtime_user (execution=%d) — RLS BYPASSEE."
                " Devrait etre charge par execute_automation(). Path legacy ?",
                execution_id,
            )
        # Cluster-K (K2) 2026-05-26 — Pas de cap depuis cette couche
        # (anti double-cap silencieux). ``QueryExecutor.execute`` accepte
        # ``max_rows=None`` (Optional[int]) qui signifie "no cap from
        # this layer". Le connector applique seul son plafond admin
        # (``db_conn.max_rows`` via /admin/database, SSoT).
        query_result = await self.query_executor.execute(sql_query, max_rows=None, **rls_kwargs)

        # Convertir QueryResult en liste de dicts
        results = []
        if query_result.rows:
            columns = query_result.columns
            for row in query_result.rows:
                row_dict = dict(zip(columns, row))
                results.append(row_dict)

        logger.info("%d lignes retournees pour execution #%d", len(results), execution_id)

        return results

    async def _generate_report(
        self, automation: Automation, execution_id: int, results: List[Dict[str, Any]]
    ) -> Path:
        """
        Génère le rapport dans le format demandé

        Args:
            automation: Automatisation
            execution_id: ID exécution
            results: Résultats de la requête

        Returns:
            Chemin du fichier généré
        """
        output_format = automation.output_format or "csv"

        # Nom de fichier basé sur timestamp (IDs sont des ints, pas de risque d'injection)
        timestamp = clock.now().strftime("%Y%m%d_%H%M%S")
        filename = f"auto_{automation.id}_exec_{execution_id}_{timestamp}.{output_format}"
        # A7-F9 — passe par le choke-point unique `_safe_output_path` (anti
        # path-traversal/symlink + réservation atomique anti-collision) au lieu
        # de réinliner les checks ici. Couvre la collision entre 2 exécutions de
        # la même auto à la même seconde (re-trigger manuel + scheduled).
        output_path = self._safe_output_path(filename)

        logger.info(
            "Generation rapport %s pour execution #%d",
            output_format.upper(),
            execution_id,
        )

        if output_format == "csv":
            self._generate_csv(output_path, results)

        elif output_format == "excel":
            self._generate_excel(output_path, results)

        elif output_format == "pdf":
            self._generate_pdf(output_path, automation, results)
            # Check if fallback to CSV occurred (suffix changed by _generate_pdf)
            csv_fallback = output_path.with_suffix(".csv")
            if csv_fallback.exists() and not output_path.exists():
                output_path = csv_fallback

        else:
            raise ValueError(f"Format de sortie non supporté: {output_format}")

        logger.info("Rapport genere: %s", output_path)
        return output_path

    def _generate_csv(self, output_path: Path, results: List[Dict[str, Any]]):
        """Délègue à :func:`report_generator.generate_csv`."""
        from app.services.automation.report_generator import generate_csv

        generate_csv(output_path, results)

    def _generate_excel(self, output_path: Path, results: List[Dict[str, Any]]):
        """Délègue à :func:`report_generator.generate_excel`."""
        from app.services.automation.report_generator import generate_excel

        generate_excel(output_path, results)

    def _generate_pdf(self, output_path: Path, automation, results: List[Dict[str, Any]]):
        """Délègue à :func:`report_generator.generate_pdf`."""
        from app.services.automation.report_generator import generate_pdf

        generate_pdf(output_path, automation, results)

    async def _load_smtp_config(self, session: AsyncSession) -> Optional[Dict[str, Any]]:
        """Charge la configuration SMTP depuis la BDD ou .env.

        Cycle 17 #12 : passe désormais par le helper unifié
        ``load_smtp_config_dict()`` (single source) au lieu de dupliquer
        la logique avec 3 autres sites. Garde cette wrapper-method pour
        rétro-compat avec les tests qui mockent `_load_smtp_config`.
        """
        from app.services.email.smtp_factory import load_smtp_config_dict

        return await load_smtp_config_dict(session=session)

    async def _send_email(
        self,
        session: AsyncSession,
        automation: Automation,
        execution: Execution,
        output_file: Path,
    ) -> None:
        """Délègue à :func:`email_dispatcher.send_legacy_pipeline_email`.

        Wrapper conservé pour compat tests qui patchent
        ``executor._send_email``. La logique réelle est dans
        :mod:`app.services.automation.email_dispatcher` (D3 phase 2).

        Résout ``owner_is_active`` via lookup ``User.is_active`` AVANT de
        déléguer (mirror exact de ``_send_execution_notification`` pour
        garantir le contrat S7 : compte désactivé = pas de leak applicatif).
        Fail-closed : exception lookup ou user orphelin → owner_active=False.
        """
        from app.services.automation.email_dispatcher import send_legacy_pipeline_email

        smtp_config = await self._load_smtp_config(session)

        # Pré-résolution owner_is_active (S7 anti-leak compte désactivé).
        # Fail-closed : par défaut False, ne devient True que si le lookup
        # réussit ET retourne un user actif. Couvre orphan user_id (user
        # supprimé hard) et exceptions DB.
        owner_active = False
        try:
            from app.models.user import User

            user = await session.get(User, automation.user_id)
            if user is not None:
                owner_active = bool(getattr(user, "is_active", False))
        except Exception:  # noqa: BLE001 — best-effort, log puis fail-closed
            logger.warning(
                "Erreur lookup owner pour rapport legacy automation %d (user %s)",
                automation.id,
                automation.user_id,
                exc_info=True,
            )

        await send_legacy_pipeline_email(
            smtp_config=smtp_config,
            automation_id=automation.id,
            automation_name=automation.name,
            automation_description=automation.description,
            automation_recipients=automation.recipients,
            output_format=automation.output_format,
            execution_finished_at=execution.finished_at,
            execution_duration_seconds=execution.duration_seconds,
            execution_result_rows=execution.result_rows,
            output_file=output_file,
            owner_is_active=owner_active,
            automation_user_id=automation.user_id,
            execution_id=execution.id,
        )

    async def _send_execution_notification(
        self,
        session: AsyncSession,
        automation: Automation,
        execution: Execution,
        success: bool,
        error_message: Optional[str] = None,
    ) -> None:
        """Délègue à :func:`email_dispatcher.send_execution_notification`.

        Le wrapper résout le fallback owner email + flag actif via la
        session SQLAlchemy avant de déléguer (le helper n'a pas de
        connexion DB pour rester pur).
        """
        from app.services.automation.email_dispatcher import send_execution_notification

        smtp_config = await self._load_smtp_config(session)

        # Pré-résolution du fallback owner (S7 anti-leak compte désactivé)
        fallback_email: Optional[str] = None
        owner_active = False
        try:
            from app.models.user import User

            user = await session.get(User, automation.user_id)
            if user is not None:
                fallback_email = getattr(user, "email", None)
                # Fail-closed : si is_active absent, on considère False
                owner_active = bool(getattr(user, "is_active", False))
        except Exception:  # noqa: BLE001 — best-effort, log puis no-op
            logger.warning(
                "Erreur lookup owner pour notification automation %d",
                automation.id,
                exc_info=True,
            )

        await send_execution_notification(
            smtp_config=smtp_config,
            automation_id=automation.id,
            automation_name=automation.name,
            automation_user_id=automation.user_id,
            notification_emails=automation.notification_emails,
            success=success,
            execution_started_at=execution.started_at,
            execution_duration_seconds=execution.duration_seconds,
            execution_result_rows=execution.result_rows,
            error_message=error_message,
            fallback_owner_email=fallback_email,
            owner_is_active=owner_active,
            # P5.3 — propage ``execution_id`` au dispatcher pour qu'il inclue
            # un lien actionnable « Voir le détail complet » dans l'email.
            execution_id=execution.id,
        )


# Instance globale singleton
_executor: Optional["AutomationExecutor"] = None
# B3 — threading.Lock (PAS asyncio.Lock — APScheduler ThreadPool 5 threads
# concurrent au reboot froid : 5× check_then_create racy → 5 instances
# QueryExecutor distinctes + mkdir() racy sur le FS). Thread-safe init via
# double-check locking.
_executor_init_lock = threading.Lock()

# S1 — runtime_user par-task asyncio. Le singleton AutomationExecutor est
# partage entre N runs concurrent (asyncio.gather des nodes DAG, 4 workers
# scheduler thread, etc.). Stocker runtime_user en attribut d'instance =
# race garantie. ContextVar est la solution canonique : isole par tache
# asyncio (et par thread via asgiref-style). Lu par _execute_query, set
# au debut d'execute_automation.
_current_runtime_user_var: contextvars.ContextVar[Optional[Any]] = contextvars.ContextVar(
    "automation_runtime_user", default=None
)


def get_executor() -> AutomationExecutor:
    """Récupère l'instance singleton de l'exécuteur (thread-safe init)."""
    global _executor
    if _executor is None:
        with _executor_init_lock:
            # Double-check : un autre thread a pu init pendant qu'on attendait
            # le lock. Évite de re-construire (et de re-mkdir).
            if _executor is None:
                _executor = AutomationExecutor()
    return _executor


def resume_automation_job(
    execution_id: int,
    step_id: int,
    wait_token_id: int,
) -> None:
    """Job APScheduler one-shot pour reprendre une execution suspendue.

    Declenche par ``WaitResponseHandler.post`` apres qu'un destinataire
    a soumis sa reponse. Tourne dans un thread worker APScheduler (sync) →
    on bridge vers asyncio via ``asyncio.run``.

    Pipeline complet :
    1. Charge wait_row + execution + checkpoint depuis BDD
    2. Convertit la reponse en workbook (texte → 1-cellule, file → loader)
    3. Marque le step waiting comme `success` en BDD avec ce workbook
       comme output (`step_output` snapshot tronque)
    4. Marque execution `running` (transition waiting → running)
    5. Relance ``run_dag_pipeline`` avec ``resume_state`` qui pre-remplit
       step_outputs + skip les steps deja executes
    6. Le DAG continue avec les niveaux Kahn aval (steps qui depend du
       step waiting recoivent maintenant son output = la reponse)
    7. Calcule status final et persiste
    """
    import asyncio as _asyncio

    from app.services.email.smtp_client import run_then_drain_email_log

    async def _async_resume() -> None:
        await _resume_automation_async(execution_id, step_id, wait_token_id)

    try:
        _asyncio.run(run_then_drain_email_log(_async_resume()))
    except Exception:  # noqa: BLE001
        logger.exception(
            "resume_automation_job: crash asyncio.run pour exec #%d",
            execution_id,
        )


async def _resume_automation_async(
    execution_id: int,
    step_id: int,
    wait_token_id: int,
) -> None:
    """Implementation async de la reprise (cf. ``resume_automation_job``)."""
    from app.core.database import get_session_factory
    from app.models.automation import Automation
    from app.models.execution import Execution
    from app.models.step_execution import StepExecution
    from app.models.wait_token import WaitToken
    from app.services.automation.dag_executor import run_dag_pipeline
    from app.services.automation.dag_validator import TERMINAL_NODE_TYPES
    from app.services.automation.wait_resume import (
        convert_response_to_workbook,
        deserialize_wait_checkpoint,
    )
    from app.services.automation.workbook_service import workbook_snapshot_for_db
    from sqlalchemy.orm import selectinload
    from sqlalchemy import select as _select, update as _update

    sf = get_session_factory()
    # Pré-checks lecture seule AVANT le claim (M2 adversarial). Si
    # wait_token est introuvable / non-résolu, on return SANS toucher
    # Execution.status — sinon le claim transitionnerait waiting→running
    # et l'execution resterait figée en running orphan (pas de pipeline
    # en route, pas de mark_failed), alors que pre-fix elle restait
    # waiting → récupérable par un retry admin.
    async with sf() as pre_sess:
        pre_wait = await pre_sess.get(WaitToken, wait_token_id)
        pre_exec = await pre_sess.get(Execution, execution_id)
        if pre_wait is None or pre_exec is None:
            logger.warning(
                "resume: token #%d ou exec #%d introuvable",
                wait_token_id,
                execution_id,
            )
            return
        if pre_wait.status != "resolved":
            logger.warning(
                "resume: token #%d statut=%s (attendu resolved) — abort",
                wait_token_id,
                pre_wait.status,
            )
            return

    # Claim atomique : un seul caller transitionne Execution waiting→running.
    # Sans ce guard, deux jobs APScheduler concurrents (multi-worker, restart
    # avec misfire_grace_time, replace_existing partiel) peuvent tous les
    # deux passer le check status='waiting' plus bas puis double-exécuter
    # le pipeline (double envoi de mails, double pipeline LLM/SQL).
    async with sf() as claim_sess:
        claim_result = await claim_sess.execute(
            _update(Execution)
            .where(Execution.id == execution_id, Execution.status == "waiting")
            .values(status="running")
        )
        await claim_sess.commit()
        if claim_result.rowcount == 0:
            logger.warning(
                "resume: exec #%d already claimed or not waiting — abort idempotent",
                execution_id,
            )
            return

    async with sf() as sess:
        wait_row = await sess.get(WaitToken, wait_token_id)
        exec_row = await sess.get(Execution, execution_id)
        if wait_row is None or exec_row is None:
            logger.warning(
                "resume: token #%d ou exec #%d disparu post-claim",
                wait_token_id,
                execution_id,
            )
            return
        if wait_row.status != "resolved":
            logger.warning(
                "resume: token #%d statut=%s (attendu resolved) — abort post-claim",
                wait_token_id,
                wait_row.status,
            )
            return

        # Cluster-V 2026-05-26 — Defense en profondeur : check expires_at
        # même pour les tokens "resolved". Cas tordu : un POST passe le
        # CAS atomic (status=pending + expires_at > now), commit. Puis le
        # job APScheduler de resume est en queue pendant 30+ minutes
        # (backlog scheduler). Au moment du resume effectif, `now` est
        # > `expires_at` → la session du wait est sémantiquement expirée
        # (le destinataire ne pouvait plus répondre légitimement).
        # On marque l'execution failed avec un message clair plutôt que
        # de relancer le DAG avec une réponse stale.
        if wait_row.expires_at is not None:
            from app.models.base import ensure_utc as _ensure_utc_v

            expires_utc = _ensure_utc_v(wait_row.expires_at)
            now_utc = clock.now()
            if expires_utc < now_utc:
                logger.warning(
                    "resume: token #%d expired (expires_at=%s, now=%s) — " "mark exec failed",
                    wait_token_id,
                    expires_utc.isoformat(),
                    now_utc.isoformat(),
                )
                exec_row.mark_failed(
                    f"Token de reponse expire au moment du resume "
                    f"(expires_at={expires_utc.isoformat()}). "
                    f"La reponse est arrivee trop tard pour etre prise en compte."
                )
                await sess.commit()
                return

        if exec_row.status != "waiting" and exec_row.status != "running":
            logger.warning(
                "resume: exec #%d statut=%s (attendu waiting|running) — abort",
                execution_id,
                exec_row.status,
            )
            return

        checkpoint_raw = exec_row.wait_checkpoint
        if not isinstance(checkpoint_raw, dict):
            logger.error(
                "resume: exec #%d sans wait_checkpoint valide",
                execution_id,
            )
            exec_row.mark_failed(
                "Checkpoint absent — reprise impossible. Re-jouer l'auto manuellement.",
            )
            await sess.commit()
            return

        try:
            checkpoint = deserialize_wait_checkpoint(checkpoint_raw)
        except Exception:  # noqa: BLE001
            logger.exception("resume: checkpoint invalide pour exec #%d", execution_id)
            exec_row.mark_failed("Checkpoint corrompu — reprise impossible.")
            await sess.commit()
            return

        # Charge l'automation eager-loaded pour le DAG
        auto_q = await sess.execute(
            _select(Automation)
            .options(
                selectinload(Automation.steps),
                selectinload(Automation.edges),
            )
            .where(Automation.id == exec_row.automation_id)
        )
        automation = auto_q.scalar_one_or_none()
        if automation is None:
            logger.error("resume: automation #%d introuvable", exec_row.automation_id)
            exec_row.mark_failed("Automation introuvable au resume.")
            await sess.commit()
            return

        # Convertir la reponse en workbook
        step_obj = next((s for s in automation.steps if s.id == step_id), None)
        step_label = (step_obj.name if step_obj else None) or "Reponse destinataire"
        response_wb = await convert_response_to_workbook(wait_row, step_label)

        # Mettre a jour le step_execution waiting → success en BDD avec
        # l'output de la reponse. On cherche la row la plus recente du
        # step (defense vs cas re-runs apres un wait precedent).
        sx_q = await sess.execute(
            _select(StepExecution)
            .where(
                StepExecution.execution_id == execution_id,
                StepExecution.step_id == step_id,
                StepExecution.status == "waiting",
            )
            .order_by(StepExecution.id.desc())
            .limit(1)
        )
        step_exec = sx_q.scalars().first()
        if step_exec is not None:
            step_exec.mark_success(
                rows_in=0,
                rows_out=sum(len(t.get("rows") or []) for t in (response_wb.get("tabs") or [])),
                duration_ms=0.0,
            )
            step_exec.step_output = workbook_snapshot_for_db(response_wb)
        else:
            logger.warning(
                "resume: step_execution waiting introuvable (exec=%d, step=%d)",
                execution_id,
                step_id,
            )

        # Transition execution : waiting → running
        exec_row.status = "running"
        await sess.commit()
        # Re-fetch automation hors session (closed).
        await sess.refresh(automation, ["steps", "edges"])
        list(automation.steps)
        list(automation.edges)
        # Detache pour usage hors session
        sess.expunge_all()

    # Construire le resume_state : tous les step_outputs du checkpoint
    # + le step waiting devient "deja calcule" avec response_wb comme output.
    pre_outputs: Dict[int, Optional[Dict[str, Any]]] = dict(checkpoint["step_outputs"])
    pre_files: Dict[int, Any] = dict(checkpoint["step_output_files"])
    pre_outputs[step_id] = response_wb
    skip_ids: List[int] = list(set(pre_outputs.keys()))

    resume_state = {
        "step_outputs": pre_outputs,
        "step_output_files": pre_files,
        "skip_step_ids": skip_ids,
    }

    # Relance le pipeline avec resume_state. Le DAG va executer uniquement
    # les niveaux Kahn AVAL du step waiting (steps qui dependent de lui
    # ou des autres steps deja faits).
    executor = get_executor()
    async with sf() as sess2:
        # Re-charge l'automation dans la session courante
        auto_q2 = await sess2.execute(
            _select(Automation)
            .options(
                selectinload(Automation.steps),
                selectinload(Automation.edges),
            )
            .where(Automation.id == automation.id)
        )
        automation_live = auto_q2.scalar_one_or_none()
        if automation_live is None:
            logger.error("resume: automation disparue avant pipeline relance")
            return

        # Set le runtime user dans le ContextVar pour les query SQL.
        # A7-C5 — Le resume est TOUJOURS un run DÉCLENCHÉ (réponse d'un
        # destinataire externe relancée via APScheduler, jamais manual). Si
        # l'owner est introuvable/désactivé, on NE relance PAS le pipeline avec
        # RLS bypassée : ce serait la MÊME escalade de privilège que sur le
        # chemin execute_automation (l'auto d'un compte révoqué accéderait à
        # toutes les données source sans RLS). Fail-CLOSED : Execution failed +
        # abort. (Avant : ``except`` → warning → ContextVar au défaut None →
        # bypass silencieux.)
        try:
            runtime_user = await executor._load_runtime_user(automation_live.user_id)
        except Exception as exc:  # noqa: BLE001
            logger.critical(
                "S1 FAIL-CLOSED (resume) — owner %d non chargeable (%s) — "
                "automation %d reprise REFUSÉE (pas de RLS bypass). "
                "Investiguer urgemment.",
                automation_live.user_id,
                exc,
                automation_live.id,
            )
            exec_fail = await sess2.get(Execution, execution_id)
            if exec_fail is not None:
                exec_fail.mark_failed(
                    "Propriétaire de l'automatisation introuvable ou désactivé "
                    "— reprise refusée (fail-closed)."
                )
                await sess2.commit()
            return
        _current_runtime_user_var.set(runtime_user)

        # Cluster-F #4 (2026-05-28) — sérialise le DAG du resume avec le
        # MÊME threading.Lock per-automation_id que ``execute_automation``.
        # Sans ça, un resume (réponse d'un destinataire) + un trigger
        # scheduled/manual concurrents sur la MÊME auto exécutaient 2
        # pipelines en parallèle → doublons emails, 2× coût LLM/SMTP,
        # races. Verrou minimal sur la seule exécution du pipeline : le
        # persist + le calcul de statut aval n'opèrent que sur l'execution
        # courante (pas de conflit avec un autre run).
        _resume_lock = _get_automation_run_lock(automation_live.id)
        await asyncio.to_thread(_resume_lock.acquire)
        try:
            adapter = _build_executor_adapter(executor, sess2, automation_live, execution_id)
            context, records = await run_dag_pipeline(
                sess2,
                automation_live,
                execution_id,
                adapter,
                trigger_data=None,
                resume_state=resume_state,
            )
        except Exception:  # noqa: BLE001
            logger.exception("resume: pipeline relance crash exec #%d", execution_id)
            async with sf() as sess_fail:
                exec_fail = await sess_fail.get(Execution, execution_id)
                if exec_fail is not None:
                    exec_fail.mark_failed(
                        "Reprise pipeline crashee — voir logs serveur.",
                    )
                    await sess_fail.commit()
            return
        finally:
            _resume_lock.release()

        # Persist les records des steps NOUVELLEMENT executes (post-resume)
        try:
            await executor._persist_dag_step_results(execution_id, records)
        except Exception:  # noqa: BLE001
            logger.exception("resume: persist step results echec")

    # Calcul du status final (re-utilise la logique standard via re-fetch
    # des step_executions). On copie la logique courte pour eviter le
    # cycle de calling `execute_automation` (qui creerait une nouvelle
    # Execution row).
    async with sf() as sess3:
        exec_final = await sess3.get(Execution, execution_id)
        if exec_final is None:
            logger.error("resume: exec #%d disparu apres pipeline", execution_id)
            return
        sx_all_q = await sess3.execute(
            _select(StepExecution).where(StepExecution.execution_id == execution_id)
        )
        sx_all = sx_all_q.scalars().all()
        has_failed = any(s.status == "failed" for s in sx_all)
        has_waiting_again = any(s.status == "waiting" for s in sx_all)

        # Si un autre step waiting a ete cree (chaine de waits), on reste
        # en waiting — le user repondra a nouveau.
        if has_waiting_again:
            exec_final.status = "waiting"
            await sess3.commit()
            logger.info("resume: exec #%d a nouveau waiting (chain)", execution_id)
            return

        # Identifier les sinks ayant reussi
        auto_q3 = await sess3.execute(
            _select(Automation)
            .options(selectinload(Automation.steps))
            .where(Automation.id == exec_final.automation_id)
        )
        auto_final = auto_q3.scalar_one_or_none()
        sink_ids: set = set()
        if auto_final is not None:
            sink_ids = {
                s.id
                for s in (auto_final.steps or [])
                if (s.step_type.value if hasattr(s.step_type, "value") else s.step_type)
                in TERMINAL_NODE_TYPES
            }
        any_sink_ok = any(s.status == "success" and s.step_id in sink_ids for s in sx_all)
        rows_total = sum((s.rows_out or 0) for s in sx_all if s.status == "success")

        if has_failed and not any_sink_ok:
            failed_steps = [s for s in sx_all if s.status == "failed"]
            agg = AutomationExecutor._aggregate_step_errors(failed_steps)
            exec_final.mark_failed(error_message=agg)
            label = "failed"
        elif has_failed and any_sink_ok:
            failed_steps = [s for s in sx_all if s.status == "failed"]
            agg = AutomationExecutor._aggregate_step_errors(failed_steps)
            exec_final.mark_partial(error_message=agg, result_rows=rows_total)
            label = "partial"
        else:
            exec_final.mark_success(result_rows=rows_total)
            label = "success"

        # Cleanup checkpoint apres reprise reussie ou definitive (libere
        # ~quelques Ko a quelques Mo selon la taille des workbooks).
        exec_final.wait_checkpoint = None
        await sess3.commit()
        logger.info(
            "resume: exec #%d terminee status=%s (%d lignes)",
            execution_id,
            label,
            rows_total,
        )


# Cluster-F (F1) 2026-05-26 — per-automation lock pour sérialiser les
# triggers concurrents (manual + scheduled tombant dans la même seconde
# créaient sinon 2 Execution rows en parallèle → 2× LLM/SMTP cost, race
# sur ``consecutive_failure_count``, doublonnage emails partiel).
#
# Doctrine single-process (cf. ``scheduler.py:171`` warning multi-process) :
# threading.Lock suffit pour serialize au sein d'un process.
# Multi-instance leader election = follow-up task séparée (CLUSTER-F2,
# nécessite advisory DB lock ou table ``scheduler_lease``).
#
# **Pourquoi threading.Lock et pas asyncio.Lock** : APScheduler utilise un
# ThreadPoolExecutor pour les ticks scheduled (cf. ``loader.py:_run_automation_sync``
# qui fait ``asyncio.run(...)`` dans un worker thread, créant un NOUVEL
# event loop par tick). Un trigger manuel arrive de la loop Tornado
# (loop principale). Donc 2 triggers pour la même auto = potentiellement
# 2 event loops différents. ``asyncio.Lock`` est bound à un seul loop
# (Python 3.10+ raise ``RuntimeError`` si accédé d'un autre loop).
# ``threading.Lock`` traverse les threads/loops sans souci. On l'acquiert
# via ``asyncio.to_thread`` pour ne pas bloquer l'event loop appelant
# pendant l'attente.
#
# Granularité : 1 lock par ``automation_id``. Lookup paresseux protégé
# par un meta-lock pour création thread-safe.
_automation_run_locks: Dict[int, threading.Lock] = {}
_automation_run_locks_meta_lock: threading.Lock = threading.Lock()


def _get_automation_run_lock(automation_id: int) -> threading.Lock:
    """Retourne le lock per-automation (création lazy thread-safe).

    Cluster-F (F1) 2026-05-26 — single source of truth pour la
    sérialisation des triggers concurrents par automation, traverse
    les event loops APScheduler ThreadPool ↔ Tornado main loop.
    """
    # Double-checked locking pour éviter le coût du meta-lock sur la
    # majorité des appels (lock déjà créé).
    lock = _automation_run_locks.get(automation_id)
    if lock is None:
        with _automation_run_locks_meta_lock:
            lock = _automation_run_locks.get(automation_id)
            if lock is None:
                lock = threading.Lock()
                _automation_run_locks[automation_id] = lock
    return lock


def _drop_automation_run_lock(automation_id: int) -> None:
    """Retire le lock per-automation du registre (à la SUPPRESSION d'une auto).

    Cluster-F #7 (2026-05-28) — borne ``_automation_run_locks`` : sans ça le
    dict croît avec le nombre d'automation_id DISTINCTS ayant tourné depuis
    le boot (les locks d'automations supprimées y restaient — axe 21). On ne
    purge QU'À la suppression (pas au toggle-off : une auto désactivée peut
    être réactivée et re-tourner).

    Sûr vis-à-vis d'un run concurrent : l'exécuteur qui détient le lock en
    garde une référence forte locale (il survit tant qu'il est tenu) ;
    retirer l'entrée du dict ne casse pas son exclusion mutuelle, et aucun
    nouveau run ne démarre pour une auto supprimée (unschedule + cascade FK).
    """
    with _automation_run_locks_meta_lock:
        _automation_run_locks.pop(automation_id, None)


async def execute_automation(
    automation_id: int,
    manual: bool = False,
    trigger_data: Optional[Dict[str, Any]] = None,
    trigger_source: Optional[str] = None,
    triggered_by_user_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Fonction d'exécution pour être appelée par le scheduler ou un webhook.

    Args:
        automation_id: ID de l'automatisation à exécuter
        manual: True si exécution manuelle (backward-compat)
        trigger_data: Données de déclenchement (webhook payload, etc.)
        trigger_source: scheduled / webhook / manual / replay (Phase 2b)
        triggered_by_user_id: User.id si manual/replay

    Returns:
        Résultat de l'exécution

    Cluster-F (F1) 2026-05-26 — sérialise les triggers concurrents
    pour la MÊME automation via un ``threading.Lock`` per-automation_id.
    Si un autre trigger (scheduled OU manual OU webhook) est déjà en
    cours pour cette auto, on attend qu'il finisse avant de démarrer.
    Évite : 2× LLM/SMTP cost, doublons emails, race sur compteurs.

    L'acquisition se fait via ``asyncio.to_thread`` pour ne pas bloquer
    la loop appelante pendant l'attente (le lock est sync, mais on le
    convertit en awaitable). Le release est sync rapide, OK en finally.
    """
    executor = get_executor()
    lock = _get_automation_run_lock(automation_id)
    await asyncio.to_thread(lock.acquire)
    try:
        return await executor.execute_automation(
            automation_id,
            manual=manual,
            trigger_data=trigger_data,
            trigger_source=trigger_source,
            triggered_by_user_id=triggered_by_user_id,
        )
    finally:
        lock.release()


# =============================================================================
# Phase 2 DAG : adapter qui execute un node avec les helpers existants
# =============================================================================


def _build_executor_adapter(
    self: "AutomationExecutor",
    session: AsyncSession,
    automation: Automation,
    execution_id: int,
):
    """Fabrique le callable adapter consomme par `dag_executor.run_dag_pipeline`.

    L'adapter traduit chaque node type en appel au helper approprie de
    AutomationExecutor (extract_sql, report, email, etc.). Il
    peuple aussi `context.step_outputs[node.id]` avec le workbook produit
    et `extras["output_file"]` (B7 cycle 3 : plus de mutation de
    `context.variables`).

    B2 cycle 13 — **Session capturee dans la closure** :
    Le param `session` est conserve pour signature compatibilite mais
    n'est PLUS UTILISE pour des ecritures BDD-app concurrentes.
    Apres B1 (cycle 3, _claim_in_dedicated_session) + S1 (cycle 2,
    ContextVar runtime_user) + Q3 (cycle 7, kill PreviewHandler), tous
    les writes BDD-app de l'adapter passent par des sessions courtes
    dediees (`get_session_factory()()`). La session principale n'est plus
    partagee entre nodes paralleles → race condition resolue.

    Retourne (output_workbook, extras_dict).
    """
    from app.services.automation.dag_executor import DAGRunContext
    from app.services.automation.idempotency_service import (
        claim_idempotency_key,
        compute_idempotency_key,
        release_idempotency_key,
    )
    from app.services.automation.workbook_service import rows_to_workbook

    async def _claim_in_dedicated_session(key: str, sink_kind: str) -> bool:
        """B1 — Claim l'idempotency dans une session courte dédiée.

        Avant : claim sur la session principale du run. Si un step aval
        crashait, la transaction principale rollback → la claim disparaît
        → re-run le lendemain re-envoie l'email / re-génère le PDF
        (idempotency cassée). Maintenant : commit immédiat dans une
        session indépendante, persiste meme si le run echoue ensuite.

        Fail-open : si la claim échoue (BDD lock SQLite concurrent, engine
        disposed pendant shutdown), on log un warning et on retourne False
        (pas de doublon detecté → on laisse le sink s'exécuter). Mieux
        qu'un faux échec de step : doublon possible mais rare, vs
        régression "step systématiquement KO si BDD locale chargée".
        """
        try:
            async with get_session_factory()() as claim_session:
                already = await claim_idempotency_key(
                    claim_session, key, sink_kind=sink_kind, step_execution_id=None
                )
                await claim_session.commit()
                return already
        except (SQLAlchemyError, RuntimeError) as e:
            logger.warning(
                "Idempotency claim failed (%s) — fail-open, sink %s execute. "
                "Risque de doublon si la session principale a deja claim.",
                e.__class__.__name__,
                sink_kind,
            )
            return False

    async def _release_in_dedicated_session(key: str) -> None:
        """Libère un claim d'idempotence quand le sink a ÉCHOUÉ.

        Sans ça, le claim posé par ``_claim_in_dedicated_session`` (commit
        dédié, persiste même si le run échoue) bloque tout retry /
        ré-exécution du jour → non-livraison / non-génération SILENCIEUSE
        + warning trompeur « déjà envoyé/généré aujourd'hui ». Compatible
        B1 : on ne libère QUE quand le sink lui-même échoue.

        Best-effort : si la BDD est lockée, on log — au pire le claim
        survit (retour au comportement pré-fix, rare).
        """
        try:
            async with get_session_factory()() as rel_session:
                await release_idempotency_key(rel_session, key)
                await rel_session.commit()
        except (SQLAlchemyError, RuntimeError) as e:
            logger.warning(
                "Idempotency release failed (%s) — le claim survit, "
                "un re-run pourrait skipper le sink.",
                e.__class__.__name__,
            )

    async def adapter(
        node: AutomationStep,
        input_workbook: Optional[Dict[str, Any]],
        context: DAGRunContext,
    ) -> tuple:
        """Execute un node DAG et retourne (output_workbook, extras)."""
        step_cfg = dict(node.config or {})
        step_cfg["_step_name"] = node.name
        step_cfg["_step_order"] = node.step_order
        step_type = node.step_type
        extras: Dict[str, Any] = {"config_snapshot": step_cfg, "warnings": []}

        # --- Sources ---
        if step_type == "extract_sql":
            sql = (step_cfg.get("sql") or "").strip()
            if not sql:
                raise ValueError(f"Etape '{node.name}': requete SQL manquante")
            rows = await asyncio.wait_for(
                self._execute_query(session, sql, execution_id),
                timeout=self.STEP_TIMEOUT_SQL_EXEC,
            )
            tab_label = (step_cfg.get("tab_label") or node.name).strip() or node.name
            output_wb = rows_to_workbook(rows, tab_label=tab_label, sql=sql)
            extras["sql_executed"] = sql
            return output_wb, extras

        if step_type == "load_workbook":
            # Charge un classeur stocke dans /datastore. On accepte 3 formats :
            # - .afz.json : format natif Komptia, multi-onglets, deja prêt.
            # - .xlsx / .xls : converti en workbook 1 onglet via load_excel_sheet.
            # - .csv : converti en workbook 1 onglet via load_csv_file.
            # Securite : `_safe_path` du datastore bloque les path-traversal et
            # isole le user a son propre repertoire (cf. _user_dir).
            output_wb = await self._load_workbook_from_datastore(
                user_id=automation.user_id,
                relative_path=(step_cfg.get("path") or "").strip(),
                step_name=node.name,
            )
            extras["loaded_path"] = step_cfg.get("path") or ""
            return output_wb, extras

        if step_type == "load_saved_query":
            # Rejoue une requete sauvegardee = lit un fichier .sql du
            # datastore (genere par Iris via le bouton "Enregistrer",
            # POST /api/datastore/sql/save). On lit le contenu, on
            # execute le SQL et on retourne le workbook resultat.
            #
            # Securite : ``_safe_path`` du datastore bloque path-traversal
            # et isole le user a son propre repertoire (cf. _user_dir).
            from app.handlers.datastore import _safe_path, _user_dir

            sql_path = (step_cfg.get("sql_path") or "").strip()
            if not sql_path:
                raise ValueError(f"Etape '{node.name}': fichier .sql manquant")
            if not sql_path.lower().endswith(".sql"):
                raise ValueError(f"Etape '{node.name}': fichier doit avoir l'extension .sql")
            user_dir = _user_dir(automation.user_id)
            target = _safe_path(user_dir, sql_path)
            if target is None or not target.exists() or not target.is_file():
                raise ValueError(
                    f"Etape '{node.name}': fichier '{sql_path}' introuvable dans /datastore"
                )
            try:
                sql = await asyncio.to_thread(target.read_text, "utf-8")
            except OSError as exc:
                raise ValueError(f"Etape '{node.name}': impossible de lire '{sql_path}'") from exc
            sql = sql.strip()
            if not sql:
                raise ValueError(f"Etape '{node.name}': fichier '{sql_path}' est vide")
            rows = await asyncio.wait_for(
                self._execute_query(session, sql, execution_id),
                timeout=self.STEP_TIMEOUT_SQL_EXEC,
            )
            tab_label = (
                step_cfg.get("tab_label")
                or sql_path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
                or node.name
            ).strip() or node.name
            output_wb = rows_to_workbook(rows, tab_label=tab_label, sql=sql)
            extras["sql_executed"] = sql
            extras["sql_path"] = sql_path
            return output_wb, extras

        # --- Report : rapport PDF analyse par l'IA (uniquement) ---
        if step_type == "report":
            if input_workbook is None:
                raise ValueError(f"Etape '{node.name}': pas d'input workbook")
            tabs = input_workbook.get("tabs", [])

            from app.services.automation.workbook_service import workbook_stable_hash

            wb_hash = workbook_stable_hash(input_workbook)
            key = compute_idempotency_key(
                sink_kind="report",
                inputs={
                    "workbook_hash": wb_hash,
                    "automation_id": automation.id,
                },
                config=step_cfg,
            )
            already = await _claim_in_dedicated_session(key, sink_kind="report")
            if already:
                extras["warnings"].append("Rapport deja genere aujourd'hui (idempotent skip)")
                # Cluster-E 2026-05-26 — flag explicite pour distinguer
                # idempotent-skip d'un vrai success (UI peut afficher
                # un badge dédié au lieu de "Succès" trompeur).
                extras["idempotent_skipped"] = True
                return input_workbook, extras

            # Mode "analyse IA" exclusif : meme chaine que /api/reports/generate-llm
            # (plan_report → build_pdf_from_plan). Consomme TOUS les onglets
            # (un dataset par onglet) — l'IA peut comparer entre sources fan-in.
            try:
                out_path = await self._generate_llm_report(
                    automation,
                    execution_id,
                    tabs=tabs,
                    user_prompt=(step_cfg.get("prompt") or "").strip() or None,
                    user_title_hint=(step_cfg.get("title") or "").strip() or None,
                )
            except (Exception, asyncio.CancelledError):
                # Cluster-E #5b — rapport NON généré (erreur OU annulation/
                # timeout asyncio.wait_for du run, CancelledError = BaseException) :
                # libère le claim pour permettre un vrai retry (sinon skip
                # silencieux au re-run + warning trompeur « déjà généré »).
                await _release_in_dedicated_session(key)
                raise
            # B7 — fichier propage UNIQUEMENT via step_output_files[node.id]
            # (peuple par dag_executor:363 depuis extras["output_file"]).
            # context.variables["_output_file"] etait last-writer-wins entre
            # 2 reports paralleles → email aval recevait un attachment
            # non-deterministe. Supprime.
            extras["output_file"] = out_path
            return input_workbook, extras

        # --- Export workbook : conversion plate Excel/CSV (sans IA) ---
        if step_type == "export_workbook":
            if input_workbook is None:
                raise ValueError(f"Etape '{node.name}' (export_workbook): pas d'input workbook")
            all_tabs = input_workbook.get("tabs", [])
            tabs_selector = step_cfg.get("tabs", "all")
            try:
                selected_tabs = self._parse_tabs_selector(tabs_selector, all_tabs)
            except ValueError as exc:
                raise ValueError(f"Etape '{node.name}' (export_workbook): {exc}") from exc

            output_format = (step_cfg.get("format") or "excel").lower()
            if output_format not in ("excel", "csv"):
                raise ValueError(
                    f"Etape '{node.name}' (export_workbook): format "
                    f"'{output_format}' invalide (excel | csv)"
                )

            from app.services.automation.workbook_service import workbook_stable_hash

            wb_hash = workbook_stable_hash(input_workbook)
            key = compute_idempotency_key(
                sink_kind="export_workbook",
                inputs={
                    "workbook_hash": wb_hash,
                    "automation_id": automation.id,
                    "output_format": output_format,
                    "tabs_selector": str(tabs_selector),
                },
                config=step_cfg,
            )
            already = await _claim_in_dedicated_session(key, sink_kind="export_workbook")
            if already:
                extras["warnings"].append("Export deja genere aujourd'hui (idempotent skip)")
                extras["idempotent_skipped"] = True  # Cluster-E 2026-05-26
                return input_workbook, extras

            try:
                out_path = await self._generate_workbook_export(
                    automation,
                    execution_id,
                    tabs=selected_tabs,
                    output_format=output_format,
                    filename_hint=(step_cfg.get("filename") or "").strip() or None,
                    anonymize=step_cfg.get("export_anonymized") is True,
                )
            except (Exception, asyncio.CancelledError):
                # Cluster-E #5b — export NON produit (erreur OU annulation/
                # timeout asyncio.wait_for du run, CancelledError = BaseException) :
                # libère le claim pour permettre un vrai retry (sinon skip
                # silencieux au re-run + warning trompeur « déjà généré »).
                await _release_in_dedicated_session(key)
                raise
            # B7 — fichier propage UNIQUEMENT via step_output_files[node.id].
            extras["output_file"] = out_path
            extras["exported_tabs"] = len(selected_tabs)
            return input_workbook, extras

        # --- Email : pas d'output workbook ---
        if step_type == "email":
            from app.services.automation.email_delivery_service import (
                VALID_DELIVERY_STRATEGIES,
                apply_delivery_strategy,
                resolve_recipients,
            )

            to_list = step_cfg.get("to") or step_cfg.get("recipients") or []
            if isinstance(to_list, str):
                to_list = [to_list]
            cc_list = step_cfg.get("cc") or []
            if isinstance(cc_list, str):
                cc_list = [cc_list]
            bcc_list = step_cfg.get("bcc") or []
            if isinstance(bcc_list, str):
                bcc_list = [bcc_list]

            # Resolution DistributionList (ownership check par user_id)
            try:
                resolved = await resolve_recipients(
                    session,
                    to=to_list,
                    cc=cc_list,
                    bcc=bcc_list,
                    from_distribution_list_id=step_cfg.get("from_distribution_list_id"),
                    owner_user_id=automation.user_id,
                )
            except ValueError as e:
                raise ValueError(f"Etape '{node.name}': {e}")

            # Fallback sur automation.recipients UNIQUEMENT si aucune source
            # explicite (to/cc/bcc/from_distribution_list_id tous absents de
            # la config). Sinon, un `to=[]` explicite doit rester vide — ne
            # PAS retomber silencieusement sur les destinataires legacy.
            no_explicit_source = (
                not to_list
                and not cc_list
                and not bcc_list
                and step_cfg.get("from_distribution_list_id") is None
            )
            if no_explicit_source and not any(resolved.values()):
                resolved["to"] = list(automation.recipients or [])

            subject = step_cfg.get("subject") or f"Rapport — {automation.name}"
            body = step_cfg.get("body") or ""

            # S3 — Anti-CRLF sur le SUBJECT uniquement (axe sécu 6, OWASP
            # Email Header Injection). Le subject est un en-tête SMTP : un
            # \r\n smuggle des en-têtes arbitraires (BCc spoof, Reply-To
            # malicieux). is_valid_email couvre les destinataires mais pas
            # le subject. Le body, lui, est passé en MIMEText(body, "html",
            # "utf-8") qui encode quoted-printable côté SMTPClient — les
            # \n y sont LÉGITIMES (HTML multi-ligne). Bloquer body casserait
            # 100% des emails WYSIWYG. Le SMTPClient applique déjà
            # _sanitize_header sur les vrais headers (from/to/cc/bcc).
            from app.utils.validators import assert_no_crlf

            try:
                subject = assert_no_crlf(str(subject), field="subject")
            except ValueError as e:
                raise ValueError(f"Etape '{node.name}': {e}") from e

            # Collecter les fichiers produits par TOUS les ancetres du node
            # email — pas seulement le dernier execute. Resout le scenario
            # "fan-in [rapport_A, rapport_B, export_csv] -> email" qui
            # n'attachait avant que le dernier fichier (variable scalaire
            # ecrasee). Maintenant on remonte le DAG via compute_ancestors
            # et on prend tous les fichiers presents dans step_output_files.
            #
            # Edges `trigger` exclues : un edge trigger signifie « executer
            # apres mais sans transmettre les donnees ». Donc les ancetres
            # reachables uniquement via une chaine d'edges trigger ne
            # contribuent PAS aux pieces jointes. Coherent avec la vision
            # user : « la connexion servirait juste a dire, quand l'etape
            # ou les etapes precedentes ont ete executees l'etape du mail
            # s'execute ». Si au moins UN chemin data existe d'un ancetre
            # vers ce node, l'ancetre reste attache (au moins un chemin
            # transmet ses donnees).
            from app.services.automation.dag_executor import compute_ancestors

            edges_data_only = [
                e for e in (automation.edges or []) if getattr(e, "data_type", None) != "trigger"
            ]
            ancestors = compute_ancestors({node.id}, edges_data_only)
            ordered_ancestor_ids = sorted(ancestors)
            attachments: List[str] = [
                f
                for aid in ordered_ancestor_ids
                if (f := context.step_output_files.get(aid)) is not None
            ]
            # B7 — legacy_file fallback supprime. step_output_files est
            # peuple systematiquement par dag_executor:363 quand un step
            # retourne extras["output_file"]. Le scalaire legacy
            # context.variables["_output_file"] etait race-condition
            # (last-writer-wins entre nodes paralleles) — danger non-determinisme
            # silencieux sur les attachments. Source de verite unique : ancestors.

            # Conversion implicite workbook → xlsx pour les ancetres qui
            # produisent un workbook en memoire (sources, format_copilot)
            # mais pas de fichier sur disque. Permet `Format → Email` direct
            # sans Export intermediaire (UX : tirer l'edge marche).
            #
            # Critere : ancetre dont `step_outputs[aid]` est un workbook
            # avec au moins un onglet ET pas deja une entree dans
            # `step_output_files` (sinon double attachment du meme contenu).
            # La conversion ecrit un .xlsx tmp via `_generate_workbook_export`
            # qui sera nettoye par le job de retention (cf. cleanup/db_retention).
            #
            # On filename-hint avec le step.name de l'ancetre pour que le
            # destinataire comprenne quel maillon a produit la pj. Si le
            # step.name n'est pas resolvable (cas tres rare : node oublie
            # apres un delete partiel), on fallback "etape_{aid}".
            implicit_xlsx_paths: List[str] = []
            steps_by_id = {s.id: s for s in (automation.steps or [])}
            for aid in ordered_ancestor_ids:
                if aid in context.step_output_files:
                    continue  # deja un fichier sur disque
                wb = context.step_outputs.get(aid)
                if not isinstance(wb, dict):
                    continue
                tabs = wb.get("tabs") or []
                if not tabs:
                    continue
                step_obj = steps_by_id.get(aid)
                ancestor_name = (step_obj.name if step_obj else None) or f"etape_{aid}"
                try:
                    xlsx_path = await self._generate_workbook_export(
                        automation,
                        execution_id,
                        tabs=tabs,
                        output_format="excel",
                        filename_hint=ancestor_name,
                        # B3 — la conversion implicite (classeur ancêtre sans step
                        # Export) suit le réglage du step Email. Les fichiers
                        # produits par un step Export gardent LEUR réglage.
                        anonymize=step_cfg.get("export_anonymized") is True,
                    )
                except Exception as exc:
                    logger.warning(
                        "Etape '%s': conversion implicite workbook→xlsx echec "
                        "pour ancetre %s : %s",
                        node.name,
                        ancestor_name,
                        exc,
                        exc_info=True,
                    )
                    extras["warnings"].append(
                        f"Conversion auto en Excel echouee pour « {ancestor_name} » "
                        f"({exc}). L'email partira sans cette piece jointe."
                    )
                    continue
                implicit_xlsx_paths.append(str(xlsx_path))
                logger.info(
                    "Etape '%s': pj implicite generee pour ancetre %s → %s",
                    node.name,
                    ancestor_name,
                    xlsx_path,
                )
            if implicit_xlsx_paths:
                attachments = sorted(attachments + implicit_xlsx_paths)
                extras["implicit_workbook_xlsx_count"] = len(implicit_xlsx_paths)

            strategy = step_cfg.get("delivery_strategy") or "single_email_all_recipients"
            if strategy not in VALID_DELIVERY_STRATEGIES:
                raise ValueError(
                    f"Etape '{node.name}': delivery_strategy '{strategy}' invalide. "
                    f"Valeurs: {list(VALID_DELIVERY_STRATEGIES)}"
                )

            # Idempotency : deterministe sur les vrais destinataires resolus
            # + subject + LISTE complete des attachments (pas seulement le
            # dernier) + strategy. Un email avec 2 PDFs differents = cle
            # differente, donc deux runs distincts.
            # automation_id + user_id obligatoires : sans eux, 2 users avec
            # template commun (meme to/cc/bcc/subject/attachments/strategy)
            # collisionnent et l'un des deux est silencieusement skip
            # (cf. Finding 1779251680-13 / test_executor_email_idempotency_user_scope).
            # Fail-closed : si l'instance Automation n'a pas d'id/user_id
            # persistes (cas pathologique : preview, replay sur snapshot
            # detache), on refuse plutot que de hasher des None — un hash
            # contenant None ne discriminerait plus rien et le bug reviendrait
            # silencieusement.
            if automation.id is None or automation.user_id is None:
                raise ValueError(
                    f"Etape '{node.name}': automation non persistee "
                    f"(id={automation.id!r}, user_id={automation.user_id!r}) — "
                    "idempotency email impossible a calculer sans risque "
                    "de collision cross-user/cross-automation."
                )
            key = compute_idempotency_key(
                sink_kind="email",
                inputs={
                    "automation_id": automation.id,
                    "user_id": automation.user_id,
                    "to": sorted(s.lower() for s in resolved["to"]),
                    "cc": sorted(s.lower() for s in resolved["cc"]),
                    "bcc": sorted(s.lower() for s in resolved["bcc"]),
                    "subject": subject,
                    "attachments": sorted(attachments),
                    "strategy": strategy,
                },
                config=step_cfg,
            )
            already = await _claim_in_dedicated_session(key, sink_kind="email")
            if already:
                extras["warnings"].append("Email deja envoye aujourd'hui (idempotent skip)")
                extras["idempotent_skipped"] = True  # Cluster-E 2026-05-26
                return None, extras

            # Eclater en tickets selon la strategie
            tickets = apply_delivery_strategy(
                strategy=strategy,
                recipients=resolved,
                attachments=attachments,
                subject=subject,
                body=body,
            )
            if not tickets:
                extras["warnings"].append("Email sans destinataire apres resolution — envoi annule")
                return None, extras

            # Envoi direct via SMTPClient (cc_emails/bcc_emails honores
            # separement pour ne PAS exposer les bcc dans le To header).
            smtp_config = await self._load_smtp_config(session)
            if not smtp_config or not smtp_config.get("host"):
                extras["warnings"].append("Config SMTP absente — emails non envoyes")
                return None, extras

            # Q2 cycle 15 : factory unique
            from app.services.email.smtp_factory import build_smtp_client_from_dict

            smtp_client = build_smtp_client_from_dict(
                smtp_config,
                from_name_override=_resolve_smtp_from_name(smtp_config),
            )

            sent_count = 0
            failed_tickets: list = []
            # Cluster-32 2026-05-26 — Sanitize filenames anti-CRLF injection
            # avant attachement. ticket.attachments contient des paths user-
            # controlled via le step config (workbook_loader / save_to_datastore).
            from app.services.automation.email_dispatcher import _safe_attachment_name

            for ticket in tickets:
                ticket_attachments = [
                    {
                        "path": p,
                        "filename": _safe_attachment_name(p.rsplit("/", 1)[-1]),
                    }
                    for p in ticket.attachments
                    if p
                ]
                try:
                    # Cluster-22 2026-05-26 — XSS protection : ticket.subject
                    # peut contenir des substitutions {{step.var}} résolues
                    # depuis un workbook user (potentiellement controlé par un
                    # attacker via cabinet compromis). Sans escape, un payload
                    # `<script>...` injecté dans le subject arriverait en clair
                    # dans le body fallback HTML. On échappe systématiquement.
                    from html import escape as _html_escape_v

                    safe_subject_fallback = _html_escape_v(str(ticket.subject or ""))
                    result = await smtp_client.send_email(
                        to_emails=ticket.to,
                        subject=ticket.subject,
                        body_html=ticket.body or f"<p>{safe_subject_fallback}</p>",
                        cc_emails=ticket.cc or None,
                        bcc_emails=ticket.bcc or None,
                        attachments=ticket_attachments or None,
                        automation_id=automation.id,
                        execution_id=execution_id,
                        sent_by_user_id=automation.user_id,
                        template_name=_EmailTemplate.DAG_EMAIL_STEP.value,
                    )
                    if result.get("success"):
                        sent_count += 1
                    else:
                        failed_tickets.append({"to": ticket.to, "error": result.get("error")})
                except Exception as e:
                    failed_tickets.append({"to": ticket.to, "error": str(e)})
                    logger.error(
                        "Echec envoi ticket email pour automation %d: %s",
                        automation.id,
                        e,
                        exc_info=True,
                    )

            extras["delivery_tickets_sent"] = sent_count
            extras["delivery_tickets_failed"] = len(failed_tickets)
            if failed_tickets:
                extras["warnings"].append(
                    f"Envoi partiel: {sent_count}/{len(tickets)} tickets reussis. "
                    f"Echecs sur: {[t['to'] for t in failed_tickets]}"
                )
            # Echec total → on fail l'etape (pas de succes silencieux).
            if sent_count == 0 and tickets:
                # Cluster-E #5b — aucun email parti : libère le claim pour
                # permettre un vrai retry / ré-exécution (sinon claim
                # orphelin → skip silencieux → non-livraison + warning
                # trompeur « déjà envoyé aujourd'hui »).
                await _release_in_dedicated_session(key)
                raise ValueError(f"Aucun ticket email envoye ({len(failed_tickets)} echecs SMTP)")

            return None, extras

        # --- format_copilot (Phase 3e bridge) ---
        # Branche le step DAG sur le copilot_agent existant via le module
        # bridge dedie. Le gate d'anonymisation reste actif (user_id
        # forwarde). Si l'utilisateur a des termes non confirmes dans
        # /iris, le step echoue avec un message clair et l'execution
        # passe a "failed" (pas de bypass silencieux).
        if step_type == "format_copilot":
            from app.services.ai.copilot_automation_bridge import (
                CopilotAutomationError,
                format_workbook_for_automation,
            )

            if input_workbook is None:
                raise ValueError(f"Etape '{node.name}' (format_copilot): pas d'input workbook")

            # Simplifié 2026-05-27 (P0 Q9 + Task #4b/4c) :
            # - tab_index supprimé du config_schema UI → default 0, le copilot
            #   utilise list_tabs/read_tab_rows pour switcher si besoin
            # - max_rows / max_rows_to_llm supprimés → bridge reçoit None, le
            #   LLM cape lui-même via son context_window (SSoT LlmModel)
            instruction = ""
            if isinstance(step_cfg, dict):
                instruction = (step_cfg.get("instruction") or "").strip()

            # Materialise les SQL tabs avant de passer au copilot.
            # Sinon : un classeur charge via load_workbook (ou produit par
            # un format_copilot precedent) peut contenir des onglets SQL
            # non hydrates → le copilot transformerait du vide silencieusement.
            from app.services.export.iris_xlsx_builder import (
                materialize_workbook_sql_tabs,
            )
            from app.services.automation.workbook_service import tab_to_dict_rows

            user = await self._load_runtime_user(automation.user_id)
            input_tabs = list(input_workbook.get("tabs") or [])
            materialization = await materialize_workbook_sql_tabs(
                input_tabs,
                user,
                rls_source="automation_format_copilot",
                logger_prefix=f"format_copilot[auto={automation.id}]",
            )
            hydrated_tabs = materialization["tabs"]
            for ht in hydrated_tabs:
                ht["rows"] = tab_to_dict_rows(ht)
                ht["isArrayFormat"] = False
            input_workbook = dict(input_workbook)
            input_workbook["tabs"] = hydrated_tabs
            extras["warnings"].extend(materialization.get("warnings") or [])

            try:
                output_wb = await format_workbook_for_automation(
                    input_workbook,
                    instruction,
                    user_id=automation.user_id,
                    user=user,
                )
            except CopilotAutomationError as e:
                # Message safe deja sanitise par le bridge.
                raise ValueError(str(e)) from e

            # Preserver les warnings cumules (turns/tokens du copilot).
            extras["warnings"].extend(output_wb.get("warnings") or [])
            return output_wb, extras

        # --- iris : agent Iris décideur (Tasks #6/#12, 2026-05-27) ---
        # Le step iris invoque l'agent Iris (le même que sur /iris page) en
        # backend headless via iris_automation_bridge. Iris ne produit PAS de
        # workbook ; il prend des DÉCISIONS (route, skip, abort, set vars).
        # Output = input_workbook tel quel (pass-through) pour que les steps
        # aval qui consomment le workbook amont continuent de fonctionner.
        if step_type == "iris":
            from app.services.ai.iris_automation_bridge import (
                IrisAutomationError,
                run_iris_for_automation,
            )

            instruction = ""
            if isinstance(step_cfg, dict):
                instruction = (step_cfg.get("instruction") or "").strip()

            if not instruction:
                raise ValueError(
                    f"Étape '{node.name}' (iris) : instruction manquante. "
                    "Décrivez en quelques mots la décision attendue."
                )

            user = await self._load_runtime_user(automation.user_id)

            # Upstream variables = variables run écrites par les steps amont
            # (interpolables via {{step.var}} dans les configs aval).
            upstream_vars = dict(context.variables) if hasattr(context, "variables") else {}

            # Upstream step outputs = workbooks/files des steps amont pour
            # que get_step_output puisse les lire si Iris en a besoin.
            upstream_outputs: Dict[int, Dict[str, Any]] = {}
            if hasattr(context, "step_outputs"):
                for sid, output in context.step_outputs.items():
                    if output is not None:
                        upstream_outputs[sid] = {"kind": "workbook", "payload": output}

            # Fix CRIT #5 (adversarial 2026-05-27) — descendants topologiques
            # autorisés pour `skip_steps`. Iris ne peut skipper QUE parmi cette
            # liste (anti-corruption DAG state si Iris hallucine des ids).
            # Le DAG executor expose `compute_descendants_of(node_id)` via le
            # contexte ; si absent, on passe set() vide = fail-closed (skip refusé).
            descendants: set = set()
            try:
                from app.services.automation.dag_executor import compute_descendants

                # Reconstituer la liste des descendants via les edges du run
                if hasattr(context, "edges_index"):
                    descendants = compute_descendants({node.id}, context.edges_index)
                elif hasattr(context, "edges_list"):
                    descendants = compute_descendants({node.id}, context.edges_list)
                # Retirer node.id de la liste (Iris ne peut pas se skipper
                # lui-même évidemment).
                descendants.discard(node.id)
            except Exception:  # noqa: BLE001
                logger.warning(
                    "iris step %s: impossible de calculer descendants topologiques "
                    "(skip_steps sera refusé en fail-closed)",
                    node.id,
                    exc_info=True,
                )
                descendants = set()

            # Fix CRIT #3 (adversarial 2026-05-27) : le `cancel_event` doit
            # venir du DAG runner (DAGRunContext) — pas un attribut self
            # imaginaire. Tant que le wiring DAG → handler n'est pas câblé,
            # on passe None EXPLICITEMENT (pas getattr masquant l'absence).
            # Cf. mini-task à créer : "câbler cancel_event dans DAGRunContext
            # + propagation aux step handlers via context.cancel_event".
            cancel_event_ref = getattr(context, "cancel_event", None)

            try:
                iris_result = await run_iris_for_automation(
                    instruction=instruction,
                    user=user,
                    automation_id=automation.id,
                    step_id=node.id,
                    cancel_event=cancel_event_ref,
                    upstream_variables=upstream_vars,
                    upstream_step_outputs=upstream_outputs,
                    allowed_skip_targets=descendants,
                )
            except IrisAutomationError as e:
                # Task #25 — propage la catégorie d'erreur (4-cas axe 5
                # Komptia) dans extras pour que l'UI affiche le bon message
                # et le bon CTA (retry vs signaler vs ajuster prompt).
                category = getattr(e, "category", "system")
                extras["warnings"].append(f"Iris erreur catégorie={category} : {str(e)[:300]}")
                extras["iris_error_category"] = category
                raise ValueError(str(e)) from e

            # Si Iris a appelé abort_run → step échoué avec raison
            if iris_result.aborted:
                raise ValueError(
                    f"Iris a abort : {iris_result.abort_reason or 'raison non précisée'}"
                )

            # Propage les variables run écrites par Iris (set_run_variable)
            # vers le state DAG pour interpolation aval ({{step.var}}).
            if iris_result.variables and hasattr(context, "variables"):
                node_name = node.name or f"step_{node.id}"
                # Convention : namespace par nom de step (compatible avec
                # le pattern existant des autres step types qui posent
                # context.variables["<step_name>.<key>"]).
                for key, value in iris_result.variables.items():
                    context.variables[f"{node_name}.{key}"] = value

            # Décision tracée dans extras pour observabilité
            extras["iris_decision"] = iris_result.decision_summary
            extras["iris_turns_used"] = iris_result.turns_used
            extras["iris_trace_length"] = len(iris_result.trace)
            extras["conversation_id"] = iris_result.conversation_id

            # Task #18 — Remonter le coût LLM dans ``extras["llm_cost_eur"]``
            # pour que le circuit-breaker `automation.max_llm_cost_eur`
            # (dag_executor.py) comptabilise les appels Iris-in-automation.
            # Conversion USD→EUR via ENV var (default 1.0 — USD≈EUR à ~5%,
            # acceptable pour cap budget. L'admin peut override via
            # ``KOMPTIA_USD_EUR_RATE`` si besoin d'une conversion stricte).
            # Fix MAJOR #14 (adversarial 2026-05-27) : math.isfinite anti-NaN
            # bypass. `float("nan") > 0` est False → cap silencieux ; on
            # rejette les valeurs non-finies (nan, inf) et fallback 1.0.
            import math as _math

            if iris_result.llm_cost_usd > 0:
                try:
                    eur_rate = float(os.environ.get("KOMPTIA_USD_EUR_RATE", "1.0"))
                    if not _math.isfinite(eur_rate) or eur_rate <= 0:
                        eur_rate = 1.0
                except (TypeError, ValueError):
                    eur_rate = 1.0
                extras["llm_cost_eur"] = iris_result.llm_cost_usd * eur_rate

            # Skip steps : extraire de la trace pour le DAG executor
            for trace_event in iris_result.trace:
                if trace_event.get("event") == "skip_steps":
                    skip_ids = trace_event.get("step_ids") or []
                    if skip_ids and hasattr(context, "skipped_descendants"):
                        context.skipped_descendants.update(skip_ids)
                        extras["warnings"].append(
                            f"Iris a skippé {len(skip_ids)} step(s) : "
                            f"{trace_event.get('reasons', {})}"
                        )

            # Pass-through workbook amont (Iris ne produit pas de données)
            output_wb = input_workbook if input_workbook is not None else {"tabs": []}
            return output_wb, extras

        # --- email_wait_response : envoi mail tokenise + suspend l'auto ---
        # Le step :
        # 1. Genere un WaitToken (UUID + HMAC) + row BDD F_WAIT_TOKEN
        # 2. Envoie un mail au destinataire avec le lien
        #    https://komptia.tld/automations/wait/{token}
        # 3. Persiste un checkpoint (snapshot des step_outputs deja
        #    calcules) sur Execution.wait_checkpoint
        # 4. Marque step + execution = waiting
        # 5. Leve WaitForResponse → catch par dag_executor (pas marque
        #    failed) → catch par execute_automation (pas marque success
        #    ni failed, transition vers waiting)
        #
        # La reprise se fait via resume_automation(execution_id, step_id,
        # response_data) declenche par POST /automations/wait/{token}.
        if step_type == "email_wait_response":
            from app.core.exceptions import WaitForResponse
            from app.models.wait_token import WaitToken
            from app.utils.wait_token_codec import issue_token

            # Validation config
            if not isinstance(step_cfg, dict):
                raise ValueError(f"Etape '{node.name}' (email_wait_response): config invalide")
            recipient = (step_cfg.get("to") or "").strip()
            subject = (step_cfg.get("subject") or "").strip()
            body = (step_cfg.get("body") or "").strip()
            response_kind = (step_cfg.get("response_kind") or "text").strip().lower()
            file_format = (step_cfg.get("file_format") or "both").strip().lower()
            wait_timeout_hours_raw = step_cfg.get("wait_timeout_hours", 0)
            include_inputs = bool(step_cfg.get("include_inputs_as_attachments", False))
            reminder_hours_before_raw = step_cfg.get("reminder_hours_before", 0)

            # Validation destinataire (un seul, format email basique)
            if not recipient or "@" not in recipient or len(recipient) > 254:
                raise ValueError(
                    f"Etape '{node.name}' (email_wait_response): destinataire "
                    "invalide (un seul email RFC 5321 requis)"
                )
            if not subject:
                raise ValueError(f"Etape '{node.name}' (email_wait_response): objet du mail requis")
            if response_kind not in ("text", "file", "both"):
                raise ValueError(
                    f"Etape '{node.name}' (email_wait_response): response_kind "
                    f"'{response_kind}' invalide (attendu: text, file, both)"
                )
            if file_format not in ("csv", "xlsx", "both"):
                raise ValueError(
                    f"Etape '{node.name}' (email_wait_response): file_format "
                    f"'{file_format}' invalide (attendu: csv, xlsx, both)"
                )
            try:
                wait_timeout_hours = int(float(wait_timeout_hours_raw or 0))
            except (TypeError, ValueError):
                wait_timeout_hours = 0
            try:
                reminder_hours_before = int(float(reminder_hours_before_raw or 0))
            except (TypeError, ValueError):
                reminder_hours_before = 0

            # TTL adaptatif : si l'admin n'a rien specifie (=0), on calcule
            # depuis le schedule de l'auto pour expirer AVANT le prochain
            # run scheduled (sinon 2 instances waiting concurrentes). Pour
            # les autos one-shot ou manuelles : fallback 30 jours.
            from app.services.automation.wait_resume import (
                compute_wait_expires_at,
                send_wait_request_email,
                serialize_wait_checkpoint,
            )

            expires_at = compute_wait_expires_at(
                automation,
                requested_hours=wait_timeout_hours,
            )

            # Generation du token
            token_public, token_hash = issue_token()

            # Persistance : on cree la row WaitToken AVANT d'envoyer le
            # mail. Si l'envoi echoue, on rollback la row + on raise une
            # erreur normale (le step est marque failed). Si le mail part
            # mais qu'on crashe juste apres, le destinataire peut cliquer
            # mais on ne saura plus quoi reprendre — on prefere donc
            # l'ordre persistance → envoi → checkpoint → waiting.
            wait_row = WaitToken(
                execution_id=execution_id,
                step_id=node.id,
                token_hash=token_hash,
                recipient_email=recipient,
                response_kind=response_kind,
                file_format=file_format,
                status="pending",
                expires_at=expires_at,
            )
            session_factory_wait = get_session_factory()
            async with session_factory_wait() as wait_sess:
                wait_sess.add(wait_row)
                await wait_sess.commit()
                await wait_sess.refresh(wait_row)
                wait_token_id = wait_row.id

            # Construction des pj optionnelles (reutilise la logique email
            # standard : conversion implicite workbook → xlsx via build_iris_xlsx
            # pour les ancetres atteignables par edge data, exclus des
            # ancetres trigger-only).
            attachments: List[str] = []
            if include_inputs:
                from app.services.automation.dag_executor import compute_ancestors

                edges_data_only = [
                    e
                    for e in (automation.edges or [])
                    if getattr(e, "data_type", None) != "trigger"
                ]
                ancestors = compute_ancestors({node.id}, edges_data_only)
                ordered_ancestor_ids = sorted(ancestors)
                attachments = [
                    f
                    for aid in ordered_ancestor_ids
                    if (f := context.step_output_files.get(aid)) is not None
                ]
                # Conversion implicite workbook → xlsx pour ancetres sans fichier
                steps_by_id = {s.id: s for s in (automation.steps or [])}
                for aid in ordered_ancestor_ids:
                    if aid in context.step_output_files:
                        continue
                    wb = context.step_outputs.get(aid)
                    if not isinstance(wb, dict):
                        continue
                    tabs = wb.get("tabs") or []
                    if not tabs:
                        continue
                    step_obj = steps_by_id.get(aid)
                    ancestor_name = (step_obj.name if step_obj else None) or f"etape_{aid}"
                    try:
                        xlsx_path = await self._generate_workbook_export(
                            automation,
                            execution_id,
                            tabs=tabs,
                            output_format="excel",
                            filename_hint=ancestor_name,
                        )
                        attachments.append(str(xlsx_path))
                    except Exception:
                        logger.warning(
                            "email_wait_response: conversion implicite workbook→xlsx "
                            "echec pour ancetre %s",
                            ancestor_name,
                            exc_info=True,
                        )

            # Envoi du mail
            try:
                async with session_factory_wait() as smtp_sess:
                    smtp_config = await self._load_smtp_config(smtp_sess)
                await send_wait_request_email(
                    smtp_config=smtp_config,
                    automation=automation,
                    execution_id=execution_id,
                    step_name=node.name or "Demande",
                    recipient=recipient,
                    subject=subject,
                    body=body,
                    token_public=token_public,
                    response_kind=response_kind,
                    file_format=file_format,
                    expires_at=expires_at,
                    attachments=attachments,
                )
            except Exception as exc:
                # Rollback de la row WaitToken pour ne pas laisser une row
                # pending sans mail correspondant (oracle-fluide pour
                # l'utilisateur qui verrait un wait sans pouvoir comprendre
                # pourquoi le destinataire n'a rien recu).
                async with session_factory_wait() as rollback_sess:
                    row = await rollback_sess.get(WaitToken, wait_token_id)
                    if row is not None:
                        await rollback_sess.delete(row)
                        await rollback_sess.commit()
                raise ValueError(
                    f"Etape '{node.name}' (email_wait_response): envoi mail "
                    f"echec ({type(exc).__name__}). La step est marquee failed."
                ) from exc

            # Persistance du checkpoint sur Execution + transition waiting.
            # Le checkpoint capture les step_outputs deja calcules pour
            # rehydrate au resume sans re-exec. include les step_output_files
            # (paths de fichiers PDF/xlsx generes par les sinks aval).
            checkpoint = serialize_wait_checkpoint(
                step_outputs=context.step_outputs,
                step_output_files=context.step_output_files,
                executed_step_ids=list(context.step_outputs.keys()),
                wait_token_id=wait_token_id,
                wait_step_id=node.id,
                reminder_hours_before=reminder_hours_before,
            )
            async with session_factory_wait() as exec_sess:
                exec_row = await exec_sess.get(Execution, execution_id)
                if exec_row is not None:
                    exec_row.wait_checkpoint = checkpoint
                    exec_row.mark_waiting()
                    await exec_sess.commit()

            extras["wait_token_id"] = wait_token_id
            extras["wait_expires_at"] = expires_at.isoformat()
            extras["warnings"].append(
                f"Etape en attente d'une reponse externe (echeance : " f"{expires_at.isoformat()})"
            )
            logger.info(
                "email_wait_response: token #%d envoye a %s, expire %s",
                wait_token_id,
                recipient,
                expires_at.isoformat(),
            )
            # Leve l'exception speciale pour interrompre le DAG sans
            # marquer la step failed. Le dag_executor + execute_automation
            # catchent et transitionnent vers waiting.
            raise WaitForResponse(
                f"Etape « {node.name} » en attente — lien envoye a {recipient}",
                wait_token_id=wait_token_id,
            )

        # --- Save to datastore : sink filesystem (.afz.json) ---
        if step_type == "save_to_datastore":
            from app.handlers.datastore import (
                _safe_path,
                _sanitize_user_filename,
                _user_dir,
            )
            import json as _json
            import shutil as _shutil
            from pathlib import Path as _Path

            # Mode detection : report_file (copy) vs workbook (serialize).
            # On regarde les ancetres DIRECTS (parents via edges entrants).
            # Si au moins un parent a un output_file dans context, on est
            # en mode "archive" et on copy. Sinon on serialise le workbook.
            #
            # NB : grace au validator (FAN_IN_MIXED_TYPES), on a la garantie
            # que tous les parents directs ont le meme type d'edge → soit
            # tous workbook soit tous report_file. Pas de melange a gerer.
            from app.services.automation.dag_validator import _edge_attr

            direct_parent_ids = [
                _edge_attr(e, "from_step_id")
                for e in (automation.edges or [])
                if _edge_attr(e, "to_step_id") == node.id
            ]
            parent_files = [
                f
                for pid in direct_parent_ids
                if (f := context.step_output_files.get(pid)) is not None
            ]
            mode = "copy" if parent_files else "serialize"

            if mode == "serialize" and input_workbook is None:
                raise ValueError(
                    f"Etape '{node.name}' (save_to_datastore): aucun input — "
                    "ni workbook (mode serialize) ni fichier amont (mode copy)"
                )

            folder_path = (step_cfg.get("folder_path") or "").strip().strip("/")
            filename_raw = (step_cfg.get("filename") or "").strip()
            overwrite = bool(step_cfg.get("overwrite", False))

            if not filename_raw:
                raise ValueError(f"Etape '{node.name}' (save_to_datastore): nom de fichier requis")

            # Substitutions {date} / {datetime} pour rendre le nom unique
            # par execution. UTC pour coherence avec audit logs / scheduler.
            # Cluster-Y 2026-05-26 — naive UTC via clock.naive_utc() (SSoT
            # horloge). strftime n'utilise pas la tzinfo pour ces patterns
            # (%Y-%m-%d / %H-%M-%S) — on garde donc la forme naive.
            now = clock.naive_utc()
            filename_subst = filename_raw.replace("{date}", now.strftime("%Y-%m-%d")).replace(
                "{datetime}", now.strftime("%Y-%m-%d_%H-%M-%S")
            )
            base_name = _sanitize_user_filename(filename_subst)
            if not base_name:
                raise ValueError(
                    f"Etape '{node.name}' (save_to_datastore): nom de fichier "
                    f"'{filename_raw}' invalide apres sanitization"
                )

            # Strip extension utilisateur (le user n'a pas a se preoccuper de
            # l'extension — c'est nous qui la determinons selon le mode).
            base_stem = base_name
            for suf in (".afz.json", ".json", ".pdf", ".xlsx", ".csv", ".zip"):
                if base_stem.lower().endswith(suf):
                    base_stem = base_stem[: -len(suf)]
                    break

            user_dir = _user_dir(automation.user_id)
            target_dir = _safe_path(user_dir, folder_path) if folder_path else user_dir
            if target_dir is None:
                raise ValueError(
                    f"Etape '{node.name}' (save_to_datastore): dossier "
                    f"'{folder_path}' invalide (path-traversal)"
                )
            target_dir.mkdir(parents=True, exist_ok=True)

            # Determine extension cible :
            # - mode serialize : .afz.json (toujours, format natif Komptia)
            # - mode copy      : extension du fichier source (.pdf, .xlsx, ...)
            if mode == "serialize":
                target_ext = ".afz.json"
            else:
                # On prend l'extension du PREMIER parent_file. Si fan-in
                # multi-files, on suffixera _1/_2/... par parent (cf. boucle
                # finale) et chaque fichier garde son extension propre.
                first_ext = _Path(parent_files[0]).suffix or ".bin"
                target_ext = first_ext

            # Resolution du nom final (avec suffixage si !overwrite et collision).
            candidate = target_dir / f"{base_stem}{target_ext}"
            if candidate.exists() and not overwrite:
                idx = 2
                while True:
                    candidate = target_dir / f"{base_stem}_{idx}{target_ext}"
                    if not candidate.exists():
                        break
                    idx += 1
                    if idx > 999:
                        raise ValueError(
                            f"Etape '{node.name}' (save_to_datastore): "
                            "trop de collisions (>999), nettoyez le dossier"
                        )

            # Validation post-resolve : le fichier final reste bien dans le
            # user_dir (defense en profondeur — _safe_path l'a deja fait
            # sur le dossier mais le suffixage peut introduire un cas limite).
            try:
                if not candidate.resolve().is_relative_to(user_dir.resolve()):
                    raise ValueError(
                        f"Etape '{node.name}' (save_to_datastore): chemin "
                        "resolu hors du datastore utilisateur"
                    )
            except (OSError, RuntimeError) as exc:
                raise ValueError(f"Etape '{node.name}' (save_to_datastore): {exc}") from exc

            if mode == "copy":
                # Mode archive : copy les fichiers amont dans le datastore.
                # Si un seul parent_file → un seul fichier copy a `candidate`.
                # Si plusieurs parents (fan-in multi-files) → on suffixe
                # _1/_2/... avec extension propre a chaque source pour
                # eviter les collisions.
                copied_paths: List[str] = []
                if len(parent_files) == 1:
                    src = parent_files[0]
                    await asyncio.to_thread(_shutil.copy2, src, str(candidate))
                    copied_paths.append(str(candidate))
                else:
                    # multi-files : recalcule le candidate par fichier
                    for i, src in enumerate(parent_files, start=1):
                        ext_i = _Path(src).suffix or ".bin"
                        candi = target_dir / f"{base_stem}_{i}{ext_i}"
                        if candi.exists() and not overwrite:
                            sub = 2
                            while (target_dir / f"{base_stem}_{i}_{sub}{ext_i}").exists():
                                sub += 1
                                if sub > 999:
                                    raise ValueError(f"Etape '{node.name}': trop de collisions")
                            candi = target_dir / f"{base_stem}_{i}_{sub}{ext_i}"
                        await asyncio.to_thread(_shutil.copy2, src, str(candi))
                        copied_paths.append(str(candi))

                # Resume : on reporte le 1er fichier comme principal pour
                # extras (compat preview), mais on liste tous les paths.
                rel_paths = []
                total_size = 0
                for p in copied_paths:
                    pp = _Path(p)
                    try:
                        rel_paths.append(pp.relative_to(user_dir).as_posix())
                    except ValueError:
                        rel_paths.append(pp.name)
                    try:
                        total_size += pp.stat().st_size
                    except OSError:
                        pass
                extras["saved_path"] = rel_paths[0] if rel_paths else ""
                extras["saved_paths"] = rel_paths
                extras["saved_size_bytes"] = total_size
                extras["save_mode"] = "copy"
                return input_workbook, extras

            # Sérialisation atomique : write_temp + rename. Evite de laisser
            # un .afz.json corrompu si le process crashe pendant l'ecriture.
            # `default=str` est obligatoire : un workbook issu d'un SELECT
            # SQL Server contient typiquement des datetime / Decimal que
            # `json.dumps` standard refuse (pattern utilise partout dans
            # la codebase, cf. agent_service.py / iris_one_shot.py).
            payload = _json.dumps(
                input_workbook,
                ensure_ascii=False,
                separators=(",", ":"),
                default=str,
            )
            tmp = candidate.with_suffix(candidate.suffix + ".tmp")
            try:
                tmp.write_text(payload, encoding="utf-8")
                tmp.replace(candidate)
            except OSError as exc:
                if tmp.exists():
                    try:
                        tmp.unlink()
                    except OSError:
                        pass
                raise ValueError(
                    f"Etape '{node.name}' (save_to_datastore): ecriture " f"impossible ({exc})"
                ) from exc

            try:
                rel_saved = candidate.relative_to(user_dir).as_posix()
            except ValueError:
                rel_saved = candidate.name
            extras["saved_path"] = rel_saved
            extras["saved_paths"] = [rel_saved]
            extras["saved_size_bytes"] = len(payload.encode("utf-8"))
            extras["save_mode"] = "serialize"
            return input_workbook, extras

        # Fail-closed : si on arrive ici c'est qu'un step persiste avec un
        # type que le DAG executor ne supporte plus (rares cas d'automations
        # tres anciennes survivantes au purge BDD). Pas de fallback silent
        # vers WorkflowEngine — le user doit savoir que le step est mort
        # plutot que de croire qu'il s'execute.
        raise ValueError(
            f"Etape '{node.name}' : type d'etape '{step_type}' non supporte "
            "par ce moteur. Types valides : extract_sql, "
            "load_workbook, load_saved_query, format_copilot, report, "
            "export_workbook, email, save_to_datastore."
        )

    return adapter
