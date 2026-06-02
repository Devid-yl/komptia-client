"""Feature #7 task #7d (2026-05-26) — Pipeline d'orchestration de la
réécriture LLM des paires Q/SQL stockées quand le serveur SQL Server
change de version.

Workflow
--------
Appelé depuis ``schema_sync._sync_from_sage_impl`` APRÈS
``_detect_and_store_server_version`` qui calcule le
``capability_delta``. Si ``broken_capabilities`` non-vide :

1. **Scan** : :func:`sql_capability_matcher.find_active_pairs_affected_by_capabilities`
   retourne les paires impactées.
2. **Rewrite (séquentiel)** : pour chaque paire,
   :func:`sql_rewrite_service.rewrite_sql_for_new_server` est appelé
   (1 LLM call). Le résultat est ``success / needs_human_review / failed``.
3. **Persist** : update ``TrainingData.sql`` (avec backup de l'ancien
   dans ``extra_metadata.auto_rewrite``), update ``pending_review``
   selon l'issue, audit log (``AuditAction.TRAINING_DATA_AUTO_REWRITE``).
4. **Progress** : callback pour propager X/N au front (overlay sync).

Doctrine
--------
* **Séquentiel pas parallèle** : 1 LLM call à la fois. Évite la
  saturation du rate-limit Anthropic et facilite la cancel propre.
  Pour N paires modestes (< 500 typiquement), 30-60s par paire =
  acceptable pour un sync qui tourne déjà 5-15 min.
* **Idempotent** : si une paire a déjà ``extra_metadata.auto_rewrite``
  avec le même ``to_version``, on skip (rewrite déjà fait dans un
  sync précédent).
* **Cancel-aware** : check ``cancel_event.is_set()`` entre paires —
  user clique cancel → on s'arrête proprement avec un partial summary.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

from sqlalchemy import select, update

from app.core import clock
from app.core.database import get_session
from app.models.audit import AuditAction, AuditLog
from app.models.training_data import TrainingData

logger = logging.getLogger(__name__)


@dataclass
class RewritePipelineResult:
    """Résumé de la pipeline rewrite après un sync.

    Inclus dans ``SchemaSync.changes_detail["capability_delta"]["rewrite"]``
    pour visibilité admin via /admin/database history.
    """

    triggered: bool  # False = aucun broken_capability détecté, no-op
    total_affected: int
    succeeded: int
    needs_human_review: int
    failed: int
    skipped_already_rewritten: int
    cancelled: bool
    duration_seconds: float
    pair_results: List[Dict[str, Any]] = field(default_factory=list)


def _build_extra_metadata_entry(
    *,
    old_sql: str,
    from_version: Optional[str],
    to_version: Optional[str],
    broken_capabilities: List[str],
    model_used: Optional[str],
    success: bool,
    needs_human_review: bool,
    error: Optional[str],
) -> Dict[str, Any]:
    """Build l'entrée à stocker dans ``TrainingData.extra_metadata.auto_rewrite``.

    Conserve l'ancien SQL pour rollback admin + métadonnées de traçabilité.
    """
    return {
        "rewritten_at": clock.now().isoformat(),
        "from_version": from_version,
        "to_version": to_version,
        "broken_capabilities": broken_capabilities,
        "old_sql": old_sql,
        "model_used": model_used,
        "success": success,
        "needs_human_review": needs_human_review,
        "error": error,
    }


async def _persist_rewrite_outcome(
    pair_id: int,
    *,
    new_sql: Optional[str],
    metadata_entry: Dict[str, Any],
    needs_human_review: bool,
    user_id: Optional[int],
) -> bool:
    """Persist le résultat d'une rewrite : update training_data + audit log.

    Returns:
        True si l'update BDD a réussi, False sinon (la pipeline continue
        sur l'erreur — on ne fait pas tomber tout le sync pour 1 paire).
    """
    try:
        async with get_session() as session:
            # Re-fetch la paire dans une nouvelle session pour avoir une
            # row attachée + capturer l'ancien extra_metadata pour merge.
            existing = (
                await session.execute(select(TrainingData).where(TrainingData.id == pair_id))
            ).scalar_one_or_none()
            if existing is None:
                logger.warning(
                    "Feature #7 persist — paire id=%s disparue entre scan "
                    "et persist (deleted par admin pendant le sync ?), "
                    "skip silencieusement.",
                    pair_id,
                )
                return False

            # Merge le nouveau auto_rewrite dans extra_metadata (dict JSON).
            current_meta = dict(existing.extra_metadata or {})
            current_meta["auto_rewrite"] = metadata_entry
            existing.extra_metadata = current_meta

            # Update le SQL UNIQUEMENT si on a un new_sql utilisable
            # (success ou needs_review avec SQL produit par le LLM).
            if new_sql:
                existing.sql = new_sql
                existing.content = f"Question: {existing.question or ''}\nSQL: {new_sql}"
            # pending_review : True si needs_review, False si success franc.
            # Si rien à reviewer (LLM down, échec dur), on NE touche PAS
            # pending_review pour ne pas perturber un workflow admin
            # éventuel.
            if metadata_entry.get("success"):
                existing.pending_review = False
            elif needs_human_review:
                existing.pending_review = True

            # Audit log — fire-and-forget côté caller (la session commit
            # ci-dessous flush l'audit dans la même transaction).
            session.add(
                AuditLog.log_action(
                    action=AuditAction.TRAINING_DATA_AUTO_REWRITE,
                    user_id=user_id,
                    entity_type="training_data",
                    entity_id=pair_id,
                    details=metadata_entry,
                )
            )
            await session.commit()
        return True
    except Exception as exc:  # noqa: BLE001 — defense in depth
        logger.warning(
            "Feature #7 persist — échec update paire id=%s (%s): %s. "
            "La pipeline continue avec les paires suivantes.",
            pair_id,
            type(exc).__name__,
            exc,
        )
        return False


def _already_rewritten_for_version(
    pair_metadata: Optional[Dict[str, Any]], to_version: Optional[str]
) -> bool:
    """Idempotence : si la paire a déjà un auto_rewrite pour cette même
    to_version, on skip (sync précédent l'a déjà traitée)."""
    if not pair_metadata or not to_version:
        return False
    auto = pair_metadata.get("auto_rewrite")
    if not isinstance(auto, dict):
        return False
    return auto.get("to_version") == to_version and bool(auto.get("success"))


async def rewrite_affected_pairs(
    capability_delta: Optional[Dict[str, Any]],
    *,
    progress_callback: Optional[Callable[[str, int, str], Awaitable[None]]] = None,
    cancel_event: Optional[asyncio.Event] = None,
    user_id: Optional[int] = None,
) -> RewritePipelineResult:
    """Pipeline complète : scan + rewrite + persist + audit pour toutes
    les paires impactées par un downgrade de capability.

    Args:
        capability_delta: Dict produit par
            :func:`compute_capability_delta`. ``None`` ou sans
            ``broken_capabilities`` → no-op (triggered=False).
        progress_callback: ``async (step, percent, message)`` — appelé
            entre chaque paire pour propager X/N au front. ``percent``
            est sur [_REWRITE_PROGRESS_START, _REWRITE_PROGRESS_END]
            pour cohabiter avec les autres phases sync.
        cancel_event: Si ``set()``, on s'arrête à la prochaine paire
            avec ``cancelled=True``.
        user_id: ID user qui a déclenché le sync (pour audit log).

    Returns:
        ``RewritePipelineResult`` détaillé.
    """
    start_ts = time.perf_counter()
    result = RewritePipelineResult(
        triggered=False,
        total_affected=0,
        succeeded=0,
        needs_human_review=0,
        failed=0,
        skipped_already_rewritten=0,
        cancelled=False,
        duration_seconds=0.0,
    )

    if not capability_delta:
        return result
    broken = capability_delta.get("broken_capabilities") or []
    if not broken:
        return result
    if not capability_delta.get("downgrade"):
        # Si pas de downgrade explicite, on ne touche pas — broken_capabilities
        # ne devrait pas être non-vide sans downgrade par construction de
        # compute_capability_delta, mais defense in depth.
        return result

    old_label = capability_delta.get("old_label")
    new_label = capability_delta.get("new_label")

    result.triggered = True

    # Scan : qui est impacté ?
    from app.services.ai.sql_capability_matcher import (
        find_active_pairs_affected_by_capabilities,
    )

    affected = await find_active_pairs_affected_by_capabilities(broken)
    result.total_affected = len(affected)

    if not affected:
        # Trigger TRUE mais 0 paire à réécrire — informatif (downgrade
        # détecté mais aucune paire stockée ne l'utilise).
        result.duration_seconds = time.perf_counter() - start_ts
        logger.info(
            "Feature #7 — downgrade détecté mais aucune paire active "
            "n'utilise les capabilities cassées %s. No-op.",
            broken,
        )
        return result

    if progress_callback:
        try:
            await progress_callback(
                "rewrite_start",
                _REWRITE_PROGRESS_START,
                f"Réécriture LLM de {len(affected)} paire(s) Q/SQL...",
            )
        except Exception:  # noqa: BLE001 — callback safe
            pass

    # Import tardif du service rewrite (évite cycle import au boot module).
    from app.services.ai.sql_rewrite_service import rewrite_sql_for_new_server

    for idx, pair in enumerate(affected):
        # Cancel check entre paires (on ne coupe pas un appel LLM en cours
        # — coût déjà engagé — mais on n'en lance pas de nouveau).
        if cancel_event is not None and cancel_event.is_set():
            result.cancelled = True
            logger.info(
                "Feature #7 — pipeline rewrite annulée par cancel_event " "à la paire %d/%d.",
                idx,
                len(affected),
            )
            break

        pair_id = pair["id"]
        old_sql = pair["sql"]

        # Idempotence : check si déjà rewritten pour cette to_version.
        # Re-lit la paire pour avoir l'extra_metadata à jour (utile si
        # sync précédent partiel ou retry).
        async with get_session() as _read_sess:
            existing = (
                await _read_sess.execute(
                    select(TrainingData.extra_metadata).where(TrainingData.id == pair_id)
                )
            ).first()
            existing_meta = existing[0] if existing else None
        if _already_rewritten_for_version(existing_meta, new_label):
            result.skipped_already_rewritten += 1
            result.pair_results.append(
                {
                    "pair_id": pair_id,
                    "status": "skipped_already_rewritten",
                }
            )
            continue

        try:
            rewrite_res = await rewrite_sql_for_new_server(
                old_sql=old_sql,
                old_label=old_label or "unknown",
                new_label=new_label or "unknown",
                broken_capabilities=pair["matched_capabilities"],
                user_id=user_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Feature #7 — appel rewrite_sql_for_new_server a levé "
                "une exception inattendue pour paire %s (%s): %s. "
                "Pair restée intacte.",
                pair_id,
                type(exc).__name__,
                exc,
            )
            result.failed += 1
            result.pair_results.append(
                {
                    "pair_id": pair_id,
                    "status": "failed",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue

        metadata_entry = _build_extra_metadata_entry(
            old_sql=old_sql,
            from_version=old_label,
            to_version=new_label,
            broken_capabilities=pair["matched_capabilities"],
            model_used=rewrite_res.model_used,
            success=rewrite_res.success,
            needs_human_review=rewrite_res.needs_human_review,
            error=rewrite_res.error,
        )

        # Persist : update training_data + audit log (transactionnel).
        persisted = await _persist_rewrite_outcome(
            pair_id,
            new_sql=rewrite_res.new_sql,
            metadata_entry=metadata_entry,
            needs_human_review=rewrite_res.needs_human_review,
            user_id=user_id,
        )

        if rewrite_res.success and persisted:
            result.succeeded += 1
            status = "succeeded"
        elif rewrite_res.needs_human_review:
            result.needs_human_review += 1
            status = "needs_human_review"
        else:
            result.failed += 1
            status = "failed"
        result.pair_results.append(
            {
                "pair_id": pair_id,
                "status": status,
                "error": rewrite_res.error,
            }
        )

        # Progress callback : interpolation linéaire entre START et END.
        if progress_callback:
            try:
                pct = _REWRITE_PROGRESS_START + int(
                    (_REWRITE_PROGRESS_END - _REWRITE_PROGRESS_START) * (idx + 1) / len(affected)
                )
                await progress_callback(
                    "rewrite_in_progress",
                    pct,
                    f"Réécriture LLM en cours : {idx + 1}/{len(affected)} "
                    f"(succès={result.succeeded}, "
                    f"à reviewer={result.needs_human_review}, "
                    f"échec={result.failed})",
                )
            except Exception:  # noqa: BLE001
                pass

    result.duration_seconds = time.perf_counter() - start_ts
    logger.info(
        "Feature #7 — pipeline rewrite terminée: %d paires affectées, "
        "%d succès, %d à reviewer, %d échec, %d skip (déjà fait), "
        "cancelled=%s, %.1fs",
        result.total_affected,
        result.succeeded,
        result.needs_human_review,
        result.failed,
        result.skipped_already_rewritten,
        result.cancelled,
        result.duration_seconds,
    )
    return result


# Plage de progression réservée au step rewrite dans la séquence sync.
# La détection version est < 5% (très rapide). Les phases lourdes (tables,
# views, FK, stats, embeddings) prennent 80-90%. Le rewrite est inséré
# entre la détection version et le scan tables → 5-10%. Cap large pour
# laisser le temps aux N appels LLM (peut prendre plusieurs min).
_REWRITE_PROGRESS_START = 1
_REWRITE_PROGRESS_END = 4
