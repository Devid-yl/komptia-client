"""Endpoints REST pour la pipeline NL→SQL.

Routes (ajoutées dans ``app/routes.py``) :

- ``POST   /api/iris/pipeline-run``                    → créer + lancer
- ``GET    /api/iris/pipeline/{run_id}``               → status + phases
- ``GET    /api/iris/pipeline-history``                → 20 derniers runs user
- ``DELETE /api/iris/pipeline/{run_id}/archive``       → soft-delete
- ``GET    /api/iris/pipeline/{run_id}/artifacts/{phase_id}``
  → JSON artefact (sert le fichier disque, vérifie ownership)

Patterns d'isolation (alignés sur les autres handlers Iris) :

- ``@authenticated`` partout — pas d'accès anonyme.
- ``check_xsrf_cookie`` automatique sur POST/DELETE (Tornado).
- Lecture/écriture filtrée par ``user_id`` du current_user — un user ne
  voit/touche que ses propres runs (404-like sinon, anti-leak existence).
- Quota max runs/jour/user (env ``PIPELINE_MAX_RUNS_PER_DAY``, défaut 10).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.database import get_session_factory
from app.handlers.base import BaseHandler, authenticated
from app.models.pipeline_run import (
    PipelineMode,
    PipelinePhaseExecution,
    PipelineRun,
    PipelineRunStatus,
    TriggeredVia,
)
from app.services.ai.pipeline_runner import (
    QuotaExceededError,
    start_pipeline_run,
)
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter
from app.utils.request_context import request_scope

logger = get_logger(__name__)


_RATE_LIMIT_RUN_CREATE = (5, 60)  # 5 starts / 60s par user (anti-flood court)
_run_create_limiter = RateLimiter()


def _safe_json_loads(body: bytes) -> dict | None:
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _serialize_run(run: PipelineRun) -> dict:
    return run.to_dict()


def _serialize_phase(phase: PipelinePhaseExecution) -> dict:
    return phase.to_dict()


async def _sanitize_pipeline_dict_for_client(d: dict, user: Any) -> None:
    """Sanitize EN PLACE un run/phase sérialisé AVANT envoi au client (status/history).

    - **L6O2** : ``error_message`` brut (``str(exc)`` : path filesystem, stack
      SQLAlchemy, fragment SQL) → message générique par catégorie via le helper
      SSoT ``sanitize_pipeline_error_for_client`` (partagé avec le forward WS).
    - **L6O1** : ``artifact_path`` (chemin disque ABSOLU serveur, ex.
      ``/Users/.../data/pipeline_runs/42/phase_search.json``) → booléen
      ``has_artifact``. Le client n'a JAMAIS besoin du chemin : il récupère
      l'artefact via ``GET /api/iris/pipeline/{run_id}/artifacts/{phase_id}``
      (clé = ``phase_id``, déjà exposé). Exposer le path absolu fuitait le layout
      filesystem serveur.

    No-op sur les champs absents (un run n'a pas d'``artifact_path``).
    """
    raw = d.get("error_message")
    if raw:
        from app.services.data_access.error_messages import (
            sanitize_pipeline_error_for_client,
        )

        d["error_message"] = await sanitize_pipeline_error_for_client(raw, user)
    if "artifact_path" in d:
        d["has_artifact"] = bool(d.pop("artifact_path"))
    # S8 (défense en profondeur) — ``metadata_summary`` est un champ texte libre
    # forwardé brut au client ; son innocuité tient à une convention, pas à une
    # barrière. On strip défensivement tout chemin filesystem absolu.
    ms = d.get("metadata_summary")
    if isinstance(ms, str) and ms:
        from app.services.data_access.error_messages import redact_filesystem_paths

        d["metadata_summary"] = redact_filesystem_paths(ms)


class IrisPipelineRunCreateHandler(BaseHandler):
    """``POST /api/iris/pipeline-run``.

    Body JSON : ``{"query_nl": str, "mode": "ir"|"legacy"?,
    "block_all_views": bool?, "use_sage": bool?, "conversation_id": int?}``

    Réponse : ``{"success": true, "run_id": int, "status": str,
    "ws_url": "/ws/iris/pipeline"}``.
    """

    @authenticated
    async def post(self) -> None:
        user_id = self.current_user.id  # type: ignore[union-attr]

        # Rate-limit
        if not _run_create_limiter.check(f"pipeline_run_create:{user_id}", *_RATE_LIMIT_RUN_CREATE):
            self.set_status(429)
            self.write(
                {
                    "success": False,
                    "error": "Trop de runs lancés. Patiente avant de réessayer.",
                }
            )
            return

        body = _safe_json_loads(self.request.body)
        if body is None:
            self.set_status(400)
            self.write({"success": False, "error": "JSON body requis."})
            return

        query_nl = (body.get("query_nl") or "").strip()
        if not query_nl or len(query_nl) > 5000:
            self.set_status(400)
            self.write(
                {
                    "success": False,
                    "error": "query_nl requis (1 à 5000 caractères).",
                }
            )
            return

        mode_raw = (body.get("mode") or "ir").strip().lower()
        try:
            mode = PipelineMode(mode_raw)
        except ValueError:
            self.set_status(400)
            self.write({"success": False, "error": f"Mode invalide '{mode_raw}'."})
            return

        # task #82 — défaut False : vues incluses dans le shortlist Phase 1.5.
        # Garde anti-hallucination via ``block_view_mined_fk=True`` côté Phase 1.5.
        block_all_views = bool(body.get("block_all_views", False))
        use_sage = bool(body.get("use_sage", True))
        conversation_id_raw = body.get("conversation_id")
        conversation_id = (
            conversation_id_raw
            if isinstance(conversation_id_raw, int) and conversation_id_raw > 0
            else None
        )

        request_id = f"iris-pipeline-api-{uuid.uuid4().hex[:12]}"
        with request_scope(request_id=request_id, user_id=user_id):
            try:
                run = await start_pipeline_run(
                    user_id=user_id,
                    query_nl=query_nl,
                    mode=mode,
                    block_all_views=block_all_views,
                    use_sage=use_sage,
                    conversation_id=conversation_id,
                    triggered_via=TriggeredVia.API,
                    request_id=request_id,
                )
            except QuotaExceededError as exc:
                self.set_status(429)
                self.write(
                    {
                        "success": False,
                        "error": (
                            f"Quota journalier atteint ({exc.limit} runs/24h). "
                            "Demande à un admin de relever PIPELINE_MAX_RUNS_PER_DAY."
                        ),
                    }
                )
                return
            except FileExistsError:
                self.set_status(500)
                self.write(
                    {
                        "success": False,
                        "error": "Conflit interne — réessaie.",
                    }
                )
                return
            except Exception as exc:  # noqa: BLE001
                logger.exception("pipeline_run create failed")
                self.set_status(500)
                # P6 SÉCURITÉ (audit 2026-05-26) — Avant : ``f"Échec : {exc}"``
                # exposait ``str(exc)`` brut au client (potentiel leak de
                # paths filesystem, stack trace de SQLAlchemy, secrets dans
                # exception args). C'est l'erreur INVERSE de l'audit : pas
                # de masquage, mais leak excessif. Maintenant : on passe par
                # le helper SSoT P2.1 qui catégorise + sanitize PII pour
                # ``audience="user"``. Le ``str(exc)`` complet reste dans la
                # log ``logger.exception`` côté serveur pour debug admin.
                from app.services.data_access.error_messages import (
                    sanitize_sql_for_client,
                )

                _payload = await sanitize_sql_for_client(
                    exc, self.current_user, audience="user"
                )
                self.write(
                    {
                        "success": False,
                        "error": _payload["message"],
                        "category": _payload["category"],
                    }
                )
                return

        self.write(
            {
                "success": True,
                "run_id": run.id,
                "status": run.status.value,
                "ws_url": "/ws/iris/pipeline",
            }
        )


class IrisPipelineStatusHandler(BaseHandler):
    """``GET /api/iris/pipeline/{run_id}`` — status + phases (active attempts)."""

    @authenticated
    async def get(self, run_id_raw: str) -> None:
        try:
            run_id = int(run_id_raw)
        except (TypeError, ValueError):
            self.set_status(400)
            self.write({"success": False, "error": "run_id invalide."})
            return

        user_id = self.current_user.id  # type: ignore[union-attr]
        async with get_session_factory()() as session:
            stmt = (
                select(PipelineRun)
                .where(PipelineRun.id == run_id)
                .options(selectinload(PipelineRun.phase_executions))
            )
            result = await session.execute(stmt)
            run = result.scalar_one_or_none()
            if run is None or run.user_id != user_id:
                self.set_status(404)
                self.write({"success": False, "error": "Run introuvable."})
                return

            phases = [_serialize_phase(p) for p in run.phase_executions if not p.is_superseded]
            run_dict = _serialize_run(run)

        # L6O2 (parité create P6) — sanitize les error_message AVANT envoi.
        user = self.current_user
        await _sanitize_pipeline_dict_for_client(run_dict, user)
        for _pd in phases:
            await _sanitize_pipeline_dict_for_client(_pd, user)
        self.write({"success": True, "run": run_dict, "phases": phases})


class IrisPipelineHistoryHandler(BaseHandler):
    """``GET /api/iris/pipeline-history?limit=20&status=running`` — historique user.

    Filtres :
      - ``limit`` (int, défaut 20, cap 100)
      - ``status`` (csv : ``pending,running,paused,success,failed,cancelled``).
        Filtre les runs par status. Sans ce paramètre → tous les non-archivés.
        Utilisé au boot ``/iris`` pour récupérer les runs actifs après refresh
        (``?status=pending,running,paused``) et auto-resubscriber.
    """

    @authenticated
    async def get(self) -> None:
        user_id = self.current_user.id  # type: ignore[union-attr]
        try:
            limit = int(self.get_argument("limit", "20"))
        except (TypeError, ValueError):
            limit = 20
        limit = max(1, min(limit, 100))

        # Filtre status optionnel (csv)
        status_arg = (self.get_argument("status", "") or "").strip()
        wanted_statuses: list[PipelineRunStatus] = []
        if status_arg:
            for raw in status_arg.split(","):
                raw = raw.strip().lower()
                if not raw:
                    continue
                try:
                    wanted_statuses.append(PipelineRunStatus(raw))
                except ValueError:
                    # Status invalide ignoré (ne pas leak la liste valide
                    # au caller, juste skip ; le frontend doit envoyer
                    # des valeurs propres).
                    pass

        async with get_session_factory()() as session:
            stmt = (
                select(PipelineRun)
                .where(PipelineRun.user_id == user_id)
                .where(PipelineRun.is_archived.is_(False))
            )
            if wanted_statuses:
                stmt = stmt.where(PipelineRun.status.in_(wanted_statuses))
            stmt = stmt.order_by(PipelineRun.created_at.desc()).limit(limit)
            result = await session.execute(stmt)
            runs = result.scalars().all()
            run_dicts = [_serialize_run(r) for r in runs]

        # L6O2 (parité create P6) — sanitize les error_message AVANT envoi.
        user = self.current_user
        for _rd in run_dicts:
            await _sanitize_pipeline_dict_for_client(_rd, user)
        self.write({"success": True, "runs": run_dicts})


class IrisPipelineArchiveHandler(BaseHandler):
    """``DELETE /api/iris/pipeline/{run_id}/archive`` — soft-delete."""

    @authenticated
    async def delete(self, run_id_raw: str) -> None:
        try:
            run_id = int(run_id_raw)
        except (TypeError, ValueError):
            self.set_status(400)
            self.write({"success": False, "error": "run_id invalide."})
            return

        user_id = self.current_user.id  # type: ignore[union-attr]
        async with get_session_factory()() as session:
            run = await session.get(PipelineRun, run_id)
            if run is None or run.user_id != user_id:
                self.set_status(404)
                self.write({"success": False, "error": "Run introuvable."})
                return
            run.is_archived = True
            await session.commit()

        self.write({"success": True, "run_id": run_id})


class IrisPipelineArtifactHandler(BaseHandler):
    """``GET /api/iris/pipeline/{run_id}/artifacts/{phase_id}``.

    Sert le JSON brut d'une phase. Vérifie ownership + que le chemin
    artefact pointe bien dans ``run.output_dir`` (anti path-traversal).
    """

    @authenticated
    async def get(self, run_id_raw: str, phase_id: str) -> None:
        # Single source of truth pour les phase_id valides : pipeline_runner
        # PHASE_LABELS. Évite la dérive 3-sources (handler API, WS, runner)
        # quand on ajoute/supprime une phase.
        from app.services.ai.pipeline_runner import PHASE_LABELS

        try:
            run_id = int(run_id_raw)
        except (TypeError, ValueError):
            self.set_status(400)
            self.write({"success": False, "error": "run_id invalide."})
            return

        if phase_id not in PHASE_LABELS:
            self.set_status(400)
            self.write({"success": False, "error": "phase_id invalide."})
            return

        user_id = self.current_user.id  # type: ignore[union-attr]
        async with get_session_factory()() as session:
            run = await session.get(PipelineRun, run_id)
            if run is None or run.user_id != user_id:
                self.set_status(404)
                self.write({"success": False, "error": "Run introuvable."})
                return

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
            phase = result.scalar_one_or_none()

        if phase is None or not phase.artifact_path:
            self.set_status(404)
            self.write({"success": False, "error": "Artefact non disponible pour cette phase."})
            return

        # Anti path-traversal (BLOCKING #2 review fix complet) : artifact
        # doit vivre sous run.output_dir ET aucun ancêtre ne doit être un
        # symlink hors-base. La version précédente filtrait avec
        # ``startswith(str(base))`` qui ratait les symlinks intermédiaires
        # POINTANT vers base (mais étant hors-base eux-mêmes). On itère
        # désormais TOUS les ancêtres du chemin BRUT (pre-resolve) sans
        # filtrer, et on refuse au moindre symlink rencontré.
        try:
            base = Path(run.output_dir).resolve()
            artifact_raw = Path(phase.artifact_path)
            artifact = artifact_raw.resolve()
            artifact.relative_to(base)  # raise ValueError si pas dedans

            # Vérification symlink renforcée : on inspecte le chemin brut
            # ET son resolved, ET tous les ancêtres BRUTS (pre-resolve).
            # Un symlink intermédiaire qui pointe vers base est aussi
            # bloqué — defense-in-depth contre TOCTOU + symlink bait.
            if artifact_raw.is_symlink() or artifact.is_symlink():
                raise OSError("symlink artifact refused")
            for ancestor in artifact_raw.parents:
                # Limiter la remontée : on s'arrête à la racine ou à `base`
                # une fois résolu (évite scan infini sur paths bizarres).
                if ancestor == ancestor.parent:
                    break
                if ancestor.is_symlink():
                    raise OSError(f"symlink ancestor: {ancestor}")
                # Stop si on remonte au-dessus de la base résolue.
                try:
                    ancestor.resolve().relative_to(base)
                except ValueError:
                    break
        except (OSError, ValueError) as exc:
            logger.warning(
                "Artifact path-traversal refusé (run_id=%s, phase=%s): %s",
                run_id,
                phase_id,
                exc,
            )
            self.set_status(403)
            self.write({"success": False, "error": "Accès artefact refusé."})
            return

        # Limiter aux extensions JSON (defense-in-depth — la pipeline ne
        # produit que du JSON, mais si un futur dev élargit, on freine).
        if artifact.suffix.lower() not in (".json",):
            self.set_status(403)
            self.write({"success": False, "error": "Type d'artefact non servi."})
            return

        if not artifact.exists():
            self.set_status(404)
            self.write({"success": False, "error": "Artefact disparu du disque."})
            return

        try:
            content = artifact.read_text(encoding="utf-8")
        except OSError:
            # A6-F4 : message générique — l'``exc`` exposait un chemin FS au
            # client (incohérent avec sanitize_sql_for_client utilisé ailleurs
            # dans ce handler). Le détail reste loggé côté serveur.
            logger.exception("Read artifact failed")
            self.set_status(500)
            self.write({"success": False, "error": "Lecture de l'artefact échouée."})
            return

        # Sert tel quel (JSON déjà sérialisé par la pipeline).
        # Content-Type aligné — si un jour la pipeline produit du non-JSON,
        # adapter ici.
        self.set_header("Content-Type", "application/json; charset=utf-8")
        self.write(content)
