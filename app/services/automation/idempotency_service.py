"""
Service d'idempotence pour les sinks (email, report).

Protection contre les doublons : un workflow qui envoie un email puis
crashe avant le commit DB peut etre relance → envoi double. Ce service
enregistre chaque sink execute avec une cle idempotent dans
`F_IDEMPOTENCY_LOG`. La cle est calculee de maniere deterministe depuis
les inputs + config + date du run : une re-tentative dans la meme fenetre
(24h) produit la meme cle → detection du doublon.

Usage type dans l'executor :

    from app.services.automation.idempotency_service import (
        compute_idempotency_key, claim_idempotency_key,
    )

    key = compute_idempotency_key(
        sink_kind="email",
        inputs={"recipients": recipients, "subject": subj, "body_hash": hbody},
        config=step.config,
        run_date=execution.started_at.date(),
    )
    already_sent = await claim_idempotency_key(session, key, sink_kind="email", step_execution_id=se.id)
    if already_sent:
        # Skip silencieux, le mail a deja ete envoye recemment
        return
    # ... envoi SMTP effectif ...

Design :
- Granularite jour (pas heure/minute) : deux tentatives dans la meme
  journee produisent la meme cle → doublon detecte.
- TTL 24h : au-dela, la cle est consideree comme expiree, un nouvel
  envoi avec la meme cle est autorise (cas : re-run le lendemain).
- `claim` = INSERT dans F_IDEMPOTENCY_LOG. Si UNIQUE violation, on a
  deja le sink → skip.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from typing import Any, Dict, Optional

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import clock
from app.models.idempotency_log import IdempotencyLog
from app.utils.logger import get_logger

logger = get_logger(__name__)


def _idempotency_now_naive_utc() -> datetime:
    """SSoT temporel pour les comparaisons sur ``IdempotencyLog.expires_at``.

    Cluster-E 2026-05-26 — helper centralisé pour la convention timezone.
    La colonne ``expires_at`` est ``DateTime`` (sans ``timezone=True``).
    Selon le dialecte :
    - SQLite stocke en TEXT (ISO8601 naive)
    - PostgreSQL stocke en ``timestamp without time zone``

    Pour comparer sans risque de mismatch tz-aware vs tz-naive sur les
    vieilles rows, on utilise un ``datetime`` UTC NAIVE. Ce helper unique
    garantit que ``purge_expired_idempotency_keys``, ``is_expired()`` et
    tout futur call-site utilisent EXACTEMENT la même convention.
    """
    return clock.naive_utc()


def compute_idempotency_key(
    *,
    sink_kind: str,
    inputs: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
    run_date: Optional[date] = None,
) -> str:
    """Calcule une cle idempotent deterministe.

    Args:
        sink_kind: "email" ou "report" (preserve si jamais on ajoute d'autres sinks).
        inputs: Dict des inputs fonctionnels (recipients, subject, body_hash, etc.).
            Les valeurs doivent etre serialisables JSON.
        config: Config du step (optionnelle, incluse si fournie).
        run_date: Date du run (defaut aujourd'hui UTC). Granularite jour :
            plusieurs tentatives dans la meme journee → meme cle.

    Returns:
        sha256 hex (64 chars).
    """
    date_iso = (run_date or clock.now().date()).isoformat()
    # Filtrer les cles privees injectees par l'executor (_step_name, _step_order,
    # _branch_*, etc.) : renommer ou reordonner un step ne doit pas invalider
    # l'idempotency. Convention : toute cle qui commence par "_" est interne.
    clean_config: Dict[str, Any] = {}
    if config:
        clean_config = {k: v for k, v in config.items() if not str(k).startswith("_")}
    payload = {
        "sink_kind": sink_kind,
        "inputs": inputs,
        "config": clean_config,
        "date": date_iso,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def claim_idempotency_key(
    session: AsyncSession,
    key: str,
    *,
    sink_kind: str,
    step_execution_id: Optional[int] = None,
) -> bool:
    """Tente de reserver la cle d'idempotence. Retourne True si deja prise.

    Args:
        session: Session SQLAlchemy async.
        key: Cle precalculee par `compute_idempotency_key`.
        sink_kind: "email" ou "report" (audit).
        step_execution_id: StepExecution associe (audit).

    Returns:
        True si la cle existe deja et n'est pas expiree (le caller doit
        skipper le sink). False si la cle est nouvellement reservee — le
        caller DOIT executer le sink.

    **Doctrine atomic CAS (Cluster-E-FOLLOWUP 2026-05-26)** : le pattern
    SELECT-puis-INSERT est protégé par le UNIQUE(key) côté BDD. Une race
    concurrente lève IntegrityError sur le 2ᵉ INSERT, qu'on traite comme
    "déjà pris" (fail-safe doublon : skip > envoi dupliqué).

    Per-ticket dedup : le caller passe une `key` calculée par
    :func:`compute_idempotency_key` avec des inputs SPÉCIFIQUES au ticket
    (recipient inclus dans `inputs`). Donc 2 destinataires différents
    génèrent 2 clés différentes → pas de cross-recipient dedup parasite.

    DST safety : `date_iso` dans `compute_idempotency_key` utilise UTC.
    Un owner en Europe/Paris qui programme un envoi à 23h30 UTC verra
    la date changer entre 2 runs avoisinants UTC-midnight. Acceptable
    pour Komptia (préférable à risquer un double envoi sur transition
    DST). Cf. cluster-E original pour la doctrine.
    """
    # 1. Lookup existant
    existing = await session.execute(select(IdempotencyLog).where(IdempotencyLog.key == key))
    flag = existing.scalar_one_or_none()
    if flag is not None:
        if not flag.is_expired():
            logger.info(
                "Idempotency hit: key=%s sink=%s → skip (deja envoye a %s)",
                key[:12],
                sink_kind,
                flag.created_at.isoformat() if flag.created_at else "?",
            )
            return True
        # Expiree : supprimer et reserver a nouveau
        await session.delete(flag)
        await session.flush()

    # 2. INSERT defensif. Si une course concurrente a commit entre le lookup
    # et l'insert, le UNIQUE(key) leve IntegrityError → traiter comme "deja
    # pris" (fail-safe cote doublon : mieux vaut skip un envoi legitime que
    # d'en envoyer deux).
    new_log = IdempotencyLog(
        key=key,
        sink_kind=sink_kind,
        step_execution_id=step_execution_id,
    )
    session.add(new_log)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        logger.warning(
            "Idempotency race: key=%s deja reservee par un autre processus → skip",
            key[:12],
        )
        return True

    return False


async def release_idempotency_key(session: AsyncSession, key: str) -> bool:
    """Libère (supprime) une clé d'idempotence précédemment réservée.

    À appeler quand le sink a ÉCHOUÉ APRÈS avoir claim la clé. Sans ça, le
    claim survit (``claim_idempotency_key`` est commit dans une session
    dédiée, donc persiste même si le run échoue ensuite) et tout retry /
    ré-exécution du jour skippe le sink → non-livraison / non-génération
    SILENCIEUSE + warning trompeur « déjà envoyé/généré aujourd'hui ».

    Compatible avec la doctrine B1 (claim persistant) : on ne libère QUE
    quand le sink lui-même a échoué, pas quand un step aval crashe après
    un sink réussi.

    Returns:
        True si une ligne a été supprimée, False si la clé était absente
        (déjà purgée / expirée / jamais claim — no-op idempotent).
    """
    existing = await session.execute(select(IdempotencyLog).where(IdempotencyLog.key == key))
    flag = existing.scalar_one_or_none()
    if flag is None:
        return False
    await session.delete(flag)
    await session.flush()
    return True


async def purge_expired_idempotency_keys(session: AsyncSession) -> int:
    """Supprime les entrees IdempotencyLog dont expires_at est passe.

    A appeler periodiquement (job scheduled ou apres chaque run). Retourne
    le nombre d'entrees supprimees.

    G2 — Filtrage SQL-side (WHERE expires_at <= :cutoff). Avant : SELECT *
    + filtre Python = OOM worker à 1M+ entrees.

    Compat datetime : la colonne ``IdempotencyLog.expires_at`` est typée
    ``DateTime`` (sans ``timezone=True``) — SQLite stocke en TEXT naive ;
    PG aurait stocké aware si on avait ``DateTime(timezone=True)``. Pour
    comparer de manière cohérente quel que soit le dialecte, on utilise un
    ``datetime`` UTC NAIVE (tzinfo=None) — le binding SQLAlchemy compare
    string lexicographiquement sur SQLite et timestamp sur PG, sans risque
    de mismatch tz-aware vs tz-naive sur les vieilles rows.

    Le caller est responsable du commit (cohérent avec les autres helpers
    de ce module : ``claim_idempotency_key`` flush mais ne commit pas).
    Ici on commit explicitement car l'appelant typique (scheduler job) a
    une session courte dédiée à la purge.
    """
    # Cluster-E 2026-05-26 — utilise le helper SSoT timezone (au lieu de
    # ré-implémenter la convention inline). Garantit cohérence avec
    # ``IdempotencyLog.is_expired()`` et tout futur call-site.
    now_naive_utc = _idempotency_now_naive_utc()
    delete_stmt = delete(IdempotencyLog).where(IdempotencyLog.expires_at <= now_naive_utc)
    result = await session.execute(delete_stmt)
    deleted = max(result.rowcount or 0, 0)
    await session.commit()
    if deleted:
        logger.info("Purge idempotency: %d entrees expirees supprimees", deleted)
    return deleted
