"""Helper centralisé pour le journal d'audit ``audit_logs``.

Doctrine compliance Komptia (RGPD / ISO 27001)
----------------------------------------------
Cluster-B du brainstorm-review 2026-05-26. Toute opération CRUD/lifecycle
d'une entité auditable (automation, schedule, step, edge, etc.) doit
laisser une trace requêtable (``audit_logs.created_at`` + ``user_id`` +
``action`` + ``entity_id`` + ``details``). Avant ce cluster :
``grep audit_log app/handlers/automations.py`` retournait 0 match — un
incident sécurité « qui a changé ma planif ? » était impossible à tracer.

Décisions de design
-------------------
1. **Atomic** — la ligne ``AuditLog`` est ajoutée à la **même** session
   que la mutation parente (``session.add(audit_row)`` + ``session.flush()``,
   pas de commit). Le caller fait le ``commit`` global. Si la mutation
   parente rollback (validation, FK, lock), l'audit rollback aussi —
   pas de trace orpheline. Si l'insertion audit lève (FK ``users.id``
   ON DELETE SET NULL invalide, contrainte CHECK violée), la mutation
   parente rollback aussi — pas de mutation sans trace.
2. **SSoT model** — utilise ``AuditLog.log_action(...)`` factory pour
   la sérialisation JSON de ``details`` et la cohérence du shape. Ne
   crée pas de nouveau modèle ; la table ``audit_logs`` existe déjà
   (cf. ``app/models/audit.py``).
3. **No commit ici** — le caller décide quand commit. Pour un audit
   « pur read » (export GET sans mutation), le caller fait
   ``session.add(...); await session.commit()`` autour de l'appel.
4. **No fire-and-forget** — pour compliance, l'audit doit succeed
   AVEC la mutation, ou échouer ENSEMBLE. Le pattern fire-and-forget
   (cf. mémoire ``feedback_db_locked_followup_2026_05_22``) est
   approprié pour les snapshots non-compliance (last_seen, etc.)
   mais pas pour le journal légal.

Doctrine SQLite-locked
----------------------
Le helper n'applique pas de ``retry_on_locked`` lui-même — il se
contente d'ajouter à la session. Si le caller veut une résilience
aux locks SQLite transitoires, il enveloppe son ``session.commit()``
global avec ``app/core/db_retry.py:retry_on_locked``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Final, Mapping, Optional

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog

logger = logging.getLogger(__name__)


# Cap dur sur la taille sérialisée du champ ``details`` JSON. Defense en
# profondeur contre (a) storage exhaustion via spam audit, (b) PII leak
# accidentel via un caller qui passe un large payload. 4 KB couvre
# largement les cas légitimes (name + IDs + flags + listes courtes).
# Au-delà, on remplace par un placeholder qui préserve la signature
# audit (action + entity) tout en évitant la fuite.
_DETAILS_JSON_MAX_BYTES: Final[int] = 4096


def _cap_details(details: Optional[Mapping[str, Any]]) -> Optional[dict]:
    """Cap la taille JSON sérialisée à ``_DETAILS_JSON_MAX_BYTES``.

    Si le payload dépasse, remplace par un placeholder qui préserve la
    traçabilité (action + entity sont stockés dans des colonnes
    distinctes, pas dans details) sans risque de fuite/exhaustion.
    """
    if details is None:
        return None
    try:
        encoded = json.dumps(details, default=str)
    except (TypeError, ValueError) as exc:
        # JSON non-sérialisable (objet exotique, cycle de ref). On log
        # WARN et on remplace par un placeholder — pas d'audit-block.
        logger.warning(
            "audit_event: details non-sérialisable (%s) — remplacé par placeholder",
            exc,
        )
        return {"_unserializable": True, "keys": sorted(map(str, details.keys()))}
    if len(encoded) > _DETAILS_JSON_MAX_BYTES:
        logger.warning(
            "audit_event: details JSON %d bytes > cap %d — tronqué",
            len(encoded),
            _DETAILS_JSON_MAX_BYTES,
        )
        return {
            "_truncated": True,
            "original_size_bytes": len(encoded),
            "keys": sorted(map(str, details.keys())),
        }
    return dict(details)


async def audit_event(
    session: AsyncSession,
    *,
    user_id: Optional[int],
    action: str,
    entity_type: Optional[str] = None,
    entity_id: Optional[int] = None,
    details: Optional[Mapping[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> AuditLog:
    """Insère une ligne ``audit_logs`` dans la session courante.

    Le caller fait le ``commit`` global (atomic avec sa mutation parente).
    Pour un audit standalone (export GET, etc.), le caller fait aussi
    le commit explicitement après cet appel.

    Args:
        session: ``AsyncSession`` SQLAlchemy de la requête courante.
        user_id: ID utilisateur initiateur. ``None`` accepté pour les
            actions système (le schéma audit_logs autorise NULL avec
            FK ON DELETE SET NULL). En pratique, les handlers HTTP/WS
            authentifiés passent toujours ``self.current_user.id``.
        action: Verbe d'action, idéalement une constante de
            ``app.models.audit.AuditAction`` pour cohérence
            (``automation_create``, ``step_delete``, etc.).
        entity_type: Type d'entité (``automation``, ``step``, ``edge``).
            ``None`` si pas d'entité précise (action globale).
        entity_id: ID de l'entité concernée. ``None`` accepté
            (action globale, ou ID non encore connu — auquel cas
            le caller doit ``flush`` la mutation parente AVANT
            cet appel pour récupérer l'ID).
        details: Dict sérialisable JSON (sera ``json.dumps``-é par
            la factory du modèle). Peut contenir ``request_id``,
            ``before``/``after`` pour les updates, etc.
        ip_address: IP source (depuis ``handler.request.remote_ip``).
            Limité à 45 chars (IPv6 max).
        user_agent: UA source. Peut être ``None`` ou string vide.

    Returns:
        La ligne ``AuditLog`` ajoutée et flushée (``id`` assigné).

    Raises:
        ValueError: si ``action`` est vide ou n'est pas une str.
        Toute exception SQLAlchemy de la mutation (lock, FK, etc.)
        propagée — le caller doit rollback ou retry au niveau du
        commit parent.
    """
    if not isinstance(action, str) or not action.strip():
        raise ValueError("audit_event: 'action' manquante ou vide")

    safe_action = action.strip()
    # Cap defense (cluster-B post-adversarial 2026-05-26).
    safe_details = _cap_details(details)
    # Defense IP : la colonne audit_logs.ip_address est String(45) — IPv6
    # max 39 + zone-id. Si remote_ip dépasse (cas exotique), on tronque
    # plutôt qu'erreur SQL silencieuse.
    safe_ip = ip_address[:45] if isinstance(ip_address, str) else ip_address

    row = AuditLog.log_action(
        action=safe_action,
        user_id=user_id,
        entity_type=entity_type,
        entity_id=entity_id,
        details=safe_details,
        ip_address=safe_ip,
        user_agent=user_agent,
    )
    session.add(row)
    # ``flush()`` propage les contraintes (FK, NOT NULL) maintenant
    # plutôt qu'au commit global → si on doit rollback la mutation
    # parente sur audit invalide, on le sait DANS le handler avant
    # l'envoi du HTTP success au client. Pas de commit ici (atomic
    # avec la mutation parente).
    try:
        await session.flush()
    except SQLAlchemyError as exc:
        # Cluster-B post-adversarial 2026-05-26 — observabilité quand
        # l'audit fail : sans ce log, le caller reçoit un 500 générique
        # et on_call ne peut pas corréler "user reports CRUD 500" à
        # "audit FK violation". Le re-raise propage tel quel (atomic
        # rollback de la mutation parente).
        logger.error(
            "audit_event flush failed: action=%s entity_type=%s entity_id=%s user_id=%s err=%s",
            safe_action,
            entity_type,
            entity_id,
            user_id,
            exc,
            exc_info=True,
        )
        raise
    return row


#: Timeout (s) d'une écriture audit *best-effort* (session dédiée). Borne la
#: latence ajoutée à la réponse HTTP si la BDD locale est verrouillée
#: (write-lock SQLite concurrent → ``busy_timeout`` 30s). Au-delà, l'audit est
#: abandonné (best-effort). Overridable par ENV pour les déploiements à BDD
#: lente/volumineuse, fallback 5.0 (cohérent avec ``_BUSY_TIMEOUT_MS``).
_AUDIT_WRITE_TIMEOUT_S: Final[float] = float(os.getenv("KOMPTIA_AUDIT_WRITE_TIMEOUT_S", "5.0"))

#: Cap défensif sur la longueur du User-Agent stocké (la colonne est ``Text`` =
#: non bornée). Évite qu'un client gonfle ``audit_logs`` via un UA géant.
#: Aligné sur ``_audit_automation_event`` (500).
_AUDIT_USER_AGENT_MAX: Final[int] = 500


async def record_audit_best_effort(
    *,
    user_id: Optional[int],
    action: str,
    entity_type: Optional[str] = None,
    entity_id: Optional[int] = None,
    details: Optional[Mapping[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    timeout_s: Optional[float] = None,
) -> bool:
    """Écrit un événement d'audit dans une session DÉDIÉE, en *best-effort*.

    Pour les call-sites où l'audit ne doit JAMAIS bloquer ni faire échouer le
    flux appelant (login, création d'utilisateur, etc.) ET où la mutation
    parente a déjà été committée séparément (pas d'atomicité requise).

    Garanties :

    * **Borné** par ``timeout_s`` (défaut :data:`_AUDIT_WRITE_TIMEOUT_S`) — ne
      retient jamais la réponse HTTP plus longtemps, même si la BDD locale est
      verrouillée (``busy_timeout`` 30s).
    * **Ne propage jamais** : un échec ne casse pas le flux appelant.
    * **Erreurs attendues** (lock SQLite, timeout) → ``WARNING`` (transitoire,
      acceptable). **Erreurs inattendues** (bug de construction de l'audit) →
      ``ERROR`` + ``exc_info`` : un trou de conformité ne doit pas être masqué
      silencieusement derrière un warning anodin.

    Pour un audit **atomique** (rollback avec la mutation parente), utiliser
    directement :func:`audit_event` dans la session de la mutation — PAS ce helper.

    Returns:
        ``True`` si la ligne a été committée, ``False`` sinon.
    """
    # Import local : ``app.core.database`` importe des modèles ; on évite un
    # cycle d'import au chargement du module audit.
    from app.core.database import get_session

    budget = _AUDIT_WRITE_TIMEOUT_S if timeout_s is None else timeout_s
    safe_ua = (
        user_agent[:_AUDIT_USER_AGENT_MAX] if isinstance(user_agent, str) else user_agent
    )

    async def _write() -> None:
        async with get_session() as session:
            await audit_event(
                session,
                user_id=user_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
                ip_address=ip_address,
                user_agent=safe_ua,
            )
            await session.commit()

    try:
        await asyncio.wait_for(_write(), timeout=budget)
        return True
    except (SQLAlchemyError, asyncio.TimeoutError) as exc:
        # Transitoire (lock SQLite / BDD lente) — acceptable en best-effort.
        logger.warning(
            "Audit best-effort '%s' non enregistré (transitoire): %s", action, exc
        )
        return False
    except Exception:  # noqa: BLE001 — ceinture : ne jamais propager au flux appelant
        # Inattendu (bug de construction de l'audit) — VISIBLE en ERROR pour ne
        # pas masquer un trou de conformité derrière un warning anodin.
        logger.error(
            "Audit best-effort '%s' échec inattendu (bug à corriger)",
            action,
            exc_info=True,
        )
        return False
