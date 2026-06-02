"""Audit trail des modifications de termes d'anonymisation.

Chaque action user (création, mise à jour de flags, suppression manuelle ou
par cleanup) DOIT laisser une row dans la table ``anonymization_audit``.

**Pourquoi un module dédié et pas un wrapper repository** : (a) le code
d'audit est transverse (appelé depuis repository, cleanup_job, copilot
reconcile), un module unique évite la duplication, (b) le hook est
fail-soft — une erreur de logging audit ne doit JAMAIS faire échouer
l'action métier sous-jacente.

**Politique fail-soft** : si l'insertion audit échoue (BDD locked, schéma
absent en mode dégradé, etc.), on log un WARNING et on continue. Le but est
de tracer le maximum d'actions, pas de bloquer le user. Pour des audits
hard-required (compliance), un job de réconciliation comparerait
``anonymization_terms.updated_at`` avec ``anonymization_audit.created_at``.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymization_audit import AnonymizationAudit
from app.services.anonymization.user_id_guard import is_valid_user_id

logger = logging.getLogger(__name__)


# Sources autorisées pour ``triggered_by`` — miroir de la doctrine du modèle.
# Validé en amont pour ne pas polluer la table avec des valeurs libres.
TRIGGERED_BY_VALUES = frozenset(
    [
        "user_panel",  # PUT /api/anonymization/terms (édition manuelle)
        "copilot",  # reconcile_state au boot d'un classeur
        "auto_classifier",  # auto_classify (Ollama local)
        "system_cleanup",  # cleanup_unused_anonymization_terms_job
        "system_migration",  # backfill ponctuel via migration BDD
        "proxy",  # anonymize_for_llm proxy (auto-detect terme nouveau)
    ]
)

# Actions autorisées.
ACTION_VALUES = frozenset(["insert", "update", "delete"])


async def log_audit_action(
    session: AsyncSession,
    *,
    user_id: int,
    term: str,
    action: str,
    triggered_by: str,
    anonymization_term_id: Optional[int] = None,
    triggered_by_user_id: Optional[int] = None,
    category: Optional[str] = None,
    risk_level: Optional[str] = None,
    enabled: Optional[bool] = None,
    confirmed: Optional[bool] = None,
    changed_fields: Optional[Dict[str, Any]] = None,
    reason: Optional[str] = None,
    classeur_ref: Optional[str] = None,
) -> Optional[int]:
    """Insère une row dans ``anonymization_audit``.

    Fail-soft : retourne ``None`` si l'insertion échoue (et log WARNING),
    l'id de la row sinon. Le caller ne doit JAMAIS dépendre de la valeur
    retournée pour la logique métier — c'est uniquement à des fins de test.

    Le commit est laissé au caller (cohérent avec la convention du
    ``repository.py`` : le ``db_session()`` context manager commit en
    sortie).

    Validation : ``triggered_by`` et ``action`` doivent appartenir aux
    énumérations. Une valeur inconnue → WARNING + skip (pas d'exception
    pour ne pas casser le caller).
    """
    if not is_valid_user_id(user_id):
        logger.warning("audit: user_id invalide (%r), skip", user_id)
        return None
    if not isinstance(term, str) or not term:
        logger.warning("audit: term invalide, skip (action=%s)", action)
        return None
    if action not in ACTION_VALUES:
        logger.warning("audit: action inconnue %r, skip", action)
        return None
    if triggered_by not in TRIGGERED_BY_VALUES:
        logger.warning("audit: triggered_by inconnu %r, skip", triggered_by)
        return None

    try:
        row = AnonymizationAudit(
            user_id=user_id,
            anonymization_term_id=anonymization_term_id,
            term=term[:500],  # cap miroir de term VARCHAR(500)
            category=category,
            risk_level=risk_level,
            enabled=enabled,
            confirmed=confirmed,
            triggered_by=triggered_by,
            triggered_by_user_id=triggered_by_user_id,
            action=action,
            changed_fields=changed_fields,
            reason=reason[:200] if reason else None,
            classeur_ref=classeur_ref[:200] if classeur_ref else None,
        )
        session.add(row)
        # Flush pour récupérer l'id (utile aux tests). Pas de commit ici —
        # le caller s'en charge via son context manager db_session().
        await session.flush([row])
        return row.id
    except Exception as exc:
        # Fail-soft : on log + on continue. Une exception ici NE DOIT JAMAIS
        # bloquer l'action métier sous-jacente (upsert d'un terme).
        logger.warning(
            "audit: insertion échouée user=%s action=%s triggered_by=%s: %s",
            user_id,
            action,
            triggered_by,
            exc,
        )
        return None


