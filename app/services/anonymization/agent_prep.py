"""Helper partagé pour la préparation d'anonymisation user-scoped.

**Single source of truth** pour le pattern d'anonymisation 2-couches
(pseudonymizer user-scoped + PII regex) consommé par tous les agents
tool-loop de Komptia (cf. Task #15 review adversariale 2026-05-17).

Factorise les phases communes entre :
- :mod:`app.services.ai.copilot_agent` (cellules workbook + iris)
- :mod:`app.services.dashboard.widget_planner_agent` (rows SQL dashboard)
- ... et tout futur agent (reports, contacts, automations) qui aura
  besoin du même pattern.

Avantages :
- Doctrine évolutive (decision David sur blocage pending, MAX_STATE_TERMS,
  scope_tokens perf) appliquée en UN point au lieu de N callers.
- Garde-fou DoS uniforme (MAX_STATE_TERMS cap au upsert).
- Restore chaîné (pseudo + PII) avec snapshot dict défensif partout.

Status : nouveau module 2026-05-18, consommé d'abord par
:mod:`widget_planner_agent.anonymization`. copilot_agent migrera quand
on aura les tests E2E de non-régression (PR future).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from app.utils.logger import get_logger

logger = get_logger(__name__)


class AnonymizationLookupError(Exception):
    """BDD anonymization_terms indisponible — fail-closed sur le run agent.

    Raise par :func:`prepare_user_anonymization` quand ``user_id`` est
    fourni mais la lecture du state utilisateur échoue (BDD down, etc.).
    Le caller DOIT propager ou wrapper en exception spécifique au domaine.
    """


@dataclass
class UserAnonymizationBundle:
    """Résultat de :func:`prepare_user_anonymization`.

    Bundle complet prêt à attacher au ``ctx`` d'un agent. Le caller
    construit son propre ``Context`` métier en wrappant ce bundle.
    """

    pseudonymizer: Any  # extract.Pseudonymizer
    pii_mapping: dict[str, str] = field(default_factory=dict)
    pii_counters: dict[str, int] = field(default_factory=dict)
    restore_fn: Callable[[Any], Any] = field(default=lambda x: x)
    # Métriques pour log/debug (review).
    state_term_count: int = 0
    scoped_term_count: int = 0
    added_token_count: int = 0


async def prepare_user_anonymization(
    *,
    user_id: Optional[int],
    current_tokens: set[str],
    source: Optional[str],
    source_ref: Optional[str] = None,
    caller_label: str = "agent",
) -> UserAnonymizationBundle:
    """Prépare les 2 couches d'anonymisation pour un run d'agent.

    Args:
        user_id: identifiant utilisateur. ``None`` = tests/scripts admin
            sans pseudonymizer user-scoped (couche PII regex seule
            via le restore_fn no-op).
        current_tokens: ensemble des tokens extraits du payload courant
            (résultat de :func:`anon_terms.extract_terms` sur un tab
            payload conforme au format ``tabs_context``).
        source: valeur canonique de ``ANONYMIZATION_SOURCES_BY_NAME``
            pour le tagging des nouveaux termes (ex: ``"sql_result"``,
            ``"workbook"``). ``None`` = pas de tag source.
        source_ref: référence optionnelle (ex: ``"dashboard:42"``) pour
            traçabilité grouping ``/data/privacy``.
        caller_label: identifiant lisible pour les logs (ex:
            ``"widget_planner_agent"``, ``"copilot_agent"``).

    Returns:
        :class:`UserAnonymizationBundle` prêt à attacher au ctx caller.

    Raises:
        AnonymizationLookupError: BDD indisponible + ``user_id`` fourni.
            Fail-closed : on refuse plutôt que laisser passer cleartext.
    """
    from app.services.anonymization import extract as anon_terms

    # ── Cas no-user : pseudonymizer no-op, PII regex seul ──────────────
    if user_id is None:
        empty_pseudo = anon_terms.build_user_pseudonymizer(
            {"version": 1, "terms": {}},
            scope_tokens=set(),
        )
        pii_mapping: dict[str, str] = {}
        return UserAnonymizationBundle(
            pseudonymizer=empty_pseudo,
            pii_mapping=pii_mapping,
            pii_counters={},
            restore_fn=build_restore_fn(empty_pseudo, pii_mapping),
        )

    # ── Lecture state BDD (source de vérité = /data/privacy) ───────────
    try:
        from app.core.database import get_session_factory
        from app.services.anonymization import repository as anon_repo

        session_factory = get_session_factory()
        async with session_factory() as session:
            stored_state = await anon_repo.get_state_for_user(session, user_id)
    except Exception as exc:
        logger.error(
            "%s: lecture state BDD user=%s échouée: %s",
            caller_label,
            user_id,
            exc,
            exc_info=True,
        )
        raise AnonymizationLookupError(
            "Impossible de lire les préférences d'anonymisation."
        ) from exc

    reconciled_state, added_tokens, vanished_tokens = anon_terms.reconcile_state(
        current_tokens,
        stored_state,
    )

    # ── Upsert nouveaux termes avec DoS cap MAX_STATE_TERMS ────────────
    if added_tokens and source:
        await _upsert_new_terms_with_cap(
            user_id=user_id,
            reconciled_state=reconciled_state,
            added_tokens=added_tokens,
            source=source,
            source_ref=source_ref,
            caller_label=caller_label,
        )

    # ── Pending laissés en clair (decision David 2026-05-19) ──────────
    # Decision David 2026-05-19 (inverse 2026-05-08) : seuls les termes
    # ``enabled=True`` sont anonymisés avant l'envoi au LLM cloud. Les
    # pending (``confirmed=False, enabled=False``) restent en clair —
    # c'est l'utilisateur qui décide via le panneau ``/data/privacy``.
    # La couche PII regex (``apply_builtin_pii`` côté caller) protège
    # toujours email/phone/SIRET/SIREN/IBAN/AMOUNT. Cf. docstring du
    # gate dans ``copilot_agent.py`` pour la rationale complète.
    #
    # **PAS DE MUTATION** : ``reconciled_state`` passe tel quel à
    # ``build_user_pseudonymizer`` qui filtre ``enabled=True`` en
    # interne (extract.py:1511). Cohérent avec ``proxy.anonymize_for_llm``
    # et les autres call sites LLM cloud.
    pending = anon_terms.pending_terms(reconciled_state)
    if pending:
        logger.info(
            "%s: %d terme(s) non confirmé(s) — laissés en clair "
            "(décision via /data/privacy). added=%d vanished=%d",
            caller_label,
            len(pending),
            len(added_tokens),
            len(vanished_tokens),
        )

    # ── Build pseudonymizer scoped (perf 5-10× vs global) ──────────────
    pseudo = anon_terms.build_user_pseudonymizer(
        reconciled_state,
        scope_tokens=current_tokens,
    )

    pii_mapping = {}
    pii_counters: dict[str, int] = {}
    restore_fn = build_restore_fn(pseudo, pii_mapping)

    state_term_count = len(reconciled_state.get("terms", {}))
    logger.info(
        "%s: pseudonymizer prepared (entries=%d state_terms=%d " "scoped=%d added=%d vanished=%d)",
        caller_label,
        len(pseudo),
        state_term_count,
        len(current_tokens),
        len(added_tokens),
        len(vanished_tokens),
    )

    return UserAnonymizationBundle(
        pseudonymizer=pseudo,
        pii_mapping=pii_mapping,
        pii_counters=pii_counters,
        restore_fn=restore_fn,
        state_term_count=state_term_count,
        scoped_term_count=len(current_tokens),
        added_token_count=len(added_tokens),
    )


async def _upsert_new_terms_with_cap(
    *,
    user_id: int,
    reconciled_state: dict[str, Any],
    added_tokens: set[str],
    source: str,
    source_ref: Optional[str],
    caller_label: str,
) -> None:
    """Persiste les nouveaux tokens avec garde DoS ``MAX_STATE_TERMS``.

    Pattern strictement aligné sur :func:`copilot_agent` lignes 483-540 +
    :mod:`widget_planner_agent.anonymization` (ce module remplace les 2).
    """
    try:
        from app.core.database import get_session_factory
        from app.services.anonymization import repository as anon_repo

        session_factory = get_session_factory()
        async with session_factory() as session:
            existing_count = await anon_repo.count_terms_for_user(session, user_id)
            # Cap dynamique dérivé du quota disque user (2026-05-19) au lieu
            # d'un seuil hardcodé. Cf. :func:`anon_repo.get_user_term_cap`.
            user_term_cap = await anon_repo.get_user_term_cap(session, user_id)
            room_left = max(0, user_term_cap - existing_count)
            if room_left == 0:
                logger.warning(
                    "%s: user=%s à la limite quota (user_term_cap=%d, "
                    "existing=%d), skip upsert de %d nouveaux termes",
                    caller_label,
                    user_id,
                    user_term_cap,
                    existing_count,
                    len(added_tokens),
                )
                return
            capped = sorted(added_tokens)[:room_left]
            new_terms = {
                t: reconciled_state["terms"][t] for t in capped if t in reconciled_state["terms"]
            }
            if new_terms:
                await anon_repo.upsert_terms(
                    session,
                    user_id,
                    new_terms,
                    source=source,
                    source_ref=source_ref,
                )
                await session.commit()
            if len(capped) < len(added_tokens):
                logger.warning(
                    "%s: user=%s, %d/%d nouveaux termes tronqués "
                    "(quota disque user_term_cap=%d)",
                    caller_label,
                    user_id,
                    len(added_tokens) - len(capped),
                    len(added_tokens),
                    user_term_cap,
                )
    except Exception as exc:
        # Non-fatal : le user reverra ces termes au prochain run. Log
        # sans exposer les tokens eux-mêmes (PII potentielle).
        logger.warning(
            "%s: upsert nouveaux termes user=%s échoué (%d termes): %s",
            caller_label,
            user_id,
            len(added_tokens),
            exc,
        )


def build_restore_fn(
    pseudonymizer: Any,
    pii_mapping: dict[str, str],
) -> Callable[[Any], Any]:
    """Construit la closure de dé-anonymisation chaînée pseudo → PII.

    **Ordre critique** : le pseudonymizer s'applique EN DERNIER à
    l'anonymisation (PII regex d'abord, pseudo ensuite), donc au restore
    il doit s'inverser EN PREMIER. Inverse ordre = tokens corrompus.

    **Snapshot** ``dict(pii_mapping)`` au point d'appel : si un futur
    parallel tool_use mute le mapping pendant que ``_pii_restore_walk``
    itère dessus → ``RuntimeError: dict changed size during iteration``.

    **Invariant séquentiel obligatoire** : les handlers de tools DOIVENT
    s'exécuter en séquence (pas en parallèle). Si un futur
    ``asyncio.gather`` introduit du parallel dispatch, le mapping
    devient un race condition.
    """

    def restore(payload: Any) -> Any:
        if payload is None:
            return None
        from app.services.anonymization.proxy import (
            _pii_restore_recursive as _pii_restore_walk,
        )

        result = payload
        if pseudonymizer is not None and len(pseudonymizer) > 0:
            result = pseudonymizer.deanonymize(result)
        if pii_mapping:
            result = _pii_restore_walk(result, dict(pii_mapping))
        return result

    return restore
