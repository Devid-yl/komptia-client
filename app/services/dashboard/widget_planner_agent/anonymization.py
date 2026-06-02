"""Anonymisation 2 couches pour l'agent widget_planner.

**Thin wrapper** depuis 2026-05-18 (Task #15 review adversariale PR 2.2) :
toute la logique commune (lecture state BDD, reconcile, DoS cap upsert,
safe-default pending, build pseudonymizer scoped, restore chaîné) est
factorisée dans :mod:`app.services.anonymization.agent_prep`. Ce module
n'expose plus que :
- Le construction du ``payload_for_tokenize`` SPÉCIFIQUE widget_planner
  (rows SQL + user_hint embarqués comme un tab)
- Le wrapper :class:`AnonymizationContext` métier (champs nommés pour
  les call-sites de l'agent)
- Le re-export de :exc:`AnonymizationLookupError` pour ne pas casser
  les imports existants
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from app.services.anonymization.agent_prep import (
    AnonymizationLookupError as _AnonLookupError,
    prepare_user_anonymization,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Re-export pour compat des imports existants
# (``widget_planner_agent.anonymization.AnonymizationLookupError``).
AnonymizationLookupError = _AnonLookupError


@dataclass
class AnonymizationContext:
    """Résultat de :func:`prepare_anonymization` — passé au ctx de l'agent.

    Les handlers de tools utilisent ``pseudonymizer.anonymize`` pour
    masquer les rows/values renvoyées au LLM, et ``restore_fn`` pour
    dé-anonymiser les tool_input avant exécution côté handler système.
    """

    pseudonymizer: Any
    pii_mapping: dict[str, str] = field(default_factory=dict)
    pii_counters: dict[str, int] = field(default_factory=dict)
    restore_fn: Callable[[Any], Any] = field(default=lambda x: x)
    state_term_count: int = 0
    scoped_term_count: int = 0
    added_token_count: int = 0


async def prepare_anonymization(
    *,
    rows: list[list[Any]],
    columns: list[str],
    user_hint: Optional[str],
    user_id: Optional[int],
    source_ref: Optional[str] = None,
) -> AnonymizationContext:
    """Setup les 2 couches d'anonymisation pour un run agent widget_planner.

    Wrapper léger sur :func:`agent_prep.prepare_user_anonymization` qui
    construit le payload tokenize SPÉCIFIQUE widget_planner (rows SQL
    + user_hint en sheet_content) avant de déléguer la logique commune.

    Args:
        rows: résultat SQL exécuté (échantillon peek). Sert au tokenize.
        columns: noms de colonnes du résultat SQL.
        user_hint: instructions libres de l'utilisateur (optionnel).
            Aussi tokenisé pour éviter qu'un nom propre tapé par le user
            ne leak au LLM.
        user_id: identifiant utilisateur. ``None`` = tests / scripts admin.
        source_ref: référence optionnelle (``dashboard:42``) pour
            traçabilité.

    Raises:
        AnonymizationLookupError: BDD indisponible et ``user_id`` fourni.
    """
    from app.models.anonymization_term import ANONYMIZATION_SOURCES_BY_NAME
    from app.services.anonymization import extract as anon_terms

    # Construction du payload pour ``extract_terms`` — format ``tabs_context``
    # (label + rows + sheet_content) attendu par extract_terms. user_hint
    # injecté en sheet_content[].value pour que les noms tapés par le
    # user soient tokenisés (sans ça, "compare Dupont 2024 vs 2025" leak
    # cleartext).
    tab_payload: dict[str, Any] = {
        "label": "sql_result",
        "rows": rows,
    }
    if user_hint and user_hint.strip():
        tab_payload["sheet_content"] = [{"value": user_hint.strip()}]
    current_tokens = anon_terms.extract_terms([tab_payload], None)

    # Délégation au helper partagé
    bundle = await prepare_user_anonymization(
        user_id=user_id,
        current_tokens=current_tokens,
        source=ANONYMIZATION_SOURCES_BY_NAME["sql_result"],
        source_ref=source_ref,
        caller_label="widget_planner_agent",
    )

    return AnonymizationContext(
        pseudonymizer=bundle.pseudonymizer,
        pii_mapping=bundle.pii_mapping,
        pii_counters=bundle.pii_counters,
        restore_fn=bundle.restore_fn,
        state_term_count=bundle.state_term_count,
        scoped_term_count=bundle.scoped_term_count,
        added_token_count=bundle.added_token_count,
    )


# Re-export du helper restore_fn builder pour les tests existants qui
# l'importaient depuis ce module (avant la factorisation Task #15).
def _build_restore_fn(
    pseudonymizer: Any,
    pii_mapping: dict[str, str],
) -> Callable[[Any], Any]:
    """Compat shim — délègue à ``agent_prep.build_restore_fn``."""
    from app.services.anonymization.agent_prep import build_restore_fn

    return build_restore_fn(pseudonymizer, pii_mapping)
