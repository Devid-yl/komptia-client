"""ToolResult dataclass standardisé pour tous les tools Iris.

**T13 (2026-05-26)** — Doctrine « blocages 100% justifiés » + single source
of truth pour le format de retour des tools.

Avant : chaque `_handle_*` retournait un dict ad-hoc avec des clés variables
(`success`, `error`, `blocked_by`, `count`, `row_count`, `_count_delta`,
`_auto_corrected_sql`, `proof`, ...). Iris devait pattern-match par tool.

Après : un seul format `ToolResult` avec champs explicites. La méthode
`to_legacy_dict()` produit un dict compatible avec les call-sites existants
(migration progressive tool par tool, pas big-bang).

**Cette task ne migre AUCUN tool.** Elle ajoute uniquement la définition.
Les migrations viendront tool par tool dans des sessions ultérieures pour
limiter le blast radius des changements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.services.ai.sql_validator import Proof


@dataclass(frozen=True)
class SystemSuggestion:
    """Suggestion système NON vérifiée à présenter à Iris.

    Le système n'AGIT pas — il propose. Iris décide d'utiliser, ajuster,
    ou ignorer. Conforme à la doctrine « pas d'auto-action LLM-based silencieuse ».
    """

    kind: str  # "sql_correction" | "tool_swap" | "rephrase" | etc.
    payload: Dict[str, Any]
    confidence_note: str  # ex: "fuzzy match difflib, peut être faux"
    rule_id: Optional[str] = None  # rule_id qui a déclenché la suggestion


@dataclass(frozen=True)
class ToolResult:
    """Format de retour standardisé pour tous les tools Iris.

    **Promesse pour Iris** : ce format est stable. Les clés ne disparaissent
    pas silencieusement entre versions. Si une donnée n'est pas applicable,
    le champ vaut `None` explicitement.

    Champs :
        success: bool — réussite du tool (False = blocage OU erreur runtime)
        data: dict | None — payload de succès (colonnes, rows, etc.) ou None
        error: str | None — message human-readable français si success=False
        proof: Proof | None — preuve formelle structurée si rejeté par validator
        provenance: list[dict] | None — arbre des transformations système (T9)
        suggestion: SystemSuggestion | None — suggestion système non vérifiée
        metadata: dict | None — traçabilité (trace_id, latency_ms, sql_hash, etc.)
    """

    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    proof: Optional[Proof] = None
    provenance: Optional[List[Dict[str, Any]]] = None
    suggestion: Optional[SystemSuggestion] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_legacy_dict(self) -> Dict[str, Any]:
        """Format JSON compat avec les call-sites legacy (ancien dict ad-hoc).

        Conserve les clés historiques `success`, `error`, `blocked_by`,
        `proof`, `suggestions`, `columns`, `row_count`, `execution_time_ms`
        pour permettre une migration progressive sans casser le dispatcher.

        Les nouveaux champs (`provenance`, `suggestion`, `metadata`) sont
        ajoutés en plus avec leurs clés explicites — les call-sites legacy
        les ignorent.
        """
        result: Dict[str, Any] = {"success": self.success}

        # Champs legacy minimaux
        if self.error is not None:
            result["error"] = self.error
        if self.proof is not None:
            # Délégué au Proof.to_tool_result() (single source for legacy format)
            proof_dict = self.proof.to_tool_result()
            # Retirer `success: False` du proof — déjà posé au top
            proof_dict.pop("success", None)
            result.update(proof_dict)
        # Payload de succès
        if self.data:
            result.update(self.data)
        # Champs additifs (n'écrasent rien)
        if self.provenance:
            result.setdefault("provenance", self.provenance)
        if self.suggestion is not None:
            result["suggestion"] = {
                "kind": self.suggestion.kind,
                "payload": self.suggestion.payload,
                "confidence_note": self.suggestion.confidence_note,
                "rule_id": self.suggestion.rule_id,
            }
        if self.metadata:
            result.setdefault("metadata", self.metadata)

        # Champs legacy par défaut si absents
        result.setdefault("columns", [])
        result.setdefault("row_count", 0)
        result.setdefault("execution_time_ms", 0)

        return result

    @classmethod
    def from_proof(cls, proof: Proof) -> "ToolResult":
        """Construit un ToolResult de blocage depuis un Proof."""
        return cls(success=False, proof=proof, error=proof.to_human_message())

    @classmethod
    def from_success(
        cls,
        data: Dict[str, Any],
        provenance: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "ToolResult":
        """Construit un ToolResult de succès avec payload."""
        return cls(
            success=True,
            data=data,
            provenance=provenance,
            metadata=metadata,
        )

    @classmethod
    def from_error(
        cls,
        error: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "ToolResult":
        """Construit un ToolResult d'erreur runtime (pas un blocage validator)."""
        return cls(success=False, error=error, metadata=metadata)
