"""
Data structures for the Iris orchestrator.

These models track the state of the 6-phase orchestrated SQL workflow:
- ConceptItem/ConceptGroup: extracted concepts from user query (Phase 1)
- ConceptSynthesis/CumulativeSynthesis: located concepts in the DB (Phase 2)
- SQLBuildState: incremental SQL construction state (Phase 3)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Phase 1 — Concept extraction
# ---------------------------------------------------------------------------


class ConceptType(str, Enum):
    CONCEPT_ABSTRAIT = "concept_abstrait"
    VALEUR_LITTERALE = "valeur_littérale"
    EXCLUSION = "exclusion"


class ConceptPriority(int, Enum):
    """Search order: sources first, exclusions last."""

    SOURCE = 1
    DONNEE = 2
    AXE_VENTILATION = 3
    TEMPOREL = 4
    FILTRE_INCLUSION = 5
    FILTRE_EXCLUSION = 6


@dataclass
class ConceptItem:
    """A single concept extracted from the user query."""

    texte_original: str
    variantes: list[str] = field(default_factory=list)
    type: ConceptType = ConceptType.CONCEPT_ABSTRAIT
    notes: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> ConceptItem:
        return cls(
            texte_original=d.get("texte_original", ""),
            variantes=d.get("variantes", []),
            type=ConceptType(d.get("type", "concept_abstrait")),
            notes=d.get("notes", ""),
        )


_CATEGORY_TO_PRIORITY: dict[str, ConceptPriority] = {
    "source": ConceptPriority.SOURCE,
    "donnee": ConceptPriority.DONNEE,
    "axe_ventilation": ConceptPriority.AXE_VENTILATION,
    "temporel": ConceptPriority.TEMPOREL,
    "filtre_inclusion": ConceptPriority.FILTRE_INCLUSION,
    "filtre_exclusion": ConceptPriority.FILTRE_EXCLUSION,
}


@dataclass
class ConceptGroup:
    """A group of related concepts (abstract concept + its literal values).

    Example: a concept like "category" + values ["A", "B", "C"]
    form ONE group that will be searched in a single Phase 2 iteration.

    Created directly from LLM output (Option A) — no programmatic grouping needed.
    """

    concept: ConceptItem
    values: list[str] = field(default_factory=list)
    priority: ConceptPriority = ConceptPriority.FILTRE_INCLUSION

    @classmethod
    def from_llm_dict(cls, d: dict) -> ConceptGroup:
        """Create a ConceptGroup from the LLM's Phase 1 JSON output.

        Expected format:
        {
            "concept": "category name",
            "variantes": ["category", "cat"],
            "valeurs": ["VAL1", "VAL2", "VAL3"],
            "categorie": "filtre_inclusion",
            "notes": "..."
        }
        """
        concept_name = d.get("concept", "")
        variantes = d.get("variantes", [])
        valeurs = d.get("valeurs", [])
        categorie = d.get("categorie", "filtre_inclusion")
        notes = d.get("notes", "")

        priority = _CATEGORY_TO_PRIORITY.get(categorie, ConceptPriority.FILTRE_INCLUSION)

        concept_item = ConceptItem(
            texte_original=concept_name,
            variantes=variantes if variantes else [concept_name],
            type=ConceptType.CONCEPT_ABSTRAIT,
            notes=notes,
        )

        return cls(concept=concept_item, values=valeurs, priority=priority)

    @property
    def all_search_terms(self) -> list[str]:
        """All terms to search for this group (concept variantes + values)."""
        terms = list(self.concept.variantes)
        terms.extend(self.values)
        return terms

    @property
    def display_name(self) -> str:
        if self.values:
            val_texts = ", ".join(self.values[:3])
            return f"{self.concept.texte_original} ({val_texts})"
        return self.concept.texte_original


def parse_phase1_response(data: dict) -> list[ConceptGroup]:
    """Parse the LLM's Phase 1 response into sorted ConceptGroups.

    Args:
        data: Parsed JSON from LLM with key "groupes"

    Returns:
        List of ConceptGroup sorted by priority (source first, exclusions last).
    """
    raw_groups = data.get("groupes", [])
    groups = []
    for raw in raw_groups:
        try:
            groups.append(ConceptGroup.from_llm_dict(raw))
        except (ValueError, KeyError) as e:
            logger.debug("Skipping malformed group: %s", e)

    groups.sort(key=lambda g: g.priority.value)
    return groups


# ---------------------------------------------------------------------------
# Phase 2 — Concept localization synthesis
# ---------------------------------------------------------------------------


@dataclass
class ColumnDetail:
    """Details about a specific column found during localization."""

    name: str
    table: str
    data_type: str = ""
    nullable: bool = True
    indexed: bool = False
    identity: bool = False
    default: str = ""
    distinct_count: int = 0
    null_pct: float = 0.0
    min_value: str = ""
    max_value: str = ""
    sample_values: list[str] = field(default_factory=list)


@dataclass
class TableDetail:
    """Details about a table found during localization."""

    name: str
    row_count: int = 0
    pk_columns: list[str] = field(default_factory=list)
    fk_outgoing: list[dict] = field(default_factory=list)
    fk_incoming: list[dict] = field(default_factory=list)
    indexes: list[str] = field(default_factory=list)
    role: str = ""
    useful_columns: list[ColumnDetail] = field(default_factory=list)


@dataclass
class JoinPath:
    """A FK-based join path between two tables."""

    source_table: str
    target_table: str
    source_column: str
    target_column: str
    nullable: bool = True
    join_type: str = "LEFT JOIN"


@dataclass
class ConceptSynthesis:
    """Mini-synthesis for a single localized concept."""

    concept_name: str
    location: str  # e.g. "TableName.columnName"
    retrieval: str  # e.g. "SUM(columnName)" or "direct" or "CASE WHEN..."
    table: TableDetail | None = None
    column: ColumnDetail | None = None
    is_calculated: bool = False
    calculation_expression: str = ""
    notes: str = ""


class CumulativeSynthesis:
    """Accumulates mini-syntheses as concepts are localized.

    The synthesis is MODIFIABLE: if a later concept reveals that an earlier
    synthesis was incomplete/incorrect, it can be updated.
    """

    def __init__(self) -> None:
        self._syntheses: list[ConceptSynthesis] = []
        self._tables: dict[str, TableDetail] = {}
        self._join_paths: list[JoinPath] = []
        self._join_path_keys: set[tuple] = set()  # O(1) dedup
        self._current_sql: str = ""  # SQL en cours de construction (Phase 2)
        self._warnings: list[str] = []  # Avertissements inter-éléments

    def add(self, synthesis: ConceptSynthesis) -> None:
        """Add a new concept synthesis."""
        self._syntheses.append(synthesis)
        if synthesis.table and synthesis.table.name:
            self._tables[synthesis.table.name.upper()] = synthesis.table

    def update(self, concept_name: str, new_synthesis: ConceptSynthesis) -> None:
        """Update an existing synthesis (if a later concept corrects it)."""
        for i, s in enumerate(self._syntheses):
            if s.concept_name == concept_name:
                self._syntheses[i] = new_synthesis
                if new_synthesis.table:
                    self._tables[new_synthesis.table.name.upper()] = new_synthesis.table
                return
        # If not found, just add it
        self.add(new_synthesis)

    def add_join_path(self, path: JoinPath) -> None:
        """Register a discovered join path (O(1) dedup via set)."""
        key = (
            path.source_table.upper(),
            path.target_table.upper(),
            path.source_column.upper(),
            path.target_column.upper(),
        )
        if key in self._join_path_keys:
            return
        self._join_path_keys.add(key)
        self._join_paths.append(path)

    def update_sql(self, sql: str) -> None:
        """Update the current SQL being built (Phase 2)."""
        self._current_sql = sql

    def get_current_sql(self) -> str:
        """Get the current SQL being built."""
        return self._current_sql

    def add_warning(self, warning: str) -> None:
        """Add an inter-element warning (COUNT anomaly, etc.)."""
        self._warnings.append(warning)

    @property
    def warnings(self) -> list[str]:
        return list(self._warnings)

    @property
    def syntheses(self) -> list[ConceptSynthesis]:
        return list(self._syntheses)

    @property
    def tables(self) -> dict[str, TableDetail]:
        return dict(self._tables)

    @property
    def join_paths(self) -> list[JoinPath]:
        return list(self._join_paths)

    @property
    def tables_involved(self) -> list[str]:
        """All unique table names discovered so far."""
        return list(self._tables.keys())

    @property
    def columns_to_project(self) -> list[dict]:
        """Columns that need to be in the final SQL SELECT."""
        result = []
        for s in self._syntheses:
            if s.column:
                result.append(
                    {
                        "concept": s.concept_name,
                        "table": s.column.table,
                        "column": s.column.name,
                        "retrieval": s.retrieval,
                        "is_calculated": s.is_calculated,
                        "expression": s.calculation_expression,
                    }
                )
        return result

    @property
    def filters(self) -> list[dict]:
        """Pre-resolved filters from the synthesis."""
        result = []
        for s in self._syntheses:
            if "filtre" in s.retrieval.lower() or "IN" in s.retrieval:
                result.append(
                    {
                        "concept": s.concept_name,
                        "location": s.location,
                        "retrieval": s.retrieval,
                    }
                )
        return result

    def get_context_string(self) -> str:
        """Format the full synthesis as a context string for LLM prompts."""
        if not self._syntheses:
            return "(Aucun concept localisé pour le moment)"

        lines = ["SYNTHÈSE CUMULATIVE DES CONCEPTS LOCALISÉS :", ""]

        # Table of concepts
        lines.append("CONCEPTS LOCALISÉS :")
        for s in self._syntheses:
            calc = " [CALCULÉ]" if s.is_calculated else ""
            lines.append(f"  • {s.concept_name} → {s.location} ({s.retrieval}){calc}")
            if s.notes:
                lines.append(f"    Note: {s.notes}")

        # Tables with details
        if self._tables:
            lines.append("")
            lines.append("TABLES IMPLIQUÉES :")
            for name, table in self._tables.items():
                lines.append(f"  ├── {name} ({table.row_count} lignes)")
                if table.pk_columns:
                    lines.append(f"  │   PK: {', '.join(table.pk_columns)}")
                if table.role:
                    lines.append(f"  │   Rôle: {table.role}")
                for col in table.useful_columns:
                    nullable = "nullable" if col.nullable else "NOT NULL"
                    indexed = ", indexed" if col.indexed else ""
                    lines.append(f"  │   ├─ {col.name} ({col.data_type}, {nullable}{indexed})")
                    if col.sample_values:
                        vals = ", ".join(f"~{v}" for v in col.sample_values[:5])
                        lines.append(f"  │   │  Valeurs ex: {vals}")
                    if col.distinct_count:
                        lines.append(
                            f"  │   │  distinct={col.distinct_count}, "
                            f"null_pct={col.null_pct:.0%}"
                        )

        # Join paths
        if self._join_paths:
            lines.append("")
            lines.append("CHEMINS DE JOINTURE :")
            for jp in self._join_paths:
                nullable_hint = "[FK nullable]" if jp.nullable else "[FK NOT NULL]"
                lines.append(
                    f"  {jp.source_table} → {jp.target_table} "
                    f"({jp.source_column} = {jp.target_column}) {nullable_hint}"
                )

        # Calculated concepts
        calculated = [s for s in self._syntheses if s.is_calculated]
        if calculated:
            lines.append("")
            lines.append("CONCEPTS CALCULÉS :")
            for s in calculated:
                lines.append(f"  • {s.concept_name} = {s.calculation_expression}")

        # Warnings (includes pre-resolved filters from Phase 2.5)
        if self._warnings:
            lines.append("")
            lines.append("⚠️ AVERTISSEMENTS ET FILTRES PRÉ-RÉSOLUS :")
            for w in self._warnings:
                lines.append(f"  {w}")

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Serialize for logging/debugging."""
        return {
            "concepts": [
                {
                    "name": s.concept_name,
                    "location": s.location,
                    "retrieval": s.retrieval,
                    "is_calculated": s.is_calculated,
                }
                for s in self._syntheses
            ],
            "tables": list(self._tables.keys()),
            "join_paths": [
                {
                    "src": jp.source_table,
                    "tgt": jp.target_table,
                    "on": f"{jp.source_column}={jp.target_column}",
                }
                for jp in self._join_paths
            ],
        }


# ---------------------------------------------------------------------------
# Phase 3 — SQL construction state
# ---------------------------------------------------------------------------


@dataclass
class SQLColumn:
    """A column in the SQL being built."""

    concept: str  # Which user concept this serves
    table: str
    column: str
    alias: str = ""
    aggregation: str = ""  # SUM, COUNT, AVG, etc.
    expression: str = ""  # For calculated columns (CASE WHEN...)
    is_filter_only: bool = False  # Not in SELECT, only in WHERE


class SQLBuildState:
    """Tracks the incremental SQL construction state."""

    def __init__(self, synthesis: CumulativeSynthesis) -> None:
        self._synthesis = synthesis
        self.sql: str = ""
        self.columns_added: list[SQLColumn] = []
        self.columns_remaining: list[dict] = []
        self.joins_added: list[str] = []  # "TABLE AS Alias"
        self.filters_added: list[str] = []
        self.current_count: int = 0
        self.has_group_by: bool = False
        self.has_order_by: bool = False
        self.cte_used: bool = False

        # Initialize remaining columns from synthesis
        self.columns_remaining = list(synthesis.columns_to_project)

    def add_column(self, col: SQLColumn) -> None:
        """Mark a column as added to the SQL."""
        self.columns_added.append(col)
        # Remove from remaining by matching concept
        self.columns_remaining = [c for c in self.columns_remaining if c["concept"] != col.concept]

    def has_remaining_columns(self) -> bool:
        return len(self.columns_remaining) > 0

    @property
    def tables_in_query(self) -> set[str]:
        """Tables already present in the FROM/JOIN clauses."""
        tables = set()
        for col in self.columns_added:
            tables.add(col.table.upper())
        return tables

    @property
    def added_column_names(self) -> list[str]:
        return [c.column for c in self.columns_added]

    @property
    def remaining_column_descriptions(self) -> list[str]:
        """Human-readable list of remaining columns."""
        result = []
        for c in self.columns_remaining:
            desc = f"{c['column']} ({c['table']}) → {c['concept']}"
            if c.get("is_calculated"):
                desc += " [calculé]"
            result.append(desc)
        return result

    def get_state_for_prompt(self) -> str:
        """Format current state for LLM prompt."""
        lines = [
            f"REQUÊTE SQL ACTUELLE :",
            f"```sql",
            self.sql,
            f"```",
            f"",
            f"COUNT ACTUEL : {self.current_count} lignes",
            f"",
            f"COLONNES DÉJÀ DANS LA REQUÊTE :",
        ]
        for col in self.columns_added:
            agg = f" ({col.aggregation})" if col.aggregation else ""
            lines.append(f"  ✅ {col.column} ({col.table}){agg}")

        if self.columns_remaining:
            lines.append("")
            lines.append("COLONNES RESTANTES À AJOUTER :")
            for desc in self.remaining_column_descriptions:
                lines.append(f"  ○ {desc}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Phase 1 (NEW) — Alignment of user query with database
# ---------------------------------------------------------------------------


@dataclass
class AlignmentState:
    """État de la Phase 1 — persiste entre les itérations de discussion."""

    original_query: str  # Requête originale de l'utilisateur
    current_query: str  # Requête mise à jour par le LLM après discussion
    listo: set[str]  # Tous les termes cherchés (grandit, jamais réduit)
    results_cache: dict = field(default_factory=dict)  # {terme: TermSearchResults}
    discussion_history: list[dict] = field(default_factory=list)  # Messages de discussion
    iteration: int = 0  # Compteur d'itérations


@dataclass
class ElementPlan:
    """Un élément à résoudre en Phase 2."""

    concept: str  # Ex: "chiffre d'affaires"
    role: str  # Ex: "donnee_a_calculer", "filtre_inclusion", "axe_ventilation"
    pertinent_results: list[dict] = field(default_factory=list)  # Résultats de recherche
    order: int = 0  # Ordre de traitement
    sql_part: str = ""  # SELECT, WHERE, GROUP_BY, etc.
    notes: str = ""  # Notes du LLM
