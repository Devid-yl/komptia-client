"""Représentation déclarative du DAG rétroactif du pipeline NL→SQL Iris.

Le pipeline `scripts/pipeline.py` est exécuté comme une séquence linéaire
de phases canoniques (`PHASES_ORDER`) mais des chantiers successifs (T1, T2,
T3a, T4, T14, T29★) y ont ajouté des **feedback loops** : des arêtes qui
enrichissent, signalent ou rétro-mutent l'état d'une phase amont à partir
d'une phase aval. Le résultat = un DAG rétroactif déguisé.

Ce module est UN SNAPSHOT DÉCLARATIF (V1) :

- **Pas de runtime** — aucun import du pipeline. Pas de circular import.
- **Pas d'effet de bord** — aucune lecture BDD, aucun appel LLM.
- **Source de vérité versionnée** — chaque modification du pipeline doit
  être reflétée ici, et le test `test_pipeline_dag.py::TestNoCodeDrift`
  vérifie via `Path.read_text()` que chaque mécanisme (fonction Python)
  référencé existe encore dans `scripts/pipeline.py`.

V2 future : remplacer `_execute_phase` linéaire par un DAG executor qui
consomme ce module au runtime.

Date du snapshot : 2026-05-11. Si le pipeline évolue, mettre à jour
`build_default_dag()` ET ré-exécuter les tests de garde.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional

# ════════════════════════════════════════════════════════════════════════
# Enums
# ════════════════════════════════════════════════════════════════════════


class PhaseKind(str, Enum):
    """Type de phase dans le DAG.

    FORWARD : phase canonique présente dans `PHASES_ORDER` de pipeline.py.
              Sa sortie est sérialisée dans `PipelineState`.
    VIRTUAL : phase déclenchée conditionnellement par une autre. N'apparaît
              pas dans `PHASES_ORDER`. Exemple : Phase 2.5 = pré-step interne
              de Phase 4 (mode IR uniquement).
    """

    FORWARD = "forward"
    VIRTUAL = "virtual"


class FeedbackKind(str, Enum):
    """Type de feedback rétroactif entre phases.

    ENRICH : la phase aval lit la sortie d'une phase amont, ajoute des
             éléments manquants, mute le state amont. Exemple T4/T14.
    SIGNAL : une phase produit un flag/score que la phase aval utilise pour
             modifier son comportement (sans muter d'autre state). T29★.
    INFORM : une phase partage un artefact spécifique avec une autre phase
             qui le consomme tel-quel. Exemple T2 (probe_validated_pairs
             Phase 3 → Phase 4 mismatch resolver).
    RETROACTIVE_MUTATE : la phase aval modifie en-place le state d'une phase
             amont (cas le plus pur du DAG rétroactif). Exemple T1 (Phase 4
             mismatch resolver mute `state.concept_resolution`).
    EXPORT : la sortie du pipeline est consommée par un système externe
             (agent IA, UI). Pas une boucle interne. T3a.
    """

    ENRICH = "enrich"
    SIGNAL = "signal"
    INFORM = "inform"
    RETROACTIVE_MUTATE = "retroactive_mutate"
    EXPORT = "export"


# ════════════════════════════════════════════════════════════════════════
# Dataclasses
# ════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class PhaseNode:
    """Nœud du DAG : une phase du pipeline.

    file_anchor pointe vers la définition Python primaire de la phase
    (ex. `scripts/pipeline.py:738`). Sert au test de garde anti-drift.
    """

    id: str
    label: str
    state_field: Optional[str]
    kind: PhaseKind
    file_anchor: str
    description: str = ""


@dataclass(frozen=True)
class FeedbackEdge:
    """Arête de feedback (rétroactive ou enrichissement) entre deux phases.

    `mechanism` = nom symbolique de la fonction Python qui réalise le feedback
    dans `scripts/pipeline.py`. Le test anti-drift cherche ce symbole en grep
    texte (pas en import, pour éviter de charger le monolithe au test time).

    `state_key` = chemin dot-notation dans `PipelineState` que l'arête lit
    ou mute. Sert à documenter le contrat sans charger le runtime.
    """

    id: str
    source: str
    target: str
    mechanism: str
    state_key: str
    kind: FeedbackKind
    description: str = ""


@dataclass
class PipelineDAG:
    """Container déclaratif du DAG complet.

    Sépare strictement :
    - `forward_edges` : la séquence canonique (acyclique).
    - `feedback_edges` : les boucles rétroactives (peuvent former des cycles
      logiques sans contredire l'ordre d'exécution).
    """

    phases: dict[str, PhaseNode] = field(default_factory=dict)
    forward_edges: list[tuple[str, str]] = field(default_factory=list)
    feedback_edges: list[FeedbackEdge] = field(default_factory=list)

    # ──────────────────────────────────────────────────────────────────
    # Introspection
    # ──────────────────────────────────────────────────────────────────

    def topological_order(self) -> list[str]:
        """Tri topologique des phases FORWARD (les VIRTUAL sont exclues).

        Cette méthode retourne l'ordre de dépendance de **données** de la
        séquence canonique. Phase 2.5 (VIRTUAL) n'apparaît pas — son
        positionnement runtime est défini par la fonction Phase 4 qui l'invoque,
        pas par les data deps.

        Implémentation Kahn — lève `RuntimeError` si cycle détecté sur
        forward_edges (feedback_edges IGNORÉES).
        """
        forward_phases = {
            pid for pid, node in self.phases.items() if node.kind == PhaseKind.FORWARD
        }
        in_degree: dict[str, int] = {pid: 0 for pid in forward_phases}
        adj: dict[str, list[str]] = {pid: [] for pid in forward_phases}
        for src, tgt in self.forward_edges:
            if src in forward_phases and tgt in forward_phases:
                adj[src].append(tgt)
                in_degree[tgt] += 1
        queue = [pid for pid, deg in in_degree.items() if deg == 0]
        order: list[str] = []
        while queue:
            queue.sort()  # déterminisme pour test
            current = queue.pop(0)
            order.append(current)
            for nxt in adj[current]:
                in_degree[nxt] -= 1
                if in_degree[nxt] == 0:
                    queue.append(nxt)
        if len(order) != len(forward_phases):
            raise RuntimeError(
                "Forward DAG contient un cycle "
                f"(visités {len(order)}/{len(forward_phases)} phases FORWARD)."
            )
        return order

    def feedback_into(self, phase_id: str) -> list[FeedbackEdge]:
        """Retourne les feedback_edges dont la cible est `phase_id`."""
        return [e for e in self.feedback_edges if e.target == phase_id]

    def feedback_from(self, phase_id: str) -> list[FeedbackEdge]:
        """Retourne les feedback_edges dont la source est `phase_id`."""
        return [e for e in self.feedback_edges if e.source == phase_id]

    def validate(self) -> list[str]:
        """Retourne la liste des erreurs structurelles. Vide = DAG cohérent.

        Vérifications :
        - phases non-vide
        - chaque forward_edge pointe vers des phases connues
        - aucun self-loop dans forward_edges (interdit explicitement —
          rétroaction = feedback_edge, pas forward_edge)
        - aucune duplication d'ID phase
        - chaque feedback_edge a un mechanism et state_key non-vides
        - chaque feedback_edge a source/target connus
        - le forward DAG (restriction aux phases FORWARD) est acyclique
        """
        errors: list[str] = []
        if not self.phases:
            errors.append("Aucune phase déclarée.")

        seen_ids: set[str] = set()
        for pid, node in self.phases.items():
            if pid != node.id:
                errors.append(f"Phase mismatched id: clé={pid!r} ≠ node.id={node.id!r}.")
            if pid in seen_ids:
                errors.append(f"Phase ID dupliquée: {pid!r}.")
            seen_ids.add(pid)

        for src, tgt in self.forward_edges:
            if src not in self.phases:
                errors.append(f"forward_edge: source inconnue {src!r}.")
            if tgt not in self.phases:
                errors.append(f"forward_edge: cible inconnue {tgt!r}.")
            if src == tgt:
                errors.append(
                    f"forward_edge: self-loop interdit sur {src!r} "
                    "(utiliser feedback_edge kind=EXPORT pour les arêtes "
                    "auto-référentes type pipeline→consumer externe)."
                )

        seen_edge_ids: set[str] = set()
        for edge in self.feedback_edges:
            if not edge.mechanism.strip():
                errors.append(f"feedback_edge {edge.id!r}: mechanism vide.")
            if not edge.state_key.strip():
                errors.append(f"feedback_edge {edge.id!r}: state_key vide.")
            if edge.source not in self.phases:
                errors.append(f"feedback_edge {edge.id!r}: source inconnue {edge.source!r}.")
            if edge.target not in self.phases:
                errors.append(f"feedback_edge {edge.id!r}: cible inconnue {edge.target!r}.")
            if edge.id in seen_edge_ids:
                errors.append(f"feedback_edge: ID dupliqué {edge.id!r}.")
            seen_edge_ids.add(edge.id)

        try:
            self.topological_order()
        except RuntimeError as exc:
            errors.append(str(exc))

        return errors

    # ──────────────────────────────────────────────────────────────────
    # Visualisation
    # ──────────────────────────────────────────────────────────────────

    def to_mermaid(self, *, highlight: Optional[Iterable[str]] = None) -> str:
        """Sérialise le DAG en flowchart Mermaid.

        `highlight` = ensemble d'IDs de phases à mettre en évidence (rendu
        coloré). Utilisé par `RunTrajectory.to_mermaid()` pour montrer les
        phases effectivement exécutées dans un run.
        """
        highlight_set: set[str] = set(highlight or ())
        lines: list[str] = ["flowchart TD"]
        for pid, node in self.phases.items():
            label = _mermaid_escape(f"{pid}\\n{node.label}")
            shape = "[[{}]]" if node.kind == PhaseKind.VIRTUAL else "[{}]"
            lines.append(f"    {_safe_id(pid)}{shape.format(label)}")
            if pid in highlight_set:
                lines.append(f"    class {_safe_id(pid)} executed")
        for src, tgt in self.forward_edges:
            lines.append(f"    {_safe_id(src)} --> {_safe_id(tgt)}")
        for edge in self.feedback_edges:
            etype = edge.kind.value
            label = _mermaid_escape(f"{edge.id} ({etype})")
            lines.append(f"    {_safe_id(edge.source)} -.->|{label}| {_safe_id(edge.target)}")
        lines.append("    classDef executed fill:#cfe8ff,stroke:#1f3a93,stroke-width:2px;")
        return "\n".join(lines)

    def to_dot(self) -> str:
        """Sérialise le DAG en Graphviz DOT.

        Forward edges en plein, feedback edges en pointillé avec label.
        """
        lines: list[str] = ["digraph PipelineDAG {", "    rankdir=LR;"]
        for pid, node in self.phases.items():
            shape = "doubleoctagon" if node.kind == PhaseKind.VIRTUAL else "box"
            label = _dot_escape(f"{pid}\\n{node.label}")
            lines.append(f'    "{pid}" [shape={shape}, label="{label}"];')
        for src, tgt in self.forward_edges:
            lines.append(f'    "{src}" -> "{tgt}";')
        for edge in self.feedback_edges:
            label = _dot_escape(f"{edge.id} ({edge.kind.value})")
            lines.append(
                f'    "{edge.source}" -> "{edge.target}" ' f'[style=dashed, label="{label}"];'
            )
        lines.append("}")
        return "\n".join(lines)

    def summary(self) -> str:
        """Résumé humain compact (phase count, edges count, feedback breakdown)."""
        forward = len(self.phases)
        virtual = sum(1 for n in self.phases.values() if n.kind == PhaseKind.VIRTUAL)
        kind_counts: dict[str, int] = {}
        for edge in self.feedback_edges:
            kind_counts[edge.kind.value] = kind_counts.get(edge.kind.value, 0) + 1
        kind_part = ", ".join(f"{k}={v}" for k, v in sorted(kind_counts.items())) or "—"
        return (
            f"PipelineDAG: {forward} phases (dont {virtual} virtuelles), "
            f"{len(self.forward_edges)} forward edges, "
            f"{len(self.feedback_edges)} feedback edges [{kind_part}]."
        )


# ════════════════════════════════════════════════════════════════════════
# Trace d'un run
# ════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class RunTrajectory:
    """Trace d'un run réel.

    `phases_executed` : tuple des IDs de phases dont l'attribut `state_field`
    est non-None dans le PipelineState fini. Préservé en ordre topologique.

    `feedback_edges_triggered` : tuple des IDs de feedback edges détectées
    comme effectivement déclenchées via heuristiques sur le state (ex.
    `concept_resolution[*]['requires_disambiguation'] == True` → T29★).
    """

    phases_executed: tuple[str, ...]
    feedback_edges_triggered: tuple[str, ...]

    @classmethod
    def from_pipeline_state(
        cls,
        state: Any,
        dag: Optional[PipelineDAG] = None,
    ) -> "RunTrajectory":
        """Reconstruit depuis un PipelineState (dict OU dataclass).

        Tolère les états partiels (None pour phases pas encore exécutées).
        L'ordre des phases exécutées suit l'ordre d'insertion du DAG
        canonique (= ordre runtime observé : FORWARD + VIRTUAL positionnée
        à son point d'exécution réel).
        """
        dag = dag or build_default_dag()
        state_dict = _coerce_state(state, dag)
        executed: list[str] = []
        for pid, node in dag.phases.items():
            if node.state_field is None:
                continue
            value = state_dict.get(node.state_field)
            if value is not None and value != {} and value != []:
                executed.append(pid)
        triggered = _detect_triggered_feedbacks(state_dict, dag)
        return cls(
            phases_executed=tuple(executed),
            feedback_edges_triggered=tuple(triggered),
        )

    def to_mermaid(self, dag: PipelineDAG) -> str:
        """Variante de `PipelineDAG.to_mermaid()` qui highlight les phases
        exécutées."""
        return dag.to_mermaid(highlight=self.phases_executed)


# ════════════════════════════════════════════════════════════════════════
# Helpers internes
# ════════════════════════════════════════════════════════════════════════


def _coerce_state(state: Any, dag: Optional[PipelineDAG] = None) -> dict[str, Any]:
    """Accepte dict ou objet avec attributs. Retourne un dict des champs
    pertinents. Tolère les attributs manquants.

    La liste des attributs à lire est dérivée du DAG fourni (source unique
    de vérité) ; fallback sur la liste canonique snapshot 2026-05-11
    quand aucun DAG n'est passé (rétro-compat).
    """
    if isinstance(state, dict):
        return state
    if dag is not None:
        attrs = tuple(node.state_field for node in dag.phases.values() if node.state_field)
    else:
        # Fallback snapshot 2026-05-11 — mis à jour quand un nouveau champ
        # est ajouté à PipelineState (mais préférer passer un `dag`).
        attrs = (
            "extracted",
            "filtered",
            "curated",
            "search",
            "scored",
            "reranks",
            "concept_resolution",
            "factsheets",
            "sql_final",
        )
    result: dict[str, Any] = {}
    for attr in attrs:
        if hasattr(state, attr):
            result[attr] = getattr(state, attr)
    return result


def _detect_triggered_feedbacks(state_dict: dict[str, Any], dag: PipelineDAG) -> list[str]:
    """Heuristique simple : un feedback edge est "déclenché" si son
    state_key est présent et non-trivial dans le state.

    Cette détection est volontairement conservative — elle ne fait QUE
    constater l'existence du champ, pas vérifier que le feedback a
    effectivement modifié quelque chose. Pour de la télémétrie fine, il
    faudra instrumenter le pipeline (V2).
    """
    triggered: list[str] = []
    for edge in dag.feedback_edges:
        if _state_path_has_signal(state_dict, edge.state_key):
            triggered.append(edge.id)
    return triggered


def _state_path_has_signal(state_dict: Any, path: str) -> bool:
    """Inspecte si `path` (dot-notation) est non-vide dans `state_dict`.

    Le segment `*` est un wildcard : la recherche réussit si **au moins une
    valeur** du dict parcouru fait apparaître le reste du chemin comme
    non-vide. Récursion garantit que tous les buckets sont inspectés
    (contre faux-négatif sur dict avec plusieurs entrées dont une seule
    porte le signal — cf. concept_resolution avec multi-concepts).
    """
    parts = path.split(".") if path else []
    return _state_path_recurse(state_dict, parts)


def _state_path_recurse(cursor: Any, parts: list[str]) -> bool:
    if cursor is None:
        return False
    if not parts:
        # Chemin consommé — la valeur courante doit être truthy.
        # bool(False), 0, "", [], {} sont considérés comme "pas de signal" :
        # ces valeurs représentent l'absence d'information utile (ex: flag
        # requires_disambiguation=False = explicitement "pas de besoin de
        # désambiguation" = feedback NON déclenché).
        return bool(cursor)
    head, tail = parts[0], parts[1:]
    if head == "*":
        if not isinstance(cursor, dict) or not cursor:
            return False
        return any(_state_path_recurse(v, tail) for v in cursor.values())
    if isinstance(cursor, dict):
        if head not in cursor:
            return False
        return _state_path_recurse(cursor[head], tail)
    return False


def _mermaid_escape(text: str) -> str:
    """Échappe les caractères qui cassent Mermaid (quotes + brackets)."""
    return text.replace('"', "'").replace("(", "&#40;").replace(")", "&#41;")


def _dot_escape(text: str) -> str:
    """Échappe les caractères qui cassent DOT (quotes + backslash brut)."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _safe_id(phase_id: str) -> str:
    """Convertit un ID de phase en identifiant Mermaid valide."""
    return phase_id.replace("-", "_").replace(".", "_")


# ════════════════════════════════════════════════════════════════════════
# Snapshot du pipeline — au 2026-05-11
# ════════════════════════════════════════════════════════════════════════


def build_default_dag() -> PipelineDAG:
    """Retourne le DAG canonique du pipeline NL→SQL Iris au 2026-05-11.

    Source de vérité pour les tests de garde anti-drift. Si une phase est
    ajoutée/renommée dans `scripts/pipeline.py`, mettre à jour ici ET
    relancer `tests/unit/test_pipeline_dag.py`.
    """
    phases = [
        PhaseNode(
            id="1.1-1.2",
            label="Extract + Expand termes",
            state_field="extracted",
            kind=PhaseKind.FORWARD,
            file_anchor="scripts/pipeline.py:738",
            description=(
                "Phase 1.1 (extraction NL) + 1.2 (expansion 3 passes). Produit "
                "termes, concepts, valeurs, exclusions, groupes, derivables, "
                "term_origins."
            ),
        ),
        PhaseNode(
            id="1.2.5",
            label="Filter entités",
            state_field="filtered",
            kind=PhaseKind.FORWARD,
            file_anchor="scripts/pipeline.py:8219",
            description=(
                "Filtre LLM des entités candidates — drop_tables, drop_views, " "qa_session."
            ),
        ),
        PhaseNode(
            id="1.2.6",
            label="Curate routing",
            state_field="curated",
            kind=PhaseKind.FORWARD,
            file_anchor="scripts/pipeline.py:8641",
            description=("Curate routing par concept (T,V,C,VC,Val) via LLM multi-turns."),
        ),
        PhaseNode(
            id="1.3-1.4",
            label="Search BDD locale",
            state_field="search",
            kind=PhaseKind.FORWARD,
            file_anchor="scripts/pipeline.py:8932",
            description=("Recherche BDD locale (LIKE % sur value_mapping). 0 LLM call."),
        ),
        PhaseNode(
            id="1.5",
            label="Scoring + FK subgraph",
            state_field="scored",
            kind=PhaseKind.FORWARD,
            file_anchor="scripts/pipeline.py:9253",
            description=("Scoring entités + FK subgraph. Produit v2_text + v2_annex_text."),
        ),
        PhaseNode(
            id="2",
            label="Rerank LLM",
            state_field="reranks",
            kind=PhaseKind.FORWARD,
            file_anchor="scripts/pipeline.py:9639",
            description=(
                "Rerank LLM par concept (parallèle gather). Produit per_concept "
                "ranking_top + rejected_or_low."
            ),
        ),
        PhaseNode(
            id="3",
            label="Concept Fact Sheets",
            state_field="factsheets",
            kind=PhaseKind.FORWARD,
            file_anchor="scripts/pipeline.py:11071",
            description=(
                "1 LLM + probes par concept (parallèle). Produit probes "
                "validées, interpretation, raw_response."
            ),
        ),
        PhaseNode(
            id="2.5",
            label="Concept Resolution (pré-step Phase 4 IR)",
            state_field="concept_resolution",
            kind=PhaseKind.VIRTUAL,
            file_anchor="scripts/pipeline.py:3044",
            description=(
                "Phase virtuelle : appelée AVANT phase_4_compose_ir() pour "
                "résoudre chaque concept en (table, col). Data-driven, 0 LLM."
            ),
        ),
        PhaseNode(
            id="4",
            label="SQL Composer",
            state_field="sql_final",
            kind=PhaseKind.FORWARD,
            file_anchor="scripts/pipeline.py:11677",
            description=(
                "Composition SQL finale. Mode IR (tool_use JSON → ir_to_sql) "
                "ou legacy. Inclut cascade mismatch resolver."
            ),
        ),
    ]

    forward_edges = [
        ("1.1-1.2", "1.2.5"),
        ("1.2.5", "1.2.6"),
        ("1.2.6", "1.3-1.4"),
        ("1.3-1.4", "1.5"),
        ("1.5", "2"),
        ("2", "3"),
        ("3", "4"),
        # Phase 2.5 = pré-step interne de Phase 4 (mode IR). Modélisée :
        # - dépend des reranks de Phase 2 (consommation directe)
        # - alimente Phase 4 compose (concept_resolution)
        ("2", "2.5"),
        ("2.5", "4"),
    ]

    feedback_edges = [
        FeedbackEdge(
            id="T4",
            source="2",
            target="2.5",
            mechanism="_t4_enrich_reranks_with_missing_fvex",
            state_key="reranks.per_concept",
            kind=FeedbackKind.ENRICH,
            description=(
                "Réinjecte dans le rerank les FvEx empiriques manquantes "
                "(biais lexical du LLM Phase 2). Idempotent."
            ),
        ),
        FeedbackEdge(
            id="T14",
            source="2",
            target="2.5",
            mechanism="_t14_enrich_reranks_with_missing_fvco",
            state_key="reranks.per_concept",
            kind=FeedbackKind.ENRICH,
            description=(
                "Complète T4 sur l'axe FUZZY : FvCo (sous-chaîne) absents du "
                "rerank, réinjectés au rang 199 (faible confiance)."
            ),
        ),
        FeedbackEdge(
            id="T29",
            source="2.5",
            target="4",
            mechanism="_compute_phase_2_5_confidence",
            state_key="concept_resolution.*.requires_disambiguation",
            kind=FeedbackKind.SIGNAL,
            description=(
                "Score de confiance Phase 2.5 → flag requires_disambiguation "
                "qui pousse Phase 4 à demander clarification utilisateur."
            ),
        ),
        FeedbackEdge(
            id="T2",
            source="3",
            target="4",
            mechanism="_extract_validated_pairs_from_probe",
            state_key="factsheets.per_concept",
            kind=FeedbackKind.INFORM,
            description=(
                "Probes Phase 3 → pairs (table, col) validées empiriquement → "
                "consommées par le mismatch resolver Phase 4 pour booster "
                "l'auto-fix sans dégrader vers ask_user."
            ),
        ),
        FeedbackEdge(
            id="T1",
            source="4",
            target="2.5",
            mechanism="_phase4_resolve_mismatches_async",
            state_key="concept_resolution",
            kind=FeedbackKind.RETROACTIVE_MUTATE,
            description=(
                "Cascade auto_fix → ask_user → degraded → unresolvable. "
                "Mute state.concept_resolution in-place : Phase 4 réécrit "
                "rétroactivement la décision de Phase 2.5."
            ),
        ),
        FeedbackEdge(
            id="T3a",
            source="4",
            target="4",  # auto-edge — signale "post-pipeline export"
            mechanism="_load_pipeline_artifacts_for_agent",
            state_key="concept_resolution",
            kind=FeedbackKind.EXPORT,
            description=(
                "Pipeline → agent IA Iris : artefacts (concept_resolution "
                "compacté, blueprint, etc.) propagés via "
                "_load_pipeline_artifacts_for_agent + "
                "_compact_concept_resolution (dans app/services/ai/agent_service.py)."
            ),
        ),
    ]

    dag = PipelineDAG(
        phases={p.id: p for p in phases},
        forward_edges=forward_edges,
        feedback_edges=feedback_edges,
    )
    return dag


__all__ = [
    "FeedbackEdge",
    "FeedbackKind",
    "PhaseKind",
    "PhaseNode",
    "PipelineDAG",
    "RunTrajectory",
    "build_default_dag",
]
